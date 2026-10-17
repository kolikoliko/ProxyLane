//! Bounded asynchronous payload cache. Quotas include both directions of an
//! exchange and are enforced by the single disk worker before every write.
use crate::{cache_directory::RunDirectory, Direction, Headers};
use serde::{Serialize, Serializer};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, SyncSender, TrySendError},
        Arc, Mutex, MutexGuard, Weak,
    },
    thread::{self, JoinHandle},
};

fn locked<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|e| e.into_inner())
}
const CHUNK: usize = 16384;
pub const PREVIEW_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub root: PathBuf,
    pub entry_bytes: u64,
    pub total_bytes: u64,
    pub queue_chunks: usize,
    pub max_entries: usize,
    pub decode_bytes: usize,
    pub decode_input_bytes: usize,
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            root: std::env::temp_dir()
                .join("ProxyLane")
                .join("protocol-cache-v1"),
            entry_bytes: 32 * 1024 * 1024,
            total_bytes: 512 * 1024 * 1024,
            queue_chunks: 128,
            max_entries: 4096,
            decode_bytes: 4*1024*1024,
            decode_input_bytes: 32*1024*1024,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct CacheSnapshot {
    pub id: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub finished: bool,
    pub pending_chunks: usize,
    pub evicted: bool,
    /// None means no cache loss has been observed. Check pending_chunks and
    /// the HTTP message's complete flag before assuming a full body is ready.
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct CacheStats {
    pub used_bytes: u64,
    pub peak_bytes: u64,
    pub entries: usize,
    pub evicted_entries: u64,
    pub recovered_runs: usize,
    pub warnings: Vec<String>,
}
#[derive(Clone, Default)]
pub(crate) struct BodyInfo {
    pub bytes: u64,
    pub complete: bool,
    pub headers: Headers,
    pub bodyless: bool,
}
struct Ticket {
    id: u64,
    state: Mutex<CacheSnapshot>,
    info: Mutex<[BodyInfo; 2]>,
    accepting: AtomicBool,
    pending: AtomicUsize,
    finished: AtomicU64,
}
impl Ticket {
    fn snapshot(&self) -> CacheSnapshot {
        let mut state = locked(&self.state).clone();
        state.pending_chunks = self.pending.load(Ordering::Acquire);
        state.finished = self.finished.load(Ordering::Acquire) != 0;
        state
    }
    fn stop(&self, reason: &str) {
        self.accepting.store(false, Ordering::Release);
        let mut state = locked(&self.state);
        if state.reason.is_none() {
            state.reason = Some(reason.into());
        }
    }
}
#[derive(Clone)]
pub struct CacheRef {
    ticket: Arc<Ticket>,
    owner: Weak<Inner>,
}
impl std::fmt::Debug for CacheRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.snapshot().fmt(f)
    }
}
impl Serialize for CacheRef {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.snapshot().serialize(serializer)
    }
}
impl CacheRef {
    /// Opaque connections share the same bounded cache as HTTP bodies.
    pub fn append_stream(&self, direction: Direction, bytes: &[u8]) {
        self.append(if matches!(direction, Direction::Client) { 0 } else { 1 }, bytes);
    }
    pub fn finish_stream(&self, bytes: [u64; 2], complete: bool) {
        if !complete { self.ticket.stop("capture ended before both directions closed"); }
        self.finish(std::array::from_fn(|side| BodyInfo {
            bytes: bytes[side], complete, ..BodyInfo::default()
        }));
    }
    pub fn id(&self) -> u64 {
        self.ticket.id
    }
    pub fn snapshot(&self) -> CacheSnapshot {
        self.ticket.snapshot()
    }
    pub(crate) fn append(&self, side: usize, bytes: &[u8]) {
        let Some(owner) = self.owner.upgrade() else {
            self.ticket.stop("cache closed");
            return;
        };
        for chunk in bytes.chunks(CHUNK) {
            if !self.ticket.accepting.load(Ordering::Acquire) {
                break;
            }
            self.ticket.pending.fetch_add(1, Ordering::AcqRel);
            // This path never waits for the disk worker or for queue capacity.
            let result = owner.try_send(Command::Append(self.ticket.clone(), side, chunk.to_vec()));
            if let Err(reason) = result {
                self.ticket.pending.fetch_sub(1, Ordering::AcqRel);
                self.ticket.stop(reason);
                break;
            }
        }
    }
    pub(crate) fn finish(&self, info: [BodyInfo; 2]) {
        if self.ticket.finished.load(Ordering::Acquire) != 0 {
            return;
        }
        *locked(&self.ticket.info) = info;
        let order = self
            .owner
            .upgrade()
            .map_or(1, |owner| owner.completion.fetch_add(1, Ordering::Relaxed));
        self.ticket.finished.store(order, Ordering::Release);
    }
}

#[derive(Debug, Serialize)]
pub struct CachedPayload {
    pub cache: CacheSnapshot,
    pub direction: Direction,
    pub offset: u64,
    #[serde(serialize_with = "serialize_bytes")]
    pub data_base64: Vec<u8>,
    pub decoded: bool,
    pub decoded_bytes: usize,
}
fn serialize_bytes<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    use base64::Engine;
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
}
enum Query {
    Stats,
    Status(u64),
    Read {
        id: u64,
        side: usize,
        offset: u64,
        length: usize,
        decode: bool,
        decoded_limit: usize,
    },
}
enum Answer {
    Stats(CacheStats),
    Status(Option<CacheSnapshot>),
    Payload(CachedPayload),
}
enum Command {
    Register(Arc<Ticket>),
    Append(Arc<Ticket>, usize, Vec<u8>),
    Query(Query, mpsc::Sender<Result<Answer, String>>),
}
struct Inner {
    sender: Mutex<Option<SyncSender<Command>>>,
    worker: Mutex<Option<JoinHandle<Result<(), String>>>>,
    next: AtomicU64,
    completion: AtomicU64,
    directory: PathBuf,
}
impl Inner {
    fn try_send(&self, command: Command) -> Result<(), &'static str> {
        match locked(&self.sender).as_ref() {
            None => Err("cache closed"),
            Some(sender) => sender.try_send(command).map_err(|e| match e {
                TrySendError::Full(_) => "cache queue full",
                TrySendError::Disconnected(_) => "cache worker unavailable",
            }),
        }
    }
    fn query(&self, query: Query) -> Result<Answer, String> {
        let (sender, receiver) = mpsc::channel();
        // Reads/flushes are explicitly synchronous API operations, not called
        // from the analyzer's packet path. Do not hold sender mutex while waiting.
        let queue = locked(&self.sender)
            .as_ref()
            .cloned()
            .ok_or("cache closed")?;
        queue
            .send(Command::Query(query, sender))
            .map_err(|_| "cache worker unavailable")?;
        drop(queue);
        receiver.recv().map_err(|_| "cache worker unavailable")?
    }
    fn shutdown(&self) -> Result<(), String> {
        // Serialize simultaneous shutdowns; drain accepted writes before cleanup.
        let mut worker = locked(&self.worker);
        locked(&self.sender).take();
        if let Some(handle) = worker.take() {
            handle.join().map_err(|_| "cache worker panicked")??;
        }
        Ok(())
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[derive(Clone)]
pub struct PayloadCache {
    inner: Arc<Inner>,
}
impl PayloadCache {
    pub fn stream(&self) -> CacheRef { self.entry() }
    pub fn new(config: CacheConfig) -> Result<Self, String> {
        if config.decode_bytes == 0 || config.decode_bytes > 64*1024*1024 || config.decode_input_bytes > 64*1024*1024 {
            return Err("invalid decode limits".into());
        }
        if config.queue_chunks == 0
            || config.queue_chunks > 4096
            || config.max_entries == 0
            || config.max_entries > 65536
        {
            return Err("invalid cache queue/entry count limit".into());
        }
        let directory = RunDirectory::create(&config.root).map_err(|e| e.to_string())?;
        let path = directory.path.clone();
        let (sender, receiver) = mpsc::sync_channel(config.queue_chunks);
        let worker = thread::Builder::new()
            .name("protocol-payload-cache".into())
            .spawn(move || {
                let mut worker = Worker::new(config, directory);
                while let Ok(command) = receiver.recv() {
                    match command {
                        Command::Register(ticket) => {
                            worker.register(ticket);
                        }
                        Command::Append(ticket, side, bytes) => {
                            worker.append(&ticket, side, &bytes);
                            ticket.pending.fetch_sub(1, Ordering::AcqRel);
                        }
                        Command::Query(query, response) => {
                            let _ = response.send(worker.query(query));
                        }
                    }
                }
                // Close payload handles before removing their files on Windows.
                for record in worker.records.values() {
                    record.ticket.stop("cache closed");
                }
                worker.records.clear();
                worker
                    .directory
                    .cleanup()
                    .map_err(|e| format!("cache cleanup: {e}"))
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            inner: Arc::new(Inner {
                sender: Mutex::new(Some(sender)),
                worker: Mutex::new(Some(worker)),
                next: AtomicU64::new(1),
                completion: AtomicU64::new(1),
                directory: path,
            }),
        })
    }
    pub fn directory(&self) -> &std::path::Path {
        &self.inner.directory
    }
    pub(crate) fn entry(&self) -> CacheRef {
        let id = self.inner.next.fetch_add(1, Ordering::Relaxed);
        let ticket = Arc::new(Ticket {
            id,
            state: Mutex::new(CacheSnapshot {
                id,
                ..CacheSnapshot::default()
            }),
            info: Mutex::new(Default::default()),
            accepting: AtomicBool::new(true),
            pending: AtomicUsize::new(0),
            finished: AtomicU64::new(0),
        });
        if let Err(reason) = self.inner.try_send(Command::Register(ticket.clone())) {
            ticket.stop(reason);
        }
        CacheRef {
            ticket,
            owner: Arc::downgrade(&self.inner),
        }
    }
    /// A barrier for earlier accepted writes. Does not complete HTTP messages.
    pub fn stats(&self) -> Result<CacheStats, String> {
        match self.inner.query(Query::Stats)? {
            Answer::Stats(stats) => Ok(stats),
            _ => unreachable!(),
        }
    }
    pub fn status(&self, id: u64) -> Result<Option<CacheSnapshot>, String> {
        match self.inner.query(Query::Status(id))? {
            Answer::Status(status) => Ok(status),
            _ => unreachable!(),
        }
    }
    /// Read a retained encoded-body range (maximum 1 MiB per call).
    pub fn read(
        &self,
        id: u64,
        direction: Direction,
        offset: u64,
        length: usize,
    ) -> Result<CachedPayload, String> {
        if length > 1024*1024 {
            return Err("cache read range exceeds 1 MiB".into());
        }
        self.payload(Query::Read {
            id,
            side: direction.index(),
            offset,
            length,
            decode: false,
            decoded_limit: 0,
        })
    }
    /// Decode only a completely captured body, on demand. The result is never
    /// retained on disk; the configured budget defaults to 4 MiB (maximum 64 MiB).
    pub fn decode(
        &self,
        id: u64,
        direction: Direction,
        limit: usize,
    ) -> Result<CachedPayload, String> {
        self.decode_preview(id,direction,limit,0)
    }
    /// Decode fully within the configured budget, returning only the requested prefix.
    /// A zero preview returns the full decoded value for library callers.
    pub fn decode_preview(&self,id:u64,direction:Direction,limit:usize,preview:usize) -> Result<CachedPayload,String> {
        if limit > 64*1024*1024 || preview > 1024*1024 {return Err("invalid decode/preview limit".into());}
        self.payload(Query::Read {
            id,
            side: direction.index(),
            offset: 0,
            length: preview,
            decode: true,
            decoded_limit: limit,
        })
    }
    fn payload(&self, query: Query) -> Result<CachedPayload, String> {
        match self.inner.query(query)? {
            Answer::Payload(payload) => Ok(payload),
            _ => unreachable!(),
        }
    }
    /// Closes all clones, drains the queue and removes this run's files.
    pub fn shutdown(&self) -> Result<(), String> {
        self.inner.shutdown()
    }
}

struct Record {
    ticket: Arc<Ticket>,
    files: [Option<File>; 2],
    stored: [u64; 2],
    stopped: bool,
}
struct Worker {
    config: CacheConfig,
    directory: RunDirectory,
    records: BTreeMap<u64, Record>,
    retired: BTreeMap<u64, CacheSnapshot>,
    retired_order: VecDeque<u64>,
    stats: CacheStats,
}
impl Worker {
    fn new(config: CacheConfig, directory: RunDirectory) -> Self {
        let stats = CacheStats {
            recovered_runs: directory.recovered,
            warnings: directory.warnings.clone(),
            ..CacheStats::default()
        };
        Self {
            config,
            directory,
            records: BTreeMap::new(),
            retired: BTreeMap::new(),
            retired_order: VecDeque::new(),
            stats,
        }
    }
    fn path(&self, id: u64, side: usize) -> PathBuf {
        self.directory.path.join(format!(
            "{id:016x}.{}.body",
            if side == 0 { "request" } else { "response" }
        ))
    }
    fn oldest(&self) -> Option<u64> {
        self.records
            .iter()
            .filter_map(|(&id, record)| {
                let order = record.ticket.finished.load(Ordering::Acquire);
                (order != 0 && record.ticket.pending.load(Ordering::Acquire) == 0)
                    .then_some((id, order))
            })
            .min_by_key(|(_, order)| *order)
            .map(|(id, _)| id)
    }
    fn evict(&mut self, id: u64) -> Result<(), String> {
        let paths = [self.path(id, 0), self.path(id, 1)];
        let record = self.records.get_mut(&id).unwrap();
        record.ticket.stop("payload evicted");
        locked(&record.ticket.state).evicted = true;
        for (side, path) in paths.iter().enumerate() {
            if record.files[side].take().is_some() || record.stored[side] != 0 {
                fs::remove_file(path).map_err(|e| format!("payload eviction failed: {e}"))?;
                self.stats.used_bytes -= record.stored[side];
                record.stored[side] = 0;
            }
        }
        let record = self.records.remove(&id).unwrap();
        let mut snapshot = record.ticket.snapshot();
        snapshot.request_bytes = 0;
        snapshot.response_bytes = 0;
        *locked(&record.ticket.state) = snapshot.clone();
        self.retired.insert(id, snapshot);
        self.retired_order.push_back(id);
        while self.retired_order.len() > self.config.max_entries {
            self.retired
                .remove(&self.retired_order.pop_front().unwrap());
        }
        self.stats.evicted_entries += 1;
        Ok(())
    }
    fn register(&mut self, ticket: Arc<Ticket>) {
        if self.records.contains_key(&ticket.id) {
            return;
        }
        if self.records.len() >= self.config.max_entries {
            if let Some(id) = self.oldest() {
                if let Err(reason) = self.evict(id) {
                    ticket.stop(&reason);
                    return;
                }
            } else {
                ticket.stop("cache entry count limit");
                return;
            }
        }
        self.records.insert(
            ticket.id,
            Record {
                ticket,
                files: Default::default(),
                stored: [0; 2],
                stopped: false,
            },
        );
    }
    fn append(&mut self, ticket: &Arc<Ticket>, side: usize, bytes: &[u8]) {
        let Some(record) = self.records.get(&ticket.id) else {
            return;
        };
        if record.stopped {
            return;
        }
        let entry_left = self
            .config
            .entry_bytes
            .saturating_sub(record.stored.iter().sum());
        let wanted = (bytes.len() as u64).min(entry_left);
        while self.config.total_bytes - self.stats.used_bytes < wanted {
            let Some(id) = self.oldest() else {
                break;
            };
            if let Err(reason) = self.evict(id) {
                self.stop(ticket.id, &reason);
                return;
            }
        }
        let keep = wanted.min(self.config.total_bytes - self.stats.used_bytes) as usize;
        if keep != 0 {
            let path = self.path(ticket.id, side);
            let record = self.records.get_mut(&ticket.id).unwrap();
            let result = (|| -> std::io::Result<()> {
                if record.files[side].is_none() {
                    record.files[side] = Some(
                        OpenOptions::new()
                            .read(true)
                            .append(true)
                            .create_new(true)
                            .open(path)?,
                    );
                }
                // Reserve the entire write first, including any partially
                // successful write on a full disk. Never refund unknown bytes.
                self.stats.used_bytes += keep as u64;
                self.stats.peak_bytes = self.stats.peak_bytes.max(self.stats.used_bytes);
                let file = record.files[side].as_mut().unwrap();
                let result = file.write_all(&bytes[..keep]);
                let actual = if result.is_ok() {
                    record.stored[side] + keep as u64
                } else {
                    file.metadata()
                        .map_or(record.stored[side] + keep as u64, |m| m.len())
                };
                let actual = actual.clamp(record.stored[side], record.stored[side] + keep as u64);
                self.stats.used_bytes -= record.stored[side] + keep as u64 - actual;
                record.stored[side] = actual;
                let mut state = locked(&ticket.state);
                state.request_bytes = record.stored[0];
                state.response_bytes = record.stored[1];
                result
            })();
            if let Err(error) = result {
                self.stop(ticket.id, &format!("cache write failed: {error}"));
                return;
            }
        }
        if keep < bytes.len() {
            self.stop(
                ticket.id,
                if wanted < bytes.len() as u64 && keep as u64 == wanted {
                    "per-exchange payload limit"
                } else {
                    "total payload limit (active entries protected)"
                },
            );
        }
    }
    fn stop(&mut self, id: u64, reason: &str) {
        if let Some(record) = self.records.get_mut(&id) {
            record.stopped = true;
            record.ticket.stop(reason);
        }
    }
    fn query(&mut self, query: Query) -> Result<Answer, String> {
        match query {
            Query::Stats => {
                self.stats.entries = self.records.len();
                Ok(Answer::Stats(self.stats.clone()))
            }
            Query::Status(id) => Ok(Answer::Status(
                self.records
                    .get(&id)
                    .map(|r| r.ticket.snapshot())
                    .or_else(|| self.retired.get(&id).cloned()),
            )),
            Query::Read {
                id,
                side,
                offset,
                length,
                decode,
                decoded_limit,
            } => {
                let record = self
                    .records
                    .get_mut(&id)
                    .ok_or("payload unavailable (evicted or not admitted)")?;
                let snapshot = record.ticket.snapshot();
                if snapshot.evicted {
                    return Err("payload evicted".into());
                }
                let info = locked(&record.ticket.info)[side].clone();
                let stored = record.stored[side];
                let count = if decode {
                    if !snapshot.finished
                        || snapshot.pending_chunks != 0
                        || !info.complete
                        || info.bytes != stored
                    {
                        return Err("cannot decode incomplete cached body".into());
                    }
                    // Bound the temporary input allocation independently of
                    // user-supplied disk quotas, including on 32-bit builds.
                    if stored > self.config.decode_input_bytes as u64 {
                        return Err(format!("decode input exceeds {} MiB",self.config.decode_input_bytes/1024/1024));
                    }
                    stored as usize
                } else {
                    (stored.saturating_sub(offset)).min(length as u64) as usize
                };
                let mut bytes = vec![0; count];
                if count != 0 {
                    let file = record.files[side]
                        .as_mut()
                        .ok_or("payload file unavailable")?;
                    file.seek(SeekFrom::Start(offset))
                        .and_then(|_| file.read_exact(&mut bytes))
                        .map_err(|e| e.to_string())?;
                }
                if decode && !info.bodyless {
                    bytes = crate::decode::body(&info.headers, &bytes, decoded_limit.min(self.config.decode_bytes))?;
                }
                let decoded_bytes=if decode {bytes.len()} else {0};
                if decode && length!=0 {bytes.truncate(length);}
                Ok(Answer::Payload(CachedPayload {
                    cache: snapshot,
                    direction: if side == 0 {
                        Direction::Client
                    } else {
                        Direction::Server
                    },
                    offset,
                    data_base64: bytes,
                    decoded: decode,
                    decoded_bytes,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_queue_stops_capture_without_blocking_or_skipping_a_gap() {
        // Intentionally leave the receiver unserviced: a deterministic slow
        // disk model, without sleeps or changing production worker behavior.
        let (sender, receiver) = mpsc::sync_channel(1);
        let cache = PayloadCache {
            inner: Arc::new(Inner {
                sender: Mutex::new(Some(sender)),
                worker: Mutex::new(None),
                next: AtomicU64::new(1),
                completion: AtomicU64::new(1),
                directory: PathBuf::new(),
            }),
        };
        let reference = cache.entry();
        assert!(matches!(receiver.recv().unwrap(), Command::Register(_)));
        reference.append(1, &vec![b'x'; CHUNK * 3]);
        assert_eq!(
            reference.snapshot().reason.as_deref(),
            Some("cache queue full")
        );
        assert_eq!(reference.snapshot().pending_chunks, 1);
        match receiver.recv().unwrap() {
            Command::Append(ticket, side, bytes) => {
                assert_eq!(side, 1);
                assert_eq!(bytes.len(), CHUNK);
                ticket.pending.fetch_sub(1, Ordering::AcqRel);
            }
            _ => panic!("expected retained prefix"),
        }
        reference.append(1, b"later bytes must not bridge the missing data");
        assert!(receiver.try_recv().is_err());
        assert_eq!(reference.snapshot().pending_chunks, 0);
    }
}
