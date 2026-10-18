//! Passive analysis is deliberately independent of TLS forwarding and of the GUI
//! preview queue. Only this worker parses/decompresses; the PRC uses try_send.
use proxylane_protocol::{
    cache::{CacheConfig, CacheRef, PayloadCache},
    Analyzer, Connection, Direction, Limits, Output, Protocol,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const QUEUE: usize = 512; // <= 32 MiB for maximum-size UDP datagrams; TCP chunks stay 16 KiB
#[cfg(test)]
const CONNECTIONS: usize = 32;
const RECORDS: usize = 256;
const RECORD_BYTES: usize = 16 * 1024 * 1024;
const POLL_BYTES: usize = 2 * 1024 * 1024;
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct Ticket {
    pending: AtomicUsize,
    closed: AtomicBool,
    lost: AtomicBool,
}
enum Event {
    Open(u64, Connection, Option<Vec<u8>>, bool, Arc<Ticket>),
    Data(u64, usize, u64, Vec<u8>, Arc<Ticket>),
    Datagram(u64, usize, Vec<u8>, Arc<Ticket>),
    Eof(u64, usize, bool, Arc<Ticket>),
    State(u64, usize, Arc<Ticket>),
    Barrier(mpsc::Sender<()>),
    StopCapture(mpsc::Sender<()>),
    Shutdown,
}
#[derive(Default)]
struct Results {
    sequence: u64,
    bytes: usize,
    evicted: u64,
    records: VecDeque<(u64, Value, usize)>,
}
impl Results {
    fn add(&mut self, mut value: Value) {
        self.sequence += 1;
        value["sequence"] = self.sequence.into();
        let size = serde_json::to_vec(&value).map_or(POLL_BYTES + 1, |v| v.len());
        // Keep each poll bounded, including a single pathological record.
        if size > POLL_BYTES {
            value = json!({"type":"analysis_diagnostic", "sequence":self.sequence,
                "connection":value["connection"], "detail":"result exceeds retention limit"});
        }
        let size = serde_json::to_vec(&value).unwrap().len();
        self.bytes += size;
        self.records.push_back((self.sequence, value, size));
        while self.bytes > RECORD_BYTES || self.records.len() > RECORDS {
            if let Some((_, _, size)) = self.records.pop_front() {
                self.bytes -= size;
                self.evicted += 1;
            }
        }
    }
}

pub struct Runtime {
    pub(crate) options: crate::options::Options,
    sender: SyncSender<Event>,
    worker: Mutex<Option<JoinHandle<()>>>,
    stopping: AtomicBool,
    // Odd epochs accept capture. Even epochs are paused; old taps never resume.
    capture_epoch: Mutex<u64>,
    next: AtomicU64,
    active: Arc<AtomicUsize>,
    rejected: AtomicU64,
    results: Arc<Mutex<Results>>,
    cache: Option<PayloadCache>,
    cache_error: Option<String>,
    pub run_id: String,
}
impl Runtime {
    pub fn lifecycle(&self, epoch: u64, identity: &Connection, state: &str, protocol: &str, problem: &str, skipped: bool) {
        let gate = lock(&self.capture_epoch);
        if *gate != epoch || epoch % 2 == 0 || self.stopping.load(Ordering::Acquire) { return; }
        lock(&self.results).add(json!({"type":"connection", "connection":identity, "protocol":protocol,
            "status":state,"detail":problem,"upstream_verification_skipped":skipped}));
    }
    pub fn capture_epoch(&self) -> u64 { *lock(&self.capture_epoch) }
    pub fn start_capture(&self) {
        let mut epoch = lock(&self.capture_epoch);
        if *epoch % 2 == 0 { *epoch += 1; }
    }
    pub fn stop_capture(&self) -> Result<(), String> {
        // Only close the gate under the producer lock. Never hold it while
        // waiting for analysis or disk I/O: forwarding must keep running.
        {
            let mut epoch = lock(&self.capture_epoch);
            if *epoch % 2 != 0 { *epoch += 1; }
        }
        let (tx, rx) = mpsc::channel();
        self.sender.send(Event::StopCapture(tx)).map_err(|_| "analysis worker unavailable")?;
        rx.recv().map_err(|_| "analysis worker unavailable")?;
        // stats is a FIFO disk-worker barrier, retaining all existing payloads.
        if let Some(cache) = &self.cache { cache.stats()?; }
        Ok(())
    }
    pub fn configured() -> Result<Arc<Self>, String> {
        let mut config = CacheConfig::default();
        if let Some(root) = std::env::var_os("PROXYLANE_PROTOCOL_CACHE_ROOT") {
            config.root = root.into();
        }
        for (name, limit) in [
            ("PROXYLANE_PROTOCOL_ENTRY_BYTES", &mut config.entry_bytes),
            ("PROXYLANE_PROTOCOL_TOTAL_BYTES", &mut config.total_bytes),
        ] {
            if let Ok(value) = std::env::var(name) {
                *limit = value.parse().map_err(|_| format!("invalid {name}"))?;
            }
        }
        let options=crate::options::current();
        if std::env::var_os("PROXYLANE_PROTOCOL_ENTRY_BYTES").is_none() {config.entry_bytes=options.entry_mib*1024*1024;}
        if std::env::var_os("PROXYLANE_PROTOCOL_TOTAL_BYTES").is_none() {config.total_bytes=options.total_mib*1024*1024;}
        config.max_entries=(options.history_rows*2).max(4096);
        Self::with_options(config,options)
    }
    pub fn new(config: CacheConfig) -> Result<Arc<Self>, String> {
        Self::with_options(config,crate::options::Options::default())
    }
    fn with_options(mut config:CacheConfig, options:crate::options::Options) -> Result<Arc<Self>,String> {
        options.validate()?;
        config.decode_bytes=options.decode_mib*1024*1024;
        config.decode_input_bytes=config.entry_bytes.min(64*1024*1024) as usize;
        let worker_options=options.clone();
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
        let (cache, cache_error) = match PayloadCache::new(config) {
            Ok(cache) => (Some(cache), None),
            Err(e) => (None, Some(e)),
        };
        let results = Arc::new(Mutex::new(Results::default()));
        let active = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = mpsc::sync_channel(QUEUE);
        let worker_results = results.clone();
        let worker_active = active.clone();
        let worker_cache = cache.clone();
        let worker = thread::Builder::new()
            .name("protocol-analysis".into())
            .spawn(move || {
                Worker {
                    options: worker_options,
                    connections: BTreeMap::new(),
                    cache: worker_cache,
                    results: worker_results,
                    active: worker_active,
                }
                .run(receiver);
            })
            .map_err(|e| e.to_string())?;
        Ok(Arc::new(Self {
            options,
            sender,
            worker: Mutex::new(Some(worker)),
            stopping: AtomicBool::new(false),
            capture_epoch: Mutex::new(1),
            next: AtomicU64::new(1),
            active,
            rejected: AtomicU64::new(0),
            results,
            cache,
            cache_error,
            run_id: format!("{:032x}", u128::from_le_bytes(random)),
        }))
    }
    pub fn tap(self: &Arc<Self>, connection: Connection, alpn: Option<Vec<u8>>) -> Option<Tap> {
        self.tap_transport(connection, alpn, true)
    }
    pub fn tap_transport(self: &Arc<Self>, connection: Connection, alpn: Option<Vec<u8>>, decrypted: bool) -> Option<Tap> {
        self.tap_at(self.capture_epoch(), connection, alpn, decrypted)
    }
    pub fn tap_at(self: &Arc<Self>, epoch: u64, mut connection: Connection, alpn: Option<Vec<u8>>, decrypted: bool) -> Option<Tap> {
        let gate = lock(&self.capture_epoch);
        if *gate != epoch || epoch % 2 == 0 || self.stopping.load(Ordering::Acquire) {
            return None;
        }
        if self
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.options.connections).then_some(n + 1)
            })
            .is_err()
        {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        connection.decrypted = decrypted;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let ticket = Arc::new(Ticket {
            pending: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            lost: AtomicBool::new(false),
        });
        if self
            .sender
            .try_send(Event::Open(id, connection, alpn, decrypted, ticket.clone()))
            .is_err()
        {
            self.active.fetch_sub(1, Ordering::AcqRel);
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(Tap {
            owner: self.clone(),
            epoch,
            id,
            ticket,
            offsets: [0; 2],
            ended: [false; 2],
        })
    }
    // Query calls belong on a consumer/background thread, never the PRC thread.
    pub fn query(&self, request: &Value) -> Result<Value, String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("analysis stopped".into());
        }
        let (tx, rx) = mpsc::channel();
        self.sender
            .send(Event::Barrier(tx))
            .map_err(|_| "analysis worker unavailable")?;
        rx.recv().map_err(|_| "analysis worker unavailable")?;
        let kind = request["type"].as_str().ok_or("missing query type")?;
        let result = match kind {
            "stats" => {
                let cache = self.cache.as_ref().map(PayloadCache::stats).transpose()?;
                let records = lock(&self.results);
                json!({"type":"stats", "active_connections":self.active.load(Ordering::Acquire),
                    "rejected_connections":self.rejected.load(Ordering::Relaxed),
                    "last_sequence":records.sequence, "retained_records":records.records.len(),
                    "retained_bytes":records.bytes, "evicted_records":records.evicted,
                    "cache":cache, "cache_error":self.cache_error})
            }
            "poll" => {
                let after = request["after"].as_u64().unwrap_or(0);
                let limit = request["limit"].as_u64().unwrap_or(16).clamp(1, 64) as usize;
                let records = lock(&self.results);
                let mut bytes = 0;
                let mut output = Vec::new();
                let mut next = after;
                for (seq, value, size) in &records.records {
                    if *seq <= after {
                        continue;
                    }
                    if output.len() == limit || bytes + size > POLL_BYTES {
                        break;
                    }
                    bytes += size;
                    next = *seq;
                    output.push(value.clone());
                }
                let oldest = records
                    .records
                    .front()
                    .map_or(records.sequence + 1, |r| r.0);
                json!({"type":"records", "records":output, "next":next,
                    "lost_before":oldest.saturating_sub(after.saturating_add(1)),
                    "last_sequence":records.sequence})
            }
            "cache_status" | "cache_read" | "cache_decode" | "dns_read" | "doh_read" => {
                if request["run_id"].as_str() != Some(&self.run_id) {
                    return Err("stale or missing run_id".into());
                }
                let cache = self.cache.as_ref().ok_or("payload cache unavailable")?;
                let id = request["cache_id"].as_u64().ok_or("missing cache_id")?;
                if kind == "cache_status" {
                    json!({"type":"cache_status", "cache":cache.status(id)?})
                } else {
                    let direction: Direction = serde_json::from_value(request["direction"].clone())
                        .map_err(|e| e.to_string())?;
                    let payload = if kind == "cache_read" || kind == "dns_read" {
                        let length =
                            request["length"].as_u64().unwrap_or(65536).min(1024*1024+1) as usize;
                        cache.read(
                            id,
                            direction,
                            request["offset"].as_u64().unwrap_or(0),
                            length,
                        )?
                    } else {
                        let preview=request["preview_bytes"].as_u64().unwrap_or(65536).clamp(1,1024*1024) as usize;
                        // DNS parsing needs the complete wire message even when the GUI
                        // displays a smaller prefix. Its wire size is bounded to 65535.
                        cache.decode_preview(id, direction, self.options.decode_mib * 1024 * 1024,
                            if kind=="doh_read" {preview.max(65535)} else {preview})?
                    };
                    let decoded = if (kind == "dns_read" || kind == "doh_read") && !payload.data_base64.is_empty() {
                        Some(proxylane_protocol::dns::decode(&payload.data_base64).map(|p|p.text))
                    } else {None};
                    json!({"type":"cache_payload", "payload":payload,
                        "text":decoded.as_ref().and_then(|r|r.as_ref().ok()),
                        "decode_error":decoded.as_ref().and_then(|r|r.as_ref().err())})
                }
            }
            _ => return Err("unknown protocol query".into()),
        };
        let mut result = result;
        result["run_id"] = self.run_id.clone().into();
        Ok(result)
    }
    pub fn shutdown(&self) -> Result<(), String> {
        let mut worker = lock(&self.worker);
        self.stopping.store(true, Ordering::Release);
        if let Some(handle) = worker.take() {
            let _ = self.sender.send(Event::Shutdown);
            handle.join().map_err(|_| "analysis worker panicked")?;
        }
        if let Some(cache) = &self.cache {
            cache.shutdown()?;
        }
        Ok(())
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

pub struct Tap {
    owner: Arc<Runtime>,
    epoch: u64,
    id: u64,
    ticket: Arc<Ticket>,
    offsets: [u64; 2],
    ended: [bool; 2],
}
impl Tap {
    pub fn transport_result(&mut self, error: usize) { self.send(Event::State(self.id,error,self.ticket.clone())); }
    fn accepting(&self) -> bool {
        !self.ticket.lost.load(Ordering::Acquire) && !self.ticket.closed.load(Ordering::Acquire)
            && !self.owner.stopping.load(Ordering::Acquire)
    }
    fn send(&self, event: Event) {
        let gate = lock(&self.owner.capture_epoch);
        if *gate != self.epoch || self.epoch % 2 == 0 || !self.accepting() { return; }
        self.enqueue(event);
    }
    fn enqueue(&self, event: Event) {
        self.ticket.pending.fetch_add(1, Ordering::AcqRel);
        if self.owner.sender.try_send(event).is_err() {
            // Out-of-band terminal flag cannot itself be lost in the full queue.
            self.ticket.lost.store(true, Ordering::Release);
            self.ticket.pending.fetch_sub(1, Ordering::AcqRel);
        }
    }
    pub fn data(&mut self, side: usize, bytes: &[u8]) {
        let gate = lock(&self.owner.capture_epoch);
        if *gate != self.epoch || self.epoch % 2 == 0 || !self.accepting() { return; }
        for chunk in bytes.chunks(16384) {
            self.enqueue(Event::Data(self.id, side, self.offsets[side], chunk.to_vec(), self.ticket.clone()));
            self.offsets[side] += chunk.len() as u64;
            if self.ticket.lost.load(Ordering::Acquire) { break; }
        }
    }
    pub fn datagram(&mut self, side: usize, bytes: &[u8]) {
        let gate = lock(&self.owner.capture_epoch);
        if bytes.len() > 65535 || *gate != self.epoch || self.epoch % 2 == 0 || !self.accepting() { return; }
        self.enqueue(Event::Datagram(self.id, side, bytes.to_vec(), self.ticket.clone()));
    }
    pub fn eof(&mut self, side: usize, clean: bool) {
        if !self.ended[side] && !self.ticket.lost.load(Ordering::Acquire) {
            self.ended[side] = true;
            self.send(Event::Eof(self.id, side, clean, self.ticket.clone()));
        }
    }
}
impl Drop for Tap {
    fn drop(&mut self) {
        self.ticket.closed.store(true, Ordering::Release);
    }
}

struct Stream {
    dns: Option<crate::dns::Dns>,
    quic: crate::quic_probe::Probe,
    identity: Connection,
    ticket: Arc<Ticket>,
    analyzer: Option<Analyzer>,
    sniff: Vec<u8>,
    detect: bool,
    decrypted: bool,
    encrypted: bool,
    cache: Option<CacheRef>,
    counts: [u64; 2],
    datagrams: [Vec<(u64, usize)>; 2],
    packet_counts: [u64; 2],
    ended: [bool; 2],
    dirty: bool,
    published: Instant,
    opened: Instant,
}
struct Worker {
    options:crate::options::Options,
    connections: BTreeMap<u64, Stream>,
    cache: Option<PayloadCache>,
    results: Arc<Mutex<Results>>,
    active: Arc<AtomicUsize>,
}
impl Worker {
    fn records(&self, records: Vec<Value>) {
        let mut results=lock(&self.results);for record in records {results.add(record);}
    }
    fn output(&self, out: Vec<Output>) {
        for output in out {
            if let Ok(mut value) = serde_json::to_value(output) {
                crate::doh::annotate(&mut value);
                lock(&self.results).add(value);
            }
        }
    }
    fn diagnostic(&self, identity: &Connection, detail: &str) {
        lock(&self.results)
            .add(json!({"type":"analysis_diagnostic", "connection":identity, "detail":detail}));
    }
    fn parser(&self, identity: Connection, protocol: Protocol) -> Analyzer {
        let limits = Limits {
            encoded_body: 65536,
            decoded_body: 65536,
            pending: self.options.pending_requests,
            ..Limits::default()
        };
        if let Some(cache) = &self.cache {
            Analyzer::with_cache(identity, protocol, limits, cache.clone())
        } else {
            Analyzer::new(identity, protocol, limits)
        }
        .expect("constant valid limits")
    }
    fn opaque(&self, stream: &mut Stream) {
        stream.detect = false;
        stream.cache = self.cache.as_ref().map(PayloadCache::stream);
        if !stream.sniff.is_empty() {
            let bytes = std::mem::take(&mut stream.sniff);
            self.opaque_data(stream, 0, &bytes);
        }
        stream.dirty = true;
    }
    fn opaque_data(&self, stream: &mut Stream, side: usize, bytes: &[u8]) {
        stream.counts[side] += bytes.len() as u64;
        if let Some(cache) = &stream.cache { cache.append_stream(direction(side), bytes); }
        stream.dirty = true;
    }
    fn publish(&self, stream: &mut Stream, finished: bool) {
        if stream.dns.is_some() { stream.dirty=false; return; }
        if stream.counts == [0,0] && stream.packet_counts == [0,0] { return; }
        let lost = stream.ticket.lost.load(Ordering::Acquire);
        lock(&self.results).add(json!({"type":"stream", "connection":stream.identity,
            "protocol":if stream.quic.version.is_some() {"quic"} else if stream.identity.transport == "udp" {"udp"} else if stream.decrypted {"tls_stream"} else if stream.encrypted {"tls_encrypted"} else {"tcp"},
            "quic":stream.quic.summary(),
            "stream":{"sent_bytes":stream.counts[0], "received_bytes":stream.counts[1],
                "finished":finished, "complete":stream.ended.iter().all(|v| *v) && !lost,
                "problem":if lost {Some("analysis queue overflow; only a contiguous prefix was captured")} else {None},
                "cache":stream.cache, "datagrams":stream.datagrams, "packet_counts":stream.packet_counts}}));
        stream.dirty = false;
        stream.published = Instant::now();
    }
    fn progress(&mut self) {
        let ids: Vec<_> = self.connections.keys().copied().collect();
        for id in ids {
            let mut stream = self.connections.remove(&id).unwrap();
            if let Some(dns)=&mut stream.dns {self.records(dns.expire(&stream.identity,None));}
            // Bound detection latency for small/idle ASCII protocols as well as memory.
            if stream.detect && !stream.sniff.is_empty() && stream.opened.elapsed() >= Duration::from_secs(2) {
                self.opaque(&mut stream);
            }
            if stream.analyzer.is_none() && !stream.detect && stream.dirty
                && stream.published.elapsed() >= Duration::from_millis(500) {
                self.publish(&mut stream, false);
            }
            self.connections.insert(id, stream);
        }
    }
    fn reap(&mut self, all: bool, stopped: bool) {
        let ids: Vec<_> = self.connections.iter().filter_map(|(id, stream)| {
            (all || (stream.ticket.pending.load(Ordering::Acquire) == 0 &&
                (stream.ticket.closed.load(Ordering::Acquire) || stream.ticket.lost.load(Ordering::Acquire))))
                .then_some(*id)
        }).collect();
        for id in ids {
            let mut stream = self.connections.remove(&id).unwrap();
            let lost = stream.ticket.lost.load(Ordering::Acquire);
            if let Some(dns) = &mut stream.dns {
                self.records(dns.close(&stream.identity,self.cache.as_ref(),if lost {"DNS capture queue overflow"}else{"DNS capture ended before response"}));
            } else if let Some(parser) = &mut stream.analyzer {
                self.output(parser.close());
                if lost { self.diagnostic(&stream.identity, "analysis queue overflow; reconstruction stopped for this connection"); }
            } else {
                if stream.detect { self.opaque(&mut stream); }
                if let Some(cache) = &stream.cache {
                    cache.finish_stream(stream.counts, stream.ended.iter().all(|v| *v) && !lost);
                }
                self.publish(&mut stream, true);
            }
            if stream.identity.transport != "udp" && !stream.decrypted {
                lock(&self.results).add(json!({"type":"connection","connection":stream.identity,"protocol":"tcp","status":if stopped {"Stopped"}else{"Closed"}}));
            }
            self.active.fetch_sub(1, Ordering::AcqRel);
        }
    }
    fn run(mut self, receiver: Receiver<Event>) {
        let mut progress = Instant::now();
        loop {
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(Event::Open(id, identity, alpn, decrypted, ticket)) => {
                    let protocol = match alpn.as_deref() {
                        Some(b"h2") => Some(Protocol::H2),
                        Some(b"http/1.1") => Some(Protocol::Http1),
                        _ => None,
                    };
                    let udp = identity.transport == "udp";
                    let dns = if identity.server_port==53 {Some(crate::dns::Dns::default())}else{None};
                    let is_dns=dns.is_some();
                    let analyzer = protocol.map(|p| self.parser(identity.clone(), p));
                    let mut stream = Stream { identity, ticket, analyzer, sniff: Vec::new(), dns, quic:Default::default(),
                        detect: alpn.is_none() && !udp && !is_dns, decrypted, encrypted: false, cache: None,
                        counts: [0;2], datagrams: [Vec::new(), Vec::new()], packet_counts: [0;2], ended: [false;2], dirty: false,
                        published: Instant::now() - Duration::from_secs(1), opened: Instant::now() };
                    if !is_dns && (udp || (protocol.is_none() && alpn.is_some())) { self.opaque(&mut stream); }
                    if !udp && !decrypted {
                        lock(&self.results).add(json!({"type":"connection","connection":stream.identity,"protocol":"tcp","status":"Connecting"}));
                    }
                    self.connections.insert(id, stream);
                }
                Ok(Event::Data(id, side, offset, bytes, ticket)) => {
                    if let Some(mut stream) = self.connections.remove(&id) {
                        if let Some(dns)=&mut stream.dns {
                            self.records(dns.tcp(&stream.identity,self.cache.as_ref(),side,&bytes));
                        } else if stream.detect {
                            if side != 0 {
                                self.opaque(&mut stream);
                                self.opaque_data(&mut stream, side, &bytes);
                            } else {
                                stream.sniff.extend_from_slice(&bytes);
                                const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                                let mut opaque = false;
                                let protocol = if stream.sniff.starts_with(PREFACE) {
                                    Some(Protocol::H2)
                                } else if PREFACE.starts_with(&stream.sniff) { None }
                                else if !stream.decrypted && stream.sniff[0] == 0x16 {
                                    if stream.sniff.len() >= 3 {
                                        stream.encrypted = stream.sniff[1] == 3 && stream.sniff[2] <= 3;
                                        opaque = true;
                                    }
                                    None
                                } else if let Some(end) = stream.sniff.windows(2).position(|v| v == b"\r\n") {
                                    let parts: Vec<_> = stream.sniff[..end].split(|c| *c == b' ').collect();
                                    if parts.len() == 3 && !parts[0].is_empty() && !parts[1].is_empty()
                                        && parts[0].iter().all(|c| c.is_ascii_uppercase())
                                        && matches!(parts[2], b"HTTP/1.0" | b"HTTP/1.1") {
                                        Some(Protocol::Http1)
                                    } else { opaque = true; None }
                                } else {
                                    opaque = stream.sniff.len() > 8192 || stream.sniff.iter().any(|b| *b == 0 || *b >= 128);
                                    None
                                };
                                if let Some(protocol) = protocol {
                                    let mut parser = self.parser(stream.identity.clone(), protocol);
                                    self.output(parser.push(Direction::Client, 0, &stream.sniff));
                                    stream.analyzer = Some(parser);
                                    stream.detect = false;
                                    stream.sniff = Vec::new();
                                } else if opaque { self.opaque(&mut stream); }
                            }
                        } else if let Some(parser) = &mut stream.analyzer {
                            self.output(parser.push(direction(side), offset, &bytes));
                        } else { self.opaque_data(&mut stream, side, &bytes); }
                        self.connections.insert(id, stream);
                    }
                    ticket.pending.fetch_sub(1, Ordering::AcqRel);
                }
                Ok(Event::Datagram(id, side, bytes, ticket)) => {
                    if let Some(mut stream) = self.connections.remove(&id) {
                        // Only probe DNS off-port at the beginning of a flow.
                        if stream.dns.is_none() && stream.packet_counts==[0,0] && proxylane_protocol::dns::decode(&bytes).is_ok() {
                            stream.dns=Some(crate::dns::Dns::default());
                            if let Some(c)=stream.cache.take(){c.finish_stream([0,0],true);}
                        }
                        if let Some(dns)=&mut stream.dns {
                            self.records(dns.feed(&stream.identity,self.cache.as_ref(),side,&bytes));
                        } else {
                            stream.quic.feed(side,&bytes);
                            if stream.datagrams[side].len() < self.options.udp_packets { stream.datagrams[side].push((stream.counts[side], bytes.len())); }
                            stream.packet_counts[side] += 1;
                            self.opaque_data(&mut stream, side, &bytes);
                        }
                        self.connections.insert(id, stream);
                    }
                    ticket.pending.fetch_sub(1, Ordering::AcqRel);
                }
                Ok(Event::Eof(id, side, clean, ticket)) => {
                    if let Some(mut stream) = self.connections.remove(&id) {
                        stream.ended[side] = clean;
                        if let Some(parser) = &mut stream.analyzer { self.output(parser.eof(direction(side), clean)); }
                        else { stream.dirty = true; }
                        self.connections.insert(id, stream);
                    }
                    ticket.pending.fetch_sub(1, Ordering::AcqRel);
                }
                Ok(Event::State(id, error, ticket)) => {
                    if let Some(stream) = self.connections.get(&id) {
                        lock(&self.results).add(json!({"type":"connection","connection":stream.identity,"protocol":"tcp",
                            "status":if error==0 {"Established"} else {"Failed"},
                            "detail":if error==0 {String::new()} else {format!("TCP connection failed: {error}")}}));
                    }
                    ticket.pending.fetch_sub(1, Ordering::AcqRel);
                }
                Ok(Event::StopCapture(reply)) => {
                    // End reconstruction without fabricating transport EOFs.
                    for stream in self.connections.values() { stream.ticket.closed.store(true, Ordering::Release); }
                    self.reap(true, true);
                    let _ = reply.send(());
                }
                Ok(Event::Barrier(reply)) => {
                    self.reap(false, false); self.progress(); let _ = reply.send(());
                }
                Ok(Event::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
            self.reap(false, false);
            if progress.elapsed() >= Duration::from_millis(500) { self.progress(); progress = Instant::now(); }
        }
        self.reap(true, false);
    }
}
fn direction(side: usize) -> Direction {
    if side == 0 {
        Direction::Client
    } else {
        Direction::Server
    }
}

fn process_name(pid: u32, process_start: u64) -> String {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME},
        System::Threading::{
            GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };
    if process_start == 0 {
        return String::new();
    }
    // Called at session creation, before the request can finish and curl exit.
    // Validate creation time as well as PID; never attach a reused PID's name.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return String::new();
        }
        let mut created: FILETIME = std::mem::zeroed();
        let mut exited: FILETIME = std::mem::zeroed();
        let mut kernel: FILETIME = std::mem::zeroed();
        let mut user: FILETIME = std::mem::zeroed();
        let mut name = String::new();
        if GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) != 0
            && (u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime))
                == process_start
        {
            let mut path = vec![0u16; 32768];
            let mut length = path.len() as u32;
            if QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut length) != 0 {
                let path = String::from_utf16_lossy(&path[..length as usize]);
                name = path.rsplit('\\').next().unwrap_or("").to_owned();
            }
        }
        CloseHandle(handle);
        name
    }
}

pub fn identity(metadata: &Value, host: &str) -> Result<Connection, String> {
    let number = |name| {
        metadata[name]
            .as_u64()
            .ok_or_else(|| format!("missing identity: {name}"))
    };
    let destination = metadata["destination"]
        .as_str()
        .ok_or("missing destination")?;
    let pid = u32::try_from(number("pid")?).map_err(|e| e.to_string())?;
    let process_start = number("process_create_time")?;
    Ok(Connection {
        id: number("connection_id")?.to_string(),
        pid,
        process_start,
        process_name: process_name(pid, process_start),
        socket: number("socket")?,
        generation: number("socket_generation")?,
        destination: format!("{host} [{destination}]:{}", number("port")?),
        decrypted: false,
        upstream_verification_skipped: false,
        transport: metadata["transport"].as_str().unwrap_or("tcp").to_owned(),
        server_name: host.to_owned(),
        server_port: u16::try_from(number("port")?).map_err(|e| e.to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_and_quic_live_records_cache_and_identity() {
        let r=Runtime::new(CacheConfig { root:std::env::temp_dir().join("proxylane-live-protocol-tests"),entry_bytes:4096,total_bytes:16384,..Default::default() }).unwrap();
        let mut identity=identity(901);identity.transport="udp".into();identity.server_port=53;
        let mut tap=r.tap_transport(identity,None,false).unwrap();
        let q=[0x12,0x34,1,0,0,1,0,0,0,0,0,0,1,b'a',0,0,1,0,1];
        tap.datagram(0,&q);
        let mut answer=q.to_vec();answer[2]=0x81;answer[3]=0x80;answer[7]=1;
        answer.extend_from_slice(&[0xc0,12,0,1,0,1,0,0,0,60,0,4,1,2,3,4]);
        tap.datagram(1,&answer);drop(tap);
        let records=r.query(&json!({"type":"poll"})).unwrap();let rows=records["records"].as_array().unwrap();
        assert_eq!(rows.len(),2);assert_eq!(rows[0]["type"],"dns");assert_eq!(rows[1]["exchange"]["status"],"NOERROR");
        assert_eq!(rows[0]["exchange"]["id"],rows[1]["exchange"]["id"]);
        assert_eq!(rows[1]["connection"]["pid"],42);
        let payload=r.query(&json!({"type":"dns_read","run_id":r.run_id,"cache_id":rows[1]["exchange"]["cache"]["id"],"direction":"server"})).unwrap();
        assert!(payload["text"].as_str().unwrap().contains("1.2.3.4"));
        assert_eq!(payload["payload"]["cache"]["response_bytes"],answer.len());
        let mut tcp_identity=super::tests::identity(903);tcp_identity.server_port=53;tcp_identity.transport="tcp".into();
        let mut tcp=r.tap_transport(tcp_identity,None,false).unwrap();
        let mut wire=(q.len() as u16).to_be_bytes().to_vec();wire.extend_from_slice(&q);
        for chunk in wire.chunks(3) {tcp.data(0,chunk);}
        let mut wire=(answer.len() as u16).to_be_bytes().to_vec();wire.extend_from_slice(&answer);tcp.data(1,&wire);drop(tcp);
        let tcp_records=r.query(&json!({"type":"poll","after":records["next"]})).unwrap();
        let tcp_row=tcp_records["records"].as_array().unwrap().iter().rev().find(|r|r["type"]=="dns").unwrap();
        assert_eq!(tcp_row["type"],"dns");assert_eq!(tcp_row["connection"]["transport"],"tcp");
        assert_eq!(tcp_row["exchange"]["sent_bytes"],q.len());assert_eq!(tcp_row["exchange"]["status"],"NOERROR");
        let mut identity=super::tests::identity(902);identity.transport="udp".into();identity.server_port=443;
        let mut tap=r.tap_transport(identity,None,false).unwrap();tap.datagram(0,&crate::quic_probe::tests::vector(false));drop(tap);
        let reply=r.query(&json!({"type":"poll","after":records["next"]})).unwrap();let row=reply["records"].as_array().unwrap().last().unwrap();
        assert_eq!(row["protocol"],"quic");assert_eq!(row["quic"]["sni"],"example.com");assert_eq!(row["connection"]["decrypted"],false);
        r.shutdown().unwrap();
    }
    #[test]
    fn doh_post_decompression_and_idle_tcp_lifecycle() {
        use base64::Engine;
        let r=Runtime::new(CacheConfig {root:std::env::temp_dir().join("proxylane-doh-tests"),entry_bytes:65536,total_bytes:262144,..Default::default()}).unwrap();
        let mut tap=r.tap_transport(identity(990),None,false).unwrap();
        tap.transport_result(0);
        let idle=r.query(&json!({"type":"poll"})).unwrap();
        assert!(idle["records"].as_array().unwrap().iter().any(|v|v["status"]=="Established"));
        let q=[0,1,1,0,0,1,0,0,0,0,0,0,1,b'a',0,0,1,0,1];
        let mut answer=q.to_vec();answer[2]=0x81;answer[3]=0x80;
        // Existing fixture is gzip encoded HTML; use a minimal uncompressed DEFLATE gzip member for DNS.
        fn gzip(bytes:&[u8])->Vec<u8> {
            let mut out=vec![31,139,8,0,0,0,0,0,0,255,1];
            out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());out.extend_from_slice(&(!(bytes.len() as u16)).to_le_bytes());out.extend_from_slice(bytes);
            let mut crc=!0u32;for byte in bytes {crc^=u32::from(*byte);for _ in 0..8 {crc=(crc>>1)^if crc&1==1 {0xedb88320}else{0};}}
            out.extend_from_slice(&(!crc).to_le_bytes());out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());out
        }
        let body=gzip(&answer);
        let request=format!("POST /dns-query HTTP/1.1\r\nHost: resolver.test\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",q.len());
        tap.data(0,request.as_bytes());tap.data(0,&q);
        let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",body.len());
        tap.data(1,response.as_bytes());tap.data(1,&body);drop(tap);
        let result=r.query(&json!({"type":"poll","limit":64})).unwrap();
        let row=result["records"].as_array().unwrap().iter().find(|v|v["type"]=="exchange").unwrap();
        assert!(row.get("doh").is_some());
        for side in ["client","server"] {
            let result=r.query(&json!({"type":"doh_read","run_id":r.run_id,"cache_id":row["exchange"]["cache"]["id"],"direction":side})).unwrap();
            assert!(result["text"].as_str().unwrap().contains("a."));
            let bytes=base64::engine::general_purpose::STANDARD.decode(result["payload"]["data_base64"].as_str().unwrap()).unwrap();
            assert_eq!(bytes,if side=="client" {q.to_vec()}else{answer.clone()});
        }
        r.shutdown().unwrap();
    }
    #[test]
    fn process_name_survives_exit_and_rejects_reused_pid() {
        use std::{
            os::windows::io::AsRawHandle,
            process::{Command, Stdio},
        };
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
        let mut child = Command::new("cmd.exe")
            .args(["/D", "/Q"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut created: FILETIME = unsafe { std::mem::zeroed() };
        let mut exited = created;
        let mut kernel = created;
        let mut user = created;
        let ok = unsafe {
            GetProcessTimes(
                child.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        };
        let start = u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime);
        let captured = super::identity(
            &json!({"pid":child.id(), "process_create_time":start,
            "connection_id":1, "socket":2, "socket_generation":3, "destination":"127.255.0.1", "port":443}),
            "ifconfig.io",
        );
        let mismatch = super::process_name(child.id(), start.wrapping_add(1));
        let unknown = super::process_name(child.id(), 0);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_ne!(ok, 0);
        let captured = captured.unwrap();
        assert!(captured.process_name.eq_ignore_ascii_case("cmd.exe"));
        assert!(mismatch.is_empty() && unknown.is_empty());
        assert_eq!(captured.server_name, "ifconfig.io");
        assert_eq!(captured.server_port, 443);
        assert_eq!(
            serde_json::to_value(captured).unwrap()["process_name"],
            "cmd.exe"
        );
    }
    fn identity(id: u64) -> Connection {
        Connection {
            id: id.to_string(),
            pid: 42,
            process_start: 98765,
            socket: 120,
            generation: id,
            destination: "test:8443".into(),
            ..Connection::default()
        }
    }
    fn runtime() -> Arc<Runtime> {
        // Every test owns its own locked run under the test-only root.
        Runtime::new(CacheConfig {
            root: std::env::temp_dir().join("proxylane-live-protocol-tests"),
            entry_bytes: 16,
            total_bytes: 24,
            ..CacheConfig::default()
        })
        .unwrap()
    }
    fn poll(r: &Runtime) -> Value {
        let mut result=r.query(&json!({"type":"poll", "limit":64})).unwrap();
        result["records"].as_array_mut().unwrap().retain(|r|r["type"]!="connection");
        result
    }
    #[test]
    fn detection_offsets_cache_identity_and_cleanup() {
        let r = runtime();
        let directory = r.cache.as_ref().unwrap().directory().to_owned();
        let mut tap = r.tap(identity(7), None).unwrap();
        for bytes in b"GET /one HTTP/1.1\r\nHost: test\r\n\r\n".chunks(3) {
            tap.data(0, bytes);
        }
        tap.data(
            1,
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabcdefghijklmnopqrst",
        );
        // Keep-alive second exchange after first body reached its cache cap.
        tap.data(0, b"GET /two HTTP/1.1\r\nHost: test\r\n\r\n");
        tap.data(1, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        drop(tap);
        let result = poll(&r);
        let records = result["records"].as_array().unwrap();
        assert_eq!(records.len(), 2, "{result}");
        assert_eq!(records[0]["connection"]["id"], "7");
        assert_eq!(records[0]["connection"]["pid"], 42);
        assert_eq!(records[0]["connection"]["process_start"], 98765);
        assert_eq!(records[0]["connection"]["generation"], 7);
        assert_eq!(records[0]["exchange"]["response"]["body_bytes"], 20);
        assert_eq!(records[1]["exchange"]["response"]["text"], "ok");
        let id = records[0]["exchange"]["cache"]["id"].as_u64().unwrap();
        let status = r
            .query(&json!({"type":"cache_status", "run_id":r.run_id,"cache_id":id}))
            .unwrap();
        assert_eq!(status["cache"]["response_bytes"], 16);
        assert_eq!(status["cache"]["reason"], "per-exchange payload limit");
        assert!(r
            .query(&json!({"type":"cache_read", "run_id":"previous-run", "cache_id":id}))
            .is_err());
        r.shutdown().unwrap();
        assert!(!directory.exists());
    }
    #[test]
    fn overload_never_bridges_missing_bytes_or_loses_terminal_marker() {
        // Deliberately hold the worker until both queue slots are occupied.
        let (sender, receiver) = mpsc::sync_channel(2);
        let r = Arc::new(Runtime {
            options:Default::default(),
            sender,
            worker: Mutex::new(None),
            stopping: AtomicBool::new(false),
            capture_epoch: Mutex::new(1),
            next: AtomicU64::new(1),
            active: Arc::new(AtomicUsize::new(0)),
            rejected: AtomicU64::new(0),
            results: Arc::new(Mutex::new(Results::default())),
            cache: None,
            cache_error: None,
            run_id: "test".into(),
        });
        let mut tap = r.tap(identity(1), Some(b"http/1.1".to_vec())).unwrap();
        tap.data(0, b"GET /partial HTTP/1.1\r\nHost: test\r\n\r\n");
        tap.data(1, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        assert!(tap.ticket.lost.load(Ordering::Acquire));
        tap.data(0, b"GET /must-not-appear HTTP/1.1\r\nHost: test\r\n\r\n");
        drop(tap);
        let worker = Worker {
            options:Default::default(),
            connections: BTreeMap::new(),
            cache: None,
            results: r.results.clone(),
            active: r.active.clone(),
        };
        let handle = thread::spawn(move || worker.run(receiver));
        let result = poll(&r);
        let text = result.to_string();
        assert!(text.contains("analysis queue overflow"));
        assert!(text.contains("capture ended before exchange completed"));
        assert!(!text.contains("must-not-appear"));
        assert_eq!(r.active.load(Ordering::Acquire), 0);
        r.sender.send(Event::Shutdown).unwrap();
        handle.join().unwrap();
    }
    #[test]
    fn non_http_and_missing_cache_do_not_affect_worker() {
        let r = runtime();
        let mut tap = r.tap(identity(1), None).unwrap();
        tap.data(0, b"\x00\x80binary");
        let mut unsupported = r.tap(identity(2), Some(b"mqtt".to_vec())).unwrap();
        unsupported.data(0, b"payload");
        drop(tap);
        drop(unsupported);
        let result = poll(&r);
        assert!(result["records"].as_array().unwrap().iter().all(|r| r["type"] == "stream"));
        assert!(!result.to_string().contains("\"type\":\"exchange\""));
        r.shutdown().unwrap();

        // A file at the cache root forces cache startup failure; analysis works.
        let path = std::env::temp_dir().join(format!("proxylane-blocked-{}", r.run_id));
        std::fs::write(&path, b"blocked").unwrap();
        let r = Runtime::new(CacheConfig {
            root: path.clone(),
            ..CacheConfig::default()
        })
        .unwrap();
        let mut tap = r.tap(identity(3), Some(b"http/1.1".to_vec())).unwrap();
        tap.data(0, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n");
        tap.data(1, b"HTTP/1.1 204 No Content\r\n\r\n");
        drop(tap);
        assert_eq!(
            poll(&r)["records"][0]["exchange"]["response"]["status"],
            204
        );
        assert!(r.query(&json!({"type":"stats"})).unwrap()["cache_error"].is_string());
        r.shutdown().unwrap();
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn opaque_streams_preserve_prefix_direction_half_close_and_limits() {
        use base64::Engine;
        let r = runtime();
        let mut tap = r.tap_transport(identity(91), None, false).unwrap();
        tap.data(0, b"PI");
        tap.data(1, b"READY"); // Server first while client sniff is buffered.
        let records = poll(&r);
        let live = records["records"].as_array().unwrap().last().unwrap();
        assert_eq!(live["protocol"], "tcp");
        assert_eq!(live["stream"]["finished"], false);
        let cache = live["stream"]["cache"]["id"].as_u64().unwrap();
        let read = |side| {
            let reply = r.query(&json!({"type":"cache_read", "run_id":r.run_id, "cache_id":cache,
                "direction":side,"length":65536})).unwrap();
            base64::engine::general_purpose::STANDARD.decode(reply["payload"]["data_base64"].as_str().unwrap()).unwrap()
        };
        assert_eq!(read("client"), b"PI"); assert_eq!(read("server"), b"READY");
        tap.data(0, b"NG"); tap.eof(0, true);
        tap.data(1, b"0123456789abcdef"); tap.eof(1, true); drop(tap);
        let result = poll(&r);
        let last = result["records"].as_array().unwrap().last().unwrap();
        assert_eq!(last["stream"]["sent_bytes"], 4);
        assert_eq!(last["stream"]["received_bytes"], 21);
        assert_eq!(last["stream"]["complete"], true);
        assert_eq!(read("client"), b"PING");
        assert_eq!(read("server"), b"READY0123456"); // Combined 16-byte cap.
        let status = r.query(&json!({"type":"cache_status","run_id":r.run_id,"cache_id":cache})).unwrap();
        assert_eq!(status["cache"]["reason"], "per-exchange payload limit");
        let mut tls = r.tap_transport(identity(92), None, false).unwrap();
        tls.data(0, &[0x16]); tls.data(0, &[3,3,0,5,1]); drop(tls);
        assert_eq!(poll(&r)["records"].as_array().unwrap().last().unwrap()["protocol"], "tls_encrypted");
        r.shutdown().unwrap();
    }

    #[test]
    fn opaque_queue_gap_is_terminal_and_plain_http_still_reconstructs() {
        let r = runtime();
        let mut tap = r.tap_transport(identity(81), None, false).unwrap();
        tap.data(0, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n");
        tap.data(1, b"HTTP/1.1 204 No Content\r\n\r\n"); drop(tap);
        assert_eq!(poll(&r)["records"][0]["protocol"], "http1");
        let mut tap = r.tap(identity(82), Some(b"mqtt".to_vec())).unwrap();
        tap.data(0, b"before"); let _ = poll(&r);
        tap.ticket.lost.store(true, Ordering::Release);
        tap.data(0, b"after-gap"); drop(tap);
        let result = poll(&r);
        let last = result["records"].as_array().unwrap().last().unwrap();
        assert_eq!(last["protocol"], "tls_stream");
        assert_eq!(last["stream"]["sent_bytes"], 6);
        assert!(last["stream"]["problem"].as_str().unwrap().contains("overflow"));
        r.shutdown().unwrap();
    }

    #[test]
    fn udp_retains_datagram_boundaries_zero_length_and_transport_identity() {
        use base64::Engine;
        let r = runtime();
        let mut connection = identity(71); connection.transport = "udp".into();
        let mut tap = r.tap_transport(connection, None, false).unwrap();
        tap.datagram(0, b"GET"); tap.datagram(0, b""); tap.datagram(0, b"PING");
        tap.datagram(1, b"one"); tap.datagram(1, b"two");
        tap.eof(0,true); tap.eof(1,true); drop(tap);
        let reply = poll(&r); let last = reply["records"].as_array().unwrap().last().unwrap();
        assert_eq!(last["protocol"], "udp");
        assert_eq!(last["connection"]["decrypted"], false);
        assert_eq!(last["stream"]["datagrams"][0], json!([[0,3],[3,0],[3,4]]));
        assert_eq!(last["stream"]["datagrams"][1], json!([[0,3],[3,3]]));
        assert_eq!(last["stream"]["packet_counts"], json!([3,2]));
        let payload = r.query(&json!({"type":"cache_read","run_id":r.run_id,
            "cache_id":last["stream"]["cache"]["id"],"direction":"server","offset":3,"length":3})).unwrap();
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(payload["payload"]["data_base64"].as_str().unwrap()).unwrap(), b"two");
        r.shutdown().unwrap();
    }

    #[test]
    fn connection_limit_and_result_retention_are_bounded() {
        let r = runtime();
        let mut taps: Vec<_> = (0..CONNECTIONS)
            .map(|n| {
                r.tap(identity(n as u64), Some(b"http/1.1".to_vec()))
                    .unwrap()
            })
            .collect();
        assert!(r.tap(identity(999), None).is_none());
        for n in 0..300 {
            taps[0].data(0, b"GET / HTTP/1.1\r\nHost: test\r\n\r\n");
            taps[0].data(1, b"HTTP/1.1 204 No Content\r\n\r\n");
            if n % 20 == 0 {
                r.query(&json!({"type":"stats"})).unwrap();
            }
        }
        drop(taps);
        let stats = r.query(&json!({"type":"stats"})).unwrap();
        assert_eq!(stats["active_connections"], 0);
        assert_eq!(stats["rejected_connections"], 1);
        assert_eq!(stats["retained_records"], 256);
        assert_eq!(stats["evicted_records"], 44);
        assert_eq!(poll(&r)["lost_before"], 44);
        r.shutdown().unwrap();
    }
    #[test]
    fn configured_connection_pending_and_datagram_limits() {
        let options=crate::options::Options{connections:1,pending_requests:2,udp_packets:16,..Default::default()};
        let r=Runtime::with_options(CacheConfig {root:std::env::temp_dir().join("proxylane-options-tests"),..Default::default()},options).unwrap();
        let mut http=r.tap(identity(1),Some(b"http/1.1".to_vec())).unwrap();
        assert!(r.tap(identity(2),None).is_none());
        http.data(0,b"GET /1 HTTP/1.1\r\nHost: t\r\n\r\nGET /2 HTTP/1.1\r\nHost: t\r\n\r\nGET /3 HTTP/1.1\r\nHost: t\r\n\r\n");
        drop(http);
        assert!(poll(&r).to_string().contains("pending exchange limit"));
        let mut id=identity(3);id.transport="udp".into();
        let mut udp=r.tap_transport(id,None,false).unwrap();
        for _ in 0..20 {udp.datagram(0,b"packet");}
        drop(udp);
        let output=poll(&r);let stream=output["records"].as_array().unwrap().iter().rev().find(|x|x["type"]=="stream").unwrap();
        assert_eq!(stream["stream"]["packet_counts"][0],20);
        assert_eq!(stream["stream"]["datagrams"][0].as_array().unwrap().len(),16);
        r.shutdown().unwrap();
    }

}

#[cfg(test)]
mod stop_tests {
    use super::*;
    #[test]
    fn concurrent_stop_drains_writes_retains_history_and_invalidates_old_taps() {
        let r=Runtime::new(CacheConfig {root:std::env::temp_dir().join("proxylane-stop-race"),..Default::default()}).unwrap();
        let mut tap=r.tap_transport(Connection {id:"race".into(),transport:"udp".into(),..Default::default()},None,false).unwrap();
        tap.datagram(0,b"before-stop");
        r.query(&json!({"type":"stats"})).unwrap();
        let running=Arc::new(AtomicBool::new(true));let run=running.clone();
        let producer=thread::spawn(move || {
            while run.load(Ordering::Acquire) { tap.datagram(0,b"during-stop"); thread::yield_now(); }
            tap
        });
        r.stop_capture().unwrap();
        let snapshot=r.query(&json!({"type":"stats"})).unwrap();
        assert_eq!(snapshot["active_connections"],0);
        assert!(snapshot["cache"]["used_bytes"].as_u64().unwrap()>0);
        for _ in 0..4 {assert_eq!(r.query(&json!({"type":"stats"})).unwrap(),snapshot);}
        running.store(false,Ordering::Release);let mut old=producer.join().unwrap();
        assert!(r.tap(Default::default(),None).is_none());
        r.start_capture();
        old.datagram(0,b"must-not-resume");old.eof(0,true);old.transport_result(0);drop(old);
        assert_eq!(r.query(&json!({"type":"stats"})).unwrap(),snapshot);
        let mut fresh=r.tap_transport(Connection {id:"new".into(),transport:"udp".into(),..Default::default()},None,false).unwrap();
        fresh.datagram(0,b"new-capture");
        r.stop_capture().unwrap();
        assert!(r.query(&json!({"type":"stats"})).unwrap()["cache"]["used_bytes"].as_u64().unwrap()>snapshot["cache"]["used_bytes"].as_u64().unwrap());
        drop(fresh);r.shutdown().unwrap();
    }
}
