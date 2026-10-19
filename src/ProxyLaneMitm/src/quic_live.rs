//! In-process QUIC/HTTP3 termination. All datagrams use the host's existing route.
//! No socket/DNS bypass; bounded queues and streaming bodies independent of capture.
use crate::{
    protocol::{H3Part, Runtime, Tap},
    session,
};
use bytes::{Buf, Bytes};
use proxylane_protocol::{Connection, Headers, Message};
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, UdpPoller,
};
use std::{
    collections::VecDeque,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const QUEUE_BYTES: usize = 512 * 1024;
pub type Notify = extern "C" fn(usize);
#[derive(Default, Debug)]
struct Queue {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
    input_bytes: usize,
    output_bytes: usize,
    read: Option<Waker>,
    write: Option<Waker>,
    closed: bool,
}
struct Pipe {
    queue: Mutex<Queue>,
    notify: Notify,
    user: usize,
    remote: SocketAddr,
}
impl std::fmt::Debug for Pipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PRC QUIC pipe")
    }
}
struct Poller(Arc<Pipe>);
impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PRC poller")
    }
}
impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut q = self.0.queue.lock().unwrap();
        if q.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if q.output_bytes + 65536 <= QUEUE_BYTES {
            Poll::Ready(Ok(()))
        } else {
            q.write = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
impl AsyncUdpSocket for Pipe {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller(self))
    }
    fn try_send(&self, t: &Transmit<'_>) -> io::Result<()> {
        let mut q = self.queue.lock().unwrap();
        if q.closed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if t.destination != self.remote || t.segment_size.is_some() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if q.output_bytes + t.contents.len() > QUEUE_BYTES {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let empty = q.output.is_empty();
        q.output_bytes += t.contents.len();
        q.output.push_back(t.contents.to_vec());
        if empty {
            (self.notify)(self.user);
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut q = self.queue.lock().unwrap();
        if q.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Some(b) = q.input.pop_front() {
            q.input_bytes -= b.len();
            if bufs.is_empty() || meta.is_empty() || bufs[0].len() < b.len() {
                return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
            }
            bufs[0][..b.len()].copy_from_slice(&b);
            meta[0] = RecvMeta {
                addr: self.remote,
                len: b.len(),
                stride: b.len(),
                ecn: None,
                dst_ip: None,
            };
            Poll::Ready(Ok(1))
        } else {
            q.read = Some(cx.waker().clone());
            Poll::Pending
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:1".parse().unwrap())
    }
}
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
struct Admission;
impl Drop for Admission {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}
pub struct Live {
    _admission: Admission,
    pipes: [Arc<Pipe>; 2],
    task: tokio::task::JoinHandle<()>,
    error: Arc<Mutex<String>>,
    finished: Arc<AtomicBool>,
}
fn engine() -> Result<&'static tokio::runtime::Runtime> {
    static RT: std::sync::OnceLock<std::result::Result<tokio::runtime::Runtime, String>> =
        std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("quic-forward")
            .build()
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| e.clone().into())
}
fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_concurrent_bidi_streams((crate::options::current().pending_requests as u32).into());
    t.max_concurrent_uni_streams(8u32.into());
    t.max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));
    t.stream_receive_window((256 * 1024u32).into());
    t.receive_window((1024 * 1024u32).into());
    t.send_window(1024 * 1024);
    t.enable_segmentation_offload(false);
    t.mtu_discovery_config(None);
    t.datagram_receive_buffer_size(None);
    Arc::new(t)
}
pub fn prepare() -> Result<()> {
    engine()?;
    crate::context()?;
    Ok(())
}
impl Live {
    /// Called only for a fresh supported Initial. A declined packet is untouched.
    pub fn open(
        host: &str,
        metadata: &serde_json::Value,
        first: &[u8],
        inspected: Option<&crate::quic_probe::Probe>,
        notify: Notify,
        user: usize,
    ) -> Result<Option<Self>> {
        let mut local = crate::quic_probe::Probe::default();
        let probe = match inspected {
            Some(p) => p,
            None => {
                local.feed(0, first);
                &local
            }
        };
        if probe.version != Some(1) || !probe.alpn.iter().any(|a| a == "h3") {
            return Ok(None);
        }
        let name = if probe.name.is_empty() {
            if host.parse::<std::net::IpAddr>().is_err() {
                return Ok(None);
            }
            host.to_owned()
        } else {
            probe.name.clone()
        };
        if ACTIVE
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < crate::options::current().connections).then_some(n + 1)
            })
            .is_err()
        {
            return Err("QUIC connection limit reached".into());
        }
        let admission = Admission;
        let (runtime, epoch) = crate::protocol_runtime()?;
        let mut identity = crate::protocol::identity(metadata, host)?;
        identity.server_name = name.clone();
        identity.transport = "udp".into();
        identity.decrypted = true;
        identity.upstream_verification_skipped =
            crate::SKIP_UPSTREAM_VERIFY.load(Ordering::Acquire);
        let make = |port| {
            Arc::new(Pipe {
                queue: Mutex::new(Queue::default()),
                notify,
                user,
                remote: SocketAddr::from(([127, 0, 0, 1], port)),
            })
        };
        let pipes = [make(2), make(3)];
        let pair = pipes.clone();
        let error = Arc::new(Mutex::new(String::new()));
        let err = error.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let done = finished.clone();
        let ctx = crate::context()?;
        runtime.lifecycle(
            epoch,
            &identity,
            "Connecting",
            "h3",
            "",
            identity.upstream_verification_skipped,
        );
        let task = engine()?.spawn(async move {
            let result = serve(
                pair.clone(),
                ctx,
                name,
                runtime.clone(),
                epoch,
                identity.clone(),
            )
            .await;
            let problem = result.err().map(|e| e.to_string()).unwrap_or_default();
            runtime.lifecycle(
                epoch,
                &identity,
                if problem.is_empty() {
                    "Closed"
                } else {
                    "Failed"
                },
                "h3",
                &problem,
                identity.upstream_verification_skipped,
            );
            *err.lock().unwrap() = problem;
            done.store(true, Ordering::Release);
            let q = pair[0].queue.lock().unwrap();
            if !q.closed {
                (pair[0].notify)(pair[0].user);
            }
        });
        let live = Self {
            _admission: admission,
            pipes,
            task,
            error,
            finished,
        };
        live.feed(0, first);
        Ok(Some(live))
    }
    pub fn feed(&self, side: usize, b: &[u8]) {
        let mut q = self.pipes[side].queue.lock().unwrap();
        if !q.closed && q.input_bytes + b.len() <= QUEUE_BYTES {
            q.input_bytes += b.len();
            q.input.push_back(b.to_vec());
            if let Some(w) = q.read.take() {
                w.wake();
            }
        }
    }
    pub fn peek(&self, side: usize, b: &mut [u8]) -> usize {
        let q = self.pipes[side].queue.lock().unwrap();
        if let Some(p) = q.output.front() {
            if p.len() <= b.len() {
                b[..p.len()].copy_from_slice(p);
                return p.len();
            }
        }
        0
    }
    pub fn consume(&self, side: usize) {
        let mut q = self.pipes[side].queue.lock().unwrap();
        if let Some(p) = q.output.pop_front() {
            q.output_bytes -= p.len();
            if let Some(w) = q.write.take() {
                w.wake();
            }
        }
    }
    pub fn error(&self) -> String {
        self.error.lock().unwrap().clone()
    }
    pub fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
}
impl Drop for Live {
    fn drop(&mut self) {
        for p in &self.pipes {
            let mut q = p.queue.lock().unwrap();
            q.closed = true;
            if let Some(w) = q.read.take() {
                w.wake();
            }
            if let Some(w) = q.write.take() {
                w.wake();
            }
        }
        self.task.abort();
    }
}
struct Driver(tokio::task::JoinHandle<h3::error::ConnectionError>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn headers(h: &http::HeaderMap) -> Headers {
    h.iter()
        .map(|(k, v)| {
            (
                k.as_str().into(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}
async fn serve(
    pipes: [Arc<Pipe>; 2],
    ctx: Arc<session::Context>,
    name: String,
    runtime: Arc<Runtime>,
    epoch: u64,
    identity: Connection,
) -> Result<()> {
    let leaf = ctx.ca.leaf(&name, ctx.crl.port())?;
    #[derive(Debug)]
    struct Leaf(Arc<rustls::sign::CertifiedKey>);
    impl rustls::server::ResolvesServerCert for Leaf {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Leaf(leaf)));
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    server.transport_config(transport());
    server.migration(false);
    let mut ec = quinn::EndpointConfig::default();
    ec.supported_versions(vec![1]);
    let downstream = quinn::Endpoint::new_with_abstract_socket(
        ec,
        Some(server),
        pipes[0].clone(),
        Arc::new(quinn::TokioRuntime),
    )?;
    let timeout = Duration::from_secs(crate::options::current().handshake_seconds);
    let incoming = tokio::time::timeout(timeout, downstream.accept())
        .await?
        .ok_or("QUIC endpoint closed")?;
    let conn = tokio::time::timeout(timeout, incoming).await??;
    // This bridge owns exactly one admitted QUIC connection, including its CIDs.
    downstream.set_server_config(None);
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(ctx.roots.clone())
        .with_no_client_auth();
    if identity.upstream_verification_skipped {
        tls.dangerous()
            .set_certificate_verifier(Arc::new(session::SkipCertificateTrust));
    }
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = false;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    config.transport_config(transport());
    config.version(1);
    let mut upstream = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        pipes[1].clone(),
        Arc::new(quinn::TokioRuntime),
    )?;
    upstream.set_default_client_config(config);
    let up = match tokio::time::timeout(timeout, upstream.connect(pipes[1].remote, &name)?).await {
        Ok(Ok(c)) => c,
        other => {
            conn.close(0x100u32.into(), b"upstream QUIC handshake failed");
            return Err(format!("Upstream QUIC handshake failed: {other:?}").into());
        }
    };
    runtime.lifecycle(
        epoch,
        &identity,
        "Established",
        "h3",
        "",
        identity.upstream_verification_skipped,
    );
    let (mut driver, sender) = h3::client::builder()
        .max_field_section_size(65536)
        .build(h3_quinn::Connection::new(up.clone()))
        .await?;
    let _driver = Driver(tokio::spawn(async move {
        std::future::poll_fn(|cx| driver.poll_close(cx)).await
    }));
    let mut server = h3::server::builder()
        .max_field_section_size(65536)
        .build(h3_quinn::Connection::new(conn.clone()))
        .await?;
    let mut jobs = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            next=server.accept()=>{
                let mut resolver=match next {
                    Ok(Some(resolver))=>resolver,Ok(None)=>break,
                    Err(e)=>{
                        if matches!(conn.close_reason(),Some(quinn::ConnectionError::ApplicationClosed(ref c)) if c.error_code.into_inner()==0 || c.error_code.into_inner()==0x100) {break;}
                        return Err(e.into());
                    }
                };
                if jobs.len()>=crate::options::current().pending_requests {
                    h3::quic::SendStream::reset(&mut resolver.frame_stream,h3::error::Code::H3_REQUEST_REJECTED.value());
                    continue;
                }
                let sender=sender.clone();let runtime=runtime.clone();let identity=identity.clone();
                // Headers belong to an individual stream. Waiting here blocks
                // acceptance of every other request; propagating a reset here
                // tears down the entire multiplexed connection. The h3 driver
                // still reports genuine connection errors through accept().
                jobs.spawn(async move {
                    let (request,stream)=resolver.resolve_request().await?;
                    forward(request,stream,sender,runtime,epoch,identity).await
                });
            }
            Some(_)=jobs.join_next(),if !jobs.is_empty()=>{}
        }
    }
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    up.close(0u32.into(), b"downstream closed");
    Ok(())
}
fn observe(tap: &Option<Tap>, side: usize, part: H3Part) {
    if let Some(t) = tap {
        t.http3(side, part);
    }
}
fn observe_data(tap: &Option<Tap>, side: usize, data: &[u8]) {
    if let Some(t) = tap {
        if t.is_capturing() {
            t.http3(side, H3Part::Data(data.to_vec()));
        }
    }
}
async fn forward(
    request: http::Request<()>,
    downstream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    runtime: Arc<Runtime>,
    epoch: u64,
    identity: Connection,
) -> Result<()> {
    let id = downstream.id().into_inner();
    let tap = runtime.tap_at(epoch, identity, Some(format!("h3:{id}").into_bytes()), true);
    let mut hs = headers(request.headers());
    if let Some(a) = request.uri().authority() {
        hs.insert(0, (":authority".into(), a.to_string()));
    }
    if let Some(s) = request.uri().scheme_str() {
        hs.insert(0, (":scheme".into(), s.into()));
    }
    let mut message = Message::default();
    message.method = Some(request.method().to_string());
    message.target = Some(
        request
            .uri()
            .path_and_query()
            .map_or("/", |v| v.as_str())
            .into(),
    );
    message.headers = hs;
    observe(&tap, 0, H3Part::Head(message));
    let upstream = sender.send_request(request).await?;
    // Upload and response are driven concurrently; early responses cannot deadlock uploads.
    let (mut down_send, mut down_recv) = downstream.split();
    let (mut up_send, mut up_recv) = upstream.split();
    let upload = async {
        while let Some(mut data) = down_recv.recv_data().await? {
            while data.has_remaining() {
                let b = data.copy_to_bytes(data.remaining().min(16384));
                observe_data(&tap, 0, &b);
                up_send.send_data(b).await?;
            }
        }
        let trailers = down_recv.recv_trailers().await?;
        observe(
            &tap,
            0,
            H3Part::End(trailers.as_ref().map(headers).unwrap_or_default()),
        );
        if let Some(t) = trailers {
            up_send.send_trailers(t).await?;
        } else {
            up_send.finish().await?;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };
    let download = async {
        let mut interim = 0;
        loop {
            let response = up_recv.recv_response().await?;
            let informational = response.status().is_informational();
            if informational {
                interim += 1;
                if interim > 16 {
                    return Err("Too many HTTP/3 informational responses".into());
                }
            }
            let mut message = Message::default();
            message.status = Some(response.status().as_u16());
            message.headers = headers(response.headers());
            observe(&tap, 1, H3Part::Head(message));
            down_send.send_response(response).await?;
            if !informational {
                break;
            }
        }
        while let Some(mut data) = up_recv.recv_data().await? {
            while data.has_remaining() {
                let b = data.copy_to_bytes(data.remaining().min(16384));
                observe_data(&tap, 1, &b);
                down_send.send_data(b).await?;
            }
        }
        let trailers = up_recv.recv_trailers().await?;
        observe(
            &tap,
            1,
            H3Part::End(trailers.as_ref().map(headers).unwrap_or_default()),
        );
        if let Some(t) = trailers {
            down_send.send_trailers(t).await?;
        } else {
            down_send.finish().await?;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}
