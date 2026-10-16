use super::*;
use crate::session::{Context, Session};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use serde_json::json;
use std::{
    io::{Cursor, Read, Write},
    sync::Arc,
};

struct Fixture {
    path: std::path::PathBuf,
    context: Arc<Context>,
}
impl Fixture {
    fn new() -> Self {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "proxylane-mitm-test-{}",
            u64::from_le_bytes(random)
        ));
        let ca = Arc::new(pki::Authority::load(&path, true).unwrap());
        let mut roots = RootCertStore::empty();
        roots.add(ca.der.clone()).unwrap();
        Self {
            path,
            context: Arc::new(Context {
                ca,
                roots: Arc::new(roots),
            }),
        }
    }
    fn session(&self) -> Session {
        Session::new(
            self.context.clone(),
            "localhost".into(),
            json!({"pid":123}),
            false,
        )
        .unwrap()
    }
    fn endpoints(&self, tls12: bool, valid: bool) -> (ClientConnection, ServerConnection) {
        let versions = if tls12 {
            vec![&rustls::version::TLS12]
        } else {
            vec![&rustls::version::TLS13]
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&versions)
            .unwrap()
            .with_root_certificates(self.context.roots.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut client =
            ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
                .unwrap();
        client.set_buffer_limit(Some(256 * 1024));
        let cert = self
            .context
            .ca
            .leaf(if valid { "localhost" } else { "wrong.test" })
            .unwrap();
        #[derive(Debug)]
        struct Resolver(Arc<rustls::sign::CertifiedKey>);
        impl rustls::server::ResolvesServerCert for Resolver {
            fn resolve(
                &self,
                _: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                Some(self.0.clone())
            }
        }
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(cert)));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        (client, ServerConnection::new(Arc::new(config)).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn exchange(
    m: &mut Session,
    app: &mut ClientConnection,
    origin: &mut ServerConnection,
    fragment: usize,
) -> Result<(), String> {
    // Sending each handshake fragment separately exercises sniffing and rustls Acceptor state.
    for side in 0..2 {
        let mut bytes = Vec::new();
        if side == 0 {
            app.write_tls(&mut bytes).unwrap();
        } else {
            origin.write_tls(&mut bytes).unwrap();
        }
        for chunk in bytes.chunks(fragment) {
            assert!(m.can_read());
            m.feed(side, chunk)?;
        }
        let mut bytes = [0u8; 4096];
        loop {
            let n = m.peek(side, &mut bytes)?;
            if n == 0 {
                break;
            }
            // Deliberately consume only a fraction of peek: models short socket sends.
            let n = n.min(fragment);
            let mut input = Cursor::new(&bytes[..n]);
            if side == 0 {
                while input.position() < n as u64 {
                    assert!(app.read_tls(&mut input).unwrap() > 0);
                    app.process_new_packets().map_err(|e| e.to_string())?;
                }
            } else {
                while input.position() < n as u64 {
                    assert!(origin.read_tls(&mut input).unwrap() > 0);
                    origin.process_new_packets().map_err(|e| e.to_string())?;
                }
            }
            m.consume(side, n)?;
        }
    }
    Ok(())
}

extern "C" fn observe(user: usize, kind: u32, data: *const u8, length: usize) {
    unsafe {
        let records = &mut *(user as *mut Vec<(u32, Vec<u8>)>);
        records.push((kind, std::slice::from_raw_parts(data, length).to_vec()));
    }
}

#[test]
fn persistent_ca_and_signed_leaf() {
    let f = Fixture::new();
    let reloaded = pki::Authority::load(&f.path, false).unwrap();
    assert_eq!(reloaded.der, f.context.ca.der);
    assert_eq!(reloaded.id, f.context.ca.id);
    let params = rcgen::CertificateParams::from_ca_cert_der(&reloaded.der).unwrap();
    assert_eq!(
        params.distinguished_name.get(&rcgen::DnType::CommonName),
        Some(&rcgen::DnValue::Utf8String("ProxyLane CA".into()))
    );
    assert_eq!(reloaded.leaf("localhost").unwrap().cert.len(), 1);
    assert!(!std::fs::read_to_string(f.path.join("ca.json"))
        .unwrap()
        .contains("PRIVATE KEY"));
    assert!(!reloaded.crl().unwrap().is_empty());
}

#[test]
fn passthrough_fragmentation_server_first_and_half_close() {
    let f = Fixture::new();
    let mut records: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut m = f.session();
    m.observer = Some((observe, &mut records as *mut _ as usize));
    m.feed(0, &[0x16]).unwrap();
    assert!(
        records.is_empty(),
        "do not display unclassified TLS prefixes"
    );
    m.feed(0, b"ordinary data").unwrap();
    let mut buf = [0u8; 128];
    let n = m.peek(1, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"\x16ordinary data");
    m.input_eof(0).unwrap();
    assert!(!m.shutdown_output(1));
    m.consume(1, n).unwrap();
    assert!(m.shutdown_output(1));
    m.feed(1, b"reply after FIN").unwrap();
    assert_eq!(m.peek(0, &mut buf).unwrap(), 15);
    assert_eq!(
        records,
        vec![
            (3, b"\x16ordinary data".to_vec()),
            (4, b"reply after FIN".to_vec())
        ]
    );
    records.clear();
    let mut m = f.session();
    m.observer = Some((observe, &mut records as *mut _ as usize));
    m.feed(1, b"220 server first\r\n").unwrap();
    assert_eq!(m.peek(0, &mut buf).unwrap(), 18);
    assert_eq!(records, vec![(4, b"220 server first\r\n".to_vec())]);
}

#[test]
fn legacy_ca_location_migrates_without_replacing_identity_or_new_ca() {
    let f = Fixture::new();
    let legacy = f.path.join("mitm");
    std::fs::create_dir(&legacy).unwrap();
    std::fs::rename(f.path.join("ca.json"), legacy.join("ca.json")).unwrap();
    pki::migrate_legacy(&f.path).unwrap();
    assert!(!legacy.join("ca.json").exists());
    assert_eq!(
        pki::Authority::load(&f.path, false).unwrap().der,
        f.context.ca.der
    );
    // Even a stale/different legacy file must not replace an existing root CA.
    std::fs::write(legacy.join("ca.json"), b"obsolete").unwrap();
    pki::migrate_legacy(&f.path).unwrap();
    assert_eq!(
        pki::Authority::load(&f.path, false).unwrap().der,
        f.context.ca.der
    );
}

#[test]
fn bounded_passthrough_preserves_bytes() {
    let f = Fixture::new();
    let mut m = f.session();
    let data = [b'x'; 16384];
    let mut total = 0;
    while m.can_read() {
        m.feed(0, &data).unwrap();
        total += data.len();
    }
    assert!(total <= session::HIGH_WATER);
    let mut count = 0;
    let mut buf = [0u8; 997];
    loop {
        let n = m.peek(1, &mut buf).unwrap();
        if n == 0 {
            break;
        }
        assert!(buf[..n].iter().all(|&b| b == b'x'));
        m.consume(1, n).unwrap();
        count += n;
    }
    assert_eq!(total, count);
    assert!(m.can_read());
}

#[test]
fn tls12_tls13_fragmented_hello_alpn_payload_close() {
    for tls12 in [true, false] {
        let f = Fixture::new();
        let mut records: Vec<(u32, Vec<u8>)> = Vec::new();
        // An unusable capture path must not affect TLS or observer delivery.
        let blocked_capture_path = f.path.join("captures");
        std::fs::write(&blocked_capture_path, b"not a directory").unwrap();
        let mut m = f.session();
        unsafe {
            plm_observe(&mut m, observe, &mut records as *mut _ as usize);
        }
        let (mut app, mut origin) = f.endpoints(tls12, true);
        for _ in 0..30 {
            exchange(&mut m, &mut app, &mut origin, 1).unwrap();
            if m.ready() && !app.is_handshaking() {
                break;
            }
        }
        assert!(m.ready());
        assert!(!app.is_handshaking());
        assert_eq!(app.alpn_protocol(), Some(b"http/1.1".as_slice()));
        assert_eq!(origin.alpn_protocol(), app.alpn_protocol());
        let data = vec![b'Z'; 128 * 1024];
        let mut actual = vec![];
        for chunk in data.chunks(8192) {
            app.writer().write_all(chunk).unwrap();
            exchange(&mut m, &mut app, &mut origin, 4096).unwrap();
            let _ = origin.reader().read_to_end(&mut actual);
        }
        assert_eq!(actual, data);
        origin.writer().write_all(b"response").unwrap();
        origin.send_close_notify();
        for _ in 0..8 {
            exchange(&mut m, &mut app, &mut origin, 17).unwrap();
        }
        let mut response = vec![];
        app.reader().read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response");
        app.send_close_notify();
        for _ in 0..8 {
            exchange(&mut m, &mut app, &mut origin, 17).unwrap();
        }
        assert!(m.shutdown_output(0));
        assert!(m.shutdown_output(1));
        let captured: Vec<u8> = records
            .iter()
            .filter(|r| r.0 == 1)
            .flat_map(|r| r.1.clone())
            .collect();
        let reply: Vec<u8> = records
            .iter()
            .filter(|r| r.0 == 2)
            .flat_map(|r| r.1.clone())
            .collect();
        assert_eq!(captured, data, "observer must preserve all plaintext bytes");
        assert_eq!(reply, b"response");
        assert_eq!(
            std::fs::read(&blocked_capture_path).unwrap(),
            b"not a directory"
        );
        m.input_eof(0).unwrap();
        m.input_eof(1).unwrap();
        drop(m);
        assert!(
            records.iter().all(|r| r.0 == 1 || r.0 == 2),
            "TLS monitor must contain only plaintext, without handshake/closed JSON or ciphertext"
        );
    }
}

#[test]
fn abrupt_tls_eof_reports_direction_once_and_never_fakes_clean_close() {
    for tls12 in [true, false] {
        for side in 0..2 {
            let f = Fixture::new();
            let mut records: Vec<(u32, Vec<u8>)> = Vec::new();
            let mut m = f.session();
            m.observer = Some((observe, &mut records as *mut _ as usize));
            let (mut app, mut origin) = f.endpoints(tls12, true);
            for _ in 0..30 {
                exchange(&mut m, &mut app, &mut origin, 7).unwrap();
                if m.ready() && !app.is_handshaking() {
                    break;
                }
            }
            assert!(m.ready());
            origin.writer().write_all(b"partial response").unwrap();
            exchange(&mut m, &mut app, &mut origin, 17).unwrap();
            let error = m.input_eof(side).unwrap_err();
            assert!(error.contains(if side == 0 {
                "application TCP EOF"
            } else {
                "upstream TCP EOF"
            }));
            assert!(
                !m.shutdown_output(1 - side),
                "truncation must not become authenticated TLS EOF"
            );
            m.fail(error.clone());
            m.fail(error.clone());
            drop(m);
            let errors: Vec<_> = records.iter().filter(|r| r.0 == 0).collect();
            assert_eq!(errors.len(), 1);
            assert_eq!(errors[0].1, error.as_bytes());
        }
    }
}

#[test]
fn invalid_upstream_identity_fails_before_client_certificate() {
    let f = Fixture::new();
    let mut m = f.session();
    let (mut app, mut origin) = f.endpoints(false, false);
    let mut error = None;
    for _ in 0..30 {
        if let Err(e) = exchange(&mut m, &mut app, &mut origin, 7) {
            error = Some(e);
            break;
        }
    }
    let error = error.unwrap();
    assert!(error.contains("not valid for name"), "{error}");
    assert!(app.peer_certificates().is_none());
}

#[test]
fn malformed_tls_never_falls_back_and_truncated_tls_fails() {
    let f = Fixture::new();
    let mut m = f.session();
    assert!(m.feed(0, &[0x16, 3, 3, 0, 4, 0xff, 0, 0, 0]).is_err());
    assert_ne!(m.state, 1);
    let mut m = f.session();
    m.feed(0, &[0x16, 3]).unwrap();
    assert!(m.input_eof(0).is_err());
}

#[test]
fn ip_san_without_sni_and_untrusted_issuer() {
    let f = Fixture::new();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(f.context.roots.clone())
        .with_no_client_auth();
    let mut app =
        ClientConnection::new(Arc::new(config), ServerName::try_from("127.0.0.1").unwrap())
            .unwrap();
    #[derive(Debug)]
    struct Resolver(Arc<rustls::sign::CertifiedKey>);
    impl rustls::server::ResolvesServerCert for Resolver {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver(f.context.ca.leaf("127.0.0.1").unwrap())));
    let mut origin = ServerConnection::new(Arc::new(config)).unwrap();
    let mut m = Session::new(f.context.clone(), "127.0.0.1".into(), json!({}), false).unwrap();
    for _ in 0..30 {
        exchange(&mut m, &mut app, &mut origin, 3).unwrap();
        if m.ready() && !app.is_handshaking() {
            break;
        }
    }
    assert!(m.ready());
    assert!(!app.is_handshaking());

    let untrusted = Arc::new(Context {
        ca: f.context.ca.clone(),
        roots: Arc::new(RootCertStore::empty()),
    });
    let mut m = Session::new(untrusted, "localhost".into(), json!({}), false).unwrap();
    let (mut app, mut origin) = f.endpoints(false, true);
    let mut error = None;
    for _ in 0..30 {
        if let Err(e) = exchange(&mut m, &mut app, &mut origin, 11) {
            error = Some(e);
            break;
        }
    }
    assert!(error.unwrap().contains("UnknownIssuer"));
    assert!(app.peer_certificates().is_none());
}
