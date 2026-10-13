//! Genuine local TLS plus local ownership checks only. The test-only ingress
//! below deliberately contains INVALID, UNVERIFIED quote bytes. No NSM call,
//! measured release admission, native principal or JIT authority is simulated.
use super::*;
use super::super::{RuntimeKeyQuoteV1, TlsAuthorityV1};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ProtocolVersion, RootCertStore};
use std::collections::VecDeque;
use std::time::Duration;
use time::OffsetDateTime;

fn boot() -> u64 {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) }, 0);
    u64::try_from(value.tv_sec).unwrap() * 1_000_000_000
        + u64::try_from(value.tv_nsec).unwrap()
}

// No socket. This real rustls peer limits every encrypted transport chunk and
// refuses unbounded progress, so complete_io exercises actual partial records.
struct PeerIo {
    client: ClientConnection,
    incoming: VecDeque<u8>,
    calls: usize,
    chunk: usize,
    fail_writes: bool,
}

impl PeerIo {
    fn tick(&mut self) {
        self.calls += 1;
        assert!(self.calls < 20_000, "local TLS test exceeded its finite IO budget");
    }
    fn queue(&mut self) -> io::Result<()> {
        let mut bytes = Vec::new();
        self.client.write_tls(&mut bytes)?;
        self.incoming.extend(bytes);
        Ok(())
    }
    fn plaintext(&mut self, bytes: &[u8]) {
        self.client.writer().write_all(bytes).unwrap();
        self.queue().unwrap();
    }
}

impl Read for PeerIo {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.tick();
        self.queue()?;
        if self.incoming.is_empty() { return Err(io::ErrorKind::WouldBlock.into()); }
        let count = buffer.len().min(self.chunk).min(self.incoming.len());
        for byte in &mut buffer[..count] { *byte = self.incoming.pop_front().unwrap(); }
        Ok(count)
    }
}

impl Write for PeerIo {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.tick();
        if self.fail_writes { return Err(io::ErrorKind::BrokenPipe.into()); }
        let count = buffer.len().min(self.chunk);
        let read = self.client.read_tls(&mut io::Cursor::new(&buffer[..count]))?;
        self.client.process_new_packets()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "local TLS peer refused"))?;
        Ok(read)
    }
    fn flush(&mut self) -> io::Result<()> { self.tick(); Ok(()) }
}

fn client_certificate() -> (rcgen::Certificate, rcgen::Certificate, KeyPair) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["client.example".to_owned()]).unwrap();
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = leaf.signed_by(&key, &ca, &ca_key).unwrap();
    (ca, leaf, key)
}

fn fixture(authenticated: bool, wrong_client: bool, tls12: bool)
    -> (Arc<QuotedMutualTlsIngressV1>, PeerIo) {
    let now = OffsetDateTime::now_utc();
    let before = now - time::Duration::minutes(1);
    let after = now + time::Duration::hours(1);
    let authority = TlsAuthorityV1::generate_in_memory(before, after).unwrap();
    let (ca, client, key) = client_certificate();
    let tls = authority.mutual_tls_server_config("outer.example", None,
        &[ca.der().to_vec()], before, after).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(authority.certificate_der().to_vec())).unwrap();
    let versions = if tls12 { vec![&rustls::version::TLS12] }
        else { vec![&rustls::version::TLS13] };
    let builder = ClientConfig::builder_with_protocol_versions(&versions).with_root_certificates(roots);
    let mut config = if authenticated {
        let (ca, client, key) = if wrong_client { client_certificate() } else { (ca, client, key) };
        builder.with_client_auth_cert(vec![client.der().clone(), ca.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()))).unwrap()
    } else { builder.with_no_client_auth() };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = ClientConnection::new(Arc::new(config), ServerName::try_from("outer.example").unwrap()).unwrap();
    // This is NOT successful native quotation. Only local PID/deadline and
    // exact generated-configuration retention are under test in this fixture.
    let ingress = Arc::new(QuotedMutualTlsIngressV1 {
        tls, quote: RuntimeKeyQuoteV1 { document: b"INVALID TEST QUOTE - NOT COSE".to_vec(),
            user_data: Vec::new(), public_key: Vec::new(), nonce: [0; 32] },
        owner_pid: unsafe { libc::getpid() }, deadline: boot() + 30_000_000_000,
    });
    (ingress, PeerIo { client, incoming: VecDeque::new(), calls: 0, chunk: 97, fail_writes: false })
}

fn connected() -> (NativeIngressConnectionV1, PeerIo) {
    let (ingress, mut peer) = fixture(true, false, false);
    let mut owner = ingress.open_connection().unwrap();
    owner.complete_io(&mut peer).unwrap();
    assert!(!owner.connection().is_handshaking());
    assert!(!peer.client.is_handshaking());
    owner.flush(&mut peer).unwrap();
    (owner, peer)
}

#[test]
fn factory_retains_exact_ingress_and_real_mandatory_tls_configuration() {
    let (ingress, mut peer) = fixture(true, false, false);
    let original_deadline = ingress.deadline();
    let mut owner = ingress.open_connection().unwrap();
    assert!(Arc::ptr_eq(owner.ingress(), &ingress));
    assert!(owner.connection().is_handshaking());
    assert_eq!(peer.calls, 0);
    owner.complete_io(&mut peer).unwrap();
    assert_eq!(owner.connection().protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(owner.connection().alpn_protocol(), Some(b"http/1.1".as_slice()));
    assert!(!owner.connection().peer_certificates().unwrap().is_empty());
    assert_eq!(peer.client.peer_certificates().unwrap()[0].as_ref(), ingress.tls().leaf_certificate_der());
    assert_eq!(owner.ingress().deadline(), original_deadline);
    assert!(peer.calls > 2, "partial transport was not exercised");
    assert!(owner.verify_live().is_ok());
    // The successful result above claims no validity for this retained quote.
    assert_eq!(owner.ingress().quote().document(), b"INVALID TEST QUOTE - NOT COSE");
}

#[test]
fn anonymous_foreign_client_and_tls12_cannot_complete_handshake() {
    for (authenticated, wrong_client, tls12) in [(false, false, false), (true, true, false), (true, false, true)] {
        let (ingress, mut peer) = fixture(authenticated, wrong_client, tls12);
        let mut owner = ingress.open_connection().unwrap();
        assert!(owner.complete_io(&mut peer).is_err());
    }
}

#[test]
fn actual_named_io_preserves_partial_records_plaintext_and_close() {
    let (mut owner, mut peer) = connected();
    peer.plaintext(b"client payload");
    let mut result = [0u8; 6];
    assert_eq!(owner.read(&mut peer, &mut result).unwrap(), 6);
    assert_eq!(&result, b"client");
    let calls = peer.calls;
    let mut remaining = [0u8; 8];
    assert_eq!(owner.read_plaintext(&mut remaining).unwrap(), 8);
    assert_eq!(&remaining, b" payload");
    assert_eq!(peer.calls, calls, "buffered plaintext read reached transport");
    assert_eq!(owner.read_plaintext(&mut [0; 1]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert_eq!(owner.write(&mut peer, b"server payload").unwrap(), 14);
    owner.flush(&mut peer).unwrap();
    let mut response = [0u8; 14];
    peer.client.reader().read_exact(&mut response).unwrap();
    assert_eq!(&response, b"server payload");
    let calls = peer.calls;
    owner.send_close_notify().unwrap();
    assert_eq!(peer.calls, calls, "close_notify performed transport IO");
    owner.flush(&mut peer).unwrap();
    assert_eq!(peer.client.reader().read(&mut [0; 1]).unwrap(), 0);
}

#[test]
fn buffered_writes_retain_rustls_error_and_flush_semantics() {
    let (mut owner, mut peer) = connected();
    peer.fail_writes = true;
    // rustls accepts plaintext before its opportunistic transport write fails.
    assert_eq!(owner.write(&mut peer, b"queued").unwrap(), 6);
    assert_eq!(owner.flush(&mut peer).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    peer.fail_writes = false;
    owner.flush(&mut peer).unwrap();
    let mut result = [0u8; 6];
    peer.client.reader().read_exact(&mut result).unwrap();
    assert_eq!(&result, b"queued");
}

struct NoIo;
impl Read for NoIo { fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { panic!("refused owner read IO") } }
impl Write for NoIo {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> { panic!("refused owner wrote IO") }
    fn flush(&mut self) -> io::Result<()> { panic!("refused owner flushed IO") }
}

#[test]
fn factory_and_every_operation_refuse_original_pid_or_expiry_without_io() {
    for expired in [false, true] {
        let (mut ingress, _) = fixture(true, false, false);
        if expired { Arc::get_mut(&mut ingress).unwrap().deadline = 0; }
        else { Arc::get_mut(&mut ingress).unwrap().owner_pid = 0; }
        assert!(ingress.open_connection().is_err());
        // Deliberately invalid private fixture exercises refusal, not a
        // constructor/import API or any successful native admission.
        let mut owner = NativeIngressConnectionV1 {
            connection: ServerConnection::new(ingress.tls().server_config()).unwrap(), ingress,
        };
        assert!(owner.verify_live().is_err());
        assert_eq!(owner.complete_io(&mut NoIo).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(owner.read(&mut NoIo, &mut [0; 1]).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(owner.write(&mut NoIo, b"no").unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(owner.flush(&mut NoIo).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(owner.read_plaintext(&mut [0; 1]).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(owner.send_close_notify().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}

struct ExpiringIo { deadline: u64, called: bool }
impl ExpiringIo {
    fn expire(&mut self) -> io::Result<usize> {
        self.called = true;
        while boot() <= self.deadline {
            std::thread::sleep(Duration::from_nanos(self.deadline.saturating_sub(boot()).saturating_add(1)));
        }
        Err(io::ErrorKind::WouldBlock.into())
    }
}
impl Read for ExpiringIo { fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { self.expire() } }
impl Write for ExpiringIo {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> { self.expire() }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[test]
fn post_io_guard_refuses_expiry_even_when_transport_also_failed() {
    let (mut ingress, _) = fixture(true, false, false);
    let deadline = boot() + 1_000_000_000;
    Arc::get_mut(&mut ingress).unwrap().deadline = deadline;
    let mut owner = ingress.open_connection().unwrap();
    let mut io = ExpiringIo { deadline, called: false };
    assert_eq!(owner.complete_io(&mut io).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert!(io.called, "expiry did not happen inside the actual IO operation");
    assert_eq!(owner.ingress().deadline(), deadline);
}
