//! One separately authenticated target connection. Never the bootstrap caller.

#[path = "../../proof_client_native_ingress_v1.rs"]
mod proof_client_native_ingress_v1;
#[path = "../../proof_client_native_transport_v1.rs"]
mod proof_client_native_transport_v1;

use super::application_proxy::{Inputs, Settings};
use super::super::{ensure, identity, originals::HeldOriginal, OriginalClock};
use proof_client_native_ingress_v1::NativeIngressAdmission;
use proof_client_native_transport_v1::NativeProxyTransportV1;
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::sync::Arc;

fn is_sha256_digest(value: &str) -> bool { super::manifest::digest(value).is_ok() }
fn sha256_prefixed(value: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(value)) }

pub(super) struct TargetTransport {
    admission: NativeIngressAdmission,
    originals: Vec<HeldOriginal>,
    private: HeldOriginal,
    transport: NativeProxyTransportV1,
    clock: Arc<OriginalClock>,
}

impl TargetTransport {
    pub(super) fn connect(inputs: Inputs, settings: &Settings,
        parents: &super::super::egress::ExecutionParents, clock: Arc<OriginalClock>)
        -> Result<Self, String> {
        clock.check()?;
        inputs.require_settings(settings)?;
        let admission = NativeIngressAdmission::open(&inputs.ingress_configuration.path,
            &inputs.ingress_configuration.sha256, &settings.target_principal_id, clock.instant_deadline()?)?;
        ensure(admission.principal_preflight(), "application proxy requires explicit native principal v3")?;
        let mut originals = Vec::new();
        let certificate = super::super::read(inputs.target_certificate, 64 * 1024, &clock, &mut originals)?;
        let leaf = CertificateDer::from_pem_slice(&certificate).map_err(|_| "target certificate PEM invalid")?;
        let (rest, parsed) = x509_parser::parse_x509_certificate(&leaf)
            .map_err(|_| "target certificate DER invalid")?;
        ensure(rest.is_empty(), "target certificate DER has trailing bytes")?;
        parents.require_application(settings, Sha256::digest(parsed.public_key().raw).into(), admission.ca())?;
        let (mut private, key) = HeldOriginal::read_private(inputs.target_private_key, 16 * 1024)?;
        clock.check()?; private.require_private()?; private.recheck()?;
        let config = identity::configuration(admission.ca(), &certificate, &key)?;
        drop(key);
        let endpoint = settings.endpoint()?;
        let name = ServerName::try_from(admission.host().to_owned()).map_err(|_| "native proxy server name invalid")?;
        let authority = if admission.host().contains(':') {
            format!("[{}]:{}", admission.host(), endpoint.port())
        } else { format!("{}:{}", admission.host(), endpoint.port()) };
        let mut transport = proof_client_native_transport_v1::connect_bounded(endpoint, name, Arc::new(config),
            clock.instant_deadline()?,Some(clock.boottime_deadline()?))?;
        // Empty auth headers is the fixed certificate-principal profile. No
        // application Proxy-Authorization or caller bootstrap headers enter it.
        admission.attest(&mut transport, &authority, &[])?;
        clock.check()?;
        parents.require_application(settings, Sha256::digest(parsed.public_key().raw).into(), admission.ca())?;
        let request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            settings.destination, settings.destination);
        transport.write_all(request.as_bytes()).map_err(|_| "target CONNECT send failed; no retry")?;
        transport.flush().map_err(|_| "target CONNECT flush failed; no retry")?;
        // Byte-at-a-time avoids consuming an inner-TLS byte across the exact
        // HTTP boundary. No chunking, body or alternate successful status.
        let mut response = Vec::with_capacity(1024);
        while !response.ends_with(b"\r\n\r\n") {
            clock.check()?;
            ensure(response.len() < 8192, "target CONNECT response exceeds bound")?;
            let mut byte = [0];
            ensure(transport.read(&mut byte).map_err(|_| "target CONNECT response failed")? == 1,
                "target CONNECT ended before response")?;
            response.push(byte[0]);
        }
        let text = std::str::from_utf8(&response).map_err(|_| "target CONNECT response is not ASCII")?;
        let mut lines = text[..text.len()-4].split("\r\n");
        ensure(lines.next()==Some("HTTP/1.1 200 Connection Established"),
            "target CONNECT did not establish the exact tunnel")?;
        let mut length_seen=false;
        for line in lines {
            ensure(line.bytes().all(|b| (32..=126).contains(&b)), "target CONNECT header invalid")?;
            let (name, value) = line.split_once(':').ok_or("target CONNECT header malformed")?;
            ensure(!length_seen && name.eq_ignore_ascii_case("content-length") && value.trim() == "0",
                "target CONNECT response has an unsupported header")?;
            length_seen=true;
        }
        transport.begin_relay().map_err(|_| "target tunnel cannot become bounded relay")?;
        let mut owner = Self { admission, originals, private, transport, clock };
        owner.check()?;
        Ok(owner)
    }
    pub(super) fn check(&mut self) -> Result<(), String> {
        self.clock.check()?;
        for original in &mut self.originals { original.recheck()?; }
        self.private.require_private()?; self.private.recheck()?;
        self.admission.recheck()?;
        self.transport.check().map_err(|_| "target transport original ownership expired")?;
        self.clock.check()
    }
    pub(super) fn step(&mut self, outgoing: &[u8], incoming: &mut [u8]) -> Result<(usize,usize,bool), String> {
        self.check()?;
        let result = self.transport.relay_step(outgoing, incoming).map_err(|_| "native tunnel relay failed")?;
        self.check()?;
        Ok(result)
    }
}
