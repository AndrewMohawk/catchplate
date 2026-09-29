//! Fixed one-CONNECT adapter for one actual executable child. Provider
//! credentials stay in the native proxy; this owner carries only target mTLS.

use super::{application_proxy_transport::TargetTransport, child::BlockedChild};
use super::super::{config, ensure, originals::ArtifactV1};
use serde::{Deserialize, Serialize};
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::io::{Read, Write};
use std::sync::Arc;

pub(super) const PROFILE: &str = "native-target-mtls-one-connect-v1";

#[derive(Deserialize, Serialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(in super::super) struct Settings {
    pub(in super::super) profile: String,
    pub(in super::super) listener_port: u16,
    pub(in super::super) destination: String,
    pub(in super::super) maximum_tunnel_bytes: u64,
    pub(in super::super) proxy_endpoint: String,
    pub(in super::super) ingress_configuration_sha256: String,
    pub(in super::super) target_certificate_sha256: String,
    pub(in super::super) target_private_key_sha256: String,
    pub(in super::super) target_principal_id: String,
}
impl Settings {
    pub(super) fn validate(&self) -> Result<(), String> {
        ensure(self.profile == PROFILE && (1024..=65535).contains(&self.listener_port)
            && (4096..=16*1024*1024).contains(&self.maximum_tunnel_bytes), "application proxy profile/bounds differ")?;
        let (host, port) = self.destination.rsplit_once(':').ok_or("application destination needs explicit port")?;
        ensure(!host.is_empty() && host.len() <= 253 && host == host.to_ascii_lowercase()
            && host.parse::<std::net::IpAddr>().is_err()
            && host.split('.').all(|part| !part.is_empty() && part.len() <= 63
                && !part.starts_with('-') && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')),
            "application destination must be a canonical DNS authority")?;
        let p = port.parse::<u16>().map_err(|_| "application destination port invalid")?;
        ensure(p > 0 && p.to_string() == port, "application destination port spelling differs")?;
        self.endpoint()?;
        for pin in [&self.ingress_configuration_sha256, &self.target_certificate_sha256,
            &self.target_private_key_sha256] { super::manifest::digest(pin)?; }
        ensure(self.target_certificate_sha256 != self.target_private_key_sha256
            && !self.target_principal_id.is_empty() && self.target_principal_id.len() <= 1024
            && self.target_principal_id.trim() == self.target_principal_id
            && !self.target_principal_id.chars().any(char::is_control), "application target identity differs")
    }
    pub(super) fn endpoint(&self) -> Result<SocketAddr, String> {
        let value: SocketAddr = self.proxy_endpoint.parse().map_err(|_| "application proxy endpoint must be literal")?;
        ensure(value.to_string() == self.proxy_endpoint && value.port() > 0 && !value.ip().is_unspecified()
            && !value.ip().is_multicast() && !value.ip().is_loopback(), "application proxy endpoint differs")?;
        Ok(value)
    }
    pub(in super::super) fn sha256(&self) -> Result<String,String> {
        Ok(format!("sha256:{:x}", Sha256::digest(canonical_ascii_bytes(self)?)))
    }
}

#[derive(Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(in super::super) struct Inputs {
    pub(super) ingress_configuration: ArtifactV1,
    pub(super) target_certificate: ArtifactV1,
    pub(super) target_private_key: ArtifactV1,
}
impl Inputs {
    pub(in super::super) fn validate(&self) -> Result<(), String> {
        let roles = [&self.ingress_configuration, &self.target_certificate, &self.target_private_key];
        for (i, role) in roles.iter().enumerate() {
            config::artifact(role)?;
            ensure(roles[..i].iter().all(|other| other.path != role.path && other.sha256 != role.sha256),
                "application proxy artifact roles overlap")?;
        }
        Ok(())
    }
    pub(in super::super) fn require_separate(&self, certificate: &ArtifactV1, key: &ArtifactV1) -> Result<(),String> {
        self.validate()?;
        ensure([&self.target_certificate, &self.target_private_key].iter().all(|target|
            [&certificate, &key].iter().all(|caller| target.path != caller.path && target.sha256 != caller.sha256)),
            "application target identity cannot reuse bootstrap caller originals")
    }
    pub(super) fn require_settings(&self, value: &Settings) -> Result<(), String> {
        self.validate()?; value.validate()?;
        ensure(self.ingress_configuration.sha256 == value.ingress_configuration_sha256
            && self.target_certificate.sha256 == value.target_certificate_sha256
            && self.target_private_key.sha256 == value.target_private_key_sha256,
            "application artifact pins differ from signed immutable manifest")
    }
}

pub(super) struct Relay<'child> {
    child: &'child BlockedChild,
    listener: Option<TcpListener>,
    local: Option<TcpStream>,
    target: Option<TargetTransport>,
    header: Vec<u8>,
    expected: Vec<u8>,
    to_local: Vec<u8>,
    to_target: Vec<u8>,
    counts: [u64;2],
    maximum: u64,
    connected: bool,
    ended: bool,
}
impl<'child> Relay<'child> {
    pub(super) fn open(child: &'child BlockedChild, inputs: Inputs) -> Result<Self,String> {
        child.check()?;
        let (settings, parents, clock) = child.application_context()?;
        let listener = child.application_listener()?;
        // Consume the same child's attempt before private-key acquisition,
        // the first outbound socket or any CONNECT byte, including failures.
        let target = TargetTransport::connect(inputs, settings, parents, Arc::clone(clock))?;
        child.check()?;
        Ok(Self { child, listener: Some(listener), local: None, target:Some(target), header: Vec::new(),
            expected: format!("CONNECT {} HTTP/1.1", settings.destination).into_bytes(),
            to_local: Vec::new(), to_target: Vec::new(), counts:[0,0], maximum: settings.maximum_tunnel_bytes,
            connected:false, ended:false })
    }
    pub(super) fn require_release(&mut self, child: &BlockedChild) -> Result<(),String> {
        ensure(std::ptr::eq(child,self.child) && !self.ended && self.local.is_none(), "application relay release owner differs")?;
        child.check()?; self.target.as_mut().ok_or("target tunnel ended before release")?.check()
    }
    pub(super) fn step(&mut self) -> Result<(),String> {
        self.child.check_continuation()?;
        if self.ended { return Ok(()); }
        self.target.as_mut().ok_or("target tunnel is unavailable")?.check()?;
        if self.local.is_none() {
            let listener = self.listener.as_ref().ok_or("application listener was already consumed")?;
            match listener.accept() {
                Ok((stream,peer)) => {
                    ensure(peer.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), "application client is not child loopback")?;
                    stream.set_nonblocking(true).map_err(|_| "application accepted socket cannot be nonblocking")?;
                    self.local = Some(stream);
                    // No second accept, even after EOF or a malformed CONNECT.
                    self.listener.take();
                },
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return Err("application loopback accept failed".to_owned()),
            }
        }
        let local = self.local.as_mut().ok_or("application stream unavailable")?;
        if !self.connected {
            // Bounded per turn and no overread into an inner TLS record.
            for _ in 0..256 {
                let mut byte=[0];
                match local.read(&mut byte) {
                    Ok(1) => self.header.push(byte[0]), Ok(_) => return Err("local CONNECT ended early".to_owned()),
                    Err(error) if error.kind()==std::io::ErrorKind::WouldBlock => break,
                    Err(_) => return Err("local CONNECT read failed".to_owned()),
                }
                ensure(self.header.len()<=8192, "local CONNECT headers exceed bound")?;
                if self.header.ends_with(b"\r\n\r\n") {
                    let text=std::str::from_utf8(&self.header).map_err(|_| "local CONNECT header invalid")?;
                    let mut lines=text[..text.len()-4].split("\r\n");
                    ensure(lines.next().is_some_and(|v|v.as_bytes()==self.expected), "local CONNECT destination differs")?;
                    let mut host=false; let mut agent=false; let mut connection=false;
                    for line in lines {
                        let (name,value)=line.split_once(':').ok_or("local CONNECT header malformed")?;
                        let value=value.trim();
                        if name.eq_ignore_ascii_case("host") {
                            ensure(!host && format!("CONNECT {value} HTTP/1.1").as_bytes()==self.expected,"local CONNECT Host differs")?; host=true;
                        } else if name.eq_ignore_ascii_case("user-agent") {
                            ensure(!agent && !value.is_empty() && value.len()<=512 && value.bytes().all(|b|(32..=126).contains(&b)),"local agent header invalid")?; agent=true;
                        } else if name.eq_ignore_ascii_case("proxy-connection") {
                            ensure(!connection && value.eq_ignore_ascii_case("keep-alive"),"local connection header invalid")?; connection=true;
                        } else { return Err("unsupported local CONNECT header; no forwarding".to_owned()); }
                    }
                    ensure(host,"local CONNECT Host is required")?;
                    self.connected=true;
                    self.to_local.extend_from_slice(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                    break;
                }
            }
            if !self.connected { return Ok(()); }
        }
        if self.to_local.is_empty() && self.to_target.is_empty() {
            let mut bytes=[0;4096];
            match local.read(&mut bytes) {
                Ok(0)=>{ self.ended=true; let _=local.shutdown(std::net::Shutdown::Both);
                    self.target.take(); return Ok(()); },
                Ok(count)=>{self.counts[0]+=count as u64; ensure(self.counts[0]<=self.maximum,"application upstream cap exceeded")?;self.to_target.extend_from_slice(&bytes[..count]);},
                Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>{},
                Err(_)=>return Err("application local TLS read failed".to_owned()),
            }
        }
        let mut incoming=[0;4096];
        let out=if self.to_local.is_empty(){&mut incoming[..]}else{&mut incoming[..0]};
        let (sent,received,eof)=self.target.as_mut().ok_or("target tunnel is unavailable")?.step(&self.to_target,out)?;
        self.to_target.drain(..sent);
        self.counts[1]+=received as u64; ensure(self.counts[1]<=self.maximum,"application downstream cap exceeded")?;
        self.to_local.extend_from_slice(&incoming[..received]);
        if !self.to_local.is_empty() {
            match local.write(&self.to_local) {
                Ok(0)=>return Err("application local TLS write ended".to_owned()),
                Ok(count)=>{self.to_local.drain(..count);},
                Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>{},
                Err(_)=>return Err("application local TLS write failed".to_owned()),
            }
        }
        if eof { ensure(self.to_local.is_empty() && self.to_target.is_empty(),"native tunnel EOF with pending data")?;
            self.ended=true;let _=local.shutdown(std::net::Shutdown::Both);self.target.take(); }
        Ok(())
    }
    pub(super) fn finish(&self)->Result<(),String> {
        // Historical own counters only. Exit may have made live-child checks
        // inapplicable; this cannot authorize another IO or renew admission.
        ensure(self.connected && self.counts.iter().all(|value|*value>0)
            && self.to_local.is_empty() && self.to_target.is_empty(),
            "application exited without completing a bidirectional bounded CONNECT tunnel")
    }
}
