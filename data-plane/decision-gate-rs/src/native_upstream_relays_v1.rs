//! Fixed ordinary relay assignments, not signed configuration admission.
//!
//! A parent port is independently configured to one literal remote endpoint.
//! No destination, HTTP headers or credentials are sent over the parent channel
//! by this owner. Reqwest must enforce HTTPS and retain origin TLS verification.
//! The loopback tunnel keeps its CONNECT authentication inside the enclave.

use crate::enclave_loopback_tunnel_v1::LoopbackTlsTunnelV1;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

pub struct NativeRelayAssignmentV1 {
    pub host: String,
    pub endpoint: SocketAddr,
    pub parent_port: u32,
}

type EndpointKey = (String, SocketAddr);

/// Retain lazy tunnel owners for the whole gate lifetime, including responses
/// and client clones. No assignment mutation or deadline extension is exposed.
pub struct NativeUpstreamRelaysV1 {
    assignments: HashMap<EndpointKey, u32>,
    tunnels: Mutex<HashMap<EndpointKey, Arc<LoopbackTlsTunnelV1>>>,
    deadline: u64,
    owner_pid: libc::pid_t,
}

fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') { format!("[{host}]:{port}") }
    else { format!("{host}:{port}") }
}

fn endpoint_valid(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 { return false; }
    match endpoint {
        SocketAddr::V4(address) => address.ip().octets()[0] != 0 && address.ip().octets()[0] < 224,
        SocketAddr::V6(address) => !address.ip().is_unspecified()
            && !address.ip().is_multicast() && !address.ip().is_unicast_link_local()
            && address.ip().to_ipv4_mapped().is_none()
            && address.scope_id() == 0 && address.flowinfo() == 0,
    }
}

impl NativeUpstreamRelaysV1 {
    pub fn new(assignments: Vec<NativeRelayAssignmentV1>, deadline: u64) -> Result<Self, String> {
        if assignments.is_empty() || assignments.len() > 32 {
            return Err("native relay inventory must contain 1..32 fixed assignments".to_owned());
        }
        let mut endpoints = HashMap::new();
        let mut parent_ports = HashMap::new();
        for assignment in assignments {
            let host = &assignment.host;
            if host.is_empty() || host.len() > 253 || !host.is_ascii()
                || host.bytes().any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
                || host.contains(['/', '?', '#', '@', '\\'])
                || !endpoint_valid(assignment.endpoint)
                || assignment.parent_port <= 1023 || assignment.parent_port == u32::MAX {
                return Err("native relay host, endpoint or parent port is invalid".to_owned());
            }
            let origin = Url::parse(&format!("https://{}/", authority(host, assignment.endpoint.port())))
                .map_err(|_| "native relay authority is invalid".to_owned())?;
            let normalized = origin.host_str().ok_or("native relay authority has no host")?;
            if normalized.trim_matches(['[', ']']) != host.trim_matches(['[', ']']) {
                return Err("native relay host is not canonical".to_owned());
            }
            if let Some(previous) = parent_ports.insert(assignment.parent_port, assignment.endpoint) {
                if previous != assignment.endpoint {
                    return Err("native parent port cannot name different remote endpoints".to_owned());
                }
            }
            if endpoints.insert((assignment.host, assignment.endpoint), assignment.parent_port).is_some() {
                return Err("native relay endpoint assignment repeats".to_owned());
            }
        }
        let owner = Self { assignments: endpoints, tunnels: Mutex::new(HashMap::new()),
            deadline, owner_pid: unsafe { libc::getpid() } };
        owner.remaining()?;
        Ok(owner)
    }

    pub fn remaining(&self) -> Result<Duration, String> {
        if unsafe { libc::getpid() } != self.owner_pid {
            return Err("native relay inventory crossed its creating process".to_owned());
        }
        let mut sampled: libc::timespec = unsafe { std::mem::zeroed() };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sampled) } != 0
            || sampled.tv_sec < 0 || !(0..1_000_000_000).contains(&sampled.tv_nsec) {
            return Err("native relay boottime sample failed".to_owned());
        }
        let now = sampled.tv_sec as u128 * 1_000_000_000 + sampled.tv_nsec as u128;
        let remaining = (self.deadline as u128).checked_sub(now)
            .filter(|value| *value != 0)
            .ok_or("native relay original deadline expired")?;
        Ok(Duration::from_nanos(remaining as u64))
    }

    /// Return only the literal addresses configured for this exact host/port.
    /// No DNS or destination admission occurs; callers must validate all answers.
    pub fn resolved_addresses(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        self.remaining()?;
        let mut addresses: Vec<IpAddr> = self.assignments.keys()
            .filter(|(name, endpoint)| name == host && endpoint.port() == port)
            .map(|(_, endpoint)| endpoint.ip())
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        self.remaining()?;
        if addresses.is_empty() {
            return Err("native origin has no fixed relay addresses".to_owned());
        }
        Ok(addresses)
    }

    pub fn proxy_for(&self, host: &str, endpoint: SocketAddr) -> Result<reqwest::Proxy, String> {
        self.remaining()?;
        let key = (host.to_owned(), endpoint);
        let parent_port = *self.assignments.get(&key)
            .ok_or("selected endpoint has no fixed native relay assignment")?;
        let mut tunnels = self.tunnels.lock()
            .map_err(|_| "native relay tunnel inventory is poisoned".to_owned())?;
        if !tunnels.contains_key(&key) {
            let tunnel = LoopbackTlsTunnelV1::open(&authority(host, endpoint.port()), parent_port, self.deadline)
                .map_err(|_| "open fixed native loopback tunnel".to_owned())?;
            tunnels.insert(key.clone(), Arc::new(tunnel));
        }
        let tunnel = tunnels.get(&key).ok_or("native relay tunnel disappeared")?;
        tunnel.verify_live().map_err(|_| "native loopback tunnel is not live".to_owned())?;
        let proxy = reqwest::Proxy::https(format!("http://{}", tunnel.proxy_addr()))
            .map_err(|_| "construct fixed native HTTPS proxy".to_owned())?
            .basic_auth("serverware-relay", tunnel.proxy_password());
        self.remaining()?;
        Ok(proxy)
    }

    /// Broker origins have independently configured literal endpoints; they
    /// cannot choose a destination from their request URL or ambient DNS.
    pub fn broker_proxy(&self, raw_url: &str) -> Result<reqwest::Proxy, String> {
        let url = Url::parse(raw_url).map_err(|_| "native broker URL is invalid".to_owned())?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some()
            || url.fragment().is_some() {
            return Err("native broker requires a credential-free HTTPS origin".to_owned());
        }
        let host = url.host_str().ok_or("native broker URL has no host")?;
        let port = url.port_or_known_default().ok_or("native broker URL has no port")?;
        let mut selected = self.assignments.keys().filter(|(name, address)| name == host && address.port() == port);
        let (_, endpoint) = selected.next().ok_or("native broker has no fixed relay assignment")?;
        if selected.next().is_some() {
            return Err("native broker origin has ambiguous fixed relay assignments".to_owned());
        }
        self.proxy_for(host, *endpoint)
    }
}
