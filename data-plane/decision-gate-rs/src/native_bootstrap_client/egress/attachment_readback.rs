//! Bounded semantic normalization of genuine, owner-retained RTNL originals.
//! A dump is not its creation request. Linux v6.12 rtnl_fill_ifinfo,
//! inet_fill_ifaddr/inet6_fill_ifaddr, neigh_fill_info, fib_dump_info and
//! rt6_fill_node define the accepted dump forms. No parser result is permission.

use super::{attachment::PreattachmentGuard, attachment_authority::Authorization,
    attachment_backend::{AttachmentTranscript, ReplyOriginals, Snapshot},
    attachment_wire::{self as wire, AttachmentPlan, DumpKind, Side}, EgressGuard};
use serde::Serialize;
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

#[path = "attachment_readback_links.rs"]
mod links;

const MAX_BYTES: usize = 1024 * 1024;
const MAX_MESSAGES: usize = 256;
const MAX_SEMANTIC: usize = 64 * 1024;

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native attachment semantic readback differs".to_owned()) }
}
fn u32_ne(raw: &[u8]) -> Result<u32, String> {
    Ok(u32::from_ne_bytes(raw.try_into().map_err(|_| "attachment scalar width differs")?))
}
fn string(raw: &[u8]) -> Result<String, String> {
    require((2..=256).contains(&raw.len()) && raw.last() == Some(&0)
        && raw[..raw.len() - 1].iter().all(|b| (0x21..=0x7e).contains(b)))?;
    String::from_utf8(raw[..raw.len() - 1].to_vec()).map_err(|_| "attachment string differs".to_owned())
}
fn attrs<'a>(raw: &'a [u8], allowed: &[u16]) -> Result<BTreeMap<u16, &'a [u8]>, String> {
    let result = wire::attributes(raw)?;
    require(result.keys().all(|key| allowed.contains(key)))?;
    Ok(result)
}
fn field<'a>(fields: &BTreeMap<u16, &'a [u8]>, key: u16) -> Result<&'a [u8], String> {
    fields.get(&key).copied().ok_or_else(|| "attachment field absent".to_owned())
}
fn ip(raw: &[u8], family: u8) -> Result<Vec<u8>, String> {
    require(raw.len() == if family == 2 { 4 } else { 16 })?;
    Ok(raw.to_vec())
}
fn signed_ip(raw: &str) -> Result<(u8, Vec<u8>), String> {
    match raw.parse::<IpAddr>().map_err(|_| "attachment signed IP invalid")? {
        IpAddr::V4(value) => Ok((2, value.octets().to_vec())),
        IpAddr::V6(value) => Ok((10, value.octets().to_vec())),
    }
}
fn mac(raw: &str) -> Result<Vec<u8>, String> {
    let parts = raw.split(':').map(|part| u8::from_str_radix(part, 16)
        .map_err(|_| "attachment signed MAC invalid".to_owned())).collect::<Result<Vec<_>, _>>()?;
    require(parts.len() == 6)?; Ok(parts)
}
fn hex(raw: &[u8]) -> String { raw.iter().map(|byte| format!("{byte:02x}")).collect() }

#[derive(Default)]
struct Bounds { bytes: usize, messages: usize, requests: BTreeSet<(Side, u32, u32)> }

fn payloads<'a>(reply: &'a ReplyOriginals, side: Side, kind: DumpKind,
    bound: &mut Bounds) -> Result<Vec<&'a [u8]>, String> {
    require(reply.side() == side && reply.sequence() != 0 && reply.port_id() != 0
        && bound.requests.insert((side, reply.port_id(), reply.sequence()))
        && reply.request() == wire::dump_request(kind, reply.sequence(), reply.port_id())?)?;
    bound.bytes = bound.bytes.checked_add(reply.request().len()).ok_or("attachment size overflow")?;
    let mut done = false;
    let mut result = Vec::new();
    for datagram in reply.datagrams() {
        require(!done)?;
        bound.bytes = bound.bytes.checked_add(datagram.len()).ok_or("attachment size overflow")?;
        require(bound.bytes <= MAX_BYTES)?;
        for frame in wire::frames(datagram)? {
            bound.messages += 1;
            require(!done && bound.messages <= MAX_MESSAGES && frame.flags == 2
                && frame.sequence == reply.sequence() && frame.port_id == reply.port_id())?;
            if frame.message_type == 3 {
                require(frame.payload == [0, 0, 0, 0])?; done = true;
            } else {
                require(frame.message_type == kind.reply_type()
                    && frame.payload.len() >= kind.body_length()
                    && frame.payload[0] == kind.family())?;
                result.push(frame.payload);
            }
        }
    }
    require(done)?; Ok(result)
}

#[derive(Serialize, Eq, PartialEq, Ord, PartialOrd)]
struct Address {
    family: u8, index: u32, address: Vec<u8>, prefix: u8, scope: u8, flags: u32,
    label: Option<String>, broadcast: Option<Vec<u8>>, priority: u32, protocol: u8,
    preferred_lifetime: u32, valid_lifetime: u32,
}
fn addresses(raw: &[&[u8]], family: u8) -> Result<Vec<Address>, String> {
    let mut output = Vec::new();
    let mut identities = BTreeSet::new();
    for value in raw {
        require(value.len() >= 8 && value[0] == family && value[1] <= if family == 2 { 32 } else { 128 })?;
        let f = attrs(&value[8..], &[1, 2, 3, 4, 6, 8, 9, 11])?;
        let address = ip(field(&f, 1)?, family)?;
        // IPv6 omits IFA_LOCAL when its peer address is zero; IPv4 emits both.
        if let Some(local) = f.get(&2) { require(*local == address.as_slice())?; }
        if family == 2 { require(f.contains_key(&2))?; }
        let flags = u32_ne(field(&f, 8)?)?;
        require(value[2] == flags as u8)?;
        let cache = field(&f, 6)?; require(cache.len() == 16)?;
        let index = u32_ne(&value[4..8])?; require(index != 0)?;
        let label = f.get(&3).map(|raw| string(raw)).transpose()?;
        let broadcast = f.get(&4).map(|raw| ip(raw, family)).transpose()?;
        let priority = f.get(&9).map(|raw| u32_ne(raw)).transpose()?.unwrap_or(0);
        let protocol = if let Some(raw) = f.get(&11) { require(raw.len() == 1)?; raw[0] } else { 0 };
        require(identities.insert((index, address.clone())))?;
        output.push(Address { family, index, address, prefix: value[1], scope: value[3], flags,
            label, broadcast, priority, protocol,
            preferred_lifetime: u32_ne(&cache[..4])?, valid_lifetime: u32_ne(&cache[4..8])? });
    }
    output.sort(); Ok(output)
}

#[derive(Serialize, Eq, PartialEq, Ord, PartialOrd)]
struct Neighbor {
    family: u8, index: u32, address: Vec<u8>, mac: Option<Vec<u8>>,
    state: u16, flags: u8, kind: u8, protocol: u8, extended_flags: u32,
}
fn neighbors(raw: &[&[u8]], family: u8) -> Result<Vec<Neighbor>, String> {
    let mut output = Vec::new(); let mut identities = BTreeSet::new();
    for value in raw {
        require(value.len() >= 12 && value[0] == family && value[1..4] == [0, 0, 0])?;
        let f = attrs(&value[12..], &[1, 2, 3, 4, 12, 15])?;
        let index = u32_ne(&value[4..8])?; require(index != 0 && index <= i32::MAX as u32)?;
        let address = ip(field(&f, 1)?, family)?;
        require(field(&f, 3)?.len() == 16 && field(&f, 4)?.len() == 4)?;
        let hardware = f.get(&2).map(|raw| raw.to_vec());
        if let Some(hardware) = &hardware { require(hardware.len() <= 32 && !hardware.is_empty())?; }
        let protocol = if let Some(raw) = f.get(&12) { require(raw.len() == 1)?; raw[0] } else { 0 };
        let extended_flags = f.get(&15).map(|raw| u32_ne(raw)).transpose()?.unwrap_or(0);
        require(identities.insert((index, address.clone())))?;
        output.push(Neighbor { family, index, address, mac: hardware,
            state: u16::from_ne_bytes(value[8..10].try_into().unwrap()), flags: value[10],
            kind: value[11], protocol, extended_flags });
    }
    output.sort(); Ok(output)
}

#[derive(Serialize, Eq, PartialEq, Ord, PartialOrd)]
struct Route {
    family: u8, destination: Vec<u8>, prefix: u8, table: u32, protocol: u8,
    scope: u8, kind: u8, flags: u32, index: u32, priority: u32,
    gateway: Option<Vec<u8>>, preferred_source: Option<Vec<u8>>,
}
fn routes(raw: &[&[u8]], family: u8) -> Result<Vec<Route>, String> {
    let mut output = Vec::new();
    for value in raw {
        require(value.len() >= 12 && value[0] == family && value[2] == 0 && value[3] == 0
            && value[1] <= if family == 2 { 32 } else { 128 })?;
        let f = attrs(&value[12..], &[1, 4, 5, 6, 7, 12, 15, 20])?;
        let table = u32_ne(field(&f, 15)?)?;
        require(table == u32::from(value[4]) && matches!(table, 254 | 255))?;
        let destination = ip(field(&f, 1)?, family)?;
        let index = u32_ne(field(&f, 4)?)?; require(index != 0 && index <= i32::MAX as u32)?;
        let priority = f.get(&6).map(|raw| u32_ne(raw)).transpose()?.unwrap_or(0);
        let gateway = f.get(&5).map(|raw| ip(raw, family)).transpose()?;
        let preferred_source = f.get(&7).map(|raw| ip(raw, family)).transpose()?;
        if family == 10 {
            // rt6_fill_node always emits priority, cacheinfo and preference.
            let cache = field(&f, 12)?; require(cache.len() == 32 && u32_ne(&cache[8..12])? == 0)?;
            require(f.contains_key(&6) && field(&f, 20)? == [0])?;
        } else { require(!f.contains_key(&12) && !f.contains_key(&20))?; }
        output.push(Route { family, destination, prefix: value[1], table, protocol: value[5],
            scope: value[6], kind: value[7], flags: u32_ne(&value[8..12])?, index,
            priority, gateway, preferred_source });
    }
    output.sort();
    require(output.windows(2).all(|pair| pair[0] != pair[1]))?; Ok(output)
}

struct State {
    host_links: BTreeMap<u32, links::Link>, child_links: BTreeMap<u32, links::Link>,
    host_addresses: Vec<Address>, child_addresses: Vec<Address>,
    host_neighbors: Vec<Neighbor>, child_neighbors: Vec<Neighbor>, child_routes: Vec<Route>,
}
fn state(authority: &Authorization, snapshot: &Snapshot) -> Result<State, String> {
    let mut bound = Bounds::default();
    let host_links = links::parse(&payloads(snapshot.get(Side::Host, DumpKind::Links)?,
        Side::Host, DumpKind::Links, &mut bound)?, authority, Side::Host)?;
    let child_links = links::parse(&payloads(snapshot.get(Side::Child, DumpKind::Links)?,
        Side::Child, DumpKind::Links, &mut bound)?, authority, Side::Child)?;
    let mut host_addresses = Vec::new(); let mut child_addresses = Vec::new();
    let mut host_neighbors = Vec::new(); let mut child_neighbors = Vec::new();
    let mut child_routes = Vec::new();
    for (family, address_kind, neighbor_kind, route_kind) in [
        (2, DumpKind::AddressV4, DumpKind::NeighborV4, DumpKind::RouteV4),
        (10, DumpKind::AddressV6, DumpKind::NeighborV6, DumpKind::RouteV6)] {
        host_addresses.extend(addresses(&payloads(snapshot.get(Side::Host, address_kind)?,
            Side::Host, address_kind, &mut bound)?, family)?);
        child_addresses.extend(addresses(&payloads(snapshot.get(Side::Child, address_kind)?,
            Side::Child, address_kind, &mut bound)?, family)?);
        host_neighbors.extend(neighbors(&payloads(snapshot.get(Side::Host, neighbor_kind)?,
            Side::Host, neighbor_kind, &mut bound)?, family)?);
        child_neighbors.extend(neighbors(&payloads(snapshot.get(Side::Child, neighbor_kind)?,
            Side::Child, neighbor_kind, &mut bound)?, family)?);
        child_routes.extend(routes(&payloads(snapshot.get(Side::Child, route_kind)?,
            Side::Child, route_kind, &mut bound)?, family)?);
    }
    require(host_links == links::parse(&payloads(snapshot.closing_links(Side::Host),
        Side::Host, DumpKind::Links, &mut bound)?, authority, Side::Host)?
        && child_links == links::parse(&payloads(snapshot.closing_links(Side::Child),
        Side::Child, DumpKind::Links, &mut bound)?, authority, Side::Child)?)?;
    require(host_addresses.iter().all(|v| host_links.contains_key(&v.index))
        && child_addresses.iter().all(|v| child_links.contains_key(&v.index))
        && host_neighbors.iter().all(|v| host_links.contains_key(&v.index))
        && child_neighbors.iter().all(|v| child_links.contains_key(&v.index)))?;
    Ok(State { host_links, child_links, host_addresses, child_addresses,
        host_neighbors, child_neighbors, child_routes })
}

fn loopback(link: &links::Link) -> Result<(), String> {
    require(link.name == "lo" && link.link_type == 772 && link.flags & 1 == 0
        && link.flags & 8 != 0 && link.master.is_none() && link.kind.is_none())
}
fn bridge_and_gateways(authority: &Authorization, value: &State) -> Result<(), String> {
    let bridge = value.host_links.get(&authority.bridge.ifindex).ok_or("attachment bridge absent")?;
    require(bridge.name == authority.bridge.name && bridge.link_type == 1
        && bridge.kind.as_deref() == Some("bridge") && bridge.flags & 1 == 1
        && bridge.mtu == authority.bridge.mtu && bridge.mac == mac(&authority.bridge.mac_address)?)?;
    for route in &authority.attachment.routes {
        let (family, gateway) = signed_ip(&route.gateway)?;
        require(value.host_addresses.iter().any(|address| address.family == family
            && address.index == bridge.index && address.address == gateway
            && address.flags & (0x08 | 0x20 | 0x40) == 0 && address.flags & 0x80 != 0
            && address.preferred_lifetime == u32::MAX && address.valid_lifetime == u32::MAX))?;
    }
    // Host addresses/neighbors are collision inventory, not an egress grant.
    for child in &authority.attachment.addresses {
        let (family, address) = signed_ip(&child.address)?;
        require(!value.host_addresses.iter().any(|v| v.family == family && v.address == address)
            && !value.host_neighbors.iter().any(|v| v.family == family && v.address == address))?;
    }
    Ok(())
}

pub(super) struct Preflight { host_index: u32, child_index: u32 }
impl Preflight {
    pub(super) fn host_index(&self) -> u32 { self.host_index }
    pub(super) fn child_index(&self) -> u32 { self.child_index }
}
pub(super) fn preflight(authority: &Authorization, snapshot: &Snapshot) -> Result<Preflight, String> {
    let value = state(authority, snapshot)?;
    bridge_and_gateways(authority, &value)?;
    require(value.child_links.len() == 1 && value.child_addresses.is_empty()
        && value.child_neighbors.is_empty() && value.child_routes.is_empty())?;
    loopback(value.child_links.values().next().ok_or("attachment loopback absent")?)?;
    for link in value.host_links.values().chain(value.child_links.values()) {
        require(link.name != authority.attachment.host_veth_name && link.name != authority.attachment.child_veth_name)?;
    }
    fn unused(links: &BTreeMap<u32, links::Link>) -> Result<u32, String> {
        (1..=MAX_MESSAGES as u32 + 1).find(|index| !links.contains_key(index))
            .ok_or_else(|| "attachment free explicit index unavailable".to_owned())
    }
    Ok(Preflight { host_index: unused(&value.host_links)?, child_index: unused(&value.child_links)? })
}

fn veth(link: &links::Link, name: &str, hardware: &str, mtu: u32, peer: u32,
    master: Option<u32>) -> Result<(), String> {
    require(link.name == name && link.link_type == 1 && link.kind.as_deref() == Some("veth")
        && link.flags & 1 == 1 && link.flags & (8 | 0x10) == 0
        // The bridge may request promiscuity/allmulti on its host slave. The
        // isolated child has neither bridge membership nor that exception.
        && (master.is_some() || link.flags & (0x100 | 0x200) == 0)
        && link.mtu == mtu && link.mac == mac(hardware)? && link.peer == Some(peer)
        && link.master == master && link.namespace_id.is_some_and(|id| id >= 0)
        && link.addrgen_mode == Some(1))
}
fn expected_addresses(authority: &Authorization, index: u32) -> Result<Vec<Address>, String> {
    let mut result = Vec::new();
    for value in &authority.attachment.addresses {
        let (family, address) = signed_ip(&value.address)?;
        result.push(Address { family, index, address, prefix: value.prefix_length, scope: 0,
            flags: 0x80 | 0x200 | if family == 10 { 2 } else { 0 },
            label: if family == 2 { Some(authority.attachment.child_veth_name.clone()) } else { None },
            broadcast: None, priority: 0, protocol: 0,
            preferred_lifetime: u32::MAX, valid_lifetime: u32::MAX });
    }
    result.sort(); Ok(result)
}
fn expected_neighbors(authority: &Authorization, index: u32) -> Result<Vec<Neighbor>, String> {
    let mut result = BTreeSet::new();
    for value in &authority.attachment.routes {
        let (family, address) = signed_ip(&value.gateway)?;
        result.insert(Neighbor { family, index, address, mac: Some(mac(&value.gateway_mac_address)?),
            state: 0x80, flags: 0, kind: 1, protocol: 0, extended_flags: 0 });
    }
    Ok(result.into_iter().collect())
}
fn expected_routes(authority: &Authorization, index: u32) -> Result<Vec<Route>, String> {
    let mut result = Vec::new();
    for value in &authority.attachment.routes {
        let (family, destination) = signed_ip(value.destination.split('/').next().ok_or("attachment route absent")?)?;
        let source = authority.attachment.addresses.iter().find(|a| a.family == value.family)
            .ok_or("attachment source address absent")?;
        result.push(Route { family, destination, prefix: if family == 2 { 32 } else { 128 },
            table: 254, protocol: 4, scope: 0, kind: 1, flags: 4, index, priority: 1024,
            gateway: Some(signed_ip(&value.gateway)?.1), preferred_source: Some(signed_ip(&source.address)?.1) });
    }
    for value in &authority.attachment.addresses {
        let (family, address) = signed_ip(&value.address)?;
        result.push(Route { family, destination: address.clone(), prefix: if family == 2 { 32 } else { 128 },
            table: 255, protocol: 2, scope: if family == 2 { 254 } else { 0 }, kind: 2,
            flags: 0, index, priority: 0, gateway: None,
            preferred_source: if family == 2 { Some(address) } else { None } });
    }
    // addrconf_add_mroute creates this exact route for an UP IPv6-enabled link,
    // including an IPv4-only manual address selection. This is not an allow rule.
    let mut multicast = vec![0; 16]; multicast[0] = 0xff;
    result.push(Route { family: 10, destination: multicast, prefix: 8, table: 255,
        protocol: 2, scope: 0, kind: 5, flags: 0, index, priority: 256,
        gateway: None, preferred_source: None });
    result.sort(); Ok(result)
}

fn transcript_plan(transcript: &AttachmentTranscript, plan: &AttachmentPlan) -> Result<(), String> {
    let raw = transcript.original();
    require((12..=MAX_BYTES).contains(&raw.len()) && &raw[..8] == b"SWNATBE1")?;
    let count = u32::from_be_bytes(raw[8..12].try_into().unwrap()) as usize;
    require((1..=512).contains(&count))?;
    let mut cursor = 12usize; let mut mutation = 0usize; let mut messages = 0usize;
    let mut awaiting: Option<(Side, &[u8])> = None;
    for _ in 0..count {
        require(raw.len().saturating_sub(cursor) >= 6)?;
        let tag = raw[cursor];
        let side = match raw[cursor + 1] { 1 => Side::Host, 2 => Side::Child,
            _ => return Err("attachment transcript side differs".to_owned()) };
        let length = u32::from_be_bytes(raw[cursor + 2..cursor + 6].try_into().unwrap()) as usize;
        cursor += 6;
        require(length != 0 && length <= wire::MAX_DATAGRAM && length <= raw.len().saturating_sub(cursor))?;
        let bytes = &raw[cursor..cursor + length]; cursor += length;
        match tag {
            1 => { require(awaiting.is_none())?; require(wire::frames(bytes)?.len() == 1)?; },
            2 => {
                require(awaiting.is_none())?;
                let operation = plan.operations().get(mutation).ok_or("attachment extra mutation")?;
                require(operation.side == side && operation.original == bytes)?;
                mutation += 1; awaiting = Some((side, bytes));
            },
            3 => {
                let frames = wire::frames(bytes)?;
                messages += frames.len(); require(messages <= MAX_MESSAGES)?;
                if let Some((expected_side, request)) = awaiting.take() {
                    let original = wire::frames(request)?;
                    require(frames.len() == 1 && original.len() == 1 && side == expected_side)?;
                    let ack = &frames[0]; let request = &original[0];
                    require(ack.message_type == 2 && ack.flags == 0x100
                        && ack.sequence == request.sequence && ack.port_id == request.port_id
                        && ack.payload.len() == 20 && ack.payload[..4] == [0, 0, 0, 0]
                        && ack.payload[4..] == request.original[..16])?;
                }
            },
            _ => return Err("attachment transcript event differs".to_owned()),
        }
    }
    require(cursor == raw.len() && awaiting.is_none() && mutation == plan.operations().len())
}

pub(super) struct VerifiedAttachment {
    owner: usize, plan_sha256: [u8; 32], transcript_sha256: [u8; 32], original: Vec<u8>,
}
impl VerifiedAttachment {
    pub(super) fn original(&self) -> &[u8] { &self.original }
    pub(super) fn transcript_sha256(&self) -> [u8; 32] { self.transcript_sha256 }
    pub(super) fn require_owner(&self, owner: &EgressGuard, plan: &AttachmentPlan) -> Result<(), String> {
        owner.check()?; plan.require_owner(owner)?;
        require(self.owner == owner as *const EgressGuard as usize && self.plan_sha256 == plan.sha256())
    }
}

pub(super) fn verify(guard: &PreattachmentGuard<'_>, plan: &AttachmentPlan,
    snapshot: &Snapshot, transcript: &AttachmentTranscript) -> Result<VerifiedAttachment, String> {
    guard.check()?; plan.require_owner(guard.egress())?;
    transcript.require_owner(guard.egress(), plan)?;
    snapshot.require_owner(guard.egress(), plan, transcript)?;
    transcript_plan(transcript, plan)?; guard.check()?;
    let authority = guard.authority();
    let value = state(authority, snapshot)?; guard.check()?;
    bridge_and_gateways(authority, &value)?;
    let host = value.host_links.get(&plan.host_index()).ok_or("attachment host veth absent")?;
    let child = value.child_links.get(&plan.child_index()).ok_or("attachment child veth absent")?;
    veth(host, &authority.attachment.host_veth_name, &authority.attachment.host_mac_address,
        authority.attachment.mtu, plan.child_index(), Some(authority.bridge.ifindex))?;
    veth(child, &authority.attachment.child_veth_name, &authority.attachment.child_mac_address,
        authority.attachment.mtu, plan.host_index(), None)?;
    require(value.child_links.len() == 2)?;
    for other in value.child_links.values().filter(|link| link.index != plan.child_index()) { loopback(other)?; }
    for index in [0usize, 3, 4, 5] {
        require(child.ipv6_conf.get(index) == Some(&0) && child.ipv4_conf.get(index) == Some(&0))?;
    }
    // Pinned v6.12 ipv6.h DEVCONF_RTR_SOLICITS and DEVCONF_USE_TEMPADDR.
    for index in [7usize, 10] { require(child.ipv6_conf.get(index) == Some(&0))?; }
    require(!value.host_addresses.iter().any(|address| address.index == plan.host_index())
        && value.child_addresses == expected_addresses(authority, plan.child_index())?
        && value.child_neighbors == expected_neighbors(authority, plan.child_index())?
        && value.child_routes == expected_routes(authority, plan.child_index())?)?;
    let gateways = value.host_addresses.iter().filter(|address| address.index == authority.bridge.ifindex)
        .collect::<Vec<_>>();
    let semantic = serde_json::json!({
        "apiVersion": "serverware.nativeNetworkAttachmentSemanticOriginal/v1",
        "authorizationSha256": format!("sha256:{}", hex(&authority.original_sha256)),
        "planSha256": format!("sha256:{}", hex(&plan.sha256())),
        "bridge": value.host_links.get(&authority.bridge.ifindex),
        "hostVeth": host, "childLinks": value.child_links,
        "bridgeAddresses": gateways, "childAddresses": value.child_addresses,
        "childNeighbors": value.child_neighbors, "childRoutes": value.child_routes,
    });
    let original = canonical_ascii_bytes(&semantic)?;
    require(!original.is_empty() && original.len() <= MAX_SEMANTIC)?;
    guard.check()?; plan.require_owner(guard.egress())?;
    transcript.require_owner(guard.egress(), plan)?;
    snapshot.require_owner(guard.egress(), plan, transcript)?;
    Ok(VerifiedAttachment { owner: plan.owner_identity(), plan_sha256: plan.sha256(),
        transcript_sha256: Sha256::digest(transcript.original()).into(), original })
}
