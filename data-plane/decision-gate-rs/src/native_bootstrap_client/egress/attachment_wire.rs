//! Fixed RTNL attachment recipe; no arbitrary messages, replacement or deletion.
//! Linux v6.12 UAPI rtnetlink.h, if_link.h, if_addr.h, neighbour.h and
//! drivers/net/veth.c define the encoded layouts and requested peer ifindex.

use super::{attachment_authority::Authorization, EgressGuard};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

pub(super) const MAX_DATAGRAM: usize = 64 * 1024;
const REQUEST: u16 = 1;
const ACK: u16 = 4;
const CREATE_EXCLUSIVE: u16 = 0x600;
const NESTED: u16 = 0x8000;

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native attachment wire profile differs".to_owned()) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum Side { Host, Child }
impl Side { pub(super) fn tag(self) -> u8 { match self { Self::Host => 1, Self::Child => 2 } } }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum DumpKind { Links, AddressV4, AddressV6, NeighborV4, NeighborV6, RouteV4, RouteV6 }
impl DumpKind {
    pub(super) fn family(self) -> u8 {
        match self { Self::Links => 0, Self::AddressV4 | Self::NeighborV4 | Self::RouteV4 => 2, _ => 10 }
    }
    pub(super) fn reply_type(self) -> u16 {
        match self { Self::Links => 16, Self::AddressV4 | Self::AddressV6 => 20,
            Self::NeighborV4 | Self::NeighborV6 => 28, Self::RouteV4 | Self::RouteV6 => 24 }
    }
    pub(super) fn body_length(self) -> usize {
        match self { Self::Links => 16, Self::AddressV4 | Self::AddressV6 => 8, _ => 12 }
    }
}

pub(super) struct Frame<'a> {
    pub(super) original: &'a [u8],
    pub(super) message_type: u16,
    pub(super) flags: u16,
    pub(super) sequence: u32,
    pub(super) port_id: u32,
    pub(super) payload: &'a [u8],
}

pub(super) fn frames(raw: &[u8]) -> Result<Vec<Frame<'_>>, String> {
    require(!raw.is_empty() && raw.len() <= MAX_DATAGRAM)?;
    let mut result = Vec::new();
    let mut cursor = 0usize;
    while cursor < raw.len() {
        require(raw.len() - cursor >= 16 && result.len() < 64)?;
        let header = &raw[cursor..cursor + 16];
        let length = u32::from_ne_bytes(header[..4].try_into().unwrap()) as usize;
        require((16..=16 * 1024).contains(&length) && length <= raw.len() - cursor)?;
        let padded = length.checked_add(3).ok_or("native attachment frame overflow")? & !3;
        require(padded <= raw.len() - cursor && raw[cursor + length..cursor + padded].iter().all(|b| *b == 0))?;
        result.push(Frame { original: &raw[cursor..cursor + length],
            message_type: u16::from_ne_bytes(header[4..6].try_into().unwrap()),
            flags: u16::from_ne_bytes(header[6..8].try_into().unwrap()),
            sequence: u32::from_ne_bytes(header[8..12].try_into().unwrap()),
            port_id: u32::from_ne_bytes(header[12..16].try_into().unwrap()),
            payload: &raw[cursor + 16..cursor + length] });
        cursor += padded;
    }
    Ok(result)
}

pub(super) fn attributes(raw: &[u8]) -> Result<BTreeMap<u16, &[u8]>, String> {
    require(raw.len() <= 16 * 1024)?;
    let mut result: BTreeMap<u16, &[u8]> = BTreeMap::new();
    let mut cursor = 0usize;
    while cursor < raw.len() {
        require(raw.len() - cursor >= 4 && result.len() < 128)?;
        let length = u16::from_ne_bytes(raw[cursor..cursor + 2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(raw[cursor + 2..cursor + 4].try_into().unwrap());
        require(length >= 4 && length <= raw.len() - cursor && kind & 0x3fff != 0)?;
        let padded = (length + 3) & !3;
        require(padded <= raw.len() - cursor && raw[cursor + length..cursor + padded].iter().all(|b| *b == 0))?;
        require(!result.keys().any(|old| *old & 0x3fff == kind & 0x3fff))?;
        require(result.insert(kind, &raw[cursor + 4..cursor + length]).is_none())?;
        cursor += padded;
    }
    Ok(result)
}

fn attribute(kind: u16, value: &[u8], output: &mut Vec<u8>) -> Result<(), String> {
    let length = value.len().checked_add(4).ok_or("native attachment attribute overflow")?;
    require(length <= u16::MAX as usize && output.len() + ((length + 3) & !3) <= 16 * 1024)?;
    output.extend_from_slice(&(length as u16).to_ne_bytes());
    output.extend_from_slice(&kind.to_ne_bytes()); output.extend_from_slice(value);
    while output.len() % 4 != 0 { output.push(0); }
    Ok(())
}

fn text_attribute(kind: u16, value: &str, output: &mut Vec<u8>) -> Result<(), String> {
    require(!value.is_empty() && value.is_ascii() && !value.as_bytes().contains(&0))?;
    let mut bytes = value.as_bytes().to_vec(); bytes.push(0); attribute(kind, &bytes, output)
}

fn message(kind: u16, flags: u16, sequence: u32, port: u32, body: &[u8]) -> Result<Vec<u8>, String> {
    require(sequence != 0 && port != 0 && body.len() <= 16 * 1024 - 16 && body.len() % 4 == 0)?;
    let mut raw = Vec::with_capacity(body.len() + 16);
    raw.extend_from_slice(&((body.len() + 16) as u32).to_ne_bytes());
    raw.extend_from_slice(&kind.to_ne_bytes()); raw.extend_from_slice(&flags.to_ne_bytes());
    raw.extend_from_slice(&sequence.to_ne_bytes()); raw.extend_from_slice(&port.to_ne_bytes());
    raw.extend_from_slice(body); Ok(raw)
}

pub(super) fn dump_request(kind: DumpKind, sequence: u32, port: u32) -> Result<Vec<u8>, String> {
    let mut body = vec![0u8; kind.body_length()]; body[0] = kind.family();
    message(kind.reply_type() + 2, REQUEST | 0x300, sequence, port, &body)
}

fn link(index: u32, flags: u32, change: u32) -> Result<Vec<u8>, String> {
    require(index > 0 && index <= i32::MAX as u32)?;
    let mut raw = vec![0; 4]; raw.extend_from_slice(&index.to_ne_bytes());
    raw.extend_from_slice(&flags.to_ne_bytes()); raw.extend_from_slice(&change.to_ne_bytes()); Ok(raw)
}

fn ip(text: &str) -> Result<Vec<u8>, String> {
    match text.parse::<IpAddr>().map_err(|_| "native attachment IP differs")? {
        IpAddr::V4(value) => Ok(value.octets().to_vec()), IpAddr::V6(value) => Ok(value.octets().to_vec()),
    }
}

fn mac(text: &str) -> Result<Vec<u8>, String> {
    require(text.len() == 17)?;
    text.split(':').map(|part| {
        require(part.len() == 2)?;
        u8::from_str_radix(part, 16).map_err(|_| "native attachment MAC differs".to_owned())
    }).collect()
}

pub(super) struct Operation { pub(super) side: Side, pub(super) original: Vec<u8> }

/// Only the actual backend builds this after complete original preflight.
/// Exact requested ifindices remove any post-claim mutation-template input.
pub(super) struct AttachmentPlan {
    owner: usize,
    original: Vec<u8>,
    operations: Vec<Operation>,
    host_index: u32,
    child_index: u32,
    last_host: u32,
    last_child: u32,
}

impl AttachmentPlan {
    pub(super) fn original(&self) -> &[u8] { &self.original }
    pub(super) fn sha256(&self) -> [u8; 32] { Sha256::digest(&self.original).into() }
    pub(super) fn host_index(&self) -> u32 { self.host_index }
    pub(super) fn child_index(&self) -> u32 { self.child_index }
    pub(super) fn owner_identity(&self) -> usize { self.owner }
    pub(super) fn operations(&self) -> &[Operation] { &self.operations }
    pub(super) fn last_sequence(&self, side: Side) -> u32 { match side { Side::Host => self.last_host, Side::Child => self.last_child } }
    pub(super) fn require_owner(&self, owner: &EgressGuard) -> Result<(), String> {
        owner.check()?; require(self.owner == owner as *const EgressGuard as usize)
    }
}

pub(super) fn build(owner: &EgressGuard, authority: &Authorization, host_index: u32,
    child_index: u32, namespace_fd: i32, host_port: u32, child_port: u32,
    host_sequence: u32, child_sequence: u32, host_namespace: (u64, u64), child_namespace: (u64, u64))
    -> Result<AttachmentPlan, String>
{
    owner.check()?;
    require(namespace_fd >= 0 && host_namespace != child_namespace)?;
    let plan = &authority.attachment;
    let mut recipes: Vec<(Side, u16, u16, Vec<u8>)> = Vec::new();
    let mut peer = link(child_index, 0, 0)?;
    text_attribute(3, &plan.child_veth_name, &mut peer)?;
    attribute(4, &plan.mtu.to_ne_bytes(), &mut peer)?;
    attribute(1, &mac(&plan.child_mac_address)?, &mut peer)?;
    attribute(28, &(namespace_fd as u32).to_ne_bytes(), &mut peer)?;
    let mut data = Vec::new(); attribute(NESTED | 1, &peer, &mut data)?;
    let mut info = Vec::new(); text_attribute(1, "veth", &mut info)?; attribute(NESTED | 2, &data, &mut info)?;
    let mut create = link(host_index, 0, 0)?;
    text_attribute(3, &plan.host_veth_name, &mut create)?;
    attribute(4, &plan.mtu.to_ne_bytes(), &mut create)?;
    attribute(1, &mac(&plan.host_mac_address)?, &mut create)?;
    attribute(NESTED | 18, &info, &mut create)?;
    recipes.push((Side::Host, 16, CREATE_EXCLUSIVE, create));
    for (side, index) in [(Side::Host, host_index), (Side::Child, child_index)] {
        let mut inet6 = Vec::new(); attribute(8, &[1], &mut inet6)?;
        let mut families = Vec::new(); attribute(NESTED | 10, &inet6, &mut families)?;
        let mut body = link(index, 0, 0)?; attribute(NESTED | 26, &families, &mut body)?;
        recipes.push((side, 16, 0, body));
    }
    let mut master = link(host_index, 0, 0)?;
    attribute(10, &authority.bridge.ifindex.to_ne_bytes(), &mut master)?;
    recipes.push((Side::Host, 16, 0, master));
    let mut sources = BTreeMap::new();
    for address in &plan.addresses {
        let packed = ip(&address.address)?;
        let family = if packed.len() == 4 { 2u8 } else { 10u8 };
        let flags = 0x80u32 | 0x200 | if family == 10 { 2 } else { 0 };
        require(address.prefix_length == if family == 2 { 32 } else { 128 }
            && sources.insert(family, packed.clone()).is_none())?;
        let mut body = vec![family, address.prefix_length, flags as u8, 0];
        body.extend_from_slice(&child_index.to_ne_bytes());
        attribute(1, &packed, &mut body)?;
        if family == 2 { attribute(2, &packed, &mut body)?; }
        attribute(8, &flags.to_ne_bytes(), &mut body)?;
        recipes.push((Side::Child, 20, CREATE_EXCLUSIVE, body));
    }
    let mut neighbors = BTreeSet::new();
    for route in &plan.routes {
        let destination = ip(&route.destination)?;
        let gateway = ip(&route.gateway)?;
        require(destination.len() == gateway.len())?;
        let family = if destination.len() == 4 { 2u8 } else { 10u8 };
        if neighbors.insert((family, gateway.clone())) {
            let mut body = vec![family, 0, 0, 0]; body.extend_from_slice(&child_index.to_ne_bytes());
            body.extend_from_slice(&0x80u16.to_ne_bytes()); body.extend_from_slice(&[0, 1]);
            attribute(1, &gateway, &mut body)?; attribute(2, &mac(&route.gateway_mac_address)?, &mut body)?;
            recipes.push((Side::Child, 28, CREATE_EXCLUSIVE, body));
        }
    }
    // ONLINK routes require an administratively UP device in both IP families.
    // The existing nft owner and fixed child network policy are already held.
    recipes.push((Side::Host, 16, 0, link(host_index, 1, 1)?));
    recipes.push((Side::Child, 16, 0, link(child_index, 1, 1)?));
    for route in &plan.routes {
        let destination = ip(&route.destination)?;
        let family = if destination.len() == 4 { 2u8 } else { 10u8 };
        let mut body = vec![family, if family == 2 { 32 } else { 128 }, 0, 0, 254, 4, 0, 1];
        body.extend_from_slice(&4u32.to_ne_bytes());
        attribute(1, &destination, &mut body)?;
        attribute(4, &child_index.to_ne_bytes(), &mut body)?;
        attribute(5, &ip(&route.gateway)?, &mut body)?;
        attribute(6, &1024u32.to_ne_bytes(), &mut body)?;
        attribute(7, sources.get(&family).ok_or("native attachment route family has no source")?, &mut body)?;
        recipes.push((Side::Child, 24, CREATE_EXCLUSIVE, body));
    }
    require(!recipes.is_empty() && recipes.len() <= 64)?;
    let mut sequences = [host_sequence, child_sequence];
    let mut operations = Vec::new();
    let mut original = b"SWNATPL1".to_vec();
    original.extend_from_slice(&authority.original_sha256);
    for value in [host_namespace.0, host_namespace.1, child_namespace.0, child_namespace.1] {
        original.extend_from_slice(&value.to_be_bytes());
    }
    original.extend_from_slice(&host_index.to_be_bytes()); original.extend_from_slice(&child_index.to_be_bytes());
    original.extend_from_slice(&(recipes.len() as u32).to_be_bytes());
    for (side, kind, flags, body) in recipes {
        let at = if side == Side::Host { 0 } else { 1 };
        let raw = message(kind, REQUEST | ACK | flags, sequences[at], if at == 0 { host_port } else { child_port }, &body)?;
        sequences[at] = sequences[at].checked_add(1).ok_or("native attachment sequence exhausted")?;
        original.push(side.tag()); original.extend_from_slice(&(raw.len() as u32).to_be_bytes()); original.extend_from_slice(&raw);
        operations.push(Operation { side, original: raw });
    }
    require(original.len() <= MAX_DATAGRAM)?;
    owner.check()?;
    Ok(AttachmentPlan { owner: owner as *const EgressGuard as usize, original, operations,
        host_index, child_index, last_host: sequences[0] - 1, last_child: sequences[1] - 1 })
}
