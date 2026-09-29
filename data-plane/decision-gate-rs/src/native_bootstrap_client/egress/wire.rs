//! Fixed create-only nftables wire originals; no socket, command or effect API.
//!
//! UAPI: linux/{netlink.h,netfilter/nfnetlink.h,netfilter/nf_tables.h}.
//! The selected Linux v6.12 nfnetlink.c queues BEGIN and successful END ACKs;
//! nft_exthdr.c represents IPv6 Fragment-header presence as one register byte.
//! Readback interprets typed attributes, never treats these originals as proof.

use super::authority::Ruleset;
use std::net::IpAddr;

pub(super) const MAX_MESSAGE_BYTES: usize = 4 * 1024;
pub(super) const MAX_BATCH_BYTES: usize = 64 * 1024;
pub(super) const GENERATION_REPLY_TYPE: u16 = (10 << 8) | 15;
const HEADER: usize = 16;
const MAX_ATTRIBUTES: usize = 64;
const MAX_DEPTH: u8 = 8;
const REQUEST: u16 = 1;
const ACK: u16 = 4;
const EXCLUSIVE: u16 = 0x200;
const CREATE: u16 = 0x400;
const APPEND: u16 = 0x800;
const DUMP: u16 = 0x300;
const NESTED: u16 = 0x8000;
const NETWORK_ORDER: u16 = 0x4000;
const KIND_MASK: u16 = 0x3fff;
const REG: u32 = 1; // NFT_REG_1: full 16-byte data register, not a verdict.

fn require(condition: bool) -> Result<(), String> {
    if condition { Ok(()) } else { Err("native egress netlink original refused".to_owned()) }
}

fn aligned(length: usize) -> Result<usize, String> {
    length.checked_add(3).map(|value| value & !3)
        .ok_or_else(|| "native egress wire length overflow".to_owned())
}

fn table_name(table: &str) -> Result<(), String> {
    require(table.len() == 39 && table.starts_with("swnegr_")
        && table[7..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DumpKind { Table, Chain, Rules, Set, Object, FlowTable }

impl DumpKind {
    fn request_type(self) -> u16 {
        (10 << 8) | match self {
            Self::Table => 1, Self::Chain => 4, Self::Rules => 7,
            Self::Set => 10, Self::Object => 19, Self::FlowTable => 23,
        }
    }

    pub(super) fn reply_type(self) -> u16 { self.request_type() - 1 }
}

pub(super) struct Ack {
    pub(super) sequence: u32,
    pub(super) message_type: u16,
    pub(super) expected_header: [u8; HEADER],
}

pub(super) struct Transaction {
    original: Vec<u8>,
    acks: Vec<Ack>,
    last_sequence: u32,
}

impl Transaction {
    pub(super) fn build(ruleset: &Ruleset, generation: u32, portid: u32,
        first_seq: u32) -> Result<Self, String> {
        // Zero GENID is the kernel's unguarded sentinel, never a valid pin here.
        require(generation != 0 && portid != 0 && first_seq != 0)?;
        let rules = expected_rule_expressions(ruleset)?;
        let count = rules.len().checked_add(4).ok_or("native egress sequence overflow")?;
        let last_sequence = first_seq.checked_add(u32::try_from(count - 1)
            .map_err(|_| "native egress sequence overflow")?)
            .ok_or("native egress sequence overflow")?;
        let mut result = Self { original: Vec::new(), acks: Vec::with_capacity(count), last_sequence };
        let mut sequence = first_seq;
        result.append(message(16, REQUEST | ACK, sequence, portid, 0, 10,
            &u32_attr(1, generation)?)?)?;
        sequence += 1;
        let table = join(&[string_attr(1, &ruleset.table_name)?, u32_attr(2, 0)?])?;
        result.append(message(10 << 8, REQUEST | ACK | CREATE | EXCLUSIVE,
            sequence, portid, 1, 0, &table)?)?;
        sequence += 1;
        let hook = join(&[u32_attr(1, 3)?, u32_attr(2, (-10_i32) as u32)?])?;
        let chain = join(&[string_attr(1, &ruleset.table_name)?, string_attr(3, "output")?,
            attr(4, true, &hook)?, u32_attr(5, 0)?, string_attr(7, "filter")?, u32_attr(10, 1)?])?;
        result.append(message((10 << 8) | 3, REQUEST | ACK | CREATE | EXCLUSIVE,
            sequence, portid, 1, 0, &chain)?)?;
        sequence += 1;
        for expressions in rules {
            let rule = join(&[string_attr(1, &ruleset.table_name)?, string_attr(2, "output")?,
                attr(4, true, &expressions)?])?;
            result.append(message((10 << 8) | 6, REQUEST | ACK | CREATE | EXCLUSIVE | APPEND,
                sequence, portid, 1, 0, &rule)?)?;
            sequence += 1;
        }
        require(sequence == last_sequence)?;
        result.append(message(17, REQUEST | ACK, sequence, portid, 0, 10, &[])?)?;
        require(result.acks.len() == count && result.original.len() <= MAX_BATCH_BYTES)?;
        Ok(result)
    }

    fn append(&mut self, original: Vec<u8>) -> Result<(), String> {
        require(self.original.len().checked_add(original.len())
            .is_some_and(|length| length <= MAX_BATCH_BYTES))?;
        let mut expected_header = [0; HEADER];
        expected_header.copy_from_slice(&original[..HEADER]);
        self.acks.push(Ack { sequence: u32::from_ne_bytes(expected_header[8..12]
                .try_into().map_err(|_| "native egress header invalid")?),
            message_type: u16::from_ne_bytes(expected_header[4..6]
                .try_into().map_err(|_| "native egress header invalid")?), expected_header });
        self.original.extend_from_slice(&original);
        Ok(())
    }

    pub(super) fn bytes(&self) -> &[u8] { &self.original }
    pub(super) fn expected_acks(&self) -> &[Ack] { &self.acks }
    pub(super) fn last_sequence(&self) -> u32 { self.last_sequence }
}

pub(super) fn get_generation_request(portid: u32, sequence: u32) -> Result<Vec<u8>, String> {
    message((10 << 8) | 16, REQUEST, sequence, portid, 0, 0, &[])
}

pub(super) fn dump_request(kind: DumpKind, table: &str, portid: u32,
    sequence: u32) -> Result<Vec<u8>, String> {
    table_name(table)?;
    // Unfiltered AF_UNSPEC dumps expose other-family and other-table additions.
    // The table argument is the authenticated expected name, not a filter.
    message(kind.request_type(), REQUEST | DUMP, sequence, portid, 0, 0, &[])
}

fn message(kind: u16, flags: u16, sequence: u32, portid: u32, family: u8,
    resource: u16, attributes: &[u8]) -> Result<Vec<u8>, String> {
    require(sequence != 0 && portid != 0 && attributes.len() <= MAX_MESSAGE_BYTES - HEADER - 4)?;
    check_tree(attributes, 1, &mut 0)?;
    let length = HEADER + 4 + attributes.len();
    require(length <= MAX_MESSAGE_BYTES && length % 4 == 0)?;
    let mut original = Vec::with_capacity(length);
    original.extend_from_slice(&(length as u32).to_ne_bytes());
    original.extend_from_slice(&kind.to_ne_bytes());
    original.extend_from_slice(&flags.to_ne_bytes());
    original.extend_from_slice(&sequence.to_ne_bytes());
    original.extend_from_slice(&portid.to_ne_bytes());
    original.extend_from_slice(&[family, 0]);
    original.extend_from_slice(&resource.to_be_bytes());
    original.extend_from_slice(attributes);
    Ok(original)
}

fn attr(kind: u16, nested: bool, payload: &[u8]) -> Result<Vec<u8>, String> {
    require(kind > 0 && kind <= KIND_MASK && payload.len() <= MAX_MESSAGE_BYTES - 4)?;
    let length = 4 + payload.len();
    let mut result = Vec::with_capacity(aligned(length)?);
    result.extend_from_slice(&(length as u16).to_ne_bytes());
    result.extend_from_slice(&(kind | if nested { NESTED } else { 0 }).to_ne_bytes());
    result.extend_from_slice(payload);
    result.resize(aligned(length)?, 0);
    Ok(result)
}

fn u32_attr(kind: u16, value: u32) -> Result<Vec<u8>, String> { attr(kind, false, &value.to_be_bytes()) }

fn string_attr(kind: u16, value: &str) -> Result<Vec<u8>, String> {
    require(!value.is_empty() && value.len() <= 255
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)))?;
    let mut payload = value.as_bytes().to_vec();
    payload.push(0);
    attr(kind, false, &payload)
}

fn join(parts: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    require(parts.len() <= MAX_ATTRIBUTES)?;
    let mut result = Vec::new();
    for part in parts {
        require(result.len().checked_add(part.len()).is_some_and(|size| size <= MAX_MESSAGE_BYTES))?;
        result.extend_from_slice(part);
    }
    Ok(result)
}

fn expression(name: &str, data: Vec<u8>) -> Result<Vec<u8>, String> {
    attr(1, true, &join(&[string_attr(1, name)?, attr(2, true, &data)?])?)
}

fn meta(key: u32) -> Result<Vec<u8>, String> {
    expression("meta", join(&[u32_attr(1, REG)?, u32_attr(2, key)?])?)
}

fn compare(operator: u32, value: &[u8]) -> Result<Vec<u8>, String> {
    require(matches!(operator, 0 | 1) && matches!(value.len(), 1 | 2 | 4 | 16))?;
    expression("cmp", join(&[u32_attr(1, REG)?, u32_attr(2, operator)?,
        attr(3, true, &attr(1, false, value)?)?])?)
}

fn payload(base: u32, offset: u32, length: u32) -> Result<Vec<u8>, String> {
    expression("payload", join(&[u32_attr(1, REG)?, u32_attr(2, base)?,
        u32_attr(3, offset)?, u32_attr(4, length)?])?)
}

fn verdict(code: u32) -> Result<Vec<u8>, String> {
    require(code <= 1)?; // NF_DROP or NF_ACCEPT only; no jumps, queues or returns.
    expression("immediate", join(&[u32_attr(1, 0)?,
        attr(2, true, &attr(2, true, &u32_attr(1, code)?)?)?])?)
}

fn ipv4_fragment_drop() -> Result<Vec<u8>, String> {
    let bitwise = expression("bitwise", join(&[u32_attr(1, REG)?, u32_attr(2, REG)?,
        u32_attr(3, 2)?, attr(4, true, &attr(1, false, &[0x3f, 0xff])?)?,
        attr(5, true, &attr(1, false, &[0, 0])?)?, u32_attr(6, 0)?])?)?;
    // IP_MF | IP_OFFSET; DF deliberately does not match this mask.
    join(&[meta(15)?, compare(0, &[2])?, payload(1, 6, 2)?, bitwise,
        compare(1, &[0, 0])?, verdict(0)?])
}

fn ipv6_fragment_drop() -> Result<Vec<u8>, String> {
    let presence = expression("exthdr", join(&[u32_attr(1, REG)?, attr(2, false, &[44])?,
        u32_attr(3, 0)?, u32_attr(4, 1)?, u32_attr(5, 1)?, u32_attr(6, 0)?])?)?;
    // PRESENT searches for type44 itself, including an atomic Fragment header.
    join(&[meta(15)?, compare(0, &[10])?, presence, compare(0, &[1])?, verdict(0)?])
}

/// Original ordered expression-list payloads, shared by create and typed readback.
pub(super) fn expected_rule_expressions(ruleset: &Ruleset) -> Result<Vec<Vec<u8>>, String> {
    table_name(&ruleset.table_name)?;
    require(ruleset.profile == "nft-inet-output-tcp-create-v1" && ruleset.family == "inet"
        && ruleset.chain_name == "output" && ruleset.chain_type == "filter"
        && ruleset.hook == "output" && ruleset.priority == -10 && ruleset.policy == "drop"
        && !ruleset.rules.is_empty() && ruleset.rules.len() <= 16)?;
    let mut originals = vec![ipv4_fragment_drop()?, ipv6_fragment_drop()?];
    if let Some(port) = ruleset.loopback_port {
        require(port >= 1024)?;
        // Two explicit directions, only 127.0.0.1 -> 127.0.0.1 TCP on the
        // fixed listener port. No blanket lo accept or external return rule.
        for offset in [0, 2] {
            originals.push(join(&[meta(15)?, compare(0, &[2])?, meta(16)?, compare(0, &[6])?,
                payload(1, 12, 8)?, compare(0, &[127,0,0,1,127,0,0,1])?,
                payload(2, offset, 2)?, compare(0, &port.to_be_bytes())?, verdict(1)?])?);
        }
    }
    let mut previous: Option<Vec<u8>> = None;
    let mut port = None;
    for rule in &ruleset.rules {
        require(rule.verdict == "accept" && rule.tcp_destination_port != 0
            && port.is_none_or(|value| value == rule.tcp_destination_port))?;
        port = Some(rule.tcp_destination_port);
        let address: IpAddr = rule.address.parse().map_err(|_| "native egress rule address invalid")?;
        require(address.to_string() == rule.address && !address.is_unspecified() && !address.is_multicast())?;
        let (family, offset, octets) = match address {
            IpAddr::V4(ip) => {
                require(rule.family == "ipv4" && !ip.is_broadcast())?;
                (2, 16, ip.octets().to_vec())
            }
            IpAddr::V6(ip) => {
                require(rule.family == "ipv6" && ip.to_ipv4_mapped().is_none())?;
                (10, 24, ip.octets().to_vec())
            }
        };
        let mut key = vec![family];
        key.extend_from_slice(&octets);
        require(previous.as_ref().is_none_or(|value| value < &key))?;
        previous = Some(key);
        originals.push(join(&[meta(15)?, compare(0, &[family])?, meta(16)?, compare(0, &[6])?,
            payload(1, offset, octets.len() as u32)?, compare(0, &octets)?, payload(2, 2, 2)?,
            compare(0, &rule.tcp_destination_port.to_be_bytes())?, verdict(1)?])?);
    }
    for original in &originals { check_tree(original, 2, &mut 0)?; }
    Ok(originals)
}

pub(super) struct Frame<'a> {
    pub(super) original: &'a [u8],
    pub(super) message_type: u16,
    pub(super) flags: u16,
    pub(super) sequence: u32,
    pub(super) port_id: u32,
    pub(super) payload: &'a [u8],
}

/// Structural parsing only. The socket owner/readback must check sender, phase,
/// sequence, port, type and permitted flags; parsing is not a kernel verdict.
pub(super) fn frames(raw: &[u8]) -> Result<Vec<Frame<'_>>, String> {
    require(!raw.is_empty() && raw.len() <= MAX_BATCH_BYTES)?;
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < raw.len() {
        require(frames.len() < 64 && raw.len() - offset >= HEADER)?;
        let header = &raw[offset..offset + HEADER];
        let length = u32::from_ne_bytes(header[..4].try_into().map_err(|_| "native netlink header invalid")?) as usize;
        require((HEADER..=MAX_MESSAGE_BYTES).contains(&length) && length <= raw.len() - offset)?;
        let end = offset + length;
        let next = offset.checked_add(aligned(length)?).ok_or("native netlink frame overflow")?;
        require(next <= raw.len() && raw[end..next].iter().all(|byte| *byte == 0))?;
        let flags = u16::from_ne_bytes(header[6..8].try_into().map_err(|_| "native netlink flags invalid")?);
        require(flags & !0x0f3f == 0)?;
        let message_type = u16::from_ne_bytes(header[4..6].try_into().map_err(|_| "native netlink type invalid")?);
        require(message_type != 0)?;
        frames.push(Frame { original: &raw[offset..end], message_type, flags,
            sequence: u32::from_ne_bytes(header[8..12].try_into().map_err(|_| "native netlink sequence invalid")?),
            port_id: u32::from_ne_bytes(header[12..16].try_into().map_err(|_| "native netlink port invalid")?),
            payload: &raw[offset + HEADER..end] });
        offset = next;
    }
    Ok(frames)
}

pub(super) struct Attr<'a> {
    pub(super) kind: u16,
    pub(super) nested: bool,
    pub(super) network_order: bool,
    pub(super) payload: &'a [u8],
}

fn scan(raw: &[u8], depth: u8) -> Result<Vec<Attr<'_>>, String> {
    require((1..=MAX_DEPTH).contains(&depth) && raw.len() <= MAX_MESSAGE_BYTES && raw.len() % 4 == 0)?;
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < raw.len() {
        require(result.len() < MAX_ATTRIBUTES && raw.len() - offset >= 4)?;
        let length = u16::from_ne_bytes([raw[offset], raw[offset + 1]]) as usize;
        let tag = u16::from_ne_bytes([raw[offset + 2], raw[offset + 3]]);
        require(length >= 4 && length <= raw.len() - offset && tag & KIND_MASK != 0
            && tag & (NESTED | NETWORK_ORDER) != NESTED | NETWORK_ORDER)?;
        let next = offset.checked_add(aligned(length)?).ok_or("native netlink attribute overflow")?;
        require(next <= raw.len() && raw[offset + length..next].iter().all(|byte| *byte == 0))?;
        result.push(Attr { kind: tag & KIND_MASK, nested: tag & NESTED != 0,
            network_order: tag & NETWORK_ORDER != 0, payload: &raw[offset + 4..offset + length] });
        offset = next;
    }
    Ok(result)
}

pub(super) fn attributes(raw: &[u8], depth: u8) -> Result<Vec<Attr<'_>>, String> {
    singletons(raw, depth, None)
}

pub(super) fn attributes_with_padding(raw: &[u8], depth: u8, pad_kind: u16)
    -> Result<Vec<Attr<'_>>, String> {
    require(pad_kind > 0 && pad_kind <= KIND_MASK)?;
    singletons(raw, depth, Some(pad_kind))
}

fn singletons(raw: &[u8], depth: u8, pad_kind: Option<u16>) -> Result<Vec<Attr<'_>>, String> {
    let mut result: Vec<Attr<'_>> = Vec::new();
    for attribute in scan(raw, depth)? {
        if Some(attribute.kind) == pad_kind {
            require(!attribute.nested && !attribute.network_order && attribute.payload.is_empty())?;
        } else {
            require(!result.iter().any(|previous| previous.kind == attribute.kind))?;
            result.push(attribute);
        }
    }
    Ok(result)
}

pub(super) fn list_attributes(raw: &[u8], depth: u8) -> Result<Vec<Attr<'_>>, String> {
    let result = scan(raw, depth)?;
    // v6.12 dumps use nla_nest_start_noflag; the typed list context owns nesting.
    require(result.iter().all(|attribute| attribute.kind == 1 && !attribute.network_order))?;
    Ok(result)
}

fn check_tree(raw: &[u8], depth: u8, total: &mut usize) -> Result<(), String> {
    for attribute in scan(raw, depth)? {
        *total = total.checked_add(1).ok_or("native netlink attribute count overflow")?;
        require(*total <= MAX_ATTRIBUTES)?;
        if attribute.nested { check_tree(attribute.payload, depth + 1, total)?; }
    }
    Ok(())
}
