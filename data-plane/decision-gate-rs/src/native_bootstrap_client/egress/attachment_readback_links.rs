//! Bounded RTM_NEWLINK payload semantics, not netlink transport admission.
//! Linux v6.12 rtnl_fill_ifinfo/rtnl_link_info_fill and br_fill_info/
//! br_port_fill_attrs define the admitted dump fields. Only named statistics,
//! cache timers and carrier observations are removed from closing comparisons.

use super::super::{attachment_authority::Authorization, attachment_wire::Side};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_PAYLOAD: usize = 16 * 1024;
const RUNTIME_FLAGS: u32 = 0x40 | 0x10000 | 0x20000;

#[derive(Serialize, PartialEq, Eq)]
pub(super) struct Link {
    pub(super) index: u32,
    pub(super) link_type: u16,
    pub(super) flags: u32,
    pub(super) name: String,
    pub(super) mtu: u32,
    pub(super) mac: Vec<u8>,
    pub(super) master: Option<u32>,
    pub(super) peer: Option<u32>,
    pub(super) namespace_id: Option<i32>,
    pub(super) kind: Option<String>,
    pub(super) addrgen_mode: Option<u8>,
    pub(super) ipv6_conf: Vec<i32>,
    pub(super) ipv4_conf: Vec<i32>,
    pub(super) semantic_attributes: BTreeMap<u16, Vec<u8>>,
}

fn require(value: bool) -> Result<(), String> {
    if value { Ok(()) } else { Err("native attachment link semantics differ".to_owned()) }
}

#[derive(Clone, Copy)]
struct Attribute<'a> { flags: u16, value: &'a [u8] }
type Attributes<'a> = BTreeMap<u16, Attribute<'a>>;

// The kernel uses both flagged and historical unflagged nests. Empty alignment
// pads may repeat; every other duplicate base type is refused, irrespective of
// its flag spelling. No recursion or caller-chosen normalization exists here.
fn attributes(raw: &[u8], pad: Option<u16>) -> Result<Attributes<'_>, String> {
    require(raw.len() <= MAX_PAYLOAD)?;
    let mut result = BTreeMap::new();
    let (mut cursor, mut count) = (0usize, 0usize);
    while cursor < raw.len() {
        require(raw.len() - cursor >= 4 && count < 128)?;
        count += 1;
        let length = u16::from_ne_bytes(raw[cursor..cursor + 2].try_into().unwrap()) as usize;
        let tag = u16::from_ne_bytes(raw[cursor + 2..cursor + 4].try_into().unwrap());
        let kind = tag & 0x3fff;
        require(length >= 4 && length <= raw.len() - cursor && kind != 0)?;
        let padded = length.checked_add(3).ok_or("native link attribute length overflow")? & !3;
        require(padded <= raw.len() - cursor
            && raw[cursor + length..cursor + padded].iter().all(|byte| *byte == 0))?;
        let attr = Attribute { flags: tag & 0xc000, value: &raw[cursor + 4..cursor + length] };
        if Some(kind) == pad { require(attr.flags == 0 && attr.value.is_empty())?; }
        else { require(result.insert(kind, attr).is_none())?; }
        cursor += padded;
    }
    Ok(result)
}

fn scalar<'a>(attr: Attribute<'a>, size: usize) -> Result<&'a [u8], String> {
    require(attr.flags == 0 && attr.value.len() == size)?; Ok(attr.value)
}
fn nested<'a>(attr: Attribute<'a>) -> Result<&'a [u8], String> {
    require(matches!(attr.flags, 0 | 0x8000))?; Ok(attr.value)
}
fn text(attr: Attribute<'_>, maximum: usize) -> Result<String, String> {
    require(attr.flags == 0 && (2..=maximum + 1).contains(&attr.value.len())
        && attr.value.last() == Some(&0)
        && attr.value[..attr.value.len() - 1].iter().all(|byte| (0x21..=0x7e).contains(byte)))?;
    String::from_utf8(attr.value[..attr.value.len() - 1].to_vec())
        .map_err(|_| "native link text is not ASCII".to_owned())
}
fn needed<'a>(attrs: &Attributes<'a>, kind: u16) -> Result<Attribute<'a>, String> {
    attrs.get(&kind).copied().ok_or_else(|| "native link required attribute absent".to_owned())
}
fn unsigned(attr: Attribute<'_>) -> Result<u32, String> {
    Ok(u32::from_ne_bytes(scalar(attr, 4)?.try_into().unwrap()))
}
fn optional_unsigned(attrs: &Attributes<'_>, kind: u16) -> Result<Option<u32>, String> {
    attrs.get(&kind).copied().map(unsigned).transpose()
}
fn signed_vector(attr: Attribute<'_>) -> Result<Vec<i32>, String> {
    require(attr.flags == 0 && !attr.value.is_empty() && attr.value.len() <= 512
        && attr.value.len() % 4 == 0)?;
    Ok(attr.value.chunks_exact(4).map(|bytes| i32::from_ne_bytes(bytes.try_into().unwrap())).collect())
}
fn normalized(values: &BTreeMap<u16, Vec<u8>>) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    for (kind, value) in values {
        require(result.len().checked_add(6 + value.len()).is_some_and(|size| size <= MAX_PAYLOAD))?;
        result.extend_from_slice(&kind.to_be_bytes());
        result.extend_from_slice(&(value.len() as u32).to_be_bytes());
        result.extend_from_slice(value);
    }
    Ok(result)
}

fn bridge_data(attr: Attribute<'_>, port: bool) -> Result<Vec<u8>, String> {
    let attrs = attributes(nested(attr)?, Some(if port { 26 } else { 40 }))?;
    let mut retained = BTreeMap::new();
    for (kind, attr) in attrs {
        let width = if port {
            match kind {
                1 | 4..=12 | 19 | 20 | 25 | 27..=30 | 32 | 33 | 35 | 36 | 39 | 40 | 43 => 1,
                2 | 15..=18 | 31 => 2,
                3 | 34 | 37 | 38 | 41 | 42 | 44 => 4,
                13 | 14 | 21..=23 => 8,
                _ => return Err("native bridge port attribute is unsupported".to_owned()),
            }
        } else {
            match kind {
                7 | 14 | 15 | 22..=25 | 36..=38 | 41..=45 => 1,
                6 | 8 | 9 | 12 | 39 => 2,
                1..=5 | 13 | 26..=29 | 48 | 49 => 4,
                10 | 11 | 16..=19 | 30..=35 | 46 => 8,
                20 => 6,
                47 => {
                    // Querier election state is informational, never a source
                    // of forwarding permission or selected bridge policy.
                    let data = nested(attr)?; require(data.len() <= 1024)?;
                    let _ = attributes(data, None)?; continue;
                }
                _ => return Err("native bridge attribute is unsupported".to_owned()),
            }
        };
        if !port && kind == 8 {
            require(matches!(attr.flags, 0 | 0x4000) && attr.value.len() == width)?;
        } else { scalar(attr, width)?; }
        let informational = if port { matches!(kind, 21..=23 | 38 | 41) }
            else { matches!(kind, 16..=19 | 48) };
        if !informational { retained.insert(kind, attr.value.to_vec()); }
    }
    normalized(&retained)
}

fn link_info(attr: Attribute<'_>, link: &mut Link, bridge: bool, veth: bool,
    host_veth: bool) -> Result<Vec<u8>, String> {
    let attrs = attributes(nested(attr)?, None)?;
    let kind = text(needed(&attrs, 1)?, 32)?;
    require((bridge && kind == "bridge") || (veth && kind == "veth"))?;
    link.kind = Some(kind);
    let mut retained = BTreeMap::new();
    for (field, value) in &attrs {
        let bytes = match *field {
            1 => { text(*value, 32)?; value.value.to_vec() }
            2 if bridge => bridge_data(*value, false)?,
            4 if host_veth => { require(text(*value, 32)? == "bridge")?; value.value.to_vec() }
            5 if host_veth => bridge_data(*value, true)?,
            _ => return Err("native selected link encapsulation differs".to_owned()),
        };
        retained.insert(*field, bytes);
    }
    require(!bridge || attrs.contains_key(&2))?;
    require(!host_veth || (attrs.contains_key(&4) == link.master.is_some()
        && attrs.contains_key(&5) == link.master.is_some()))?;
    normalized(&retained)
}

fn address_families(attr: Attribute<'_>, link: &mut Link) -> Result<Vec<u8>, String> {
    let families = attributes(nested(attr)?, None)?;
    let mut retained = BTreeMap::new();
    for (family, outer) in families {
        let fields = attributes(nested(outer)?, None)?;
        let mut config = BTreeMap::new();
        for (kind, value) in fields {
            match (family, kind) {
                (2, 1) => { link.ipv4_conf = signed_vector(value)?; }
                (10, 1 | 9) => { scalar(value, 4)?; }
                (10, 2) => { link.ipv6_conf = signed_vector(value)?; }
                (10, 3 | 6) => {
                    require(value.flags == 0 && !value.value.is_empty()
                        && value.value.len() <= 4096 && value.value.len() % 8 == 0)?;
                    continue;
                }
                (10, 5) => { scalar(value, 16)?; continue; }
                (10, 7) => { scalar(value, 16)?; }
                (10, 8) => { link.addrgen_mode = Some(scalar(value, 1)?[0]); }
                _ => return Err("native link address-family attribute is unsupported".to_owned()),
            }
            config.insert(kind, value.value.to_vec());
        }
        retained.insert(family, normalized(&config)?);
    }
    normalized(&retained)
}

fn xdp(attr: Attribute<'_>, new_veth: bool) -> Result<Vec<u8>, String> {
    let attrs = attributes(nested(attr)?, None)?;
    let attached = scalar(needed(&attrs, 2)?, 1)?[0];
    require(attached <= 4 && (!new_veth || (attached == 0 && attrs.len() == 1)))?;
    let mut retained = BTreeMap::new();
    for (kind, value) in attrs {
        match kind { 2 => { scalar(value, 1)?; }, 4..=7 => { scalar(value, 4)?; },
            _ => return Err("native link XDP attribute is unsupported".to_owned()) }
        retained.insert(kind, value.value.to_vec());
    }
    normalized(&retained)
}

fn selected_attributes(attrs: &Attributes<'_>, link: &mut Link, bridge: bool,
    veth: bool, host_veth: bool) -> Result<(), String> {
    require(link.mac.len() == 6 && link.flags & !0x7ffff == 0)?;
    let mut semantic = BTreeMap::new();
    for (kind, value) in attrs {
        let retained = match *kind {
            1 | 2 | 54 => { scalar(*value, 6)?; Some(value.value.to_vec()) }
            3 => { text(*value, 15)?; Some(value.value.to_vec()) }
            4 | 5 | 10 | 13 | 27 | 30..=32 | 37 | 40 | 41 | 50 | 51 | 58..=61 | 63 | 64 => {
                scalar(*value, 4)?; Some(value.value.to_vec())
            }
            6 => {
                let name = text(*value, 32)?; require(!veth || name == "noqueue")?;
                Some(value.value.to_vec())
            }
            7 => { scalar(*value, 96)?; None }
            14 => { scalar(*value, 32)?; Some(value.value.to_vec()) }
            16 | 33 => { scalar(*value, 1)?; None }
            17 | 39 => { scalar(*value, 1)?; Some(value.value.to_vec()) }
            18 => Some(link_info(*value, link, bridge, veth, host_veth)?),
            20 if !veth => {
                require(value.flags == 0 && value.value.len() <= 256)?;
                Some(value.value.to_vec())
            }
            23 => { scalar(*value, 200)?; None }
            26 => Some(address_families(*value, link)?),
            35 | 47 | 48 => { scalar(*value, 4)?; None }
            43 => Some(xdp(*value, veth)?),
            // v6.12 emits these nests even without a device association.
            62 | 65 => { require(nested(*value)?.is_empty())?; Some(Vec::new()) }
            _ => return Err("native selected link attribute is unsupported".to_owned()),
        };
        if let Some(bytes) = retained { semantic.insert(*kind, bytes); }
    }
    require((!bridge && !veth) || attrs.contains_key(&18))?;
    require(!veth || (attrs.contains_key(&6) && attrs.contains_key(&43)
        && !attrs.contains_key(&20) && !attrs.contains_key(&52) && !attrs.contains_key(&53)))?;
    link.semantic_attributes = semantic;
    Ok(())
}

pub(super) fn parse(payloads: &[&[u8]], authority: &Authorization, side: Side)
    -> Result<BTreeMap<u32, Link>, String> {
    require(payloads.len() <= 256)?;
    let mut result = BTreeMap::new();
    let mut names = BTreeSet::new();
    for payload in payloads {
        require((16..=MAX_PAYLOAD).contains(&payload.len()) && payload[0] == 0 && payload[1] == 0
            && payload[12..16] == [0, 0, 0, 0])?;
        let index = i32::from_ne_bytes(payload[4..8].try_into().unwrap()); require(index > 0)?;
        let attrs = attributes(&payload[16..], Some(42))?;
        let name = text(needed(&attrs, 3)?, 15)?;
        require(!name.contains('/') && names.insert(name.clone()))?;
        let mtu = unsigned(needed(&attrs, 4)?)?; require(mtu != 0)?;
        let mac = if let Some(value) = attrs.get(&1) {
            require(value.flags == 0 && value.value.len() <= 32)?; value.value.to_vec()
        } else { Vec::new() };
        let namespace_id = attrs.get(&37).copied().map(|value|
            scalar(value, 4).map(|bytes| i32::from_ne_bytes(bytes.try_into().unwrap()))).transpose()?;
        let mut link = Link { index: index as u32,
            link_type: u16::from_ne_bytes(payload[2..4].try_into().unwrap()),
            flags: u32::from_ne_bytes(payload[8..12].try_into().unwrap()) & !RUNTIME_FLAGS,
            name, mtu, mac, master: optional_unsigned(&attrs, 10)?, peer: optional_unsigned(&attrs, 5)?,
            namespace_id, kind: None, addrgen_mode: None, ipv6_conf: Vec::new(),
            ipv4_conf: Vec::new(), semantic_attributes: BTreeMap::new() };
        let bridge = side == Side::Host && (link.name == authority.bridge.name || link.index == authority.bridge.ifindex);
        let host_veth = side == Side::Host && link.name == authority.attachment.host_veth_name;
        let veth = host_veth || (side == Side::Child && link.name == authority.attachment.child_veth_name);
        // Other host links contribute only collision inventory, never bridge
        // forwarding evidence. Every child link is parsed before the parent
        // enforces its exact loopback-plus-veth inventory.
        if bridge || veth || side == Side::Child {
            selected_attributes(&attrs, &mut link, bridge, veth, host_veth)?;
        }
        require(result.insert(link.index, link).is_none())?;
    }
    Ok(result)
}
