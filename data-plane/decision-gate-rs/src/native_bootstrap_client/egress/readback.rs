//! Bounded semantic interpretation of retained kernel reply originals.
//!
//! This result is data, not installation permission or a substitute for the
//! backend's socket/namespace provenance, original clock, or durable raw custody.
//! Dump shape is pinned to Linux v6.12 nf_tables_api.c fill/dump functions;
//! legacy noflag containers and kernel metadata are not request-byte equality.

use super::{authority::Ruleset, backend::ReplyOriginals, wire::{self, Attr, DumpKind, Frame}};
use serverware_decision_gate::native_response_profile_v1::canonical_ascii_bytes;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_MESSAGES: usize = 256;
const MULTI: u16 = 2;
const APPEND: u16 = 0x800;
const DONE: u16 = 3;
const DOMAIN: &[u8] = b"serverware/native-egress-observed-semantics/v1\0";

pub(super) struct Readback {
    generation: u32,
    semantic_sha256: [u8; 32],
}

impl Readback {
    pub(super) fn generation(&self) -> u32 { self.generation }
    pub(super) fn semantic_sha256(&self) -> [u8; 32] { self.semantic_sha256 }
}

fn require(condition: bool) -> Result<(), String> {
    if condition { Ok(()) } else { Err("native egress kernel readback refused".to_owned()) }
}

fn refused() -> String { "native egress kernel readback refused".to_owned() }

// Closed structural normalization: attribute order and legacy nested flags may
// differ, but bytes, register choices and expression/list order may not.
#[derive(PartialEq, Eq)]
enum Value {
    Bytes(Vec<u8>),
    Fields(BTreeMap<u16, Value>),
}

#[derive(PartialEq, Eq)]
struct Expression {
    name: String,
    fields: BTreeMap<u16, Value>,
}

fn scalar<'a>(attribute: &Attr<'a>, length: usize) -> Result<&'a [u8], String> {
    require(!attribute.nested && !attribute.network_order && attribute.payload.len() == length)?;
    Ok(attribute.payload)
}

fn container<'a>(attribute: &Attr<'a>) -> Result<&'a [u8], String> {
    // nf_tables_api.c intentionally uses nla_nest_start_noflag on dumps.
    require(!attribute.network_order)?;
    Ok(attribute.payload)
}

fn be32(attribute: &Attr<'_>) -> Result<u32, String> {
    Ok(u32::from_be_bytes(scalar(attribute, 4)?.try_into().map_err(|_| refused())?))
}

fn be64(attribute: &Attr<'_>) -> Result<u64, String> {
    Ok(u64::from_be_bytes(scalar(attribute, 8)?.try_into().map_err(|_| refused())?))
}

fn string<'a>(attribute: &Attr<'a>, maximum: usize) -> Result<&'a str, String> {
    require(!attribute.nested && !attribute.network_order)?;
    let raw = attribute.payload;
    require(raw.len() >= 2 && raw.len() <= maximum + 1 && raw.last() == Some(&0))?;
    require(!raw[..raw.len() - 1].contains(&0))?;
    std::str::from_utf8(&raw[..raw.len() - 1]).map_err(|_| refused())
}

fn field<'a, 'b>(attributes: &'b [Attr<'a>], kind: u16) -> Result<&'b Attr<'a>, String> {
    attributes.iter().find(|attribute| attribute.kind == kind).ok_or_else(refused)
}

fn shape(attributes: &[Attr<'_>], required: &[u16], optional: &[u16]) -> Result<(), String> {
    require(required.iter().all(|kind| attributes.iter().any(|attribute| attribute.kind == *kind))
        && attributes.iter().all(|attribute| required.contains(&attribute.kind)
            || optional.contains(&attribute.kind)))
}

fn byte_value(attribute: &Attr<'_>, length: usize) -> Result<Value, String> {
    Ok(Value::Bytes(scalar(attribute, length)?.to_vec()))
}

fn data(attribute: &Attr<'_>, depth: u8, verdict: bool) -> Result<Value, String> {
    let attributes = wire::attributes(container(attribute)?, depth)?;
    let kind = if verdict { 2 } else { 1 };
    shape(&attributes, &[kind], &[])?;
    let value = if verdict {
        let children = wire::attributes(container(field(&attributes, 2)?)?, depth + 1)?;
        shape(&children, &[1], &[])?;
        let mut values = BTreeMap::new();
        values.insert(1, byte_value(field(&children, 1)?, 4)?);
        Value::Fields(values)
    } else {
        let value = field(&attributes, 1)?;
        require(!value.payload.is_empty() && value.payload.len() <= 16)?;
        byte_value(value, value.payload.len())?
    };
    let mut values = BTreeMap::new();
    values.insert(kind, value);
    Ok(Value::Fields(values))
}

fn expressions(original: &[u8]) -> Result<Vec<Expression>, String> {
    // Object attrs are depth1, expressions depth2, list element depth3,
    // expr-data depth4, data depth5, verdict depth6; no generic recursion.
    let list = wire::list_attributes(original, 2)?;
    require(!list.is_empty() && list.len() <= 16)?;
    let mut result = Vec::with_capacity(list.len());
    for element in list {
        let outer = wire::attributes(container(&element)?, 3)?;
        shape(&outer, &[1, 2], &[])?;
        let name = string(field(&outer, 1)?, 16)?;
        let attributes = wire::attributes(container(field(&outer, 2)?)?, 4)?;
        let (scalars, data_fields, verdict): (&[u16], &[u16], bool) = match name {
            "meta" => (&[1, 2], &[], false),
            "payload" => (&[1, 2, 3, 4], &[], false),
            "cmp" => (&[1, 2], &[3], false),
            "immediate" => (&[1], &[2], true),
            "bitwise" => (&[1, 2, 3, 6], &[4, 5], false),
            "exthdr" => (&[1, 2, 3, 4, 5, 6], &[], false),
            _ => return Err(refused()),
        };
        let required: Vec<u16> = scalars.iter().chain(data_fields.iter()).copied().collect();
        shape(&attributes, &required, &[])?;
        let mut fields = BTreeMap::new();
        for attribute in &attributes {
            let value = if data_fields.contains(&attribute.kind) {
                data(attribute, 5, verdict)?
            } else {
                byte_value(attribute, if name == "exthdr" && attribute.kind == 2 { 1 } else { 4 })?
            };
            fields.insert(attribute.kind, value);
        }
        result.push(Expression { name: name.to_owned(), fields });
    }
    Ok(result)
}

fn collect(original: &ReplyOriginals) -> Result<Vec<Frame<'_>>, String> {
    require(original.sequence() != 0 && original.port_id() != 0)?;
    let mut total = original.request().len();
    let mut result = Vec::new();
    for datagram in original.datagrams() {
        total = total.checked_add(datagram.len()).ok_or_else(refused)?;
        require(total <= MAX_BYTES)?;
        for frame in wire::frames(datagram)? {
            require(frame.sequence == original.sequence() && frame.port_id == original.port_id())?;
            result.push(frame);
            require(result.len() <= MAX_MESSAGES)?;
        }
    }
    require(!result.is_empty())?;
    Ok(result)
}

fn object_body<'a>(frame: &Frame<'a>, family: u8, generation: u32) -> Result<&'a [u8], String> {
    let raw = frame.payload;
    require(raw.len() >= 4 && raw[0] == family && raw[1] == 0)?;
    require(u16::from_be_bytes([raw[2], raw[3]]) == generation as u16)?;
    Ok(&raw[4..])
}

pub(super) fn generation(original: &ReplyOriginals) -> Result<u32, String> {
    require(original.request() == wire::get_generation_request(original.port_id(), original.sequence())?)?;
    let frames = collect(original)?;
    require(frames.len() == 1)?;
    let frame = &frames[0];
    require(frame.message_type == wire::GENERATION_REPLY_TYPE && frame.flags == 0
        && frame.payload.len() >= 4)?;
    let attributes = wire::attributes(&frame.payload[4..], 1)?;
    shape(&attributes, &[1, 2, 3], &[])?;
    let value = be32(field(&attributes, 1)?)?;
    require(value != 0)?; // Zero is the batch API's unguarded generation sentinel.
    object_body(frame, 0, value)?;
    be32(field(&attributes, 2)?)?;
    // PROC_NAME is informational kernel task_comm, not an identity/policy field.
    let name = field(&attributes, 3)?;
    require(!name.nested && !name.network_order && !name.payload.is_empty()
        && name.payload.len() <= 16 && name.payload.last() == Some(&0)
        && !name.payload[..name.payload.len() - 1].contains(&0))?;
    Ok(value)
}

fn dump<'a>(original: &'a ReplyOriginals, kind: DumpKind, table: &str,
    generation: u32) -> Result<Vec<Frame<'a>>, String> {
    require(original.request() == wire::dump_request(kind, table, original.port_id(), original.sequence())?)?;
    let mut frames = collect(original)?;
    let done = frames.pop().ok_or_else(refused)?;
    require(done.message_type == DONE && done.flags == MULTI && done.payload == [0, 0, 0, 0])?;
    let flags = MULTI | if kind == DumpKind::Rules { APPEND } else { 0 };
    for frame in &frames {
        // Excludes ERROR/OVERRUN, interrupted/filtered dumps and unknown flags.
        require(frame.message_type == kind.reply_type() && frame.flags == flags)?;
        object_body(frame, 1, generation)?;
    }
    Ok(frames)
}

fn table(frame: &Frame<'_>, expected: &Ruleset, generation: u32) -> Result<(), String> {
    let attributes = wire::attributes_with_padding(object_body(frame, 1, generation)?, 1, 5)?;
    shape(&attributes, &[1, 2, 3, 4], &[])?;
    require(string(field(&attributes, 1)?, 255)? == expected.table_name
        && be32(field(&attributes, 2)?)? == 0
        && be64(field(&attributes, 4)?)? != 0)?;
    be32(field(&attributes, 3)?)?; // USE is observational, not permission.
    Ok(())
}

fn chain(frame: &Frame<'_>, expected: &Ruleset, generation: u32) -> Result<(), String> {
    let attributes = wire::attributes_with_padding(object_body(frame, 1, generation)?, 1, 9)?;
    shape(&attributes, &[1, 2, 3, 4, 5, 6, 7, 10], &[8])?;
    require(string(field(&attributes, 1)?, 255)? == expected.table_name
        && string(field(&attributes, 3)?, 255)? == expected.chain_name
        && string(field(&attributes, 7)?, 16)? == "filter"
        && be64(field(&attributes, 2)?)? != 0
        && be32(field(&attributes, 5)?)? == 0
        && be32(field(&attributes, 10)?)? == 1)?; // BASE only; no offload/binding.
    be32(field(&attributes, 6)?)?;
    let hook = wire::attributes(container(field(&attributes, 4)?)?, 2)?;
    shape(&hook, &[1, 2], &[])?;
    require(be32(field(&hook, 1)?)? == 3 && be32(field(&hook, 2)?)? == (-10_i32) as u32)?;
    if let Some(counters) = attributes.iter().find(|attribute| attribute.kind == 8) {
        // Base-chain accounting is not an expression/verdict. Values can change
        // without a generation change and are retained only in raw originals.
        let counters = wire::attributes_with_padding(container(counters)?, 2, 3)?;
        shape(&counters, &[1, 2], &[])?;
        be64(field(&counters, 1)?)?;
        be64(field(&counters, 2)?)?;
    }
    Ok(())
}

fn rule(frame: &Frame<'_>, expected: &Ruleset, generation: u32,
    previous: Option<u64>) -> Result<(u64, Vec<Expression>), String> {
    let attributes = wire::attributes_with_padding(object_body(frame, 1, generation)?, 1, 8)?;
    shape(&attributes, &[1, 2, 3, 4], if previous.is_some() { &[6] } else { &[] })?;
    require(string(field(&attributes, 1)?, 255)? == expected.table_name
        && string(field(&attributes, 2)?, 255)? == expected.chain_name)?;
    let handle = be64(field(&attributes, 3)?)?;
    require(handle != 0)?;
    if let Some(previous) = previous {
        require(be64(field(&attributes, 6)?)? == previous)?;
    }
    Ok((handle, expressions(container(field(&attributes, 4)?)?)?))
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) -> Result<(), String> {
    let length = u32::try_from(bytes.len()).map_err(|_| refused())?;
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn hash_fields(hasher: &mut Sha256, fields: &BTreeMap<u16, Value>) -> Result<(), String> {
    hasher.update(u32::try_from(fields.len()).map_err(|_| refused())?.to_be_bytes());
    for (kind, value) in fields {
        hasher.update(kind.to_be_bytes());
        match value {
            Value::Bytes(bytes) => { hasher.update([0]); hash_bytes(hasher, bytes)?; }
            Value::Fields(children) => { hasher.update([1]); hash_fields(hasher, children)?; }
        }
    }
    Ok(())
}

fn snapshot_generation(before: &ReplyOriginals, dumps: [&ReplyOriginals; 6],
    after: &ReplyOriginals) -> Result<u32, String> {
    let all = [before, dumps[0], dumps[1], dumps[2], dumps[3], dumps[4], dumps[5], after];
    let (mut bytes, mut messages, mut previous_sequence) = (0_usize, 0_usize, 0_u32);
    for original in all {
        require(original.port_id() == before.port_id() && original.sequence() > previous_sequence)?;
        previous_sequence = original.sequence();
        bytes = bytes.checked_add(original.request().len()).ok_or_else(refused)?;
        for datagram in original.datagrams() {
            bytes = bytes.checked_add(datagram.len()).ok_or_else(refused)?;
            require(bytes <= MAX_BYTES)?;
            messages = messages.checked_add(wire::frames(datagram)?.len()).ok_or_else(refused)?;
            require(messages <= MAX_MESSAGES)?;
        }
    }
    require(bytes <= MAX_BYTES)?;
    let generation = generation(before)?;
    require(self::generation(after)? == generation)?;
    Ok(generation)
}

/// Preclaim observation only. Exclusive create and the batch generation pin
/// still protect against changes after this stable empty-namespace snapshot.
pub(super) fn verify_empty_namespace(expected: &Ruleset, before: &ReplyOriginals,
    dumps: [&ReplyOriginals; 6], after: &ReplyOriginals) -> Result<u32, String> {
    wire::expected_rule_expressions(expected)?;
    let generation = snapshot_generation(before, dumps, after)?;
    let kinds = [DumpKind::Table, DumpKind::Chain, DumpKind::Rules,
        DumpKind::Set, DumpKind::Object, DumpKind::FlowTable];
    for (original, kind) in dumps.into_iter().zip(kinds) {
        require(dump(original, kind, &expected.table_name, generation)?.is_empty())?;
    }
    Ok(generation)
}

pub(super) fn verify(expected: &Ruleset, before: &ReplyOriginals,
    dumps: [&ReplyOriginals; 6], after: &ReplyOriginals) -> Result<Readback, String> {
    // All six queries are AF_UNSPEC without name filtering. No other family or
    // table can hide extra hooks/objects in this exclusively created namespace.
    let generation = snapshot_generation(before, dumps, after)?;
    // Shared fixed constructor validates the signed Ruleset profile/fields and
    // generates explicit fragment exclusions before every address/port accept.
    let expected_originals = wire::expected_rule_expressions(expected)?;
    require((3..=18).contains(&expected_originals.len()))?;
    let table_frames = dump(dumps[0], DumpKind::Table, &expected.table_name, generation)?;
    let chain_frames = dump(dumps[1], DumpKind::Chain, &expected.table_name, generation)?;
    let rule_frames = dump(dumps[2], DumpKind::Rules, &expected.table_name, generation)?;
    require(table_frames.len() == 1 && chain_frames.len() == 1
        && rule_frames.len() == expected_originals.len())?;
    table(&table_frames[0], expected, generation)?;
    chain(&chain_frames[0], expected, generation)?;
    for (original, kind) in dumps[3..].iter().zip([DumpKind::Set, DumpKind::Object, DumpKind::FlowTable]) {
        require(dump(original, kind, &expected.table_name, generation)?.is_empty())?;
    }
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    let value = serde_json::to_value(expected).map_err(|_| refused())?;
    hash_bytes(&mut hasher, &canonical_ascii_bytes(&value)?)?;
    hasher.update(u32::try_from(rule_frames.len()).map_err(|_| refused())?.to_be_bytes());
    let mut previous = None;
    let mut handles = BTreeSet::new();
    for (frame, original) in rule_frames.iter().zip(&expected_originals) {
        let (handle, actual) = rule(frame, expected, generation, previous)?;
        require(handles.insert(handle) && actual == expressions(original)?)?;
        previous = Some(handle);
        hasher.update(u32::try_from(actual.len()).map_err(|_| refused())?.to_be_bytes());
        for expression in actual {
            hash_bytes(&mut hasher, expression.name.as_bytes())?;
            hash_fields(&mut hasher, &expression.fields)?;
        }
    }
    Ok(Readback { generation, semantic_sha256: hasher.finalize().into() })
}
