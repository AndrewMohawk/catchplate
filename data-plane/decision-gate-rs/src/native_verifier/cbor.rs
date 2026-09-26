//! Small borrowed CBOR decoder for original Nitro/COSE bytes only.
//!
//! Definite, minimal encodings are a fixed local profile, not an assertion that
//! AWS requires canonical CBOR. Maps may have any order; integer/text keys are
//! checked for semantic duplicates. No encoding normalization, general
//! serializer, permissive tag interpretation, or authority is supplied here.

use std::collections::BTreeSet;

pub(super) const MAX_BYTES: usize = 12 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_ITEMS: usize = 100_000;

pub(super) enum Value<'a> {
    Unsigned(u64),
    // Encoded n represents the integer -1-n, without overflowing an i64.
    Negative(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Value<'a>>),
    Map(Vec<(Value<'a>, Value<'a>)>),
    Tag(u64, Box<Value<'a>>),
    False,
    True,
    Null,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum MapKey<'a> {
    Unsigned(u64),
    Negative(u64),
    Text(&'a str),
}

struct Decoder<'a> {
    original: &'a [u8],
    cursor: usize,
    items: usize,
    reserved_items: usize,
}

pub(super) fn parse(original: &[u8]) -> Result<Value<'_>, String> {
    if original.is_empty() || original.len() > MAX_BYTES {
        return Err("Nitro CBOR original exceeds its byte bound".to_owned());
    }
    let mut decoder = Decoder { original, cursor: 0, items: 0, reserved_items: 0 };
    let value = decoder.value(0)?;
    if decoder.cursor != original.len() {
        return Err("Nitro CBOR original has trailing bytes".to_owned());
    }
    Ok(value)
}

impl<'a> Decoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self.cursor.checked_add(length).ok_or("Nitro CBOR length overflows")?;
        let bytes = self.original.get(self.cursor..end).ok_or("Nitro CBOR is truncated")?;
        self.cursor = end;
        Ok(bytes)
    }

    fn argument(&mut self, additional: u8) -> Result<u64, String> {
        if additional < 24 { return Ok(u64::from(additional)); }
        let (bytes, minimum) = match additional {
            24 => (1, 24),
            25 => (2, 1 << 8),
            26 => (4, 1 << 16),
            27 => (8, 1 << 32),
            _ => return Err("Nitro CBOR uses an indefinite or reserved encoding".to_owned()),
        };
        let mut value = 0u64;
        for byte in self.take(bytes)? { value = (value << 8) | u64::from(*byte); }
        if value < minimum { return Err("Nitro CBOR integer or length is not minimal".to_owned()); }
        Ok(value)
    }

    fn length(&mut self, additional: u8) -> Result<usize, String> {
        usize::try_from(self.argument(additional)?)
            .map_err(|_| "Nitro CBOR length exceeds this address space".to_owned())
    }

    fn container_bound(&mut self, length: usize, items_per_entry: usize) -> Result<(), String> {
        let minimum_items = length.checked_mul(items_per_entry).ok_or("Nitro CBOR container overflows")?;
        // Each encoded child takes at least one original byte. Check this
        // before reserving memory, including for malicious huge length fields.
        if length > MAX_ITEMS || minimum_items > self.original.len() - self.cursor
            || minimum_items > MAX_ITEMS.saturating_sub(self.items) {
            return Err("Nitro CBOR container exceeds its original or item bound".to_owned());
        }
        // Charge all reservations, including parents still being populated, so
        // nested malicious length declarations cannot amplify allocations.
        self.reserved_items = self.reserved_items.checked_add(minimum_items)
            .filter(|total| *total <= MAX_ITEMS)
            .ok_or("Nitro CBOR aggregate allocation bound exceeded")?;
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Value<'a>, String> {
        if depth > MAX_DEPTH || self.items >= MAX_ITEMS {
            return Err("Nitro CBOR nesting or item count exceeds its bound".to_owned());
        }
        self.items += 1;
        let initial = self.take(1)?[0];
        let additional = initial & 31;
        match initial >> 5 {
            0 => Ok(Value::Unsigned(self.argument(additional)?)),
            1 => Ok(Value::Negative(self.argument(additional)?)),
            2 => {
                let length = self.length(additional)?;
                Ok(Value::Bytes(self.take(length)?))
            }
            3 => {
                let length = self.length(additional)?;
                let value = std::str::from_utf8(self.take(length)?)
                    .map_err(|_| "Nitro CBOR text is not valid UTF-8")?;
                Ok(Value::Text(value))
            }
            4 => {
                let length = self.length(additional)?;
                self.container_bound(length, 1)?;
                let mut values = Vec::with_capacity(length);
                for _ in 0..length { values.push(self.value(depth + 1)?); }
                Ok(Value::Array(values))
            }
            5 => {
                let length = self.length(additional)?;
                self.container_bound(length, 2)?;
                let mut entries = Vec::with_capacity(length);
                let mut keys = BTreeSet::new();
                for _ in 0..length {
                    let key = self.value(depth + 1)?;
                    let identity = match &key {
                        Value::Unsigned(value) => MapKey::Unsigned(*value),
                        Value::Negative(value) => MapKey::Negative(*value),
                        Value::Text(value) => MapKey::Text(*value),
                        _ => return Err("Nitro CBOR map keys must be integers or text".to_owned()),
                    };
                    if !keys.insert(identity) {
                        return Err("Nitro CBOR map has a duplicate key".to_owned());
                    }
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            6 => {
                let tag = self.argument(additional)?;
                self.container_bound(1, 1)?;
                Ok(Value::Tag(tag, Box::new(self.value(depth + 1)?)))
            }
            7 => match additional {
                20 => Ok(Value::False),
                21 => Ok(Value::True),
                22 => Ok(Value::Null),
                _ => Err("Nitro CBOR floating or unsupported simple value is forbidden".to_owned()),
            },
            _ => Err("Nitro CBOR major type is invalid".to_owned()),
        }
    }
}
