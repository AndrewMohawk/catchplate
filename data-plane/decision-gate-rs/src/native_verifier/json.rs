//! Bounded strict JSON with duplicate detection before constructing a Value.
//! UTF-8 scalar strings and signed-i64/unsigned-u64 numbers match Rust custody;
//! floating values, excessive structure and trailing input are never accepted.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

const MAX_NODES: usize = 100_000;
const MAX_DEPTH: usize = 64;

pub(super) fn parse(raw: &[u8], maximum: usize) -> Result<Value, String> {
    super::ensure(!raw.is_empty() && raw.len() <= maximum, "native JSON exceeds its byte bound")?;
    let mut parser = serde_json::Deserializer::from_slice(raw);
    let mut nodes = 0;
    let value = Seed { depth: 0, nodes: &mut nodes }.deserialize(&mut parser)
        .map_err(|_| "native JSON is not strict or bounded")?;
    parser.end().map_err(|_| "native JSON has trailing data")?;
    Ok(value)
}

struct Seed<'a> { depth: usize, nodes: &'a mut usize }
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH || *self.nodes >= MAX_NODES {
            return Err(de::Error::custom("native JSON structural bound"));
        }
        *self.nodes += 1;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded integer-only JSON")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> { Ok(Value::Bool(value)) }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> { Ok(Value::from(value)) }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> { Ok(Value::from(value)) }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Value, E> { Err(E::custom("native JSON float")) }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> { Ok(Value::String(value.to_owned())) }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> { Ok(Value::String(value)) }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(Seed {
            depth: self.depth + 1, nodes: &mut *self.nodes,
        })? { values.push(value); }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if self.depth + 1 > MAX_DEPTH || *self.nodes >= MAX_NODES || values.contains_key(&key) {
                return Err(de::Error::custom("native JSON duplicate key or structural bound"));
            }
            *self.nodes += 1;
            let value = map.next_value_seed(Seed { depth: self.depth + 1, nodes: &mut *self.nodes })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
