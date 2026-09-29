//! Structural compatibility with cryptography 50's typed AlgorithmIdentifier.
//!
//! This private helper accepts the untouched parameters suffix of RSA-PSS SPKI.
//! It does not select a hash, execute a KDF, verify signatures or enforce PSS
//! signing semantics. Known algorithm parameters keep their actual typed DER
//! grammar; unknown parameters and explicitly opaque sequences remain opaque.
//! Reference: pyca/cryptography 50.0.0 cryptography-x509/src/{common,oid}.rs,
//! and alex/rust-asn1 0.24.1's DER primitives/default-value rules.

const MAX_BYTES: usize = 64 * 1024;
const SHA1_NULL: &[u8] = b"\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00";
const MGF1_SHA1_NULL: &[u8] = b"\x30\x16\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00";
const HMAC_SHA1_NULL: &[u8] = b"\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x07\x05\x00";

fn invalid() -> String { "native bootstrap algorithm parameters violate their typed DER profile".to_owned() }
fn require(value: bool) -> Result<(), String> { if value { Ok(()) } else { Err(invalid()) } }

struct Guard { pid: u32, deadline: u64, last: u64, steps: usize }
impl Guard {
    fn tick(&mut self) -> Result<(), String> {
        require(self.steps > 0 && self.pid == std::process::id())?;
        self.steps -= 1;
        let mut sample: libc::timespec = unsafe { std::mem::zeroed() };
        require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } == 0
            && sample.tv_sec >= 0 && (0..1_000_000_000).contains(&sample.tv_nsec))?;
        let now = (sample.tv_sec as u64).checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(sample.tv_nsec as u64)).ok_or_else(invalid)?;
        require(now >= self.last && now < self.deadline)?;
        self.last = now;
        Ok(())
    }
}

struct Part<'a> { tag: u8, body: &'a [u8], original: &'a [u8] }
struct Reader<'a> { original: &'a [u8], position: usize }
impl<'a> Reader<'a> {
    fn new(original: &'a [u8]) -> Self { Self { original, position: 0 } }
    fn rest(&self) -> &'a [u8] { &self.original[self.position..] }
    fn peek(&self) -> Option<u8> { self.original.get(self.position).copied() }
    fn end(&self) -> Result<(), String> { require(self.position == self.original.len()) }
    fn byte(&mut self) -> Result<u8, String> {
        let value = *self.original.get(self.position).ok_or_else(invalid)?;
        self.position += 1;
        Ok(value)
    }
    fn part(&mut self, guard: &mut Guard) -> Result<Part<'a>, String> {
        guard.tick()?;
        let start = self.position;
        let tag = self.byte()?;
        if tag & 0x1f == 0x1f {
            let number = base128(self, guard)?;
            require((31..=u32::MAX as u128).contains(&number))?;
        }
        let first = self.byte()?;
        let length = if first < 128 { usize::from(first) } else {
            let count = usize::from(first & 0x7f);
            require((1..=4).contains(&count) && self.peek() != Some(0))?;
            let mut length = 0usize;
            for _ in 0..count {
                length = length.checked_mul(256).ok_or_else(invalid)?
                    .checked_add(usize::from(self.byte()?)).ok_or_else(invalid)?;
            }
            require(length >= 128)?;
            length
        };
        let end = self.position.checked_add(length).ok_or_else(invalid)?;
        let body = self.original.get(self.position..end).ok_or_else(invalid)?;
        self.position = end;
        Ok(Part { tag, body, original: &self.original[start..end] })
    }
    fn take(&mut self, tag: u8, guard: &mut Guard) -> Result<Part<'a>, String> {
        let part = self.part(guard)?;
        require(part.tag == tag)?;
        Ok(part)
    }
    fn sequence(original: &'a [u8], guard: &mut Guard) -> Result<Self, String> {
        let mut outer = Self::new(original);
        let part = outer.take(0x30, guard)?;
        outer.end()?;
        Ok(Self::new(part.body))
    }
}

fn base128(reader: &mut Reader<'_>, guard: &mut Guard) -> Result<u128, String> {
    require(reader.peek() != Some(0x80))?;
    let mut value = 0u128;
    for _ in 0..19 {
        guard.tick()?;
        let byte = reader.byte()?;
        value = value.checked_mul(128).ok_or_else(invalid)?
            .checked_add(u128::from(byte & 0x7f)).ok_or_else(invalid)?;
        if byte & 0x80 == 0 { return Ok(value); }
    }
    Err(invalid())
}

fn oid(original: &[u8], guard: &mut Guard) -> Result<(), String> {
    require(!original.is_empty() && original.len() <= 63)?;
    let mut reader = Reader::new(original);
    while reader.peek().is_some() { base128(&mut reader, guard)?; }
    reader.end()
}

fn unsigned(original: &[u8]) -> Result<&[u8], String> {
    require(!original.is_empty() && original[0] & 0x80 == 0)?;
    if original.len() > 1 && original[0] == 0 {
        require(original[1] & 0x80 != 0)?;
        Ok(&original[1..])
    } else { Ok(original) }
}
fn number(reader: &mut Reader<'_>, maximum: u64, guard: &mut Guard) -> Result<u64, String> {
    let bytes = unsigned(reader.take(0x02, guard)?.body)?;
    require(bytes.len() <= 8)?;
    let mut value = 0u64;
    for byte in bytes {
        value = value.checked_mul(256).ok_or_else(invalid)?
            .checked_add(u64::from(*byte)).ok_or_else(invalid)?;
    }
    require(value <= maximum)?;
    Ok(value)
}
fn big_uint(reader: &mut Reader<'_>, guard: &mut Guard) -> Result<(), String> {
    unsigned(reader.take(0x02, guard)?.body)?;
    Ok(())
}
fn octets(reader: &mut Reader<'_>, size: Option<usize>, guard: &mut Guard) -> Result<(), String> {
    let body = reader.take(0x04, guard)?.body;
    require(size.is_none_or(|size| body.len() == size))
}
fn bit_string(original: &[u8]) -> Result<(), String> {
    let (&padding, content) = original.split_first().ok_or_else(invalid)?;
    require(padding <= 7)?;
    if let Some(last) = content.last() { require(*last & ((1u8 << padding) - 1) == 0) }
    else { require(padding == 0) }
}

enum Kind { Null, Absent, Ec, Dsa, Dhx, Dh, Pss, Pbes2, Pbkdf2, Scrypt, Iv16, Iv8, Rc2, Pbe8, Pbe, Other }
fn kind(value: &[u8]) -> Kind {
    match value {
        // SHA1, SHA2 and both legacy/NIST SHA3 encodings.
        [0x2b,0x0e,0x03,0x02,0x1a]
        | [0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,1..=4 | 7..=10]
        | [0x2b,0x06,0x01,0x04,0x01,0x82,0xa4,0x64,0x03,0x02,0x01,0x63,0x07,0x81,0x60]
        | [0x2b,0x06,0x01,0x04,0x01,0x82,0xa4,0x64,0x03,0x02,0x01,0x63,0x07,0x82..=0x84,0x00]
        // RSA, the enumerated RSA signature algorithms, HMAC-SHA1/SHA2.
        | [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,1 | 5 | 11..=14]
        | [0x2b,0x0e,0x03,0x02,0x1d]
        | [0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,13..=16]
        | [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,7..=11] => Kind::Null,
        // Ed/X, ML-DSA/ML-KEM, unsigned, ECDSA and DSA signatures.
        [0x2b,0x65,110..=113]
        | [0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,1..=4 | 9..=12 | 17..=19]
        | [0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x04,2 | 3]
        | [0x2b,0x06,0x01,0x05,0x05,0x07,0x06,0x24]
        | [0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,1..=4] => Kind::Absent,
        [0x2a,0x86,0x48,0xce,0x3d,0x02,0x01] => Kind::Ec,
        [0x2a,0x86,0x48,0xce,0x38,0x04,0x01] => Kind::Dsa,
        [0x2a,0x86,0x48,0xce,0x3e,0x02,0x01] => Kind::Dhx,
        [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x03,0x01] => Kind::Dh,
        [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0a] => Kind::Pss,
        [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0d] => Kind::Pbes2,
        [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0c] => Kind::Pbkdf2,
        [0x2b,0x06,0x01,0x04,0x01,0xda,0x47,0x04,0x0b] => Kind::Scrypt,
        [0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,2 | 22 | 42] => Kind::Iv16,
        [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x03,0x07] => Kind::Iv8,
        [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x03,0x02] => Kind::Rc2,
        [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x03] => Kind::Pbe8,
        [0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x0c,0x01,1 | 3 | 6] => Kind::Pbe,
        _ => Kind::Other,
    }
}

fn ec_parameters(original: &[u8], guard: &mut Guard) -> Result<(), String> {
    let mut reader = Reader::new(original);
    let part = reader.part(guard)?;
    reader.end()?;
    match part.tag {
        0x06 => oid(part.body, guard),
        0x05 => require(part.body.is_empty()),
        0x30 => {
            let mut domain = Reader::new(part.body);
            number(&mut domain, u8::MAX as u64, guard)?;
            let mut field = Reader::new(domain.take(0x30, guard)?.body);
            let field_oid = field.take(0x06, guard)?.body;
            oid(field_oid, guard)?;
            match field_oid {
                [0x2a,0x86,0x48,0xce,0x3d,0x01,0x01] => big_uint(&mut field, guard)?,
                [0x2a,0x86,0x48,0xce,0x3d,0x01,0x02] => { field.take(0x30, guard)?; },
                _ => return Err(invalid()),
            }
            field.end()?;
            let mut curve = Reader::new(domain.take(0x30, guard)?.body);
            octets(&mut curve, None, guard)?;
            octets(&mut curve, None, guard)?;
            if curve.peek().is_some() { bit_string(curve.take(0x03, guard)?.body)?; }
            curve.end()?;
            octets(&mut domain, None, guard)?;
            big_uint(&mut domain, guard)?;
            if domain.peek().is_some() { number(&mut domain, u8::MAX as u64, guard)?; }
            domain.end()
        }
        _ => Err(invalid()),
    }
}

enum Task<'a> { Pss(&'a [u8]), Algorithm(&'a [u8]), Mask(&'a [u8]) }

fn algorithm<'a>(original: &'a [u8], tasks: &mut Vec<Task<'a>>, guard: &mut Guard) -> Result<(), String> {
    let mut identifier = Reader::sequence(original, guard)?;
    let algorithm_oid = identifier.take(0x06, guard)?.body;
    oid(algorithm_oid, guard)?;
    let params = identifier.rest();
    match kind(algorithm_oid) {
        Kind::Absent => require(params.is_empty()),
        Kind::Null => {
            let mut value = Reader::new(params);
            if value.peek().is_some() { require(value.take(0x05, guard)?.body.is_empty())?; }
            value.end()
        }
        Kind::Other => {
            let mut value = Reader::new(params);
            if value.peek().is_some() { value.part(guard)?; }
            value.end()
        }
        Kind::Pss => { tasks.push(Task::Pss(params)); Ok(()) }
        Kind::Ec => ec_parameters(params, guard),
        Kind::Iv16 | Kind::Iv8 => {
            let size = if matches!(kind(algorithm_oid), Kind::Iv16) { 16 } else { 8 };
            let mut value = Reader::new(params);
            octets(&mut value, Some(size), guard)?;
            value.end()
        }
        profile => {
            let mut value = Reader::sequence(params, guard)?;
            match profile {
                Kind::Dsa => { for _ in 0..3 { big_uint(&mut value, guard)?; } }
                Kind::Dhx => {
                    for _ in 0..3 { big_uint(&mut value, guard)?; }
                    if value.peek() == Some(0x02) { big_uint(&mut value, guard)?; }
                    if value.peek().is_some() { value.take(0x30, guard)?; }
                }
                Kind::Dh => {
                    big_uint(&mut value, guard)?;
                    big_uint(&mut value, guard)?;
                    if value.peek().is_some() { number(&mut value, u32::MAX as u64, guard)?; }
                }
                Kind::Pbes2 => {
                    tasks.push(Task::Algorithm(value.take(0x30, guard)?.original));
                    tasks.push(Task::Algorithm(value.take(0x30, guard)?.original));
                }
                Kind::Pbkdf2 => {
                    octets(&mut value, None, guard)?;
                    number(&mut value, u64::MAX, guard)?;
                    if value.peek() == Some(0x02) { number(&mut value, u64::MAX, guard)?; }
                    if value.peek().is_some() {
                        let prf = value.take(0x30, guard)?.original;
                        require(prf != HMAC_SHA1_NULL)?;
                        tasks.push(Task::Algorithm(prf));
                    }
                }
                Kind::Scrypt => {
                    octets(&mut value, None, guard)?;
                    for _ in 0..3 { number(&mut value, u64::MAX, guard)?; }
                    if value.peek().is_some() { number(&mut value, u32::MAX as u64, guard)?; }
                }
                Kind::Rc2 => {
                    if value.peek() == Some(0x02) { number(&mut value, u32::MAX as u64, guard)?; }
                    octets(&mut value, Some(8), guard)?;
                }
                Kind::Pbe8 => { octets(&mut value, Some(8), guard)?; number(&mut value, u64::MAX, guard)?; }
                Kind::Pbe => { octets(&mut value, None, guard)?; number(&mut value, u64::MAX, guard)?; }
                _ => return Err(invalid()),
            }
            value.end()
        }
    }
}

/// Exact optional PSS parameters; the caller already selected rsaPss SPKI.
pub(crate) fn verify_pss_parameters(original: &[u8], deadline: u64) -> Result<(), String> {
    require(original.len() <= MAX_BYTES)?;
    // Every scheduled child lies strictly inside its parent's original. Each
    // header consumes at least two bytes; four steps per input byte plus fixed
    // entry/exit overhead covers header rereads and OID octets. This is an input
    // bound, not a smaller PSS nesting/profile limit or a new time allowance.
    let mut guard = Guard { pid: std::process::id(), deadline, last: 0,
        steps: original.len().checked_mul(4).and_then(|size| size.checked_add(8)).ok_or_else(invalid)? };
    guard.tick()?;
    let mut tasks = vec![Task::Pss(original)];
    while let Some(task) = tasks.pop() {
        guard.tick()?;
        match task {
            Task::Algorithm(original) => algorithm(original, &mut tasks, &mut guard)?,
            Task::Mask(original) => {
                let mut mask = Reader::sequence(original, &mut guard)?;
                oid(mask.take(0x06, &mut guard)?.body, &mut guard)?;
                tasks.push(Task::Algorithm(mask.take(0x30, &mut guard)?.original));
                mask.end()?;
            }
            Task::Pss(original) => {
                if original.is_empty() { continue; }
                let mut pss = Reader::sequence(original, &mut guard)?;
                for tag in 0xa0..=0xa3 {
                    if pss.peek() != Some(tag) { continue; }
                    let explicit = pss.take(tag, &mut guard)?.body;
                    match tag {
                        0xa0 => { require(explicit != SHA1_NULL)?; tasks.push(Task::Algorithm(explicit)); }
                        0xa1 => { require(explicit != MGF1_SHA1_NULL)?; tasks.push(Task::Mask(explicit)); }
                        0xa2 | 0xa3 => {
                            let mut value = Reader::new(explicit);
                            let maximum = if tag == 0xa2 { u16::MAX as u64 } else { u8::MAX as u64 };
                            let parsed = number(&mut value, maximum, &mut guard)?;
                            require(tag != 0xa2 || parsed != 20)?;
                            value.end()?;
                        }
                        _ => return Err(invalid()),
                    }
                }
                pss.end()?;
            }
        }
        require(tasks.len() <= original.len() + 1)?;
    }
    guard.tick()
}
