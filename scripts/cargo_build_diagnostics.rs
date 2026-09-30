//! Build-only Cargo output owner: bound warning display, never compiler checks.
//! Compiled directly with the pinned rustc; no Cargo dependencies or lint flags.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

const WARNING_EXAMPLES: u64 = 8;
const WARNING_CHARACTERS: usize = 200;

// Read only a top-level field from a complete JSON object. Nested diagnostic
// levels must never classify their parent. Any decoding failure falls back to
// the original line, including future Cargo records and non-JSON tool output.
struct Json<'a> {
    source: &'a str,
    at: usize,
}

impl<'a> Json<'a> {
    fn peek(&self) -> Option<u8> { self.source.as_bytes().get(self.at).copied() }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) { self.at += 1; }
    }

    fn take(&mut self, byte: u8) -> Option<()> {
        if self.peek()? != byte { return None; }
        self.at += 1;
        Some(())
    }

    fn hex(&mut self) -> Option<u32> {
        let digits = self.source.get(self.at..self.at + 4)?;
        if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) { return None; }
        let value = u32::from_str_radix(digits, 16).ok()?;
        self.at += 4;
        Some(value)
    }

    fn string(&mut self) -> Option<String> {
        self.take(b'"')?;
        let mut text = String::new();
        loop {
            match self.peek()? {
                b'"' => { self.at += 1; return Some(text); }
                b'\\' => {
                    self.at += 1;
                    let escape = self.peek()?;
                    self.at += 1;
                    text.push(match escape {
                        b'"' => '"', b'\\' => '\\', b'/' => '/',
                        b'b' => '\u{8}', b'f' => '\u{c}', b'n' => '\n',
                        b'r' => '\r', b't' => '\t',
                        b'u' => {
                            let mut point = self.hex()?;
                            if (0xd800..=0xdbff).contains(&point) {
                                self.take(b'\\')?;
                                self.take(b'u')?;
                                let low = self.hex()?;
                                if !(0xdc00..=0xdfff).contains(&low) { return None; }
                                point = 0x10000 + ((point - 0xd800) << 10) + low - 0xdc00;
                            }
                            char::from_u32(point)?
                        }
                        _ => return None,
                    });
                }
                0..=0x1f => return None,
                _ => {
                    let character = self.source.get(self.at..)?.chars().next()?;
                    self.at += character.len_utf8();
                    text.push(character);
                }
            }
        }
    }

    fn digits(&mut self) -> Option<()> {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) { self.at += 1; }
        (self.at > start).then_some(())
    }

    fn value(&mut self, depth: usize) -> Option<()> {
        if depth > 64 { return None; }
        self.space();
        match self.peek()? {
            b'"' => { self.string()?; }
            b'{' | b'[' => {
                let object = self.peek()? == b'{';
                let close = if object { b'}' } else { b']' };
                self.at += 1;
                self.space();
                if self.peek()? == close { self.at += 1; return Some(()); }
                loop {
                    self.space();
                    if object { self.string()?; self.space(); self.take(b':')?; }
                    self.value(depth + 1)?;
                    self.space();
                    if self.peek()? == close { self.at += 1; break; }
                    self.take(b',')?;
                }
            }
            b't' | b'f' | b'n' => {
                let literal = match self.peek()? { b't' => "true", b'f' => "false", _ => "null" };
                if !self.source.get(self.at..)?.starts_with(literal) { return None; }
                self.at += literal.len();
            }
            _ => {
                if self.peek()? == b'-' { self.at += 1; }
                match self.peek()? {
                    b'0' => self.at += 1,
                    b'1'..=b'9' => self.digits()?,
                    _ => return None,
                }
                if self.peek() == Some(b'.') { self.at += 1; self.digits()?; }
                if matches!(self.peek(), Some(b'e' | b'E')) {
                    self.at += 1;
                    if matches!(self.peek(), Some(b'+' | b'-')) { self.at += 1; }
                    self.digits()?;
                }
            }
        }
        Some(())
    }
}

fn field<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let mut json = Json { source, at: 0 };
    json.space();
    json.take(b'{')?;
    json.space();
    let mut found = None;
    if json.peek()? != b'}' {
        loop {
            json.space();
            let key = json.string()?;
            json.space();
            json.take(b':')?;
            json.space();
            let start = json.at;
            json.value(0)?;
            if key == name {
                if found.is_some() { return None; }
                found = Some(&source[start..json.at]);
            }
            json.space();
            if json.peek()? == b'}' { break; }
            json.take(b',')?;
        }
    }
    json.take(b'}')?;
    json.space();
    if json.at != source.len() { return None; }
    found
}

fn string(source: &str) -> Option<String> {
    let mut json = Json { source, at: 0 };
    let value = json.string()?;
    (json.at == source.len()).then_some(value)
}

enum Record { Warning(String), Rendered(String), Metadata }

fn record(line: &[u8]) -> Option<Record> {
    let source = std::str::from_utf8(line).ok()?;
    match string(field(source, "reason")?)?.as_str() {
        "compiler-message" => {
            let message = field(source, "message")?;
            let level = string(field(message, "level")?)?;
            let rendered = string(field(message, "rendered")?)?;
            if rendered.is_empty() { return None; }
            if level == "warning" {
                Some(Record::Warning(string(field(message, "message")?)?))
            } else { Some(Record::Rendered(rendered)) }
        }
        "compiler-artifact" | "build-script-executed" | "build-finished" => Some(Record::Metadata),
        _ => None,
    }
}

fn run() -> io::Result<i32> {
    let mut child = Command::new("cargo").args(["build", "--keep-going", "--message-format=json"])
        .args(std::env::args_os().skip(1)).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
    let output = child.stdout.take().ok_or_else(|| io::Error::other("Cargo stdout unavailable"))?;
    let mut reader = BufReader::new(output);
    let stderr = io::stderr();
    let mut log = stderr.lock();
    let mut warnings = 0u64;
    let streamed = (|| -> io::Result<()> {
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 { break; }
            match record(&line) {
                Some(Record::Warning(message)) => {
                    warnings = warnings.saturating_add(1);
                    if warnings <= WARNING_EXAMPLES {
                        let summary: String = message.chars().take(WARNING_CHARACTERS)
                            .map(|c| if c.is_control() { ' ' } else { c }).collect();
                        writeln!(log, "[cargo warning {warnings}; summary only] {summary}")?;
                    }
                }
                Some(Record::Rendered(text)) => {
                    log.write_all(text.as_bytes())?;
                    if !text.ends_with('\n') { writeln!(log)?; }
                }
                Some(Record::Metadata) => {}
                None => log.write_all(&line)?,
            }
            log.flush()?;
        }
        Ok(())
    })();
    if let Err(error) = streamed {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let status = child.wait()?;
    writeln!(log, "[cargo diagnostics] {warnings} compiler warnings; at most {WARNING_EXAMPLES} \
        summaries of {WARNING_CHARACTERS} characters shown; full non-warning diagnostics streamed.")?;
    log.flush()?;
    Ok(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => { eprintln!("Cargo diagnostic runner failed: {error}"); std::process::exit(1); }
    }
}
