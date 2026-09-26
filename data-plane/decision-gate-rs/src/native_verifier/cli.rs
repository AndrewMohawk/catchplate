//! Fixed original-file/stdin interface for the standalone native verifier.
//!
//! Digests authenticate bytes against caller-supplied pins, not the provenance
//! or currentness of those pins. No shell, environment configuration, file write
//! or network request is involved. Blocking I/O still needs the invoking owner's
//! external deadline/watchdog; no successful output precedes final rechecks.

use sha2::{Digest, Sha256};
use std::env;
use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const MAX_EXPECTATIONS: usize = 16 * 1024;
const MAX_TRUST_ROOTS: usize = 1024 * 1024;
const MAX_INPUT: usize = 512 * 1024;
const MAX_RESULT: usize = 4095;
const MAX_PATH: usize = 4096;

type Fingerprint = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);

fn fingerprint(metadata: &Metadata) -> Fingerprint {
    (metadata.dev(), metadata.ino(), metadata.mode(), metadata.uid(), metadata.gid(),
     metadata.nlink(), metadata.len(), metadata.mtime(), metadata.mtime_nsec(),
     metadata.ctime(), metadata.ctime_nsec())
}

fn pin(value: OsString) -> Result<[u8; 32], String> {
    let value = value.to_str().ok_or("native verifier pin is not UTF-8")?;
    let digest = value.strip_prefix("sha256:")
        .ok_or("native verifier pin requires sha256 prefix")?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("native verifier pin is not canonical SHA-256".to_owned());
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(digest, &mut bytes)
        .map_err(|_| "native verifier pin is invalid")?;
    Ok(bytes)
}

fn path(value: OsString) -> Result<PathBuf, String> {
    let bytes = value.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PATH || bytes.contains(&0) {
        return Err("native verifier input path exceeds its bound".to_owned());
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() || path.file_name().is_none()
        || path.components().any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err("native verifier input path must be absolute without traversal".to_owned());
    }
    Ok(path)
}

struct Arguments {
    expectations: PathBuf,
    expectations_pin: [u8; 32],
    trust_roots: PathBuf,
    trust_roots_pin: [u8; 32],
}

fn arguments() -> Result<Arguments, String> {
    let mut expectations = None;
    let mut expectations_pin = None;
    let mut trust_roots = None;
    let mut trust_roots_pin = None;
    let mut arguments = env::args_os().skip(1);
    while let Some(flag) = arguments.next() {
        let flag = flag.to_str().ok_or("native verifier flag is not UTF-8")?;
        let value = arguments.next().ok_or("native verifier flag requires a value")?;
        match flag {
            "--expectations" if expectations.is_none() => expectations = Some(path(value)?),
            "--expectations-sha256" if expectations_pin.is_none() => expectations_pin = Some(pin(value)?),
            "--trust-roots" if trust_roots.is_none() => trust_roots = Some(path(value)?),
            "--trust-roots-sha256" if trust_roots_pin.is_none() => trust_roots_pin = Some(pin(value)?),
            _ => return Err("native verifier received an unknown or repeated flag".to_owned()),
        }
    }
    Ok(Arguments {
        expectations: expectations.ok_or("native verifier requires expectations")?,
        expectations_pin: expectations_pin.ok_or("native verifier requires expectations pin")?,
        trust_roots: trust_roots.ok_or("native verifier requires trust roots")?,
        trust_roots_pin: trust_roots_pin.ok_or("native verifier requires trust roots pin")?,
    })
}

fn open(path: &Path, limit: usize) -> Result<(File, Fingerprint), String> {
    let file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path).map_err(|_| "open native verifier original without following final symlink")?;
    let metadata = file.metadata().map_err(|_| "inspect native verifier original")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit as u64 {
        return Err("native verifier original must be a bounded nonempty regular file".to_owned());
    }
    Ok((file, fingerprint(&metadata)))
}

fn read_original(file: &mut File, expected: Fingerprint, pin: &[u8; 32], limit: usize)
    -> Result<Vec<u8>, String>
{
    if fingerprint(&file.metadata().map_err(|_| "inspect held native verifier original")?) != expected {
        return Err("native verifier original identity changed".to_owned());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| "seek native verifier original")?;
    let mut bytes = Vec::with_capacity(expected.6 as usize);
    Read::by_ref(file).take(limit as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| "read bounded native verifier original")?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if bytes.len() as u64 != expected.6 || bytes.len() > limit || digest != *pin
        || fingerprint(&file.metadata().map_err(|_| "reinspect native verifier original")?) != expected
    {
        return Err("native verifier original bytes or metadata differ from the pin".to_owned());
    }
    Ok(bytes)
}

struct HeldOriginal {
    path: PathBuf,
    file: File,
    fingerprint: Fingerprint,
    pin: [u8; 32],
    limit: usize,
}

impl HeldOriginal {
    fn read(path: PathBuf, pin: [u8; 32], limit: usize) -> Result<(Self, Vec<u8>), String> {
        let (mut file, fingerprint) = open(&path, limit)?;
        let original = read_original(&mut file, fingerprint, &pin, limit)?;
        let held = Self { path, file, fingerprint, pin, limit };
        held.recheck_name()?;
        Ok((held, original))
    }

    fn recheck_name(&self) -> Result<(), String> {
        let (_named, named) = open(&self.path, self.limit)?;
        if named != self.fingerprint
            || fingerprint(&self.file.metadata().map_err(|_| "inspect retained native verifier original")?) != self.fingerprint
        {
            return Err("native verifier original path or retained identity changed".to_owned());
        }
        Ok(())
    }

    fn recheck(&mut self) -> Result<(), String> {
        read_original(&mut self.file, self.fingerprint, &self.pin, self.limit)?;
        self.recheck_name()
    }
}

pub(super) fn run() -> Result<(), String> {
    run_with_input_limit(MAX_INPUT, super::verify)
}

pub(super) fn run_with_input_limit(
    limit: usize,
    verifier: fn(&[u8], &[u8], &[u8]) -> Result<Vec<u8>, String>,
) -> Result<(), String> {
    if limit == 0 || limit > MAX_INPUT {
        return Err("native verifier input limit exceeds its source bound".to_owned());
    }
    let arguments = arguments()?;
    let (mut expectations, expectations_raw) = HeldOriginal::read(
        arguments.expectations, arguments.expectations_pin, MAX_EXPECTATIONS)?;
    let (mut trust_roots, trust_roots_raw) = HeldOriginal::read(
        arguments.trust_roots, arguments.trust_roots_pin, MAX_TRUST_ROOTS)?;
    let mut raw = Vec::new();
    std::io::stdin().lock().take(limit as u64 + 1).read_to_end(&mut raw)
        .map_err(|_| "read bounded native proof original")?;
    if raw.is_empty() || raw.len() > limit {
        return Err("native proof original exceeds its input bound".to_owned());
    }
    let mut result = verifier(&raw, &expectations_raw, &trust_roots_raw)?;
    if result.is_empty() || result.len() > MAX_RESULT || result.contains(&b'\n') || result.contains(&b'\r') {
        return Err("native verifier result exceeds its canonical output bound".to_owned());
    }
    expectations.recheck()?;
    trust_roots.recheck()?;
    result.push(b'\n');
    let mut output = std::io::stdout().lock();
    output.write_all(&result).map_err(|_| "publish native verifier result")?;
    output.flush().map_err(|_| "flush native verifier result")
}
