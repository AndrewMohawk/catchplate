//! Bounded ELF admission for the new native image profile, not the old static
//! custody launcher's validator. No loading, relocation or execution occurs.

use super::manifest::{path, MAX_EXECUTABLE};
use super::super::OriginalClock;
use std::fs::File;
use std::os::unix::fs::FileExt;

const MAX_PROGRAMS: usize = 128;
const MAX_DYNAMIC_ENTRIES: u64 = 4096;

fn require(condition: bool) -> Result<(), String> {
    if condition { Ok(()) } else { Err("native execution ELF profile mismatch".to_owned()) }
}
fn u16_at(raw: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([raw[offset], raw[offset + 1]])
}
fn u32_at(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(raw[offset..offset + 4].try_into().expect("fixed ELF field"))
}
fn u64_at(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(raw[offset..offset + 8].try_into().expect("fixed ELF field"))
}

pub(super) fn read_exact(file: &File, raw: &mut [u8], offset: u64,
    clock: &OriginalClock) -> Result<(), String>
{
    let mut completed = 0usize;
    while completed < raw.len() {
        clock.check()?;
        let position = offset.checked_add(completed as u64).ok_or("native ELF offset overflow")?;
        let count = file.read_at(&mut raw[completed..], position)
            .map_err(|_| "read held native image original")?;
        clock.check()?;
        require(count > 0)?;
        completed += count;
    }
    Ok(())
}

fn dynamic(file: &File, offset: u64, length: u64, clock: &OriginalClock)
    -> Result<bool, String>
{
    require(length > 0 && length % 16 == 0 && length / 16 <= MAX_DYNAMIC_ENTRIES)?;
    let mut needed = false;
    for index in 0..length / 16 {
        let mut entry = [0u8; 16];
        read_exact(file, &mut entry, offset + index * 16, clock)?;
        match u64_at(&entry, 0) {
            0 => return Ok(needed),
            1 => needed = true,
            _ => {}
        }
    }
    Err("native ELF dynamic table lacks its bounded terminator".to_owned())
}

/// `None` admits a static entry or a self-contained loader: both must lack
/// PT_INTERP and DT_NEEDED. `Some` requires the exact independently pinned
/// in-image interpreter path. DT_NEEDED remains permitted for that entry.
pub(super) fn admit(file: &File, length: u64, interpreter: Option<&str>,
    clock: &OriginalClock) -> Result<(), String>
{
    require((64..=MAX_EXECUTABLE).contains(&length))?;
    let mut header = [0u8; 64];
    read_exact(file, &mut header, 0, clock)?;
    let machine = if cfg!(target_arch = "x86_64") { 62 }
        else if cfg!(target_arch = "aarch64") { 183 }
        else { return Err("native execution architecture is unsupported".to_owned()); };
    require(header[..7] == [0x7f, b'E', b'L', b'F', 2, 1, 1]
        && matches!(u16_at(&header, 16), 2 | 3) && u16_at(&header, 18) == machine
        && u32_at(&header, 20) == 1 && u16_at(&header, 52) == 64
        && u16_at(&header, 54) == 56)?;
    let count = usize::from(u16_at(&header, 56));
    let offset = u64_at(&header, 32);
    let entry = u64_at(&header, 24);
    require(count > 0 && count <= MAX_PROGRAMS && offset >= 64
        && offset.checked_add((count * 56) as u64).is_some_and(|end| end <= length))?;
    clock.check()?;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    clock.check()?;
    require(page > 0 && (page as u64).is_power_of_two())?;
    let mask = page as u64 - 1;
    let mut loads: Vec<(u64, u64, u64, u64, u32)> = Vec::with_capacity(count);
    let mut file_loads: Vec<(u64, u64, u64)> = Vec::with_capacity(count);
    let mut dynamic_range = None;
    let mut has_entry = false;
    let mut has_interpreter = false;
    let mut has_dynamic = false;
    let mut has_needed = false;
    let mut has_stack = false;
    for index in 0..count {
        let mut program = [0u8; 56];
        read_exact(file, &mut program, offset + (index * 56) as u64, clock)?;
        let kind = u32_at(&program, 0);
        let flags = u32_at(&program, 4);
        let file_offset = u64_at(&program, 8);
        let address = u64_at(&program, 16);
        let size = u64_at(&program, 32);
        let memory = u64_at(&program, 40);
        let alignment = u64_at(&program, 48);
        require(size <= memory && file_offset.checked_add(size).is_some_and(|end| end <= length)
            && address.checked_add(memory).is_some()
            && (alignment <= 1 || alignment.is_power_of_two()
                && address % alignment == file_offset % alignment))?;
        match kind {
            1 => {
                require(memory > 0 && flags & !7 == 0 && flags & 3 != 3)?;
                let end = address + memory;
                let rounded_start = address & !mask;
                let rounded_end = end.checked_add(mask).ok_or("native ELF page bound overflow")? & !mask;
                for (prior_start, prior_end, prior_page, prior_page_end, prior_flags) in &loads {
                    require(!(address < *prior_end && *prior_start < end)
                        && !(rounded_start < *prior_page_end && *prior_page < rounded_end
                            && (flags | *prior_flags) & 3 == 3))?;
                }
                loads.push((address, end, rounded_start, rounded_end, flags));
                file_loads.push((address, size, file_offset));
                has_entry |= flags & 1 != 0 && entry >= address && entry < address + size;
            }
            2 => {
                require(!has_dynamic)?;
                has_dynamic = true;
                dynamic_range = Some((address, size, file_offset));
                has_needed = dynamic(file, file_offset, size, clock)?;
            }
            3 => {
                require(!has_interpreter && (2..=4096).contains(&size))?;
                let expected = interpreter.ok_or("static native ELF unexpectedly has PT_INTERP")?;
                let mut original = vec![0u8; size as usize];
                read_exact(file, &mut original, file_offset, clock)?;
                require(original.last() == Some(&0) && !original[..original.len() - 1].contains(&0))?;
                let observed = std::str::from_utf8(&original[..original.len() - 1])
                    .map_err(|_| "native ELF interpreter path is not UTF-8")?;
                path(observed, false)?;
                require(observed == expected)?;
                has_interpreter = true;
            }
            0x6474_e551 => {
                require(!has_stack && flags & 1 == 0)?;
                has_stack = true;
            }
            _ => {}
        }
    }
    if let Some((address, size, file_offset)) = dynamic_range {
        // Join the parsed file bytes to the same mapped dynamic table; a
        // caller cannot hide DT_NEEDED in a different virtual-address view.
        require(file_loads.iter().any(|(load_address, load_size, load_offset)|
            address >= *load_address && address + size <= *load_address + *load_size
                && file_offset == *load_offset + (address - *load_address)))?;
    }
    require(!loads.is_empty() && entry != 0 && has_entry && has_stack
        && has_interpreter == interpreter.is_some()
        && (interpreter.is_some() && has_dynamic || interpreter.is_none() && !has_needed))?;
    clock.check()
}
