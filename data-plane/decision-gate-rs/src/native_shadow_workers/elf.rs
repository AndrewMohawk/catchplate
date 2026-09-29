//! Existing pinned verifier static-ELF algorithm, shared without widening it.

fn static_elf_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let raw: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or("production attestation verifier has a truncated ELF header")?
        .try_into()
        .map_err(|_| "production attestation verifier has an invalid ELF header")?;
    Ok(u16::from_le_bytes(raw))
}

fn static_elf_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let raw: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or("production attestation verifier has a truncated ELF header")?
        .try_into()
        .map_err(|_| "production attestation verifier has an invalid ELF header")?;
    Ok(u32::from_le_bytes(raw))
}

fn static_elf_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let raw: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or("production attestation verifier has a truncated ELF header")?
        .try_into()
        .map_err(|_| "production attestation verifier has an invalid ELF header")?;
    Ok(u64::from_le_bytes(raw))
}

pub fn validate_static_amd64_elf_verifier(bytes: &[u8]) -> Result<(), String> {
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const DT_NULL: u64 = 0;
    const DT_NEEDED: u64 = 1;
    if bytes.len() < 64
        || &bytes[0..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || !matches!(static_elf_u16(bytes, 16)?, 2 | 3)
        || static_elf_u16(bytes, 18)? != 62
        || static_elf_u32(bytes, 20)? != 1
    {
        return Err(
            "production attestation verifier must be a little-endian static x86-64 ELF"
                .to_string(),
        );
    }
    let program_offset = usize::try_from(static_elf_u64(bytes, 32)?)
        .map_err(|_| "production attestation verifier ELF program table is out of range")?;
    let program_entry_bytes = usize::from(static_elf_u16(bytes, 54)?);
    let program_entries = usize::from(static_elf_u16(bytes, 56)?);
    if program_entry_bytes != 56 || !(1..=256).contains(&program_entries) {
        return Err(
            "production attestation verifier has an invalid ELF program table".to_string(),
        );
    }
    let program_bytes = program_entry_bytes
        .checked_mul(program_entries)
        .and_then(|size| program_offset.checked_add(size))
        .ok_or("production attestation verifier ELF program table overflows")?;
    if program_bytes > bytes.len() {
        return Err(
            "production attestation verifier ELF program table is truncated".to_string(),
        );
    }
    let mut load_segment_seen = false;
    for index in 0..program_entries {
        let offset = program_offset + index * program_entry_bytes;
        let program_type = static_elf_u32(bytes, offset)?;
        if program_type == PT_INTERP {
            return Err(
                "production attestation verifier must not use a runtime interpreter"
                    .to_string(),
            );
        }
        if program_type == PT_LOAD {
            load_segment_seen = true;
        }
        if program_type != PT_DYNAMIC {
            continue;
        }
        let dynamic_offset = usize::try_from(static_elf_u64(bytes, offset + 8)?)
            .map_err(|_| "production attestation verifier dynamic segment is out of range")?;
        let dynamic_bytes = usize::try_from(static_elf_u64(bytes, offset + 32)?)
            .map_err(|_| "production attestation verifier dynamic segment is out of range")?;
        let dynamic_end = dynamic_offset
            .checked_add(dynamic_bytes)
            .ok_or("production attestation verifier dynamic segment overflows")?;
        if dynamic_bytes % 16 != 0 || dynamic_end > bytes.len() {
            return Err(
                "production attestation verifier dynamic segment is invalid".to_string(),
            );
        }
        for entry in (dynamic_offset..dynamic_end).step_by(16) {
            let tag = static_elf_u64(bytes, entry)?;
            if tag == DT_NEEDED {
                return Err(
                    "production attestation verifier must not load shared libraries"
                        .to_string(),
                );
            }
            if tag == DT_NULL {
                break;
            }
        }
    }
    if !load_segment_seen {
        return Err(
            "production attestation verifier ELF has no loadable segment".to_string(),
        );
    }
    Ok(())
}
