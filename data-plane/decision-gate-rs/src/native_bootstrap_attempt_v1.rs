//! A distinct bootstrap purpose within the actual locked custody ledger.
//!
//! Only the genuine library bootstrap path calls begin. Digests are association
//! inputs, not authorization. A durable claim without completed originals is
//! burned: neither retry nor restart creates another signing permission. The
//! existing manifest's fail-closed interrupted-update and filesystem rollback
//! limitations remain; this is not an independent rollback witness.

use super::*;
use crate::enclave_runtime_identity_v1::GeneratedBootstrapEnrollmentV1;
use std::sync::MutexGuard;

pub(super) const API_VERSION: &str = "catchplate.custodyNativeBootstrapAttempt/v1";
pub(super) const MAX_RECORD_BYTES: usize = 24 * 1024;
pub(super) const MAX_ATTEMPTS: usize = 64;
const MAX_QUOTE_BYTES: usize = 12 * 1024;
const ATTEMPT_DOMAIN: &[u8] = b"catchplate/native-enrollment-bootstrap-attempt/v1\0";
const MAX_PROCESSING_NS: u64 = 30_000_000_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredOutcome {
    signature_base64url: String,
    public_key_base64url: String,
    quote_base64url: String,
}

// deserialize_with runs only for a present field. Decoding the object directly
// deliberately rejects explicit null rather than treating it as absence.
pub(super) fn deserialize_outcome<'de, D: serde::Deserializer<'de>>(decoder: D)
    -> Result<Option<StoredOutcome>, D::Error> {
    StoredOutcome::deserialize(decoder).map(Some)
}

/// Read-back public originals only. No constructor, signing capability or
/// conversion to the source-only generated-output type is exposed.
pub(crate) struct RetainedNativeBootstrapOriginals {
    signature: [u8; 64],
    public_key: [u8; 32],
    quote: Vec<u8>,
}

impl RetainedNativeBootstrapOriginals {
    pub(crate) fn signature(&self) -> &[u8; 64] { &self.signature }
    pub(crate) fn public_key(&self) -> &[u8; 32] { &self.public_key }
    pub(crate) fn quote_document(&self) -> &[u8] { &self.quote }
}

pub(crate) enum BootstrapAttempt<'a> {
    New(NativeBootstrapClaim<'a>),
    Complete(RetainedNativeBootstrapOriginals),
}

/// Held across the one key generation/sign/NSM/publication operation. No Clone,
/// public constructor, serialization or borrowed-key escape exists.
pub(crate) struct NativeBootstrapClaim<'a> {
    runtime: &'a CustodyRuntime,
    ledger: MutexGuard<'a, AttemptStatementLedger>,
    binding: AttemptBindingPayload,
    owner_pid: libc::pid_t,
    deadline: u64,
    last_boot_ns: u64,
    last_epoch_ms: u64,
    failed: bool,
}

fn error(message: &'static str) -> ProtocolError {
    attempt_ledger_error("native_bootstrap_attempt_refused", message)
}

fn boot_ns() -> Result<u64, ProtocolError> {
    let mut sample = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut sample) } != 0
        || sample.tv_sec < 0 || !(0..1_000_000_000).contains(&sample.tv_nsec) {
        return Err(error("native bootstrap monotonic clock is unavailable"));
    }
    (sample.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(sample.tv_nsec as u64))
        .ok_or_else(|| error("native bootstrap monotonic clock overflow"))
}

fn decode_original(value: &str, exact: Option<usize>, maximum: usize)
    -> Result<Vec<u8>, ProtocolError> {
    if value.is_empty() || value.len() > maximum.saturating_mul(4).div_ceil(3) {
        return Err(error("native bootstrap retained original exceeds its bound"));
    }
    let bytes = general_purpose::URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| error("native bootstrap retained original encoding is invalid"))?;
    if bytes.is_empty() || bytes.len() > maximum || exact.is_some_and(|size| bytes.len() != size)
        || general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(error("native bootstrap retained original is noncanonical"));
    }
    Ok(bytes)
}

impl StoredOutcome {
    fn originals(&self) -> Result<RetainedNativeBootstrapOriginals, ProtocolError> {
        let signature = decode_original(&self.signature_base64url, Some(64), 64)?
            .try_into().map_err(|_| error("native bootstrap signature length changed"))?;
        let public_key: [u8; 32] = decode_original(&self.public_key_base64url, Some(32), 32)?
            .try_into().map_err(|_| error("native bootstrap public-key length changed"))?;
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| error("native bootstrap retained public key is invalid"))?;
        if public_key == [0; 32] || key.is_weak() {
            return Err(error("native bootstrap retained public key is weak"));
        }
        Ok(RetainedNativeBootstrapOriginals {
            signature, public_key,
            quote: decode_original(&self.quote_base64url, None, MAX_QUOTE_BYTES)?,
        })
    }
}

pub(super) fn validate_record(payload: &AttemptBindingPayload, size: usize)
    -> Result<(), ProtocolError> {
    if payload.api_version != API_VERSION || size > MAX_RECORD_BYTES {
        return Err(error("native bootstrap ledger record is invalid"));
    }
    if let Some(outcome) = &payload.bootstrap_outcome { outcome.originals()?; }
    Ok(())
}

fn publish(ledger: &mut AttemptStatementLedger, payload: &AttemptBindingPayload,
    old: Option<&AttemptBindingPayload>, now: u64) -> Result<(), ProtocolError> {
    ledger.ensure_available()?;
    let directory = ledger.directory.as_ref()
        .ok_or_else(|| error("native bootstrap requires the actual durable ledger"))?;
    let checksum = checksum_payload(payload)?;
    let record = AttemptBindingRecord { payload: payload.clone(), checksum: checksum.clone() };
    let encoded = canonical_json_bytes(&record)?;
    validate_attempt_binding_record(&record, "native bootstrap publication")?;
    if encoded.len() > MAX_RECORD_BYTES { return Err(error("native bootstrap outcome exceeds its reservation")); }
    let mut manifest = ledger.manifest.clone();
    manifest.commit_sequence = manifest.commit_sequence.checked_add(1)
        .ok_or_else(|| error("native bootstrap ledger sequence is exhausted"))?;
    manifest.max_observed_epoch_ms = now;
    let mut accumulator = decode_accumulator(&manifest.active_bindings_accumulator)?;
    if let Some(previous) = old {
        xor_accumulator(&mut accumulator, checksum_bytes(&checksum_payload(previous)?)?);
    } else {
        manifest.active_binding_count = manifest.active_binding_count.checked_add(1)
            .ok_or_else(|| error("native bootstrap ledger count overflow"))?;
    }
    xor_accumulator(&mut accumulator, checksum_bytes(&checksum)?);
    manifest.active_bindings_accumulator = general_purpose::URL_SAFE_NO_PAD.encode(accumulator);
    let path = directory.join(attempt_binding_filename(&payload.attempt_id)?);
    // The only replacement is the original small claim, never a completed
    // outcome. Existing atomic file/fsync and manifest commit rules are shared.
    let result = write_atomic_ledger_file(&path, &encoded, old.is_some())
        .and_then(|()| persist_attempt_ledger_manifest(directory, &manifest));
    if let Err(failure) = result {
        ledger.poisoned = true;
        return Err(failure);
    }
    ledger.manifest = manifest;
    ledger.expiry_index.insert((payload.retain_until_epoch_ms, payload.attempt_id.clone()));
    ledger.bindings.insert(payload.attempt_id.clone(), payload.clone());
    Ok(())
}

impl NativeBootstrapClaim<'_> {
    pub(crate) fn check(&mut self, deadline: u64) -> Result<(), ProtocolError> {
        if self.failed { return Err(error("native bootstrap attempt guard is already closed")); }
        self.deadline = self.deadline.min(deadline);
        let result = (|| {
            if unsafe { libc::getpid() } != self.owner_pid {
                return Err(error("native bootstrap attempt crossed its creating process"));
            }
            let boot = boot_ns()?;
            let epoch = current_epoch_ms()?;
            if boot < self.last_boot_ns || boot >= self.deadline || epoch < self.last_epoch_ms
                || epoch >= self.binding.retain_until_epoch_ms {
                return Err(error("native bootstrap original lifetime expired or moved backwards"));
            }
            self.ledger.ensure_available()?;
            self.runtime.verify_native_live()?; // Never narrows the shared key's lifetime.
            if self.ledger.bindings.get(&self.binding.attempt_id) != Some(&self.binding) {
                return Err(error("native bootstrap retained claim association changed"));
            }
            // The retained native-owner check may wait for its existing lock;
            // it must not turn the opening sample into a stale final guard.
            let closing_boot = boot_ns()?;
            let closing_epoch = current_epoch_ms()?;
            if closing_boot < boot || closing_boot >= self.deadline || closing_epoch < epoch
                || closing_epoch >= self.binding.retain_until_epoch_ms {
                return Err(error("native bootstrap lifetime ended during its owner check"));
            }
            self.last_boot_ns = closing_boot;
            self.last_epoch_ms = closing_epoch;
            Ok(())
        })();
        if result.is_err() { self.failed = true; }
        result
    }

    fn readback(&mut self) -> Result<AttemptBindingPayload, ProtocolError> {
        let result = (|| {
            let directory = self.ledger.directory.as_ref()
                .ok_or_else(|| error("native bootstrap durable ledger disappeared"))?;
            let record = load_attempt_binding_record(
                &directory.join(attempt_binding_filename(&self.binding.attempt_id)?))?;
            let manifest = load_attempt_ledger_manifest(&directory.join(ATTEMPT_LEDGER_MANIFEST_FILE))?;
            if record.payload != self.binding || manifest != self.ledger.manifest {
                return Err(error("native bootstrap durable readback differs from committed originals"));
            }
            Ok(record.payload)
        })();
        if result.is_err() { self.ledger.poisoned = true; self.failed = true; }
        result
    }

    pub(crate) fn complete(mut self, output: &GeneratedBootstrapEnrollmentV1, deadline: u64)
        -> Result<RetainedNativeBootstrapOriginals, ProtocolError> {
        self.check(deadline)?;
        if self.binding.bootstrap_outcome.is_some() {
            return Err(error("native bootstrap completed attempt cannot publish again"));
        }
        // This type can only originate in the actual private generated-key
        // sign+NSM path. Raw public tuples cannot enter this completion seam.
        if output.quote_document().is_empty() || output.quote_document().len() > MAX_QUOTE_BYTES {
            return Err(error("native bootstrap generated quote is outside its bound"));
        }
        let mut completed = self.binding.clone();
        completed.bootstrap_outcome = Some(StoredOutcome {
            signature_base64url: general_purpose::URL_SAFE_NO_PAD.encode(output.signature()),
            public_key_base64url: general_purpose::URL_SAFE_NO_PAD.encode(output.public_key()),
            quote_base64url: general_purpose::URL_SAFE_NO_PAD.encode(output.quote_document()),
        });
        self.readback()?;
        self.check(deadline)?;
        publish(&mut self.ledger, &completed, Some(&self.binding), self.last_epoch_ms)?;
        self.binding = completed;
        let retained = self.readback()?.bootstrap_outcome
            .ok_or_else(|| error("native bootstrap completion was not retained"))?.originals()?;
        if retained.signature() != output.signature() || retained.public_key() != output.public_key()
            || retained.quote_document() != output.quote_document() {
            self.ledger.poisoned = true;
            return Err(error("native bootstrap output readback differs from generated originals"));
        }
        self.check(deadline)?;
        Ok(retained)
    }
}

pub(crate) fn begin<'a>(runtime: &'a CustodyRuntime, setup_authorizer_key_id: [u8; 32],
    setup_id: [u8; 32], operation_digest: [u8; 32], retain_until_epoch_ms: u64, deadline: u64)
    -> Result<BootstrapAttempt<'a>, ProtocolError> {
    runtime.verify_native_process()?; // Before locking an inherited mutex.
    if !runtime.is_native() || [setup_authorizer_key_id, setup_id, operation_digest].contains(&[0; 32]) {
        return Err(error("native bootstrap requires its genuine native owner and exact association"));
    }
    let opened_boot = boot_ns()?;
    let opened_epoch = current_epoch_ms()?;
    let deadline = deadline.min(opened_boot.checked_add(MAX_PROCESSING_NS)
        .ok_or_else(|| error("native bootstrap original deadline overflow"))?);
    if opened_boot >= deadline || retain_until_epoch_ms <= opened_epoch
        || retain_until_epoch_ms - opened_epoch > 300_000 {
        return Err(error("native bootstrap setup lifetime is not current and bounded"));
    }
    let mut hash = Sha256::new();
    hash.update(ATTEMPT_DOMAIN);
    hash.update(setup_authorizer_key_id);
    hash.update(setup_id);
    let attempt_id = format!("sha256:{}", hex::encode(hash.finalize()));
    let statement_digest = format!("sha256:{}", hex::encode(operation_digest));
    let mut ledger = runtime.attempt_statement_ledger.lock()
        .map_err(|_| error("native bootstrap actual ledger lock is unavailable"))?;
    runtime.verify_native_live()?;
    ledger.ensure_available()?;
    if ledger.directory.is_none() || opened_epoch < ledger.manifest.max_observed_epoch_ms {
        return Err(error("native bootstrap durable owner or clock high-water is invalid"));
    }
    let epoch = current_epoch_ms()?;
    let boot = boot_ns()?;
    if epoch < opened_epoch || epoch >= retain_until_epoch_ms || boot < opened_boot || boot >= deadline {
        return Err(error("native bootstrap original clock expired while acquiring its ledger"));
    }
    ledger.prune_expired(epoch)?;
    let previous = ledger.bindings.get(&attempt_id).cloned();
    let binding = if let Some(existing) = &previous {
        if existing.api_version != API_VERSION || existing.statement_digest != statement_digest
            || existing.retain_until_epoch_ms != retain_until_epoch_ms {
            return Err(error("native bootstrap setup is already bound to another operation"));
        }
        ledger.advance_max_observed_time(epoch)?;
        existing.clone()
    } else {
        // Each new-purpose slot reserves its entire eventual 24-KiB output.
        // Unknown claims count too; no temporary success state releases slots.
        let mut native_count = 0usize;
        for value in ledger.bindings.values() {
            if boot_ns()? >= deadline { return Err(error("native bootstrap capacity check expired")); }
            if value.api_version == API_VERSION { native_count += 1; }
        }
        if native_count >= MAX_ATTEMPTS || ledger.bindings.len() >= ledger.max_bindings {
            return Err(error("native bootstrap durable output capacity is exhausted"));
        }
        let claimed = AttemptBindingPayload {
            api_version: API_VERSION.to_owned(), attempt_id, statement_digest,
            retain_until_epoch_ms, bootstrap_outcome: None,
        };
        publish(&mut ledger, &claimed, None, epoch)?;
        claimed
    };
    let mut claim = NativeBootstrapClaim {
        runtime, ledger, binding, owner_pid: unsafe { libc::getpid() }, deadline,
        last_boot_ns: boot, last_epoch_ms: epoch, failed: false,
    };
    let actual = claim.readback()?;
    claim.check(deadline)?;
    if previous.is_some() {
        let outcome = actual.bootstrap_outcome.ok_or_else(|| attempt_ledger_error(
            "native_bootstrap_outcome_unknown", "native bootstrap was claimed without a completed outcome; signing is forbidden",
        ))?;
        let retained = outcome.originals()?;
        claim.check(deadline)?;
        Ok(BootstrapAttempt::Complete(retained))
    } else {
        Ok(BootstrapAttempt::New(claim))
    }
}
