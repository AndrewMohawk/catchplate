//! Public Setup result framing only, never a replacement signature verifier.
use super::*;
use crate::native_shadow_verifier_runtime_v1::setup_issuer::Role;

pub(super) fn shape(raw: &[u8], role: Role) -> Result<(), String> {
    let value = json::parse(raw, 16384)?;
    ensure(canonical_ascii_bytes(&value)? == raw, "Setup result is not canonical original")?;
    let envelope = value.as_object().ok_or("Setup envelope absent")?;
    ensure(envelope.len() == 2 && envelope.contains_key("payload") && envelope.contains_key("signature"),
        "Setup envelope shape differs")?;
    let payload = value["payload"].as_object().ok_or("Setup payload absent")?;
    let names: &[&str] = if role == Role::Final {
        &["apiVersion", "purpose", "resultScope", "hostAssociationTrust", "challengeSha256", "hardwareSha256",
            "sessionId", "nonceSha256", "policyHash", "configurationSha256", "authorityKeyId", "authorityProvider",
            "issuedAtEpochNs", "expiresAtEpochNs", "measuredHost", "proxyReady"]
    } else {
        &["apiVersion", "purpose", "resultScope", "attemptSha256", "evidenceSha256", "runtimeSha256",
            "enrollmentSha256", "installationSha256", "scopeSha256", "quoteSha256", "releaseRecordSha256",
            "policyHash", "verifierKeyId", "verifierProvider", "issuedAtEpochNs", "expiresAtEpochNs",
            "measuredHost", "finalSetup", "proxyReady"]
    };
    ensure(payload.len() == names.len() && names.iter().all(|name| payload.contains_key(*name))
        && value["payload"]["measuredHost"] == false && value["payload"]["proxyReady"] == false,
        "Setup result shape/scope differs")?;
    if role == Role::Final {
        ensure(value["payload"]["apiVersion"] == "serverware.setupNativeFinalReceipt/v1"
            && value["payload"]["purpose"] == "native-setup-final-authorization"
            && value["payload"]["resultScope"] == "enclave-hardware-and-proxy-only"
            && value["payload"]["hostAssociationTrust"] == "trusted-host-local", "Setup final purpose differs")?;
    } else {
        ensure(value["payload"]["apiVersion"] == "serverware.setupNativeIndependentVerification/v1"
            && value["payload"]["purpose"] == role.name()
            && value["payload"]["resultScope"] == "enclave-hardware-and-proxy-only"
            && value["payload"]["finalSetup"] == false, "Setup verifier purpose differs")?;
    }
    ensure(value["signature"].as_str().is_some_and(|s| s.len() == 94 && s.starts_with("ed25519:")
        && s[8..].bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')),
        "Setup signature framing differs")
}
fn attempt(role: Role) -> Result<(), String> {
    ensure(std::env::args_os().count() == 1, "Setup issuer accepts no arguments")?;
    parent_security()?;
    let mut inputs = inputs::Inputs::take_setup()?;
    let output = inputs::Output::take()?;
    let admission = RuntimeAdmission::open_setup(role)?;
    let watch = Watchdog::arm(&admission)?;
    inputs.bind(&admission)?;
    let originals = admission.retain_setup_originals()?;
    let raw = execute(admission,&inputs,&watch)?;
    originals.check()?;
    // Output is bounded; retain and recheck the same originals around each
    // potentially blocking pipe write, not merely around the whole publish.
    let mut offset=0;
    while offset<raw.len() {
        originals.check()?; watch.check()?; output.check()?; inputs.check()?;
        let count=unsafe { libc::write(output.fd().as_raw_fd(),raw[offset..].as_ptr().cast(),raw.len()-offset) };
        if count>0 { offset+=count as usize; continue; }
        if count<0 && interrupted() { continue; }
        if count<0 && would_block() {
            let mut poll=libc::pollfd { fd:output.fd().as_raw_fd(),events:libc::POLLOUT,revents:0 };
            let rc=unsafe { libc::poll(&mut poll,1,25) };
            if rc<0 && interrupted() { continue; }
            ensure(rc>=0 && poll.revents & (libc::POLLERR|libc::POLLHUP|libc::POLLNVAL)==0,"Setup output pipe failed")?;
            continue;
        }
        return Err("Setup output write failed".into());
    }
    originals.check()?; watch.check()?; inputs.check()?; output.check()
}
pub(super) fn run(role: Role) -> ! {
    let status = if attempt(role).is_ok() { 0 } else { 1 };
    unsafe { libc::_exit(status) }
}
