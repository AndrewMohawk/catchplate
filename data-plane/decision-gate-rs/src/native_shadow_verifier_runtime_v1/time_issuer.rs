//! Separate fixed launch admission. Cryptographic issuance remains in the
//! pinned issuer, never in this root/image/identity framing owner.
use super::*;
use std::net::IpAddr;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TimeLaunch { api_version: String, runtime_image: RuntimeImage, issuer_configuration_sha256: String }

pub(super) fn transport(value: &Value) -> Result<(String, u16, String), String> {
    let fields = value["transport"].as_object().ok_or("issuer transport absent")?;
    ensure(fields.len() == 3 && ["localIp", "localPort", "peerIp"].iter().all(|key| fields.contains_key(*key)),
        "issuer transport is not closed")?;
    let mut addresses = Vec::with_capacity(2);
    for key in ["localIp", "peerIp"] {
        let text = value["transport"][key].as_str().ok_or("issuer address not a string")?;
        let address: IpAddr = text.parse().map_err(|_| "issuer address invalid")?;
        ensure(address.to_string() == text && !address.is_unspecified() && !address.is_multicast(),
            "issuer address is not exact unicast")?;
        addresses.push(text.to_owned());
    }
    let port = value["transport"]["localPort"].as_u64().filter(|v| (1024..=65535).contains(v))
        .ok_or("issuer local port outside admitted bound")? as u16;
    Ok((addresses.remove(0), port, addresses.remove(0)))
}

pub(super) fn open() -> Result<RuntimeAdmission, String> {
    let origin = Origin::capture()?;
    let launch = Original::open("native-shadow-time-issuer-launch.json", 16384)?;
    let selected: TimeLaunch = serde_json::from_value(document(&launch.bytes, 16384)?)
        .map_err(|_| "issuer launch not closed")?;
    ensure(selected.api_version == "catchplate.nativeShadowGuestTimeIssuerLaunch/v1"
        && selected.runtime_image.profile == "sealed-memfd-squashfs-v1"
        && selected.runtime_image.image_path == TIME_IMAGE_PATH, "issuer launch purpose differs")?;
    for pin in [&selected.issuer_configuration_sha256, &selected.runtime_image.image_sha256,
        &selected.runtime_image.interpreter_sha256, &selected.runtime_image.entrypoint_sha256] { digest(pin)?; }
    let configuration = Original::open("native-shadow-guest-time-issuer.json", 512 * 1024)?;
    ensure(hash(&configuration.bytes) == selected.issuer_configuration_sha256, "issuer actual policy pin differs")?;
    let value = document(&configuration.bytes, 512 * 1024)?;
    let fields = value.as_object().ok_or("issuer configuration not object")?;
    let expected = ["apiVersion", "uid", "gid", "operation", "issuerAuthorityKey", "timeKey",
        "guestAuthorityPublicKeyBase64url", "guestConfigurationOriginalBase64url", "guestDeliveryOriginalBase64url",
        "nitro", "collateralRevocation", "transport", "maximumBracketNanos", "timestampErrorNanos",
        "maximumClockRateErrorPpm", "maximumAnchorAgeNanos", "authorization"];
    ensure(fields.len() == expected.len() && expected.iter().all(|key| fields.contains_key(*key))
        && value["apiVersion"] == "catchplate.nativeShadowGuestTimeIssuerConfiguration/v1", "issuer policy shape differs")?;
    let uid = value["uid"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("issuer UID invalid")?;
    let gid = value["gid"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("issuer GID invalid")?;
    ensure([uid, gid].iter().all(|v| *v > 0 && *v < u32::MAX && ![64988,64989,64990,65534].contains(v)),
        "issuer identity is reserved or root")?;
    let op: Operation = serde_json::from_value(value["operation"].clone()).map_err(|_| "issuer operation not closed")?;
    ensure(op.boot_id_base64url == origin.boot && op.time_namespace_device > 0 && op.time_namespace_inode > 0
        && origin.time_identity()? == (op.time_namespace_device, op.time_namespace_inode), "issuer boot/time namespace differs")?;
    let issued = decimal(&op.issued_at_boottime_ns)?; let deadline = decimal(&op.deadline_boottime_ns)?;
    ensure(deadline.checked_sub(issued).is_some_and(|v| v > 0 && v <= 30_000_000_000), "issuer original interval differs")?;
    within(issued, deadline)?; transport(&value)?;
    let image_config = ImageConfiguration { profile: selected.runtime_image.profile,
        image_path: selected.runtime_image.image_path, image_sha256: selected.runtime_image.image_sha256,
        interpreter_sha256: selected.runtime_image.interpreter_sha256, helper_sha256: selected.runtime_image.entrypoint_sha256 };
    let owner = RuntimeAdmission { launch, configuration, origin,
        policy: Policy { uid, gid, issued, deadline, purpose:None, profile: Profile::TimeIssuer }, image_config };
    owner.check()?; Ok(owner)
}
