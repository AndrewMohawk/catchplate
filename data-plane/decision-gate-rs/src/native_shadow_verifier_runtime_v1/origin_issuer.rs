//! Separate fixed launch admission. Cryptographic issuance remains in the
//! pinned issuer, never in this root/image/identity framing owner.
use super::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OriginLaunch { api_version: String, runtime_image: RuntimeImage, issuer_configuration_sha256: String }

pub(super) fn open() -> Result<RuntimeAdmission, String> {
    let origin = Origin::capture()?;
    let launch = Original::open("native-generation-origin-issuer-launch.json", 16384)?;
    let selected: OriginLaunch = serde_json::from_value(document(&launch.bytes, 16384)?)
        .map_err(|_| "issuer launch not closed")?;
    ensure(selected.api_version == "catchplate.nativeGenerationOriginIssuerLaunch/v1"
        && selected.runtime_image.profile == "sealed-memfd-squashfs-v1"
        && selected.runtime_image.image_path == ORIGIN_IMAGE_PATH, "issuer launch purpose differs")?;
    for pin in [&selected.issuer_configuration_sha256, &selected.runtime_image.image_sha256,
        &selected.runtime_image.interpreter_sha256, &selected.runtime_image.entrypoint_sha256] { digest(pin)?; }
    let configuration = Original::open("native-generation-origin-issuer.json", 512 * 1024)?;
    ensure(hash(&configuration.bytes) == selected.issuer_configuration_sha256, "issuer actual policy pin differs")?;
    let value = document(&configuration.bytes, 512 * 1024)?;
    let fields = value.as_object().ok_or("issuer configuration not object")?;
    let expected = ["apiVersion", "uid", "gid", "operation", "issuerAuthorityKey", "originKey",
        "target", "nitro", "collateralRevocation", "transport", "authorization"];
    ensure(fields.len() == expected.len() && expected.iter().all(|key| fields.contains_key(*key))
        && value["apiVersion"] == "catchplate.nativeGenerationOriginIssuerConfiguration/v1", "issuer policy shape differs")?;
    let uid = value["uid"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("issuer UID invalid")?;
    let gid = value["gid"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("issuer GID invalid")?;
    ensure([uid, gid].iter().all(|v| *v > 0 && *v < u32::MAX && ![64988,64989,64990,65534].contains(v)),
        "issuer identity is reserved or root")?;
    let op: Operation = serde_json::from_value(value["operation"].clone()).map_err(|_| "issuer operation not closed")?;
    ensure(op.boot_id_base64url == origin.boot && op.time_namespace_device > 0 && op.time_namespace_inode > 0
        && origin.time_identity()? == (op.time_namespace_device, op.time_namespace_inode), "issuer boot/time namespace differs")?;
    let issued = decimal(&op.issued_at_boottime_ns)?; let deadline = decimal(&op.deadline_boottime_ns)?;
    ensure(deadline.checked_sub(issued).is_some_and(|v| v > 0 && v <= 30_000_000_000), "issuer original interval differs")?;
    within(issued, deadline)?; time_issuer::transport(&value)?;
    let image_config = ImageConfiguration { profile: selected.runtime_image.profile,
        image_path: selected.runtime_image.image_path, image_sha256: selected.runtime_image.image_sha256,
        interpreter_sha256: selected.runtime_image.interpreter_sha256, helper_sha256: selected.runtime_image.entrypoint_sha256 };
    let owner = RuntimeAdmission { launch, configuration, origin,
        policy: Policy { uid, gid, issued, deadline, purpose:None, profile: Profile::OriginIssuer }, image_config };
    owner.check()?; Ok(owner)
}
