//! Data-only closure for the explicitly selected fresh v24 delivery layout.
//! These joins grant neither inner signature validity nor native readiness.
//! The unchanged v24 decoder and retained original owners remain mandatory.
use super::{digest, ensure, json, pin, Profile, MAX_FILE, MAX_TOTAL};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const ROOT: &str = "/run/catchplate-preboot";
const INVENTORY: &str = "/run/catchplate-role-key-provisioning/inventory.enc.json";
const RESPONSE: &str = "/run/catchplate-preboot/response-v2.json";
const ROLE_EXECUTABLE: &str = "/usr/local/bin/catchplate-response-v2-guest-role";
const WORKER: &str = "/usr/local/bin/catchplate-native-shadow-worker";
const ROLES: [&str; 7] = ["custody-router", "state-authority", "credential-transport",
    "policy-proof-verifier", "immutable-artifact-ledger", "release-attestor-publisher", "cleanup-watchdog"];

pub(super) struct FileEntry {
    pub(super) label: String, pub(super) path: String,
    pub(super) bytes: Zeroizing<Vec<u8>>, pub(super) sha256: String,
    pub(super) mode: u32, pub(super) uid: u32, pub(super) gid: u32,
}
pub(super) struct Directory {
    pub(super) path: String, pub(super) mode: u32, pub(super) uid: u32, pub(super) gid: u32,
}
pub(super) struct Plan {
    pub(super) files: Vec<FileEntry>, pub(super) directories: Vec<Directory>,
    pub(super) absent_paths: Vec<String>,
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| format!("preboot closure lacks {field}"))
}
fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    ensure(value.as_object().is_some_and(|v| v.len() == names.len()
        && names.iter().all(|name| v.contains_key(*name))), "preboot closure fields differ")
}
fn array<'a>(value: &'a Value, name: &str, maximum: usize) -> Result<&'a [Value], String> {
    let result = value.get(name).and_then(Value::as_array).ok_or("preboot closure array absent")?;
    ensure(!result.is_empty() && result.len() <= maximum, "preboot closure collection bound")?;
    Ok(result)
}
fn canonical(raw: &[u8], maximum: usize) -> Result<Value, String> {
    let value = json::parse(raw, maximum)?;
    ensure(catchplate_decision_gate::canonical_json_bytes(&value)
        .map_err(|_| "preboot canonical original unavailable")? == raw,
        "preboot guest original is not canonical")?;
    Ok(value)
}
fn exact(value: &Value, name: &str, expected: &str) -> Result<(), String> {
    ensure(text(value, name)? == expected, "preboot closure fixed path or profile differs")
}
fn image(value: &Value, path_field: &str, hash_field: &str) -> Result<(), String> {
    let path = text(value, path_field)?;
    let leaf = path.strip_prefix("/usr/local/bin/")
        .or_else(|| path.strip_prefix("/usr/local/libexec/"));
    ensure(leaf.is_some_and(|v| !v.is_empty() && v.len() <= 255 && v.starts_with("catchplate-")
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
        && pin(text(value, hash_field)?), "preboot executable must remain a pinned image reference")?;
    if let Some(arguments) = value.get("arguments") {
        ensure(arguments.as_array().is_some_and(Vec::is_empty), "preboot image command arguments forbidden")?;
    }
    Ok(())
}

struct Builder<'a> {
    supplied: &'a BTreeMap<String, Vec<u8>>, used: BTreeSet<String>,
    plan: Plan, paths: BTreeSet<String>, total: usize,
}
impl<'a> Builder<'a> {
    fn directory(&mut self, path: String, mode: u32, uid: u32, gid: u32) -> Result<(), String> {
        ensure(self.paths.insert(path.clone()) && self.plan.directories.len() < 256,
            "preboot closure directory repeats")?;
        self.plan.directories.push(Directory { path, mode, uid, gid }); Ok(())
    }
    fn bytes(&mut self, label: &str, path: &str, bytes: &[u8], maximum: usize,
        uid: u32, gid: u32) -> Result<(), String> {
        ensure(!bytes.is_empty() && bytes.len() <= maximum.min(MAX_FILE) && self.plan.files.len() < 128
            && self.paths.insert(path.to_owned()), "preboot closure file repeats or exceeds bound")?;
        self.total = self.total.checked_add(bytes.len()).ok_or("preboot aggregate overflow")?;
        ensure(self.total <= MAX_TOTAL, "preboot aggregate exceeds 32 MiB")?;
        // Verifier jobs run after the permanent drop. Their public expectation
        // originals, and legacy public shadow sidecars, must remain readable.
        let public = uid == 0 && (label.starts_with("response-verifier.")
            || label.starts_with("generation-verifier.") || label.starts_with("shadow-"));
        self.plan.files.push(FileEntry { label: label.to_owned(), path: path.to_owned(),
            bytes: Zeroizing::new(bytes.to_vec()), sha256: digest(bytes),
            mode: if public { 0o444 } else { 0o400 }, uid, gid }); Ok(())
    }
    fn artifact(&mut self, label: &str, reference: &Value, path: &str, maximum: usize,
        uid: u32, gid: u32) -> Result<Value, String> {
        let raw = self.raw_artifact(label, reference, path, maximum, uid, gid)?;
        json::parse(raw, maximum)
    }
    fn raw_artifact(&mut self, label: &str, reference: &Value, path: &str, maximum: usize,
        uid: u32, gid: u32) -> Result<&'a [u8], String> {
        fields(reference, &["path", "sha256"])?;
        exact(reference, "path", path)?;
        let raw = self.supplied.get(label).ok_or("preboot required artifact label missing")?;
        ensure(self.used.insert(label.to_owned()) && pin(text(reference, "sha256")?)
            && digest(raw) == text(reference, "sha256")?, "preboot original pin or label differs")?;
        self.bytes(label, path, raw, maximum, uid, gid)?; Ok(raw)
    }
    fn absent(&mut self, path: String) -> Result<(), String> {
        ensure(self.paths.insert(path.clone()) && self.plan.absent_paths.len() < 128,
            "preboot absent output overlaps another original")?;
        self.plan.absent_paths.push(path); Ok(())
    }
    fn verifier(&mut self, value: &Value, label: &str) -> Result<(), String> {
        image(value, "executable", "executableSha256")?;
        ensure(value.get("verifierModule").is_none_or(Value::is_null),
            "preboot data delivery cannot install executable verifier modules")?;
        for (field, suffix) in [("expectations", "expectations"), ("trustRoots", "roots")] {
            self.raw_artifact(&format!("{label}.{suffix}"), &value[field],
                &format!("{ROOT}/{label}-{suffix}.json"), MAX_FILE, 0, 0)?;
        }
        Ok(())
    }
}

fn logical_roles(role: &str) -> &'static [&'static str] {
    match role {
        "custody-router" => &["readiness-topology-attestor"],
        "state-authority" => &["trusted-time", "recovery", "linearizable-store", "quorum", "public-release-consumption", "emergency-fence-revoker"],
        "credential-transport" => &["credential-authority", "target-transport", "mutation-supervisor"],
        "policy-proof-verifier" => &["evidence-trust", "live-proof-verifier", "archive-proof-verifier"],
        "immutable-artifact-ledger" => &["persistence", "archive-store"],
        "release-attestor-publisher" => &["runtime-attestation", "transparency", "attester", "publisher", "public-release", "custody"],
        "cleanup-watchdog" => &["outcome-reconciliation", "emergency-cleanup-executor"],
        _ => &[],
    }
}

/// Signature/actual boot/time admission is the caller's preceding operation.
/// Exact N and launch bytes are copied, never rewritten into this layout.
pub(super) fn validate(configuration: &[u8], launch: &[u8], artifacts: &BTreeMap<String, Vec<u8>>, profile: Profile)
    -> Result<Plan, String> {
    ensure(artifacts.len() <= 126 && !artifacts.contains_key("configuration")
        && !artifacts.contains_key("launch"), "preboot artifact count or reserved label differs")?;
    let n = json::parse(configuration, MAX_FILE)?;
    let l = json::parse(launch, 16384)?;
    exact(&n, "apiVersion", profile.configuration())?;
    if profile == Profile::RotationV25 {
        ensure(n.get("measuredStaticCredential").is_none(), "rotation delivery excludes creation profile")?;
        exact(&n["measuredStaticCredentialRotation"], "apiVersion",
            "catchplate.nativeStaticCredentialRotationConfiguration/v1")?;
        exact(&n["measuredStaticCredentialRotation"]["staticCredentialRotationPolicy"], "schema",
            "catchplate.staticCredentialRotationAuthorityPolicy/v1")?;
        exact(&n["measuredStaticCredentialRotation"]["staticCredentialRotationPolicy"], "nativeCustodyPurpose",
            "catchplate.nativeStaticCredentialRotationStatement/v1")?;
    }
    exact(&l, "apiVersion", "catchplate.nativeStartupLaunch/v1")?;
    ensure(text(&l, "configurationSha256")? == digest(configuration), "preboot launch does not bind literal N")?;
    for field in ["credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
        "releaseAuthorizationToken", "managementToken", "auditToken"] {
        ensure(n["gate"].get(field) == Some(&Value::Null), "preboot refuses plaintext service tokens")?;
    }
    fields(&n["gate"]["policyTrust"]["verifier"], &["executable", "arguments", "sha256"])?;
    image(&n["gate"]["policyTrust"]["verifier"], "executable", "sha256")?;
    let mut b = Builder { supplied: artifacts, used: BTreeSet::new(), paths: BTreeSet::new(), total: 0,
        plan: Plan { files: Vec::new(), directories: Vec::new(), absent_paths: Vec::new() } };
    b.directory(ROOT.into(), 0o755, 0, 0)?;
    b.directory(format!("{ROOT}/roles"), 0o755, 0, 0)?;
    b.directory(format!("{ROOT}/deliveries"), 0o700, 0, 0)?;
    b.directory(format!("{ROOT}/identity"), 0o755, 0, 0)?;
    b.directory("/run/catchplate-role-key-provisioning".into(), 0o700, 0, 0)?;
    b.directory(format!("{ROOT}/attempt-ledger"), 0o700, 65534, 65534)?;
    exact(&n["native"], "attemptLedgerDirectory", &format!("{ROOT}/attempt-ledger"))?;
    b.bytes("configuration", &format!("{ROOT}/configuration.json"), configuration, MAX_FILE, 0, 0)?;
    b.bytes("launch", &format!("{ROOT}/launch.json"), launch, 16384, 0, 0)?;
    b.raw_artifact("policy", &n["policy"], &format!("{ROOT}/policy.json"), MAX_FILE, 0, 0)?;

    let shadow = &n["shadow"];
    ensure(matches!(shadow.get("apiVersion").and_then(Value::as_str),
        None | Some("catchplate.nativeShadowConfiguration/v2")) && shadow.get("nativeActivation").is_none(),
        "preboot delivery excludes inherited publication and activation descriptors")?;
    for (field, label) in [("trustManifest", "shadow-trust"), ("custodyConfig", "shadow-custody"),
        ("startupActiveAuthorization", "shadow-startup")] {
        let raw = b.raw_artifact(label, &shadow[field], &format!("{ROOT}/{label}.json"), MAX_FILE, 0, 0)?;
        if field == "custodyConfig" {
            let value = json::parse(raw, MAX_FILE)?;
            ensure(!text(&value, "apiVersion").unwrap_or("").starts_with("catchplate.nativeShadowCustodyLifecycleReceiver/"),
                "preboot delivery cannot synthesize a host custody channel")?;
        }
    }
    for field in ["runtimeVerifier", "webauthnVerifier", "publicationHandoff"] {
        fields(&shadow[field], &["executable", "arguments", "sha256"])?;
        image(&shadow[field], "executable", "sha256")?;
        ensure(text(&shadow[field], "executable")? != WORKER,
            "worker launcher is not a stdio purpose verifier")?;
    }
    if let Some(workers) = shadow.get("workers") {
        fields(workers, &["apiVersion", "executable"])?;
        exact(workers, "apiVersion", "catchplate.nativeShadowWorkers/v1")?;
        exact(&workers["executable"], "path", WORKER)?;
        image(&workers["executable"], "path", "sha256")?;
    }

    let inspector = &n["guestInspector"];
    let cohort = &n["guestCohort"];
    exact(inspector, "apiVersion", "catchplate.nativeGuestInspector/v1")?;
    exact(cohort, "apiVersion", "catchplate.nativeGuestCohort/v1")?;
    exact(&inspector["executable"], "path", "/usr/local/bin/catchplate-response-v2-guest-inspector")?;
    exact(&cohort["executable"], "path", ROLE_EXECUTABLE)?;
    image(&inspector["executable"], "path", "sha256")?;
    image(&cohort["executable"], "path", "sha256")?;
    ensure(inspector["configuration"] == cohort["configuration"], "inspector/cohort configuration originals differ")?;
    let response_raw = b.raw_artifact("response-v2", &cohort["configuration"], RESPONSE, 256 * 1024, 0, 0)?;
    let response = canonical(response_raw, 256 * 1024)?;
    ensure(response.get("providerRouter").is_none_or(Value::is_null),
        "preboot guest closure cannot provision ambient provider-router files")?;
    ensure(response.get("guestDeliveryAuthority").is_some_and(Value::is_object)
        && response["guestListener"]["apiVersion"] == "catchplate.responseV2.guestListener/v1"
        && response["guestPublicArtifacts"]["apiVersion"] == "catchplate.responseV2.guestPublicArtifacts/v1",
        "preboot requires explicit guest originals and public-artifact owner")?;
    b.verifier(&n["responseObservationV2"]["teeVerifier"], "response-verifier")?;
    b.verifier(&response["teeHardwareGenerationVerifier"], "generation-verifier")?;
    let deliveries = array(cohort, "deliveries", 7)?;
    let processes = array(&response["custodyTopology"], "processes", 7)?;
    ensure(deliveries.len() == 7 && processes.len() == 7, "preboot requires all seven guest roles")?;
    let mut uids = BTreeSet::new();
    let mut public_keys = BTreeMap::new();
    for role in ROLES {
        let refs: Vec<_> = deliveries.iter().filter(|v| v["serviceRole"] == role).collect();
        let owners: Vec<_> = processes.iter().filter(|v| v["serviceRole"] == role).collect();
        ensure(refs.len() == 1 && owners.len() == 1, "preboot role roster differs")?;
        let delivery = refs[0]; let process = owners[0];
        fields(delivery, &["serviceRole", "path", "sha256"])?;
        let uid = process["uid"].as_u64().filter(|v| *v > 0 && *v < u32::MAX as u64
            && ![64988, 65519, 65534].contains(v)).ok_or("preboot role UID invalid")? as u32;
        ensure(process["gid"].as_u64() == Some(65519) && uids.insert(uid), "preboot role isolation differs")?;
        let base = format!("{ROOT}/roles/{role}");
        b.directory(base.clone(), 0o755, 0, 0)?;
        for directory in ["credentials", "keys", "state"] {
            b.directory(format!("{base}/{directory}"), 0o700, uid, 65519)?;
        }
        b.directory(format!("{base}/sockets"), 0o755, uid, 65519)?;
        exact(process, "stateDirectory", &format!("{base}/state"))?;
        let socket = if role == "custody-router" { "/run/catchplate-response-v2-guest/transaction.sock".to_owned() }
            else { format!("{base}/sockets/service.sock") };
        exact(process, "socketPath", &socket)?;
        exact(process, "readinessSocketPath", &if role == "custody-router" {
            format!("{base}/sockets/readiness.sock") } else { socket.clone() })?;
        exact(process, "readinessRecordPath", &format!("{base}/state/readiness.json"))?;
        ensure(process.get("backendSocketPath").is_none_or(Value::is_null),
            "preboot role cannot select an external backend socket")?;
        let label = format!("delivery.{role}");
        let reference = serde_json::json!({"path":delivery["path"], "sha256":delivery["sha256"]});
        let raw = b.raw_artifact(&label, &reference, &format!("{ROOT}/deliveries/{role}.json"), 65536, 0, 0)?;
        let envelope = canonical(raw, 65536)?;
        fields(&envelope, &["apiVersion", "payload", "signatureBase64url"])?;
        exact(&envelope, "apiVersion", "catchplate.responseV2.guestCredentialDelivery/v1")?;
        let payload = &envelope["payload"];
        ensure(payload["configurationSha256"] == digest(response_raw)
            && payload["serviceRole"] == role && payload["generationId"] == response["custodyTopology"]["generationId"]
            && payload["generation"] == response["custodyTopology"]["generation"], "preboot role delivery source joins differ")?;
        if role == "custody-router" {
            ensure(inspector["delivery"] == reference, "inspector is not the exact router delivery")?;
        }
        let credentials = &payload["credentials"];
        fields(credentials, &["generationManifest", "trustAnchorPublicKey", "bootstrapManifests", "roleKeys"])?;
        b.raw_artifact(&format!("generation.{role}"), &credentials["generationManifest"],
            &format!("{base}/credentials/generation.json"), 4 * 1024 * 1024, uid, 65519)?;
        let key = b.raw_artifact(&format!("trust-anchor.{role}"), &credentials["trustAnchorPublicKey"],
            &format!("{base}/credentials/trust-anchor.pub"), 32, uid, 65519)?;
        ensure(key.len() == 32, "generation trust root is not exact 32 bytes")?;
        if role == "state-authority" {
            let bootstrap = &credentials["bootstrapManifests"];
            fields(bootstrap, &["topologyManifest", "roleManifest", "keyManifest"])?;
            for (name, suffix) in [("topologyManifest", "topology"), ("roleManifest", "role"), ("keyManifest", "key")] {
                b.raw_artifact(&format!("bootstrap.{suffix}"), &bootstrap[name],
                    &format!("{base}/credentials/{suffix}.json"), 4 * 1024 * 1024, uid, 65519)?;
            }
        } else { ensure(credentials["bootstrapManifests"].is_null(), "non-state role received bootstrap inputs")?; }
        let keys = array(credentials, "roleKeys", 32)?;
        let descriptors = array(process, "roleKeys", 32)?;
        ensure(keys.len() == descriptors.len(), "delivered logical key roster differs")?;
        let mut seen = BTreeSet::new();
        for key in keys {
            fields(key, &["logicalRole", "publicKey", "secretKey"])?;
            let logical = text(key, "logicalRole")?;
            ensure(logical_roles(role).contains(&logical) && seen.insert(logical), "logical role not assigned to service")?;
            let matches: Vec<_> = descriptors.iter().filter(|v| v["logicalRole"] == logical).collect();
            ensure(matches.len() == 1, "logical role descriptor differs")?;
            let descriptor = matches[0];
            let path = format!("{base}/keys/{logical}.pub");
            let secret = format!("{base}/keys/{logical}.seed");
            exact(descriptor, "publicKeyPath", &path)?;
            exact(descriptor, "secretKeyPath", &secret)?;
            fields(&key["secretKey"], &["path", "sha256"])?;
            exact(&key["secretKey"], "path", &secret)?;
            ensure(pin(text(&key["secretKey"], "sha256")?) && descriptor["publicKeySha256"] == key["publicKey"]["sha256"],
                "public/absent-seed commitments differ")?;
            let raw = b.raw_artifact(&format!("public-key.{role}.{logical}"), &key["publicKey"], &path, 32, uid, 65519)?;
            ensure(raw.len() == 32 && public_keys.insert(logical.to_owned(), (path, digest(raw))).is_none(),
                "public logical key is not unique exact 32 bytes")?;
            b.absent(secret)?;
        }
    }
    // Role identity configuration is separate public data, not the enclosing
    // response configuration (which would require its own full self-hash).
    let mut identity_configs = BTreeMap::<String, Value>::new();
    for identities in [&n["responseObservationV2"]["roleKeys"], &response["roleIdentities"]] {
        let entries = identities.as_array().ok_or("preboot role identity pins absent")?;
        ensure(!entries.is_empty() && entries.len() <= 256, "preboot role identity bounds")?;
        for identity in entries {
            let (path, hash) = public_keys.get(text(identity, "role")?).ok_or("preboot role identity is not in delivered topology")?;
            exact(identity, "keyMaterialPath", path)?;
            exact(identity, "keyMaterialSha256", hash)?;
            let logical = text(identity, "role")?;
            let config_path = format!("{ROOT}/identity/{logical}.json");
            exact(identity, "providerConfigPath", &config_path)?;
            let reference = serde_json::json!({"path":config_path,"sha256":identity["providerConfigSha256"]});
            if let Some(previous) = identity_configs.get(logical) {
                ensure(previous == &reference, "native/client identity configuration originals differ")?;
            } else {
                b.raw_artifact(&format!("identity-config.{logical}"), &reference,
                    &config_path, MAX_FILE, 0, 0)?;
                identity_configs.insert(logical.to_owned(), reference);
            }
            image(identity, "executablePath", "executableMeasurementSha256")?;
        }
    }
    let provisioner = &n["guestRoleKeyProvisioner"];
    exact(provisioner, "apiVersion", "catchplate.nativeGuestRoleKeyProvisioner/v1")?;
    let encrypted = b.artifact("role-inventory", &provisioner["encryptedInventory"], INVENTORY, 32768, 0, 0)?;
    fields(&encrypted, &["apiVersion", "inventorySha256", "nonce", "ciphertext"])?;
    exact(&encrypted, "apiVersion", "catchplate.nativeGuestRoleKeyCiphertext/v1")?;
    ensure(b.used.len() == artifacts.len(), "preboot contains artifacts outside the complete source closure")?;
    b.plan.files.sort_by(|a, z| a.path.cmp(&z.path));
    b.plan.directories.sort_by(|a, z| a.path.cmp(&z.path));
    b.plan.absent_paths.sort();
    Ok(b.plan)
}
