//! Independently pinned ordinary policy-aware response scope. No attestation,
//! authorization or runtime-provided profile selection is produced here.

use super::*;
use super::proof_client_native_verifier_v1::{HeldInput, strict_json};

const MAXIMUM: usize = 16 * 1024;

pub(super) struct PolicyAwareExpectations {
    input: HeldInput,
    expected: Value,
    deadline: Instant,
    owner: u32,
}

impl PolicyAwareExpectations {
    pub(super) fn open(path: PathBuf, pin: String, deadline: Instant,
        principal: &str, instance: Option<&str>, control_plane_key_id: &str) -> Result<Self, String> {
        let (input, original) = HeldInput::open(path, pin, MAXIMUM, true, deadline)?;
        let expected = strict_json(&original, MAXIMUM, deadline)?;
        require_exact_fields(expected.as_object().ok_or("policy-aware expectations must be an object")?,
            &["apiVersion", "statementProfile", "responseSigningKeyId", "controlPlaneResponseSigningKeyId",
                "policyDigest", "releaseDigest", "dataPlaneBinaryDigest", "serverInstanceId", "principalId"],
            "policy-aware response expectations")?;
        if required_string(&expected, "apiVersion")? != "serverware.policyAwareResponseExpectations/v1"
            || required_string(&expected, "statementProfile")? != "serverware.policyAwareResponseStatements/v1"
            || !valid_bounded_identity(principal)
            || required_string(&expected, "principalId")? != principal
            || instance != Some(required_string(&expected, "serverInstanceId")?)
            || required_string(&expected, "controlPlaneResponseSigningKeyId")? != control_plane_key_id {
            return Err("policy-aware independent expectations differ from configured scope".to_owned());
        }
        let server = required_string(&expected, "serverInstanceId")?;
        if server.is_empty() || server.len() > 2048 || server != server.trim() || server.chars().any(char::is_control) {
            return Err("policy-aware expected server identity is invalid".to_owned());
        }
        for field in ["responseSigningKeyId", "controlPlaneResponseSigningKeyId", "policyDigest", "releaseDigest", "dataPlaneBinaryDigest"] {
            let digest = required_digest(&expected, field)?;
            if digest[7..].bytes().all(|byte| byte == b'0') {
                return Err("policy-aware expected digest must be nonzero".to_owned());
            }
        }
        let owner = Self { input, expected, deadline, owner: std::process::id() };
        owner.check()?;
        Ok(owner)
    }

    pub(super) fn check(&self) -> Result<(), String> {
        self.check_live()?;
        self.input.verify(self.deadline)
    }

    pub(super) fn check_live(&self) -> Result<(), String> {
        if self.owner != std::process::id() || Instant::now() >= self.deadline {
            return Err("policy-aware expectation owner or original deadline changed".to_owned());
        }
        Ok(())
    }

    pub(super) fn protect_target(&self, target: &ResolvedOutputTarget) -> Result<(), String> {
        self.check()?;
        self.input.protect_target(target)?;
        self.check()
    }

    pub(super) fn require_statement(&self, statement: &Value, signature: &Map<String, Value>,
        control_plane_key: &VerifyingKey, kind: StatementKind) -> Result<(), String> {
        self.check()?;
        let key_pem = control_plane_key.to_public_key_pem(Default::default())
            .map_err(|_| "encode configured control-plane key")?;
        let (_, control_plane_key_id) = decode_public_key_pem(&key_pem)?;
        if control_plane_key_id != required_string(&self.expected, "controlPlaneResponseSigningKeyId")?
            || signature.get("key_id").and_then(Value::as_str) != Some(required_string(&self.expected, "responseSigningKeyId")?)
            || required_string(statement, "apiVersion")? != ReleaseProfile::PolicyAware.statement(kind)
            || statement.get("server_instance").and_then(|value| value.get("id"))
                != self.expected.get("serverInstanceId") {
            return Err("policy-aware response does not match independently pinned keys/profile/instance".to_owned());
        }
        match statement.get("principal_id") {
            Some(Value::Null) if kind == StatementKind::Observation => {},
            Some(value) if Some(value) == self.expected.get("principalId") => {},
            _ => return Err("policy-aware response principal differs from independent pin".to_owned()),
        }
        let policy = if kind == StatementKind::Observation {
            statement.get("policy").and_then(|value| value.get("digest"))
        } else { statement.get("policy_digest") };
        if policy != self.expected.get("policyDigest")
            || statement.get("release_digest") != self.expected.get("releaseDigest")
            || statement.get("data_plane_binary_digest") != self.expected.get("dataPlaneBinaryDigest") {
            return Err("policy-aware response differs from independently pinned release/policy/binary".to_owned());
        }
        // This comparison is data-only. The caller still verifies the original
        // Ed25519 statement, exact receipt, request/response and TLS exporter.
        self.check()
    }
}
