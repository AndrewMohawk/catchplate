//! Explicit engineering-only selection; never an alternative custody authority.
//!
//! This module is deliberately std-only so its admission/refusal controls can
//! be exercised without compiling the native production test harness.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MARKER: &[u8] =
    b"{\"schema\": \"serverware.developmentSandbox/v1\", \"syntheticOnly\": true}\n";
const O_NOFOLLOW: i32 = 0x20000;

unsafe extern "C" {
    fn geteuid() -> u32;
}

pub(crate) struct Selection(());

pub(crate) struct Configuration<'a> {
    pub is_production: bool,
    pub has_native_authority: bool,
    pub has_shadow_control: bool,
    pub atomic: bool,
    pub ingress_mode: &'a str,
    pub policy_path: &'a str,
    pub policy_id: &'a str,
    pub policy_hash: &'a str,
    pub routes: Vec<(&'a str, &'a str, u16)>,
    pub lease_url: Option<&'a str>,
    pub audit_url: Option<&'a str>,
    pub instance_id: Option<&'a str>,
    pub audit_enabled: bool,
}

pub(crate) struct Profile {
    policy_hash: String,
}

fn refused() -> String {
    "isolated development sandbox admission refused".to_owned()
}

fn select(
    flag: Option<&str>,
    channel: Option<&str>,
    production: Option<&str>,
    native_arguments: bool,
    forbidden_configuration: bool,
) -> Result<Option<Selection>, String> {
    match flag {
        None | Some("0") => Ok(None),
        Some("1")
            if channel == Some("dev")
                && matches!(production, None | Some("0"))
                && !native_arguments
                && !forbidden_configuration =>
        {
            Ok(Some(Selection(())))
        }
        _ => Err(refused()),
    }
}

pub(crate) fn from_environment() -> Result<Option<Selection>, String> {
    let flag = env::var("SERVERWARE_DEVELOPMENT_SANDBOX").ok();
    let channel = env::var("SERVERWARE_RELEASE_CHANNEL").ok();
    let production = env::var("SERVERWARE_PRODUCTION_IMAGE").ok();
    let forbidden = env::vars_os().any(|(name, value)| {
        let name = name.to_string_lossy();
        !value.is_empty()
            && name.starts_with("SERVERWARE_")
            && ([
                "SERVERWARE_NATIVE_",
                "SERVERWARE_NITRO_",
                "SERVERWARE_AUTHORITY_",
                "SERVERWARE_AWS_KMS_",
                "SERVERWARE_POLICY_SHADOW_",
                "SERVERWARE_MASTER_KEY_UNSEAL_COMMAND",
                "SERVERWARE_WORKLOAD_IDENTITY_",
                "SERVERWARE_CONTROL_PLANE_CUSTODY_",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
                || name.ends_with("_FD")
                || name.contains("_FD_"))
    });
    select(
        flag.as_deref(),
        channel.as_deref(),
        production.as_deref(),
        env::args_os().nth(1).is_some(),
        forbidden,
    )
}

fn validate_marker(directory: &Path) -> Result<(), String> {
    let owner = unsafe { geteuid() };
    let metadata = fs::symlink_metadata(directory).map_err(|_| refused())?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
        return Err(refused());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(directory.join(".serverware-development-sandbox.json"))
        .map_err(|_| refused())?;
    let before = file.metadata().map_err(|_| refused())?;
    if !before.is_file()
        || before.uid() != owner
        || before.mode() & 0o077 != 0
        || before.len() != MARKER.len() as u64
    {
        return Err(refused());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(513)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    let after = file.metadata().map_err(|_| refused())?;
    if bytes != MARKER
        || before.ino() != after.ino()
        || before.dev() != after.dev()
        || before.len() != after.len()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(refused());
    }
    Ok(())
}

impl Selection {
    fn validate_configuration(&self, config: &Configuration<'_>) -> Result<(), String> {
        let digest = config
            .policy_hash
            .strip_prefix("sha256:")
            .ok_or_else(refused)?;
        if config.is_production
            || config.has_native_authority
            || config.has_shadow_control
            || config.atomic
            || config.ingress_mode != "development-raw"
            || config.policy_path != "/data/policy-bundle.json"
            || config.policy_id != "serverware-demo"
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || config.routes.is_empty()
            || config
                .routes
                .iter()
                .any(|route| *route != ("https", "demo-upstream", 8443))
            || config.lease_url != Some("http://serverware:3000/api/data-plane/credential-leases")
            || config.audit_url != Some("http://serverware:3000/api/data-plane/audit")
            || config.instance_id != Some("spiffe://development.serverware/decision-gate/local")
            || !config.audit_enabled
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn admit(self, config: Configuration<'_>) -> Result<Profile, String> {
        self.validate_configuration(&config)?;
        validate_marker(Path::new("/data"))?;
        Ok(Profile {
            policy_hash: config.policy_hash.to_owned(),
        })
    }
}

impl Profile {
    pub(crate) fn matches(&self, policy_hash: &str) -> bool {
        self.policy_hash == policy_hash
    }
    pub(crate) fn policy_hash(&self) -> &str {
        &self.policy_hash
    }
}

pub(crate) fn serving_ready(
    profile: Option<&Profile>,
    policy_hash: &str,
    custody_ready: bool,
) -> bool {
    profile.map_or(custody_ready, |profile| profile.matches(policy_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn config() -> Configuration<'static> {
        Configuration {
            is_production: false,
            has_native_authority: false,
            has_shadow_control: false,
            atomic: false,
            ingress_mode: "development-raw",
            policy_path: "/data/policy-bundle.json",
            policy_id: "serverware-demo",
            policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            routes: vec![("https", "demo-upstream", 8443)],
            lease_url: Some("http://serverware:3000/api/data-plane/credential-leases"),
            audit_url: Some("http://serverware:3000/api/data-plane/audit"),
            instance_id: Some("spiffe://development.serverware/decision-gate/local"),
            audit_enabled: true,
        }
    }

    #[test]
    fn selection_is_explicit_and_cannot_enter_production_or_native() {
        assert!(select(None, Some("dev"), None, false, false)
            .unwrap()
            .is_none());
        assert!(select(Some("0"), Some("production"), None, false, false)
            .unwrap()
            .is_none());
        assert!(select(Some("1"), Some("dev"), None, false, false)
            .unwrap()
            .is_some());
        for (flag, channel, production, native, forbidden) in [
            ("yes", "dev", None, false, false),
            ("1", "production", None, false, false),
            ("1", "dev", Some("1"), false, false),
            ("1", "dev", None, true, false),
            ("1", "dev", None, false, true),
        ] {
            assert!(select(Some(flag), Some(channel), production, native, forbidden).is_err());
        }
    }

    #[test]
    fn authority_external_destinations_and_audit_removal_are_refused() {
        assert!(Selection(()).validate_configuration(&config()).is_ok());
        let mut cases = vec![];
        let mut value = config();
        value.is_production = true;
        cases.push(value);
        let mut value = config();
        value.has_native_authority = true;
        cases.push(value);
        let mut value = config();
        value.has_shadow_control = true;
        cases.push(value);
        let mut value = config();
        value.atomic = true;
        cases.push(value);
        let mut value = config();
        value.routes = vec![("https", "provider.example", 443)];
        cases.push(value);
        let mut value = config();
        value.lease_url = Some("http://provider.example/credential-leases");
        cases.push(value);
        let mut value = config();
        value.audit_enabled = false;
        cases.push(value);
        let mut value = config();
        value.policy_id = "ordinary-production-policy";
        cases.push(value);
        let mut value = config();
        value.policy_path = "/pilot/policy-bundle.json";
        cases.push(value);
        for value in cases {
            assert!(Selection(()).validate_configuration(&value).is_err());
        }
    }

    #[test]
    fn profile_never_adopts_a_changed_policy() {
        let profile = Profile {
            policy_hash: config().policy_hash.to_owned(),
        };
        assert!(profile.matches(config().policy_hash));
        assert!(!profile
            .matches("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        assert!(serving_ready(Some(&profile), config().policy_hash, false));
        assert!(!serving_ready(Some(&profile), "changed-policy", true));
        assert!(!serving_ready(None, config().policy_hash, false));
        assert!(serving_ready(None, config().policy_hash, true));
    }

    #[test]
    fn marker_requires_existing_private_owned_synthetic_data() {
        let base =
            env::var_os("SERVERWARE_SANDBOX_TEST_TMPDIR").expect("explicit test scratch root");
        let directory = Path::new(&base).join(format!("marker-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join(".serverware-development-sandbox.json");
        assert!(validate_marker(&directory).is_err());
        fs::write(&path, MARKER).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_marker(&directory).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_marker(&directory).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"{}").unwrap();
        assert!(validate_marker(&directory).is_err());
        fs::remove_file(&path).unwrap();
        let original = directory.join("original");
        fs::write(&original, MARKER).unwrap();
        symlink(&original, &path).unwrap();
        assert!(validate_marker(&directory).is_err());
        fs::remove_file(&path).unwrap();
        fs::remove_file(&original).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}
