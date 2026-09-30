//! Bounded, static membership in an explicitly pinned native closure set.
//!
//! This validates bytes, manifests and membership only. Neither the supplied
//! root pins nor this value constitute assignment, guest or process authority.
//! Existing live closure admission must still authenticate its own signature,
//! image, executable, runtime, exact seccomp program and provenance. In
//! particular, a seccomp-set root is never a single seccomp-policy digest.

use super::*;

pub(in crate::policy_shadow) const MAX_SET_BYTES: usize = 12 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub(in crate::policy_shadow) const MEMBER_ROLES: [&str; 11] = [
    "retrieval",
    "persistence",
    "trustedTime",
    "generationInstall",
    "commitRequest",
    "ingressAdmission",
    "terminalAppend",
    "dispatchBarrier",
    "activeEffectBarrier",
    "activeEffectCommit",
    "bridge",
];

const SET_API: &str = "serverware.nativeCustodyExecutionClosureSet/v1";
const LEAF_DOMAIN: &[u8] = b"serverware.nativeCustodyExecutionClosureSetLeaf/v1";
const ROOT_DOMAIN: &[u8] = b"serverware.nativeCustodyExecutionClosureSetRoot/v1";
const SECCOMP_ROOT_DOMAIN: &[u8] = b"serverware.nativeCustodySeccompSetRoot/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Member {
    role: String,
    manifest: Manifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Wire {
    api_version: String,
    members: [Member; 11],
    set_root_sha256: Sha256Digest,
    seccomp_set_root_sha256: Sha256Digest,
}

/// Static validation result with no deserialization or live-owner constructor.
/// Its roots are useful only under an independently authorized caller contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::policy_shadow) struct ValidatedSet {
    wire: Wire,
    leaves: Vec<Sha256Digest>,
}

/// Borrowed membership in a validated set, not a guest or custody capability.
pub(in crate::policy_shadow) struct RoleBinding<'a> {
    role: &'static str,
    set: &'a ValidatedSet,
    index: usize,
}

impl ValidatedSet {
    pub(in crate::policy_shadow) fn from_bytes(
        raw: &[u8],
        expected_set_root: &Sha256Digest,
        expected_seccomp_set_root: &Sha256Digest,
    ) -> Result<Self, ShadowError> {
        require(!raw.is_empty() && raw.len() <= MAX_SET_BYTES && raw.is_ascii())?;
        let wire: Wire = serde_json::from_slice(raw).map_err(unavailable)?;
        require(
            wire.api_version == SET_API
                && &wire.set_root_sha256 == expected_set_root
                && &wire.seccomp_set_root_sha256 == expected_seccomp_set_root,
        )?;

        let mut leaves = Vec::with_capacity(MEMBER_ROLES.len());
        let mut seccomp_members = Vec::with_capacity(MEMBER_ROLES.len());
        for (member, role) in wire.members.iter().zip(MEMBER_ROLES) {
            require(member.role == role)?;
            let manifest = &member.manifest;
            require(canonical_json_bytes(manifest)?.len() <= MAX_MANIFEST_BYTES)?;
            let (api, profile) = if role == "bridge" {
                (
                    "serverware.nativeCustodyExecutionClosure/v2",
                    BOOTSTRAP_PROFILE,
                )
            } else {
                ("serverware.nativeCustodyExecutionClosure/v1", PROFILE)
            };
            require(manifest.api_version == api && manifest.profile == profile)?;
            // The existing validator compiles/checks the exact seccomp policy,
            // validates build provenance and recomputes the original manifest.
            manifest.validate()?;
            leaves.push(hash_domain_frames(
                LEAF_DOMAIN,
                &[&canonical_json_bytes(&(role, manifest))?],
            ));
            seccomp_members.push((role, manifest.seccomp_policy.policy_sha256()));
        }
        require(
            wire.set_root_sha256
                == hash_domain_frames(ROOT_DOMAIN, &[&canonical_json_bytes(&leaves)?])
                && wire.seccomp_set_root_sha256
                    == hash_domain_frames(
                        SECCOMP_ROOT_DOMAIN,
                        &[&canonical_json_bytes(&seccomp_members)?],
                    ),
        )?;
        // Includes exact field spelling/order, integers, ASCII escaping and no
        // trailing LF; duplicate fields are refused by the typed deserializer.
        require(canonical_json_bytes(&wire)? == raw)?;
        Ok(Self { wire, leaves })
    }

    pub(in crate::policy_shadow) fn set_root_sha256(&self) -> &Sha256Digest {
        &self.wire.set_root_sha256
    }

    pub(in crate::policy_shadow) fn seccomp_set_root_sha256(&self) -> &Sha256Digest {
        &self.wire.seccomp_set_root_sha256
    }

    pub(in crate::policy_shadow) fn role_binding(
        &self,
        role: &str,
    ) -> Result<RoleBinding<'_>, ShadowError> {
        let index = MEMBER_ROLES
            .iter()
            .position(|expected| *expected == role)
            .ok_or(ShadowError::BindingDrift)?;
        Ok(RoleBinding {
            role: MEMBER_ROLES[index],
            set: self,
            index,
        })
    }

    /// Compare the complete selected manifest, not a caller-supplied hash DTO.
    /// This is still static membership; it never substitutes for live admission.
    pub(in crate::policy_shadow) fn require_member(
        &self,
        role: &str,
        manifest: &Manifest,
    ) -> Result<RoleBinding<'_>, ShadowError> {
        let binding = self.role_binding(role)?;
        require(binding.manifest() == manifest)?;
        Ok(binding)
    }
}

impl RoleBinding<'_> {
    pub(in crate::policy_shadow) fn role(&self) -> &'static str {
        self.role
    }

    pub(in crate::policy_shadow) fn set_root_sha256(&self) -> &Sha256Digest {
        self.set.set_root_sha256()
    }

    pub(in crate::policy_shadow) fn seccomp_set_root_sha256(&self) -> &Sha256Digest {
        self.set.seccomp_set_root_sha256()
    }

    pub(in crate::policy_shadow) fn leaf_sha256(&self) -> &Sha256Digest {
        &self.set.leaves[self.index]
    }

    pub(in crate::policy_shadow) fn manifest(&self) -> &Manifest {
        &self.set.wire.members[self.index].manifest
    }

    pub(in crate::policy_shadow) fn manifest_sha256(&self) -> &Sha256Digest {
        &self.manifest().manifest_sha256
    }

    pub(in crate::policy_shadow) fn seccomp_policy_sha256(&self) -> &Sha256Digest {
        self.manifest().seccomp_policy.policy_sha256()
    }
}
