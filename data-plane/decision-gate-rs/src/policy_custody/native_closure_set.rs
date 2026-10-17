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

const SET_API: &str = "catchplate.nativeCustodyExecutionClosureSet/v1";
const PUBLICATION_API: &str = "catchplate.nativeCustodyExecutionClosureSet/v2";
pub(in crate::policy_shadow) const PUBLICATION_ROLES: [&str; 12] = [
    "retrieval", "persistence", "trustedTime", "generationInstall", "commitRequest",
    "ingressAdmission", "terminalAppend", "dispatchBarrier", "activeEffectBarrier",
    "activeEffectCommit", "publicationReconciliation", "bridge",
];
const GENESIS_API: &str = "catchplate.nativePublicationGenesisClosureSet/v1";
const GENESIS_BOOTSTRAP_API: &str = "catchplate.nativePublicationGenesisClosureSet/v2";
pub(in crate::policy_shadow) const GENESIS_ROLES: [&str;3] = [
    "publicationGenesisRetrieval", "publicationGenesis", "publicationGenesisCoordinator"];
const LEAF_DOMAIN: &[u8] = b"catchplate.nativeCustodyExecutionClosureSetLeaf/v1";
const ROOT_DOMAIN: &[u8] = b"catchplate.nativeCustodyExecutionClosureSetRoot/v1";
const SECCOMP_ROOT_DOMAIN: &[u8] = b"catchplate.nativeCustodySeccompSetRoot/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetProfile { Legacy, Genesis, GenesisBootstrap, Publication }
impl SetProfile {
    fn roles(self) -> &'static [&'static str] { match self {
        Self::Legacy => &MEMBER_ROLES, Self::Genesis | Self::GenesisBootstrap => &GENESIS_ROLES,
        Self::Publication => &PUBLICATION_ROLES,
    } }
    fn api(self) -> &'static str { match self {
        Self::Legacy => SET_API, Self::Genesis => GENESIS_API, Self::GenesisBootstrap => GENESIS_BOOTSTRAP_API,
        Self::Publication => PUBLICATION_API,
    } }
    fn leaf_domain(self) -> &'static [u8] { match self {
        Self::Legacy => LEAF_DOMAIN, Self::Genesis => b"catchplate.nativePublicationGenesisClosureSetLeaf/v1",
        Self::GenesisBootstrap => b"catchplate.nativePublicationGenesisClosureSetLeaf/v2",
        Self::Publication => b"catchplate.nativeCustodyExecutionClosureSetLeaf/v2",
    } }
    fn root_domain(self) -> &'static [u8] { match self {
        Self::Legacy => ROOT_DOMAIN, Self::Genesis => b"catchplate.nativePublicationGenesisClosureSetRoot/v1",
        Self::GenesisBootstrap => b"catchplate.nativePublicationGenesisClosureSetRoot/v2",
        Self::Publication => b"catchplate.nativeCustodyExecutionClosureSetRoot/v2",
    } }
    fn seccomp_domain(self) -> &'static [u8] { match self {
        Self::Legacy => SECCOMP_ROOT_DOMAIN, Self::Genesis => b"catchplate.nativePublicationGenesisSeccompSetRoot/v1",
        Self::GenesisBootstrap => b"catchplate.nativePublicationGenesisSeccompSetRoot/v2",
        Self::Publication => b"catchplate.nativeCustodySeccompSetRoot/v2",
    } }
    fn manifest_profile(self, role: &str) -> (&'static str, &'static str) {
        if role == "bridge" || (self == Self::GenesisBootstrap && role == "publicationGenesisCoordinator") {
            ("catchplate.nativeCustodyExecutionClosure/v2", BOOTSTRAP_PROFILE)
        } else {
            ("catchplate.nativeCustodyExecutionClosure/v1", PROFILE)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Member {
    role: String,
    manifest: Manifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Wire {
    api_version: String,
    members: Vec<Member>,
    set_root_sha256: Sha256Digest,
    seccomp_set_root_sha256: Sha256Digest,
}

/// Static validation result with no deserialization or live-owner constructor.
/// Its roots are useful only under an independently authorized caller contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::policy_shadow) struct ValidatedSet {
    wire: Wire,
    leaves: Vec<Sha256Digest>,
    profile: SetProfile,
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
        Self::selected(raw,expected_set_root,expected_seccomp_set_root,SetProfile::Legacy)
    }
    pub(in crate::policy_shadow) fn from_genesis_bytes(raw:&[u8],expected_set_root:&Sha256Digest,
        expected_seccomp_set_root:&Sha256Digest)->Result<Self,ShadowError>{
        Self::selected(raw,expected_set_root,expected_seccomp_set_root,SetProfile::Genesis)
    }
    pub(in crate::policy_shadow) fn from_genesis_bootstrap_bytes(raw:&[u8],expected_set_root:&Sha256Digest,
        expected_seccomp_set_root:&Sha256Digest)->Result<Self,ShadowError>{
        Self::selected(raw,expected_set_root,expected_seccomp_set_root,SetProfile::GenesisBootstrap)
    }
    pub(in crate::policy_shadow) fn from_publication_bytes(raw:&[u8],expected_set_root:&Sha256Digest,
        expected_seccomp_set_root:&Sha256Digest)->Result<Self,ShadowError>{
        Self::selected(raw,expected_set_root,expected_seccomp_set_root,SetProfile::Publication)
    }
    fn selected(raw:&[u8],expected_set_root:&Sha256Digest,expected_seccomp_set_root:&Sha256Digest,
        profile:SetProfile)->Result<Self,ShadowError>{
        require(!raw.is_empty() && raw.len() <= MAX_SET_BYTES && raw.is_ascii())?;
        let wire: Wire = serde_json::from_slice(raw).map_err(unavailable)?;
        let roles=profile.roles();
        require(
            wire.api_version == profile.api()
                && wire.members.len()==roles.len()
                && &wire.set_root_sha256 == expected_set_root
                && &wire.seccomp_set_root_sha256 == expected_seccomp_set_root,
        )?;

        let mut leaves = Vec::with_capacity(roles.len());
        let mut seccomp_members = Vec::with_capacity(roles.len());
        for (member, &role) in wire.members.iter().zip(roles) {
            require(member.role == role)?;
            let manifest = &member.manifest;
            require(canonical_json_bytes(manifest)?.len() <= MAX_MANIFEST_BYTES)?;
            let (api, manifest_profile) = profile.manifest_profile(role);
            require(manifest.api_version == api && manifest.profile == manifest_profile)?;
            // The existing validator compiles/checks the exact seccomp policy,
            // validates build provenance and recomputes the original manifest.
            manifest.validate()?;
            leaves.push(hash_domain_frames(
                profile.leaf_domain(),
                &[&canonical_json_bytes(&(role, manifest))?],
            ));
            seccomp_members.push((role, manifest.seccomp_policy.policy_sha256()));
        }
        require(
            wire.set_root_sha256
                == hash_domain_frames(profile.root_domain(), &[&canonical_json_bytes(&leaves)?])
                && wire.seccomp_set_root_sha256
                    == hash_domain_frames(
                        profile.seccomp_domain(),
                        &[&canonical_json_bytes(&seccomp_members)?],
                    ),
        )?;
        // Includes exact field spelling/order, integers, ASCII escaping and no
        // trailing LF; duplicate fields are refused by the typed deserializer.
        require(canonical_json_bytes(&wire)? == raw)?;
        Ok(Self { wire, leaves, profile })
    }
    pub(in crate::policy_shadow) fn genesis(&self)->bool{
        matches!(self.profile,SetProfile::Genesis|SetProfile::GenesisBootstrap)
    }
    pub(in crate::policy_shadow) fn genesis_bootstrap(&self)->bool{self.profile==SetProfile::GenesisBootstrap}
    pub(in crate::policy_shadow) fn publication(&self)->bool{self.profile==SetProfile::Publication}
    pub(in crate::policy_shadow) fn authority_role(&self)->&'static str{
        if self.genesis(){"publicationGenesisCoordinator"}else{"bridge"}
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
        let roles=self.profile.roles();
        let index = roles
            .iter()
            .position(|expected| *expected == role)
            .ok_or(ShadowError::BindingDrift)?;
        Ok(RoleBinding {
            role: roles[index],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_bootstrap_has_distinct_commitment_domains(){
        let old=SetProfile::Genesis;let new=SetProfile::GenesisBootstrap;
        assert_eq!(old.roles(),new.roles());
        assert_ne!(old.api(),new.api());
        assert_ne!(old.leaf_domain(),new.leaf_domain());
        assert_ne!(old.root_domain(),new.root_domain());
        assert_ne!(old.seccomp_domain(),new.seccomp_domain());
        let frames=[b"same-independent-static-data".as_slice()];
        assert_ne!(hash_domain_frames(old.root_domain(),&frames),hash_domain_frames(new.root_domain(),&frames));
    }
    #[test]
    fn only_successor_coordinator_uses_measured_bootstrap(){
        let immutable=("catchplate.nativeCustodyExecutionClosure/v1",PROFILE);
        let measured=("catchplate.nativeCustodyExecutionClosure/v2",BOOTSTRAP_PROFILE);
        for role in GENESIS_ROLES {
            assert_eq!(SetProfile::Genesis.manifest_profile(role),immutable);
            assert_eq!(SetProfile::GenesisBootstrap.manifest_profile(role),
                if role=="publicationGenesisCoordinator"{measured}else{immutable});
        }
        assert_eq!(SetProfile::Legacy.manifest_profile("bridge"),measured);
        assert_eq!(SetProfile::Publication.manifest_profile("bridge"),measured);
        assert_eq!(SetProfile::Publication.manifest_profile("publicationReconciliation"),immutable);
    }
}
