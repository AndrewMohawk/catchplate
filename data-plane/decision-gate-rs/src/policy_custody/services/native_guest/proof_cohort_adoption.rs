//! Explicit adopted-publication endpoint cohort. The driver is logical slot 4,
//! retained by its real supervisor and never represented as an owned child.
pub(super) const CONFIG_API:&str="serverware.nativeShadowProofCohortConfiguration/v8";
pub(super) const ROLES:&[&str]=&["retrieval","persistence","trustedTime","generationInstall",
    "commitRequest","ingressAdmission","terminalAppend","dispatchBarrier","activeEffectBarrier",
    "activeEffectCommit","publicationReconciliation"];
pub(super) const ORIGINALS_API:&str="serverware.nativeShadowProofCohortOriginals/v7";
pub(super) const RELEASE_API:&str="serverware.nativeShadowProofCohortRelease/v7";
pub(super) const RELEASE_DOMAIN:&[u8]=b"serverware.nativeShadowProofCohortRelease.signature/v7\0";
pub(super) const CLEANUP_API:&str="serverware.nativeShadowProofCohortCleanup/v7";
pub(super) const CLEANUP_DOMAIN:&[u8]=b"serverware.nativeShadowProofCohortCleanup.signature/v7\0";
pub(super) const TERMINAL_API:&str="serverware.nativeShadowProofCohortTerminal/v7";
pub(super) const CLEANUP_RESULT_API:&str="serverware.nativeShadowProofCohortCleanupResult/v7";
const LEGACY_INDEX:&[usize]=&[0,1,2,3,5,6,7,8,9,10];
const ADOPTED_INDEX:&[usize]=&[0,1,2,3,5,6,7,8,9,10,11];
fn indices(adopted:bool)->&'static [usize] {if adopted{ADOPTED_INDEX}else{LEGACY_INDEX}}
pub(super) fn logical_index(owned:usize,adopted:bool)->Option<usize>{indices(adopted).get(owned).copied()}
pub(super) fn owned_index(logical:usize,adopted:bool)->Option<usize>{indices(adopted).iter().position(|v|*v==logical)}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_roster_has_no_publication_or_driver_child(){
        assert_eq!(logical_index(9,false),Some(10));
        assert_eq!(logical_index(10,false),None);
        assert_eq!(owned_index(11,false),None);
        assert_eq!(owned_index(4,false),None);
    }
    #[test]
    fn adopted_roster_is_fixed_and_bijective(){
        assert_eq!(ROLES,&["retrieval","persistence","trustedTime","generationInstall",
            "commitRequest","ingressAdmission","terminalAppend","dispatchBarrier",
            "activeEffectBarrier","activeEffectCommit","publicationReconciliation"]);
        for (owned,logical) in [0,1,2,3,5,6,7,8,9,10,11].into_iter().enumerate(){
            assert_eq!(logical_index(owned,true),Some(logical));
            assert_eq!(owned_index(logical,true),Some(owned));
        }
        assert_eq!(owned_index(4,true),None);
        assert_eq!(logical_index(11,true),None);
        assert_eq!(owned_index(12,true),None);
    }
    #[test]
    fn successor_is_explicit_and_domains_are_distinct(){
        assert_eq!(CONFIG_API,"serverware.nativeShadowProofCohortConfiguration/v8");
        assert_eq!(ORIGINALS_API,"serverware.nativeShadowProofCohortOriginals/v7");
        assert_eq!(RELEASE_API,"serverware.nativeShadowProofCohortRelease/v7");
        assert_eq!(CLEANUP_API,"serverware.nativeShadowProofCohortCleanup/v7");
        assert_eq!(TERMINAL_API,"serverware.nativeShadowProofCohortTerminal/v7");
        assert_eq!(CLEANUP_RESULT_API,"serverware.nativeShadowProofCohortCleanupResult/v7");
        assert_eq!(RELEASE_DOMAIN,b"serverware.nativeShadowProofCohortRelease.signature/v7\0");
        assert_eq!(CLEANUP_DOMAIN,b"serverware.nativeShadowProofCohortCleanup.signature/v7\0");
        assert_ne!(RELEASE_DOMAIN,CLEANUP_DOMAIN);
    }
}
