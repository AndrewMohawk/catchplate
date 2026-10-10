//! Local synthetic files only. No provider, running gate, or process-env mutation.
use super::*;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "operator-publication-test-{}-{}-{}",
            std::process::id(),
            super::super::now_epoch_ms(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn policy(&self) -> PathBuf {
        self.0.join("policy-bundle.json")
    }
    fn lock(&self) -> PathBuf {
        self.0.join(LOCK_NAME)
    }
    fn provision(&self) {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.lock())
            .unwrap();
        file.sync_all().unwrap();
    }
    fn owner(&self) -> Owner {
        self.provision();
        Owner::open(&self.policy()).unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned publication test scratch");
    }
}

fn exclusive(file: &File) -> bool {
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

#[test]
fn publication_missing_inode_is_never_created_by_rust() {
    let scratch = Scratch::new();
    assert!(Owner::open(&scratch.policy()).is_err());
    assert!(!scratch.lock().exists());
}

#[test]
fn publication_valid_shared_guard_excludes_writer_until_drop() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let writer = Owner::open_file(&scratch.lock()).unwrap();
    let permit = owner.acquire(deadline()).unwrap();
    assert!(permit.check().is_ok());
    assert!(!exclusive(&writer));
    drop(permit);
    assert!(exclusive(&writer));
}

#[test]
fn publication_independent_shared_descriptors_cannot_unlock_each_other() {
    let scratch = Scratch::new();
    let first = scratch.owner();
    let second = Owner::open(&scratch.policy()).unwrap();
    let writer = Owner::open_file(&scratch.lock()).unwrap();
    let first_permit = first.acquire(deadline()).unwrap();
    let second_permit = second.acquire(deadline()).unwrap();
    drop(first_permit);
    assert!(!exclusive(&writer));
    drop(second_permit);
    assert!(exclusive(&writer));
}

#[test]
fn publication_shared_acquisition_respects_original_deadline() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let writer = Owner::open_file(&scratch.lock()).unwrap();
    assert!(exclusive(&writer));
    let original = Instant::now() + Duration::from_millis(20);
    assert!(owner.acquire(original).is_err());
    assert!(remaining(original).is_err());
    drop(writer);
    assert!(owner.acquire(deadline()).is_ok());
}

#[test]
fn publication_local_serialization_uses_same_original_deadline() {
    let scratch = Scratch::new();
    let owner = Arc::new(scratch.owner());
    let held = owner.acquire(deadline()).unwrap();
    let other = Arc::clone(&owner);
    let waiting = std::thread::spawn(move || {
        other
            .acquire(Instant::now() + Duration::from_millis(20))
            .is_err()
    });
    assert!(waiting.join().unwrap());
    drop(held);
    assert!(owner.acquire(deadline()).is_ok());
}

#[test]
fn publication_already_expired_deadline_never_acquires() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    assert!(owner
        .acquire(Instant::now() - Duration::from_secs(1))
        .is_err());
}

#[test]
fn publication_completion_rechecks_deadline() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let mut permit = owner.acquire(deadline()).unwrap();
    permit.deadline = Instant::now() - Duration::from_secs(1);
    assert!(permit.check().is_err());
}

#[test]
fn publication_credential_preserves_original_operation_deadline() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    // Neither a shorter operation nor one longer than the acquisition cap may
    // acquire a freshly armed or acquisition-only completion deadline.
    for budget in [ACQUISITION_BUDGET / 2, ACQUISITION_BUDGET * 2] {
        let original = Instant::now() + budget;
        let permit = owner.acquire_credential(original).unwrap();
        assert_eq!(permit.deadline(), original);
        assert!(permit.check().is_ok());
    }
}

#[test]
fn publication_credential_and_audit_lanes_independently_exclude_writer() {
    // Exercise both release orders on one Owner, not two owners that could
    // conceal accidental sharing of the same local lane.
    for credential_first in [false, true] {
        let scratch = Scratch::new();
        let owner = Arc::new(scratch.owner());
        let writer = Owner::open_file(&scratch.lock()).unwrap();
        let original = Instant::now() + Duration::from_secs(10);
        let first = if credential_first {
            owner.acquire_credential(original).unwrap()
        } else {
            owner.acquire(original).unwrap()
        };
        let first_fd = first.descriptor.as_raw_fd();
        let first_metadata = first.descriptor.metadata().unwrap();
        let other = Arc::clone(&owner);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let waiting = std::thread::spawn(move || {
            let second = if credential_first {
                other.acquire(original).unwrap()
            } else {
                other.acquire_credential(original).unwrap()
            };
            let metadata = second.descriptor.metadata().unwrap();
            ready_tx
                .send((
                    second.descriptor.as_raw_fd(),
                    metadata.dev(),
                    metadata.ino(),
                    second.deadline(),
                ))
                .unwrap();
            let released = release_rx.recv_timeout(Duration::from_secs(2)).is_ok();
            let current = second.check().is_ok();
            drop(second);
            (released, current)
        });

        let ready = ready_rx.recv_timeout(Duration::from_secs(2));
        let both_exclude_writer = ready.is_ok() && !exclusive(&writer);
        drop(first);
        let second_alone_excludes_writer = ready.is_ok() && !exclusive(&writer);
        // Release and join before asserting so a failed coexistence check
        // cannot strand a worker holding a permit or its scratch directory.
        let _ = release_tx.send(());
        let completed = waiting.join();
        let (second_fd, device, inode, retained_deadline) = ready.unwrap();
        assert_ne!(first_fd, second_fd);
        assert_eq!(first_metadata.dev(), owner.identity.device);
        assert_eq!(first_metadata.ino(), owner.identity.inode);
        assert_eq!(device, owner.identity.device);
        assert_eq!(inode, owner.identity.inode);
        assert_eq!(retained_deadline, original);
        assert!(both_exclude_writer);
        assert!(second_alone_excludes_writer);
        assert_eq!(completed.unwrap(), (true, true));
        assert!(exclusive(&writer));
    }
}

#[test]
fn publication_credential_contended_acquisition_keeps_short_original_deadline() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let writer = Owner::open_file(&scratch.lock()).unwrap();
    assert!(exclusive(&writer));
    let original = Instant::now() + Duration::from_millis(20);
    assert_eq!(
        owner.acquire_credential(original).err().unwrap(),
        "operator publication coordination deadline expired"
    );
    assert!(remaining(original).is_err());
    drop(writer);
    assert!(owner.acquire_credential(deadline()).is_ok());
}

#[test]
fn publication_credential_expired_acquisition_or_operation_is_refused() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let expired = Instant::now() - Duration::from_secs(1);
    let live = Instant::now() + Duration::from_secs(10);
    assert_eq!(
        owner.acquire_credential(expired).err().unwrap(),
        "operator publication coordination deadline expired"
    );
    // Exercise the two independently supplied deadlines without a five-second
    // test delay. A live operation cannot rescue expired acquisition, and a
    // live acquisition cannot rearm an already expired operation.
    for (acquisition, operation) in [(expired, live), (live, expired)] {
        assert_eq!(
            owner
                .acquire_in_lane(&owner.credential_serial, acquisition, operation)
                .err()
                .unwrap(),
            "operator publication coordination deadline expired"
        );
        let writer = Owner::open_file(&scratch.lock()).unwrap();
        assert!(exclusive(&writer));
    }
    assert!(owner.acquire_credential(live).is_ok());
}

#[test]
fn publication_credential_completion_rechecks_operation_deadline() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let mut permit = owner.acquire_credential(deadline()).unwrap();
    permit.deadline = Instant::now() - Duration::from_secs(1);
    assert_eq!(
        permit.check().err().unwrap(),
        "operator publication coordination deadline expired"
    );
}

#[test]
fn publication_credential_replaced_inode_refused_during_acquisition() {
    let scratch = Scratch::new();
    let path = scratch.lock();
    let retained = scratch.0.join("retained-old-lock");
    let owner = scratch.owner().with_test_hook(Arc::new(move |phase| {
        if phase == TestPhase::BeforeSharedLock {
            // The credential descriptor is already open. Substitution must
            // still fail, rather than adopting the replacement path or inode.
            fs::rename(&path, &retained).unwrap();
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap()
                .sync_all()
                .unwrap();
        }
    }));
    assert_eq!(
        owner.acquire_credential(deadline()).err().unwrap(),
        "operator publication coordination refused"
    );
    // Subsequent acquisition cannot adopt the substituted path either.
    assert!(owner.acquire_credential(deadline()).is_err());
    let old_writer = Owner::open_file(&scratch.0.join("retained-old-lock")).unwrap();
    assert!(exclusive(&old_writer));
}

#[test]
fn publication_credential_replaced_inode_refused_before_completion() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let old_writer = Owner::open_file(&scratch.lock()).unwrap();
    let permit = owner.acquire_credential(deadline()).unwrap();
    fs::rename(scratch.lock(), scratch.0.join("retained-old-lock")).unwrap();
    scratch.provision();
    assert_eq!(
        permit.check().err().unwrap(),
        "operator publication coordination refused"
    );
    assert!(!exclusive(&old_writer));
    drop(permit);
    assert!(exclusive(&old_writer));
}

#[test]
fn publication_replaced_inode_refused_before_acquisition() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    fs::rename(scratch.lock(), scratch.0.join("retained-old-lock")).unwrap();
    scratch.provision();
    assert!(owner.acquire(deadline()).is_err());
}

#[test]
fn publication_replaced_inode_refused_before_success() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let permit = owner.acquire(deadline()).unwrap();
    fs::rename(scratch.lock(), scratch.0.join("retained-old-lock")).unwrap();
    scratch.provision();
    assert!(permit.check().is_err());
}

#[test]
fn publication_changed_metadata_refused_before_success() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let permit = owner.acquire(deadline()).unwrap();
    fs::set_permissions(scratch.lock(), fs::Permissions::from_mode(0o640)).unwrap();
    assert!(permit.check().is_err());
}

#[test]
fn publication_symlink_hardlink_and_content_are_refused() {
    let scratch = Scratch::new();
    let target = scratch.0.join("target");
    fs::write(&target, []).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, scratch.lock()).unwrap();
    assert!(Owner::open(&scratch.policy()).is_err());
    fs::remove_file(scratch.lock()).unwrap();
    fs::hard_link(&target, scratch.lock()).unwrap();
    assert!(Owner::open(&scratch.policy()).is_err());
    fs::remove_file(scratch.lock()).unwrap();
    fs::remove_file(&target).unwrap();
    scratch.provision();
    fs::write(scratch.lock(), b"not an empty lock inode").unwrap();
    assert!(Owner::open(&scratch.policy()).is_err());
}

#[test]
fn publication_fifo_and_directory_are_refused_without_blocking_open() {
    let scratch = Scratch::new();
    let path = CString::new(scratch.lock().as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(Owner::open(&scratch.policy()).is_err());
    fs::remove_file(scratch.lock()).unwrap();
    fs::create_dir(scratch.lock()).unwrap();
    fs::set_permissions(scratch.lock(), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Owner::open(&scratch.policy()).is_err());
    fs::set_permissions(scratch.lock(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn publication_nonprivate_or_symlink_parent_is_refused() {
    let scratch = Scratch::new();
    scratch.provision();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(Owner::open(&scratch.policy()).is_err());
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = scratch.0.join("alias");
    symlink(&scratch.0, &alias).unwrap();
    assert!(Owner::open(&alias.join("policy-bundle.json")).is_err());
}

#[test]
fn publication_deleted_inode_cannot_be_recreated_on_acquire() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    fs::remove_file(scratch.lock()).unwrap();
    assert!(owner.acquire(deadline()).is_err());
    assert!(!scratch.lock().exists());
}

#[test]
fn publication_guard_is_not_admitted_to_ordinary_or_production_state() {
    let scratch = Scratch::new();
    let owner = Arc::new(scratch.owner());
    let mut state = crate::tests::test_gate_state(crate::tests::test_snapshot(1));
    assert!(acquire(&state).unwrap().is_none());
    state.operator_audit_publication = Some(Arc::clone(&owner));
    assert!(acquire(&state).is_err());
    state.is_production = true;
    assert!(acquire(&state).is_err());
    state.operator_audit_publication = None;
    assert!(acquire(&state).unwrap().is_none());
}

#[test]
fn publication_unheld_permit_cannot_enter_guarded_refresh() {
    let scratch = Scratch::new();
    let owner = scratch.owner();
    let state = crate::tests::test_gate_state(crate::tests::test_snapshot(1));
    let permit = owner.acquire(deadline()).unwrap();
    assert!(require_permit(&state, Some(&permit)).is_err());
}

fn external_verifier_source() -> PolicyTrustRootSource {
    PolicyTrustRootSource::AttestedControlPlane {
        url: "not-a-transport-url".to_owned(),
        expected_quote_key_id: None,
        verifier: Some(crate::ControlPlaneAttestationVerifier::Development(
            "never-execute-this-synthetic-command".to_owned(),
        )),
        native_transport: None,
    }
}

#[test]
fn publication_operator_external_verifier_is_explicitly_refused() {
    let source = external_verifier_source();
    let error = require_local_verifier(&source).unwrap_err();
    assert_eq!(
        error,
        "operator publication does not admit external attestation verifiers"
    );
    assert!(!error.contains("never-execute"));
    let in_process = PolicyTrustRootSource::AttestedControlPlane {
        url: "not-a-transport-url".to_owned(),
        expected_quote_key_id: None,
        verifier: None,
        native_transport: None,
    };
    assert!(require_local_verifier(&in_process).is_ok());
}

#[test]
fn publication_deadline_trust_fetch_refuses_external_verifier_before_transport() {
    let PolicyTrustRootSource::AttestedControlPlane {
        url,
        expected_quote_key_id,
        verifier,
        ..
    } = external_verifier_source()
    else {
        unreachable!()
    };
    let result = crate::fetch_attested_policy_trust_root(
        &url,
        &expected_quote_key_id,
        &verifier,
        None,
        Some(deadline()),
    );
    assert!(
        matches!(result, Err(error) if error == "operator publication does not admit external attestation verifiers")
    );
}

#[test]
fn publication_external_verifier_selection_does_not_change_other_profiles() {
    let mut state = crate::tests::test_gate_state(crate::tests::test_snapshot(1));
    state.policy_trust_root_source = external_verifier_source();
    assert!(acquire(&state).unwrap().is_none());
    assert!(require_permit(&state, None).unwrap().is_none());
    state.is_production = true;
    assert!(acquire(&state).unwrap().is_none());
    assert!(require_permit(&state, None).unwrap().is_none());
}

#[test]
fn publication_source_keeps_startup_sync_post_verifier_and_final_check_order() {
    let source = include_str!("main.rs");
    let post = source
        .split("fn post_serialized_legacy_audit_batch(")
        .nth(1)
        .unwrap()
        .split("fn flush_audit_batch(")
        .next()
        .unwrap();
    let guard = post
        .find("operator_audit_publication::acquire(state)")
        .unwrap();
    let sync = post
        .find("refresh_policy_snapshot_guarded(state, true, Some(permit))")
        .unwrap();
    let capture = post.find("let snapshot = current_snapshot(state)").unwrap();
    let execute = post.find("client.execute(request)").unwrap();
    let verify = post.find("verify_control_plane_signed_response(").unwrap();
    let completion = post.rfind("permit.check()").unwrap();
    assert!(
        guard < sync
            && sync < capture
            && capture < execute
            && execute < verify
            && verify < completion
    );
    assert!(post.contains(".min(Duration::from_secs(2))"));
    let startup = source
        .split("fn main() -> Result<(), String>")
        .nth(1)
        .unwrap();
    assert!(
        startup
            .find("operator_audit_publication::require_local_verifier(&policy_trust_root_source)")
            .unwrap()
            < startup
                .find("operator_audit_publication::Owner::open")
                .unwrap()
    );
    assert!(
        startup
            .find("owner.acquire(operator_audit_publication::deadline())")
            .unwrap()
            < startup
                .find("let mut initial_snapshot = load_snapshot_on_deadline")
                .unwrap()
    );
    assert!(
        startup.find("selection.admit(&initialized_state)").unwrap()
            < startup.find("drop(operator_startup_guard)").unwrap()
    );
}
