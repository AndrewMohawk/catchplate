//! Native immutable closure authority. No quote, role key, readiness or
//! settlement is manufactured here. Legacy IMA/fs-verity profiles stay distinct.
use super::*;
use policy_custody::{GuestClosureAssociation,GuestClosureBinding};
use serverware_decision_gate::native_secret_broker_v1::shadow_image::ShadowImage;
use std::fs::File;
use std::os::fd::{AsRawFd,BorrowedFd};
use std::os::unix::fs::{FileExt,MetadataExt};

const PROFILE:&str="sealed-memfd-squashfs-static-amd64-v1";
const BOOTSTRAP_PROFILE:&str="measured-bootstrap-late-runtime-static-amd64-v1";
#[path="native_closure_late.rs"] mod late;
#[path="native_closure_remote.rs"] mod remote;
pub(in crate::policy_shadow) use remote::RemoteNativeCustodyClosure;
const DOMAIN:&str="serverware.nativeCustodyClosureAssignment.signature/v1";
const MANIFEST_DOMAIN:&[u8]=b"serverware.nativeCustodyExecutionClosure/v1";
const ALL_SEALS:i32=libc::F_SEAL_WRITE|libc::F_SEAL_GROW|libc::F_SEAL_SHRINK|libc::F_SEAL_SEAL;
fn unavailable<T>(_:T)->ShadowError {ShadowError::CustodyUnavailable}
fn require(value:bool)->Result<(),ShadowError> {if value {Ok(())} else {Err(ShadowError::BindingDrift)}}

#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow) struct Manifest {
    api_version:String,profile:String,image_sha256:Sha256Digest,worker_executable_sha256:Sha256Digest,
    seccomp_policy:StructurallyVerifiedCustodySeccompPolicy,runtime_configuration_sha256:Sha256Digest,
    build_provenance:ProductionCustodyBuildProvenance,manifest_sha256:Sha256Digest,
}
impl Manifest {
    fn validate(&self)->Result<(),ShadowError> {
        let domain=match (self.api_version.as_str(),self.profile.as_str()) {
            ("serverware.nativeCustodyExecutionClosure/v1",PROFILE)=>MANIFEST_DOMAIN,
            ("serverware.nativeCustodyExecutionClosure/v2",BOOTSTRAP_PROFILE)=>b"serverware.nativeCustodyExecutionClosure/v2".as_slice(),
            _=>return Err(ShadowError::BindingDrift),
        };
        require(cfg!(target_arch="x86_64")
            && self.seccomp_policy.architecture==ProductionCustodySeccompArchitecture::X86_64)?;
        self.build_provenance.validate()?;self.seccomp_policy.validate()?;
        require(self.manifest_sha256==hash_domain_frames(domain,&[&canonical_json_bytes(&(
            &self.api_version,&self.profile,&self.image_sha256,&self.worker_executable_sha256,
            &self.seccomp_policy,&self.runtime_configuration_sha256,&self.build_provenance))?]))
    }
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct AssignmentPayload {
    api_version:String,purpose:String,profile:String,assignment_id:Sha256Digest,
    assignment_payload_sha256:Sha256Digest,assignment_revision:u64,manifest_sha256:Sha256Digest,
    guest:GuestClosureBinding,trust_checkpoint_id:Sha256Digest,revocation_generation:u64,
    revocation_root_sha256:Sha256Digest,issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,
    signing_key_id:Sha256Digest,signing_key_spki_sha256:Sha256Digest,
}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Assignment {payload:AssignmentPayload,signature:CanonicalEd25519Signature}
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(in crate::policy_shadow) struct Configuration {api_version:String,manifest:Manifest,authorization:Assignment}

impl Configuration {
    fn require_legacy(&self)->Result<(),ShadowError>{
        require(self.api_version=="serverware.nativeCustodyClosure/v1"
            && self.manifest.api_version=="serverware.nativeCustodyExecutionClosure/v1"
            && self.manifest.profile==PROFILE)?;self.manifest.validate()
    }
    pub(in crate::policy_shadow) fn require_pair_image(&self,image:&Sha256Digest,executable:&Sha256Digest)->Result<(),ShadowError> {
        self.require_legacy()?;
        require(&self.manifest.image_sha256==image && &self.manifest.worker_executable_sha256==executable)
    }
    /// Root parent cold-original selection only. The child independently
    /// verifies the NEW closure signature after genuine trusted-time delivery.
    /// No native assignment/TEE authority is returned by this image mechanism.
    pub(in crate::policy_shadow) fn prepare_parent_image(&self,
        delivery:&policy_custody::services::guest::FileAdmission)->Result<ShadowImage,ShadowError> {
        delivery.check_preparation().map_err(unavailable)?;
        self.require_legacy()?;
        let m=&self.manifest;let b=&m.build_provenance;
        require(&m.runtime_configuration_sha256==delivery.runtime_sha256())?;
        let image=ShadowImage::open(m.image_sha256.as_str(),m.worker_executable_sha256.as_str(),[
            m.seccomp_policy.raw_bpf_sha256().as_str(),m.runtime_configuration_sha256.as_str(),
            b.dependency_lock_sha256.as_str(),b.build_recipe_sha256.as_str(),b.provenance_statement_sha256.as_str()],
            delivery.startup()).map_err(unavailable)?;
        require(read(image.seccomp(),32768)?==custody_seccomp_raw_bytes(m.seccomp_policy.exact_instructions()))?;
        delivery.check_preparation().map_err(unavailable)?;Ok(image)
    }
}

fn verify_assignment(wire:&Assignment,manifest:&Manifest,guest:&GuestClosureBinding,
    assignment:&VerifiedAssignment,checkpoint:&AtomicTrustCheckpoint,trust:&dyn EnvelopeKeyTrust)->Result<(),ShadowError> {
    let p=&wire.payload;let original=assignment.payload();
    let domain=if manifest.profile==BOOTSTRAP_PROFILE {
        require(p.api_version=="serverware.nativeCustodyClosureAssignment/v2"
            && p.purpose=="shadow-custody-bootstrap-late-runtime" && p.profile==BOOTSTRAP_PROFILE)?;
        "serverware.nativeCustodyClosureAssignment.signature/v2"
    } else {
        require(p.api_version=="serverware.nativeCustodyClosureAssignment/v1"
            && p.purpose=="shadow-custody-execution-closure" && p.profile==PROFILE
            && guest.runtime_configuration_sha256==manifest.runtime_configuration_sha256)?;
        DOMAIN
    };
    require(p.assignment_id==original.assignment_id
        && p.assignment_payload_sha256==*assignment.payload_sha256() && p.assignment_revision==original.assignment_revision
        && p.manifest_sha256==manifest.manifest_sha256 && &p.guest==guest)?;
    require(matches!(&original.custody_authority.attestation_mode,
        CustodyAttestationMode::Tee {platform:TeePlatform::AwsNitroEnclave,..})
        && original.custody_authority.execution_closure_manifest_sha256==manifest.manifest_sha256
        && original.custody_authority.structurally_verified_seccomp_policy_sha256==*manifest.seccomp_policy.policy_sha256())?;
    // Validate interval shape here. Freshness separately uses actual TrustedTime,
    // never the (potentially older) current checkpoint's as-of time.
    validate_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,p.issued_at_unix_nanos,MAX_ENVELOPE_AGE_NANOS)?;
    let binding=original.authority_key_independence.binding(AuthorityRole::CustodySupervisorCapability,&original.assignment_id)?;
    require(p.signing_key_id==binding.key_id && p.signing_key_spki_sha256==binding.key_spki_sha256)?;
    // Role/current-key resolution and NEW purpose signature are both mandatory.
    // Ordinary supervisor-capability signatures cannot verify this preimage.
    let key=trust.resolve_ed25519_key(checkpoint,authority_role_signature_domain(AuthorityRole::CustodySupervisorCapability),
        &binding.key_id,&binding.key_spki_sha256)?;
    require(ed25519_public_key_material_sha256(&key)==binding.key_material_sha256)?;
    key.verify_strict(&signature_preimage(domain,&canonical_json_bytes(p)?),&Signature::from_bytes(&wire.signature.decode()?))
        .map_err(|_|ShadowError::SignatureInvalid)?;
    require(trust.current_checkpoint()?==*checkpoint)
}

fn read(file:&File,maximum:u64)->Result<Vec<u8>,ShadowError> {
    let size=file.metadata().map_err(unavailable)?.len();
    require(size>0 && size<=maximum)?;
    let mut bytes=vec![0;size as usize];let mut offset=0;
    while offset<bytes.len() {
        let n=file.read_at(&mut bytes[offset..],offset as u64).map_err(unavailable)?;
        require(n>0)?;offset+=n;
    }
    Ok(bytes)
}
#[derive(PartialEq,Eq)]
struct ExecutableIdentity {device:u64,inode:u64,size:u64,mode:u32,uid:u32,gid:u32}
fn executable_identity(file:&File)->Result<ExecutableIdentity,ShadowError> {
    let m=file.metadata().map_err(unavailable)?;
    let mut fs:libc::statfs=unsafe {std::mem::zeroed()};
    require(m.is_file() && m.nlink()==0 && m.uid()==0 && m.gid()==0 && m.mode()&0o7777==0o500
        && unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)}==ALL_SEALS
        && unsafe {libc::fstatfs(file.as_raw_fd(),&mut fs)}==0 && fs.f_type==0x0102_1994)?;
    Ok(ExecutableIdentity {device:m.dev(),inode:m.ino(),size:m.len(),mode:m.mode(),uid:m.uid(),gid:m.gid()})
}
fn status_number(label:&str)->Result<u64,ShadowError> {
    let status=std::fs::read_to_string("/proc/thread-self/status").map_err(unavailable)?;
    let values:Vec<_>=status.lines().filter_map(|v|v.strip_prefix(label)).collect();
    require(values.len()==1)?;values[0].trim().parse().map_err(unavailable)
}
fn check_current_executable(original:&ExecutableIdentity)->Result<(),ShadowError> {
    // After permanent drop the root:root0500 executable cannot be reopened
    // for content. Stat the kernel magic link and join the SAME retained FD.
    let same=||->Result<(),ShadowError> {
        let m=std::fs::metadata("/proc/self/exe").map_err(unavailable)?;
        require(m.is_file() && m.nlink()==0 && (m.dev(),m.ino(),m.len(),m.mode(),m.uid(),m.gid())
            ==(original.device,original.inode,original.size,original.mode,original.uid,original.gid))
    };
    same()?;
    let maps=std::fs::read_to_string("/proc/self/maps").map_err(unavailable)?;
    for line in maps.lines() {
        let f:Vec<_>=line.split_whitespace().collect();require(f.len()>=5)?;
        if f[1].as_bytes().get(2)!=Some(&b'x') {continue;}
        if f.len()==6 && matches!(f[5],"[vdso]"|"[vsyscall]") {continue;}
        let (major,minor)=f[3].split_once(':').ok_or(ShadowError::BindingDrift)?;
        let device=libc::makedev(u32::from_str_radix(major,16).map_err(unavailable)?,u32::from_str_radix(minor,16).map_err(unavailable)?);
        require(device==original.device && f[4].parse::<u64>().map_err(unavailable)?==original.inode)?;
    }
    same()
}
fn check_root(image:&ShadowImage)->Result<(),ShadowError> {
    let root=File::open("/").map_err(unavailable)?;let m=root.metadata().map_err(unavailable)?;
    let mut original:libc::stat=unsafe {std::mem::zeroed()};
    require(unsafe {libc::fstat(image.root().as_raw_fd(),&mut original)}==0
        && m.dev()==original.st_dev && m.ino()==original.st_ino)
}

/// Pre-key consistency with an independently protected cold original only.
/// This is not the epoch-dependent closure assignment or an installed image.
/// The later full closure constructor still verifies all authority and bytes.
pub(in crate::policy_shadow) struct PrekeyExecutable {
    executable:File,identity:ExecutableIdentity,association:GuestClosureAssociation,
}
impl PrekeyExecutable {
    pub(in crate::policy_shadow) fn open(configuration:&Configuration,delivery:&PreparedGuestServiceDelivery)
        ->Result<Self,ShadowError> {
        let association=delivery.closure_association().map_err(unavailable)?;
        association.check_preparation().map_err(unavailable)?;
        configuration.require_legacy()?;
        require(configuration.manifest.runtime_configuration_sha256==association.binding().runtime_configuration_sha256)?;
        let executable=File::open("/proc/self/exe").map_err(unavailable)?;
        let identity=executable_identity(&executable)?;
        let bytes=read(&executable,128*1024*1024)?;
        require(Sha256Digest::compute(&bytes)==configuration.manifest.worker_executable_sha256)?;
        serverware_decision_gate::native_shadow_workers::validate_static_amd64_elf_verifier(&bytes).map_err(unavailable)?;
        let owner=Self{executable,identity,association};owner.check()?;Ok(owner)
    }
    pub(in crate::policy_shadow) fn check(&self)->Result<(),ShadowError> {
        self.association.check_native_preparation().map_err(unavailable)?;
        require(executable_identity(&self.executable)?==self.identity && status_number("Threads:")?==1)?;
        check_current_executable(&self.identity)
    }
}

/// Constructed only in the same root process as admitted guest delivery.
/// It may be borrowed for the root's real chroot setup but cannot cross exec.
pub(in crate::policy_shadow) struct PreparedNativeCustodyClosure {
    configuration:Configuration,association:GuestClosureAssociation,image:Arc<ShadowImage>,
    executable:File,executable_identity:ExecutableIdentity,checkpoint:AtomicTrustCheckpoint,
}
impl PreparedNativeCustodyClosure {
    pub(in crate::policy_shadow) fn require_prekey(&self,original:&PrekeyExecutable)->Result<(),ShadowError> {
        original.check()?;self.association.check_preparation().map_err(unavailable)?;
        require(self.association.same_origin(&original.association) && self.executable_identity==original.identity)
    }
    pub(in crate::policy_shadow) fn open(configuration:Configuration,assignment:&VerifiedAssignment,
        trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,delivery:&PreparedGuestServiceDelivery)->Result<Self,ShadowError> {
        let association=delivery.closure_association().map_err(unavailable)?;association.check_preparation().map_err(unavailable)?;
        configuration.require_legacy()?;
        revalidate_verified_freshness(assignment,trust,time,MAX_ENVELOPE_AGE_NANOS)?;
        let checkpoint=trust.current_checkpoint()?;let p=&configuration.authorization.payload;
        require(p.trust_checkpoint_id==checkpoint.checkpoint_id && p.revocation_generation==checkpoint.revocation_generation
            && p.revocation_root_sha256==checkpoint.revocation_root_sha256)?;
        verify_assignment(&configuration.authorization,&configuration.manifest,&association.binding(),assignment,
            &checkpoint,trust)?;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        let m=&configuration.manifest;let b=&m.build_provenance;
        let image=ShadowImage::open(m.image_sha256.as_str(),m.worker_executable_sha256.as_str(),[
            m.seccomp_policy.raw_bpf_sha256().as_str(),m.runtime_configuration_sha256.as_str(),
            b.dependency_lock_sha256.as_str(),b.build_recipe_sha256.as_str(),b.provenance_statement_sha256.as_str()],association.startup()).map_err(unavailable)?;
        require(read(image.seccomp(),32768)?==custody_seccomp_raw_bytes(m.seccomp_policy.exact_instructions()))?;
        let runtime=read(image.configuration(),4*1024*1024)?;
        require(Sha256Digest::compute(&runtime)==association.binding().runtime_configuration_sha256)?;
        let executable=File::open("/proc/self/exe").map_err(unavailable)?;
        let executable_identity=executable_identity(&executable)?;
        let bytes=read(&executable,128*1024*1024)?;
        require(Sha256Digest::compute(&bytes)==m.worker_executable_sha256)?;
        serverware_decision_gate::native_shadow_workers::validate_static_amd64_elf_verifier(&bytes).map_err(unavailable)?;
        // Same full bytes, not merely a matching path or mutable executable.
        require(read(image.executable(),128*1024*1024)?==bytes)?;
        check_current_executable(&executable_identity)?;association.check_preparation().map_err(unavailable)?;
        Ok(Self {configuration,association,image:Arc::new(image),executable,executable_identity,checkpoint})
    }
    pub(in crate::policy_shadow) fn root(&self)->Result<BorrowedFd<'_>,ShadowError> {
        self.association.check_preparation().map_err(unavailable)?;self.image.check(self.association.startup()).map_err(unavailable)?;
        Ok(self.image.root())
    }
    /// Called before service threads/input, AFTER exact permanent role drop and
    /// real root installation. Installs the already authenticated exact BPF.
    pub(in crate::policy_shadow) fn bind_current_process(self)->Result<NativeCustodyClosureOwner,ShadowError> {
        self.association.check_startup().map_err(unavailable)?;check_root(&self.image)?;
        check_current_executable(&self.executable_identity)?;
        require(status_number("Threads:")?==1)?;
        let before=status_number("Seccomp_filters:")?;
        let mut instructions:Vec<libc::sock_filter>=self.configuration.manifest.seccomp_policy.exact_instructions().iter()
            .map(|v|libc::sock_filter {code:v.code,jt:v.jump_if_true,jf:v.jump_if_false,k:v.operand}).collect();
        let program=libc::sock_fprog {len:u16::try_from(instructions.len()).map_err(unavailable)?,filter:instructions.as_mut_ptr()};
        require(unsafe {libc::syscall(libc::SYS_seccomp,1,0,&program)}==0)?;
        let filters=before.checked_add(1).ok_or(ShadowError::BindingDrift)?;
        require(status_number("Seccomp_filters:")?==filters)?;
        let owner=NativeCustodyClosureOwner(Arc::new(Core {prepared:self,filters,poisoned:AtomicBool::new(false)}));
        owner.check()?;Ok(owner)
    }
}
struct Core {prepared:PreparedNativeCustodyClosure,filters:u64,poisoned:AtomicBool}
/// Clone shares actual original ownership; equality is owner identity, not JSON.
#[derive(Clone)]
pub(in crate::policy_shadow) struct NativeCustodyClosureOwner(Arc<Core>);
impl fmt::Debug for NativeCustodyClosureOwner {
    fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.debug_struct("NativeCustodyClosureOwner").field("manifest",&self.manifest_sha256()).finish_non_exhaustive()}
}
impl PartialEq for NativeCustodyClosureOwner {fn eq(&self,other:&Self)->bool {Arc::ptr_eq(&self.0,&other.0)}}
impl Eq for NativeCustodyClosureOwner {}
impl NativeCustodyClosureOwner {
    pub(in crate::policy_shadow) fn require_origin(&self,association:&GuestClosureAssociation)->Result<(),ShadowError> {
        self.check()?;require(self.0.prepared.association.same_origin(association))
    }
    pub(super) fn check(&self)->Result<(),ShadowError> {
        let result=(|| {
            require(!self.0.poisoned.load(Ordering::Acquire))?;let p=&self.0.prepared;
            p.association.check().map_err(unavailable)?;p.image.check(p.association.lifetime()).map_err(unavailable)?;
            require(executable_identity(&p.executable)?==p.executable_identity)?;check_root(&p.image)?;
            check_current_executable(&p.executable_identity)?;
            require(unsafe {libc::prctl(libc::PR_GET_SECCOMP,0,0,0,0)}==2 && status_number("Seccomp_filters:")?==self.0.filters)
        })();
        if result.is_err() {self.0.poisoned.store(true,Ordering::Release);}result
    }
    pub(super) fn verify_current(&self,assignment:&VerifiedAssignment,checkpoint:&AtomicTrustCheckpoint,trust:&dyn EnvelopeKeyTrust)->Result<(),ShadowError> {
        self.check()?;let p=&self.0.prepared;
        require(p.checkpoint.permits_successor(checkpoint))?;
        verify_assignment(&p.configuration.authorization,&p.configuration.manifest,&p.association.binding(),assignment,
            checkpoint,trust)
    }
    pub(super) fn freshness(&self,now:i64)->Result<(),ShadowError> {
        self.check()?;let p=&self.0.prepared.configuration.authorization.payload;
        validate_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,now,MAX_ENVELOPE_AGE_NANOS)
    }
    pub(super) fn trusted_freshness(&self,time:&dyn TrustedTime)->Result<(),ShadowError> {
        self.check()?;let p=&self.0.prepared.configuration.authorization.payload;
        validate_trusted_freshness(p.issued_at_unix_nanos,p.expires_at_unix_nanos,time,MAX_ENVELOPE_AGE_NANOS)?;
        Ok(())
    }
    pub(super) fn require_assignment(&self,assignment:&VerifiedAssignment,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime,
        supervisor_instance:&Sha256Digest,supervisor_boot:&Sha256Digest)->Result<(),ShadowError> {
        let checkpoint=trust.current_checkpoint()?;self.verify_current(assignment,&checkpoint,trust)?;self.trusted_freshness(time)?;
        let binding=self.0.prepared.association.binding();
        let raw=URL_SAFE_NO_PAD.decode(&binding.boot_id_base64url).map_err(unavailable)?;
        require(&Sha256Digest::compute(&raw)==supervisor_boot
            && &Sha256Digest::compute(binding.invocation_id.as_bytes())==supervisor_instance
            && trust.current_checkpoint()?==checkpoint)
    }
    pub(super) fn manifest_sha256(&self)->&Sha256Digest {&self.0.prepared.configuration.manifest.manifest_sha256}
    pub(super) fn seccomp_policy_sha256(&self)->&Sha256Digest {self.0.prepared.configuration.manifest.seccomp_policy.policy_sha256()}
    pub(super) fn worker_executable_sha256(&self)->&Sha256Digest {&self.0.prepared.configuration.manifest.worker_executable_sha256}
}
