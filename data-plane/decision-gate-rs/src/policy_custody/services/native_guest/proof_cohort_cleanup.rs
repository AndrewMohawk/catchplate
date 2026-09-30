//! Explicit whole-cohort cancellation, not an operation settlement receipt.
//! The parent retains every resource through real waitid(P_PIDFD) consumption.
use super::*;
use std::io::Write;
use std::os::unix::fs::FileExt;
const DOMAIN:&[u8]=b"serverware.nativeShadowProofCohortCleanup.signature/v1\0";
const SIX_DOMAIN:&[u8]=b"serverware.nativeShadowProofCohortCleanup.signature/v2\0";
const DIRECTORY:&str="/var/lib/serverware/native-shadow-proof-cohort-cleanup";
const MAX_RECORD:usize=65536;
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Authority {public_key_base64url:String,key_id:Sha256Digest}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Identity {device:u64,inode:u64,mode:u32,uid:u32,gid:u32}
#[derive(Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Configuration {authority:Authority,scope_id:Sha256Digest,journal:Identity,genesis_sha256:Sha256Digest}
impl Configuration {
    pub(super) fn validate(&self,launch_public:&str)->Result<VerifyingKey,ShadowError>{
        let raw=URL_SAFE_NO_PAD.decode(&self.authority.public_key_base64url).map_err(fail)?;
        require(raw.len()==32 && raw.iter().any(|v|*v!=0)
            && URL_SAFE_NO_PAD.encode(&raw)==self.authority.public_key_base64url
            && self.authority.public_key_base64url!=launch_public && Sha256Digest::compute(&raw)==self.authority.key_id
            && self.journal.inode>0 && self.journal.uid==0 && self.journal.gid==0
            && self.journal.mode==(libc::S_IFDIR|0o700))?;
        VerifyingKey::from_bytes(&raw.try_into().map_err(fail)?).map_err(fail)
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Payload {api_version:String,purpose:String,configuration_sha256:Sha256Digest,precreation_sha256:Sha256Digest,
    observation_sha256:Sha256Digest,release_sha256:Sha256Digest,invocation_id:String,operation_id_sha256:Sha256Digest,
    requested_at_boottime_ns:String,deadline_boottime_ns:String,signing_key_id:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Authorization {payload:Payload,signature_base64url:String}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Genesis {api_version:String,scope_id:Sha256Digest,authority_key_id:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Record {api_version:String,sequence:u32,previous_head_sha256:Sha256Digest,original:String}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Terminal {api_version:&'static str,authorization_sha256:Sha256Digest,configuration_sha256:Sha256Digest,
    precreation_sha256:Sha256Digest,observation_sha256:Sha256Digest,release_sha256:Sha256Digest,
    invocation_id:String,completed_at_boottime_ns:String,children:BTreeMap<&'static str,child::TerminalObservation>}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct ResultOriginal {api_version:&'static str,authorization_sha256:Sha256Digest,intent_record_sha256:Sha256Digest,
    terminal_original:String,terminal_record_sha256:Sha256Digest}
struct Held {name:&'static str,file:File,raw:Vec<u8>}
pub(super) struct Owner {config:Configuration,key:VerifyingKey,directory:File,lock:File,ancestors:Vec<(File,&'static str,Identity)>,
    held:Vec<Held>,head:Sha256Digest,attempted:bool}
fn identity(file:&File)->Result<Identity,ShadowError>{let m=file.metadata().map_err(fail)?;
    Ok(Identity{device:m.dev(),inode:m.ino(),mode:m.mode(),uid:m.uid(),gid:m.gid()})}
fn at(directory:&File,name:&str,flags:i32)->Result<File,ShadowError>{
    let name=std::ffi::CString::new(name).map_err(fail)?;
    let raw=unsafe{libc::openat(directory.as_raw_fd(),name.as_ptr(),flags|libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_NONBLOCK,0o600)};
    require(raw>=0)?;Ok(unsafe{File::from_raw_fd(raw)})
}
fn read(file:&File)->Result<Vec<u8>,ShadowError>{
    let m=file.metadata().map_err(fail)?;
    require(m.is_file() && m.nlink()==1 && m.uid()==0 && m.gid()==0 && m.mode()&0o7777==0o400
        && m.len()>0 && m.len()<=MAX_RECORD as u64)?;
    let mut raw=vec![0;m.len() as usize];file.read_exact_at(&mut raw,0).map_err(fail)?;
    let n=file.metadata().map_err(fail)?;
    require((m.dev(),m.ino(),m.len(),m.mode(),m.uid(),m.gid(),m.nlink(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec())
        ==(n.dev(),n.ino(),n.len(),n.mode(),n.uid(),n.gid(),n.nlink(),n.mtime(),n.mtime_nsec(),n.ctime(),n.ctime_nsec()))?;Ok(raw)
}
impl Owner {
    pub(super) fn open(config:&Configuration,key:VerifyingKey)->Result<Self,ShadowError>{
        require(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0)?;
        let mut current=File::open("/").map_err(fail)?;let mut ancestors=Vec::new();
        for name in DIRECTORY[1..].split('/') {
            let id=identity(&current)?;
            require(id.mode&libc::S_IFMT==libc::S_IFDIR && id.uid==0 && id.gid==0 && id.mode&0o022==0)?;
            let next=at(&current,name,libc::O_RDONLY|libc::O_DIRECTORY)?;
            ancestors.push((current,name,identity(&next)?));current=next;
        }
        require(identity(&current)?==config.journal)?;
        let mut fs:libc::statfs=unsafe{zeroed()};
        require(unsafe{libc::fstatfs(current.as_raw_fd(),&mut fs)}==0
            && matches!(fs.f_type as u64,0xef53|0x5846_5342|0x9123_683e) && fs.f_flags as u64&1==0)?;
        let lock=at(&current,"cleanup.lock",libc::O_RDWR)?;let m=lock.metadata().map_err(fail)?;
        require(m.is_file() && m.uid()==0 && m.gid()==0 && m.nlink()==1 && m.len()==0
            && m.mode()&0o7777==0o600 && m.dev()==config.journal.device
            && unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0)?;
        let file=at(&current,"genesis.json",libc::O_RDONLY)?;let raw=read(&file)?;
        let genesis:Genesis=exact(&raw)?;
        require(Sha256Digest::compute(&raw)==config.genesis_sha256 && genesis.api_version=="serverware.nativeShadowProofCohortCleanupGenesis/v1"
            && genesis.scope_id==config.scope_id && genesis.authority_key_id==config.authority.key_id)?;
        let owner=Self{config:config.clone(),key,directory:current,lock,ancestors,
            held:vec![Held{name:"genesis.json",file,raw}],head:config.genesis_sha256.clone(),attempted:false};
        owner.check()?;Ok(owner)
    }
    pub(super) fn check(&self)->Result<(),ShadowError>{
        require(unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0 && identity(&self.directory)?==self.config.journal)?;
        let mut fs:libc::statfs=unsafe{zeroed()};
        require(unsafe{libc::fstatfs(self.directory.as_raw_fd(),&mut fs)}==0
            && matches!(fs.f_type as u64,0xef53|0x5846_5342|0x9123_683e) && fs.f_flags as u64&1==0)?;
        for (parent,name,id) in &self.ancestors {
            let m=parent.metadata().map_err(fail)?;
            require(m.is_dir() && m.uid()==0 && m.gid()==0 && m.mode()&0o022==0
                && identity(&at(parent,name,libc::O_RDONLY|libc::O_DIRECTORY)?)?==*id)?;
        }
        let m=self.lock.metadata().map_err(fail)?;
        require(m.is_file() && m.nlink()==1 && m.len()==0 && m.uid()==0 && m.gid()==0
            && m.mode()&0o7777==0o600 && m.dev()==self.config.journal.device)?;
        require(identity(&at(&self.directory,"cleanup.lock",libc::O_RDWR)?)?==identity(&self.lock)?
            && unsafe{libc::flock(self.lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0)?;
        let mut expected:BTreeSet<String>=BTreeSet::from(["cleanup.lock".into()]);
        for held in &self.held {
            require(identity(&at(&self.directory,held.name,libc::O_RDONLY)?)?==identity(&held.file)? && read(&held.file)?==held.raw)?;
            expected.insert(held.name.into());
        }
        let raw=unsafe{libc::openat(self.directory.as_raw_fd(),c".".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_CLOEXEC)};
        require(raw>=0)?;let stream=unsafe{libc::fdopendir(raw)};
        if stream.is_null(){unsafe{libc::close(raw)};return Err(ShadowError::CustodyUnavailable);}
        let result=(||{let mut count=0;loop {
            unsafe{*libc::__errno_location()=0;}let item=unsafe{libc::readdir(stream)};
            if item.is_null(){require(std::io::Error::last_os_error().raw_os_error()==Some(0))?;break;}
            count+=1;require(count<=6)?;
            let name=unsafe{std::ffi::CStr::from_ptr((*item).d_name.as_ptr())}.to_str().map_err(fail)?;
            if name!="." && name!=".." {require(expected.remove(name))?;}
        }require(expected.is_empty())})();unsafe{libc::closedir(stream)};result
    }
    fn append(&mut self,name:&'static str,original:&[u8],check:&impl Fn()->Result<(),ShadowError>)->Result<Sha256Digest,ShadowError>{
        self.check()?;check()?;require(self.held.len()<3 && original.is_ascii() && !original.is_empty()
            && original.len()<=(MAX_RECORD-1024)/2)?;
        let record=Record{api_version:"serverware.nativeShadowProofCohortCleanupRecord/v1".into(),sequence:self.held.len() as u32,
            previous_head_sha256:self.head.clone(),original:String::from_utf8(original.to_vec()).map_err(fail)?};
        let raw=canonical_json_bytes(&record)?;require(raw.len()<=MAX_RECORD)?;
        let mut file=at(&self.directory,name,libc::O_RDWR|libc::O_CREAT|libc::O_EXCL)?;
        file.write_all(&raw).map_err(fail)?;file.sync_all().map_err(fail)?;check()?;
        require(unsafe{libc::fchmod(file.as_raw_fd(),0o400)}==0)?;file.sync_all().map_err(fail)?;
        require(read(&file)?==raw && unsafe{libc::fsync(self.directory.as_raw_fd())}==0)?;check()?;
        self.head=Sha256Digest::compute(&raw);self.held.push(Held{name,file,raw});self.check()?;check()?;Ok(self.head.clone())
    }
    pub(super) fn perform(mut self,raw:&[u8],cohort:&mut Cohort,observed:&[u8],release:&[u8],control:&Control)
        ->Result<(Self,Vec<u8>,u64),ShadowError>{
        require(!self.attempted && raw.len()<=MAX_WIRE && cohort.children.len()==cohort.admission.roles().len()
            && cohort.programs.len()==cohort.admission.roles().len())?;
        self.attempted=true;let authorization:Authorization=exact(raw)?;let p=&authorization.payload;
        let issued=decimal(&p.requested_at_boottime_ns)?;let deadline=decimal(&p.deadline_boottime_ns)?;
        let a=&cohort.admission;
        let eleven=a.eleven();let eight=a.eight();let seven=a.seven();let six=a.six();let roles=a.roles();
        require(p.api_version==(if eleven{"serverware.nativeShadowProofCohortCleanup/v5"}else if eight{"serverware.nativeShadowProofCohortCleanup/v4"}else if seven{"serverware.nativeShadowProofCohortCleanup/v3"}else if six{"serverware.nativeShadowProofCohortCleanup/v2"}else{"serverware.nativeShadowProofCohortCleanup/v1"})
            && p.purpose=="terminate-owned-proof-cohort"
            && p.configuration_sha256==a.configuration_sha256() && p.precreation_sha256==a.precreation_sha256()
            && p.observation_sha256==Sha256Digest::compute(observed) && p.release_sha256==Sha256Digest::compute(release)
            && p.invocation_id==a.invocation_id() && p.signing_key_id==self.config.authority.key_id
            && issued>=a.issued() && issued<=now()? && now()?<deadline
            && deadline.checked_sub(issued).is_some_and(|duration|duration<=30_000_000_000)
            && deadline<=a.lifetime().checked_sub(REAP_RESERVE_NS).ok_or(ShadowError::BindingDrift)?)?;
        let signature=URL_SAFE_NO_PAD.decode(&authorization.signature_base64url).map_err(fail)?;
        require(signature.len()==64 && URL_SAFE_NO_PAD.encode(&signature)==authorization.signature_base64url)?;
        let mut preimage=(if eleven{b"serverware.nativeShadowProofCohortCleanup.signature/v5\0".as_slice()}else if eight{b"serverware.nativeShadowProofCohortCleanup.signature/v4\0".as_slice()}else if seven{b"serverware.nativeShadowProofCohortCleanup.signature/v3\0".as_slice()}else if six{SIX_DOMAIN}else{DOMAIN}).to_vec();preimage.extend(canonical_json_bytes(p)?);
        self.key.verify_strict(&preimage,&Signature::from_bytes(&signature.try_into().map_err(fail)?)).map_err(fail)?;
        cohort.check()?;control.check()?;
        let intent=self.append("intent.json",raw,&||{cohort.check()?;control.check()?;require(now()?<deadline)})?;
        // Signal every actual owned child before waiting for any of them.
        // Once this begins there is no continuation, retry or new release.
        let mut signalled=true;
        for child in &mut cohort.children {require(now()?<deadline)?;signalled &= child.request_stop().is_ok();}
        require(signalled)?;
        let mut children=BTreeMap::new();
        for (role,child) in roles.iter().zip(&mut cohort.children) {
            children.insert(*role,child.reap_observed(deadline)?);
        }
        let completed=now()?;require(completed<deadline)?;
        let terminal=Terminal{api_version:if eleven{"serverware.nativeShadowProofCohortTerminal/v5"}else if eight{"serverware.nativeShadowProofCohortTerminal/v4"}else if seven{"serverware.nativeShadowProofCohortTerminal/v3"}else if six{"serverware.nativeShadowProofCohortTerminal/v2"}else{"serverware.nativeShadowProofCohortTerminal/v1"},authorization_sha256:Sha256Digest::compute(raw),
            configuration_sha256:p.configuration_sha256.clone(),precreation_sha256:p.precreation_sha256.clone(),
            observation_sha256:p.observation_sha256.clone(),release_sha256:p.release_sha256.clone(),
            invocation_id:p.invocation_id.clone(),completed_at_boottime_ns:completed.to_string(),children};
        let terminal_raw=canonical_json_bytes(&terminal)?;
        let terminal_head=self.append("terminal.json",&terminal_raw,&||{cohort.check_resources()?;control.check()?;require(now()?<deadline)})?;
        let response=canonical_json_bytes(&ResultOriginal{api_version:if eleven{"serverware.nativeShadowProofCohortCleanupResult/v5"}else if eight{"serverware.nativeShadowProofCohortCleanupResult/v4"}else if seven{"serverware.nativeShadowProofCohortCleanupResult/v3"}else if six{"serverware.nativeShadowProofCohortCleanupResult/v2"}else{"serverware.nativeShadowProofCohortCleanupResult/v1"},
            authorization_sha256:terminal.authorization_sha256,intent_record_sha256:intent,
            terminal_original:String::from_utf8(terminal_raw).map_err(fail)?,terminal_record_sha256:terminal_head})?;
        require(response.len()<=MAX_WIRE)?;Ok((self,response,deadline))
    }
}
