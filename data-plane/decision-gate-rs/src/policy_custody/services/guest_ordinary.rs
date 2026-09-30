//! Explicit software five-service C9 entry. No key-admission/NSM projection.
//! The actual signed Guest owner survives drop into the existing serving loop.
use super::*;

fn now()->Result<u64,ServiceRunnerError> {
    boottime_now_nanos().map_err(|e|fail(&e.to_string()))
}
fn require(value:bool)->Result<(),ServiceRunnerError> {
    if value {Ok(())} else {Err(fail("ordinary guest launch refused"))}
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Launch {api_version:String,delivery_configuration:Pin,delivery:Pin}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct InspectedLaunch {api_version:String,delivery_configuration:Pin,delivery:Pin,peer_inspection_credential:String}

enum EntryProfile {Generation,InspectedGeneration,CommitRequest,InspectedCommitRequest,InspectedSpool}
impl EntryProfile {
    fn selector(&self)->&'static str {match self {
        Self::Generation=>"--guest-c9-generation",
        Self::InspectedGeneration=>"--guest-c9-generation-inspected",
        Self::CommitRequest=>"--guest-c9-commitment",
        Self::InspectedCommitRequest=>"--guest-c9-commitment-inspected",
        Self::InspectedSpool=>"--guest-c9-spool-inspected",
    }}
    fn inspected(&self)->bool {matches!(self,Self::InspectedGeneration|Self::InspectedCommitRequest|Self::InspectedSpool)}
    fn commitment(&self)->bool {matches!(self,Self::CommitRequest|Self::InspectedCommitRequest|Self::InspectedSpool)}
    fn launch(&self,raw:&[u8])->Result<(Pin,Pin),ServiceRunnerError> {match self {
        Self::Generation=>{
            let value:Launch=exact(raw)?;
            require(value.api_version=="serverware.custodyOrdinaryServiceGuestLaunch/v1")?;
            Ok((value.delivery_configuration,value.delivery))
        },
        Self::InspectedGeneration=>{
            let value:InspectedLaunch=exact(raw)?;
            require(value.api_version=="serverware.custodyOrdinaryServiceGuestLaunch/v2"
                && value.peer_inspection_credential==super::ordinary_inspection::CREDENTIAL)?;
            Ok((value.delivery_configuration,value.delivery))
        },
        Self::CommitRequest=>{
            let value:Launch=exact(raw)?;
            require(value.api_version=="serverware.custodyOrdinaryServiceGuestLaunch/v3")?;
            Ok((value.delivery_configuration,value.delivery))
        },
        Self::InspectedCommitRequest=>{
            let value:InspectedLaunch=exact(raw)?;
            require(value.api_version=="serverware.custodyOrdinaryServiceGuestLaunch/v4"
                && value.peer_inspection_credential==super::ordinary_inspection::CREDENTIAL)?;
            Ok((value.delivery_configuration,value.delivery))
        },
        Self::InspectedSpool=>{
            let value:InspectedLaunch=exact(raw)?;
            require(value.api_version=="serverware.custodyOrdinaryServiceGuestLaunch/v5"
                && value.peer_inspection_credential==super::ordinary_inspection::CREDENTIAL)?;
            Ok((value.delivery_configuration,value.delivery))
        },
    }}
}

pub(super) struct Timer {handle:usize,pid:i32,deadline:u64}
impl Timer {
    pub(super) fn arm(deadline:u64)->Result<Self,ServiceRunnerError> {
        require(now()?<deadline)?;
        let mut event:libc::sigevent=unsafe{std::mem::zeroed()};
        event.sigev_notify=libc::SIGEV_SIGNAL;event.sigev_signo=libc::SIGKILL;
        let mut timer=std::ptr::null_mut();
        require(unsafe{libc::timer_create(libc::CLOCK_BOOTTIME,&mut event,&mut timer)}==0)?;
        let owner=Self{handle:timer as usize,pid:unsafe{libc::getpid()},deadline};
        let value=libc::itimerspec{it_interval:libc::timespec{tv_sec:0,tv_nsec:0},
            it_value:libc::timespec{tv_sec:(deadline/1_000_000_000) as _,tv_nsec:(deadline%1_000_000_000) as _}};
        require(unsafe{libc::timer_settime(timer,libc::TIMER_ABSTIME,&value,std::ptr::null_mut())}==0)?;
        owner.check()?;Ok(owner)
    }
    pub(super) fn check(&self)->Result<(),ServiceRunnerError> {
        require(unsafe{libc::getpid()}==self.pid)?;
        let before=now()?;let mut value:libc::itimerspec=unsafe{std::mem::zeroed()};
        require(unsafe{libc::timer_gettime(self.handle as libc::timer_t,&mut value)}==0)?;
        let after=now()?;
        require(before<=after && after<self.deadline && value.it_interval.tv_sec==0 && value.it_interval.tv_nsec==0
            && value.it_value.tv_sec>=0 && (0..1_000_000_000).contains(&value.it_value.tv_nsec))?;
        let remaining=value.it_value.tv_sec as u128*1_000_000_000+value.it_value.tv_nsec as u128;
        require(remaining>0 && remaining>=(self.deadline-after) as u128 && remaining<=(self.deadline-before) as u128)
    }
}
impl Drop for Timer {fn drop(&mut self){if self.pid==unsafe{libc::getpid()} {
    unsafe{libc::timer_delete(self.handle as libc::timer_t);}
}}}
pub(super) struct Lifetime {pid:i32,parent:i32,startup:Option<Timer>,lifetime:Timer}
impl Lifetime {
    fn arm(owner:&Delivery)->Result<Self,ServiceRunnerError> {
        owner.check_originals()?;
        let parent=owner.parent.native_binding()?.0;
        require(unsafe{libc::getppid()}==parent && unsafe{libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)}==0
            && unsafe{libc::getppid()}==parent)?;
        Ok(Self{pid:unsafe{libc::getpid()},parent,startup:Some(Timer::arm(owner.startup)?),lifetime:Timer::arm(owner.lifetime)?})
    }
    pub(super) fn check(&self)->Result<(),ServiceRunnerError> {
        require(unsafe{libc::getpid()}==self.pid && unsafe{libc::getppid()}==self.parent)?;
        self.lifetime.check()?;
        if let Some(startup)=&self.startup {startup.check()?;}
        if unsafe{libc::syscall(libc::SYS_gettid)}==self.pid as libc::c_long {
            let mut signal=0;
            require(unsafe{libc::prctl(libc::PR_GET_PDEATHSIG,&mut signal)}==0 && signal==libc::SIGKILL)?;
        }
        Ok(())
    }
    pub(super) fn constructed(&mut self)->Result<(),ServiceRunnerError> {
        self.check()?;require(self.startup.take().is_some())?;self.check()
    }
}

fn entry(role:&str,profile:EntryProfile)->Result<(),ServiceRunnerError> {
    let args=std::env::args().collect::<Vec<_>>();
    require(args.len()==2 && args[1]==profile.selector() && std::env::vars_os().next().is_none()
        && unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0)?;
    let core=libc::rlimit{rlim_cur:0,rlim_max:0};
    require(unsafe{libc::setrlimit(libc::RLIMIT_CORE,&core)}==0 && unsafe{libc::prctl(libc::PR_SET_DUMPABLE,0)}==0)?;
    let mut inherited=BTreeSet::new();
    // Enumerate before any admission opens can occupy an absent expected slot.
    let observed=std::fs::read_dir("/proc/self/fd")?.map(|entry| {
        entry?.file_name().to_str().ok_or_else(||fail("non-numeric descriptor"))?.parse::<i32>()
            .map_err(|_|fail("non-numeric descriptor"))
    }).collect::<Result<Vec<_>,ServiceRunnerError>>()?;
    require(observed.len()<=70)?;
    for fd in observed {
        if unsafe{libc::fcntl(fd,libc::F_GETFD)}<0 {
            require(std::io::Error::last_os_error().raw_os_error()==Some(libc::EBADF))?;continue;
        }
        require((0..=4).contains(&fd)||(6..=69).contains(&fd))?;inherited.insert(fd);
    }
    require(inherited.contains(&3) && inherited.contains(&4))?;
    let original=Original::ordinary_service_launch(role)?;
    let (configuration,envelope)=profile.launch(&original.read(32768)?)?;
    let delivery=PreparedGuestServiceDelivery::admit(&configuration.path,configuration.sha256,
        &envelope.path,envelope.sha256)?;
    require(delivery.closure_association()?.binding().service_role==role
        && delivery.owner.payload.service_role!=Role::ProductionBridge
        && inherited.iter().filter(|fd|**fd>=6).copied().eq(6..6+delivery.activation.len() as i32))?;
    let runtime:serde_json::Value=exact(&delivery.owner.runtime.read(MAX_CONFIG_BYTES)?)?;
    let expected=if profile.commitment(){
        require(matches!(delivery.owner.payload.service_role,Role::DurableRecoveryStore|Role::CurrentSignatureAuthority))?;
        if matches!(profile,EntryProfile::InspectedSpool){super::super::spool_head::RUNTIME}else{super::super::dispatch_service::RUNTIME}
    }else{generation_service::RUNTIME};
    require(runtime.get("runtime").and_then(|v|v.get("apiVersion")).and_then(|v|v.as_str())==Some(expected))?;
    let lifetime=Lifetime::arm(&delivery.owner)?;
    *delivery.owner.ordinary_lifetime.lock().map_err(|_|fail("ordinary lifetime owner poisoned"))?=Some(lifetime);
    // The only fork is before service threads, private key reads and role drop.
    // Keep its stop/reap owner on this stack across the actual serving loop.
    let worker=if profile.inspected() {Some(super::ordinary_inspection::prepare(&delivery)?)} else {None};
    require(unsafe{libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0)}==0 && unsafe{libc::prctl(47,4,0,0,0)}==0)?;
    for capability in 0..64 {
        let present=unsafe{libc::prctl(libc::PR_CAPBSET_READ,capability,0,0,0)};
        if present<0 {require(std::io::Error::last_os_error().raw_os_error()==Some(libc::EINVAL))?;continue;}
        if present==1 {require(unsafe{libc::prctl(libc::PR_CAPBSET_DROP,capability,0,0,0)}==0)?;}
    }
    require(unsafe{libc::setgroups(0,std::ptr::null())}==0
        && unsafe{libc::setresgid(delivery.role_gid(),delivery.role_gid(),delivery.role_gid())}==0
        && unsafe{libc::setresuid(delivery.role_uid(),delivery.role_uid(),delivery.role_uid())}==0)?;
    #[repr(C)]struct Header{version:u32,pid:i32}
    #[repr(C)]struct Data{effective:u32,permitted:u32,inheritable:u32}
    let header=Header{version:0x2008_0522,pid:0};
    let data=[Data{effective:0,permitted:0,inheritable:0},Data{effective:0,permitted:0,inheritable:0}];
    require(unsafe{libc::syscall(libc::SYS_capset,&header,data.as_ptr())}==0
        && unsafe{libc::prctl(libc::PR_SET_DUMPABLE,0)}==0
        && unsafe{libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)}==0)?;
    original.check()?;delivery.owner.check_startup()?;
    if let Some(worker)=worker.as_ref() {super::ordinary_inspection::final_role_listening(&delivery,worker)?;}
    // The real software serving owner constructs, journals and signs through
    // its existing keys. No native-key admission or NSM proof is synthesized.
    delivery.run_after_drop()
}
pub(crate) fn run(role:&str)->! {
    let _=entry(role,EntryProfile::Generation);
    unsafe{libc::_exit(1)}
}
pub(crate) fn run_inspected(role:&str)->! {
    let _=entry(role,EntryProfile::InspectedGeneration);
    unsafe{libc::_exit(1)}
}
pub(crate) fn run_commitment(role:&str,inspected:bool)->! {
    let profile=if inspected{EntryProfile::InspectedCommitRequest}else{EntryProfile::CommitRequest};
    let _=entry(role,profile);
    unsafe{libc::_exit(1)}
}
pub(crate) fn run_spool(role:&str)->!{let _=entry(role,EntryProfile::InspectedSpool);unsafe{libc::_exit(1)}}
