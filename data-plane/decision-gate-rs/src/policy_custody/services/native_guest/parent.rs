//! Root-only fixed parent through real child exit, not a custody service.
use super::*;
use super::super::{admit_files,take_activation,FileAdmission};
use std::os::fd::{AsFd,AsRawFd,OwnedFd};
#[path="parent_image.rs"]
mod image;
#[path="parent_process.rs"]
pub(in crate::policy_shadow::policy_custody::services::guest::native_guest) mod child;
#[path="retrieval_pair.rs"]
mod pair;
#[path="proof_cohort.rs"]
mod proof_cohort;
#[path="genesis_controller.rs"]
mod genesis_controller;

// Cleanup is a narrowing of the signed lifetime, never a fresh interval.
const REAP_RESERVE_NS:u64=250_000_000;
struct Watchdog(libc::timer_t);
impl Watchdog {
    fn arm_proof_cohort(admission:&proof_cohort::inputs::Admission)->Result<Self,ShadowError> {
        admission.check_startup()?;
        let mut event:libc::sigevent=unsafe{std::mem::zeroed()};
        event.sigev_notify=libc::SIGEV_SIGNAL;event.sigev_signo=libc::SIGKILL;
        let mut timer=std::ptr::null_mut();
        require(unsafe{libc::timer_create(libc::CLOCK_BOOTTIME,&mut event,&mut timer)}==0)?;
        let owner=Self(timer);let deadline=admission.lifetime();
        let value=libc::itimerspec{it_interval:libc::timespec{tv_sec:0,tv_nsec:0},
            it_value:libc::timespec{tv_sec:(deadline/1_000_000_000) as _,tv_nsec:(deadline%1_000_000_000) as _}};
        require(unsafe{libc::timer_settime(timer,libc::TIMER_ABSTIME,&value,std::ptr::null_mut())}==0)?;
        admission.check_startup()?;Ok(owner)
    }
    fn arm_pair(admission:&pair::inputs::Admission)->Result<Self,ShadowError> {
        admission.check_startup()?;
        let mut event:libc::sigevent=unsafe{std::mem::zeroed()};
        event.sigev_notify=libc::SIGEV_SIGNAL;event.sigev_signo=libc::SIGKILL;
        let mut timer=std::ptr::null_mut();
        require(unsafe{libc::timer_create(libc::CLOCK_BOOTTIME,&mut event,&mut timer)}==0)?;
        let owner=Self(timer);let deadline=admission.lifetime();
        let value=libc::itimerspec{it_interval:libc::timespec{tv_sec:0,tv_nsec:0},
            it_value:libc::timespec{tv_sec:(deadline/1_000_000_000) as _,tv_nsec:(deadline%1_000_000_000) as _}};
        require(unsafe{libc::timer_settime(timer,libc::TIMER_ABSTIME,&value,std::ptr::null_mut())}==0)?;
        admission.check_startup()?;Ok(owner)
    }
    fn arm(files:&FileAdmission)->Result<Self,ShadowError> {
        files.check_preparation().map_err(fail)?;
        let mut event:libc::sigevent=unsafe{std::mem::zeroed()};
        event.sigev_notify=libc::SIGEV_SIGNAL;event.sigev_signo=libc::SIGKILL;
        let mut timer=std::ptr::null_mut();
        require(unsafe{libc::timer_create(libc::CLOCK_BOOTTIME,&mut event,&mut timer)}==0)?;
        let owner=Self(timer);let deadline=files.lifetime();
        let value=libc::itimerspec{it_interval:libc::timespec{tv_sec:0,tv_nsec:0},
            it_value:libc::timespec{tv_sec:(deadline/1_000_000_000) as _,tv_nsec:(deadline%1_000_000_000) as _}};
        require(unsafe{libc::timer_settime(timer,libc::TIMER_ABSTIME,&value,std::ptr::null_mut())}==0)?;
        files.check_preparation().map_err(fail)?;Ok(owner)
    }
}
impl Drop for Watchdog {fn drop(&mut self){unsafe{libc::timer_delete(self.0);}}}
fn inherited()->Result<BTreeSet<i32>,ShadowError> {
    require(cfg!(target_arch="x86_64") && std::env::args_os().count()==1 && std::env::vars_os().next().is_none()
        && unsafe{libc::getuid()}==0 && unsafe{libc::geteuid()}==0)?;
    let core=libc::rlimit{rlim_cur:0,rlim_max:0};
    require(unsafe{libc::setrlimit(libc::RLIMIT_CORE,&core)}==0
        && unsafe{libc::prctl(libc::PR_SET_DUMPABLE,0)}==0)?;
    // A failed private gate write must take the owned PIDFD cleanup path,
    // not asynchronously bypass it via inherited/default SIGPIPE behavior.
    let mut pipe_action:libc::sigaction=unsafe{std::mem::zeroed()};
    pipe_action.sa_sigaction=libc::SIG_IGN;
    require(unsafe{libc::sigemptyset(&mut pipe_action.sa_mask)}==0
        && unsafe{libc::sigaction(libc::SIGPIPE,&pipe_action,std::ptr::null_mut())}==0)?;
    let status=std::fs::read_to_string("/proc/self/status").map_err(fail)?;
    let threads:Vec<_>=status.lines().filter_map(|v|v.strip_prefix("Threads:")).collect();
    require(threads.len()==1 && threads[0].trim()=="1")?;
    let mut present=BTreeSet::new();
    for entry in std::fs::read_dir("/proc/self/fd").map_err(fail)? {
        let name=entry.map_err(fail)?.file_name();
        present.insert(name.to_str().ok_or(ShadowError::BindingDrift)?.parse::<i32>().map_err(fail)?);
    }
    let mut inherited=BTreeSet::new();
    for fd in present {
        if unsafe{libc::fcntl(fd,libc::F_GETFD)}<0 {
            require(std::io::Error::last_os_error().raw_os_error()==Some(libc::EBADF))?;continue;
        }
        require(fd<=2 || (6..=69).contains(&fd))?;inherited.insert(fd);
    }
    Ok(inherited)
}
struct Running {
    // Drop child first: its Drop refuses process continuation without actual
    // same-PIDFD reap. Thus the image/originals cannot retire under a live child.
    child:child::Child,image:image::Image,files:FileAdmission,activation:BTreeMap<String,OwnedFd>,
    launch:Original,launch_bytes:Vec<u8>,_watchdog:Watchdog,inspector:Option<Inspection>,
}
enum Inspection {Server(retrieval_peer::Inspector),Client(retrieval_client::Inspector),ProofClient(proof_client::Inspector)}
impl Inspection {
    fn progress(&mut self,child:&child::Child,files:&FileAdmission)->Result<(),ShadowError> {
        match self {
            Self::Server(v)=>v.progress(child,files.lifetime(),files.payload.uid,files.payload.gid),
            Self::Client(v)=>v.progress(child,files),
            Self::ProofClient(v)=>v.progress(child,files),
        }
    }
}
impl Running {
    fn start()->Result<Self,ShadowError> {
        Self::start_selected(false)
    }
    fn start_selected(require_genesis:bool)->Result<Self,ShadowError>{
        let inherited=inherited()?;
        let launch=Original::native_launch().map_err(fail)?;
        let launch_bytes=launch.read(32768).map_err(fail)?.to_vec();
        let (selected,service_selection)=selection(&launch_bytes)?;
        require(!require_genesis || matches!(&service_selection,SelectedService::PublicationGenesisCoordinator))?;
        let files=admit_files(&selected.delivery_configuration.path,selected.delivery_configuration.sha256,
            &selected.delivery.path,selected.delivery.sha256).map_err(fail)?;
        require(inherited.iter().filter(|fd|**fd>=6).copied().eq(6..6+files.payload.activation.len() as i32)
            && now()?.checked_add(REAP_RESERVE_NS).ok_or(ShadowError::BindingDrift)?<files.lifetime())?;
        // Arm the ORIGINAL absolute deadline before image, loop or mount work.
        let watchdog=Watchdog::arm(&files)?;
        if service_selection.endpoint_runtime_role().is_some(){
            service_selection.check_endpoint_runtime(&files.retrieval_client_runtime().map_err(fail)?)?;
        }
        let native_lock=match &service_selection {
            SelectedService::PersistenceLocked(_)|SelectedService::AdoptedPersistence(_)=>Some(super::super::NativeLock::Persistence),
            SelectedService::AdoptedPublicationRetrieval(_)=>Some(super::super::NativeLock::AdoptedLedger),
            SelectedService::LedgerRetrieval(_)|SelectedService::CompletionRetrieval(_)|SelectedService::EffectRetrieval(_)|SelectedService::PublicationRetrieval(_)|SelectedService::PublicationGenesisRetrieval(_)=>Some(super::super::NativeLock::Ledger),
            _=>None,
        };
        let (activation,_)=take_activation(&files.payload.activation,false,false,false,false,false,false,native_lock).map_err(fail)?;
        let genesis_coordinator=matches!(&service_selection,SelectedService::PublicationGenesisCoordinator);
        if genesis_coordinator{
            require(files.payload.activation.len()==10
                && files.payload.activation[9].name==super::super::super::publication_genesis_client::RESULT_PARENT_FD
                && files.payload.activation[9].fd==15)?;
        }
        process::isolate_mounts()?;
        let image=image::Image::prepare(&selected.closure,&files,service_selection.closure_set_role())?;
        let (inspector,inspection)=match service_selection {
            SelectedService::PublicationGenesisCoordinator=>{
                let (owner,channel)=proof_client::Inspector::prepare_genesis(&files,&activation)?;
                (Some(Inspection::ProofClient(owner)),Some(channel))
            }
            service @ (SelectedService::LedgerRetrieval(_)|SelectedService::LedgerSpool(_)|SelectedService::Ingress(_)|SelectedService::SpoolBridge(_)
                |SelectedService::CompletionRetrieval(_)|SelectedService::CompletionLedgerSpool(_)|SelectedService::TerminalSpool(_)|SelectedService::TerminalBridge(_)
                |SelectedService::EffectRetrieval(_)|SelectedService::ActiveEffectBridge(_)|SelectedService::InitialHistoryBridge(..)|SelectedService::DispatchSpool(_)
                |SelectedService::ActiveEffectBarrier(_)|SelectedService::ActiveEffectCommit(_)
                |SelectedService::Publication(_)|SelectedService::PublicationRetrieval(_)|SelectedService::PublicationBridge(..)
                |SelectedService::AdoptedPublication(_)|SelectedService::AdoptedPublicationRetrieval(_)|SelectedService::AdoptedPersistence(_)
                |SelectedService::PublicationGenesis(_)|SelectedService::PublicationGenesisRetrieval(_))=>{
                let (owner,channel)=proof_cohort::prepare_inspection(service,&files,&activation)?;
                (Some(owner),Some(channel))
            }
            SelectedService::Generation(pin)=>{
                require(activation.len()==2 && activation.contains_key("shadow-generation-install-listener")
                    && activation.contains_key("generation-install-journal"))?;
                let original=pin.open(admission::generation_install::MAX_CONFIGURATION)?;
                let configuration:admission::generation_install::Configuration=exact(&original.read(admission::generation_install::MAX_CONFIGURATION).map_err(fail)?)?;
                configuration.validate_shape()?;
                let (owner,channel)=retrieval_peer::Inspector::prepare_history_endpoint(original,
                    configuration.expected_peer().checked().map_err(fail)?,configuration.guest_uid(),
                    activation.get("shadow-generation-install-listener").ok_or(ShadowError::BindingDrift)?,retrieval_peer::EndpointKind::GenerationInstallEnvelope)?;
                (Some(Inspection::Server(owner)),Some(channel))
            }
            SelectedService::Retrieval(pin)=>{
                require(activation.len()==2 && activation.contains_key("retrieval-listener")
                    && activation.contains_key("retrieval-objects"))?;
                let (owner,channel)=retrieval_peer::Inspector::prepare(&pin,&activation)?;
                (Some(Inspection::Server(owner)),Some(channel))
            }
            SelectedService::RetrievalBridge=>{
                let (owner,channel)=retrieval_client::Inspector::prepare(&files,&activation)?;
                (Some(Inspection::Client(owner)),Some(channel))
            }
            SelectedService::Persistence(pin)=>{
                require(activation.len()==2 && activation.contains_key("persistence-listener")
                    && activation.contains_key("persistence-journal"))?;
                let original=pin.open(65536)?;
                let configuration:admission::persistence::Configuration=exact(&original.read(65536).map_err(fail)?)?;
                configuration.validate_shape()?;
                let expected=configuration.expected_peer().checked().map_err(fail)?;
                let (owner,channel)=retrieval_peer::Inspector::prepare_endpoint(original,expected,configuration.guest_uid(),
                    activation.get("persistence-listener").ok_or(ShadowError::BindingDrift)?,retrieval_peer::EndpointKind::Persistence)?;
                (Some(Inspection::Server(owner)),Some(channel))
            }
            SelectedService::PersistenceLocked(pin)=>{
                require(activation.len()==3 && activation.contains_key("persistence-listener")
                    && activation.contains_key("persistence-journal") && activation.contains_key("persistence-lock"))?;
                let original=pin.open(65536)?;
                let configuration:admission::persistence::Configuration=exact(&original.read(65536).map_err(fail)?)?;
                configuration.validate_shape()?;
                let expected=configuration.expected_peer().checked().map_err(fail)?;
                let (owner,channel)=retrieval_peer::Inspector::prepare_endpoint(original,expected,configuration.guest_uid(),
                    activation.get("persistence-listener").ok_or(ShadowError::BindingDrift)?,retrieval_peer::EndpointKind::Persistence)?;
                (Some(Inspection::Server(owner)),Some(channel))
            }
            SelectedService::TrustedTime(pin)=>{
                require(activation.len()==1)?;
                let original=pin.open(65536)?;
                let config:admission::trusted_time::Configuration=exact(&original.read(65536).map_err(fail)?)?;
                config.validate_shape()?;
                let socket=activation.get("trusted-time-listener").ok_or(ShadowError::BindingDrift)?;
                let (owner,channel)=retrieval_peer::Inspector::prepare_endpoint(original,
                    config.expected_peer().checked().map_err(fail)?,config.guest_uid(),socket,retrieval_peer::EndpointKind::TrustedTime)?;
                (Some(Inspection::Server(owner)),Some(channel))
            }
            SelectedService::ProofBridge(_)=>{
                let (owner,channel)=proof_client::Inspector::prepare(&files,&activation)?;
                (Some(Inspection::ProofClient(owner)),Some(channel))
            }
            SelectedService::CommitmentBridge(_)=>{
                let (owner,channel)=proof_client::Inspector::prepare_selected(&files,&activation,true)?;
                (Some(Inspection::ProofClient(owner)),Some(channel))
            }
            SelectedService::CommitRequest(pin)=>{
                require(activation.len()==1)?;
                let original=pin.open(admission::commit_request::MAX_CONFIGURATION)?;
                let config:admission::commit_request::Configuration=exact(&original.read(admission::commit_request::MAX_CONFIGURATION).map_err(fail)?)?;
                config.validate_shape()?;
                let (owner,channel)=retrieval_peer::Inspector::prepare_history_endpoint(original,config.expected_peer().checked().map_err(fail)?,
                    config.guest_uid(),activation.get("commit-request-listener").ok_or(ShadowError::BindingDrift)?,
                    retrieval_peer::EndpointKind::CommitRequest)?;
                (Some(Inspection::Server(owner)),Some(channel))
            }
            SelectedService::None=>(None,None),
            SelectedService::Activation(_)=>{
                require(activation.len()==2 && activation.contains_key("activation-channel")
                    && activation.contains_key("activation-journal"))?;
                (None,None)
            }
        };
        let child_entries=if genesis_coordinator{&files.payload.activation[..9]}else{files.payload.activation.as_slice()};
        let ordered=child_entries.iter().map(|entry| {
            activation.get(&entry.name).map(AsFd::as_fd).ok_or(ShadowError::BindingDrift)
        }).collect::<Result<Vec<_>,_>>()?;
        files.check_preparation().map_err(fail)?;
        require(now()?.checked_add(REAP_RESERVE_NS).ok_or(ShadowError::BindingDrift)?<files.lifetime())?;
        let child=child::Child::spawn(image.executable(),&ordered,inspection.as_ref().map(AsFd::as_fd),files.lifetime())?;
        drop(inspection);
        let mut owner=Self{child,image,files,activation,launch,launch_bytes,_watchdog:watchdog,inspector};
        let admitted=owner.check_originals()
            .and_then(|()|owner.files.check_preparation().map_err(fail))
            .and_then(|()|owner.child.release());
        if let Err(error)=admitted {
            // The cold controller must retain even a partially started real
            // child when its one bounded cleanup attempt cannot prove reap.
            // Other entrypoints retain their existing Drop behavior.
            if require_genesis && owner.child.stop_and_reap().is_err(){
                genesis_controller::retain_uncertain(GenesisParent{running:Some(owner)},None);
            }
            return Err(error);
        }
        Ok(owner)
    }
    fn check_originals(&self)->Result<(),ShadowError> {
        self.files.check().map_err(fail)?;self.image.check(&self.files)?;
        require(self.launch.read(32768).map_err(fail)?.as_slice()==self.launch_bytes.as_slice())?;
        for entry in &self.files.payload.activation {
            let fd=self.activation.get(&entry.name).ok_or(ShadowError::BindingDrift)?;
            let mut stat:libc::stat=unsafe{std::mem::zeroed()};
            require(unsafe{libc::fstat(fd.as_raw_fd(),&mut stat)}==0
                && (stat.st_dev,stat.st_ino,stat.st_mode,stat.st_uid,stat.st_gid)
                    ==(entry.device,entry.inode,entry.mode,entry.uid,entry.gid))?;
        }
        Ok(())
    }
    fn hold(mut self)->Result<(),ShadowError> {
        loop {
            self.check_originals()?;
            if now()?>=self.files.lifetime()-REAP_RESERVE_NS || !self.child.check()? {break;}
            if let Some(inspector)=&mut self.inspector {
                inspector.progress(&self.child,&self.files)?;
            }
            let result=unsafe{libc::poll(std::ptr::null_mut(),0,25)};
            require(result==0 || (result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR)))?;
        }
        self.child.stop_and_reap()?;
        // No ready/result/success frame exists. This only retires an actually
        // reaped child; loop autoclear/root-FD release is not claimed verified.
        Ok(())
    }
}
/// Callable cold parent handoff, deliberately separate from the ordinary
/// no-result entrypoint. Receiving evidence does not install a policy or retire
/// any peer. The caller must keep this owner and invoke its bounded close.
pub(in crate::policy_shadow::policy_custody::services) struct GenesisParent {running:Option<Running>}
impl GenesisParent {
    pub(in crate::policy_shadow::policy_custody::services) fn start()->Result<Self,ShadowError>{
        Ok(Self{running:Some(Running::start_selected(true)?)})
    }
    pub(in crate::policy_shadow::policy_custody::services) fn run_until_genesis_handoff(&mut self)->Result<Vec<u8>,ShadowError>{
        self.run_until_genesis_handoff_checked(||Ok(()))
    }
    fn run_until_genesis_handoff_checked(&mut self,mut check:impl FnMut()->Result<(),ShadowError>)->Result<Vec<u8>,ShadowError>{
        let running=self.running.as_mut().ok_or(ShadowError::BindingDrift)?;
        loop {
            check()?;
            running.check_originals()?;require(running.child.check()?)?;
            let Some(Inspection::ProofClient(inspector))=running.inspector.as_mut() else{return Err(ShadowError::BindingDrift);};
            require(now()?<inspector.genesis_deadline()?
                && now()?.checked_add(REAP_RESERVE_NS).ok_or(ShadowError::CounterOverflow)?<running.files.lifetime())?;
            inspector.progress(&running.child,&running.files)?;
            let deadline=inspector.genesis_deadline()?;
            running.check_originals()?;
            require(now()?<deadline
                && now()?.checked_add(REAP_RESERVE_NS).ok_or(ShadowError::CounterOverflow)?<running.files.lifetime())?;
            let Some(Inspection::ProofClient(inspector))=running.inspector.as_mut() else{return Err(ShadowError::BindingDrift);};
            if let Some(bundle)=inspector.take_genesis_result()?{check()?;return Ok(bundle);}
            let result=unsafe{libc::poll(std::ptr::null_mut(),0,1)};
            require(result==0 || (result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR)))?;
        }
    }
    pub(in crate::policy_shadow::policy_custody::services) fn close(&mut self)->Result<(),ShadowError>{
        // An uncertain reap keeps every original, PIDFD and watchdog in this
        // owner. Taking first would invoke Drop on the error path instead.
        if let Some(running)=self.running.as_mut(){running.child.stop_and_reap()?;}
        self.running.take();
        Ok(())
    }
}
pub(super) fn run_genesis_controller()->! {genesis_controller::run()}
pub(super) fn run()->! {
    let _=Running::start().and_then(Running::hold);
    unsafe{libc::_exit(1)}
}
pub(super) fn run_pair()->! {pair::run()}
pub(super) fn run_proof_cohort()->! {proof_cohort::run()}
