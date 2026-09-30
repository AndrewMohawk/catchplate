//! Private inherited router endpoint. This is not a general measurement RPC.
use super::wire::{self, require, Bootstrap, Operation, Phase, Request};
use super::super::{guest_delivery, peer_measurement as peer,
    RootOwnedResponseObservationV2Config as Config, V2RuntimeError};
use serde::{Deserialize, Serialize};
use std::{fs::File, io, mem::{size_of, zeroed}, os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::fs::{FileExt, MetadataExt}, sync::{Arc, Mutex, TryLockError, atomic::{AtomicBool, Ordering}},
    time::Duration};

const INSPECTOR: u32 = 64990;
const SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
fn error(value: impl std::fmt::Display) -> io::Error { io::Error::other(value.to_string()) }
fn now() -> io::Result<u64> { super::super::recovery::boottime_ns().map_err(error) }
fn runtime(value: io::Error) -> V2RuntimeError { V2RuntimeError::new("guest_inspector_unavailable", value.to_string()) }

struct BootstrapOriginal { file:File, bytes:Vec<u8>, identity:(u64,u64,u32,u32,u32), value:Bootstrap }
impl BootstrapOriginal {
    fn open(file:File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        require(metadata.is_file() && metadata.uid() == 0 && metadata.gid() == 0
            && metadata.mode() & 0o7777 == 0o600 && metadata.nlink() == 0
            && metadata.len() > 0 && metadata.len() <= wire::MAX_BOOTSTRAP as u64
            && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS,
            "router bootstrap is not the original sealed worker input")?;
        let mut bytes = vec![0;metadata.len() as usize]; file.read_exact_at(&mut bytes,0)?;
        let value:Bootstrap = crate::decode_canonical_json(&bytes).map_err(error)?;
        value.validate()?;
        let original = Self { file,bytes,value,
            identity:(metadata.dev(),metadata.ino(),metadata.mode(),metadata.uid(),metadata.gid()) };
        original.check()?; Ok(original)
    }
    fn check(&self) -> io::Result<()> {
        let m = self.file.metadata()?;
        require((m.dev(),m.ino(),m.mode(),m.uid(),m.gid()) == self.identity && m.nlink() == 0
            && m.len() == self.bytes.len() as u64
            && unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GET_SEALS) } == SEALS,
            "router bootstrap original changed")?;
        let mut bytes = vec![0;self.bytes.len()]; self.file.read_exact_at(&mut bytes,0)?;
        require(bytes == self.bytes, "router bootstrap bytes changed")
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Measurement {
    process_binding_sha256:String, uid:u32, gid:u32, cgroup_sha256:String,
    security_label_sha256:String, executable_sha256:String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Response { api_version:String, request:Request, measurement:Measurement }
struct State { sequence:u64 }
pub(crate) struct Client {
    pid:libc::pid_t, channel:OwnedFd, inspector:OwnedFd, inspector_process:peer::StableProcessIdentity,
    bootstrap:BootstrapOriginal, delivery:Arc<guest_delivery::Delivery>, lifetime:u64,
    state:Mutex<State>, poisoned:AtomicBool,
}
impl std::fmt::Debug for Client {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("GuestInspectorClient(retained-private-owner)") }
}
// Only exchange() constructs this owner after real response sender/PIDFD and
// target-original checks. Never deserialize an opaque host PeerMeasurement.
pub(crate) struct Observation {
    measurement:Measurement, process:peer::StableProcessIdentity, credentials:libc::ucred,
}
impl Observation {
    pub(crate) fn uid(&self)->u32 { self.measurement.uid }
    pub(crate) fn process_binding_sha256(&self)->&str { &self.measurement.process_binding_sha256 }
    pub(crate) fn cgroup(&self)->&str { &self.measurement.cgroup_sha256 }
    pub(crate) fn label(&self)->&str { &self.measurement.security_label_sha256 }
    pub(crate) fn executable(&self)->&str { &self.measurement.executable_sha256 }
    pub(crate) fn matches(&self,value:&libc::ucred)->bool {
        self.credentials.pid == value.pid && self.credentials.uid == value.uid && self.credentials.gid == value.gid
    }
}

/// Called only after the exact signed guest loader and listener owner attach.
/// The cohort factory exports B's non-Clone actual endpoint once into 8/9/10.
pub(crate) fn attach(config:&mut Config) -> Result<(),V2RuntimeError> {
    let result = (|| {
        require(config.guest_listener.is_some() && config.guest_listener_owner.is_some()
            && config.guest_inspector_client.is_none(), "inspector requires genuine guest listener ownership")?;
        let delivery = Arc::clone(config.guest_delivery.as_ref().ok_or_else(|| error("guest delivery owner absent"))?);
        let binding = delivery.listener_binding().map_err(error)?;
        require(unsafe { libc::getuid() } == binding.router_uid && unsafe { libc::geteuid() } == binding.router_uid
            && unsafe { libc::getgid() } == binding.router_gid && unsafe { libc::getegid() } == binding.router_gid,
            "inspector endpoint must be consumed by the actual signed final router")?;
        for fd in 8..=10 {
            let flags = unsafe { libc::fcntl(fd,libc::F_GETFD) };
            require(flags >= 0 && flags & libc::FD_CLOEXEC != 0,
                "inherited inspector descriptor is not protected")?;
        }
        let channel = unsafe { OwnedFd::from_raw_fd(8) };
        let inspector = unsafe { OwnedFd::from_raw_fd(9) };
        let bootstrap = BootstrapOriginal::open(unsafe { File::from_raw_fd(10) })?;
        require(bootstrap.value.configuration_sha256 == binding.configuration_sha256
            && bootstrap.value.delivery_sha256 == binding.delivery_sha256,
            "inspector bootstrap differs from actual signed router originals")?;
        // Cached SO_PEERCRED describes the socketpair creator, NOT inspector.
        super::socket(channel.as_raw_fd())?;
        let actual = peer::capture_received_pidfd(&inspector)?;
        require(actual.pid() != unsafe { libc::getpid() }, "router cannot inspect through itself")?;
        for name in [libc::SO_PASSCRED,76] {
            let one:i32 = 1;
            require(unsafe { libc::setsockopt(channel.as_raw_fd(),libc::SOL_SOCKET,name,
                (&one as *const i32).cast(),size_of::<i32>() as libc::socklen_t) } == 0,
                "enable actual inspector packet identity")?;
        }
        let flags = unsafe { libc::fcntl(channel.as_raw_fd(),libc::F_GETFL) };
        require(flags >= 0 && unsafe { libc::fcntl(channel.as_raw_fd(),libc::F_SETFL,flags|libc::O_NONBLOCK) } == 0,
            "protect inspector channel IO")?;
        let lifetime = wire::ns(&bootstrap.value.gate_lifetime_deadline_boottime_ns)?;
        let client = Arc::new(Client { pid:unsafe { libc::getpid() },channel,inspector,inspector_process:actual,
            bootstrap,delivery,lifetime,state:Mutex::new(State { sequence:1 }),poisoned:AtomicBool::new(false) });
        client.check()?;
        config.guest_inspector_client = Some(client);
        Ok(())
    })();
    result.map_err(runtime)
}
pub(crate) fn require_attached(config:&Config) -> Result<(),V2RuntimeError> {
    if config.guest_listener.is_some() {
        let owner = config.guest_inspector_client.as_ref()
            .ok_or_else(|| V2RuntimeError::new("guest_inspector_absent","guest router requires actual inherited inspector"))?;
        let delivery = config.guest_delivery.as_ref()
            .ok_or_else(|| V2RuntimeError::new("guest_delivery_absent","guest router delivery absent"))?;
        if !Arc::ptr_eq(delivery,&owner.delivery) { return Err(V2RuntimeError::new("guest_inspector_owner","guest delivery owner differs")); }
        owner.check().map_err(runtime)?;
    } else if config.guest_inspector_client.is_some() {
        return Err(V2RuntimeError::new("guest_inspector_profile","host profile cannot acquire a guest inspector"));
    }
    Ok(())
}

impl Client {
    fn fail(&self) {
        self.poisoned.store(true,Ordering::Release);
        unsafe { libc::shutdown(self.channel.as_raw_fd(),libc::SHUT_RDWR); }
    }
    pub(crate) fn check(&self)->io::Result<()> {
        let result = (|| {
            require(!self.poisoned.load(Ordering::Acquire) && unsafe { libc::getpid() } == self.pid
                && now()? < self.lifetime, "private inspector owner ended")?;
            self.delivery.check().map_err(error)?; self.bootstrap.check()?;
            require(peer::capture_received_pidfd(&self.inspector)? == self.inspector_process,
                "original inspector process changed")
        })();
        if result.is_err() { self.fail(); }
        result
    }
    fn remaining(&self,deadline:u64)->io::Result<u64> {
        self.check()?;
        let deadline = deadline.min(self.lifetime);
        deadline.checked_sub(now()?).filter(|n| *n > 0).ok_or_else(|| error("original inspection deadline ended"))
    }
    fn wait(&self,event:i16,deadline:u64)->io::Result<()> {
        loop {
            let remaining = self.remaining(deadline)?;
            let mut fds = [
                libc::pollfd { fd:self.channel.as_raw_fd(),events:event,revents:0 },
                libc::pollfd { fd:self.inspector.as_raw_fd(),events:libc::POLLIN,revents:0 }];
            let ms = (remaining / 1_000_000).clamp(1,100) as i32;
            require(unsafe { libc::poll(fds.as_mut_ptr(),2,ms) } >= 0
                && fds[1].revents == 0 && fds[0].revents & !event == 0, "private inspector IO owner ended")?;
            self.remaining(deadline)?;
            if fds[0].revents == event { return Ok(()); }
        }
    }
    pub(crate) fn connection(&self,socket:RawFd,pidfd:&OwnedFd,deadline:u64)->io::Result<Observation> {
        self.exchange(socket,pidfd,None,None,None,None,false,deadline)
    }
    pub(crate) fn packet(&self,socket:RawFd,pidfd:&OwnedFd,sender:&OwnedFd,credentials:&libc::ucred,expected:&Observation,
        frame:&[u8],session:Option<&str>,index:u16,response:bool,deadline:u64)->io::Result<()> {
        if !expected.matches(credentials) {
            self.fail(); return Err(error("actual guest packet credentials differ"));
        }
        let observed = self.exchange(socket,pidfd,Some(sender),Some(frame),session,Some(index),response,deadline)?;
        if observed.process != expected.process || observed.measurement != expected.measurement
            || !expected.matches(&observed.credentials) {
            self.fail(); return Err(error("guest measurement changed since authenticated connection"));
        }
        Ok(())
    }
    fn exchange(&self,socket:RawFd,pidfd:&OwnedFd,sender:Option<&OwnedFd>,frame:Option<&[u8]>,
        session:Option<&str>,index:Option<u16>,response:bool,deadline:u64)->io::Result<Observation> {
        let result = (|| {
            self.remaining(deadline)?;
            let mut state = loop {
                match self.state.try_lock() {
                    Ok(value)=>break value,
                    Err(TryLockError::Poisoned(_))=>return Err(error("inspector channel lock poisoned")),
                    Err(TryLockError::WouldBlock)=>{
                        let remaining = self.remaining(deadline)?;
                        std::thread::sleep(Duration::from_nanos(remaining.min(1_000_000)));
                    }
                }
            };
            let credentials = peer::socket_peer_credentials(socket)?;
            require(credentials.uid == 65534 && credentials.gid == 65534, "guest target is not final gate identity")?;
            let process = peer::capture_pidfd_process_identity(pidfd,credentials.pid)?;
            let actual = peer::open_peer_pidfd(socket)?;
            require(peer::prove_pidfds_same_process(pidfd,&actual,credentials.pid)? == process,
                "accepted socket differs from retained gate")?;
            if let Some(sender)=sender {
                require(peer::prove_pidfds_same_process(pidfd,sender,credentials.pid)? == process,
                    "packet differs from retained gate")?;
            }
            let request = Request { api_version:"serverware.responseV2.guestInspectorRequest/v1".to_owned(),
                channel_nonce:self.bootstrap.value.channel_nonce.clone(),request_sequence:state.sequence,
                phase:if sender.is_some() { Phase::Packet } else { Phase::Connection },
                frame_sha256:frame.map(wire::digest),
                operation:if sender.is_none() { Operation::Connection } else if response { Operation::BeforeResponse } else { Operation::BeforeDispatch },
                session_id:session.map(str::to_owned),sequence:index,deadline_boottime_ns:deadline.min(self.lifetime).to_string() };
            request.validate(&self.bootstrap.value.channel_nonce,state.sequence,self.lifetime,now()?)?;
            let bytes = crate::canonical_json_bytes(&request).map_err(error)?;
            let mut files = vec![socket,pidfd.as_raw_fd()];
            if let Some(sender)=sender { files.push(sender.as_raw_fd()); }
            self.wait(libc::POLLOUT,deadline)?;
            send(self.channel.as_raw_fd(),&bytes,&files)?;
            self.wait(libc::POLLIN,deadline)?;
            let (bytes,credentials_of_inspector,inspector_sender) = receive(self.channel.as_raw_fd())?;
            require(credentials_of_inspector.uid == INSPECTOR && credentials_of_inspector.gid == INSPECTOR
                && credentials_of_inspector.pid == self.inspector_process.pid()
                && peer::prove_pidfds_same_process(&self.inspector,&inspector_sender,credentials_of_inspector.pid)? == self.inspector_process,
                "response is not from retained final inspector")?;
            let result:Response = crate::decode_canonical_json(&bytes).map_err(error)?;
            require(result.api_version == "serverware.responseV2.guestInspectorResult/v1"
                && crate::canonical_json_bytes(&result.request).map_err(error)? == crate::canonical_json_bytes(&request).map_err(error)?
                && result.measurement.uid == credentials.uid && result.measurement.gid == credentials.gid
                && result.measurement.process_binding_sha256 == process.binding_sha256(),
                "inspection response/context/target original differs")?;
            for digest in [&result.measurement.cgroup_sha256,&result.measurement.security_label_sha256,&result.measurement.executable_sha256] {
                require(digest.len() == 71 && digest.starts_with("sha256:")
                    && digest[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && digest[7..].bytes().any(|b| b != b'0'), "invalid actual measurement digest")?;
            }
            require(peer::capture_pidfd_process_identity(pidfd,credentials.pid)? == process
                && peer::prove_pidfds_same_process(pidfd,&actual,credentials.pid)? == process,
                "gate identity changed during inspection")?;
            if let Some(sender)=sender { require(peer::prove_pidfds_same_process(pidfd,sender,credentials.pid)? == process,"packet identity changed")?; }
            self.remaining(deadline)?;
            state.sequence = state.sequence.checked_add(1).ok_or_else(|| error("inspector channel sequence exhausted"))?;
            Ok(Observation { measurement:result.measurement,process,credentials })
        })();
        if result.is_err() { self.fail(); }
        result
    }
}

fn send(fd:RawFd,bytes:&[u8],files:&[RawFd])->io::Result<()> {
    require(bytes.len() <= wire::MAX_FRAME && (files.len() == 2 || files.len() == 3),"inspector request bounds")?;
    let descriptor_bytes=files.len()*size_of::<RawFd>();
    let descriptor_length=u32::try_from(descriptor_bytes).map_err(|_| error("inspector descriptor length exceeds ABI"))?;
    let mut ancillary = [0usize;8];
    let mut vector = libc::iovec { iov_base:bytes.as_ptr() as *mut libc::c_void,iov_len:bytes.len() };
    let mut message:libc::msghdr = unsafe { zeroed() };
    message.msg_iov=&mut vector; message.msg_iovlen=1;
    message.msg_control=ancillary.as_mut_ptr().cast();
    message.msg_controllen=unsafe { libc::CMSG_SPACE(descriptor_length) }.try_into()
        .map_err(|_| error("inspector control length exceeds ABI"))?;
    let header=unsafe { libc::CMSG_FIRSTHDR(&message) };
    require(!header.is_null(),"inspector ancillary layout")?;
    unsafe {
        (*header).cmsg_level=libc::SOL_SOCKET; (*header).cmsg_type=libc::SCM_RIGHTS;
        (*header).cmsg_len=libc::CMSG_LEN(descriptor_length).try_into()
            .map_err(|_| error("inspector header length exceeds ABI"))?;
        std::ptr::copy_nonoverlapping(files.as_ptr().cast::<u8>(),libc::CMSG_DATA(header),descriptor_bytes);
    }
    require(unsafe { libc::sendmsg(fd,&message,libc::MSG_DONTWAIT|libc::MSG_NOSIGNAL) } == bytes.len() as isize,
        "inspection request uncertain; no resend")
}
fn receive(fd:RawFd)->io::Result<(Vec<u8>,libc::ucred,OwnedFd)> {
    let mut bytes=vec![0;wire::MAX_FRAME+1]; let mut ancillary=[0usize;128];
    let mut vector=libc::iovec { iov_base:bytes.as_mut_ptr().cast(),iov_len:bytes.len() };
    let mut message:libc::msghdr=unsafe { zeroed() };
    message.msg_iov=&mut vector; message.msg_iovlen=1; message.msg_control=ancillary.as_mut_ptr().cast();
    message.msg_controllen=std::mem::size_of_val(&ancillary).try_into()
        .map_err(|_| error("inspector receive control capacity exceeds ABI"))?;
    let count=unsafe { libc::recvmsg(fd,&mut message,libc::MSG_DONTWAIT|libc::MSG_CMSG_CLOEXEC) };
    if count < 0 { return Err(io::Error::last_os_error()); }
    let mut bad=false; let mut sender=Vec::new(); let mut credentials=Vec::new(); let mut rejected=Vec::new();
    let mut header=unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let h=unsafe { &*header }; let base=unsafe { libc::CMSG_LEN(0) } as usize;
        let header_length=h.cmsg_len as usize;
        if header_length < base { bad=true; break; }
        let length=header_length-base; let data=unsafe { libc::CMSG_DATA(header) };
        if h.cmsg_level==libc::SOL_SOCKET && (h.cmsg_type==libc::SCM_RIGHTS || h.cmsg_type==4) {
            if h.cmsg_type==libc::SCM_RIGHTS || length != size_of::<RawFd>() { bad=true; }
            for n in 0..length/size_of::<RawFd>() {
                let raw=unsafe { std::ptr::read_unaligned(data.add(n*size_of::<RawFd>()).cast::<RawFd>()) };
                if raw<0 { bad=true; continue; }
                let owned=unsafe { OwnedFd::from_raw_fd(raw) };
                if !peer::received_fd_is_cloexec(raw) { bad=true; }
                if h.cmsg_type==4 { sender.push(owned); } else { rejected.push(owned); }
            }
        } else if h.cmsg_level==libc::SOL_SOCKET && h.cmsg_type==libc::SCM_CREDENTIALS && length==size_of::<libc::ucred>() {
            credentials.push(unsafe { std::ptr::read_unaligned(data.cast::<libc::ucred>()) });
        } else { bad=true; }
        header=unsafe { libc::CMSG_NXTHDR(&message,header) };
    }
    require(!bad && count>0 && count as usize<=wire::MAX_FRAME
        && message.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)==0
        && sender.len()==1 && credentials.len()==1 && rejected.is_empty(),"invalid inspection response ancillary or bytes")?;
    bytes.truncate(count as usize);
    Ok((bytes,credentials.pop().unwrap(),sender.pop().unwrap()))
}
