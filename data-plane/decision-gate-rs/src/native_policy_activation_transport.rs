//! Fixed inherited public-data transport. Signatures and the native activation
//! verifier confer authority; socket credentials/shape do not. No confidentiality,
//! generic peer attestation, receipt verification or retry is asserted here.
use crate::native_serving_privileges::{Association,Prepared as ServingPreparation,Owner as ServingOwner};
use serde::{Serialize,Deserialize};
use std::os::fd::{AsFd,AsRawFd,BorrowedFd,FromRawFd,OwnedFd};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{FileExt,MetadataExt};
use std::sync::Arc;
#[path="native_policy_activation_stream.rs"]
mod stream;
const FD:i32=70;
const MAXIMUM:usize=8*1024*1024;
const MAX_PUBLICATION:usize=32768;
const API:&str="serverware.nativePolicyActivationChannelRequest/v1";
const SEALS:i32=libc::F_SEAL_SEAL|libc::F_SEAL_SHRINK|libc::F_SEAL_GROW|libc::F_SEAL_WRITE;
fn require(value:bool)->Result<(),String>{if value{Ok(())}else{Err("native activation public channel unavailable".into())}}
fn now()->Result<u64,String>{crate::native_canary_evidence_v1::now_boot()}
fn canonical<T:Serialize>(value:&T)->Result<Vec<u8>,String>{
    crate::native_response_profile_v1::canonical_ascii_bytes(&serde_json::to_value(value).map_err(|_|"activation JSON")?)
}
fn parse<T:serde::de::DeserializeOwned+Serialize>(raw:&[u8],maximum:usize)->Result<T,String>{
    require(!raw.is_empty() && raw.len()<=maximum && raw.is_ascii())?;
    let value:T=serde_json::from_slice(raw).map_err(|_|"activation channel frame")?;require(canonical(&value)?==raw)?;Ok(value)
}
#[derive(Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Identity{device:u64,inode:u64,mode:u32,uid:u32,gid:u32}
fn identity(fd:BorrowedFd<'_>)->Result<Identity,String>{
    let mut s:libc::stat=unsafe{std::mem::zeroed()};require(unsafe{libc::fstat(fd.as_raw_fd(),&mut s)}==0)?;
    Ok(Identity{device:s.st_dev,inode:s.st_ino,mode:s.st_mode,uid:s.st_uid,gid:s.st_gid})
}
pub fn validate_channel(fd:BorrowedFd<'_>)->Result<(),String>{
    for(option,expected)in [(libc::SO_TYPE,libc::SOCK_SEQPACKET),(libc::SO_DOMAIN,libc::AF_UNIX),(libc::SO_ACCEPTCONN,0)]{
        let mut actual=0i32;let mut len=std::mem::size_of::<i32>() as libc::socklen_t;
        require(unsafe{libc::getsockopt(fd.as_raw_fd(),libc::SOL_SOCKET,option,(&mut actual as *mut i32).cast(),&mut len)}==0
            && len as usize==std::mem::size_of::<i32>() && actual==expected)?;
    }
    let mut address:libc::sockaddr_un=unsafe{std::mem::zeroed()};let mut len=std::mem::size_of_val(&address) as libc::socklen_t;
    require(unsafe{libc::getpeername(fd.as_raw_fd(),(&mut address as *mut libc::sockaddr_un).cast(),&mut len)}==0
        && address.sun_family==libc::AF_UNIX as libc::sa_family_t)?;
    require(identity(fd)?.mode&libc::S_IFMT==libc::S_IFSOCK)?;
    let flags=unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_GETFL)};
    require(flags>=0 && unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_SETFL,flags|libc::O_NONBLOCK)}==0
        && unsafe{libc::fcntl(fd.as_raw_fd(),libc::F_SETFD,libc::FD_CLOEXEC)}==0)
}
#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Configuration{api_version:String,channel:Identity}
#[derive(Clone,Copy,PartialEq,Eq)]
pub enum ChannelVersion{UnixV1,VsockV2}
impl ChannelVersion{
    pub fn validate(self,fd:BorrowedFd<'_>)->Result<(),String>{match self{
        Self::UnixV1=>validate_channel(fd),Self::VsockV2=>stream::Connection::capture(fd).map(|_|())}}
}
impl Configuration{
    pub fn version(&self)->Result<ChannelVersion,String>{match self.api_version.as_str(){
        "serverware.nativePolicyActivationChannel/v1"=>Ok(ChannelVersion::UnixV1),
        "serverware.nativePolicyActivationChannel/v2"=>Ok(ChannelVersion::VsockV2),
        _=>Err("native activation channel profile not selected".into()),
    }}
}
enum Binding{Unix,Vsock(stream::Connection)}
impl Binding{
    fn capture(version:ChannelVersion,fd:BorrowedFd<'_>)->Result<Self,String>{match version{
        ChannelVersion::UnixV1=>{validate_channel(fd)?;Ok(Self::Unix)},
        ChannelVersion::VsockV2=>Ok(Self::Vsock(stream::Connection::capture(fd)?)),
    }}
    fn check(&self,fd:BorrowedFd<'_>)->Result<(),String>{match self{
        Self::Unix=>validate_channel(fd),Self::Vsock(value)=>value.check(fd),
    }}
    fn is_stream(&self)->bool{matches!(self,Self::Vsock(_))}
}
pub struct Prepared{channel:OwnedFd,identity:Identity,association:Association,binding:Binding}
pub struct Owner{channel:OwnedFd,identity:Identity,association:Association,serving:Arc<ServingOwner>,attempted:bool,binding:Binding}
impl Prepared{
    pub fn take(configuration:Configuration,prepared:&ServingPreparation)->Result<Self,String>{
        prepared.check()?;let version=configuration.version()?;
        require(unsafe{libc::fcntl(FD,libc::F_GETFD)}>=0)?;
        let channel=unsafe{OwnedFd::from_raw_fd(FD)};let binding=Binding::capture(version,channel.as_fd())?;
        require(identity(channel.as_fd())?==configuration.channel)?;
        let association=Association::capture(prepared)?;prepared.check()?;
        Ok(Self{channel,identity:configuration.channel,association,binding})
    }
    pub fn bind(self,serving:Arc<ServingOwner>)->Result<Owner,String>{
        self.association.require(&serving)?;
        let owner=Owner{channel:self.channel,identity:self.identity,association:self.association,serving,attempted:false,binding:self.binding};owner.check()?;Ok(owner)
    }
}
impl Owner{
    pub fn check(&self)->Result<(),String>{self.association.require(&self.serving)?;
        require(identity(self.channel.as_fd())?==self.identity)?;self.binding.check(self.channel.as_fd())}
    pub fn deadline(&self)->u64{self.serving.deadline()}
    /// One invocation, including uncertain outcomes. Request bytes are public;
    /// the caller must retain its verified preparation until receipt admission.
    pub fn publish(&mut self,raw:&[u8],deadline:u64,check:impl Fn()->Result<(),String>)->Result<Vec<u8>,String>{
        self.check()?;check()?;require(!self.attempted && now()?<deadline && deadline<=self.serving.deadline())?;
        let value:serde_json::Value=parse(raw,MAXIMUM)?;
        require(value["apiVersion"]=="serverware.nativePolicyActivationRequest/v1")?;
        self.attempted=true;
        if self.binding.is_stream(){return self.publish_stream(raw,deadline,&check);}
        let file=sealed(raw)?;
        let frame=Frame{api_version:API.into(),request_sha256:crate::sha256_prefixed(raw),request_byte_count:raw.len() as u64,
            deadline_boottime_ns:deadline.to_string()};let bytes=canonical(&frame)?;
        loop{self.check()?;check()?;require(now()?<deadline)?;
            if send(self.channel.as_fd(),&bytes,Some(file.as_fd()))?{break;}
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
        loop{self.check()?;check()?;require(now()?<deadline)?;
            if let Some((bytes,rights))=receive(self.channel.as_fd(),MAX_PUBLICATION)?{
                require(rights.is_empty())?;let _:serde_json::Value=parse(&bytes,MAX_PUBLICATION)?;
                self.check()?;check()?;require(now()?<deadline)?;return Ok(bytes);
            }
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
    }
    fn publish_stream(&self,raw:&[u8],deadline:u64,check:&impl Fn()->Result<(),String>)->Result<Vec<u8>,String>{
        let mut output=stream::Writer::new(raw,MAXIMUM)?;
        loop{
            self.check()?;check()?;require(now()?<deadline)?;
            let complete=output.poll(self.channel.as_fd())?;
            self.check()?;check()?;require(now()?<deadline)?;
            if complete{break;}
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
        let mut input=stream::Reader::new(MAX_PUBLICATION);
        loop{
            self.check()?;check()?;require(now()?<deadline)?;
            let received=input.poll(self.channel.as_fd())?;
            self.check()?;check()?;require(now()?<deadline)?;
            if let Some(bytes)=received{
                let _:serde_json::Value=parse(&bytes,MAX_PUBLICATION)?;
                self.check()?;check()?;require(now()?<deadline)?;return Ok(bytes);
            }
            unsafe{libc::poll(std::ptr::null_mut(),0,1);}
        }
    }
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Frame{api_version:String,request_sha256:String,request_byte_count:u64,deadline_boottime_ns:String}
pub struct Incoming{file:File,identity:Identity,raw:Vec<u8>,deadline:u64}
impl Incoming{
    pub fn original(&self)->&[u8]{&self.raw}
    /// Narrow only from the service's genuine verified original expiry. This
    /// local bound is not wire evidence or an admission/verification result.
    pub fn narrow_deadline(&mut self,deadline:u64)->Result<(),String>{
        self.check()?;require(now()?<deadline && deadline<=self.deadline)?;
        self.deadline=deadline;self.check()
    }
    pub fn check(&self)->Result<(),String>{
        require(now()?<self.deadline && identity(self.file.as_fd())?==self.identity)?;
        require(read_sealed(&self.file)?==self.raw)
    }
}
pub struct ServiceChannel{channel:OwnedFd,identity:Identity,pid:u32,received:bool,binding:Binding,
    input:Option<stream::Reader>,output:Option<stream::Writer>,receive_deadline:Option<u64>,failed:bool,sent:bool}
impl ServiceChannel{
    /// Only the genuine C9 activation owner calls this with its consumed slot.
    /// The resulting object is a transport, never an authority/ready token.
    pub fn from_delivery(channel:OwnedFd)->Result<Self,String>{
        Self::from_delivery_version(channel,ChannelVersion::UnixV1)
    }
    pub fn from_delivery_version(channel:OwnedFd,version:ChannelVersion)->Result<Self,String>{
        require(unsafe{libc::geteuid()}!=0)?;let binding=Binding::capture(version,channel.as_fd())?;
        let input=if binding.is_stream(){Some(stream::Reader::new(MAXIMUM))}else{None};
        let original=identity(channel.as_fd())?;Ok(Self{channel,identity:original,pid:std::process::id(),received:false,
            binding,input,output:None,receive_deadline:None,failed:false,sent:false})
    }
    pub fn check(&self)->Result<(),String>{require(self.pid==std::process::id() && identity(self.channel.as_fd())?==self.identity)?;
        self.binding.check(self.channel.as_fd())}
    pub fn receive(&mut self,lifetime:u64)->Result<Option<Incoming>,String>{
        self.check()?;require(!self.received && now()?<lifetime)?;
        if self.binding.is_stream(){
            require(!self.failed)?;
            let result=self.receive_stream(lifetime);
            if result.is_err(){self.failed=true;}
            return result;
        }
        let Some((bytes,mut rights))=receive(self.channel.as_fd(),4096)?else{return Ok(None)};
        self.received=true;require(rights.len()==1)?;
        let frame:Frame=parse(&bytes,4096)?;let deadline=frame.deadline_boottime_ns.parse::<u64>().map_err(|_|"activation original deadline")?;
        require(frame.api_version==API && deadline.to_string()==frame.deadline_boottime_ns && now()?<deadline && deadline<=lifetime
            && (1..=MAXIMUM as u64).contains(&frame.request_byte_count))?;
        let file=File::from(rights.remove(0));let raw=read_sealed(&file)?;
        require(raw.len() as u64==frame.request_byte_count && crate::sha256_prefixed(&raw)==frame.request_sha256)?;
        let owner=Incoming{identity:identity(file.as_fd())?,file,raw,deadline};owner.check()?;self.check()?;Ok(Some(owner))
    }
    fn receive_stream(&mut self,lifetime:u64)->Result<Option<Incoming>,String>{
        let deadline=*self.receive_deadline.get_or_insert(lifetime);
        require(lifetime==deadline && now()?<deadline)?;
        let result=self.input.as_mut().ok_or("activation stream reader absent")?.poll(self.channel.as_fd())?;
        self.check()?;require(now()?<deadline)?;
        let Some(raw)=result else{return Ok(None)};
        self.received=true;
        let value:serde_json::Value=parse(&raw,MAXIMUM)?;
        require(value["apiVersion"]=="serverware.nativePolicyActivationRequest/v1")?;
        // Retain immutable received bytes locally; this is not an imported FD
        // or a replacement for genuine request/authority verification.
        let file=sealed(&raw)?;
        let owner=Incoming{identity:identity(file.as_fd())?,file,raw,deadline};
        owner.check()?;self.check()?;require(now()?<deadline)?;Ok(Some(owner))
    }
    pub fn send(&mut self,request:&Incoming,bytes:&[u8])->Result<bool,String>{
        self.check()?;request.check()?;require(self.received && !bytes.is_empty() && bytes.len()<=MAX_PUBLICATION)?;
        let value:serde_json::Value=parse(bytes,MAX_PUBLICATION)?;
        require(value["payload"]["apiVersion"]=="serverware.nativePolicyActivationPublication/v1"
            && value["payload"]["requestSha256"]==crate::sha256_prefixed(request.original()))?;
        if self.binding.is_stream(){
            require(!self.failed && !self.sent)?;
            let result=(||{
                if self.output.is_none(){self.output=Some(stream::Writer::new(bytes,MAX_PUBLICATION)?);}
                let output=self.output.as_mut().ok_or("activation stream writer absent")?;
                require(output.original()==bytes && now()?<request.deadline)?;
                let complete=output.poll(self.channel.as_fd())?;
                self.check()?;request.check()?;require(now()?<request.deadline)?;
                self.sent=complete;Ok(complete)
            })();
            if result.is_err(){self.failed=true;}
            return result;
        }
        send(self.channel.as_fd(),bytes,None)
    }
}
fn read_sealed(file:&File)->Result<Vec<u8>,String>{
    let m=file.metadata().map_err(|_|"activation sealed input metadata")?;
    require(m.is_file() && m.nlink()==0 && m.mode()&0o7777==0o600 && m.len()>0 && m.len()<=MAXIMUM as u64
        && unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GET_SEALS)}==SEALS)?;
    let mut raw=vec![0;m.len() as usize];file.read_exact_at(&mut raw,0).map_err(|_|"activation original read")?;Ok(raw)
}
fn sealed(raw:&[u8])->Result<File,String>{
    require(!raw.is_empty() && raw.len()<=MAXIMUM)?;
    let fd=unsafe{libc::syscall(libc::SYS_memfd_create,c"native-activation-original".as_ptr(),libc::MFD_CLOEXEC|libc::MFD_ALLOW_SEALING)} as i32;
    require(fd>=0)?;let mut file=unsafe{File::from_raw_fd(fd)};
    require(unsafe{libc::fchmod(fd,0o600)}==0)?;file.write_all(raw).map_err(|_|"activation original seal write")?;
    require(unsafe{libc::fcntl(fd,libc::F_ADD_SEALS,SEALS)}==0 && read_sealed(&file)?==raw)?;Ok(file)
}
fn send(fd:BorrowedFd<'_>,bytes:&[u8],right:Option<BorrowedFd<'_>>)->Result<bool,String>{
    let mut iov=libc::iovec{iov_base:bytes.as_ptr() as *mut _,iov_len:bytes.len()};
    let mut header:libc::msghdr=unsafe{std::mem::zeroed()};header.msg_iov=&mut iov;header.msg_iovlen=1;
    let mut control=[0usize;4];
    if let Some(right)=right{
        header.msg_control=control.as_mut_ptr().cast();
        header.msg_controllen=unsafe{libc::CMSG_SPACE(std::mem::size_of::<i32>() as _)}
            .try_into().map_err(|_|"activation ancillary buffer length")?;
        let c=unsafe{libc::CMSG_FIRSTHDR(&header)};
        unsafe{(*c).cmsg_level=libc::SOL_SOCKET;(*c).cmsg_type=libc::SCM_RIGHTS;
            (*c).cmsg_len=libc::CMSG_LEN(std::mem::size_of::<i32>() as _)
                .try_into().map_err(|_|"activation ancillary header length")?;
            std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<i32>(),right.as_raw_fd());}
    }
    let n=unsafe{libc::sendmsg(fd.as_raw_fd(),&header,libc::MSG_DONTWAIT|libc::MSG_NOSIGNAL)};
    if n<0{let e=std::io::Error::last_os_error();if matches!(e.raw_os_error(),Some(libc::EAGAIN)|Some(libc::EINTR)){return Ok(false);}return Err("activation transport send".into());}
    require(n as usize==bytes.len())?;Ok(true)
}
fn receive(fd:BorrowedFd<'_>,maximum:usize)->Result<Option<(Vec<u8>,Vec<OwnedFd>)>,String>{
    let mut bytes=vec![0;maximum];let mut control=[0usize;32];
    let mut iov=libc::iovec{iov_base:bytes.as_mut_ptr().cast(),iov_len:bytes.len()};let mut h:libc::msghdr=unsafe{std::mem::zeroed()};
    h.msg_iov=&mut iov;h.msg_iovlen=1;h.msg_control=control.as_mut_ptr().cast();
    h.msg_controllen=std::mem::size_of_val(&control).try_into().map_err(|_|"activation ancillary capacity")?;
    let n=unsafe{libc::recvmsg(fd.as_raw_fd(),&mut h,libc::MSG_DONTWAIT|libc::MSG_CMSG_CLOEXEC)};
    if n<0{let e=std::io::Error::last_os_error();if matches!(e.raw_os_error(),Some(libc::EAGAIN)|Some(libc::EINTR)){return Ok(None);}return Err("activation transport receive".into());}
    let mut valid=n>0 && h.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)==0;let mut rights=Vec::new();
    let control_length=usize::try_from(h.msg_controllen).map_err(|_|"activation received ancillary length")?;
    let mut c=unsafe{libc::CMSG_FIRSTHDR(&h)};
    while !c.is_null(){let item=unsafe{&*c};let base=unsafe{libc::CMSG_LEN(0)} as usize;
        let item_length=match usize::try_from(item.cmsg_len){Ok(value)=>value,Err(_)=>{valid=false;break;}};
        if item_length<base || (c as usize).checked_sub(h.msg_control as usize)
            .and_then(|offset|offset.checked_add(item_length))
            .is_none_or(|end|end>control_length || end>std::mem::size_of_val(&control)){valid=false;break;}
        let len=item_length-base;
        if item.cmsg_level==libc::SOL_SOCKET && (item.cmsg_type==libc::SCM_RIGHTS || item.cmsg_type==4){
            valid &= item.cmsg_type==libc::SCM_RIGHTS && len%std::mem::size_of::<i32>()==0;
            for offset in (0..len/std::mem::size_of::<i32>()).map(|i|i*std::mem::size_of::<i32>()){
                let raw=unsafe{std::ptr::read_unaligned(libc::CMSG_DATA(c).add(offset).cast::<i32>())};
                if raw<0{valid=false;}else{rights.push(unsafe{OwnedFd::from_raw_fd(raw)});}
            }
        }else{valid=false;}
        c=unsafe{libc::CMSG_NXTHDR(&h,c)};
    }
    require(valid)?;bytes.truncate(n as usize);Ok(Some((bytes,rights)))
}
