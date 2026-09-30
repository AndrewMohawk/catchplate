//! A source-fixed syscall-only pre-exec park. No admission or ready result.
use super::*;
use std::mem::size_of_val;
struct Prepared {parent:i32,channel:OwnedFd,gate:OwnedFd,executable:OwnedFd,null:OwnedFd,
    launch_target:OwnedFd,image_target:OwnedFd}
// Stack-only formatting for kernel-assigned descriptors; no caller path.
fn fd_path(fd:i32)->[u8;64] {
    let mut out=[0u8;64];let prefix=b"/proc/self/fd/";
    let mut i=0;while i<prefix.len(){out[i]=prefix[i];i+=1;}
    let mut number=fd as u32;let mut digits=[0u8;10];let mut count=0;
    loop {digits[count]=b'0'+(number%10) as u8;count+=1;number/=10;if number==0 {break;}}
    while count>0 {count-=1;out[i]=digits[count];i+=1;}out
}
unsafe fn bind(source:i32,target:i32,path:&std::ffi::CStr)->bool {
    let source=fd_path(source);
    let mut held:libc::stat=unsafe{zeroed()};let mut named:libc::stat=unsafe{zeroed()};
    if unsafe{libc::fstat(target,&mut held)}!=0
        || unsafe{libc::fstatat(libc::AT_FDCWD,path.as_ptr(),&mut named,libc::AT_SYMLINK_NOFOLLOW)}!=0
        || (held.st_dev,held.st_ino,held.st_mode,held.st_uid,held.st_gid)
            !=(named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid) {return false;}
    (unsafe{libc::mount(source.as_ptr().cast(),path.as_ptr(),std::ptr::null(),libc::MS_BIND,std::ptr::null())})==0
        && unsafe{libc::mount(std::ptr::null(),path.as_ptr(),std::ptr::null(),
            libc::MS_BIND|libc::MS_REMOUNT|libc::MS_RDONLY|libc::MS_NOSUID|libc::MS_NODEV|libc::MS_NOEXEC,std::ptr::null())}==0
}
impl Prepared {
    unsafe fn enter(&self)->! {
        let mut good=unsafe{libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)}==0
            && unsafe{libc::getppid()}==self.parent
            && unsafe{libc::unshare(libc::CLONE_NEWNS)}==0
            && unsafe{libc::mount(std::ptr::null(),c"/".as_ptr(),std::ptr::null(),libc::MS_PRIVATE|libc::MS_REC,std::ptr::null())}==0
            && unsafe{libc::syscall(libc::SYS_close_range,3u32,u32::MAX,4u32)}==0
            && unsafe{libc::dup3(self.channel.as_raw_fd(),3,0)}==3;
        for target in [0,1,2] {good &= unsafe{libc::dup3(self.null.as_raw_fd(),target,0)}==target;}
        let action=Action{handler:0,flags:0,restorer:0,mask:0};
        for signal in 1..=64 {if signal!=libc::SIGKILL && signal!=libc::SIGSTOP {
            good &= unsafe{libc::syscall(libc::SYS_rt_sigaction,signal,&action,std::ptr::null::<u8>(),8usize)}==0;
        }}
        let mask=0u64;
        good &= unsafe{libc::syscall(libc::SYS_rt_sigprocmask,libc::SIG_SETMASK,&mask,std::ptr::null::<u8>(),8usize)}==0;
        // Source-fixed ordering acknowledgment only. Parent requires the
        // kernel sender PIDFD/credentials and a genuinely distinct mount NS
        // before changing its own image view; this is not service readiness.
        let parked=0x50u8;
        if good {good &= unsafe{libc::send(self.gate.as_raw_fd(),(&parked as *const u8).cast(),1,libc::MSG_NOSIGNAL)}==1;}
        // Blocks only in the genuine child; parent's original absolute timer
        // and this thread's PDEATHSIG remain armed throughout the park.
        let mut bytes=[0u8;2];let mut control=[0usize;80];let mut rights=[-1i32;67];
        let mut iov=libc::iovec{iov_base:bytes.as_mut_ptr().cast(),iov_len:bytes.len()};
        let mut message:libc::msghdr=unsafe{zeroed()};message.msg_iov=&mut iov;message.msg_iovlen=1;
        message.msg_control=control.as_mut_ptr().cast();
        message.msg_controllen=match size_of_val(&control).try_into(){Ok(value)=>value,Err(_)=>{good=false;0}};
        let count=if good {unsafe{libc::recvmsg(self.gate.as_raw_fd(),&mut message,libc::MSG_CMSG_CLOEXEC)}}else{-1};
        good &= count==2 && bytes[0]==0xa5 && (1..=64).contains(&bytes[1])
            && message.msg_flags&(libc::MSG_TRUNC|libc::MSG_CTRUNC)==0;
        let mut total=0usize;let mut credentials=false;let mut pidfd=-1i32;let mut rights_seen=false;
        let mut item=unsafe{libc::CMSG_FIRSTHDR(&message)};
        while !item.is_null() && good {
            let c=unsafe{&*item};let base=unsafe{libc::CMSG_LEN(0)} as usize;
            let Ok(cmsg_len)=usize::try_from(c.cmsg_len) else{good=false;break;};
            good &= c.cmsg_level==libc::SOL_SOCKET && cmsg_len>=base;
            if !good {break;}
            let length=cmsg_len-base;let data=unsafe{libc::CMSG_DATA(item)};
            if c.cmsg_type==libc::SCM_CREDENTIALS && !credentials && length==size_of::<libc::ucred>() {
                let cred=unsafe{std::ptr::read_unaligned(data.cast::<libc::ucred>())};
                credentials=cred.pid==self.parent && cred.uid==0 && cred.gid==0;good &= credentials;
            } else if c.cmsg_type==4 && pidfd<0 && length==size_of::<i32>() {
                pidfd=unsafe{std::ptr::read_unaligned(data.cast::<i32>())};good &= pidfd>=0;
            } else if c.cmsg_type==libc::SCM_RIGHTS && !rights_seen && length%size_of::<i32>()==0 {
                rights_seen=true;total=length/size_of::<i32>();good &= total<=rights.len();
                if good {for (index,slot) in rights[..total].iter_mut().enumerate() {
                    *slot=unsafe{std::ptr::read_unaligned(data.cast::<i32>().add(index))};good &= *slot>=0;
                }}
            } else {good=false;}
            item=unsafe{libc::CMSG_NXTHDR(&message,item)};
        }
        good &= credentials && pidfd>=0 && rights_seen && total==bytes[1] as usize+3
            && unsafe{libc::getppid()}==self.parent;
        if good {
            let mut poll=libc::pollfd{fd:pidfd,events:libc::POLLIN,revents:0};
            good &= unsafe{libc::poll(&mut poll,1,0)}==0;
            good &= unsafe{bind(rights[0],self.launch_target.as_raw_fd(),c"/etc/serverware/native-shadow-guest-launch.json")}
                && unsafe{bind(rights[1],self.image_target.as_raw_fd(),c"/opt/serverware/native-shadow-custody-runtime.squashfs")};
            // All received sources are duplicated above the destination range
            // before assignment; kernel allocation need not choose high FDs.
            let mut retained=[-1i32;65];
            for index in 0..total-2 {
                retained[index]=unsafe{libc::fcntl(rights[index+2],libc::F_DUPFD_CLOEXEC,192)};
                good &= retained[index]>=192;
            }
            good &= unsafe{libc::dup3(retained[0],4,0)}==4;
            for index in 0..bytes[1] as usize {
                good &= unsafe{libc::dup3(retained[index+1],6+index as i32,0)}==6+index as i32;
            }
            good &= unsafe{libc::chdir(c"/".as_ptr())}==0 && unsafe{libc::getppid()}==self.parent;
        }
        if good {
            let argv=[c"serverware-policy-shadow-custody-guest".as_ptr(),std::ptr::null()];
            let env:[*const libc::c_char;1]=[std::ptr::null()];
            unsafe{libc::syscall(libc::SYS_execveat,self.executable.as_raw_fd(),c"".as_ptr(),
                argv.as_ptr(),env.as_ptr(),libc::AT_EMPTY_PATH);}
        }
        unsafe{libc::syscall(libc::SYS_exit_group,127);}loop{std::hint::spin_loop();}
    }
}
pub(super) fn spawn(executable:BorrowedFd<'_>,launch_target:BorrowedFd<'_>,image_target:BorrowedFd<'_>,
    startup:u64,deadline:u64)->Result<Child,ShadowError> {
    require(cfg!(target_arch="x86_64") && now()?<startup && startup<=deadline)?;
    let mut disposition:libc::sigaction=unsafe{zeroed()};
    require(unsafe{libc::sigaction(libc::SIGCHLD,std::ptr::null(),&mut disposition)}==0
        && disposition.sa_sigaction==libc::SIG_DFL && disposition.sa_flags&libc::SA_NOCLDWAIT==0)?;
    let (channel,remote)=pair()?;let (gate,receiver)=pair()?;
    retrieval_peer::configure(gate.as_fd())?;
    // Keep the private child gate blocking. Only its parent's send is bounded
    // nonblocking; kernel credentials/PIDFD accompany the one release packet.
    for option in [libc::SO_PASSCRED,76] {
        let one=1i32;require(unsafe{libc::setsockopt(receiver.as_raw_fd(),libc::SOL_SOCKET,option,
            (&one as *const i32).cast(),size_of::<i32>() as _)}==0)?;
    }
    let raw=unsafe{libc::open(c"/dev/null".as_ptr(),libc::O_RDWR|libc::O_CLOEXEC|libc::O_NOFOLLOW)};
    require(raw>=0)?;let null=unsafe{OwnedFd::from_raw_fd(raw)};let mut stat:libc::stat=unsafe{zeroed()};
    require(unsafe{libc::fstat(null.as_raw_fd(),&mut stat)}==0 && stat.st_mode&libc::S_IFMT==libc::S_IFCHR
        && libc::major(stat.st_rdev)==1 && libc::minor(stat.st_rdev)==3 && stat.st_uid==0 && stat.st_gid==0)?;
    let parent=unsafe{libc::getpid()};
    let prepared=Prepared{parent,channel:duplicate(remote.as_fd())?,gate:duplicate(receiver.as_fd())?,
        executable:duplicate(executable)?,null:duplicate(null.as_fd())?,
        launch_target:duplicate(launch_target)?,image_target:duplicate(image_target)?};
    let mut pidfd=-1i32;
    let args=CloneArgs{flags:libc::CLONE_PIDFD as u64,pidfd:(&mut pidfd as *mut i32) as u64,
        exit_signal:libc::SIGCHLD as u64,..CloneArgs::default()};
    let pid=unsafe{libc::syscall(libc::SYS_clone3,&args,size_of::<CloneArgs>())};
    if pid==0 {unsafe{prepared.enter();}}
    if pid>0 && pidfd<0 {unsafe{libc::_exit(1);}}
    require(pid>0 && pidfd>=0)?;
    let mut child=Child{channel,pidfd:unsafe{OwnedFd::from_raw_fd(pidfd)},gate:Some(gate),pid:pid as i32,
        parent,start:None,deadline,reaped:false,pair_mode:true};
    child.start=Some(child.identity()?);
    loop {
        require(now()?<startup && child.check()?)?;
        if let Some(packet)=retrieval_peer::receive(child.gate.as_ref().ok_or(ShadowError::BindingDrift)?.as_fd(),1,0)? {
            child.require_inspection_sender(&packet,0,0)?;
            require(packet.bytes==[0x50])?;
            use std::os::unix::fs::MetadataExt;
            let own=std::fs::metadata("/proc/self/ns/mnt").map_err(fail)?;
            let remote=std::fs::metadata(format!("/proc/{}/ns/mnt",child.pid)).map_err(fail)?;
            require((own.dev(),own.ino())!=(remote.dev(),remote.ino()))?;
            child.parked_identity()?;break;
        }
        let result=unsafe{libc::poll(std::ptr::null_mut(),0,1)};
        require(result==0 || (result<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR)))?;
    }
    Ok(child)
}
pub(super) fn release(child:&mut Child,launch:BorrowedFd<'_>,image:BorrowedFd<'_>,inspection:BorrowedFd<'_>,
    activation:&[BorrowedFd<'_>])->Result<(),ShadowError> {
    require(!activation.is_empty() && activation.len()<=64)?;
    let bytes=[0xa5u8,activation.len() as u8];
    let mut fds=vec![launch.as_raw_fd(),image.as_raw_fd(),inspection.as_raw_fd()];
    fds.extend(activation.iter().map(AsRawFd::as_raw_fd));
    let mut control=[0usize;48];let mut iov=libc::iovec{iov_base:bytes.as_ptr() as *mut _,iov_len:2};
    let mut message:libc::msghdr=unsafe{zeroed()};message.msg_iov=&mut iov;message.msg_iovlen=1;
    message.msg_control=control.as_mut_ptr().cast();
    let rights_bytes=u32::try_from(fds.len().checked_mul(size_of::<i32>()).ok_or(ShadowError::BindingDrift)?).map_err(fail)?;
    message.msg_controllen=unsafe{libc::CMSG_SPACE(rights_bytes)}.try_into().map_err(fail)?;
    let item=unsafe{libc::CMSG_FIRSTHDR(&message)};
    unsafe{(*item).cmsg_level=libc::SOL_SOCKET;(*item).cmsg_type=libc::SCM_RIGHTS;
        (*item).cmsg_len=libc::CMSG_LEN(rights_bytes).try_into().map_err(fail)?;
        std::ptr::copy_nonoverlapping(fds.as_ptr(),libc::CMSG_DATA(item).cast::<i32>(),fds.len());}
    child.parked_identity()?;
    let gate=child.gate.take().ok_or(ShadowError::BindingDrift)?;
    // One effect attempt. EAGAIN/error refuses the cohort, never a retry.
    require(unsafe{libc::sendmsg(gate.as_raw_fd(),&message,libc::MSG_DONTWAIT|libc::MSG_NOSIGNAL)}==2)
}
