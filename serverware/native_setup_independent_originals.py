"""Independent fixed-purpose verifier input ownership; no claimant key custody."""
import fcntl
import os
import select
import stat
import time
from serverware import native_shadow_nitro_profile as wire
from serverware.native_shadow_nitro_originals import _File, _boot, _clock, _hardening, _identity, _security, _start
from serverware import authority_setup_native_hardware as p

_TOKEN = object()
_NAMES = {p.ROLES[0]:"setup-native-hardware-verifier.json", p.ROLES[1]:"setup-native-proxy-verifier.json"}


class Originals:
    def __init__(self,token):
        p.require(token is _TOKEN)
        self.fds, self.closed, self.taken = [], False, False

    @classmethod
    def _open(cls,role):
        p.require(cls is Originals and role in p.ROLES)
        self=cls(_TOKEN); self.role=role
        try:
            for fd in (3,4,5): os.fstat(fd); self.fds.append(fd)
            self.libc=_hardening(); _security(self.libc)
            self.pid,self.start,self.uid,self.gid=os.getpid(),_start(),os.getuid(),os.getgid()
            p.require(self.uid not in {64988,64989,64990,65534} and self.gid not in {64988,64989,64990,65534})
            self.pidfd=os.pidfd_open(self.pid,0); self.fds.append(self.pidfd); os.set_inheritable(self.pidfd,False)
            self.pidfd_identity=_identity(os.fstat(self.pidfd)); self.pidfd_flags=fcntl.fcntl(self.pidfd,fcntl.F_GETFL)
            parent=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC); self.fds.append(parent); self.directories=[]
            for name in ("etc","serverware"):
                before=os.fstat(parent); p.require(stat.S_ISDIR(before.st_mode) and before.st_uid==0 and before.st_mode&0o022==0)
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                self.fds.append(child); actual=os.fstat(child)
                p.require(actual.st_uid==0 and actual.st_mode&0o022==0)
                self.directories.append((parent,name,child,_identity(actual))); parent=child
            self.directory=parent
            self.config=_File(3,4*1024*1024,uid=0,gid=0,sealed=False)
            self.seed=_File(4,32,uid=self.uid,gid=self.gid,sealed=True)
            self.request=_File(5,p.MAX_BUNDLE,uid=self.uid,gid=self.gid,sealed=True)
            p.require(self.seed.identity[6]==32 and len({o.identity[:2] for o in (self.config,self.seed,self.request)})==3)
            self.config_raw=self.config.read(); self.configuration=p.enrollment.setup.document(self.config_raw,4*1024*1024)
            c=self.configuration
            p.require(set(c)=={"apiVersion","role","uid","gid","operation","authorityRootPublicKeyPem","authorityConfigurationOriginal",
                "authorityConfigurationSha256","controlPlaneConfigurationDigest"}
                and c["apiVersion"]=="serverware.setupNativeIndependentVerifierConfiguration/v1" and c["role"]==role
                and type(c["uid"]) is int and type(c["gid"]) is int and (c["uid"],c["gid"])==(self.uid,self.gid))
            operation=wire.fields(c["operation"],("bootIdBase64url","timeNamespaceDevice","timeNamespaceInode","issuedAtBoottimeNs","deadlineBoottimeNs"))
            self.boot=_boot(); p.require(self.boot==(operation["bootIdBase64url"],operation["timeNamespaceDevice"],operation["timeNamespaceInode"]))
            wire.integer(operation["timeNamespaceDevice"]); wire.integer(operation["timeNamespaceInode"])
            self.issued,self.deadline=wire.ns(operation["issuedAtBoottimeNs"]),wire.ns(operation["deadlineBoottimeNs"])
            p.require(0<self.deadline-self.issued<=30_000_000_000)
            self.wall=0; self.request_raw=self.request.read()
            self.values=p.enrollment.setup.document(self.request_raw,p.MAX_BUNDLE)
            p.require(set(self.values)==p.INPUT_FIELDS|{"attempt_original","evidence_original"})
            self.check(); return self
        except BaseException:
            self.close(); raise

    def check(self):
        p.require(not self.closed and (os.getpid(),_start())==(self.pid,self.start)
            and os.getresuid()==(self.uid,)*3 and os.getresgid()==(self.gid,)*3 and os.getgroups()==[]
            and _boot()==self.boot and self.issued<=_clock()<self.deadline)
        _security(self.libc)
        p.require(_identity(os.fstat(self.pidfd))==self.pidfd_identity and fcntl.fcntl(self.pidfd,fcntl.F_GETFL)==self.pidfd_flags
            and not os.get_inheritable(self.pidfd))
        poll=select.poll(); poll.register(self.pidfd,select.POLLIN); p.require(poll.poll(0)==[])
        with open("/proc/self/fdinfo/"+str(self.pidfd),"rt",encoding="ascii") as stream: text=stream.read(4097)
        p.require(len(text)<=4096 and [line for line in text.splitlines() if line.startswith("Pid:")]==["Pid:\t"+str(self.pid)])
        for parent,name,child,identity in self.directories:
            p.require(_identity(os.fstat(child))==identity and _identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==identity)
        p.require(_identity(os.stat(_NAMES[self.role],dir_fd=self.directory,follow_symlinks=False))==self.config.identity)
        for original in (self.config,self.seed,self.request): original.check()
        p.require(self.config.read()==self.config_raw==p.canonical(self.configuration)
            and self.request.read()==self.request_raw==p.canonical(self.values))
        now=time.time_ns(); p.require(type(now) is int and self.wall<=now<2**63 and self.issued<=_clock()<self.deadline)
        if hasattr(self,"result_expires"): p.require(now<self.result_expires)
        self.wall=now; return now

    def _take_seed(self):
        self.check(); p.require(not self.taken); self.taken=True
        value=bytearray(self.seed.read())
        try: self.check(); return value
        except BaseException: value[:]=bytes(len(value)); raise

    def _publish(self,raw):
        self.check(); p.require(self.taken and type(raw) is bytes and 0<len(raw)<=16384)
        observed=os.fstat(1); flags=fcntl.fcntl(1,fcntl.F_GETFL)
        p.require(stat.S_ISFIFO(observed.st_mode) and flags&os.O_ACCMODE==os.O_WRONLY and not flags&(os.O_ASYNC|os.O_APPEND|os.O_PATH))
        identity=_identity(observed); fcntl.fcntl(1,fcntl.F_SETFL,flags|os.O_NONBLOCK)
        selected=fcntl.fcntl(1,fcntl.F_GETFL); offset=0
        poll=select.poll(); poll.register(1,select.POLLOUT)
        while offset<len(raw):
            self.check(); p.require(_identity(os.fstat(1))==identity and fcntl.fcntl(1,fcntl.F_GETFL)==selected)
            if not poll.poll(max(1,min(100,(self.deadline-_clock())//1_000_000))): continue
            try: written=os.write(1,raw[offset:])
            except BlockingIOError: continue
            p.require(written>0); offset+=written
        self.check()

    def close(self):
        if not self.closed:
            self.closed=True
            for fd in set(self.fds):
                try: os.close(fd)
                except OSError: pass
            self.fds.clear()

    def __enter__(self): return self
    def __exit__(self,*_): self.close()


def hardware_originals(): return Originals._open(p.ROLES[0])
def proxy_originals(): return Originals._open(p.ROLES[1])
