//! Exclusive seed targets; root never holds a readable seed descriptor.
use super::guest_delivery::ProvisioningSeed;
use std::{ffi::CString, fs::File, os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::MetadataExt}}, path::Path};
use serde_json::{json,Value};
use super::guest_role_provisioning::{ensure,live};

#[derive(PartialEq,Eq)]
struct Identity { dev:u64, ino:u64, mode:u32, uid:u32, gid:u32, links:u64 }
fn identity(file:&File)->Result<Identity,String>{
    let m=file.metadata().map_err(|_|"role output metadata unavailable")?;
    Ok(Identity{dev:m.dev(),ino:m.ino(),mode:m.mode(),uid:m.uid(),gid:m.gid(),links:m.nlink()})
}
fn owned(fd:i32)->Result<File,String>{
    ensure(fd>=0,"role output descriptor unavailable")?;
    Ok(unsafe{File::from_raw_fd(fd)})
}
struct Directory { file:File, id:Identity, name:Option<CString> }
struct Target {
    directories:Vec<Directory>, name:CString, held:File, id:Identity, writer:Option<File>,
}
impl Target {
    fn create(key:&ProvisioningSeed,deadline:u64)->Result<Self,String>{
        live(deadline)?;
        let path=key.path.to_str().ok_or("role key path encoding")?;
        ensure(path.is_ascii() && !path.bytes().any(|v|v<32||v==127) && path.starts_with('/') && path.len()<=4096
            && path[1..].split('/').all(|v|!v.is_empty() && v!="." && v!=".." && v.len()<=255),"role key path is not canonical")?;
        let root=File::open("/").map_err(|_|"role output root unavailable")?;
        let root_id=identity(&root)?;
        ensure(root_id.uid==0 && root_id.gid==0 && root_id.mode & 0o022==0,"role output root differs")?;
        let mut directories=vec![Directory{file:root,id:root_id,name:None}];
        let parts:Vec<_>=path[1..].split('/').collect();
        for name in &parts[..parts.len()-1] {
            live(deadline)?;
            let name=CString::new(*name).map_err(|_|"role output path NUL")?;
            let parent=directories.last().ok_or("role output parent absent")?;
            let file=owned(unsafe{libc::openat(parent.file.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
            let id=identity(&file)?;
            ensure(id.mode & libc::S_IFMT==libc::S_IFDIR && [0,key.uid].contains(&id.uid)
                && id.mode & 0o022==0,"role output ancestry is not protected")?;
            directories.push(Directory{file,id,name:Some(name)});
        }
        let parent=directories.last().ok_or("role output directory absent")?;
        ensure(parent.id.uid==key.uid && parent.id.gid==key.gid && parent.id.mode & 0o7777==0o700,
            "role seed requires its preprovisioned dedicated private directory")?;
        let name=CString::new(*parts.last().ok_or("role output leaf absent")?).map_err(|_|"role output leaf NUL")?;
        let writer=owned(unsafe{libc::openat(parent.file.as_raw_fd(),name.as_ptr(),
            libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o400)})?;
        // Any failure from this point preserves the created name. It cannot be
        // repaired, removed or adopted by a later provisioning attempt.
        ensure(unsafe{libc::fchown(writer.as_raw_fd(),key.uid,key.gid)}==0
            && unsafe{libc::fchmod(writer.as_raw_fd(),0o400)}==0,"role output exact ownership unavailable")?;
        writer.sync_all().map_err(|_|"role output creation durability uncertain")?;
        parent.file.sync_all().map_err(|_|"role output parent creation durability uncertain")?;
        let held=owned(unsafe{libc::openat(parent.file.as_raw_fd(),name.as_ptr(),libc::O_PATH|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
        let id=identity(&held)?;
        ensure(id==identity(&writer)? && id.mode & libc::S_IFMT==libc::S_IFREG && id.links==1
            && id.uid==key.uid && id.gid==key.gid && id.mode & 0o7777==0o400
            && writer.metadata().map_err(|_|"role output size unavailable")?.len()==0,"fresh role output differs")?;
        let result=Self{directories,name,held,id,writer:Some(writer)};
        result.check_named(0)?; live(deadline)?;
        Ok(result)
    }
    fn check_held(&self,length:u64)->Result<(),String>{
        ensure(identity(&self.held)?==self.id && self.held.metadata().map_err(|_|"role output stat unavailable")?.len()==length,
            "retained role output inode/owner/mode/length changed")?;
        for directory in &self.directories {ensure(identity(&directory.file)?==directory.id,"retained role output directory changed")?;}
        Ok(())
    }
    fn check_named(&self,length:u64)->Result<(),String>{
        self.check_held(length)?;
        for index in 1..self.directories.len() {
            let current=&self.directories[index];
            named(&self.directories[index-1].file,current.name.as_ref().ok_or("role directory name absent")?,&current.id)?;
        }
        named(&self.directories.last().ok_or("role output parent absent")?.file,&self.name,&self.id)
    }
}
fn named(parent:&File,name:&CString,expected:&Identity)->Result<(),String>{
    let mut value:libc::stat=unsafe{std::mem::zeroed()};
    ensure(unsafe{libc::fstatat(parent.as_raw_fd(),name.as_ptr(),&mut value,libc::AT_SYMLINK_NOFOLLOW)}==0
        && value.st_dev as u64==expected.dev && value.st_ino as u64==expected.ino && value.st_mode==expected.mode
        && value.st_uid==expected.uid && value.st_gid==expected.gid && value.st_nlink as u64==expected.links,
        "role output original name changed")
}

pub(super) struct Outputs { targets:Vec<Target>, complete:bool }
impl Outputs {
    pub(super) fn create(keys:&[ProvisioningSeed],deadline:u64)->Result<Self,String>{
        ensure((7..=64).contains(&keys.len()),"role output count differs")?;
        let mut targets=Vec::new();
        for key in keys {targets.push(Target::create(key,deadline)?);}
        Ok(Self{targets,complete:false})
    }
    pub(super) fn descriptors(&self)->Value{
        Value::Array(self.targets.iter().enumerate().map(|(index,item)|json!({
            "fd":64+index,"device":item.id.dev,"inode":item.id.ino})).collect())
    }
    pub(super) fn take_writers(&mut self)->Result<Vec<File>,String>{
        ensure(!self.complete,"completed outputs cannot be reopened")?;
        self.targets.iter_mut().map(|item|item.writer.take().ok_or_else(||"role writer already consumed".to_owned())).collect()
    }
    pub(super) fn finish(&mut self,deadline:u64)->Result<(),String>{
        ensure(!self.complete && self.targets.iter().all(|item|item.writer.is_none()),"role completion lost one-use writers")?;
        for target in &self.targets {
            live(deadline)?; target.check_named(32)?;
            target.directories.last().ok_or("role output parent absent")?.file.sync_all()
                .map_err(|_|"role output directory completion durability uncertain")?;
            target.check_named(32)?;
        }
        live(deadline)?; self.complete=true; Ok(())
    }
    pub(super) fn check(&self)->Result<(),String>{
        ensure(self.complete,"role outputs did not finish")?;
        for target in &self.targets {target.check_held(32)?;}
        Ok(())
    }
}

// Ciphertext is a public original. Seed targets deliberately have no such
// reader. This fixed path is distinct from every signed role seed path.
pub(super) fn ciphertext(path:&Path,pin:&str,deadline:u64)->Result<Vec<u8>,String>{
    ensure(path==Path::new("/run/catchplate-role-key-provisioning/inventory.enc.json"),"role inventory fixed path differs")?;
    let mut directory=File::open("/").map_err(|_|"role inventory root unavailable")?;
    let components:Vec<_>=path.components().skip(1).collect();
    for (index,part) in components.iter().enumerate() {
        live(deadline)?;
        let name=CString::new(part.as_os_str().as_bytes()).map_err(|_|"role inventory path NUL")?;
        let final_part=index+1==components.len();
        let next=owned(unsafe{libc::openat(directory.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC
            |if final_part {0}else{libc::O_DIRECTORY})})?;
        let id=identity(&next)?;
        ensure(id.uid==0 && id.gid==0 && id.mode & 0o022==0,"role encrypted inventory ancestry differs")?;
        directory=next;
    }
    use std::os::unix::fs::FileExt;
    let before=directory.metadata().map_err(|_|"role encrypted inventory stat unavailable")?;
    ensure(before.is_file() && before.nlink()==1 && [0o400,0o444].contains(&(before.mode()&0o7777))
        && before.len()>0 && before.len()<=32768,"role encrypted inventory original differs")?;
    let mut raw=vec![0;before.len() as usize]; let mut offset=0;
    while offset<raw.len() {live(deadline)?; let n=directory.read_at(&mut raw[offset..],offset as u64).map_err(|_|"role inventory read failed")?;
        ensure(n>0,"role inventory truncated")?; offset+=n;}
    let after=directory.metadata().map_err(|_|"role inventory closing stat unavailable")?;
    ensure((before.dev(),before.ino(),before.mode(),before.uid(),before.gid(),before.nlink(),before.len(),before.mtime_nsec(),before.ctime_nsec(),before.mtime(),before.ctime())
        ==(after.dev(),after.ino(),after.mode(),after.uid(),after.gid(),after.nlink(),after.len(),after.mtime_nsec(),after.ctime_nsec(),after.mtime(),after.ctime())
        && super::guest_role_provisioning::sha(&raw)==pin,"role encrypted inventory original changed")?;
    live(deadline)?; Ok(raw)
}
