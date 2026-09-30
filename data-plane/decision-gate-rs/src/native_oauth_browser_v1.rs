//! Actual enclave-terminated browser requests. The sealed Accepted value owns
//! the live kernel stream and the same generated TLS configuration that the
//! native evidence names. No forwarded header or supplied verdict constructs it.
use crate::enclave_vsock_v1::{VsockStreamV1, VsockShutdownV1};
use crate::native_oauth_exchange_v1::{self as wire, BrowserTls};
use rustls::{ServerConnection, StreamOwned};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;

const MAX_BODY: usize = 8 * 1024 * 1024;
#[derive(Clone,Copy)]
pub enum Kind { BeginPage, AuthorizePage, Draft, Authorize, Begin, Callback }
#[derive(Clone,Copy,PartialEq,Eq)]
enum Purpose { Unbound, Setup, Reconnect, Succession }
pub struct Accepted {
    stream: StreamOwned<ServerConnection, VsockStreamV1>, ingress: Arc<BrowserTls>, deadline: u64,
    kind: Kind, purpose: Purpose, body: Vec<u8>, query: String, provider: Option<String>, cookies: BTreeMap<String,String>, responded: bool,
}
impl Accepted {
    pub fn accept(stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline: u64) -> Result<Self,String> {
        Self::accept_for(stream, ingress, deadline, Purpose::Unbound)
    }
    pub fn accept_setup(stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline: u64) -> Result<Self,String> {
        Self::accept_for(stream, ingress, deadline, Purpose::Setup)
    }
    pub fn accept_reconnect(stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline: u64) -> Result<Self,String> {
        Self::accept_for(stream, ingress, deadline, Purpose::Reconnect)
    }
    pub fn accept_succession(stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline:u64)->Result<Self,String>{
        Self::accept_for(stream,ingress,deadline,Purpose::Succession)
    }
    fn accept_for(mut stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline: u64, purpose: Purpose) -> Result<Self,String> {
        ingress.check(deadline)?;
        stream.narrow_deadline(deadline).map_err(|_|"browser cannot renew its socket interval")?;
        stream.verify_connected_original(deadline).map_err(|_|"browser accepted socket changed")?;
        let connection = ServerConnection::new(ingress.config()).map_err(|_|"native browser TLS unavailable")?;
        let mut owner = Self { stream: StreamOwned::new(connection,stream), ingress, deadline,
            kind:Kind::BeginPage, purpose, body:Vec::new(),query:String::new(),provider:None,cookies:BTreeMap::new(),responded:false };
        while owner.stream.conn.is_handshaking() {
            owner.check()?;
            owner.stream.conn.complete_io(&mut owner.stream.sock).map_err(|_|"native browser TLS handshake failed")?;
        }
        let origin = wire::origin(owner.ingress.origin())?;
        wire::ensure(owner.stream.conn.server_name() == origin.host_str()
            && owner.stream.conn.alpn_protocol() == Some(b"http/1.1"), "native browser SNI or ALPN differs")?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            owner.check()?;
            let mut byte=[0u8;1]; owner.stream.read_exact(&mut byte).map_err(|_|"native browser request incomplete")?;
            header.push(byte[0]); wire::ensure(header.len() <= 16384,"native browser header bound")?;
        }
        let raw = std::str::from_utf8(&header).map_err(|_|"native browser header encoding")?;
        wire::ensure(raw.is_ascii(),"native browser header spelling")?;
        let mut lines = raw[..raw.len()-4].split("\r\n");
        let first: Vec<_> = lines.next().ok_or("native browser request line")?.split(' ').collect();
        wire::ensure(first.len()==3 && first[2]=="HTTP/1.1" && first[1].starts_with('/') && !first[1].starts_with("//")
            && !first[1].contains(['#','\\']) && matches!(first[0],"GET"|"POST"),"native browser request line differs")?;
        let mut headers=BTreeMap::new();
        for line in lines {
            let (name,value)=line.split_once(':').ok_or("native browser header malformed")?;
            wire::ensure(!name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || c==b'-')
                && !value.bytes().any(|c| c<32 && c!=9 || c==127) && headers.len()<64,"native browser header invalid")?;
            wire::ensure(headers.insert(name.to_ascii_lowercase(),value.trim().to_owned()).is_none(),"native browser header repeated")?;
        }
        wire::ensure(headers.get("host").map(String::as_str)==origin.host_str() && !headers.contains_key("transfer-encoding")
            && !headers.contains_key("content-encoding") && !headers.contains_key("authorization")
            && !headers.contains_key("expect"),"native browser origin or framing differs")?;
        let length=if let Some(value)=headers.get("content-length") {
            wire::ensure(!value.is_empty() && value.len()<=8 && value.bytes().all(|c|c.is_ascii_digit()),"native body length invalid")?;
            value.parse::<usize>().map_err(|_|"native body length overflow")?
        } else {0};
        wire::ensure(length<=MAX_BODY,"native browser body bound")?;
        let (path,query)=first[1].split_once('?').unwrap_or((first[1],""));
        owner.kind=match (first[0],path) {
            ("GET","/oauth/begin") if query.is_empty()=>Kind::BeginPage,
            ("GET","/oauth/authorize") if query.is_empty() && matches!(purpose,Purpose::Unbound|Purpose::Setup)=>Kind::AuthorizePage,
            ("POST","/oauth/draft") if query.is_empty() && matches!(purpose,Purpose::Unbound|Purpose::Setup)=>Kind::Draft,
            ("POST","/oauth/authorize") if query.is_empty() && matches!(purpose,Purpose::Unbound|Purpose::Setup)=>Kind::Authorize,
            ("POST","/oauth/begin") if query.is_empty() && matches!(purpose,Purpose::Reconnect|Purpose::Succession)=>Kind::Begin,
            ("GET","/oauth/callback/google"|"/oauth/callback/x") if !query.is_empty() && query.len()<=8192=>Kind::Callback,
            _=>return Err("native browser route is not fixed".to_owned()),
        };
        if matches!(owner.kind,Kind::Callback) { owner.provider=path.rsplit('/').next().map(str::to_owned); }
        if first[0]=="POST" {
            wire::ensure(length>0 && headers.get("origin").map(String::as_str)==Some(owner.ingress.origin())
                && headers.get("sec-fetch-site").map(String::as_str)==Some("same-origin")
                && headers.get("content-type").map(String::as_str)==Some("application/json"),"native browser POST lacks same-origin framing")?;
        } else {wire::ensure(length==0,"native browser GET body refused")?;}
        if let Some(cookie)=headers.get("cookie") {
            for pair in cookie.split(';') {
                let (name,value)=pair.trim().split_once('=').ok_or("native browser cookie malformed")?;
                wire::ensure(!name.is_empty() && owner.cookies.len()<32 && owner.cookies.insert(name.to_owned(),value.to_owned()).is_none(),"native browser cookie repeated")?;
            }
        }
        owner.query=query.to_owned(); owner.body.resize(length,0);
        let mut offset=0;
        while offset<length {
            owner.check()?;
            let end=(offset+16384).min(length);
            let n=owner.stream.read(&mut owner.body[offset..end]).map_err(|_|"native browser body incomplete")?;
            wire::ensure(n>0,"native browser body truncated")?; offset+=n;
        }
        owner.check()?;
        Ok(owner)
    }
    pub fn kind(&self)->&Kind{&self.kind}
    pub fn deadline(&self)->u64{self.deadline}
    pub fn shutdown_handle(&self)->Result<VsockShutdownV1,String>{self.stream.sock.shutdown_handle().map_err(|_|"native browser shutdown owner".to_owned())}
    pub fn check(&self)->Result<(),String>{
        self.ingress.check(self.deadline)?;
        self.stream.sock.verify_connected_original(self.deadline).map_err(|_|"native browser socket original changed".to_owned())
    }
    pub(crate) fn command(&self)->Result<Value,String>{
        wire::ensure(self.purpose == Purpose::Unbound, "Setup ingress cannot become unbound issuance")?;
        self.selected_command()
    }
    pub(crate) fn setup_command(&self)->Result<Value,String>{
        wire::ensure(self.purpose == Purpose::Setup, "unbound ingress cannot become Setup issuance")?;
        self.selected_command()
    }
    pub(crate) fn reconnect_command(&self)->Result<Value,String>{
        wire::ensure(self.purpose == Purpose::Reconnect, "another ingress purpose cannot become reconnect")?;
        self.selected_command()
    }
    pub(crate) fn succession_command(&self)->Result<Value,String>{
        wire::ensure(self.purpose==Purpose::Succession,"another ingress purpose cannot become retired-scope succession")?;
        self.selected_command()
    }
    pub(crate) fn verify_ingress(&self, expected:&Arc<BrowserTls>)->Result<(),String>{
        wire::ensure(Arc::ptr_eq(&self.ingress, expected), "browser request belongs to another actual TLS ingress")?;
        self.check()
    }
    fn selected_command(&self)->Result<Value,String>{
        self.check()?;
        let channel = match self.purpose {
            Purpose::Unbound => wire::CHANNEL,
            Purpose::Setup => crate::native_oauth_setup_v1::CHANNEL,
            Purpose::Reconnect => crate::native_oauth_reconnect_v1::CHANNEL,
            Purpose::Succession => crate::native_oauth_succession_v1::CHANNEL,
        };
        match self.kind {
            Kind::Begin=>{
                wire::ensure(matches!(self.purpose,Purpose::Reconnect|Purpose::Succession), "begin requires its actual independently selected ingress")?;
                let intent=crate::native_oauth_refresh_v1::response_document(&self.body)?;
                let command=serde_json::json!({"apiVersion":channel,"phase":"begin","intent":intent,"deadlineBoottimeNs":self.deadline});
                // Bound the complete encoded helper envelope, not only its
                // nested intent. The existing generic frame remains unchanged.
                wire::ensure(crate::native_response_profile_v1::canonical_ascii_bytes(&command)?.len()<=MAX_BODY,
                    "native reconnect complete envelope exceeds its original bound")?;
                Ok(command)
            },
            Kind::Draft=>{
                let intent=crate::native_oauth_refresh_v1::response_document(&self.body)?;
                wire::ensure(self.body.len()<=65536,"native public intent bound")?;
                Ok(serde_json::json!({"apiVersion":channel,"phase":"draft","intent":intent,"deadlineBoottimeNs":self.deadline}))
            },
            Kind::Authorize=>{
                let value=crate::native_oauth_refresh_v1::response_document(&self.body)?;
                wire::fields(&value,&["exchangeId","originals"])?;
                let id=value["exchangeId"].as_str().ok_or("native authorization exchange")?;
                wire::ensure(crate::native_currentness_v1::uuid(id),"native exchange identity")?;
                wire::fields(&value["originals"],&["requestOriginal","responseOriginal"])?;
                Ok(serde_json::json!({"apiVersion":channel,"phase":"authorize","exchangeId":id,
                    "browserNonce":self.nonce(id)?,"originals":value["originals"],"deadlineBoottimeNs":self.deadline}))
            },
            Kind::Callback=>{
                let mut states=url::form_urlencoded::parse(self.query.as_bytes()).filter(|(name,_)|name=="state");
                let state=states.next().ok_or("native callback state absent")?.1.into_owned();
                wire::ensure(states.next().is_none() && state.is_ascii() && state.len()==76 && state.as_bytes()[32]==b'_',"native callback state differs")?;
                let hex=&state[..32]; wire::ensure(hex.bytes().all(|b|b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),"native state identity")?;
                let id=format!("{}-{}-{}-{}-{}",&hex[..8],&hex[8..12],&hex[12..16],&hex[16..20],&hex[20..]);
                Ok(serde_json::json!({"apiVersion":channel,"phase":"callback","exchangeId":id,
                    "providerId":self.provider.as_deref().ok_or("native callback provider absent")?,
                    "browserNonce":self.nonce(&id)?,"query":self.query,"deadlineBoottimeNs":self.deadline}))
            },
            _=>Err("static native page has no helper command".to_owned()),
        }
    }
    fn nonce(&self,id:&str)->Result<&str,String>{
        let name=format!("__Host-serverware-native-oauth-{}",id.replace('-',""));
        self.cookies.get(&name).map(String::as_str).ok_or_else(||"original native browser cookie absent".to_owned())
    }
    pub fn respond(&mut self,content_type:&str,body:&[u8],cookie:Option<&str>,csp:&str)->Result<(),String>{
        self.check()?; wire::ensure(!self.responded && body.len()<=MAX_BODY
            && matches!(content_type,"application/json"|"text/html; charset=utf-8")
            && !csp.contains(['\r','\n']),"native browser response invalid")?;
        if let Some(value)=cookie{wire::ensure(value.len()<=512 && !value.contains(['\r','\n']),"native cookie framing")?;}
        self.responded=true;
        let mut header=format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: {csp}\r\n",body.len());
        if let Some(value)=cookie{header.push_str("Set-Cookie: ");header.push_str(value);header.push_str("\r\n");}
        header.push_str("\r\n");
        for piece in [header.as_bytes(),body] {
            for chunk in piece.chunks(16384){self.check()?;self.stream.write_all(chunk).map_err(|_|"native browser response uncertain")?;}
        }
        self.stream.flush().map_err(|_|"native browser response flush uncertain")?;
        self.check()
    }
}
impl Drop for Accepted {fn drop(&mut self){let _=self.stream.sock.shutdown();}}
