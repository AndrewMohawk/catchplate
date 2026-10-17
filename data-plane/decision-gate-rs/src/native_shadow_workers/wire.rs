//! Private consistency framing, never verifier or publication authority.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use super::{Purpose, image};

pub(super) const MAX_INPUT: usize = 32 * 1024 * 1024;
pub(super) const MAX_FRAME: usize = 4096;
pub(super) const WINDOW: u64 = 10_000_000_000;
pub(super) fn require(ok: bool) -> Result<(), String> {
    if ok { Ok(()) } else { Err("native shadow worker original binding unavailable".into()) }
}
pub(super) fn now() -> Result<u64, String> {
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    require(unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) } == 0
        && t.tv_sec >= 0 && (0..1_000_000_000).contains(&t.tv_nsec))?;
    (t.tv_sec as u64).checked_mul(1_000_000_000).and_then(|n| n.checked_add(t.tv_nsec as u64))
        .ok_or("native shadow clock overflow".into())
}
pub(super) fn sha(bytes: &[u8]) -> String { format!("sha256:{:x}", Sha256::digest(bytes)) }
pub(super) fn hash(s: &str) -> bool {
    s.len() == 71 && s.starts_with("sha256:") && s[7..].bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && s[7..].bytes().any(|c| c != b'0')
}
pub(super) fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    crate::canonical_json_bytes(v).map_err(|_| "native shadow canonical encoding failed".into())
}
pub(super) fn decode<T: serde::de::DeserializeOwned + Serialize>(b: &[u8]) -> Result<T, String> {
    crate::decode_canonical_json(b).map_err(|_| "native shadow canonical original differs".into())
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Bootstrap {
    pub(super) api_version: String,
    pub(super) channel_nonce: String,
    pub(super) deadline_boottime_ns: u64,
    pub(super) executable_sha256: [String; 3],
    pub(super) executable_path: [String; 3],
}
impl Bootstrap {
    pub(super) fn validate(&self) -> Result<(), String> {
        require(self.api_version == "catchplate.nativeShadowWorkerBootstrap/v1")?;
        validate_bootstrap(&self.channel_nonce,self.deadline_boottime_ns,&self.executable_sha256,&self.executable_path)
    }
}
fn validate_bootstrap(nonce:&str,deadline:u64,pins:&[String],paths:&[String])->Result<(),String> {
    use base64::Engine as _;
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(nonce)
        .map_err(|_| "native shadow channel nonce differs")?;
    require(b.len() == 32
        && b.iter().any(|v| *v != 0)
        && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b) == nonce
        && deadline > now()? && pins.iter().all(|s| hash(s))
        && paths.iter().all(|s| s.len() <= 4096 && s.starts_with('/') && !s.contains('\0')))
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct PublicationBootstrap {
    pub(super) api_version:String,
    pub(super) worker:Bootstrap,
    pub(super) publication_resources_sha256:String,
}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct RuntimeBootstrap {
    pub(super) api_version:String,
    pub(super) worker:Bootstrap,
    pub(super) runtime_resources_sha256:String,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(super) publication_resources_sha256:Option<String>,
}
/// The two positions are exactly Runtime and Publication. There is no
/// WebAuthn placeholder executable, hash or inherited descriptor.
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct NativeActivationBootstrap {
    pub(super) api_version:String,
    pub(super) channel_nonce:String,
    pub(super) deadline_boottime_ns:u64,
    pub(super) executable_sha256:[String;2],
    pub(super) executable_path:[String;2],
    pub(super) runtime_resources_sha256:String,
    pub(super) publication_resources_sha256:String,
}
#[derive(Serialize,Deserialize)]
#[serde(untagged)]
pub(super) enum WorkerBootstrap {Legacy(Bootstrap),Publication(PublicationBootstrap),Runtime(RuntimeBootstrap),NativeActivation(NativeActivationBootstrap)}
impl WorkerBootstrap {
    fn worker(&self)->Option<&Bootstrap> {
        match self {Self::Legacy(v)=>Some(v),Self::Publication(v)=>Some(&v.worker),Self::Runtime(v)=>Some(&v.worker),
            Self::NativeActivation(_)=>None}
    }
    pub(super) fn channel_nonce(&self)->&str {
        match self {Self::Legacy(v)=>&v.channel_nonce,Self::Publication(v)=>&v.worker.channel_nonce,
            Self::Runtime(v)=>&v.worker.channel_nonce,Self::NativeActivation(v)=>&v.channel_nonce}
    }
    pub(super) fn deadline(&self)->u64 {
        match self {Self::Legacy(v)=>v.deadline_boottime_ns,Self::Publication(v)=>v.worker.deadline_boottime_ns,
            Self::Runtime(v)=>v.worker.deadline_boottime_ns,Self::NativeActivation(v)=>v.deadline_boottime_ns}
    }
    pub(super) fn executable(&self,index:usize)->Option<(&str,&str)> {
        match self {
            Self::NativeActivation(v)=>match index {
                0=>Some((&v.executable_sha256[0],&v.executable_path[0])),
                2=>Some((&v.executable_sha256[1],&v.executable_path[1])),_=>None,
            },
            _=>self.worker().and_then(|v|v.executable_sha256.get(index).zip(v.executable_path.get(index)))
                .map(|(pin,path)|(pin.as_str(),path.as_str())),
        }
    }
    pub(super) fn publication(&self)->Option<&str> {
        match self {Self::Legacy(_)=>None,Self::Publication(v)=>Some(&v.publication_resources_sha256),
            Self::Runtime(v)=>v.publication_resources_sha256.as_deref(),
            Self::NativeActivation(v)=>Some(&v.publication_resources_sha256)}
    }
    pub(super) fn runtime(&self)->Option<&str> {
        match self {Self::Runtime(v)=>Some(&v.runtime_resources_sha256),
            Self::NativeActivation(v)=>Some(&v.runtime_resources_sha256),_=>None}
    }
    pub(super) fn validate(&self)->Result<(),String> {
        if let Some(worker)=self.worker() {worker.validate()?;}
        if let Self::Publication(v)=self {
            require(v.api_version=="catchplate.nativeShadowWorkerBootstrap/v2" && hash(&v.publication_resources_sha256))?;
        }
        if let Self::Runtime(v)=self {
            require(v.api_version=="catchplate.nativeShadowWorkerBootstrap/v3" && hash(&v.runtime_resources_sha256)
                && v.publication_resources_sha256.as_ref().is_none_or(|pin|hash(pin)))?;
        }
        if let Self::NativeActivation(v)=self {
            require(v.api_version=="catchplate.nativeShadowWorkerBootstrap/v4"
                && hash(&v.runtime_resources_sha256) && hash(&v.publication_resources_sha256))?;
            validate_bootstrap(&v.channel_nonce,v.deadline_boottime_ns,&v.executable_sha256,&v.executable_path)?;
            require(v.executable_path[0]==super::runtime_resources::EXECUTABLE
                && v.executable_path[1]=="/usr/local/bin/catchplate-native-publication-handoff")?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Request {
    pub(super) api_version: String, pub(super) sequence: u64, pub(super) purpose: Purpose,
    pub(super) input_sha256: String, pub(super) input_bytes: u64,
    pub(super) deadline_boottime_ns: u64, pub(super) channel_nonce: String,
    pub(super) bootstrap_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct ResultWire { pub(super) status: String, pub(super) output_sha256: String, pub(super) output_bytes: u64 }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Response { pub(super) api_version: String, pub(super) request: Request, pub(super) result: ResultWire }
#[derive(Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Initialized { pub(super) api_version: String, pub(super) channel_nonce: String, pub(super) bootstrap_sha256: String }

pub(super) fn input(request: &Request, file: std::fs::File, expected_uid: u32) -> Result<image::Sealed, String> {
    require(request.api_version == "catchplate.nativeShadowWorkerRequest/v1" && request.sequence > 0
        && hash(&request.input_sha256) && hash(&request.bootstrap_sha256)
        && request.input_bytes > 0 && request.input_bytes <= MAX_INPUT as u64)?;
    image::Sealed::receive(file, expected_uid, request.input_bytes, &request.input_sha256, false)
}
