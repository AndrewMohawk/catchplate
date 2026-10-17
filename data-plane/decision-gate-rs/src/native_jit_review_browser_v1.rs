//! Purpose-fixed review requests on the retained native TLS owner. No bytes,
//! forwarded TLS verdict or portal cookie can construct an accepted request.
use crate::native_browser_transport_v1::Transport;
use crate::enclave_vsock_v1::{VsockShutdownV1, VsockStreamV1};
use crate::native_oauth_exchange_v1::{self as wire, BrowserTls};
use crate::native_currentness_v1 as current;
use crate::native_jit_review_open_v1::{require, fields};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};
use zeroize::Zeroizing;

const MAX_BODY: usize = 8 * 1024 * 1024;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind { Page, Challenge, Prepare, Disclose }
pub struct Accepted {
    transport: Transport, kind: Kind, body: Zeroizing<Vec<u8>>,
    cookies: BTreeMap<String, Zeroizing<String>>,
}
impl Accepted {
    pub fn accept(stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline: u64) -> Result<Self, String> {
        let transport = Transport::accept(stream, ingress, deadline)?;
        let origin = wire::origin(transport.origin())?;
        let mut held = Self { transport, kind: Kind::Page, body: Zeroizing::new(Vec::new()), cookies: BTreeMap::new() };
        let mut header = Zeroizing::new(Vec::new());
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1]; held.transport.read_exact(&mut byte)?; header.push(byte[0]);
            require(header.len() <= 16384)?;
        }
        let text = std::str::from_utf8(&header).map_err(|_| "review header UTF8")?;
        require(text.is_ascii())?;
        let mut lines = text[..text.len()-4].split("\r\n");
        let request: Vec<_> = lines.next().ok_or("review request line")?.split(' ').collect();
        require(request.len() == 3 && request[2] == "HTTP/1.1")?;
        held.kind = route(request[0], request[1])?;
        let mut headers = BTreeMap::new();
        for line in lines {
            let (name, value) = line.split_once(':').ok_or("review header")?;
            require(!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !value.bytes().any(|b| b < 32 && b != 9 || b == 127) && headers.len() < 64)?;
            require(headers.insert(name.to_ascii_lowercase(), Zeroizing::new(value.trim().to_owned())).is_none())?;
        }
        let get = |name: &str| headers.get(name).map(|value| value.as_str());
        require(get("host") == origin.host_str() && get("transfer-encoding").is_none()
            && get("content-encoding").is_none() && get("authorization").is_none() && get("expect").is_none())?;
        let length = match get("content-length") {
            Some(v) => { require(!v.is_empty() && v.len() <= 8 && v.bytes().all(|b| b.is_ascii_digit()))?;
                v.parse::<usize>().map_err(|_| "review length")? }, None => 0,
        };
        require(length <= MAX_BODY)?;
        if held.kind == Kind::Page { require(length == 0)?; }
        else { require(length > 0 && get("origin") == Some(held.transport.origin())
            && get("sec-fetch-site") == Some("same-origin") && get("content-type") == Some("application/json"))?; }
        if let Some(cookies) = get("cookie") {
            for item in cookies.split(';') {
                let (name, value) = item.trim().split_once('=').ok_or("review cookie")?;
                require(!name.is_empty() && held.cookies.len() < 32
                    && held.cookies.insert(name.to_owned(), Zeroizing::new(value.to_owned())).is_none())?;
            }
        }
        held.body.resize(length, 0); let mut offset = 0;
        while offset < length {
            let end = (offset + 16384).min(length);
            let n = held.transport.read(&mut held.body[offset..end])?; require(n > 0)?; offset += n;
        }
        held.check()?; Ok(held)
    }
    pub fn deadline(&self) -> u64 { self.transport.deadline() }
    pub fn shutdown_handle(&self) -> Result<VsockShutdownV1, String> { self.transport.shutdown_handle() }
    pub(crate) fn kind(&self) -> Kind { self.kind }
    pub(crate) fn check(&self) -> Result<(), String> { self.transport.check() }
    pub(crate) fn narrow_deadline(&mut self, deadline: u64) -> Result<(), String> { self.transport.narrow_deadline(deadline) }
    pub(crate) fn verify_ingress(&self, owner: &Arc<BrowserTls>) -> Result<(), String> { self.transport.verify_ingress(owner) }
    pub(crate) fn input(&self) -> Result<Value, String> {
        self.check()?;
        let value = crate::native_oauth_refresh_v1::response_document(&self.body)?;
        fields(&value, match self.kind {
            Kind::Challenge => &["approvalRequestId"],
            Kind::Prepare => &["reviewId", "authorizationOriginal", "parentOriginal", "childOriginal", "pairOriginal", "proofOriginal"],
            Kind::Disclose => &["reviewId", "commitAckOriginal"],
            Kind::Page => return Err("review page has no operation".into()),
        })?;
        Ok(value)
    }
    pub(crate) fn cookie(&self, id: &str) -> Result<&str, String> {
        self.check()?;
        let name = cookie_name(id)?;
        let value = self.cookies.get(&name).ok_or("review native cookie absent")?;
        current::bytes32(value)?; Ok(value)
    }
    // Only the admitted review owner may choose the purpose response bytes.
    pub(crate) fn respond(&mut self, content_type: &str, body: &[u8], cookie: Option<&str>, csp: &str) -> Result<(), String> {
        self.transport.respond(content_type, body, cookie, csp)
    }
}
fn route(method: &str, path: &str) -> Result<Kind, String> {
    match (method, path) {
        ("GET", "/reviews/jit") => Ok(Kind::Page),
        ("POST", "/reviews/jit/challenge") => Ok(Kind::Challenge),
        ("POST", "/reviews/jit/prepare") => Ok(Kind::Prepare),
        ("POST", "/reviews/jit/disclose") => Ok(Kind::Disclose),
        _ => Err("review fixed route refused".into()),
    }
}
pub(crate) fn cookie_name(id: &str) -> Result<String, String> {
    require(current::uuid(id))?;
    Ok(format!("__Host-catchplate-native-jit-review-{}", id.replace('-', "")))
}
pub(crate) fn cookie(id: &str, nonce: &str, remaining_seconds: u64) -> Result<Zeroizing<String>, String> {
    current::bytes32(nonce)?; require((1..=300).contains(&remaining_seconds))?;
    Ok(Zeroizing::new(format!("{}={nonce}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={remaining_seconds}", cookie_name(id)?)))
}
pub(crate) fn page(portal: &str) -> Result<(Vec<u8>, String), String> {
    wire::origin(portal)?;
    let mut entropy = [0u8; 32]; SystemRandom::new().fill(&mut entropy).map_err(|_| "review page nonce")?;
    let nonce = URL_SAFE_NO_PAD.encode(entropy);
    let portal = serde_json::to_string(portal).map_err(|_| "review origin")?.replace('<', "\\u003c");
    let page = include_str!("native_jit_review_browser_page.html").replace("__PORTAL__", &portal).replace("__NONCE__", &nonce);
    Ok((page.into_bytes(), format!("default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn review_routes_are_closed_and_separate_from_static() {
        for (method,path,kind) in [("GET","/reviews/jit",Kind::Page),
            ("POST","/reviews/jit/challenge",Kind::Challenge),("POST","/reviews/jit/prepare",Kind::Prepare),
            ("POST","/reviews/jit/disclose",Kind::Disclose)] { assert!(route(method,path).unwrap()==kind); }
        for (method,path) in [("GET","/reviews/jit/prepare"),("POST","/reviews/jit"),
            ("POST","/credentials/static/prepare"),("POST","/reviews/jit/disclose?retry=1"),
            ("POST","/reviews/jit/disclose/"),("GET","/reviews/jit#approval")] { assert!(route(method,path).is_err()); }
    }
    #[test]
    fn review_cookie_has_its_own_bounded_host_only_domain() {
        let id="00000000-0000-4000-8000-000000000001";
        let nonce=URL_SAFE_NO_PAD.encode([7u8;32]);
        let value=cookie(id,&nonce,30).unwrap();
        assert!(value.starts_with("__Host-catchplate-native-jit-review-00000000000040008000000000000001="));
        assert!(value.ends_with("; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=30"));
        assert!(cookie(id,&nonce,1).unwrap().ends_with("Max-Age=1"));
        assert!(cookie(id,&nonce,0).is_err());assert!(cookie(id,&nonce,301).is_err());
        assert!(cookie("not-an-id",&nonce,30).is_err());assert!(cookie(id,"wrong",30).is_err());
    }
    #[test]
    fn review_page_keeps_private_content_on_native_origin() {
        let (bytes,csp)=page("https://portal.example.test").unwrap();
        let html=String::from_utf8(bytes).unwrap();
        assert!(!html.contains("__PORTAL__")&&!html.contains("__NONCE__"));
        assert!(html.contains("event.source!==source||event.origin!==portal"));
        assert!(html.contains("view.textContent=text"));
        assert!(html.contains("send({type:\"catchplate.native-jit-review.disclosed\",reviewId})"));
        assert!(html.contains("phase=\"disclosure-attempted\""));
        assert!(html.contains("reader=response.body.getReader()")&&html.contains("size>maximum"));
        assert!(html.contains("deadline=Math.min(deadline,performance.now()+remaining)"));
        assert!(!html.contains("postMessage(view")&&!html.contains("postMessage(text"));
        assert!(csp.contains("connect-src 'self'")&&csp.contains("frame-ancestors 'none'"));
    }
}
