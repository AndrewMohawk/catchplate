//! Fixed native-origin navigation only. Parent JavaScript sees public intent,
//! ciphertext and signed receipts, never browser nonce/state/verifier/code.
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest,Sha256};

pub(super) fn page(authorize:bool,portal_origin:&str)->Result<(Vec<u8>,String),String>{
    render(authorize, portal_origin, Purpose::Unbound)
}
pub(super) fn setup_page(authorize:bool,portal_origin:&str)->Result<(Vec<u8>,String),String>{
    render(authorize, portal_origin, Purpose::Setup)
}
enum Purpose { Unbound, Setup }
/// Reconnect arrives with the original signed family fence. It never creates
/// an issuance/Setup draft or sends private callback correlation to the portal.
pub(super) fn reconnect_page(portal_origin:&str)->Result<(Vec<u8>,String),String>{
    serverware_decision_gate::native_oauth_reconnect_v1::origin(portal_origin)?;
    let script=r#"'use strict';
const need=v=>{if(!v)throw new Error('Native reconnect unavailable; no automatic retry.');};
function decode(s){need(typeof s==='string'&&s.length>0&&s.length<=11184811&&/^[A-Za-z0-9_-]+$/.test(s));const b=atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4));need(b.length<=8*1024*1024);return new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(b,c=>c.charCodeAt(0)));}
let sent=false,original=null;
try{need(location.hash.startsWith('#original='));original=decode(location.hash.slice(10));}
catch(_){sent=true;document.getElementById('continue').disabled=true;document.getElementById('status').textContent='The original reconnect authorization is unavailable; no fallback.';}
history.replaceState(null,'',location.pathname);
document.getElementById('continue').onclick=async()=>{
  if(sent)return;sent=true;document.getElementById('continue').disabled=true;
  try{
    need(original!==null);const raw=original;original=null;
    const reply=await fetch('/oauth/begin',{method:'POST',credentials:'same-origin',redirect:'error',cache:'no-store',headers:{'Content-Type':'application/json'},body:raw,signal:AbortSignal.timeout(30000)});
    need(reply.status===200&&reply.headers.get('content-type')==='application/json');
    const text=await reply.text();need(new TextEncoder().encode(text).length<=64*1024);
    const result=JSON.parse(text);need(Object.keys(result).sort().join(',')==='apiVersion,exchangeId,location'&&result.apiVersion==='serverware.nativeOAuthReconnectAuthorizationRedirect/v1');
    const url=new URL(result.location);need(url.protocol==='https:'&&!url.username&&!url.password&&!url.hash&&!url.port
      &&((url.hostname==='accounts.google.com'&&url.pathname==='/o/oauth2/v2/auth')||(url.hostname==='twitter.com'&&url.pathname==='/i/oauth2/authorize')));
    location.assign(url.href);
  }catch(_){document.getElementById('status').textContent='Reconnect stopped. No provider retry or alternate endpoint was attempted. Return to the control-plane portal for status.';}
};
"#;
    let hash=STANDARD.encode(Sha256::digest(script.as_bytes()));
    let csp=format!("default-src 'none'; script-src 'sha256-{hash}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    let html=format!("<!doctype html><meta charset=utf-8><title>Serverware confidential reconnect</title><h1>Reconnect the authorized provider account</h1><p>The original family authorization and fence are checked before consent. The callback and private browser correlation stay at this native origin.</p><button id=continue type=button>Continue once</button><p id=status></p><script>{script}</script>");
    Ok((html.into_bytes(),csp))
}

fn render(authorize:bool,portal_origin:&str,purpose:Purpose)->Result<(Vec<u8>,String),String>{
    serverware_decision_gate::native_oauth_exchange_v1::origin(portal_origin)?;
    let portal=serde_json::to_string(portal_origin).map_err(|_|"native portal origin encoding")?;
    let action=if authorize {"authorize"} else {"begin"};
    let (fragment, redirect_schema) = match purpose {
        Purpose::Unbound => ("nativeOAuthDraft", "serverware.nativeOAuthAuthorizationRedirect/v1"),
        Purpose::Setup => ("nativeOAuthSetupDraft", "serverware.nativeOAuthSetupAuthorizationRedirect/v1"),
    };
    let script=format!(r#"'use strict';
const portal={portal},action='{action}';
const need=v=>{{if(!v)throw new Error('Native consent unavailable; no automatic retry.');}};
const encode=s=>{{const raw=new TextEncoder().encode(s);let bytes='';for(let i=0;i<raw.length;i+=8192)bytes+=String.fromCharCode(...raw.subarray(i,i+8192));return btoa(bytes).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');}};
function decode(s){{need(typeof s==='string'&&s.length>0&&s.length<=1048576&&/^[A-Za-z0-9_-]+$/.test(s));const b=atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4));return new TextDecoder('utf-8',{{fatal:true}}).decode(Uint8Array.from(b,c=>c.charCodeAt(0)));}}
let sent=false,original=null;
try{{need(location.hash.startsWith('#original='));original=decode(location.hash.slice(10));need(new TextEncoder().encode(original).length<=768*1024);}}
catch(_){{sent=true;document.getElementById('continue').disabled=true;document.getElementById('status').textContent='Native preparation is unavailable; no fallback.';}}
history.replaceState(null,'',location.pathname);
document.getElementById('continue').onclick=async()=>{{
  if(sent)return;sent=true;document.getElementById('continue').disabled=true;
  try{{
    need(original!==null);const raw=original;original=null;
    const path=action==='begin'?'/oauth/draft':'/oauth/authorize';
    const reply=await fetch(path,{{method:'POST',credentials:'same-origin',redirect:'error',cache:'no-store',headers:{{'Content-Type':'application/json'}},body:raw,signal:AbortSignal.timeout(30000)}});
    need(reply.status===200&&reply.headers.get('content-type')==='application/json');
    const text=await reply.text();need(new TextEncoder().encode(text).length<=768*1024);
    if(action==='begin'){{location.assign(portal+'/#{fragment}='+encode(text));return;}}
    const result=JSON.parse(text);need(Object.keys(result).sort().join(',')==='apiVersion,exchangeId,location'&&result.apiVersion==='{redirect_schema}');
    const url=new URL(result.location);need(url.protocol==='https:'&&!url.username&&!url.password&&!url.hash&&!url.port
      &&((url.hostname==='accounts.google.com'&&url.pathname==='/o/oauth2/v2/auth')||(url.hostname==='twitter.com'&&url.pathname==='/i/oauth2/authorize')));
    location.assign(url.href);
  }}catch(_){{document.getElementById('status').textContent='Consent stopped. No provider retry or alternate endpoint was attempted. Return to the control-plane portal for status.';}}
}};
"#);
    let hash=STANDARD.encode(Sha256::digest(script.as_bytes()));
    let csp=format!("default-src 'none'; script-src 'sha256-{hash}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    let html=format!("<!doctype html><meta charset=utf-8><title>Serverware confidential consent</title><h1>Confidential provider consent</h1><p>The provider callback and private browser correlation stay at this independently trusted native origin.</p><button id=continue type=button>Continue once</button><p id=status></p><script>{script}</script>");
    Ok((html.into_bytes(),csp))
}

pub(super) fn terminal(status:&str,portal_origin:&str)->Result<Vec<u8>,String>{
    serverware_decision_gate::native_oauth_exchange_v1::origin(portal_origin)?;
    if !matches!(status,"staged"|"observed-staged"|"cancelled"|"captured-unusable") {return Err("native result status differs".to_owned());}
    // Origin validation excludes markup and non-HTTPS navigation. No private
    // callback values, provider error bodies or credentials reach this page.
    Ok(format!("<!doctype html><meta charset=utf-8><title>Serverware consent status</title><h1>Consent status: {status}</h1><p>This is not credential activation or a retry grant.</p><a href=\"{portal_origin}/\" rel=noreferrer>Return to the control-plane portal</a>").into_bytes())
}
