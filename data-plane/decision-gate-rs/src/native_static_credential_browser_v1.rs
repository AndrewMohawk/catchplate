//! Fixed static-secret intake on the actual enclave-terminated TLS stream.
//! No public byte constructor or forwarded TLS assertion creates Accepted.
use crate::enclave_vsock_v1::{VsockShutdownV1, VsockStreamV1};
use crate::native_currentness_v1 as current;
use crate::native_oauth_exchange_v1::{self as wire, BrowserTls};
use crate::native_response_profile_v1::canonical_ascii_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::SecureRandom;
use rustls::{ServerConnection, StreamOwned};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const CHANNEL: &str = "serverware.nativeStaticCredentialChannel/v1";
const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_ORIGINAL: usize = 2 * 1024 * 1024;
const MAX_SECRET: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose { Creation, Rotation }

impl Purpose {
    fn channel(self) -> &'static str {
        match self { Self::Creation => CHANNEL,
            Self::Rotation => "serverware.nativeStaticCredentialRotationChannel/v1" }
    }
    fn path(self) -> &'static str {
        match self { Self::Creation => "/credentials/static", Self::Rotation => "/credentials/static/rotate" }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind { Page, Intake, Prepare }

pub struct Accepted {
    stream: StreamOwned<ServerConnection, VsockStreamV1>,
    ingress: Arc<BrowserTls>, deadline: u64, kind: Kind, body: Vec<u8>,
    cookies: BTreeMap<String, String>, challenge: Option<String>, responded: bool,
    purpose: Purpose,
}

impl Accepted {
    pub fn accept(stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline: u64) -> Result<Self, String> {
        Self::accept_for(stream, ingress, deadline, Purpose::Creation)
    }

    pub(crate) fn accept_rotation(stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline: u64) -> Result<Self, String> {
        Self::accept_for(stream, ingress, deadline, Purpose::Rotation)
    }

    fn accept_for(mut stream: VsockStreamV1, ingress: Arc<BrowserTls>, deadline: u64, purpose: Purpose) -> Result<Self, String> {
        ingress.check(deadline)?;
        stream.narrow_deadline(deadline).map_err(|_| "static browser cannot renew its socket interval")?;
        stream.verify_connected_original(deadline).map_err(|_| "static browser accepted socket changed")?;
        let connection = ServerConnection::new(ingress.config()).map_err(|_| "static browser TLS unavailable")?;
        let mut owner = Self { stream: StreamOwned::new(connection, stream), ingress, deadline,
            kind: Kind::Page, body: Vec::new(), cookies: BTreeMap::new(), challenge: None, responded: false, purpose };
        while owner.stream.conn.is_handshaking() {
            owner.check()?;
            owner.stream.conn.complete_io(&mut owner.stream.sock).map_err(|_| "static browser TLS handshake failed")?;
        }
        let origin = wire::origin(owner.ingress.origin())?;
        wire::ensure(owner.stream.conn.server_name() == origin.host_str()
            && owner.stream.conn.alpn_protocol() == Some(b"http/1.1"), "static browser SNI or ALPN differs")?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            owner.check()?;
            let mut byte = [0u8; 1];
            owner.stream.read_exact(&mut byte).map_err(|_| "static browser request incomplete")?;
            header.push(byte[0]);
            wire::ensure(header.len() <= 16384, "static browser header bound")?;
        }
        let raw = std::str::from_utf8(&header).map_err(|_| "static browser header encoding")?;
        wire::ensure(raw.is_ascii(), "static browser header spelling")?;
        let mut lines = raw[..raw.len() - 4].split("\r\n");
        let first: Vec<_> = lines.next().ok_or("static browser request line")?.split(' ').collect();
        wire::ensure(first.len() == 3 && first[2] == "HTTP/1.1", "static browser request line differs")?;
        owner.kind = match (purpose, first[0], first[1]) {
            (Purpose::Creation, "GET", "/credentials/static")
                | (Purpose::Rotation, "GET", "/credentials/static/rotate") => Kind::Page,
            (Purpose::Creation, "POST", "/credentials/static/intake")
                | (Purpose::Rotation, "POST", "/credentials/static/rotate/intake") => Kind::Intake,
            (Purpose::Creation, "POST", "/credentials/static/prepare")
                | (Purpose::Rotation, "POST", "/credentials/static/rotate/prepare") => Kind::Prepare,
            _ => return Err("static browser route is not fixed".to_owned()),
        };
        let mut headers = BTreeMap::new();
        for line in lines {
            let (name, value) = line.split_once(':').ok_or("static browser header malformed")?;
            wire::ensure(!name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                && !value.bytes().any(|c| c < 32 && c != 9 || c == 127) && headers.len() < 64,
                "static browser header invalid")?;
            wire::ensure(headers.insert(name.to_ascii_lowercase(), value.trim().to_owned()).is_none(),
                "static browser header repeated")?;
        }
        wire::ensure(headers.get("host").map(String::as_str) == origin.host_str()
            && !headers.contains_key("transfer-encoding") && !headers.contains_key("content-encoding")
            && !headers.contains_key("authorization") && !headers.contains_key("expect"),
            "static browser origin or framing differs")?;
        let length = if let Some(value) = headers.get("content-length") {
            wire::ensure(!value.is_empty() && value.len() <= 8 && value.bytes().all(|c| c.is_ascii_digit()),
                "static browser body length invalid")?;
            value.parse::<usize>().map_err(|_| "static browser body length overflow")?
        } else { 0 };
        wire::ensure(length <= MAX_BODY, "static browser body bound")?;
        if owner.kind == Kind::Page {
            wire::ensure(length == 0, "static browser GET body refused")?;
        } else {
            wire::ensure(length > 0 && headers.get("origin").map(String::as_str) == Some(owner.ingress.origin())
                && headers.get("sec-fetch-site").map(String::as_str) == Some("same-origin")
                && headers.get("content-type").map(String::as_str) == Some("application/json"),
                "static browser POST lacks same-origin framing")?;
        }
        if let Some(cookie) = headers.get("cookie") {
            for pair in cookie.split(';') {
                let (name, value) = pair.trim().split_once('=').ok_or("static browser cookie malformed")?;
                wire::ensure(!name.is_empty() && owner.cookies.len() < 32
                    && owner.cookies.insert(name.to_owned(), value.to_owned()).is_none(), "static browser cookie repeated")?;
            }
        }
        owner.body.resize(length, 0);
        let mut offset = 0;
        while offset < length {
            owner.check()?;
            let end = (offset + 16384).min(length);
            let count = owner.stream.read(&mut owner.body[offset..end]).map_err(|_| "static browser body incomplete")?;
            wire::ensure(count > 0, "static browser body truncated")?;
            offset += count;
        }
        if owner.kind == Kind::Prepare {
            // The browser cannot select the attestation challenge. It is held
            // on this exact accepted request and never regenerated by command.
            owner.challenge = Some(nonce()?);
        }
        owner.check()?;
        Ok(owner)
    }

    pub fn kind(&self) -> &Kind { &self.kind }
    pub fn deadline(&self) -> u64 { self.deadline }
    pub fn shutdown_handle(&self) -> Result<VsockShutdownV1, String> {
        self.stream.sock.shutdown_handle().map_err(|_| "static browser shutdown owner".to_owned())
    }
    pub fn check(&self) -> Result<(), String> {
        self.ingress.check(self.deadline)?;
        self.stream.sock.verify_connected_original(self.deadline).map_err(|_| "static browser socket original changed".to_owned())
    }
    pub(crate) fn verify_ingress(&self, expected: &Arc<BrowserTls>) -> Result<(), String> {
        wire::ensure(Arc::ptr_eq(&self.ingress, expected), "static request belongs to another actual TLS ingress")?;
        self.check()
    }
    pub(crate) fn command(&self) -> Result<Value, String> {
        self.check()?;
        let value = crate::native_oauth_refresh_v1::response_document(&self.body)?;
        let result = match self.kind {
            Kind::Intake => {
                wire::fields(&value, &["intentOriginal", "secret"])?;
                let intent = original(&value["intentOriginal"])?;
                let secret = value["secret"].as_str().ok_or("static UTF-8 secret absent")?;
                wire::ensure(!secret.is_empty() && secret.len() <= MAX_SECRET, "static secret bound")?;
                json!({"apiVersion": self.purpose.channel(), "phase": "intake", "intentOriginal": intent,
                    "secretBase64url": URL_SAFE_NO_PAD.encode(secret.as_bytes()), "deadlineBoottimeNs": self.deadline})
            },
            Kind::Prepare => {
                wire::fields(&value, &["credentialId", "argumentsOriginal"])?;
                let id = value["credentialId"].as_str().ok_or("static credential identity absent")?;
                let name = cookie_name(id, self.purpose)?;
                let cookie = self.cookies.get(&name).ok_or("original static browser cookie absent")?;
                current::bytes32(cookie)?;
                json!({"apiVersion": self.purpose.channel(), "phase": "prepare-execution", "credentialId": id,
                    "argumentsOriginal": original(&value["argumentsOriginal"])?, "browserNonce": cookie,
                    "challenge": self.challenge.as_deref().ok_or("static native challenge absent")?,
                    "deadlineBoottimeNs": self.deadline})
            },
            Kind::Page => return Err("static page has no helper command".to_owned()),
        };
        wire::ensure(canonical_ascii_bytes(&result)?.len() <= MAX_BODY, "static complete private frame bound")?;
        self.check()?;
        Ok(result)
    }

    pub fn respond(&mut self, content_type: &str, body: &[u8], cookie: Option<&str>, csp: &str) -> Result<(), String> {
        self.check()?;
        wire::ensure(!self.responded && body.len() <= MAX_BODY
            && matches!(content_type, "application/json" | "text/html; charset=utf-8")
            && !csp.contains(['\r', '\n']), "static browser response invalid")?;
        if let Some(value) = cookie {
            wire::ensure(value.len() <= 512 && !value.contains(['\r', '\n']), "static cookie framing")?;
        }
        self.responded = true;
        let mut header = format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: {csp}\r\n", body.len());
        if let Some(value) = cookie { header.push_str("Set-Cookie: "); header.push_str(value); header.push_str("\r\n"); }
        header.push_str("\r\n");
        for piece in [header.as_bytes(), body] {
            for chunk in piece.chunks(16384) {
                self.check()?;
                self.stream.write_all(chunk).map_err(|_| "static browser response uncertain")?;
            }
        }
        self.stream.flush().map_err(|_| "static browser response flush uncertain")?;
        self.check()
    }
}

impl Drop for Accepted {
    fn drop(&mut self) {
        self.body.zeroize();
        for value in self.cookies.values_mut() { value.zeroize(); }
        let _ = self.stream.sock.shutdown();
    }
}

fn original(value: &Value) -> Result<&str, String> {
    let value = value.as_str().ok_or("static original must remain a literal string")?;
    wire::ensure(!value.is_empty() && value.is_ascii() && value.len() <= MAX_ORIGINAL, "static original bound")?;
    Ok(value)
}

fn nonce() -> Result<String, String> {
    let mut raw = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut raw).map_err(|_| "static native entropy unavailable")?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn cookie_name(id: &str, purpose: Purpose) -> Result<String, String> {
    wire::ensure(current::uuid(id), "static cookie credential identity")?;
    let prefix = match purpose { Purpose::Creation => "__Host-serverware-native-static-",
        Purpose::Rotation => "__Host-serverware-native-static-rotate-" };
    Ok(format!("{prefix}{}", id.replace('-', "")))
}

pub fn cookie(id: &str, value: &str, expires: u64) -> Result<String, String> {
    cookie_for(id, value, expires, Purpose::Creation)
}

pub(crate) fn rotation_cookie(id: &str, value: &str, expires: u64) -> Result<String, String> {
    cookie_for(id, value, expires, Purpose::Rotation)
}

fn cookie_for(id: &str, value: &str, expires: u64, purpose: Purpose) -> Result<String, String> {
    let name = cookie_name(id, purpose)?;
    current::bytes32(value)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "static cookie clock")?.as_nanos();
    wire::ensure(now < u128::from(expires) && u128::from(expires) - now <= 3_600_000_000_000,
        "static cookie original expiry")?;
    let age = (u128::from(expires) - now) / 1_000_000_000;
    Ok(format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={age}"))
}

/// Only the cold-configured portal and the retained original opener may hand
/// off public originals. JavaScript never re-encodes their nanosecond integers
/// or metadata. The optional manual fragment likewise contains no secret.
pub fn page(portal_origin: &str) -> Result<(Vec<u8>, String), String> {
    page_for(portal_origin, Purpose::Creation)
}

pub(crate) fn rotation_page(portal_origin: &str) -> Result<(Vec<u8>, String), String> {
    page_for(portal_origin, Purpose::Rotation)
}

fn page_for(portal_origin: &str, purpose: Purpose) -> Result<(Vec<u8>, String), String> {
    wire::origin(portal_origin)?;
    let portal = serde_json::to_string(portal_origin).map_err(|_| "static portal origin encoding")?
        .replace('<', "\\u003c");
    let nonce = nonce()?;
    let (title, effect, action, completed, prefix, intent, operation) = match purpose {
        Purpose::Creation => ("Native static credential intake", "create a credential", "Create", "create a credential",
            "serverware.nativeStaticCredential", "serverware.staticCredentialCreationIntent/v1", "credential.static.create"),
        Purpose::Rotation => ("Native static credential rotation", "replace the current credential", "Rotate", "rotate a credential",
            "serverware.nativeStaticCredentialRotation", "serverware.staticCredentialRotationIntent/v1", "credential.static.rotate"),
    };
    let body = PAGE.replace("__PURPOSE_TITLE__", title).replace("__EFFECT__", effect)
        .replace("__ACTION__", action).replace("__COMPLETED__", completed)
        .replace("__MESSAGE_PREFIX__", prefix).replace("__INTENT_SCHEMA__", intent)
        .replace("__OPERATION__", operation).replace("__BASE_PATH__", purpose.path())
        .replace("__SCRIPT_NONCE__", &nonce)
        .replace("__PORTAL_ORIGIN_JSON__", &portal).into_bytes();
    let csp = format!("default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    Ok((body, csp))
}

const PAGE: &str = r##"<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__PURPOSE_TITLE__</title>
<h1>__PURPOSE_TITLE__</h1>
<p>Enter a secret only on this native TLS page. The portal receives encrypted candidate material, never this secret. Sealing and preparation do not __EFFECT__ or prove approval.</p>
<p id="status" role="status">Waiting for the original portal's public intent…</p>
<pre id="selection"></pre>
<form id="intake" hidden><label for="secret">Secret (exact UTF-8; whitespace is preserved)</label><br>
<textarea id="secret" rows="5" cols="64" autocomplete="off" autocapitalize="off" spellcheck="false" required></textarea><br>
<button id="seal" type="submit">Seal this candidate once</button></form>
<button id="prepare" type="button" hidden>Prepare fresh evidence once</button>
<p>Only public encrypted candidate material and fresh evidence return to the original portal. __ACTION__ there is a separate explicit hardware-approved action. No database change or retry occurs on this page. The literal public result is also shown below.</p>
<textarea id="result" rows="14" cols="90" readonly aria-label="Public candidate or evidence"></textarea>
<script nonce="__SCRIPT_NONCE__">
(() => {
  'use strict';
  const status = document.getElementById('status');
  const selection = document.getElementById('selection');
  const intake = document.getElementById('intake');
  const secret = document.getElementById('secret');
  const seal = document.getElementById('seal');
  const prepare = document.getElementById('prepare');
  const result = document.getElementById('result');
  const portalOrigin = __PORTAL_ORIGIN_JSON__;
  const originalOpener = window.opener;
  const prefix = '__MESSAGE_PREFIX__';
  let original = '', mode = '', id = '', selected = false;
  let intakeAttempted = false, preparationAttempted = false, sealedCandidate = null;
  const fragment = location.hash.slice(1);
  history.replaceState(null, '', '__BASE_PATH__');
  const fields = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
  const literal = value => typeof value === 'string' && value.length > 0
    && value.length <= 2097152 && /^[\x00-\x7f]+$/.test(value);
  const identity = value => typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
  function send(value) {
    if (!originalOpener || originalOpener.closed) return false;
    originalOpener.postMessage(value, portalOrigin);
    return true;
  }
  function select(value, phase) {
    if (selected) throw new Error();
    selected = true;
    if (!literal(value)) throw new Error();
    const view = JSON.parse(value);
    const request = view.request;
    if (!request || !identity(request.credentialId) || typeof request.name !== 'string'
        || typeof request.kind !== 'string') throw new Error();
    if (phase === 'intake' && (view.apiVersion !== '__INTENT_SCHEMA__'
        || view.operation !== '__OPERATION__')) throw new Error();
    original = value; mode = phase; id = request.credentialId;
    selection.textContent = `Credential: ${id}\nActor: ${mode === 'intake' ? view.actorId : view.actor_id}\nName: ${request.name}\nKind: ${request.kind}`;
    intake.hidden = mode !== 'intake'; prepare.hidden = mode !== 'prepare';
    status.textContent = mode === 'intake' ? 'Review the selected intent, then enter the secret here.'
      : 'This prepares fresh evidence for the same retained candidate. Its approval and current state are verified separately.';
  }
  function refused() {
    status.textContent = 'Outcome uncertain or refused. This page will not retry. Preserve the selected identity and resolve through the portal.';
  }
  async function post(phase, payload) {
    // Originals remain strings: only this outer transport wrapper is encoded.
    const body = JSON.stringify(payload);
    const response = await fetch(`__BASE_PATH__/${phase}`, {method: 'POST',
      credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      headers: {'Content-Type': 'application/json'}, body});
    if (!response.ok || response.redirected || response.headers.get('content-type') !== 'application/json') throw new Error();
    const raw = await response.text();
    if (!raw || raw.length > 8388608) throw new Error();
    return {raw, reply: JSON.parse(raw)};
  }
  async function sealOnce(event) {
    event.preventDefault();
    if (mode !== 'intake' || !original || intakeAttempted) return;
    if (!secret.value || new TextEncoder().encode(secret.value).length > 1048576) {
      status.textContent = 'Enter a nonempty UTF-8 secret of at most 1 MiB.'; return;
    }
    let payload = {intentOriginal: original, secret: secret.value};
    intakeAttempted = true; seal.disabled = true;
    secret.value = ''; secret.disabled = true;
    status.textContent = 'Sealing once. Do not repeat if delivery is uncertain.';
    try {
      const pending = post('intake', payload); payload = null;
      const {raw, reply} = await pending;
      if (!fields(reply, ['apiVersion', 'candidate'])
          || reply.apiVersion !== prefix + 'CandidateResponse/v1'
          || !fields(reply.candidate, ['credentialId', 'intentOriginal', 'nativeGenerationOriginal', 'intentSha256', 'generationSha256', 'expiresAtEpochNs'])
          || reply.candidate.credentialId !== id || reply.candidate.intentOriginal !== original
          || !literal(reply.candidate.nativeGenerationOriginal)) throw new Error();
      sealedCandidate = reply.candidate;
      // Display and transfer the literal response, never parsed timestamps.
      result.value = raw;
      status.textContent = 'Encrypted candidate retained. Return to the original portal for independent approval and explicit __ACTION__. Keep this page open.';
      send({apiVersion: prefix + 'CandidateMessage/v1', candidateOriginal: raw});
    } catch (_) {
      sealedCandidate = null; refused();
    } finally { payload = null; }
  }
  async function prepareOnce(argumentsOriginal, credentialId, fromPortal) {
    if (preparationAttempted) return;
    preparationAttempted = true; prepare.disabled = true;
    try {
      if (!literal(argumentsOriginal) || credentialId !== id) throw new Error();
      const args = JSON.parse(argumentsOriginal);
      if (!fields(args, ['actor_id', 'control_plane_configuration_digest', 'credential_policy', 'request', 'approval_id'])
          || !args.request || args.request.credentialId !== id
          || (fromPortal && (!sealedCandidate
            || args.request.nativeGenerationOriginal !== sealedCandidate.nativeGenerationOriginal))) throw new Error();
      status.textContent = 'Preparing once for the original portal request. Do not retry if delivery is uncertain.';
      const {raw, reply} = await post('prepare', {credentialId, argumentsOriginal});
      if (!fields(reply, ['apiVersion', 'argumentsOriginal', 'evidence'])
          || reply.apiVersion !== prefix + 'PreparationResponse/v1'
          || reply.argumentsOriginal !== argumentsOriginal || !reply.evidence) throw new Error();
      result.value = raw;
      status.textContent = 'Fresh evidence prepared once. The original portal must independently authorize the database change; this page did not __COMPLETED__.';
      if (fromPortal) send({apiVersion: prefix + 'PreparedMessage/v1', preparationOriginal: raw});
    } catch (_) {
      refused();
      if (fromPortal) {
        try { send({apiVersion: prefix + 'PrepareFailedMessage/v1', credentialId, argumentsOriginal, outcome: 'uncertain'}); }
        catch (_) { /* The original portal must also fence a missing response. */ }
      }
    }
  }
  intake.addEventListener('submit', sealOnce);
  prepare.addEventListener('click', () => {
    if (mode === 'prepare' && original && !originalOpener) void prepareOnce(original, id, false);
  });
  window.addEventListener('message', event => {
    if (!originalOpener || event.source !== originalOpener || event.origin !== portalOrigin) return;
    const value = event.data;
    if (fields(value, ['apiVersion', 'intentOriginal']) && value.apiVersion === prefix + 'IntentMessage/v1') {
      if (selected) return;
      try { select(value.intentOriginal, 'intake'); } catch (_) { refused(); }
    } else if (fields(value, ['apiVersion', 'credentialId', 'argumentsOriginal'])
        && value.apiVersion === prefix + 'PrepareMessage/v1') {
      if (mode !== 'intake' || !sealedCandidate || preparationAttempted) return;
      void prepareOnce(value.argumentsOriginal, value.credentialId, true);
    }
  });
  try {
    if (fragment) {
      const query = new URLSearchParams(fragment);
      if ([...query.keys()].length !== 1 || !(query.has('intent') || query.has('prepare'))) throw new Error();
      const phase = query.has('intent') ? 'intake' : 'prepare';
      // Manual prepare needs a separate explicit button and the original
      // HttpOnly cookie. A portal-owned page never adopts a fragment execution.
      if (phase === 'prepare' && originalOpener) throw new Error();
      select(query.get(phase === 'intake' ? 'intent' : 'prepare'), phase);
    } else if (!send({apiVersion: prefix + 'ReadyMessage/v1'})) {
      status.textContent = 'Open this page from the credential portal, or supply a public intent fragment. Do not enter a secret without a selected intent.';
    }
  } catch (_) {
    selected = true; original = ''; intake.hidden = true; prepare.hidden = true;
    status.textContent = 'A valid public intent or fresh execution original is required. Return to the portal; do not enter a secret.';
  }
})();
</script></html>"##;
