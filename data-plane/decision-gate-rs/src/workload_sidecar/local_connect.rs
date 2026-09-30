//! Local CONNECT authentication only, never native admission or forwarding.
//!
//! The retained caller must check the workload, accepted loopback peer, actual
//! network namespace and original lifetime before and after this function. It
//! must read exactly through CRLFCRLF without consuming inner TLS bytes, and
//! must not contact native ingress until this function succeeds. No supplied
//! local header is returned; construct the upstream CONNECT independently.

use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub(super) const MAX_HEAD_BYTES: usize = 8192;
const MAX_LINES: usize = 64; // Request line and header lines, excluding final CRLF.
const MAX_USERNAME_BYTES: usize = 128;
const TOKEN_BYTES: usize = 32;
const TOKEN_TEXT_BYTES: usize = 43;
const MAX_BASIC_TEXT_BYTES: usize = 232;

struct WipedHead<'a>(&'a mut [u8]);
impl Drop for WipedHead<'_> {
    fn drop(&mut self) { self.0.zeroize(); }
}

fn username(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_USERNAME_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn destination(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else { return false; };
    if host.is_empty() || host.len() > 253 || host.parse::<std::net::IpAddr>().is_ok()
        || !host.split('.').all(|label| !label.is_empty() && label.len() <= 63
            && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
    {
        return false;
    }
    port.parse::<u16>().is_ok_and(|number| number != 0 && number.to_string() == port)
}

fn basic(value: &str, expected_username: &str, token_sha256: &[u8; 32]) -> Result<(), ()> {
    let (scheme, encoded) = value.split_once(' ').ok_or(())?;
    if !scheme.eq_ignore_ascii_case("Basic") || encoded.is_empty() || encoded.len() > MAX_BASIC_TEXT_BYTES {
        return Err(());
    }
    // Allocate zeroizing destinations before decoding: even partially written
    // output from a failed decode is wiped. Extra bytes cover decoder estimates.
    let mut decoded = Zeroizing::new([0u8; 174]);
    let length = STANDARD.decode_slice(encoded.as_bytes(), &mut decoded[..]).map_err(|_| ())?;
    let expected_length = expected_username.len() + 1 + TOKEN_TEXT_BYTES;
    if length != expected_length || &decoded[..expected_username.len()] != expected_username.as_bytes()
        || decoded[expected_username.len()] != b':'
    {
        return Err(());
    }
    let mut canonical_basic = Zeroizing::new([0u8; MAX_BASIC_TEXT_BYTES]);
    let canonical_length = STANDARD.encode_slice(&decoded[..length], &mut canonical_basic[..]).map_err(|_| ())?;
    if &canonical_basic[..canonical_length] != encoded.as_bytes() { return Err(()); }

    let token = &decoded[expected_username.len() + 1..length];
    let mut decoded_token = Zeroizing::new([0u8; TOKEN_BYTES + 1]);
    let token_length = URL_SAFE_NO_PAD.decode_slice(token, &mut decoded_token[..]).map_err(|_| ())?;
    if token_length != TOKEN_BYTES || !decoded_token[..TOKEN_BYTES].iter().any(|byte| *byte != 0) {
        return Err(());
    }
    let mut canonical_token = Zeroizing::new([0u8; TOKEN_TEXT_BYTES]);
    let token_text_length = URL_SAFE_NO_PAD.encode_slice(&decoded_token[..TOKEN_BYTES], &mut canonical_token[..])
        .map_err(|_| ())?;
    if token_text_length != TOKEN_TEXT_BYTES || &canonical_token[..] != token { return Err(()); }
    // The independently pinned digest commits to the exact 43 ASCII token
    // bytes, not the decoded random value or the whole Basic credential.
    let digest: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(token).into());
    ring::constant_time::verify_slices_are_equal(&digest[..], token_sha256).map_err(|_| ())
}

fn parse(head: &[u8], expected_username: &str, token_sha256: &[u8; 32],
    allowed_destinations: &[String]) -> Result<String, ()>
{
    if !username(expected_username) || !token_sha256.iter().any(|byte| *byte != 0)
        || !(1..=64).contains(&allowed_destinations.len())
        || allowed_destinations.iter().enumerate().any(|(index, value)| !destination(value)
            || allowed_destinations[..index].contains(value))
        || head.len() > MAX_HEAD_BYTES || !head.ends_with(b"\r\n\r\n")
    {
        return Err(());
    }
    let text = std::str::from_utf8(head).map_err(|_| ())?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let mut request = lines.next().ok_or(())?.split(' ');
    let method = request.next().ok_or(())?;
    let target = request.next().ok_or(())?;
    let version = request.next().ok_or(())?;
    if method != "CONNECT" || !matches!(version, "HTTP/1.0" | "HTTP/1.1") || request.next().is_some()
        || !destination(target) || !allowed_destinations.iter().any(|allowed| allowed == target)
    {
        return Err(());
    }
    let (mut host, mut user_agent, mut connection, mut proxy_connection) = (false, false, false, false);
    let mut authorization = None;
    for (index, line) in lines.enumerate() {
        if index >= MAX_LINES - 1 || line.is_empty() || line.starts_with(' ') || line.starts_with('\t')
            || !line.bytes().all(|byte| (32..=126).contains(&byte) || byte == b'\t')
        {
            return Err(());
        }
        let (name, value) = line.split_once(':').ok_or(())?;
        let value = value.trim_matches(|character| character == ' ' || character == '\t');
        if name.eq_ignore_ascii_case("Host") {
            if host || value != target { return Err(()); }
            host = true;
        } else if name.eq_ignore_ascii_case("Proxy-Authorization") {
            if authorization.replace(value).is_some() { return Err(()); }
        } else if name.eq_ignore_ascii_case("User-Agent") {
            if user_agent || value.is_empty() || value.len() > 512
                || !value.bytes().all(|byte| (32..=126).contains(&byte)) { return Err(()); }
            user_agent = true;
        } else if name.eq_ignore_ascii_case("Connection") || name.eq_ignore_ascii_case("Proxy-Connection") {
            let seen = if name.eq_ignore_ascii_case("Connection") { &mut connection } else { &mut proxy_connection };
            if *seen || !(value.eq_ignore_ascii_case("keep-alive") || value.eq_ignore_ascii_case("close")) {
                return Err(());
            }
            *seen = true;
        } else {
            // Includes Content-Length (even zero), Transfer-Encoding, Upgrade,
            // caller identity headers and every unrecognized extension.
            return Err(());
        }
    }
    if version == "HTTP/1.1" && !host { return Err(()); }
    basic(authorization.ok_or(())?, expected_username, token_sha256)?;
    Ok(target.to_owned())
}

/// Returns only an authenticated, exact allowlisted destination. Entire input
/// storage is zeroized on success, refusal or unwind; all deny errors are public
/// generic strings. The caller retains source/namespace/workload/expiry checks.
pub(super) fn authenticate_connect(head: &mut [u8], expected_username: &str,
    token_sha256: &[u8; 32], allowed_destinations: &[String]) -> Result<String, String>
{
    let held = WipedHead(head);
    parse(&*held.0, expected_username, token_sha256, allowed_destinations)
        .map_err(|_| "local CONNECT authentication refused".to_owned())
}
