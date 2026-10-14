//! Pure response framing/fence controls and labelled source-order checks.
//! No synthetic Transport/Accepted owner and no native TLS acceptance claim.
use super::*;

#[test]
fn response_headers_preserve_exact_static_wire_bytes() {
    let cookie = "__Host-serverware-native-static-0123=private-nonce; Path=/; Secure; HttpOnly";
    let header = response_header("application/json", 7, Some(cookie), "default-src 'none'").unwrap();
    assert_eq!(header.as_str(), format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 7\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'\r\nSet-Cookie: {cookie}\r\n\r\n"));
    let html = response_header("text/html; charset=utf-8", 0, None, "default-src 'none'").unwrap();
    assert!(html.contains("Content-Type: text/html; charset=utf-8\r\nContent-Length: 0\r\n"));
    assert!(!html.contains("Set-Cookie:"));
    assert!(html.ends_with("\r\n\r\n"));
}

#[test]
fn response_bounds_and_header_refusals_match_static_profile() {
    assert!(response_header("application/json", MAX_RESPONSE_BODY, None, "").is_ok());
    assert!(response_header("application/json", MAX_RESPONSE_BODY + 1, None, "").is_err());
    for content_type in ["text/plain", "APPLICATION/JSON", "application/json\r\nX-Test: 1"] {
        assert!(response_header(content_type, 0, None, "").is_err());
    }
    for csp in ["\r", "\n", "default-src 'none'\r\nX-Test: 1"] {
        assert!(response_header("application/json", 0, None, csp).is_err());
    }
    let exact = "x".repeat(512);
    assert!(response_header("application/json", 0, Some(&exact), "").is_ok());
    for cookie in ["x".repeat(513), "x\r".to_owned(), "x\n".to_owned()] {
        assert!(response_header("application/json", 0, Some(&cookie), "").is_err());
    }
}

#[test]
fn response_fence_has_no_rearm_after_an_attempt() {
    let mut fence = ResponseFence::default();
    assert!(fence.require_unspent().is_ok());
    fence.start().unwrap();
    assert!(fence.require_unspent().is_err());
    assert!(fence.start().is_err());
    assert!(fence.require_unspent().is_err());
}

#[test]
fn source_order_keeps_actual_transport_and_private_write_guards() {
    // Source-order assertions supplement pure helpers; they do not execute a
    // VSOCK handshake, prove native admission, or simulate a live TLS owner.
    let source = include_str!("native_browser_transport_v1.rs");
    assert!(source.contains("pub(crate) struct Transport"));
    assert!(!source.contains("pub fn "));
    assert!(source.contains("StreamOwned<ServerConnection, VsockStreamV1>"));
    let accept = source.split("pub(crate) fn accept(").nth(1).unwrap()
        .split("pub(crate) fn origin(").next().unwrap();
    for guard in ["stream.narrow_deadline(deadline)", "stream.verify_connected_original(deadline)",
        "ServerConnection::new(ingress.config())", "server_name() == origin.host_str()",
        "alpn_protocol() == Some(b\"http/1.1\")"] {
        assert!(accept.contains(guard));
    }
    assert!(accept.rfind("owner.check()?").unwrap() < accept.rfind("Ok(owner)").unwrap());
    assert!(source.contains("Arc::ptr_eq(&self.ingress, expected)"));
    assert!(!source.contains("impl Read for Transport"));
    let respond = source.split("pub(crate) fn respond(").nth(1).unwrap()
        .split("impl Drop for Transport").next().unwrap();
    assert!(respond.find("self.response.start()?").unwrap() < respond.find("self.stream.write_all(chunk)").unwrap());
    assert!(respond.contains("for chunk in piece.chunks(IO_CHUNK) {\n                self.check()?;"));
    assert!(respond.contains("self.stream.flush()"));
    assert!(source.contains("let _ = self.stream.sock.shutdown();"));
    assert!(source.contains("Result<Zeroizing<String>, String>"));
    let header = source.split("fn response_header(").nth(1).unwrap();
    assert!(header.find("header.reserve(").unwrap() < header.find("header.push_str(value)").unwrap());
}
