//! Static-profile controls after private transport extraction.
//! No caller-created Accepted value or native socket acceptance is asserted.
use super::*;

#[test]
fn fixed_static_routes_remain_purpose_separated() {
    for (purpose, base, other) in [
        (Purpose::Creation, "/credentials/static", "/credentials/static/rotate"),
        (Purpose::Rotation, "/credentials/static/rotate", "/credentials/static"),
    ] {
        for (method, suffix, kind) in [("GET", "", Kind::Page),
                ("POST", "/intake", Kind::Intake), ("POST", "/prepare", Kind::Prepare)] {
            assert!(route(purpose, method, &format!("{base}{suffix}")).unwrap() == kind);
            assert!(route(purpose, method, &format!("{other}{suffix}")).is_err());
            for changed in [format!("{base}{suffix}?x=1"), format!("{base}{suffix}/"),
                    format!("{base}{suffix}#fragment")] {
                assert!(route(purpose, method, &changed).is_err());
            }
        }
        assert!(route(purpose, "HEAD", base).is_err());
        assert!(route(purpose, "POST", base).is_err());
        assert!(route(purpose, "GET", &format!("{base}/prepare")).is_err());
    }
}

#[test]
fn creation_rotation_pages_and_cookies_keep_distinct_domains() {
    let portal = "https://portal.example.test";
    let (creation, creation_csp) = page(portal).unwrap();
    let (rotation, rotation_csp) = crate::native_static_credential_rotation_browser_v1::page(portal).unwrap();
    for (body, csp, operation, base) in [
        (creation, creation_csp, "credential.static.create", "/credentials/static"),
        (rotation, rotation_csp, "credential.static.rotate", "/credentials/static/rotate"),
    ] {
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains(operation) && text.contains(base) && text.contains(portal));
        assert!(!text.contains("__PORTAL_ORIGIN_JSON__") && !text.contains("__SCRIPT_NONCE__"));
        assert!(csp.starts_with("default-src 'none'; script-src 'nonce-"));
        assert!(csp.contains("connect-src 'self'") && csp.contains("frame-ancestors 'none'"));
        assert!(text.contains("const originalOpener = window.opener;"));
    }
    let id = "12345678-1234-4123-8123-123456789abc";
    let nonce = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let expiry = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        + 60_000_000_000) as u64;
    let creation = cookie(id, &nonce, expiry).unwrap();
    let rotation = crate::native_static_credential_rotation_browser_v1::cookie(id, &nonce, expiry).unwrap();
    assert!(creation.starts_with("__Host-catchplate-native-static-12345678123441238123123456789abc="));
    assert!(rotation.starts_with("__Host-catchplate-native-static-rotate-12345678123441238123123456789abc="));
    for value in [creation, rotation] {
        assert!(value.contains("; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age="));
    }
    assert!(cookie("not-an-id", &nonce, expiry).is_err());
    assert!(cookie(id, "not-a-nonce", expiry).is_err());
    assert!(cookie(id, &nonce, 0).is_err());
}

#[test]
fn source_wiring_keeps_static_request_ownership_and_rotation_delegation() {
    // These are source-wiring controls, not executed native TLS acceptance.
    let source = include_str!("native_static_credential_browser_v1.rs");
    for guard in ["transport: Transport", "Transport::accept(stream, ingress, deadline)?",
        "owner.kind = route(purpose, first[0], first[1])?", "header.len() <= 16384",
        "length <= MAX_BODY", "owner.cookies.len() < 32", "owner.challenge = Some(nonce()?)",
        "self.transport.verify_ingress(expected)", "self.transport.respond(content_type, body, cookie, csp)",
        "self.body.zeroize();", "for value in self.cookies.values_mut() { value.zeroize(); }"] {
        assert!(source.contains(guard));
    }
    assert!(!source.contains("StreamOwned<"));
    let rotation = include_str!("native_static_credential_rotation_browser_v1.rs");
    assert!(rotation.contains("pub struct Accepted(shared::Accepted)"));
    assert!(rotation.contains("shared::Accepted::accept_rotation(stream, ingress, deadline).map(Self)"));
    assert!(rotation.contains("self.0.respond(content_type, body, cookie, csp)"));
    let root = include_str!("custody_protocol.rs");
    assert!(root.contains("\nmod native_browser_transport_v1;"));
    assert!(!root.contains("pub mod native_browser_transport_v1;"));
}
