//! Pure contract/owned-buffer tests; no sockets, registry, archive extraction or SDK execution.
use super::*;
use flate2::{write::GzEncoder, Compression, GzBuilder};
use std::io::Write;

fn config(mode: &str) -> Value {
    json!({"credentialBinding":{"credentialType":"static","provider":"operator-demo",
        "subjects":["synthetic-install"],"secretClass":"bearerToken"},
        "packages":["@fixture/leaf","fixture"],"mode":mode,
        "request":request_config(mode).unwrap(),"response":response_profile(mode, false).unwrap()})
}

fn route(mode: &str) -> Route {
    let mut route = crate::tests::test_snapshot(1).routes[0].clone();
    route.adapter_type = ADAPTER.into();
    route.adapter_config = config(mode);
    route.scheme = "https".into(); route.host = HOST.into(); route.port = 443;
    route.methods = HashSet::from([if mode == "audit" { "POST".into() } else { "GET".into() }]);
    route.paths = route_paths(mode).unwrap().into_iter().map(|path| crate::compile_template(path).unwrap()).collect();
    route.credential_ref = Some("synthetic-install-credential".into());
    route.credential_header = Some(json!({"mode":"replaceExact","expectedValue":PLACEHOLDER}));
    route.discard_headers = DISCARD.iter().map(|name| name.to_string()).collect();
    route.constraints = vec![envelope(mode, "install-response").unwrap()];
    route.jit = json!({}); route.response_observation = None;
    route
}

fn wire_policy(mode: &str) -> Value {
    json!({"id":"synthetic-install-route","principals":["synthetic-install-app"],
        "credentialRef":"synthetic-install-credential",
        "credentialHeader":{"mode":"replaceExact","expectedValue":PLACEHOLDER},
        "match":{"scheme":"https","host":HOST,"port":443,
            "methods":[if mode == "audit" { "POST" } else { "GET" }],"paths":route_paths(mode).unwrap()},
        "adapter":{"type":ADAPTER,"config":config(mode)},
        "constraints":[envelope(mode, "install-response").unwrap()]})
}

fn gzip(raw: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(raw).unwrap(); encoder.finish().unwrap()
}

fn request(method: &str, path: &str) -> DecisionRequest {
    serde_json::from_value(json!({"method":method,"url":format!("https://{HOST}{path}"),"headers":{}})).unwrap()
}

fn audit_request(document: &[u8]) -> DecisionRequest {
    let wire = gzip(document);
    let owner = AuditBody::from_wire(&wire).unwrap();
    let mut req = request("POST", AUDIT_PATH);
    req.headers = BTreeMap::from([("content-type".into(), "application/json".into()),
        ("content-encoding".into(), "gzip".into()), ("content-length".into(), wire.len().to_string())]);
    req.body = owner.decoded_text().into();
    req.body_sha256 = Some(crate::sha256_prefixed(&wire));
    req.forwarded_body_length = Some(wire.len() as u64);
    req.forwarded_body_utf8_valid = Some(std::str::from_utf8(&wire).is_ok());
    req.npm_install_audit_body = Some(owner);
    req
}

fn operation(req: &DecisionRequest, mode: &str) -> Value {
    validate_request(req, &Url::parse(&req.url).unwrap(), &route(mode)).unwrap()
}

fn response(mode: &str, req: &DecisionRequest, status: u16, media: &str,
    bytes: Vec<u8>, guard: &ResponseSecretGuard) -> Result<SensitiveResponseBytes, Value> {
    inspect_response(&Url::parse(&req.url).unwrap(), StatusCode::from_u16(status).unwrap(), Some(media),
        &response_profile(mode, status >= 400).unwrap(), bytes.into(), guard, &config(mode), &operation(req, mode))
}

#[test]
fn npm_install_profiles_are_closed_and_mode_specific() {
    for mode in ["metadata", "tarball", "audit"] {
        let config = config(mode);
        validate_config(&config, &[envelope(mode, "e").unwrap()]).unwrap();
        assert_eq!(config["request"]["maxBodyBytes"], if mode == "audit" { 65536 } else { 0 });
        assert_eq!(config["response"]["error"]["maxBodyBytes"], 65536);
        assert_eq!(config["request"]["discardHeaders"], json!(["accept-encoding", "npm-session"]));
        for other in ["metadata", "tarball", "audit"].into_iter().filter(|other| *other != mode) {
            let mut changed = config.clone(); changed["request"] = request_config(other).unwrap();
            changed["response"] = response_profile(other, false).unwrap();
            assert!(validate_config(&changed, &[envelope(mode, "e").unwrap()]).is_err());
        }
    }
    for mode in ["", "install", "Metadata", "stream"] {
        assert!(request_profile(mode).is_err()); assert!(response_profile(mode, false).is_err());
        assert!(route_paths(mode).is_err()); assert!(envelope(mode, "e").is_err());
    }
    assert_eq!(request_config("tarball").unwrap()["allowedHeaders"][5], "pacote-integrity");
    assert_eq!(response_profile("tarball", false).unwrap()["maxBodyBytes"], 8 * 1024 * 1024);
    assert_eq!(TARBALL_DECODED_BYTES, 32 * 1024 * 1024);
    assert_eq!(AUDIT_DECODED_BYTES, 256 * 1024);
}

#[test]
fn npm_install_binding_and_package_closure_cannot_be_widened() {
    for (pointer, value) in [
        ("/credentialBinding/provider", json!("npm")), ("/credentialBinding/credentialType", json!("oauth2")),
        ("/credentialBinding/subjects", json!(["one", "two"])), ("/credentialBinding/subjects", json!([" "])),
        ("/packages", json!([])), ("/packages", json!(["fixture", "fixture"])),
        ("/packages", json!(["fixture", "@fixture/leaf"])), ("/packages", json!(["@fixture%2fleaf"])),
        ("/packages", json!(["*"])), ("/packages", json!(["Fixture"])),
        ("/request/maxBodyBytes", json!(1)), ("/request/allowedQueryKeys", json!(["write"])),
    ] {
        let mut changed = config("metadata"); *changed.pointer_mut(pointer).unwrap() = value;
        assert!(validate_config(&changed, &[envelope("metadata", "e").unwrap()]).is_err(), "{pointer}");
    }
    let mut changed = config("metadata"); changed["extra"] = json!(true);
    assert!(validate_config(&changed, &[envelope("metadata", "e").unwrap()]).is_err());
    let names = (0..64).map(|index| format!("package-{index:03}")).collect::<Vec<_>>();
    let mut maximum = config("metadata"); maximum["packages"] = json!(names);
    validate_config(&maximum, &[envelope("metadata", "e").unwrap()]).unwrap();
    maximum["packages"].as_array_mut().unwrap().push(json!("package-064"));
    assert!(validate_config(&maximum, &[envelope("metadata", "e").unwrap()]).is_err());
}

#[test]
fn npm_install_routes_and_response_envelopes_are_exact() {
    for mode in ["metadata", "tarball", "audit"] {
        validate_route(&route(mode)).unwrap();
        validate_policy(wire_policy(mode).as_object().unwrap()).unwrap();
        for (pointer, value) in [("/match/host", json!("elsewhere.example")), ("/match/port", json!(444)),
            ("/match/methods", json!(["GET", "POST"])), ("/match/paths", json!(["/**"])),
            ("/credentialHeader/expectedValue", json!("Bearer other")),
            ("/constraints/0/contentTypes", json!(["application/json", "text/plain"]))] {
            let mut changed = wire_policy(mode); *changed.pointer_mut(pointer).unwrap() = value;
            assert!(validate_policy(changed.as_object().unwrap()).is_err());
        }
        let mut changed = route(mode); changed.paths[0] = crate::compile_template("/**").unwrap();
        assert!(validate_route(&changed).is_err());
        for field in ["jit", "responseObservation"] {
            let mut changed = wire_policy(mode); changed[field] = json!({});
            assert!(validate_policy(changed.as_object().unwrap()).is_err());
        }
    }
    assert!(validate_envelope(Some(METADATA_MODE), &[]).is_err());
    assert!(validate_envelope(Some(METADATA_MODE), &[envelope("audit", "e").unwrap()]).is_err());
}

#[test]
fn npm_install_metadata_binds_canonical_selected_package_capture() {
    for (path, package) in [("/fixture", "fixture"), ("/@fixture%2fleaf", "@fixture/leaf")] {
        let req = request("GET", path); let route = route("metadata"); let url = Url::parse(&req.url).unwrap();
        let matched = RouteMatch { route: &route, params: route.paths[0].matches_canonical(url.path()).unwrap() };
        assert_eq!(normalize_request(&req, &url, &matched).unwrap(),
            (json!({"operation":"npm.install.metadata.read","package":package}), json!({})));
        let wrong = RouteMatch { route: &route, params: BTreeMap::new() };
        assert!(normalize_request(&req, &url, &wrong).is_err());
    }
    for path in ["/other", "/@fixture%2Fleaf", "/@fixture/leaf", "/fixture?", "/fixture/",
        "/%66ixture", "/fixture#fragment", "/fixture/-/fixture-1.0.0.tgz"] {
        let req = request("GET", path);
        assert!(validate_request(&req, &Url::parse(&req.url).unwrap(), &route("metadata")).is_err(), "{path}");
    }
    for raw in ["https://registry.npmjs.org:443/fixture", "https://REGISTRY.npmjs.org/fixture",
        "https://registry.npmjs.org./fixture", "https://registry.npmjs.org/a/../fixture"] {
        let mut req = request("GET", "/fixture"); req.url = raw.into();
        assert!(validate_request(&req, &Url::parse(raw).unwrap(), &route("metadata")).is_err());
    }
}

#[test]
fn npm_install_tarball_authority_stands_alone_for_cold_ci() {
    for (path, package, version) in [("/fixture/-/fixture-1.2.3.tgz", "fixture", "1.2.3"),
        ("/@fixture/leaf/-/leaf-2.0.0-beta.1+build.2.tgz", "@fixture/leaf", "2.0.0-beta.1+build.2")] {
        let req = request("GET", path);
        assert_eq!(operation(&req, "tarball"), json!({"operation":"npm.install.tarball.read",
            "package":package,"version":version}));
    }
    for path in ["/fixture/-/other-1.0.0.tgz", "/@other/leaf/-/leaf-1.0.0.tgz",
        "/@fixture%2fleaf/-/leaf-1.0.0.tgz", "/@fixture/leaf/-/@fixture/leaf-1.0.0.tgz",
        "/fixture/-/fixture-01.0.0.tgz", "/fixture/-/fixture-latest.tgz",
        "/fixture/-/fixture-1.0.0.tgz?token=x", "/fixture/-/fixture-1.0.0.tar"] {
        let req = request("GET", path);
        assert!(validate_request(&req, &Url::parse(&req.url).unwrap(), &route("tarball")).is_err(), "{path}");
    }
}

#[test]
fn npm_install_get_never_admits_body_or_audit_encoding() {
    for mode in ["metadata", "tarball"] {
        let path = if mode == "metadata" { "/fixture" } else { "/fixture/-/fixture-1.0.0.tgz" };
        for change in 0..6 {
            let mut req = request("GET", path);
            match change { 0 => req.body = "{}".into(), 1 => req.forwarded_body_length = Some(2),
                2 => { req.headers.insert("content-encoding".into(), "gzip".into()); },
                3 => { req.headers.insert("transfer-encoding".into(), "chunked".into()); },
                4 => { req.headers.insert("content-type".into(), "application/json".into()); },
                _ => req.method = "HEAD".into() }
            assert!(validate_request(&req, &Url::parse(&req.url).unwrap(), &route(mode)).is_err());
        }
    }
}

#[test]
fn npm_install_audit_head_is_exact_and_requires_selected_route() {
    let req = audit_request(br#"{"fixture":["1.0.0"]}"#);
    let length = req.npm_install_audit_body.as_ref().unwrap().wire().len();
    let url = Url::parse(&req.url).unwrap();
    admit_audit_head(&route("audit"), "POST", &url, &req.headers, length).unwrap();
    for (key, value) in [("content-encoding", "identity"), ("content-encoding", "Gzip"),
        ("content-length", "0"), ("content-length", "00069"), ("content-type", "application/octet-stream"),
        ("transfer-encoding", "chunked"), ("Content-Encoding", "gzip")] {
        let mut headers = req.headers.clone(); headers.insert(key.into(), value.into());
        assert!(admit_audit_head(&route("audit"), "POST", &url, &headers, length).is_err());
    }
    for key in ["content-length", "content-encoding", "content-type"] {
        let mut headers = req.headers.clone(); headers.remove(key);
        assert!(admit_audit_head(&route("audit"), "POST", &url, &headers, length).is_err());
    }
    assert!(admit_audit_head(&route("metadata"), "POST", &url, &req.headers, length).is_err());
    assert!(admit_audit_head(&route("audit"), "POST", &url, &req.headers, 65537).is_err());
}

#[test]
fn npm_install_gzip_is_single_complete_crc_checked_and_bounded() {
    let raw = gzip(b"12345678");
    assert_eq!(&*bounded_gzip(&raw, raw.len() as u64, 8).unwrap(), b"12345678");
    assert!(bounded_gzip(&raw, raw.len() as u64 - 1, 8).is_err());
    assert!(bounded_gzip(&raw, raw.len() as u64, 7).is_err());
    let mut corrupt = raw.clone(); let crc = corrupt.len() - 8; corrupt[crc] ^= 1;
    let mut trailing = raw.clone(); trailing.push(0);
    let mut concatenated = raw.clone(); concatenated.extend_from_slice(&raw);
    for invalid in [Vec::new(), gzip(b""), b"not gzip".to_vec(), raw[..raw.len() - 1].to_vec(), corrupt, trailing, concatenated] {
        assert!(bounded_gzip(&invalid, 65536, 256).is_err());
    }
    assert!(AuditBody::from_wire(&vec![0; 65537]).is_err());
    assert!(AuditBody::from_wire(&gzip(&vec![b' '; AUDIT_DECODED_BYTES + 1])).is_err());
}

#[test]
fn npm_install_audit_json_requires_closed_package_version_map() {
    for body in [br#"[]"#.as_slice(), br#"{}"#, br#"{"fixture":[]}"#, br#"{"fixture":["1.0.0","1.0.0"]}"#,
        br#"{"fixture":["1.0.0"],"fixture":["2.0.0"]}"#, br#"{"fixture":["latest"]}"#,
        br#"{"fixture":[-0]}"#, br#"{"fixture":[1e999]}"#, br#"{"Fixture":["1.0.0"]}"#,
        br#"{"fixture":["1.0.0"]} trailing"#] {
        assert!(AuditBody::from_wire(&gzip(body)).is_err());
    }
    let many = json!({"fixture":(0..129).map(|index| format!("1.0.{index}")).collect::<Vec<_>>()});
    assert!(AuditBody::from_wire(&gzip(&serde_json::to_vec(&many).unwrap())).is_err());
}

#[test]
fn npm_install_audit_operation_is_derived_only_from_owned_wire() {
    let req = audit_request(br#"{"fixture":["2.0.0","1.0.0"],"@fixture/leaf":["1.0.0"]}"#);
    assert_eq!(operation(&req, "audit"), json!({"operation":"npm.install.audit.read",
        "packages":["@fixture/leaf","fixture"],
        "packageVersions":{"@fixture/leaf":["1.0.0"],"fixture":["1.0.0","2.0.0"]}}));
    let owner = req.npm_install_audit_body.as_ref().unwrap();
    assert!(owner.clone().matches_wire(owner.wire()));
    assert!(!owner.matches_wire(b"different"));
    assert_eq!(format!("{owner:?}"), "AuditBody([redacted])");
    for change in 0..6 {
        let mut changed = req.clone();
        match change { 0 => changed.npm_install_audit_body = None, 1 => changed.body.clear(),
            2 => changed.body_sha256 = Some(crate::sha256_prefixed(changed.body.as_bytes())),
            3 => changed.forwarded_body_length = Some(0), 4 => changed.forwarded_body_utf8_valid = Some(true),
            _ => changed.body = "{\"other\":[\"1.0.0\"]}".into() }
        assert!(validate_request(&changed, &Url::parse(&changed.url).unwrap(), &route("audit")).is_err());
    }
    let mut caller: DecisionRequest = serde_json::from_value(json!({"method":"POST","url":req.url,
        "headers":req.headers,"body":req.body,"bodySha256":req.body_sha256,
        "npm_install_audit_body":{"wire":[1,2,3]},"forwarded_body_length":69})).unwrap();
    assert!(caller.npm_install_audit_body.is_none());
    caller.forwarded_body_length = req.forwarded_body_length;
    assert!(validate_request(&caller, &Url::parse(&caller.url).unwrap(), &route("audit")).is_err());
    let outside = audit_request(br#"{"unselected":["1.0.0"]}"#);
    assert!(validate_request(&outside, &Url::parse(&outside.url).unwrap(), &route("audit")).is_err());
}

#[test]
fn npm_install_metadata_response_preserves_bytes_and_checks_identity() {
    let req = request("GET", "/fixture"); let guard = ResponseSecretGuard::default();
    let raw = b" {\"name\":\"fixture\",\"versions\":{},\"extra\":true} \n".to_vec();
    for media in ["application/json", "application/vnd.npm.install-v1+json; charset=utf-8"] {
        assert_eq!(&*response("metadata", &req, 200, media, raw.clone(), &guard).unwrap(), &raw);
    }
    for raw in [br#"{"name":"other"}"#.as_slice(), br#"[]"#, br#"{"name":"fixture","name":"fixture"}"#] {
        assert!(response("metadata", &req, 200, "application/json", raw.to_vec(), &guard).is_err());
    }
    assert!(response("metadata", &req, 304, "application/json", Vec::new(), &guard).is_err());
    assert!(response("metadata", &req, 200, "text/plain", b"{}".to_vec(), &guard).is_err());
    assert!(response("metadata", &req, 404, "application/json", br#"{"error":"missing"}"#.to_vec(), &guard).is_ok());
}

#[test]
fn npm_install_tarball_preserves_original_gzip_and_scans_both_views() {
    let req = request("GET", "/fixture/-/fixture-1.0.0.tgz");
    let guard = ResponseSecretGuard::default();
    // Inspection treats archive contents as bytes; this is deliberately not an
    // archive-validity or extraction-safety assertion.
    let raw = gzip(b"bounded synthetic archive bytes");
    assert_eq!(&*response("tarball", &req, 200, "application/octet-stream", raw.clone(), &guard).unwrap(), &raw);
    let mut guarded = ResponseSecretGuard::default(); guarded.add_text_encodings("synthetic-protected-token");
    let reflected = gzip(b"archive synthetic-protected-token file");
    assert_eq!(response("tarball", &req, 200, "application/octet-stream", reflected, &guarded).err().unwrap()["error"],
        "response_credential_reflection");
    let mut header = GzBuilder::new().comment("synthetic-protected-token")
        .write(Vec::new(), Compression::fast());
    header.write_all(b"otherwise inert").unwrap();
    assert_eq!(response("tarball", &req, 200, "application/octet-stream", header.finish().unwrap(), &guarded)
        .err().unwrap()["error"], "response_credential_reflection");
    let mut suffix = raw.clone(); suffix.push(0);
    for invalid in [b"opaque raw body".to_vec(), suffix, [raw.clone(), raw].concat()] {
        assert!(response("tarball", &req, 200, "application/octet-stream", invalid, &guard).is_err());
    }
    assert!(response("tarball", &req, 200, "application/json", gzip(b"{}"), &guard).is_err());
    assert!(response("tarball", &req, 404, "application/json", b"{}".to_vec(), &guard).is_ok());
}

#[test]
fn npm_install_audit_response_binds_actual_requested_package_subset() {
    let req = audit_request(br#"{"fixture":["1.0.0"]}"#); let guard = ResponseSecretGuard::default();
    for raw in [br#"{}"#.as_slice(), br#"{"fixture":[{"id":1,"title":"synthetic advisory"}]}"#] {
        assert_eq!(&*response("audit", &req, 200, "application/json", raw.to_vec(), &guard).unwrap(), raw);
    }
    for raw in [br#"{"@fixture/leaf":[]}"#.as_slice(), br#"{"outside":[]}"#,
        br#"{"fixture":{}}"#, br#"{"fixture":["not an advisory object"]}"#, br#"[]"#] {
        assert!(response("audit", &req, 200, "application/json", raw.to_vec(), &guard).is_err());
    }
    assert!(response("audit", &req, 400, "application/json", br#"{"error":"refused"}"#.to_vec(), &guard).is_ok());
    let mut forged = operation(&req, "audit"); forged["packages"] = json!(["@fixture/leaf"]);
    assert!(inspect_response(&Url::parse(&req.url).unwrap(), StatusCode::OK, Some("application/json"),
        &response_profile("audit", false).unwrap(), b"{}".to_vec().into(), &guard, &config("audit"), &forged).is_err());
}

#[test]
fn npm_install_json_response_inspects_decoded_secret_reflection_and_limits() {
    let req = request("GET", "/fixture");
    let mut guard = ResponseSecretGuard::default(); guard.add_text_encodings("secret-fixture");
    let escaped = br#"{"name":"fixture","extra":"\u0073ecret-fixture"}"#.to_vec();
    assert_eq!(response("metadata", &req, 200, "application/json", escaped, &guard).err().unwrap()["error"],
        "response_credential_reflection");
    assert!(response("metadata", &req, 500, "application/json", vec![b' '; ERROR_BYTES as usize + 1], &guard).is_err());
    let audit = audit_request(br#"{"fixture":["1.0.0"]}"#);
    assert!(response("audit", &audit, 200, "application/json", vec![b' '; JSON_BYTES as usize + 1], &guard).is_err());
}

#[test]
fn npm_install_capability_and_media_do_not_relabel_old_grants() {
    assert_eq!(gate_capability(), json!({"schema":"serverware.operatorNpmInstallGate/v1",
        "adapter":ADAPTER,"modes":["metadata","tarball","audit"]}));
    for mode in ["metadata", "tarball", "audit"] {
        assert!(crate::npm_metadata::validate_config(&config(mode), &[envelope(mode, "e").unwrap()]).is_err());
        assert!(crate::npm_publish::validate_config(&config(mode), &[envelope(mode, "e").unwrap()]).is_err());
    }
    for value in ["application/json; charset=utf-8", "APPLICATION/JSON", "application/octet-stream", "APPLICATION/OCTET-STREAM"] {
        assert!(is_content_type(value));
    }
    for value in ["application/octet-stream; charset=utf-8", "application/json; charset=latin1",
        "application/problem+json", "application/gzip", "application/json; charset=utf-8; x=1"] {
        assert!(!is_content_type(value));
    }
}
