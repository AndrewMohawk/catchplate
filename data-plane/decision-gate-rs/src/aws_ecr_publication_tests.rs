//! Focused inert ECR adapter tests. These do not contact AWS or prove a push.
use super::*;
use crate::tests::{policy_with_route, test_snapshot};
use crate::*;
const SUBJECT: &str = "5c83338e-113e-43de-a602-eaf5fa891f27";
const PUBLICATION: &str = "710e4d73-2207-43f4-89b3-a07466bc9393";
fn config() -> Value {
    json!({"credentialBinding":{"credentialType":"static","provider":"operator-demo",
    "subjects":[SUBJECT],"secretClass":"awsSigV4"},"registryId":"123456789012","region":"us-east-1",
    "repositoryName":"example/app","imageTag":"reviewed","approval":{"mode":"host_review_v1","scope":"publication"},
    "request":request_config(),"response":response_profile(false)})
}
fn route() -> Route {
    let mut route = test_snapshot(1).routes[0].clone();
    route.adapter_type = ADAPTER.into();
    route.adapter_config = config();
    route.host = "api.ecr.us-east-1.amazonaws.com".into();
    route.methods = HashSet::from(["POST".into()]);
    route.paths = vec![compile_template("/").unwrap()];
    route.credential_ref = Some("credential:ecr".into());
    route.credential_header = None;
    route.discard_headers = DISCARD.iter().map(|s| s.to_string()).collect();
    route.constraints = vec![envelope("ecr-response")];
    route.jit = json!({});
    route
}
fn request(action: &str, body: Value) -> DecisionRequest {
    let mut req: DecisionRequest = serde_json::from_value(
        json!({"method":"POST","url":"https://api.ecr.us-east-1.amazonaws.com/",
        "headers":{},"body":serde_json::to_string(&body).unwrap()}),
    )
    .unwrap();
    let credentials = aws_ecr_signing::Credentials::new(
        aws_ecr_signing::CredentialKind::LongTerm,
        DUMMY_ACCESS_KEY.into(),
        DUMMY_SECRET.into(),
        None,
        None,
    )
    .unwrap();
    let signed = aws_ecr_signing::sign(
        &credentials,
        "us-east-1",
        action,
        req.body.as_bytes(),
        aws_ecr_signing::ClockObservation {
            unix_seconds: 1_700_000_000,
            monotonic_ns: 0,
        },
    )
    .unwrap();
    req.headers = signed
        .headers()
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .collect();
    req.headers.insert(
        "user-agent".into(),
        format!("Boto3/1.34.46 ServerwarePublication/{PUBLICATION}"),
    );
    req.headers
        .insert("amz-sdk-request".into(), "attempt=1".into());
    req
}
#[test]
fn ecr_closed_policy_and_schema() {
    let raw = json!({"id":"route:test","principals":["agent:test"],"credentialRef":"credential:ecr",
        "match":{"scheme":"https","host":"api.ecr.us-east-1.amazonaws.com","port":443,"methods":["POST"],"paths":["/"]},
        "adapter":{"type":ADAPTER,"config":config()},"constraints":[envelope("ecr-response")]});
    let mut policy = policy_with_route(raw.clone());
    policy["routes"] = json!([raw]);
    policy["credentials"] = json!([{"id":"credential:ecr","credentialType":"static","provider":"operator-demo","providerSubject":SUBJECT,
        "injection":{"type":"awsEcrSigningV1"}}]);
    assert_eq!(RESPONSE_BYTES, 25 * 1024 * 1024);
    assert_eq!(
        policy["routes"][0]["adapter"]["config"]["response"]["maxBodyBytes"],
        json!(RESPONSE_BYTES)
    );
    validate_policy_capabilities(&policy).expect("closed ECR policy admits its exact 25 MiB limit");
    for limit in [MAX_BUFFERED_RESPONSE_BODY_BYTES, RESPONSE_BYTES + 1] {
        let mut changed = policy.clone();
        changed["routes"][0]["adapter"]["config"]["response"]["maxBodyBytes"] = json!(limit);
        assert!(validate_policy_capabilities(&changed)
            .expect_err("ECR response limit must remain exact, not an arbitrary larger allowance")
            .contains("ECR config differs from its closed contract"));
    }
    validate_route(&route()).unwrap();
    validate_route_response_release_mode(&route()).unwrap();
    policy["apiVersion"] = json!("serverware.policy/v1");
    policy["kind"] = json!("PolicyBundle");
    policy["metadata"] = json!({"id":"ecr-startup","sequence":1,"rollbackEpoch":1});
    validate_policy_schema(&policy).unwrap();
    let mut changed = policy.clone();
    changed["routes"][0]["adapter"]["config"]["approval"]["scope"] = json!("request");
    assert!(validate_policy_capabilities(&changed).is_err());
    let mut changed = policy.clone();
    changed["routes"][0]["credentialHeader"] =
        json!({"mode":"replaceExact","expectedValue":"dummy"});
    assert!(validate_policy_capabilities(&changed).is_err());
    let mut changed = policy;
    changed["routes"][0]["adapter"]["type"] = json!("generic.rest");
    assert!(validate_policy_capabilities(&changed).is_err());
}
#[test]
fn ecr_dummy_signing_explicit_publication_and_closed_bodies() {
    let route = route();
    let req = request(
        "InitiateLayerUpload",
        json!({"registryId":"123456789012","repositoryName":"example/app"}),
    );
    let url = Url::parse(&req.url).unwrap();
    let op = validate_request(&req, &url, &route).unwrap();
    assert_eq!(op["publicationId"], PUBLICATION);
    for (name, value) in [
        ("x-amz-security-token", "real-token"),
        ("authorization", "AWS4-HMAC-SHA256 Credential=unknown"),
        ("amz-sdk-request", "attempt=2"),
        ("user-agent", "Boto3/1"),
        (
            "x-amz-target",
            "AmazonEC2ContainerRegistry_V20150921.DeleteRepository",
        ),
    ] {
        let mut bad = req.clone();
        bad.headers.insert(name.into(), value.into());
        assert!(validate_request(&bad, &url, &route).is_err(), "{name}");
    }
    let mut bad = req.clone();
    bad.headers.insert(
        "User-Agent".into(),
        format!("ServerwarePublication/{PUBLICATION}"),
    );
    assert!(validate_request(&bad, &url, &route).is_err());
    let mut bad = req.clone();
    bad.headers
        .get_mut("user-agent")
        .unwrap()
        .push_str(&format!(" ServerwarePublication/{PUBLICATION}"));
    assert!(validate_request(&bad, &url, &route).is_err());
    let mut bad = req;
    bad.body.push(' ');
    assert!(
        validate_request(&bad, &url, &route).is_err(),
        "signature binds original bytes"
    );
    assert!(!body_valid(&config(),"InitiateLayerUpload",br#"{"registryId":"123456789012","registryId":"123456789012","repositoryName":"example/app"}"#));
    assert!(!body_valid(&config(),"UploadLayerPart",br#"{"registryId":"123456789012","repositoryName":"example/app","uploadId":"710e4d73-2207-43f4-89b3-a07466bc9393","partFirstByte":0.0,"partLastByte":0,"layerPartBlob":"YQ=="}"#));
    assert!(body_valid(&config(),"UploadLayerPart",br#"{"registryId":"123456789012","repositoryName":"example/app","uploadId":"710e4d73-2207-43f4-89b3-a07466bc9393","partFirstByte":0,"partLastByte":0,"layerPartBlob":"YQ=="}"#));
}
