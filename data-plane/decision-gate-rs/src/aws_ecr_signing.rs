//! Pure, unintegrated SigV4 signing for five ECR upload API actions.
//!
//! This is not operation authorization, an account/repository/upload-state
//! check, credential-generation admission, or a cache. The caller must retain
//! its original authority, operation deadline and secret-lifetime checks. Clock
//! observations come from that trusted caller, never client signing headers.
//! Region syntax does not establish endpoint existence or an AWS permission.
//!
//! The final check covers application request fields/headers and exact body
//! bytes, not transport-generated framing or an atomic socket send. Obtain a
//! second trusted clock observation and call `require_fresh` after the body
//! check, immediately before any separately authorized send. No function here
//! sends, stores, renews, retries, loads ambient credentials or logs material.
//!
//! Owned credential/header/canonical buffers and derived-key scratch use
//! Zeroizing. Borrowed caller buffers and cryptographic-library internals are
//! outside that guarantee; redacted Debug is not a confidentiality boundary.

use ring::hmac;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};
use zeroize::Zeroizing;

pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_SESSION_TOKEN_BYTES: usize = 8192;
pub const MAX_SIGNATURE_AGE_SECONDS: u64 = 60;
pub const SESSION_EXPIRY_MARGIN_SECONDS: u64 = 5;
pub const ACTIONS: [&str; 5] = [
    "BatchCheckLayerAvailability",
    "InitiateLayerUpload",
    "UploadLayerPart",
    "CompleteLayerUpload",
    "PutImage",
];
const MAX_UNIX_SECONDS: u64 = 253_402_300_799;
const MAX_MONOTONIC_NS: u64 = i64::MAX as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningError;

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AWS ECR signing unavailable")
    }
}

impl std::error::Error for SigningError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialKind {
    LongTerm,
    Session,
}

/// No Clone, serialization, public secret fields, or secret-bearing Debug.
pub struct Credentials {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
    expires_at: Option<u64>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credentials(<redacted>)")
    }
}

impl Credentials {
    pub fn new(
        kind: CredentialKind,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        expires_at: Option<&str>,
    ) -> Result<Self, SigningError> {
        // Take zeroizing ownership before any validation can return an error.
        let access_key_id = Zeroizing::new(access_key_id);
        let secret_access_key = Zeroizing::new(secret_access_key);
        let session_token = session_token.map(Zeroizing::new);
        let expected_prefix = match kind {
            CredentialKind::LongTerm => "AKIA",
            CredentialKind::Session => "ASIA",
        };
        if access_key_id.len() != 20
            || !access_key_id.starts_with(expected_prefix)
            || !access_key_id.bytes().all(|value| value.is_ascii_uppercase() || value.is_ascii_digit())
            || secret_access_key.len() != 40
            || !secret_access_key.bytes().all(|value| {
                value.is_ascii_alphanumeric() || matches!(value, b'/' | b'+' | b'=')
            })
        {
            return Err(SigningError);
        }
        let expires_at = match kind {
            CredentialKind::LongTerm => {
                if session_token.is_some() || expires_at.is_some() {
                    return Err(SigningError);
                }
                None
            }
            CredentialKind::Session => {
                let token = session_token.as_ref().ok_or(SigningError)?;
                if token.is_empty()
                    || token.len() > MAX_SESSION_TOKEN_BYTES
                    || !token.bytes().all(|value| (b'!'..=b'~').contains(&value))
                {
                    return Err(SigningError);
                }
                Some(expiry_seconds(expires_at.ok_or(SigningError)?)?)
            }
        };
        Ok(Self { access_key_id, secret_access_key, session_token, expires_at })
    }
}

/// Trusted observations only. Neither value may be obtained from request fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockObservation {
    pub unix_seconds: u64,
    pub monotonic_ns: u64,
}

fn check_clock(clock: ClockObservation) -> Result<(), SigningError> {
    if clock.unix_seconds > MAX_UNIX_SECONDS || clock.monotonic_ns > MAX_MONOTONIC_NS {
        return Err(SigningError);
    }
    Ok(())
}

fn decimal(bytes: &[u8]) -> Result<u32, SigningError> {
    bytes.iter().try_fold(0u32, |value, byte| {
        if !byte.is_ascii_digit() {
            return Err(SigningError);
        }
        value.checked_mul(10).and_then(|value| value.checked_add(u32::from(*byte - b'0')))
            .ok_or(SigningError)
    })
}

fn expiry_seconds(value: &str) -> Result<u64, SigningError> {
    let bytes = value.as_bytes();
    if bytes.len() != 20 || bytes[4] != b'-' || bytes[7] != b'-'
        || bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' || bytes[19] != b'Z'
    {
        return Err(SigningError);
    }
    let date = Date::from_calendar_date(
        decimal(&bytes[..4])? as i32,
        Month::try_from(decimal(&bytes[5..7])? as u8).map_err(|_| SigningError)?,
        decimal(&bytes[8..10])? as u8,
    ).map_err(|_| SigningError)?;
    let time = Time::from_hms(
        decimal(&bytes[11..13])? as u8,
        decimal(&bytes[14..16])? as u8,
        decimal(&bytes[17..19])? as u8,
    ).map_err(|_| SigningError)?;
    let seconds = u64::try_from(PrimitiveDateTime::new(date, time).assume_utc().unix_timestamp())
        .map_err(|_| SigningError)?;
    if seconds > MAX_UNIX_SECONDS {
        return Err(SigningError);
    }
    Ok(seconds)
}

fn region_valid(region: &str) -> bool {
    if region.len() > 63 || region.starts_with("cn-") {
        return false;
    }
    let mut pieces = region.split('-');
    let (Some(area), Some(location), Some(number), None) =
        (pieces.next(), pieces.next(), pieces.next(), pieces.next()) else { return false; };
    area.len() == 2 && area.bytes().all(|value| value.is_ascii_lowercase())
        && !location.is_empty() && location.bytes().all(|value| value.is_ascii_lowercase())
        && (1..=2).contains(&number.len()) && number.as_bytes()[0] != b'0'
        && number.bytes().all(|value| value.is_ascii_digit())
}

fn session_current(expiry: Option<u64>, clock: ClockObservation) -> Result<(), SigningError> {
    if expiry.is_some_and(|expiry| {
        expiry.checked_sub(clock.unix_seconds)
            .is_none_or(|remaining| remaining <= SESSION_EXPIRY_MARGIN_SECONDS)
    }) {
        return Err(SigningError);
    }
    Ok(())
}

fn keyed_digest(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 32]> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, message);
    let mut output = Zeroizing::new([0u8; 32]);
    output.copy_from_slice(tag.as_ref());
    output
}

/// Immutable application request binding; getters borrow sensitive buffers.
pub struct SignedRequest {
    authority: String,
    headers: BTreeMap<String, Zeroizing<String>>,
    canonical_request: Zeroizing<String>,
    string_to_sign: Zeroizing<String>,
    body_sha256: [u8; 32],
    body_length: usize,
    clock: ClockObservation,
    expires_at: Option<u64>,
}

impl fmt::Debug for SignedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignedRequest(<redacted>)")
    }
}

impl SignedRequest {
    pub fn method(&self) -> &'static str { "POST" }
    pub fn scheme(&self) -> &'static str { "https" }
    pub fn authority(&self) -> &str { &self.authority }
    pub fn path(&self) -> &'static str { "/" }
    pub fn query(&self) -> &'static str { "" }
    pub fn headers(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.headers.iter().map(|(name, value)| (name.as_str(), value.as_str()))
    }
    pub fn canonical_request(&self) -> &[u8] { self.canonical_request.as_bytes() }
    pub fn string_to_sign(&self) -> &str { self.string_to_sign.as_str() }
    pub fn body_sha256(&self) -> &[u8; 32] { &self.body_sha256 }
    pub fn body_length(&self) -> usize { self.body_length }
}

pub fn sign(
    credentials: &Credentials,
    region: &str,
    action: &str,
    body: &[u8],
    clock: ClockObservation,
) -> Result<SignedRequest, SigningError> {
    check_clock(clock)?;
    session_current(credentials.expires_at, clock)?;
    if !region_valid(region) || !ACTIONS.contains(&action) || body.len() > MAX_BODY_BYTES {
        return Err(SigningError);
    }
    let utc = OffsetDateTime::from_unix_timestamp(clock.unix_seconds as i64)
        .map_err(|_| SigningError)?;
    let date = format!("{:04}{:02}{:02}", utc.year(), u8::from(utc.month()), utc.day());
    let timestamp = format!("{date}T{:02}{:02}{:02}Z", utc.hour(), utc.minute(), utc.second());
    let authority = format!("api.ecr.{region}.amazonaws.com");
    let mut headers = BTreeMap::from([
        ("content-type".to_owned(), Zeroizing::new("application/x-amz-json-1.1".to_owned())),
        ("host".to_owned(), Zeroizing::new(authority.clone())),
        ("x-amz-date".to_owned(), Zeroizing::new(timestamp.clone())),
        ("x-amz-target".to_owned(), Zeroizing::new(format!("AmazonEC2ContainerRegistry_V20150921.{action}"))),
    ]);
    if let Some(token) = credentials.session_token.as_ref() {
        headers.insert("x-amz-security-token".to_owned(), Zeroizing::new(token.as_str().to_owned()));
    }
    let signed_headers = headers.keys().map(String::as_str).collect::<Vec<_>>().join(";");
    let body_sha256: [u8; 32] = Sha256::digest(body).into();
    let mut canonical_request = Zeroizing::new("POST\n/\n\n".to_owned());
    for (name, value) in &headers {
        canonical_request.push_str(name);
        canonical_request.push(':');
        canonical_request.push_str(value.as_str());
        canonical_request.push('\n');
    }
    canonical_request.push('\n');
    canonical_request.push_str(&signed_headers);
    canonical_request.push('\n');
    canonical_request.push_str(&hex::encode(body_sha256));
    let scope = format!("{date}/{region}/ecr/aws4_request");
    let string_to_sign = Zeroizing::new(format!("AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))));
    let mut prefixed_key = Zeroizing::new(String::with_capacity(44));
    prefixed_key.push_str("AWS4");
    prefixed_key.push_str(credentials.secret_access_key.as_str());
    let date_key = keyed_digest(prefixed_key.as_bytes(), date.as_bytes());
    let region_key = keyed_digest(date_key.as_ref(), region.as_bytes());
    let service_key = keyed_digest(region_key.as_ref(), b"ecr");
    let signing_key = keyed_digest(service_key.as_ref(), b"aws4_request");
    let signature = keyed_digest(signing_key.as_ref(), string_to_sign.as_bytes());
    let signature_hex = Zeroizing::new(hex::encode(signature.as_ref()));
    headers.insert("authorization".to_owned(), Zeroizing::new(format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={}",
        credentials.access_key_id.as_str(), signature_hex.as_str(),
    )));
    Ok(SignedRequest { authority, headers, canonical_request, string_to_sign, body_sha256,
        body_length: body.len(), clock, expires_at: credentials.expires_at })
}

/// Borrow the complete candidate application request without copying its body.
/// No derived Debug: fields may contain authorization/token/body material.
pub struct RequestView<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub authority: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

pub fn require_fresh(signed: &SignedRequest, clock: ClockObservation) -> Result<(), SigningError> {
    check_clock(clock)?;
    let wall_elapsed = clock.unix_seconds.checked_sub(signed.clock.unix_seconds).ok_or(SigningError)?;
    let monotonic_elapsed = clock.monotonic_ns.checked_sub(signed.clock.monotonic_ns).ok_or(SigningError)?;
    if wall_elapsed >= MAX_SIGNATURE_AGE_SECONDS
        || monotonic_elapsed >= MAX_SIGNATURE_AGE_SECONDS * 1_000_000_000
    {
        return Err(SigningError);
    }
    session_current(signed.expires_at, clock)
}

fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() { return false; }
    left.iter().zip(right).fold(0u8, |different, (left, right)| different | (*left ^ *right)) == 0
}

pub fn assert_dispatch(
    signed: &SignedRequest,
    request: &RequestView<'_>,
    clock: ClockObservation,
) -> Result<(), SigningError> {
    require_fresh(signed, clock)?;
    if request.method != signed.method() || request.scheme != signed.scheme()
        || request.authority != signed.authority() || request.path != signed.path()
        || request.query != signed.query() || request.body.len() > MAX_BODY_BYTES
        || request.body.len() != signed.body_length
        || request.headers.len() < signed.headers.len()
        || request.headers.len() > signed.headers.len() + 1
        || !same_bytes(Sha256::digest(request.body).as_ref(), &signed.body_sha256)
    {
        return Err(SigningError);
    }
    let mut seen = std::collections::BTreeSet::new();
    let content_length = signed.body_length.to_string();
    for &(name, value) in request.headers {
        if name.len() > 64 || value.len() > MAX_SESSION_TOKEN_BYTES || !seen.insert(name) {
            return Err(SigningError);
        }
        let expected = if name == "content-length" { Some(content_length.as_str()) }
            else { signed.headers.get(name).map(|value| value.as_str()) };
        if !expected.is_some_and(|expected| same_bytes(value.as_bytes(), expected.as_bytes())) {
            return Err(SigningError);
        }
    }
    if !signed.headers.keys().all(|name| seen.contains(name.as_str())) {
        return Err(SigningError);
    }
    // This supplied clock cannot measure time spent hashing. The caller must
    // take a second observation and require_fresh immediately before its send.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const TOKEN: &str = "synthetic-session-token+/=";
    const CLOCK: ClockObservation = ClockObservation { unix_seconds: 1_791_633_600, monotonic_ns: 1_000_000_000_000 };

    fn credentials(session: bool) -> Credentials {
        Credentials::new(if session { CredentialKind::Session } else { CredentialKind::LongTerm },
            if session { "ASIAIOSFODNN7EXAMPLE" } else { "AKIAIOSFODNN7EXAMPLE" }.to_owned(),
            SECRET.to_owned(), session.then(|| TOKEN.to_owned()),
            session.then_some("2026-10-10T12:10:00Z")).unwrap()
    }

    fn view<'a>(signed: &'a SignedRequest, headers: &'a [(&'a str, &'a str)], body: &'a [u8]) -> RequestView<'a> {
        RequestView { method: "POST", scheme: "https", authority: signed.authority(), path: "/", query: "", headers, body }
    }

    #[test]
    fn hmac_public_rfc4231_vector() {
        assert_eq!(hex::encode(keyed_digest(&[0x0b; 20], b"Hi There").as_ref()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    #[test]
    fn fixed_ecr_target_and_canonical_bytes() {
        let signed = sign(&credentials(false), "us-east-1", "InitiateLayerUpload", b"{}", CLOCK).unwrap();
        assert_eq!(signed.authority(), "api.ecr.us-east-1.amazonaws.com");
        assert_eq!(signed.canonical_request(), concat!("POST\n/\n\n",
            "content-type:application/x-amz-json-1.1\nhost:api.ecr.us-east-1.amazonaws.com\n",
            "x-amz-date:20261010T120000Z\nx-amz-target:AmazonEC2ContainerRegistry_V20150921.InitiateLayerUpload\n\n",
            "content-type;host;x-amz-date;x-amz-target\n",
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a").as_bytes());
        let headers: Vec<_> = signed.headers().collect();
        assert_dispatch(&signed, &view(&signed, &headers, b"{}"), CLOCK).unwrap();
    }

    #[test]
    fn stock_botocore_1_34_46_twelve_literal_vectors() {
        // Actual offline Botocore 1.34.46 output, generated independently by
        // scripts/test_aws_ecr_signing.py --emit-botocore-vectors. Source JSON
        // SHA256: 57425874f14973df372e31d26ca4b1e2227c25bb98f287c5b306eb8049156b08.
        // These bodies and expected digests/signatures are literal SDK output,
        // not expected values computed with this module or its Python peer.
        let bodies: [&[u8]; 6] = [
            br#"{"registryId": "123456789012", "repositoryName": "serverware-fixture", "layerDigests": ["sha256:0d3c5cea1ebd719281f75c4965740c8ae30757f7e7833eeb5b1be95469ac0ebb"]}"#,
            br#"{"registryId": "123456789012", "repositoryName": "serverware-fixture"}"#,
            br#"{"registryId": "123456789012", "repositoryName": "serverware-fixture", "uploadId": "00000000-0000-4000-8000-000000000001", "partFirstByte": 0, "partLastByte": 21, "layerPartBlob": "c3ludGhldGljLWxheWVyLXBhcnQA/w=="}"#,
            br#"{"registryId": "123456789012", "repositoryName": "serverware-fixture", "uploadId": "00000000-0000-4000-8000-000000000001", "layerDigests": ["sha256:0d3c5cea1ebd719281f75c4965740c8ae30757f7e7833eeb5b1be95469ac0ebb"]}"#,
            br#"{"registryId": "123456789012", "repositoryName": "serverware-fixture", "imageManifest": "{\"config\":{\"digest\":\"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\",\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"size\":2},\"layers\":[],\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"schemaVersion\":2}", "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json", "imageTag": "fixture", "imageDigest": "sha256:1a532c454699d73464c8a86e03915be89b826ed24cd326a0442f0a310fd496af"}"#,
            b"synthetic-layer-part\x00\xff",
        ];
        let body_hashes = [
            "dafcd86a9d0ba2424d8ca87ff665d4307e83ba314b25c9a71185975593cac9cd",
            "62d0c2451a62cf7ef60bf414a45e49d1e68b9d2793a63c438f71863c370ca40d",
            "0ff0d09b681a3d53ece2c03e53d2847126b1637601f034f8eec3ab4c05d21ea1",
            "1bfecc9919a9b0ec550e6a782fd4a22a66546b2d7522148cc76073995719208d",
            "678623932f61feddce8a41a63c3c683959852205fa4821e622420e52eee837f4",
            "0d3c5cea1ebd719281f75c4965740c8ae30757f7e7833eeb5b1be95469ac0ebb",
        ];
        let signatures = [
            [
                "1c7f824b7fbd14a58813ad371581cc00ea811a0b399883bba79fcd19218852c2",
                "352c2abb1ceddf072e64cbfc39847a38fefc2838aab30bcf161b16c43d54654c",
                "65b28d3d08b5755e61d43f6220a766822c608205cb68b36039493285901dbace",
                "67c069cda174268ec33db5783cb47fa7092a2b067d43ce6463684f3e86dcc422",
                "37c06b2bad31e30fd9e6b1605286f301891d56563a694a0d4f79c6a98bc08cd5",
                "f816be2485c59a5ba3180ff794cf24520f2d810ac40bb975db03a4c69a646c2f",
            ],
            [
                "2a717c06309915d2a9713474e6849cb770ae7cb7c18acab1a77f161c201f31e2",
                "bda2b7e85b36fc02b276f8aceaa0152d1ba3f0a791ac2d8a10a3ea8dd2fd2155",
                "1beda7c29c0cde881380c94aa074e67394926c26ed9ee7c3d492cb69a1df67ff",
                "0e1362d37e696f0736d8c6f88e4cbd330b23e4645782abf305494be14d5aedbe",
                "3337966ad0fc4262828e0dd9394bde33661c9a443f11f10ec76093d5c713343f",
                "0b0a1b32c70e40ad95db15c9133d37deaae731e43d78d8fccd99c4a2bfd23df1",
            ],
        ];
        let canonical_hashes = [
            [
                "3c122d2b01a2734f2058233b0c66f090827152178a3dbd4228b8eaed8c88e13a",
                "39724cd6077623c36a39dfb2829ece446f04d7eafc50abe59479f633cdca55ca",
                "45517b8a14552708ae3b654f40f561e247468668a9e0837cb3888f973ccc4e5b",
                "4dc3c6d6f77b241eddae063eae3606f513a147582fe6ceef636ae6cf5c331e5d",
                "934bbe24e0aa373bd04bd0810e1e0113d007a77a0f8c7d2da8f6d7caeeaf6403",
                "3a54f96724e811725b3905a49e29dc64e2642cf5939418c9f1c7e86831dc20e0",
            ],
            [
                "dd60ad040027995772b2ab7608b5121de85bbd79153d3250153a787d044b6832",
                "3ad06f0a010307278d35296c541bc93f5ad30487dfbc4c71a3c26a4d4d7202b0",
                "1f57021605cad4748b0336f756ba0ff4cc0cbfb9aa87df9f19dc79de365f992b",
                "d7873c7643153759e5c741b5104a6a00f9cb742dbf957ff3b532f995808cf2fe",
                "e1f7020a5ef74503ede2396ec0ed3b57f8a02c3b9f15444952575d168fcd7855",
                "68411904d1ceb6facd801f58d6f91e445bd6fc171cc7de0abeb153c018bdd381",
            ],
        ];
        let actions = ["BatchCheckLayerAvailability", "InitiateLayerUpload", "UploadLayerPart",
            "CompleteLayerUpload", "PutImage", "UploadLayerPart"];
        for kind in 0..2 {
            let credential = credentials(kind == 1);
            let access = if kind == 1 { "ASIAIOSFODNN7EXAMPLE" } else { "AKIAIOSFODNN7EXAMPLE" };
            let signed_names = if kind == 1 {
                "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
            } else { "content-type;host;x-amz-date;x-amz-target" };
            for index in 0..6 {
                let signed = sign(&credential, "us-east-1", actions[index], bodies[index], CLOCK).unwrap();
                assert_eq!(hex::encode(signed.body_sha256()), body_hashes[index]);
                assert_eq!(signed.string_to_sign(), format!(
                    "AWS4-HMAC-SHA256\n20261010T120000Z\n20261010/us-east-1/ecr/aws4_request\n{}",
                    canonical_hashes[kind][index]));
                assert_eq!(hex::encode(Sha256::digest(signed.canonical_request())), canonical_hashes[kind][index]);
                let expected_authorization = format!(
                    "AWS4-HMAC-SHA256 Credential={access}/20261010/us-east-1/ecr/aws4_request, SignedHeaders={signed_names}, Signature={}",
                    signatures[kind][index]);
                let expected_target = format!("AmazonEC2ContainerRegistry_V20150921.{}", actions[index]);
                let mut expected_headers = vec![
                    ("authorization", expected_authorization.as_str()),
                    ("content-type", "application/x-amz-json-1.1"),
                    ("host", "api.ecr.us-east-1.amazonaws.com"),
                    ("x-amz-date", "20261010T120000Z"),
                ];
                if kind == 1 { expected_headers.push(("x-amz-security-token", TOKEN)); }
                expected_headers.push(("x-amz-target", expected_target.as_str()));
                assert_eq!(signed.headers().collect::<Vec<_>>(), expected_headers);
                assert_dispatch(&signed, &view(&signed, &expected_headers, bodies[index]), CLOCK).unwrap();
            }
        }
    }

    #[test]
    fn only_reviewed_actions_and_endpoint_shape() {
        for action in ACTIONS {
            sign(&credentials(false), "us-east-1", action, b"", CLOCK).unwrap();
        }
        for region in ["cn-north-1", "us-gov-west-1", "us-iso-east-1", "US-east-1", "us-east-0", "us-east-01", "us-east-100", "us-east-1.", "us-east-1:443"] {
            assert!(sign(&credentials(false), region, "PutImage", b"{}", CLOCK).is_err());
        }
        // Shape is not a claim that this endpoint exists or is authorized.
        sign(&credentials(false), "zz-fictional-99", "PutImage", b"{}", CLOCK).unwrap();
        let region = format!("us-{}-1", "a".repeat(58));
        assert_eq!(region.len(), 63);
        sign(&credentials(false), &region, "PutImage", b"{}", CLOCK).unwrap();
        assert!(sign(&credentials(false), &region.replace("-1", "a-1"), "PutImage", b"{}", CLOCK).is_err());
        for action in ["GetAuthorizationToken", "DeleteRepository", "PutImage\n", "ecr:PutImage"] {
            assert!(sign(&credentials(false), "us-east-1", action, b"{}", CLOCK).is_err());
        }
    }

    #[test]
    fn strict_credential_tuple_and_expiry() {
        assert!(Credentials::new(CredentialKind::LongTerm, "ASIAIOSFODNN7EXAMPLE".into(), SECRET.into(), None, None).is_err());
        assert!(Credentials::new(CredentialKind::LongTerm, "AKIAIOSFODNN7EXAMPLE".into(), SECRET.into(), Some(TOKEN.into()), None).is_err());
        for token in ["", "has space", "line\nbreak", "nonasciié"] {
            assert!(Credentials::new(CredentialKind::Session, "ASIAIOSFODNN7EXAMPLE".into(), SECRET.into(), Some(token.into()), Some("2026-10-10T12:10:00Z")).is_err());
        }
        for expiry in ["2026-10-10T12:10:00+00:00", "2026-02-30T12:10:00Z", "1969-12-31T23:59:59Z", "2026-10-10T12:10:60Z"] {
            assert!(expiry_seconds(expiry).is_err());
        }
        assert_eq!(expiry_seconds("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(expiry_seconds("9999-12-31T23:59:59Z").unwrap(), MAX_UNIX_SECONDS);
    }

    #[test]
    fn session_token_signed_and_secret_debug_redacted() {
        let credential = credentials(true);
        let signed = sign(&credential, "us-east-1", "PutImage", b"secret-body-canary", CLOCK).unwrap();
        assert!(signed.canonical_request().windows(TOKEN.len()).any(|value| value == TOKEN.as_bytes()));
        let shown = format!("{credential:?} {signed:?} {SigningError}");
        for value in [SECRET, TOKEN, "ASIAIOSFODNN7EXAMPLE", "secret-body-canary", "Signature="] {
            assert!(!shown.contains(value));
        }
    }

    #[test]
    fn final_body_and_target_mutations_refused() {
        let signed = sign(&credentials(false), "us-east-1", "PutImage", b"{}", CLOCK).unwrap();
        let headers: Vec<_> = signed.headers().collect();
        for body in [b"{ }".as_slice(), b"[]", b""] {
            assert!(assert_dispatch(&signed, &view(&signed, &headers, body), CLOCK).is_err());
        }
        for field in 0..5 {
            let mut request = view(&signed, &headers, b"{}");
            match field { 0 => request.method = "GET", 1 => request.scheme = "http", 2 => request.authority = "api.ecr.us-east-1.amazonaws.com:443", 3 => request.path = "//", _ => request.query = "x=1" }
            assert!(assert_dispatch(&signed, &request, CLOCK).is_err());
        }
    }

    #[test]
    fn final_headers_are_closed_with_optional_exact_length() {
        let signed = sign(&credentials(true), "us-east-1", "PutImage", b"{}", CLOCK).unwrap();
        let mut headers: Vec<_> = signed.headers().collect();
        headers.reverse();
        headers.push(("content-length", "2"));
        assert_dispatch(&signed, &view(&signed, &headers, b"{}"), CLOCK).unwrap();
        for pair in [("content-length", "02"), ("Content-Length", "2"), ("user-agent", "client"), ("transfer-encoding", "chunked"), ("x-amz-security-token", "different")] {
            let mut changed: Vec<_> = signed.headers().collect();
            changed.push(pair);
            assert!(assert_dispatch(&signed, &view(&signed, &changed, b"{}"), CLOCK).is_err());
        }
        let mut changed: Vec<_> = signed.headers().collect();
        changed[0].1 = "changed-authorization";
        assert!(assert_dispatch(&signed, &view(&signed, &changed, b"{}"), CLOCK).is_err());
    }

    #[test]
    fn original_clock_age_and_rollback_never_rearmed() {
        let signed = sign(&credentials(false), "us-east-1", "PutImage", b"{}", CLOCK).unwrap();
        require_fresh(&signed, ClockObservation { unix_seconds: CLOCK.unix_seconds + 59, monotonic_ns: CLOCK.monotonic_ns + 59_999_999_999 }).unwrap();
        for clock in [ClockObservation { unix_seconds: CLOCK.unix_seconds - 1, ..CLOCK },
            ClockObservation { monotonic_ns: CLOCK.monotonic_ns - 1, ..CLOCK },
            ClockObservation { unix_seconds: CLOCK.unix_seconds + 60, ..CLOCK },
            ClockObservation { monotonic_ns: CLOCK.monotonic_ns + 60_000_000_000, ..CLOCK },
            ClockObservation { unix_seconds: MAX_UNIX_SECONDS + 1, ..CLOCK },
            ClockObservation { monotonic_ns: MAX_MONOTONIC_NS + 1, ..CLOCK }] {
            assert!(require_fresh(&signed, clock).is_err());
        }
        require_fresh(&signed, CLOCK).unwrap();
        assert!(require_fresh(&signed, ClockObservation { unix_seconds: CLOCK.unix_seconds + 60, ..CLOCK }).is_err());
    }

    #[test]
    fn session_margin_checked_at_sign_and_final_freshness() {
        let short = Credentials::new(CredentialKind::Session, "ASIAIOSFODNN7EXAMPLE".into(), SECRET.into(), Some(TOKEN.into()), Some("2026-10-10T12:00:06Z")).unwrap();
        let signed = sign(&short, "us-east-1", "PutImage", b"{}", CLOCK).unwrap();
        let later = ClockObservation { unix_seconds: CLOCK.unix_seconds + 1, monotonic_ns: CLOCK.monotonic_ns + 1_000_000_000 };
        assert!(require_fresh(&signed, later).is_err());
        assert!(sign(&short, "us-east-1", "PutImage", b"{}", later).is_err());
    }

    #[test]
    fn exact_body_bound_and_empty_bytes() {
        let credential = credentials(false);
        sign(&credential, "us-east-1", "UploadLayerPart", b"", CLOCK).unwrap();
        let mut body = vec![b'x'; MAX_BODY_BYTES];
        let signed = sign(&credential, "us-east-1", "UploadLayerPart", &body, CLOCK).unwrap();
        assert_eq!(signed.body_length(), MAX_BODY_BYTES);
        body.push(b'x');
        assert!(sign(&credential, "us-east-1", "UploadLayerPart", &body, CLOCK).is_err());
    }
}
