use base64::{engine::general_purpose, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("canonical JSON serialization failed")
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn run() -> Result<Value, String> {
    let mut input = Vec::new();
    io::stdin()
        .take(65_537)
        .read_to_end(&mut input)
        .map_err(|err| format!("read fixture request: {err}"))?;
    if input.len() > 65_536 {
        return Err("fixture request is too large".to_string());
    }
    let request: Value =
        serde_json::from_slice(&input).map_err(|err| format!("parse fixture request: {err}"))?;
    if request.get("apiVersion").and_then(Value::as_str)
        != Some("serverware.responseProofAttestationRequest/v1")
        || request.get("kind").and_then(Value::as_str)
            != Some("ServerwareResponseProofAttestationRequest")
    {
        return Err("fixture request has the wrong type".to_string());
    }
    let claims = request
        .get("attested_claims")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or("fixture request is missing attested_claims")?;
    let statement_digest = request
        .get("server_statement_sha256")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha256:") && value.len() == 71)
        .ok_or("fixture request is missing server_statement_sha256")?;
    let key_id = request
        .get("response_signing_key_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("sha256:") && value.len() == 71)
        .ok_or("fixture request is missing response_signing_key_id")?;
    let quote = json!({
        "format":"serverware-development-fixture",
        "body_b64":general_purpose::URL_SAFE_NO_PAD.encode(
            format!("development-only:{statement_digest}:{key_id}").repeat(2).as_bytes()
        ),
    });
    Ok(json!({
        "vendor_tee":{
            "platform":"none-dev",
            "provider":"development-fixture",
            "quote_sha256":sha256_prefixed(canonical_json(&quote).as_bytes()),
            "quote":quote,
            "trusted_verifier":{
                "apiVersion":"serverware.vendorTeeVerification/v1",
                "kind":"ServerwareVendorTeeVerification",
                "statement":{
                    "outcome":"development-fixture",
                    "environment":"development",
                    "debug":true,
                    "server_statement_sha256":statement_digest,
                    "response_signing_key_id":key_id,
                    "attested_claims":claims,
                },
                "signature":null,
            },
        }
    }))
}

fn main() {
    match run() {
        Ok(output) => println!("{}", canonical_json(&output)),
        Err(error) => {
            eprintln!("{}", canonical_json(&json!({"ok":false,"error":error})));
            std::process::exit(1);
        }
    }
}
