//! Complete signed v2 route classification. No request-name/method heuristic.
//! A local compilation is not independent compiler-analysis approval.
use super::*;
use crate::policy_shadow::{ObservedAuthorityBinding, OperationClass, Sha256Digest};
use std::collections::{BTreeMap, BTreeSet};

const PROFILE: &str = "serverware.compiledRouteAuthority/v1";
pub(crate) const BUNDLE: &str = "serverware.policy/v2";
const MAX_ROUTES: usize = 128;
const MAX_OPERATIONS: usize = 128;
const MAX_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub(crate) struct Compiled {
    mapping: Value,
    mapping_sha256: String,
    route_root: String,
    operation_root: String,
}

pub(crate) fn canonical(value: &Value) -> Result<String, String> {
    fn transcript(value: &Value) -> Result<Value, String> {
        Ok(match value {
            Value::Null => json!(["null"]), Value::Bool(value) => json!(["boolean",value]),
            Value::String(value) => json!(["string",value]),
            Value::Number(number) if number.is_i64() || number.is_u64() => json!(["integer",number.to_string()]),
            Value::Number(number) => {
                let value = number.as_f64().filter(|v| v.is_finite()).ok_or("non-finite v2 policy number")?;
                json!(["binary64",format!("{:016x}",value.to_bits())])
            },
            Value::Array(items) => json!(["array",items.iter().map(transcript).collect::<Result<Vec<_>,_>>()?]),
            Value::Object(items) => {
                let ordered = items.iter().collect::<BTreeMap<_,_>>();
                json!(["object",ordered.into_iter().map(|(key,value)| Ok(json!([key,transcript(value)?])))
                    .collect::<Result<Vec<Value>,String>>()?])
            },
        })
    }
    Ok(format!("serverware.policyTypedCanonical/v1\0{}",
        canonical_json_ensure_ascii(&transcript(value)?).replace('\u{007f}', "\\u007f")))
}

fn digest(value: &Value) -> Result<String, String> {
    Ok(sha256_prefixed(canonical(value)?.as_bytes()))
}

fn text<'a>(value: &'a Value) -> Result<&'a str, String> {
    value.as_str().filter(|v| !v.is_empty() && v.len() <= 256)
        .ok_or_else(|| "compiled authority text is invalid".into())
}

fn class(value: &str) -> Result<OperationClass, String> {
    match value {
        "read" => Ok(OperationClass::Read), "search" => Ok(OperationClass::Search),
        "write" => Ok(OperationClass::Write), "publish" => Ok(OperationClass::Publish),
        "delete" => Ok(OperationClass::Delete), "administrative" => Ok(OperationClass::Administrative),
        _ => Err("compiled authority operation is invalid".into()),
    }
}

fn builtin(kind: &str, name: &str) -> Result<&'static str, String> {
    let value = match (kind, name) {
        ("gmail.v1", "gmail.message.get") => "read",
        ("gmail.v1", "gmail.messages.list") => "search",
        ("x.v2", "tweets.write") => "write",
        ("x.v2", "search.read") => "search",
        ("x.v2", operation) if X_V2_READ_OPERATION_PATHS.iter().any(|(name, _)| *name == operation) => "read",
        ("npm.registry", "npm.read") => "read", ("npm.registry", "npm.publish") => "publish",
        ("npm.metadata.v1", "npm.metadata.read") => "read",
        ("npm.install.v1", "npm.install.metadata.read" | "npm.install.tarball.read" | "npm.install.audit.read") => "read",
        ("x.app_read.v1", "x.username.read") => "read",
        ("alchemy.rpc_read.v1", "alchemy.rpc.read") => "read",
        ("npm.publish.v1", "npm.publish") => "publish",
        ("npm.registry", "npm.unpublish") => "delete", ("npm.registry", "npm.tokenWrite") => "administrative",
        ("npm.registry", "npm.distTagWrite" | "npm.metadataWrite") => "write",
        _ => return Err("built-in operation lacks a source-fixed authority classifier".into()),
    };
    Ok(value)
}

pub(crate) fn admit(raw: &Value, compiled_routes: &[Route]) -> Result<Option<Arc<Compiled>>, String> {
    if raw["apiVersion"] == "serverware.policy/v1" {
        if raw.get("routeAuthority").is_some() { return Err("v1 has no route authority profile".into()); }
        return Ok(None);
    }
    if raw["apiVersion"] != BUNDLE { return Err("unsupported policy profile".into()); }
    canonical(raw)?;
    let held = raw["routeAuthority"].as_object().ok_or("routeAuthority missing")?;
    if held.len() != 5 || held.get("apiVersion").and_then(Value::as_str) != Some(PROFILE)
        || ["genericOperations", "mappingSha256", "routeAuthorityRootSha256", "operationAuthorityRootSha256"]
            .iter().any(|field| !held.contains_key(*field)) {
        return Err("routeAuthority shape changed".into());
    }
    let declarations = held["genericOperations"].as_array().ok_or("generic operations missing")?;
    if declarations.len() > MAX_ROUTES { return Err("generic authority capacity exceeded".into()); }
    let mut generic = BTreeMap::new();
    let mut previous = None;
    for entry in declarations {
        let object = entry.as_object().ok_or("generic declaration must be object")?;
        if object.len() != 3 { return Err("generic declaration shape changed".into()); }
        let identity = (text(&entry["routeId"])?.to_string(), text(&entry["operationName"])?.to_string());
        let operation = text(&entry["operation"])?;
        class(operation)?;
        if previous.as_ref().is_some_and(|prior| prior >= &identity) {
            return Err("generic declarations must be unique and sorted".into());
        }
        previous = Some(identity.clone());
        generic.insert(identity, operation.to_string());
    }
    let routes = raw["routes"].as_array().ok_or("route originals missing")?;
    if routes.is_empty() || routes.len() > MAX_ROUTES || routes.len() != compiled_routes.len()
        || canonical(&raw["routes"])?.len() > MAX_BYTES { return Err("classifier route capacity exceeded".into()); }
    let mut ordered = BTreeMap::new();
    let mut principal_ids = BTreeSet::new();
    for principal in raw["principals"].as_array().ok_or("principal originals missing")? {
        if !principal_ids.insert(text(&principal["id"])?.to_string()) { return Err("duplicate classifier principal".into()); }
    }
    let principal_pin = digest(&raw["principals"])?;
    let credential_pin = digest(&raw["credentials"])?;
    let defaults_pin = digest(&raw["defaults"])?;
    for route in routes {
        if ordered.insert(text(&route["id"])?, route).is_some() { return Err("duplicate classifier route".into()); }
    }
    let mut used = BTreeSet::new();
    let mut profiles = Vec::new();
    let mut entries = Vec::new();
    for (route_id, route) in ordered {
        let compiled = compiled_routes.iter().find(|value| value.id == route_id).ok_or("compiled route missing")?;
        let kind = text(&route["adapter"]["type"])?;
        let config = route["adapter"]["config"].as_object().ok_or("adapter original missing")?;
        if compiled.adapter_type != kind || compiled.adapter_config != route["adapter"]["config"] {
            return Err("classifier is not attached to its exact compiled route".into());
        }
        let paths = route["match"]["paths"].as_array().ok_or("route paths missing")?;
        let mut names = declared_policy_operations(kind, config, paths)?.into_iter().collect::<Vec<_>>();
        names.sort();
        let mut operations = Vec::new();
        for name in names {
            text(&Value::String(name.clone()))?;
            let identity = (route_id.to_string(), name.clone());
            let operation = if kind == "generic.rest" {
                used.insert(identity.clone());
                generic.get(&identity).ok_or("generic route needs exact signed authority declaration")?.as_str()
            } else {
                if generic.contains_key(&identity) { return Err("generic declaration overrides built-in authority".into()); }
                builtin(kind, &name)?
            };
            operations.push(json!({"operationName":name,"operation":operation,
                "requestAuthorityClass":if matches!(operation, "read" | "search") {"read"} else {"write"}}));
        }
        let members = route["principals"].as_array().ok_or("route principals missing")?;
        if members.is_empty() || members.iter().any(|value| value.as_str().is_none_or(|member| member != "*" && !principal_ids.contains(member))) {
            return Err("classifier principal membership changed".into());
        }
        let wildcard = members.iter().any(|member| member == "*");
        let mut principal_hashes = principal_ids.iter().filter(|id| wildcard || members.iter().any(|member| member.as_str() == Some(id.as_str())))
            .map(|id| sha256_prefixed(id.as_bytes())).collect::<Vec<_>>();
        principal_hashes.sort();
        let original = json!({"apiVersion":PROFILE,"routeSha256":sha256_prefixed(route_id.as_bytes()),
            "signedRouteSha256":digest(route)?,"adapterType":kind,"operations":operations,
            "signedPrincipalsSha256":principal_pin,"signedCredentialsSha256":credential_pin,
            "signedDefaultsSha256":defaults_pin,"principalSha256s":principal_hashes});
        let profile_sha = digest(&original)?;
        for operation in &operations {
            entries.push(json!({"routeSha256":original["routeSha256"],"compiledSemanticProfileSha256":profile_sha,
                "operationName":operation["operationName"],"operation":operation["operation"],
                "requestAuthorityClass":operation["requestAuthorityClass"]}));
        }
        profiles.push(json!({"routeId":route_id,"compiledSemanticProfileSha256":profile_sha,"profile":original}));
    }
    if used != generic.keys().cloned().collect() || entries.len() > MAX_OPERATIONS {
        return Err("classifier declarations or operation capacity are not exact".into());
    }
    let mapping = json!({"apiVersion":PROFILE,"profiles":profiles});
    if canonical(&mapping)?.len() > MAX_BYTES { return Err("classifier mapping capacity exceeded".into()); }
    let value = Compiled { mapping_sha256:digest(&mapping)?,
        route_root:digest(&json!({"apiVersion":"serverware.compiledRouteAuthorityRoutes/v1","profiles":profiles}))?,
        operation_root:digest(&json!({"apiVersion":"serverware.compiledRouteAuthorityOperations/v1","operations":entries}))?, mapping };
    if held["mappingSha256"] != value.mapping_sha256 || held["routeAuthorityRootSha256"] != value.route_root
        || held["operationAuthorityRootSha256"] != value.operation_root {
        return Err("signed classifier pins differ from exact compilation".into());
    }
    Ok(Some(Arc::new(value)))
}

impl Compiled {
    pub(crate) fn estimated_bytes(&self) -> Result<usize, String> {
        Ok(canonical(&self.mapping)?.len().saturating_mul(4))
    }

    pub(crate) fn binding(&self, principal: &Principal, route: &Route, operation: &Value)
        -> Result<ObservedAuthorityBinding, String> {
        if !route.principals.iter().any(|id| id == "*" || id == &principal.id) {
            return Err("classified principal is outside the signed route".into());
        }
        let profile = self.mapping["profiles"].as_array().ok_or("classifier map missing")?
            .iter().find(|value| value["routeId"] == route.id).ok_or("classified route missing")?;
        let name = operation.get("operation").and_then(Value::as_str).ok_or("actual adapter operation missing")?;
        let entry = profile["profile"]["operations"].as_array().ok_or("classifier operations missing")?
            .iter().find(|value| value["operationName"] == name).ok_or("actual adapter operation is unclassified")?;
        let digest = |value: &str| Sha256Digest::parse(value.to_string()).map_err(|error| error.to_string());
        Ok(ObservedAuthorityBinding::from_compiled_route(digest(&sha256_prefixed(principal.id.as_bytes()))?,
            digest(profile["profile"]["routeSha256"].as_str().ok_or("route digest missing")?)?,
            class(entry["operation"].as_str().ok_or("operation class missing")?)?,
            digest(profile["compiledSemanticProfileSha256"].as_str().ok_or("profile digest missing")?)?))
    }
}
