//! Dedicated native audit mTLS client; generated client key never leaves TLS memory.
use super::*;
use serverware_decision_gate::native_audit_batch_v1 as wire;

#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct Configuration {
    pub(super) api_version:String, pub(super) deployment_id:String, pub(super) instance_id:String,
    pub(super) epoch_id:String, pub(super) assignment_sha256:String,
    pub(super) initial_sequence:u64,
    #[serde(deserialize_with="deserialize_required_option")]
    pub(super) previous_batch_sha256:Option<String>,
}

pub(super) fn prepare(config:Configuration, roots:&ControlPlaneClientConfig,
    relays:&Arc<NativeUpstreamRelaysV1>, url:&str, identity:&mut EnclaveRuntimeIdentityV1, deadline:u64)
    ->Result<native_audit_owner::Owner,String> {
    if config.api_version!="serverware.nativeMeasuredAuditConfiguration/v1" || !wire::digest(&config.assignment_sha256)
        || config.initial_sequence==0 || config.initial_sequence>=i64::MAX as u64
        || (config.initial_sequence==1)!=config.previous_batch_sha256.is_none()
        || config.previous_batch_sha256.as_ref().is_some_and(|v|!wire::digest(v))
        || !wire::uuid(&config.epoch_id) {
        return Err("native audit configuration is invalid".into());
    }
    let endpoint=Url::parse(url).map_err(|_|"audit endpoint")?;
    if endpoint.scheme()!="https" || endpoint.path()!="/api/data-plane/audit" || endpoint.query().is_some()
        || endpoint.fragment().is_some() || !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err("native audit endpoint must be the exact HTTPS intake".into());
    }
    let uri=wire::workload_uri(&config.deployment_id,&config.instance_id)?;
    let (tls,certificate)=identity.audit_client_identity(&uri,deadline)?;
    let (_,leaf)=x509_parser::parse_x509_certificate(&certificate).map_err(|_|"audit generated certificate")?;
    let spki=sha256_prefixed(leaf.public_key().raw);
    let client=roots.builder(Duration::from_secs(2)).https_only(true).identity(tls)
        .min_tls_version(reqwest::tls::Version::TLS_1_3).max_tls_version(reqwest::tls::Version::TLS_1_3)
        .pool_max_idle_per_host(0).proxy(relays.service_proxy(&[url])?).build().map_err(|_|"native audit TLS client")?;
    Ok(native_audit_owner::Owner::new(config,client,url.to_owned(),sha256_prefixed(&certificate),spki,uri))
}
