//! Dedicated native audit mTLS client; generated client key never leaves TLS memory.
use super::*;
use serverware_decision_gate::native_audit_batch_v1 as wire;

#[derive(Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct ConfigurationV1 {
    pub(super) api_version:String, pub(super) deployment_id:String, pub(super) instance_id:String,
    pub(super) epoch_id:String, pub(super) assignment_sha256:String,
    pub(super) initial_sequence:u64,
    #[serde(deserialize_with="deserialize_required_option")]
    pub(super) previous_batch_sha256:Option<String>,
}

/// Only the two public cold shapes deserialize. A resolved postboot assignment
/// can be produced only by the purpose-fixed signature/actual-owner join.
pub(super) enum Configuration {
    Legacy(ConfigurationV1),
    Postboot(super::native_audit_assignment::ConfigurationV2),
    Admitted(ResolvedConfiguration),
}

impl<'de> Deserialize<'de> for Configuration {
    fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->Result<Self,D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Cold { Legacy(ConfigurationV1), Postboot(super::native_audit_assignment::ConfigurationV2) }
        match Cold::deserialize(decoder)? {
            Cold::Legacy(config) => {
                if config.api_version!="serverware.nativeMeasuredAuditConfiguration/v1" {
                    return Err(serde::de::Error::custom("native audit configuration version differs"));
                }
                Ok(Self::Legacy(config))
            }
            Cold::Postboot(config) => {
                config.validate().map_err(serde::de::Error::custom)?;
                Ok(Self::Postboot(config))
            }
        }
    }
}

impl Configuration {
    pub(super) fn is_legacy(&self)->bool { matches!(self,Self::Legacy(_)) }
    pub(super) fn requires_postboot_assignment(&self)->bool { matches!(self,Self::Postboot(_)) }
    pub(super) fn admit_postboot(self, original:&[u8], identity:&mut EnclaveRuntimeIdentityV1,
        signer:&CustodyResponseProofSigner, actual_configuration_sha256:&str,
        actual_binary_digest:&str, deadline:u64)->Result<Self,String> {
        let Self::Postboot(config)=self else {return Err("audit postboot admission requires unconsumed v2 configuration".into());};
        super::native_audit_assignment::admit(config,original,identity,signer,
            actual_configuration_sha256,actual_binary_digest,deadline).map(Self::Admitted)
    }
}

pub(super) struct ResolvedConfiguration {
    pub(super) deployment_id:String, pub(super) instance_id:String,
    pub(super) epoch_id:String, pub(super) assignment_sha256:String,
    pub(super) initial_sequence:u64, pub(super) previous_batch_sha256:Option<String>,
    pub(super) admission:Option<super::native_audit_assignment::Admission>,
}

pub(super) fn prepare(config:Configuration, roots:&ControlPlaneClientConfig,
    relays:&Arc<NativeUpstreamRelaysV1>, url:&str, identity:&mut EnclaveRuntimeIdentityV1, deadline:u64)
    ->Result<native_audit_owner::Owner,String> {
    let config=match config {
        Configuration::Postboot(_)=>return Err("audit postboot assignment has not been admitted".into()),
        Configuration::Admitted(config)=>{
            config.admission.as_ref().ok_or("audit postboot admission original absent")?.check()?;
            config
        }
        Configuration::Legacy(config)=>{
            if config.api_version!="serverware.nativeMeasuredAuditConfiguration/v1" || !wire::digest(&config.assignment_sha256)
                || config.initial_sequence==0 || config.initial_sequence>=i64::MAX as u64
                || (config.initial_sequence==1)!=config.previous_batch_sha256.is_none()
                || config.previous_batch_sha256.as_ref().is_some_and(|v|!wire::digest(v))
                || !wire::uuid(&config.epoch_id) {
                return Err("native audit configuration is invalid".into());
            }
            ResolvedConfiguration { deployment_id:config.deployment_id,instance_id:config.instance_id,
                epoch_id:config.epoch_id,assignment_sha256:config.assignment_sha256,
                initial_sequence:config.initial_sequence,previous_batch_sha256:config.previous_batch_sha256,
                admission:None }
        }
    };
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
    if let Some(admission)=&config.admission { admission.check()?; }
    Ok(native_audit_owner::Owner::new(config,client,url.to_owned(),sha256_prefixed(&certificate),spki,uri))
}
