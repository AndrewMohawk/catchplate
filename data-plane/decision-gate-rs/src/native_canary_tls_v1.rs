//! Dedicated generated canary TLS custody. No imported certificate, private-key
//! getter, audit alias, network send, or transport-derived admission exists.
use super::{live, EnclaveRuntimeIdentityV1};
use crate::native_canary_evidence_v1 as wire;
use sha2::{Digest, Sha256};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use time::OffsetDateTime;

pub struct NativeCanaryTlsIdentity {
    identity: Option<reqwest::Identity>, certificate: Vec<u8>, certificate_sha256: String,
    spki_sha256: String, uri: String, ca_sha256: [u8; 32], pid: libc::pid_t, deadline: u64,
    not_before: OffsetDateTime, not_after: OffsetDateTime,
    privileges: Arc<crate::native_serving_privileges::Owner>, poisoned: AtomicBool,
}
impl NativeCanaryTlsIdentity {
    pub fn deadline(&self) -> u64 { self.deadline }
    pub fn certificate_der(&self) -> &[u8] { &self.certificate }
    pub fn certificate_sha256(&self) -> &str { &self.certificate_sha256 }
    pub fn spki_sha256(&self) -> &str { &self.spki_sha256 }
    pub fn workload_uri(&self) -> &str { &self.uri }
    pub(crate) fn require_statement_window(&self, issued: u64, expires: u64, deadline: u64) -> Result<(), String> {
        self.check(deadline)?;
        if (issued as i128) < self.not_before.unix_timestamp_nanos() || (expires as i128) > self.not_after.unix_timestamp_nanos() {
            return Err("canary statement exceeds original TLS validity".into());
        }
        Ok(())
    }
    pub fn check(&self, deadline: u64) -> Result<(), String> {
        let result = (|| {
            if self.poisoned.load(Ordering::Acquire) || unsafe { libc::getpid() } != self.pid {
                return Err("canary TLS owner changed process or is poisoned".into());
            }
            self.privileges.check()?; live(deadline.min(self.deadline))?;
            let now = OffsetDateTime::now_utc();
            if now < self.not_before || now >= self.not_after { return Err("canary TLS original CA interval expired".into()); }
            Ok(())
        })();
        if result.is_err() { self.poisoned.store(true, Ordering::Release); }
        result
    }

    /// Consumes the private identity into a fixed-path TLS1.3 client. The
    /// returned owner intentionally offers no generic client/request access.
    /// Builder roots and relay ownership must be supplied by native startup.
    pub fn bind_http_client(mut self, builder: reqwest::blocking::ClientBuilder, intake_url: &str,
        deadline: u64) -> Result<NativeCanaryHttpClient, String> {
        self.check(deadline)?;
        let url = url::Url::parse(intake_url).map_err(|_| "canary intake URL")?;
        if url.scheme() != "https" || url.host_str().is_none() || url.path() != wire::INTAKE_PATH
            || url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
            return Err("canary client requires its exact HTTPS intake path".into());
        }
        let mut inspect = url.clone(); inspect.set_path(wire::INSPECT_PATH);
        let identity = self.identity.take().ok_or("canary TLS identity already installed")?;
        let client = builder.https_only(true).identity(identity)
            .min_tls_version(reqwest::tls::Version::TLS_1_3).max_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none()).pool_max_idle_per_host(0)
            .build().map_err(|_| "build dedicated native canary TLS client")?;
        self.check(deadline)?;
        Ok(NativeCanaryHttpClient { client, tls: self, intake: url.to_string(), inspect: inspect.to_string() })
    }
}

/// Construction is real but contact deliberately awaits the durable
/// precontact/uncertain-state owner. A cloned bare reqwest client cannot escape.
pub struct NativeCanaryHttpClient {
    #[allow(dead_code)] client: reqwest::blocking::Client,
    tls: NativeCanaryTlsIdentity, intake: String, inspect: String,
}
impl NativeCanaryHttpClient {
    pub fn tls(&self) -> &NativeCanaryTlsIdentity { &self.tls }
    pub fn endpoint(&self, operation: wire::Operation) -> &str {
        match operation { wire::Operation::Intake => &self.intake, wire::Operation::Inspect => &self.inspect }
    }
    pub fn check(&self, identity: &mut EnclaveRuntimeIdentityV1, deadline: u64) -> Result<(), String> {
        identity.verify_canary_tls(&self.tls, deadline)
    }
}

impl EnclaveRuntimeIdentityV1 {
    pub fn canary_client_identity(&mut self, deployment: &str, instance: &str, deadline: u64)
        -> Result<NativeCanaryTlsIdentity, String> {
        let deadline = self.begin(deadline)?;
        self.require_tls_time(OffsetDateTime::now_utc())?;
        let privileges = Arc::clone(self.serving_privileges.as_ref().ok_or("canary TLS requires actual permanent native serving custody")?);
        privileges.check()?;
        let material = self.authority.canary_client_identity(deployment, instance, self.ca_not_before, self.ca_not_after)?;
        if material.certificate.is_empty() || material.certificate.len() > 16 * 1024 {
            return Err("canary generated TLS certificate bound".into());
        }
        let result = NativeCanaryTlsIdentity {
            identity: Some(material.identity), certificate_sha256: crate::sha256_prefixed(&material.certificate),
            spki_sha256: crate::sha256_prefixed(&material.spki), certificate: material.certificate,
            uri: wire::workload_uri(deployment, instance)?, ca_sha256: Sha256::digest(self.authority.certificate_der()).into(),
            pid: self.owner_pid, deadline, not_before: self.ca_not_before, not_after: self.ca_not_after,
            privileges, poisoned: AtomicBool::new(false),
        };
        result.check(deadline)?; self.finish(deadline)?; Ok(result)
    }
    pub fn verify_canary_tls(&mut self, tls: &NativeCanaryTlsIdentity, deadline: u64) -> Result<(), String> {
        let deadline = self.begin(deadline.min(tls.deadline))?;
        tls.check(deadline)?; self.require_tls_time(OffsetDateTime::now_utc())?;
        let ca: [u8; 32] = Sha256::digest(self.authority.certificate_der()).into();
        if self.owner_pid != tls.pid || ca != tls.ca_sha256 || self.ca_not_before != tls.not_before || self.ca_not_after != tls.not_after
            || !self.serving_privileges.as_ref().is_some_and(|actual| Arc::ptr_eq(actual, &tls.privileges)) {
            tls.poisoned.store(true, Ordering::Release);
            return Err("canary TLS belongs to another actual runtime identity".into());
        }
        tls.check(deadline)?; self.finish(deadline)
    }
}
