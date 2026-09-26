//! Supplied TLS-root configuration only, not loading or trust admission.
//!
//! The caller owns PEM provenance and input bounds. This preserves main's
//! existing PEM extraction/Reqwest parsing and exclusive custom-root behavior;
//! it does not read environment variables, files, or network state.

use super::pem_certificates;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::Certificate;
use std::time::Duration;

#[derive(Clone)]
pub(super) struct ControlPlaneClientConfig {
    // None preserves Reqwest's built-ins. Some is nonempty and replaces them.
    roots: Option<Vec<Certificate>>,
}

impl ControlPlaneClientConfig {
    pub(super) fn builtin() -> Self { Self { roots: None } }

    pub(super) fn from_pem(text: &str) -> Result<Self, String> {
        let originals = pem_certificates(text);
        if originals.is_empty() {
            return Err("control-plane CA bundle has no PEM certificates".to_owned());
        }
        let mut roots = Vec::with_capacity(originals.len());
        for original in originals {
            let certificate = Certificate::from_pem(&original)
                .map_err(|error| format!("parse control-plane CA certificate: {error}"))?;
            roots.push(certificate);
        }
        Ok(Self { roots: Some(roots) })
    }

    pub(super) fn builder(&self, timeout: Duration) -> ClientBuilder {
        let mut builder = Client::builder()
            .timeout(timeout)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_info(true);
        if let Some(roots) = self.roots.as_ref() {
            builder = builder.tls_built_in_root_certs(false);
            for certificate in roots {
                builder = builder.add_root_certificate(certificate.clone());
            }
        }
        builder
    }
}
