//! Opt-in native capture orchestration. This is local evidence, not release authority.
use super::*;
use super::proof_client_native_verifier_v1::NativeResponseVerifierV1;
use serverware_decision_gate::response_principal_compatibility_v1::{
    require_response_principal_compatible, ResponseProofPrincipalProfile,
};
use std::net::{IpAddr, SocketAddr};
use zeroize::Zeroizing;

struct InputSnapshot {
    path: PathBuf,
    label: &'static str,
    owner_only: bool,
    limit: usize,
    file: File,
    chain: Vec<FileIdentity>,
    metadata: fs::Metadata,
    digest: String,
}

impl InputSnapshot {
    fn open(path: &Path, label: &'static str, owner_only: bool, limit: usize)
        -> Result<(Self, Zeroizing<Vec<u8>>), String>
    {
        let (mut file, chain, metadata) = open_trusted_input_path(path, label, owner_only, limit)?;
        let mut bytes = Zeroizing::new(Vec::new());
        Read::by_ref(&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)
            .map_err(|err| format!("read native {label}: {err}"))?;
        if bytes.len() as u64 != metadata.len() || bytes.len() > limit
            || trusted_metadata_fingerprint(&metadata) != trusted_metadata_fingerprint(
                &file.metadata().map_err(|err| format!("inspect native {label}: {err}"))?)
        {
            return Err(format!("native {label} changed during admission"));
        }
        let snapshot = Self {
            path: path.to_owned(), label, owner_only, limit, file, chain, metadata,
            digest: sha256_prefixed(&bytes),
        };
        snapshot.recheck()?;
        Ok((snapshot, bytes))
    }

    fn recheck(&self) -> Result<(), String> {
        let (mut current, chain, metadata) = open_trusted_input_path(
            &self.path, self.label, self.owner_only, self.limit)?;
        if chain != self.chain
            || trusted_metadata_fingerprint(&metadata) != trusted_metadata_fingerprint(&self.metadata)
            || trusted_metadata_fingerprint(&self.file.metadata()
                .map_err(|err| format!("inspect held native input: {err}"))?)
                != trusted_metadata_fingerprint(&self.metadata)
        {
            return Err(format!("native {} input identity changed", self.label));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        Read::by_ref(&mut current).take(self.limit as u64 + 1).read_to_end(&mut bytes)
            .map_err(|err| format!("reread native {}: {err}", self.label))?;
        if bytes.len() as u64 != self.metadata.len() || sha256_prefixed(&bytes) != self.digest
            || trusted_metadata_fingerprint(&current.metadata()
                .map_err(|err| format!("reinspect native input: {err}"))?)
                != trusted_metadata_fingerprint(&self.metadata)
        {
            return Err(format!("native {} original bytes changed", self.label));
        }
        Ok(())
    }
}

pub(super) struct NativeCaptureSessionV1 {
    verifier: NativeResponseVerifierV1,
    ingress: Option<super::proof_client_native_ingress_v1::NativeIngressAdmission>,
    pub(super) control_plane_key: VerifyingKey,
    collector_key: SigningKey,
    roots: RootCertStore,
    expected_peer: String,
    inputs: Vec<InputSnapshot>,
    owner_pid: u32,
    outer_endpoint: SocketAddr,
    outer_name: ServerName<'static>,
    outer_config: Arc<ClientConfig>,
    deadline: Instant,
}

impl NativeCaptureSessionV1 {
    pub(super) fn open(args: &Args, config: NativeVerifierConfigV1) -> Result<Self, String> {
        let owner_pid = std::process::id();
        let deadline = Instant::now().checked_add(Duration::from_secs(args.timeout_seconds))
            .ok_or("native session deadline overflow")?;
        if args.proxy_raw_development {
            return Err("native capture cannot use raw development proxy transport".to_string());
        }
        let endpoint = parse_proxy_endpoint(&args.proxy, false, args.proxy_server_name.as_deref())?;
        let outer_endpoint = native_outer_endpoint(&endpoint.address)?;
        let outer_name = ServerName::try_from(endpoint.server_name.clone())
            .map_err(|_| "native outer TLS server name is invalid")?;
        // Require all three even if an in-process caller bypasses Args parsing.
        let proxy_ca_path = args.proxy_ca.as_deref().ok_or("native capture requires --proxy-ca")?;
        let proxy_certificate_path = args.proxy_client_cert.as_deref()
            .ok_or("native capture requires --proxy-client-cert")?;
        let proxy_key_path = args.proxy_client_key.as_deref()
            .ok_or("native capture requires --proxy-client-key")?;
        let verifier = NativeResponseVerifierV1::open(config, deadline)?;
        // A failed opt-in ingress admission cannot fall back to the historical
        // CA-only transport. All public startup checks precede private keys.
        let ingress = args.native_ingress_configuration.as_ref()
            .map(|(path, pin)| super::proof_client_native_ingress_v1::NativeIngressAdmission::open(
                path, pin, &args.expected_principal_id, deadline)).transpose()?;
        // Argument parsing only provisionally permits the wider identity when
        // native ingress is requested. The pinned, genuinely opened v3 profile
        // must select it before private inputs, output staging or any contact.
        let maximum_principal = if ingress.as_ref().is_some_and(|item| item.principal_preflight()) {
            1024
        } else { 256 };
        if args.expected_principal_id.is_empty()
            || args.expected_principal_id != args.expected_principal_id.trim()
            || args.expected_principal_id.len() > maximum_principal
            || args.expected_principal_id.chars().any(char::is_control)
            || args.proxy_headers.iter().any(|(name, value)| name.eq_ignore_ascii_case("x-serverware-agent")
                && (value.is_empty() || value != value.trim() || value.len() > maximum_principal
                    || value.chars().any(char::is_control))) {
            return Err("native principal arguments exceed the admitted ingress profile".to_owned());
        }
        if let Some(admission) = ingress.as_ref() {
            let instance = args.expected_server_instance_id.as_deref()
                .ok_or("native ingress requires expected server instance")?;
            verifier.require_ingress_scope(admission.scope(), admission.trust_roots_sha256(), instance)?;
            if endpoint.server_name != admission.host() {
                return Err("native proxy TLS name differs from verified ingress scope".to_owned());
            }
        }
        // Principal preflight and response proof are distinct profiles. Refuse
        // an incompatible requested capture here, before loading private inputs
        // or connecting, instead of failing only after a provider operation.
        let response_profile = if args.observation {
            ResponseProofPrincipalProfile::Observation
        } else if args.stream {
            ResponseProofPrincipalProfile::Streaming
        } else {
            ResponseProofPrincipalProfile::Buffered
        };
        require_response_principal_compatible(response_profile, &args.expected_principal_id)?;
        let nonce = args.client_nonce.ok_or("native capture requires explicit --nonce")?;
        if verifier.expected_nonce()?.as_slice() != nonce {
            return Err("native independently pinned nonce differs from --nonce".to_string());
        }
        if args.observation { validate_observation_nonce_freshness(&nonce)?; }
        let (ca_input, ca_bytes) = InputSnapshot::open(&args.ca, "--ca", false, MAX_CA_BUNDLE_BYTES)?;
        let certificates = CertificateDer::pem_slice_iter(&ca_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("parse native CA: {err}"))?;
        if certificates.len() != 1 {
            return Err("native --ca must contain exactly the independently pinned CA certificate".to_string());
        }
        let certificate = &certificates[0];
        let (remaining, parsed) = X509Certificate::from_der(certificate.as_ref())
            .map_err(|_| "parse native CA DER")?;
        if !remaining.is_empty()
            || sha256_prefixed(certificate.as_ref()) != verifier.ca_certificate_sha256()
            || sha256_prefixed(parsed.public_key().raw) != verifier.ca_public_key_spki_sha256()
        {
            return Err("native TLS CA does not match independently pinned attestation scope".to_string());
        }
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).map_err(|err| format!("add native CA: {err}"))?;
        let (cp_input, cp_bytes) = InputSnapshot::open(&args.control_plane_response_key,
            "--control-plane-response-key", false, MAX_TRUST_KEY_BYTES)?;
        let (control_plane_key, key_id) = decode_public_key_pem(
            std::str::from_utf8(&cp_bytes).map_err(|_| "native control-plane key is not UTF-8")?)?;
        if key_id != verifier.control_plane_key_id() {
            return Err("native control-plane key does not match independently pinned key ID".to_string());
        }
        let (proxy_ca_input, proxy_ca_bytes) = InputSnapshot::open(
            proxy_ca_path, "--proxy-ca", false, MAX_CA_BUNDLE_BYTES)?;
        let outer_certificates = CertificateDer::pem_slice_iter(&proxy_ca_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "parse retained native outer CA bundle")?;
        if outer_certificates.is_empty() {
            return Err("native outer CA bundle contains no certificates".to_string());
        }
        if let Some(admission) = ingress.as_ref() {
            if outer_certificates.len() != 1 || outer_certificates[0].as_ref() != admission.ca() {
                return Err("native proxy CA differs from the exact verified ingress CA".to_owned());
            }
            admission.recheck()?;
        }
        let mut outer_roots = RootCertStore::empty();
        for certificate in outer_certificates {
            outer_roots.add(certificate).map_err(|_| "add retained native outer CA certificate")?;
        }
        let (proxy_certificate_input, proxy_certificate_bytes) = InputSnapshot::open(
            proxy_certificate_path, "--proxy-client-cert", false, MAX_PROXY_CLIENT_CERTIFICATE_BYTES)?;
        let outer_chain = native_outer_client_chain(&proxy_certificate_bytes)?;
        let (proxy_key_input, proxy_key_bytes) = InputSnapshot::open(
            proxy_key_path, "--proxy-client-key", true, MAX_PROXY_CLIENT_PRIVATE_KEY_BYTES)?;
        let outer_key = PrivateKeyDer::from_pem_slice(&proxy_key_bytes)
            .map_err(|_| "parse retained native outer client private key")?;
        // Only admitted original bytes configure TLS; no path-based loader is
        // called here or at connect. The key source remains zeroizing storage.
        let mut outer_config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(outer_roots)
            .with_client_auth_cert(outer_chain, outer_key)
            .map_err(|_| "build retained native outer mTLS configuration")?;
        outer_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        outer_config.resumption = rustls::client::Resumption::disabled();
        outer_config.enable_early_data = false;
        drop(proxy_key_bytes);
        let (collector_input, collector_bytes) = InputSnapshot::open(&args.collector_key,
            "--collector-key", true, MAX_TRUST_KEY_BYTES)?;
        let collector_key = SigningKey::from_pkcs8_pem(
            std::str::from_utf8(&collector_bytes).map_err(|_| "native collector key is not UTF-8")?)
            .map_err(|err| format!("parse native collector key: {err}"))?;
        let mut inputs = vec![ca_input, cp_input, collector_input, proxy_ca_input,
            proxy_certificate_input, proxy_key_input];
        if let Some(path) = args.request_body.as_deref() {
            let (snapshot, _) = InputSnapshot::open(path, "--request-body", false, MAX_RESPONSE_BODY_BYTES)?;
            inputs.push(snapshot);
        }
        let session = Self {
            verifier, ingress, control_plane_key, collector_key, roots, inputs, deadline,
            owner_pid, outer_endpoint, outer_name, outer_config: Arc::new(outer_config),
            expected_peer: args.expected_server_instance_id.clone()
                .ok_or("native capture requires expected SPIFFE identity")?,
        };
        session.recheck()?;
        Ok(session)
    }

    pub(super) fn roots(&self) -> RootCertStore { self.roots.clone() }

    // Cheap enough to guard every inner plaintext I/O, including rustls's
    // already-buffered bytes. Do not add filesystem work or renew the deadline.
    pub(super) fn check_live(&self) -> Result<(), String> {
        if std::process::id() != self.owner_pid || Instant::now() >= self.deadline {
            return Err("native session process changed or original deadline expired".to_string());
        }
        Ok(())
    }

    pub(super) fn recheck(&self) -> Result<(), String> {
        self.check_live()?;
        self.verifier.recheck_inputs()?;
        if let Some(ingress) = self.ingress.as_ref() { ingress.recheck()?; }
        for input in &self.inputs { input.recheck()?; }
        self.check_live()
    }

    pub(super) fn connect_proxy(&self, identity_headers: &[(String, String)])
        -> Result<super::proof_client_native_transport_v1::NativeProxyTransportV1, String>
    {
        self.recheck()?;
        let mut transport = super::proof_client_native_transport_v1::connect(
            self.outer_endpoint, self.outer_name.clone(), Arc::clone(&self.outer_config), self.deadline)?;
        if let Some(ingress) = self.ingress.as_ref() {
            let authority = if ingress.host().contains(':') {
                format!("[{}]:{}", ingress.host(), self.outer_endpoint.port())
            } else { format!("{}:{}", ingress.host(), self.outer_endpoint.port()) };
            ingress.attest(&mut transport, &authority, identity_headers)?;
        }
        self.recheck()?;
        Ok(transport)
    }

    pub(super) fn protect_target(&self, target: &ResolvedOutputTarget) -> Result<(), String> {
        if let Some(ingress) = self.ingress.as_ref() { ingress.protect_target(target)?; }
        // Anchored parent identity + name catches lexical aliases even before a
        // target exists; held inode catches hard-link aliases. Same-UID writers
        // remain trusted, as in the existing private publication protocol.
        for input in &self.inputs {
            reject_alias(target, &input.path, &input.chain, &input.metadata)?;
        }
        for (path, held_identity) in self.verifier.input_paths().into_iter()
            .zip(self.verifier.input_file_identities())
        {
            let (_, chain, metadata) = open_trusted_input_path(path,
                "native verifier input", false, 64 * 1024 * 1024)?;
            if (metadata.dev(), metadata.ino()) != held_identity {
                return Err("native verifier input identity changed before output admission".to_string());
            }
            reject_alias(target, path, &chain, &metadata)?;
        }
        Ok(())
    }

    pub(super) fn require_original(&self, proof: &Value, encoded: &str, digest: &str,
        max_bytes: usize) -> Result<(), String>
    {
        if encoded.len() > max_bytes * 4 / 3 + 4 {
            return Err("native original envelope exceeds its bound".to_string());
        }
        let bytes = general_purpose::URL_SAFE_NO_PAD.decode(encoded.as_bytes())
            .map_err(|_| "native original envelope is not base64url")?;
        if bytes.is_empty() || bytes.len() > max_bytes
            || general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != encoded
            || sha256_prefixed(&bytes) != digest
            || canonical_json(proof).as_bytes() != bytes
        {
            return Err("native original envelope must be bounded canonical unique-key JSON with exact digest".to_string());
        }
        Ok(())
    }

    // Call only after the corresponding real buffered/stream/observation capture
    // entrypoint succeeds. No caller-supplied quote verdict is accepted here.
    pub(super) fn verify_and_sign(&self, mode: &str, proof: &Value, mut capture: Value,
        runtime_digest: &str, nonce: &[u8], peer: &str) -> Result<(Vec<u8>, Value), String>
    {
        self.recheck()?;
        if peer != self.expected_peer { return Err("native actual TLS peer differs from expected SPIFFE ID".to_string()); }
        let verification = self.verifier.verify(proof, nonce, self.deadline)?;
        capture["runtime_proof_sha256"] = json!(runtime_digest);
        let mut artifact = json!({
            "apiVersion":"serverware.nativeResponseCapture/v1",
            "kind":"ServerwareNativeResponseCapture",
            "resultScope":"local-capture-and-native-quote-only",
            "okForAction":false,
            "environment":"native-unadmitted",
            "captureMode":mode,
            "external_capture":capture,
            "runtime_proof":proof,
            "native_verification":verification,
        });
        let canonical = canonical_json(&artifact);
        let signature = self.collector_key.sign(canonical.as_bytes());
        self.collector_key.verifying_key().verify_strict(canonical.as_bytes(), &signature)
            .map_err(|_| "native collector signature self-verification failed")?;
        let (pem, key_id) = public_key_material(&self.collector_key);
        artifact["collector_signature"] = json!({
            "algorithm":"Ed25519", "key_id":key_id, "public_key_pem":pem,
            "signature":format!("ed25519:{}", general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())),
            "capture_digest":sha256_prefixed(canonical.as_bytes()),
        });
        let mut payload = serde_json::to_vec_pretty(&artifact)
            .map_err(|err| format!("serialize native capture: {err}"))?;
        payload.push(b'\n');
        self.recheck()?;
        let capture = &artifact["external_capture"];
        let summary = json!({
            "ok":true, "capture_verified":true, "captureMode":mode,
            "resultScope":"local-capture-and-native-quote-only", "okForAction":false,
            "environment":"native-unadmitted", "proof_sha256":sha256_prefixed(&payload),
            "runtime_proof_sha256":runtime_digest, "collector_key_id":key_id,
            "client_nonce":general_purpose::URL_SAFE_NO_PAD.encode(nonce),
            "server_instance_id":peer,
            "external_capture":capture,
        });
        Ok((payload, summary))
    }
}

fn native_outer_endpoint(original: &str) -> Result<SocketAddr, String> {
    let endpoint = original.parse::<SocketAddr>()
        .map_err(|_| "native proxy endpoint must be a literal socket address without DNS")?;
    if endpoint.to_string() != original || endpoint.port() == 0 {
        return Err("native proxy endpoint must use a canonical nonzero port".to_string());
    }
    let ip = match endpoint {
        SocketAddr::V4(value) => IpAddr::V4(*value.ip()),
        SocketAddr::V6(value) => {
            if value.scope_id() != 0 || value.flowinfo() != 0 {
                return Err("native proxy endpoint cannot select an IPv6 scope".to_string());
            }
            value.ip().to_ipv4_mapped().map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(*value.ip()))
        }
    };
    if ip.is_unspecified() || ip.is_multicast()
        || matches!(ip, IpAddr::V4(value) if value.is_broadcast())
    {
        return Err("native proxy endpoint must be a concrete unicast address".to_string());
    }
    Ok(endpoint)
}

fn native_outer_client_chain(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let certificates = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "parse retained native outer client certificate chain")?;
    if certificates.is_empty() || certificates.len() > 16 {
        return Err("native outer client chain must contain 1-16 certificates".to_string());
    }
    let total = certificates.iter().try_fold(0usize, |total, certificate| {
        if certificate.is_empty() || certificate.len() > 256 * 1024 {
            return Err("native outer client chain has an invalid certificate size");
        }
        total.checked_add(certificate.len()).ok_or("native outer client chain size overflow")
    })?;
    if total > MAX_PROXY_CLIENT_CERTIFICATE_BYTES {
        return Err("native outer client chain exceeds its total bound".to_string());
    }
    Ok(certificates)
}

pub(super) fn reject_alias(target: &ResolvedOutputTarget, input_path: &Path,
    chain: &[FileIdentity], metadata: &fs::Metadata) -> Result<(), String>
{
    let parent = chain.get(chain.len().checked_sub(2).ok_or("native input parent identity missing")?)
        .ok_or("native input parent identity missing")?;
    if *parent == target.directory.identity && input_path.file_name() == Some(target.name.as_os_str()) {
        return Err("native output aliases an input path".to_string());
    }
    match target.directory.open_read(&target.name) {
        Ok(file) => {
            if FileIdentity::from_metadata(&file.metadata().map_err(|err| format!("inspect native output: {err}"))?)
                == FileIdentity::from_metadata(metadata)
            {
                return Err("native output aliases an input inode".to_string());
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("inspect native output without following symlinks: {err}")),
    }
    Ok(())
}
