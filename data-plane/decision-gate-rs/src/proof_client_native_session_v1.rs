//! Opt-in native capture orchestration. This is local evidence, not release authority.
use super::*;
use super::proof_client_native_verifier_v1::NativeResponseVerifierV1;
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
    pub(super) control_plane_key: VerifyingKey,
    collector_key: SigningKey,
    roots: RootCertStore,
    expected_peer: String,
    inputs: Vec<InputSnapshot>,
    deadline: Instant,
}

impl NativeCaptureSessionV1 {
    pub(super) fn open(args: &Args, config: NativeVerifierConfigV1) -> Result<Self, String> {
        let deadline = Instant::now().checked_add(Duration::from_secs(args.timeout_seconds))
            .ok_or("native session deadline overflow")?;
        let verifier = NativeResponseVerifierV1::open(config, deadline)?;
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
        let (collector_input, collector_bytes) = InputSnapshot::open(&args.collector_key,
            "--collector-key", true, MAX_TRUST_KEY_BYTES)?;
        let collector_key = SigningKey::from_pkcs8_pem(
            std::str::from_utf8(&collector_bytes).map_err(|_| "native collector key is not UTF-8")?)
            .map_err(|err| format!("parse native collector key: {err}"))?;
        let mut inputs = vec![ca_input, cp_input, collector_input];
        for (path, label, secret, limit) in [
            (args.proxy_ca.as_deref(), "--proxy-ca", false, MAX_CA_BUNDLE_BYTES),
            (args.proxy_client_cert.as_deref(), "--proxy-client-cert", false, MAX_PROXY_CLIENT_CERTIFICATE_BYTES),
            (args.proxy_client_key.as_deref(), "--proxy-client-key", true, MAX_PROXY_CLIENT_PRIVATE_KEY_BYTES),
            (args.request_body.as_deref(), "--request-body", false, MAX_RESPONSE_BODY_BYTES),
        ] {
            if let Some(path) = path {
                let (snapshot, _) = InputSnapshot::open(path, label, secret, limit)?;
                inputs.push(snapshot);
            }
        }
        let session = Self {
            verifier, control_plane_key, collector_key, roots, inputs, deadline,
            expected_peer: args.expected_server_instance_id.clone()
                .ok_or("native capture requires expected SPIFFE identity")?,
        };
        session.recheck()?;
        Ok(session)
    }

    pub(super) fn roots(&self) -> RootCertStore { self.roots.clone() }

    pub(super) fn recheck(&self) -> Result<(), String> {
        if Instant::now() >= self.deadline { return Err("native session deadline expired".to_string()); }
        self.verifier.recheck_inputs()?;
        for input in &self.inputs { input.recheck()?; }
        if Instant::now() >= self.deadline { return Err("native session deadline expired".to_string()); }
        Ok(())
    }

    pub(super) fn protect_target(&self, target: &ResolvedOutputTarget) -> Result<(), String> {
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

fn reject_alias(target: &ResolvedOutputTarget, input_path: &Path,
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
