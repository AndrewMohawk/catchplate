//! One-shot gate executor. Credential injection, native identity, currentness,
//! snapshot and dispatch mutation guards remain in this actual measured gate.
use super::*;
use serverware_decision_gate::native_target_dispatch_v1 as profile;
use serverware_decision_gate::native_response_gate::{state_receipt::RawObjectReference, target_dispatch as wire};
use rustls::{ClientConfig,ClientConnection,RootCertStore,StreamOwned};
use rustls::pki_types::{CertificateDer,ServerName};

const EXPORTER:&[u8]=b"EXPORTER-serverware-native-target-dispatch-v1";

pub(super) fn tls_configuration(original:&str)->Result<Arc<ClientConfig>,String> {
    let certificates=pem_certificates(original);
    if certificates.is_empty() || certificates.len()>32 {return Err("capture TLS roots absent or oversized".into());}
    let mut roots=RootCertStore::empty();
    for pem in certificates {
        let text=std::str::from_utf8(&pem).map_err(|_|"capture root PEM encoding")?;
        let encoded=text.strip_prefix("-----BEGIN CERTIFICATE-----\n")
            .and_then(|s|s.strip_suffix("-----END CERTIFICATE-----\n")).ok_or("capture root PEM framing")?;
        let body:String=encoded.lines().collect();
        let der=general_purpose::STANDARD.decode(&body).map_err(|_|"capture root base64")?;
        if general_purpose::STANDARD.encode(&der)!=body {return Err("capture root noncanonical base64".into());}
        roots.add(CertificateDer::from(der)).map_err(|_|"capture root is not a valid trust anchor")?;
    }
    let mut configuration=ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13,&rustls::version::TLS12])
        .with_root_certificates(roots).with_no_client_auth();
    configuration.alpn_protocols=vec![b"http/1.1".to_vec()];
    configuration.enable_early_data=false;
    configuration.resumption=rustls::client::Resumption::disabled();
    Ok(Arc::new(configuration))
}

fn require(ok:bool)->Result<(),String> {
    if ok {Ok(())} else {Err("native target dispatch original binding changed".into())}
}
fn epoch_ns()->Result<u64,String> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|"capture epoch clock")?.as_nanos()
        .try_into().map_err(|_|"capture epoch overflow".into())
}
fn now()->Result<u64,String> {
    serverware_decision_gate::native_secret_broker_v1::now()
}

/// Not deserializable, not Clone and not constructible from a lease DTO.
/// The guard prevents a new dispatch mutation/barrier while this one actual
/// admitted send is in progress. It does not undo an already dispatched effect.
pub(super) struct Prepared<'a> {
    state:&'a GateState,
    authority:UpstreamSendAuthority<'a>,
    lease:CredentialLeaseReleaseBinding,
    original:wire::DispatchOriginal,
    request:Zeroizing<Vec<u8>>,
    method:String,
    statement:wire::NativeStatement,
    deadline:u64,
    response_guard:ResponseSecretGuard,
}

impl<'a> Prepared<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn open(state:&'a GateState,snapshot:&Arc<Snapshot>,decision:&Value,
        request:&IncomingRequest,url:&Url,headers:&BTreeMap<String,String>,injection:&Value,
        binding:V2OperationBinding,stable_resume_id:&str,
        staged_request:RawObjectReference,
        staged_bytes:&[u8],session:&ResponseObservationV2Session<'_>,
        shadow:Option<&policy_core::ShadowRequestHandle>)->Result<Self,String> {
        let lifetime=state.native_runtime_lifetime.as_ref().ok_or("capture lacks actual native lifetime")?;
        lifetime.check()?;
        require(state.native_secret_broker.is_some() && state.credential_currentness.enabled()
            && state.upstream_client_config.native_capture_tls.is_some()
            && session.client.guest_listener.is_some())?;
        let ResponseProofSigner::Custody(signer)=&state.response_proof_signer else {return Err("capture native signer absent".into());};
        signer.transport.require_native()?;
        let route=snapshot.routes.iter().find(|route|route.id==binding.transaction.route_id)
            .ok_or("capture actual route absent")?;
        require(route.scheme=="https" && url.scheme()=="https" && url.host_str()==Some(route.host.as_str())
            && url.port_or_known_default()==Some(route.port)
            && binding.custody_boot_id==session.client.boot_id
            && binding.client_identity_sha256==session.client.authenticated_client_identity_sha256
            && binding.monotonic_deadline==session.monotonic_deadline
            && binding.deadline_at_epoch_ms==session.deadline_at_epoch_ms
            && binding.transaction.policy_sha256==snapshot.hash
            && decision.get("principal_id").and_then(Value::as_str)==Some(binding.transaction.principal_id.as_str())
            && decision.get("route_id").and_then(Value::as_str)==Some(route.id.as_str())
            && staged_request.generation_id.0==session.client.generation_id
            && staged_request.object_kind.0=="staged-request"
            && profile::sha256(staged_bytes)==staged_request.content_sha256.0
            && staged_bytes.len() as u64==staged_request.content_length)?;
        let deadline=binding.monotonic_deadline.absolute_boottime_ns.parse::<u64>().map_err(|_|"capture deadline invalid")?;
        require(deadline>now()? && deadline<=lifetime.deadline())?;
        let credential=decision.get("credential_ref").and_then(Value::as_str).ok_or("capture credential absent")?;
        let version=decision.get("credential_version").and_then(Value::as_u64).filter(|v|*v>0).ok_or("capture version absent")?;
        require(binding.transaction.credential_binding_sha256.as_deref()==Some(digest_json(&json!({
            "credentialId":credential,"credentialGeneration":version,"injectionPlanSha256":digest_json(injection)})).as_str()))?;
        let lease=credential_lease_for_release(state,snapshot,decision,credential,version).map_err(str::to_owned)?;
        let held=credential_lease_release_binding(&lease);
        let mut exact_headers=HeaderMap::new();
        for (name,value) in headers {
            let name=HeaderName::from_bytes(name.as_bytes()).map_err(|_|"capture original header name")?;
            let value=HeaderValue::from_str(value).map_err(|_|"capture original header value")?;
            if exact_headers.insert(name,value).is_some() {return Err("capture original header repeats after normalization".into());}
        }
        let mut provider=TransientProviderRequest::new(exact_headers,url.clone());
        let (final_headers,final_url)=provider.injection_parts();
        let response_guard=apply_bound_credential_injection(snapshot,decision,final_headers,url,final_url,injection,&lease,shadow)?;
        let final_request=serialize_request(request,final_url,final_headers)?;
        let relays=state.native_upstream_relays.as_ref().ok_or("capture fixed relay owner absent")?;
        let addresses=relays.resolved_addresses(&route.host,route.port)?;
        let addresses=validate_resolved_addresses(addresses.into_iter().map(|ip|SocketAddr::new(ip,route.port)).collect(),
            route.port,&route.resolved_address_policy).map_err(|_|"capture route address policy refused")?;
        let address=addresses.first().ok_or("capture fixed relay set is empty")?.ip().to_string();
        let original=wire::DispatchOriginal {api_version:wire::ORIGINAL.to_owned(),
            generation_id:session.client.generation_id.clone(),generation:session.client.provider_generation,
            stable_resume_id:stable_resume_id.to_owned(),binding,
            session_sha256:session.hello_attestation.authenticated_session_sha256.clone(),
            staged_request,target:wire::Target {scheme:"https".to_owned(),host:route.host.clone(),port:route.port,address},
            request_sha256:profile::sha256(&final_request),gate_key_id:signer.key_id.clone()};
        let authority=acquire_upstream_send_authority(state,snapshot,Some(&held)).map_err(str::to_owned)?;
        let transport_started=now()?;
        let lease_remaining=credential_lease_send_timeout(authority.lease_deadline).map_err(str::to_owned)?
            .ok_or("capture lacks an actual credential expiration owner")?;
        let issued=epoch_ns()?;
        let expires=original.binding.deadline_at_epoch_ms.checked_mul(1_000_000).ok_or("capture epoch deadline overflow")?
            .min(issued.checked_add(30_000_000_000).ok_or("capture window overflow")?)
            .min(u64::try_from(lease.expires_at_epoch_ms).map_err(|_|"capture lease epoch overflow")?
                .checked_mul(1_000_000).ok_or("capture lease epoch overflow")?);
        let statement=wire::NativeStatement {api_version:wire::NATIVE_STATEMENT.to_owned(),phase:"prepare".to_owned(),
            original:original.clone(),permit_sha256:None,raw_response:None,tls:None,
            boot_id:signer.boot_id.clone(),key_id:signer.key_id.clone(),
            control_plane_response_signing_key_id:signer.control_plane_response_signing_key_id.clone(),
            issued_at_epoch_ns:issued,expires_at_epoch_ns:expires};
        let epoch_remaining=expires.checked_sub(issued).filter(|n|*n>0).ok_or("capture allowance already expired")?;
        let private_budget=epoch_remaining.min(u64::try_from(lease_remaining.as_nanos()).map_err(|_|"capture lease duration overflow")?);
        // This private transport cutoff only narrows the original wire
        // allowance. Sampling BOOTTIME before the remaining-budget reads makes
        // the conversion conservative; it is never renewed by an I/O call.
        let deadline=deadline.min(transport_started.checked_add(private_budget).ok_or("capture transport cutoff overflow")?);
        let prepared=Self {state,authority,lease:held,original,request:final_request,method:request.method.clone(),statement,deadline,response_guard};
        prepared.check()?;
        Ok(prepared)
    }

    pub(super) fn check(&self)->Result<(),String> {
        self.state.native_runtime_lifetime.as_ref().ok_or("capture lifetime disappeared")?.check()?;
        native_secret_broker::check(self.state)?;
        self.state.credential_currentness.require_send(&self.lease.scope.credential_id,self.lease.version)?;
        credential_lease_send_timeout(self.authority.lease_deadline).map_err(str::to_owned)?;
        require(now()?<self.deadline && epoch_ns()?<self.statement.expires_at_epoch_ns && policy_trust_is_fresh(self.state)
            && self.authority._snapshot.hash==self.original.binding.transaction.policy_sha256
            && profile::sha256(&self.request)==self.original.request_sha256)?;
        profile::validate_statement(&self.statement,epoch_ns()?)
    }
    // Called with the identity lock held. The full broker/currentness check
    // brackets that lock in evidence(); never invert broker -> identity order.
    pub(super) fn statement(&self)->Result<&wire::NativeStatement,String> {
        require(now()?<self.deadline && epoch_ns()?<self.statement.expires_at_epoch_ns)?;
        profile::validate_statement(&self.statement,epoch_ns()?)?;Ok(&self.statement)
    }
    pub(super) fn request_sha256(&self)->&str {&self.original.request_sha256}
    pub(super) fn evidence(&self)->Result<wire::NativeCaptureEnvelope,String> {
        self.check()?;
        let ResponseProofSigner::Custody(signer)=&self.state.response_proof_signer else {return Err("capture signer disappeared".into());};
        let result={
            let mut identity=self.state.mitm_authority.as_ref().ok_or("capture actual identity absent")?.lock()
                .map_err(|_|"capture identity poisoned")?;
            let MitmAuthority::Native(identity)=&mut *identity else {return Err("capture identity is not native".into());};
            signer.transport.target_dispatch_evidence(identity,self,self.deadline)?
        };
        self.check()?;
        Ok(result)
    }
    pub(super) fn begin_original(&self)->Result<wire::BeginRequest,String> {
        Ok(wire::BeginRequest {api_version:"serverware.responseV2.targetDispatchBegin/v1".into(),
            original:self.original.clone(),gate_evidence:self.evidence()?})
    }
}

fn serialize_request(request:&IncomingRequest,url:&Url,headers:&HeaderMap)->Result<Zeroizing<Vec<u8>>,String> {
    require(!request.method.is_empty() && request.method.bytes().all(|b|b.is_ascii_uppercase())
        && url.username().is_empty() && url.password().is_none() && url.fragment().is_none())?;
    let mut target=Zeroizing::new(url.path().to_owned());
    if let Some(query)=url.query() {target.push('?');target.push_str(query);}
    require(target.starts_with('/') && !target.bytes().any(|b|b.is_ascii_control() || b==b' '))?;
    let mut selected=BTreeMap::new();
    for (name,value) in headers {
        let name=name.as_str();
        require(!name.starts_with(SERVERWARE_INTERNAL_HEADER_PREFIX)
            && !matches!(name,"proxy-authorization"|"cookie"|"set-cookie"|"transfer-encoding"|"upgrade"|"connection"|"host"|"content-length"))?;
        let value=value.to_str().map_err(|_|"capture header encoding")?;
        require(!value.bytes().any(|b|matches!(b,b'\r'|b'\n'|0)) && !selected.contains_key(name))?;
        selected.insert(name,Zeroizing::new(value.to_owned()));
    }
    let host=url.host_str().ok_or("capture host absent")?;
    let host=if host.contains(':') {format!("[{host}]")} else {host.to_owned()};
    let host=match url.port() {Some(port)=>format!("{host}:{port}"),None=>host};
    let mut output=Zeroizing::new(Vec::new());
    write!(&mut *output,"{} {} HTTP/1.1\r\nhost: {}\r\ncontent-length: {}\r\nconnection: close\r\n",
        request.method,target.as_str(),host,request.body.len()).map_err(|_|"capture request serialization")?;
    for (name,value) in selected {write!(&mut *output,"{name}: {}\r\n",value.as_str()).map_err(|_|"capture header serialization")?;}
    output.extend_from_slice(b"\r\n");output.extend_from_slice(&request.body);
    require(output.len() as u64<=wire::MAX_RAW_BYTES)?;
    Ok(output)
}

pub(super) struct Captured {
    pub(super) request:wire::CapturePersistRequest,
    pub(super) raw:Zeroizing<Vec<u8>>,
    pub(super) response_guard:ResponseSecretGuard,
}

impl Prepared<'_> {
    /// Consumes the source-owned preparation before any socket contact. A
    /// failure after this point is uncertain; no reconnect or replay exists.
    pub(super) fn capture(mut self,admitted:response_v2::AuthenticatedTargetDispatchReply)->Result<Captured,String> {
        self.check()?;
        let permit=admitted.into_permit();
        require(profile::canonical(&permit.original)?==profile::canonical(&self.original)?)?;
        let permit_sha=profile::sha256(&profile::canonical(&permit)?);
        let endpoint=SocketAddr::new(self.original.target.address.parse().map_err(|_|"capture target address")?,self.original.target.port);
        let relays=self.state.native_upstream_relays.as_ref().ok_or("capture relay disappeared")?;
        let socket=relays.target_dispatch_stream(&self.original.target.host,endpoint,self.deadline)?;
        let config=Arc::clone(self.state.upstream_client_config.native_capture_tls.as_ref().ok_or("capture actual roots absent")?);
        let name=ServerName::try_from(self.original.target.host.clone()).map_err(|_|"capture TLS server name")?;
        let mut connection=ClientConnection::new(config,name).map_err(|_|"capture TLS configuration")?;
        connection.set_buffer_limit(Some(64*1024));
        let mut tls=StreamOwned::new(connection,socket);
        while tls.conn.is_handshaking() {
            self.check()?;
            tls.conn.complete_io(&mut tls.sock).map_err(|_|"capture origin TLS handshake failed")?;
            self.check()?;
        }
        require(matches!(tls.conn.handshake_kind(),Some(rustls::HandshakeKind::Full|rustls::HandshakeKind::FullWithHelloRetryRequest))
            && !tls.conn.is_early_data_accepted()
            && tls.conn.alpn_protocol().is_none_or(|value|value==b"http/1.1"))?;
        let chain=tls.conn.peer_certificates().ok_or("capture authenticated peer absent")?;
        require(!chain.is_empty() && chain.len()<=8 && chain.iter().all(|c|!c.as_ref().is_empty() && c.as_ref().len()<=16*1024))?;
        let mut chain_original=Vec::new();
        for certificate in chain {chain_original.extend((certificate.as_ref().len() as u32).to_be_bytes());chain_original.extend(certificate.as_ref());}
        let exporter=Zeroizing::new(tls.conn.export_keying_material([0;32],EXPORTER,Some(permit_sha.as_bytes()))
            .map_err(|_|"capture TLS exporter unavailable")?);
        let observation=wire::TlsObservation {server_name:self.original.target.host.clone(),port:self.original.target.port,
            peer_chain_sha256:profile::sha256(&chain_original),protocol:format!("{:?}",tls.conn.protocol_version().ok_or("capture TLS version absent")?),
            cipher_suite:format!("{:?}",tls.conn.negotiated_cipher_suite().ok_or("capture cipher absent")?.suite()),
            exporter_sha256:profile::sha256(exporter.as_ref())};
        self.check()?;
        // Exactly one write of the retained application request; rustls may
        // fragment transport records, but no HTTP retry/reconstruction occurs.
        tls.write_all(&self.request).map_err(|_|"capture request send outcome unknown")?;
        tls.flush().map_err(|_|"capture request flush outcome unknown")?;
        let mut raw=Zeroizing::new(Vec::new());
        let mut buffer=Zeroizing::new([0u8;16*1024]);
        loop {
            self.check()?;
            let count=tls.read(&mut *buffer).map_err(|_|"capture response/close outcome unknown")?;
            if count==0 {break;}
            require(raw.len().checked_add(count).is_some_and(|v|v as u64<=wire::MAX_RAW_BYTES))?;
            raw.extend_from_slice(&buffer[..count]);
        }
        self.check()?;
        // A clean rustls EOF is required; truncation is never accepted as the
        // boundary of a connection-close framed response.
        response_observation_v2_parse_http11(&raw,Some(&self.method))?;
        let digest=profile::sha256(&raw);
        let descriptor=ExactByteObjectDescriptor {object_id:format!("obj:{}",&digest[7..]),
            media_type:ExactObjectMediaType::Http11Response,fd_index:0,byte_length:raw.len() as u64,sha256:digest,
            required_seals:MemfdSealProfile::ImmutableV1};
        self.statement.phase="capture".to_owned();self.statement.permit_sha256=Some(permit_sha);
        self.statement.raw_response=Some(descriptor.clone());self.statement.tls=Some(observation);
        let capture=self.evidence()?;
        let capture_sha=profile::sha256(&profile::canonical(&capture)?);
        Ok(Captured {request:wire::CapturePersistRequest {api_version:wire::PERSIST.to_owned(),
            request_id:format!("capture:{}",&capture_sha[7..]),operation_id:format!("persist:{}",&capture_sha[7..]),
            stable_resume_id:self.original.stable_resume_id.clone(),permit,capture,raw_response:descriptor},raw,response_guard:self.response_guard})
    }
}
