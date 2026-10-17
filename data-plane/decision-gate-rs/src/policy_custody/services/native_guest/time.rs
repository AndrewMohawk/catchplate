//! Actual pre-key NSM challenge/sample exchange. Public bytes over an untrusted
//! relay; only the independently pinned issuer signature admits a time range.
use super::*;
use ed25519_dalek::{Signer,SigningKey};
use catchplate_decision_gate::enclave_runtime_identity_v1::ShadowTimeNsmV1;
use catchplate_decision_gate::enclave_vsock_v1::VsockStreamV1;
use std::io::{Read,Write};
use zeroize::Zeroizing;

const CHALLENGE_DOMAIN:&str="catchplate.nativeShadowGuestTimeChallenge.signature/v1";
const SAMPLE_DOMAIN:&str="catchplate.nativeShadowGuestTimeSample.signature/v1";
const ANCHOR_DOMAIN:&str="catchplate.nativeShadowGuestTimeAnchor.signature/v2";
const MAXIMUM:usize=65536;
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Bootstrap {api_version:String,guest:GuestClosureBinding,signing_key_id:Sha256Digest,parent_port:u32,
    maximum_bracket_nanos:String,timestamp_error_nanos:i64,maximum_clock_rate_error_ppm:u32}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct ChallengePayload {api_version:String,purpose:String,guest:GuestClosureBinding,nonce_base64url:String,
    issued_at_unix_nanos:i64,expires_at_unix_nanos:i64,maximum_bracket_nanos:String,
    timestamp_error_nanos:i64,maximum_clock_rate_error_ppm:u32,signing_key_id:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Challenge {payload:ChallengePayload,signature:CanonicalEd25519Signature}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Statement {api_version:&'static str,purpose:&'static str,guest:GuestClosureBinding,
    challenge_sha256:Sha256Digest,before_boottime_ns:String,public_key_base64url:String}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Sample<'a> {statement:&'a Statement,after_boottime_ns:String,quote_sha256:Sha256Digest}
#[derive(Serialize)]
#[serde(rename_all="camelCase")]
struct Evidence<'a> {api_version:&'static str,statement:&'a Statement,after_boottime_ns:String,
    attestation_document_base64url:String,signature:CanonicalEd25519Signature}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct AnchorPayload {api_version:String,purpose:String,guest:GuestClosureBinding,
    challenge_sha256:Sha256Digest,evidence_sha256:Sha256Digest,quote_sha256:Sha256Digest,
    anchor_boottime_ns:String,earliest_unix_nanos:i64,latest_unix_nanos:i64,expires_at_unix_nanos:i64,
    maximum_clock_rate_error_ppm:u32,signing_key_id:Sha256Digest}
#[derive(Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct Anchor {payload:AnchorPayload,signature:CanonicalEd25519Signature}

fn signature<T:Serialize>(key:&VerifyingKey,domain:&str,payload:&T,sig:&CanonicalEd25519Signature)
    ->Result<(),ShadowError> {
    key.verify_strict(&signature_preimage(domain,&canonical_json_bytes(payload)?),
        &Signature::from_bytes(&sig.decode()?)).map_err(|_|ShadowError::SignatureInvalid)
}
fn receive(stream:&mut VsockStreamV1,tag:&[u8;8])->Result<Vec<u8>,ShadowError> {
    let mut header=[0;12];stream.read_exact(&mut header).map_err(fail)?;
    let count=u32::from_be_bytes(header[8..].try_into().map_err(fail)?) as usize;
    require(&header[..8]==tag && count>0 && count<=MAXIMUM)?;
    let mut raw=vec![0;count];stream.read_exact(&mut raw).map_err(fail)?;Ok(raw)
}
fn send(stream:&mut VsockStreamV1,tag:&[u8;8],raw:&[u8])->Result<(),ShadowError> {
    require(!raw.is_empty() && raw.len()<=MAXIMUM)?;
    stream.write_all(tag).map_err(fail)?;
    stream.write_all(&(raw.len() as u32).to_be_bytes()).map_err(fail)?;
    stream.write_all(raw).map_err(fail)
}
fn drift(elapsed:u64,ppm:u32)->Result<i64,ShadowError> {
    let value=(elapsed as u128).checked_mul(ppm as u128).ok_or(ShadowError::CounterOverflow)?;
    i64::try_from(value.checked_add(999_999).ok_or(ShadowError::CounterOverflow)?/1_000_000).map_err(fail)
}

pub(in crate::policy_shadow::policy_custody::services) struct Clock {
    original:Original,bootstrap:Bootstrap,association:GuestClosureAssociation,
    challenge:Challenge,challenge_original:Vec<u8>,evidence_original:Vec<u8>,anchor:Anchor,anchor_original:Vec<u8>,
    before:u64,last:AtomicU64,
}
impl Clock {
    /// The only constructor consumes a genuine root-prepared C9 association
    /// and performs the fixed exchange itself. No epoch or verified DTO input.
    pub(super) fn acquire(original:Original,association:GuestClosureAssociation,key:&VerifyingKey,
        key_id:&Sha256Digest,prekey:&PrekeyExecutable)->Result<Self,ShadowError> {
        association.check_preparation().map_err(fail)?;
        let nsm=ShadowTimeNsmV1::open(association.startup()).map_err(fail)?;
        Self::acquire_owned(original,association,key,key_id,prekey,nsm)
    }
    pub(super) fn acquire_late(original:Original,association:GuestClosureAssociation,key:&VerifyingKey,
        key_id:&Sha256Digest,prekey:&PrekeyExecutable,prepared:catchplate_decision_gate::enclave_runtime_identity_v1::PreparedShadowTimeNsmV1)
        ->Result<Self,ShadowError> {
        association.check_native_preparation().map_err(fail)?;
        require(association.owner.native_continuation.is_some())?;
        Self::acquire_owned(original,association,key,key_id,prekey,prepared.consume().map_err(fail)?)
    }
    fn acquire_owned(original:Original,association:GuestClosureAssociation,key:&VerifyingKey,
        key_id:&Sha256Digest,prekey:&PrekeyExecutable,mut nsm:ShadowTimeNsmV1)->Result<Self,ShadowError> {
        association.check_native_preparation().map_err(fail)?;
        prekey.check()?;
        let bootstrap:Bootstrap=exact(&original.read(MAXIMUM).map_err(fail)?)?;
        let maximum_bracket=decimal(&bootstrap.maximum_bracket_nanos)?;
        require(bootstrap.api_version=="catchplate.nativeShadowGuestTimeBootstrap/v1"
            && bootstrap.guest==association.binding() && &bootstrap.signing_key_id==key_id
            && bootstrap.parent_port>1023 && bootstrap.parent_port<u32::MAX
            && maximum_bracket<=1_000_000_000 && (0..=1_000_000_000).contains(&bootstrap.timestamp_error_nanos)
            && bootstrap.maximum_clock_rate_error_ppm<=10_000)?;
        let deadline=association.startup();
        let mut stream=VsockStreamV1::connect_parent(bootstrap.parent_port,deadline).map_err(fail)?;
        let received=(|| {
            association.check_native_preparation().map_err(fail)?;stream.verify_connected_original(deadline).map_err(fail)?;
            let challenge_original=receive(&mut stream,b"SWNGTC1\0")?;
            let challenge:Challenge=exact(&challenge_original)?;let p=&challenge.payload;
            require(p.api_version=="catchplate.nativeShadowGuestTimeChallenge/v1"
                && p.purpose=="native-shadow-guest-time-challenge" && p.guest==bootstrap.guest
                && p.signing_key_id==bootstrap.signing_key_id && p.maximum_bracket_nanos==bootstrap.maximum_bracket_nanos
                && p.timestamp_error_nanos==bootstrap.timestamp_error_nanos
                && p.maximum_clock_rate_error_ppm==bootstrap.maximum_clock_rate_error_ppm
                && p.issued_at_unix_nanos>0 && p.expires_at_unix_nanos>p.issued_at_unix_nanos
                && p.expires_at_unix_nanos.checked_sub(p.issued_at_unix_nanos).is_some_and(|v|v<=30_000_000_000))?;
            signature(key,CHALLENGE_DOMAIN,p,&challenge.signature)?;
            let nonce=URL_SAFE_NO_PAD.decode(&p.nonce_base64url).map_err(fail)?;
            require(nonce.len()==32 && nonce.iter().any(|v|*v!=0) && URL_SAFE_NO_PAD.encode(&nonce)==p.nonce_base64url)?;
            // No private key is imported or exported. This ephemeral key can
            // sign only this one measured bracket and is dropped immediately.
            let mut seed=Zeroizing::new([0u8;32]);let mut offset=0;
            while offset<seed.len() {
                association.check_native_preparation().map_err(fail)?;
                let count=unsafe{libc::getrandom(seed[offset..].as_mut_ptr().cast(),seed.len()-offset,0)};
                if count<0 && std::io::Error::last_os_error().raw_os_error()==Some(libc::EINTR) {continue;}
                require(count>0 && count as usize<=seed.len()-offset)?;offset+=count as usize;
            }
            let signing=SigningKey::from_bytes(&seed);
            let public=signing.verifying_key().to_bytes();drop(seed);
            association.check_native_preparation().map_err(fail)?;prekey.check()?;
            let before=now()?;
            let statement=Statement{api_version:"catchplate.nativeShadowGuestTimeStatement/v1",
                purpose:"native-shadow-guest-time-sample",guest:association.binding(),
                challenge_sha256:Sha256Digest::compute(&challenge_original),before_boottime_ns:before.to_string(),
                public_key_base64url:URL_SAFE_NO_PAD.encode(public)};
            let document=nsm.quote(Sha256Digest::compute(&canonical_json_bytes(&statement)?).raw_bytes()?,public,
                nonce.try_into().map_err(fail)?).map_err(fail)?;
            let after=now()?;
            require(after>before && after-before<=maximum_bracket)?;
            association.check_native_preparation().map_err(fail)?;prekey.check()?;
            let quote_sha256=Sha256Digest::compute(&document);
            let sample=Sample{statement:&statement,after_boottime_ns:after.to_string(),quote_sha256:quote_sha256.clone()};
            let signed=signing.sign(&signature_preimage(SAMPLE_DOMAIN,&canonical_json_bytes(&sample)?));drop(signing);
            let evidence=Evidence{api_version:"catchplate.nativeShadowGuestTimeEvidence/v1",statement:&statement,
                after_boottime_ns:after.to_string(),attestation_document_base64url:URL_SAFE_NO_PAD.encode(&document),
                signature:CanonicalEd25519Signature(URL_SAFE_NO_PAD.encode(signed.to_bytes()))};
            let evidence_original=canonical_json_bytes(&evidence)?;
            send(&mut stream,b"SWNGTE1\0",&evidence_original)?;
            // The genuine parent relay stops on either half's EOF. Length
            // framing ends the request; never half-close before the anchor.
            let anchor_original=receive(&mut stream,b"SWNGTA2\0")?;
            let mut extra=[0;1];require(stream.read(&mut extra).map_err(fail)?==0)?;
            let anchor:Anchor=exact(&anchor_original)?;let a=&anchor.payload;
            signature(key,ANCHOR_DOMAIN,a,&anchor.signature)?;
            let tolerance=1_000_000i64.checked_add(bootstrap.timestamp_error_nanos)
                .and_then(|v|v.checked_add(drift(after-before,bootstrap.maximum_clock_rate_error_ppm).ok()?))
                .ok_or(ShadowError::CounterOverflow)?;
            let maximum_width=i64::try_from(after-before).map_err(fail)?.checked_add(tolerance.checked_mul(2)
                .ok_or(ShadowError::CounterOverflow)?).ok_or(ShadowError::CounterOverflow)?;
            require(a.api_version=="catchplate.nativeShadowGuestTimeAnchor/v2" && a.purpose=="native-shadow-guest-trusted-time"
                && a.guest==bootstrap.guest && a.signing_key_id==bootstrap.signing_key_id
                && a.challenge_sha256==statement.challenge_sha256 && a.evidence_sha256==Sha256Digest::compute(&evidence_original)
                && a.quote_sha256==quote_sha256 && a.anchor_boottime_ns==before.to_string()
                && a.maximum_clock_rate_error_ppm==bootstrap.maximum_clock_rate_error_ppm
                && a.earliest_unix_nanos>0 && a.latest_unix_nanos>=a.earliest_unix_nanos
                && a.latest_unix_nanos.checked_sub(a.earliest_unix_nanos)==Some(maximum_width)
                && a.expires_at_unix_nanos>a.latest_unix_nanos
                && a.expires_at_unix_nanos.checked_sub(a.earliest_unix_nanos).is_some_and(|v|v<=300_000_000_000))?;
            association.check_native_preparation().map_err(fail)?;prekey.check()?;
            Ok((challenge,challenge_original,evidence_original,anchor,anchor_original,before))
        })();
        let closed=stream.shutdown().map_err(fail);
        let (challenge,challenge_original,evidence_original,anchor,anchor_original,before)=received?;closed?;
        let owner=Self{original,bootstrap,association,challenge,challenge_original,evidence_original,anchor,anchor_original,
            before,last:AtomicU64::new(before)};
        // Bootstrap has no trusted epoch beforehand. Only now can both ends
        // of the authenticated interval be checked against challenge validity.
        validate_trusted_freshness(owner.challenge.payload.issued_at_unix_nanos,
            owner.challenge.payload.expires_at_unix_nanos,&owner,30_000_000_000)?;
        Ok(owner)
    }
    fn sampled_interval(&self)->Result<(u64,i64,i64),ShadowError> {
        self.association.owner.check_originals().map_err(fail)?;
        require(canonical_json_bytes(&self.bootstrap)?.as_slice()==self.original.read(MAXIMUM).map_err(fail)?.as_slice()
            && canonical_json_bytes(&self.challenge)?==self.challenge_original
            && canonical_json_bytes(&self.anchor)?==self.anchor_original
            && Sha256Digest::compute(&self.evidence_original)==self.anchor.payload.evidence_sha256)?;
        let now=now()?;
        require(now>=self.before && now<self.association.lifetime())?;
        let previous=self.last.fetch_max(now,Ordering::AcqRel);require(now>=previous)?;
        let elapsed=now-self.before;
        let widening=drift(elapsed,self.anchor.payload.maximum_clock_rate_error_ppm)?;
        let elapsed=i64::try_from(elapsed).map_err(fail)?;let a=&self.anchor.payload;
        let earliest=a.earliest_unix_nanos.checked_add(elapsed).and_then(|v|v.checked_sub(widening))
            .ok_or(ShadowError::CounterOverflow)?;
        let latest=a.latest_unix_nanos.checked_add(elapsed).and_then(|v|v.checked_add(widening))
            .ok_or(ShadowError::CounterOverflow)?;
        require(earliest>0 && earliest<=latest && latest<a.expires_at_unix_nanos)?;
        Ok((now,earliest,latest))
    }
    pub(in crate::policy_shadow::policy_custody::services) fn proof_sample(&self,
        association:&GuestClosureAssociation,assignment:&Sha256Digest,operation:&Sha256Digest)
        ->Result<super::trusted_time_sample::Sample,ShadowError> {
        require(self.association.same_origin(association))?;
        association.check().map_err(fail)?;
        let (sampled,earliest,latest)=self.sampled_interval()?;
        let binding=association.binding();
        Ok(super::trusted_time_sample::Sample {
            api_version:"catchplate.nativeShadowTrustedTimeSample/v1".into(),purpose:"native-shadow-trusted-time-sample".into(),
            assignment_payload_sha256:assignment.clone(),service_guest_sha256:Sha256Digest::compute(&canonical_json_bytes(&binding)?),
            clock_anchor_sha256:Sha256Digest::compute(&self.anchor_original),
            clock_bootstrap_sha256:Sha256Digest::compute(&canonical_json_bytes(&self.bootstrap)?),
            boot_id_base64url:binding.boot_id_base64url,time_namespace_device:binding.time_namespace_device,
            time_namespace_inode:binding.time_namespace_inode,sampled_at_boottime_ns:sampled.to_string(),
            earliest_unix_nanos:earliest,latest_unix_nanos:latest,
            maximum_clock_rate_error_ppm:self.anchor.payload.maximum_clock_rate_error_ppm,
            anchor_expires_at_unix_nanos:self.anchor.payload.expires_at_unix_nanos,
            lifetime_deadline_boottime_ns:association.lifetime().to_string(),operation_sha256:operation.clone(),
        })
    }
}
impl TrustedTime for Clock {
    fn now_unix_nanos(&self)->Result<i64,ShadowError> {Ok(self.sampled_interval()?.2)}
    fn now_interval_unix_nanos(&self)->Result<(i64,i64),ShadowError> {
        let (_,earliest,latest)=self.sampled_interval()?;Ok((earliest,latest))
    }
}
