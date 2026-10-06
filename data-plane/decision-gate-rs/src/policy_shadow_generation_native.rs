//! Source-owned cold handoff; worker process exit is never verifier authority.
use super::*;
use serverware_decision_gate::{native_shadow_workers as workers,
    native_serving_privileges::{Prepared, Owner}, StartedGuestCohort};

pub(crate) struct PreparedNativeShadowControl {
    control: Arc<PolicyShadowGenerationControl>,
    worker: workers::Prepared,
    activation:Option<activation::Prepared>,
    lifecycle:Option<super::super::policy_shadow::PreparedNativeCustodyLifecycle>,
}

fn publication_pins(trust:&PinnedEnvelopeKeyTrust)
    ->Result<workers::publication_resources::PublicationAuthorityPins,String> {
    let key_id=trust.publication_signing_key_id.clone();
    let spki=trust.publication_signing_key_spki_sha256.clone();
    let mut opening=trust.issued_at_unix_nanos;let mut closing=trust.expires_at_unix_nanos;
    let mut public=None;
    for domain in [PUBLICATION_SIGNATURE_DOMAIN,PUBLICATION_PREPARATION_SIGNATURE_DOMAIN] {
        let key=trust.keys.get(&("fleet-shadow-runtime".into(),domain.into(),key_id.clone(),spki.clone()))
            .ok_or("publication key lacks one independently admitted signature domain")?;
        if public.is_some_and(|previous| previous!=key.verifying_key.to_bytes()) {
            return Err("publication signature domains name different admitted keys".into());
        }
        public=Some(key.verifying_key.to_bytes());
        opening=opening.max(key.not_before_unix_nanos);closing=closing.min(key.not_after_unix_nanos);
    }
    if opening>=closing {return Err("publication trust/key validity intersection is empty".into());}
    Ok(workers::publication_resources::PublicationAuthorityPins {
        key_id:key_id.as_str().into(),key_spki_sha256:spki.as_str().into(),
        replay_store_sha256:trust.publication_replay_store_sha256.as_str().into(),
        not_before_unix_nanos:opening,not_after_unix_nanos:closing,
    })
}

impl PreparedNativeShadowControl {
    pub(crate) fn open(mut config: PolicyShadowGenerationConfig, prepared: &Prepared,
        cohort: Arc<StartedGuestCohort>) -> Result<Self, String> {
        prepared.check()?;
        let selected = config.native_workers.take().ok_or("native shadow worker profile absent")?;
        let activation=config.native_activation.take().map(|value|activation::Prepared::open(value,prepared)).transpose()?;
        let commands = [&config.runtime_verifier, &config.webauthn_verifier, &config.publication_handoff]
            .map(|command| workers::Executable {
                path: command.executable.clone(), sha256: command.expected_sha256.clone(),
            });
        // These are the existing real manifest/configuration/pinned-command
        // constructors. No caller-ready token or native-custody classification.
        let control = PolicyShadowGenerationControl::from_config(true, true, config)?;
        let lifecycle=super::super::policy_shadow::PreparedNativeCustodyLifecycle::open(
            control.custody_config.retained_file()?,control.custody_config.content_sha256(),prepared)?;
        let worker = if selected.publication_resources() {
            let pins=publication_pins(control.key_trust.as_ref())?;
            workers::Prepared::launch_with_publication(selected,commands,prepared,cohort,pins)?
        } else {
            workers::Prepared::launch(selected, commands, prepared, cohort)?
        };
        prepared.check()?;
        Ok(Self {control, worker,activation,lifecycle})
    }

    pub(crate) fn bind(mut self, serving: Arc<Owner>)
        -> Result<(Arc<PolicyShadowGenerationControl>, Arc<workers::Owner>), String> {
        let worker = self.worker.bind(Arc::clone(&serving))?;
        let activation=self.activation.map(|value|value.bind(Arc::clone(&serving))).transpose()?;
        let lifecycle=self.lifecycle.map(|value|value.bind(serving)).transpose()?;
        let control = Arc::get_mut(&mut self.control)
            .ok_or("native shadow control published before permanent serving bind")?;
        if control.native_workers.is_some() { return Err("native shadow worker already bound".into()); }
        control.native_workers = Some(Arc::clone(&worker));
        if control.native_custody_lifecycle.is_some(){return Err("native custody lifecycle already bound".into());}
        control.native_custody_lifecycle=lifecycle;
        *control.native_activation.get_mut().map_err(|_|"native activation startup mutex poisoned")?=activation;
        Ok((self.control, worker))
    }
}

pub(super) fn run_command(owner: Option<&Arc<workers::Owner>>, purpose: workers::Purpose,
    command: &PinnedVerifierCommand, request: &Value, label: &str, maximum: usize)
    -> Result<Value, String> {
    match owner {
        Some(owner) => {
            let bytes = zeroize::Zeroizing::new(owner.execute(purpose, request)?);
            if bytes.is_empty() || bytes.len() > maximum {
                return Err("native shadow command output exceeds its original purpose bound".into());
            }
            // Keep existing strict JSON semantics, including noncanonical
            // whitespace. Signed envelopes below remain the sole authority.
            let value = super::super::strict_json_value_from_slice(&bytes)
                .map_err(|_| "native shadow command output is not strict JSON")?;
            owner.check()?;
            Ok(value)
        }
        None => run_pinned_bounded_json_command_with_output_limit(command, request, label, maximum),
    }
}
