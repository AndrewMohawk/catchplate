//! Source-owned cold handoff; worker process exit is never verifier authority.
use super::*;
use serverware_decision_gate::{native_shadow_workers as workers,
    native_serving_privileges::{Prepared, Owner}, StartedGuestCohort};

pub(crate) struct PreparedNativeShadowControl {
    control: Arc<PolicyShadowGenerationControl>,
    worker: workers::Prepared,
}

impl PreparedNativeShadowControl {
    pub(crate) fn open(mut config: PolicyShadowGenerationConfig, prepared: &Prepared,
        cohort: Arc<StartedGuestCohort>) -> Result<Self, String> {
        prepared.check()?;
        let selected = config.native_workers.take().ok_or("native shadow worker profile absent")?;
        let commands = [&config.runtime_verifier, &config.webauthn_verifier, &config.publication_handoff]
            .map(|command| workers::Executable {
                path: command.executable.clone(), sha256: command.expected_sha256.clone(),
            });
        // These are the existing real manifest/configuration/pinned-command
        // constructors. No caller-ready token or native-custody classification.
        let control = PolicyShadowGenerationControl::from_config(true, true, config)?;
        let worker = workers::Prepared::launch(selected, commands, prepared, cohort)?;
        prepared.check()?;
        Ok(Self {control, worker})
    }

    pub(crate) fn bind(mut self, serving: Arc<Owner>)
        -> Result<(Arc<PolicyShadowGenerationControl>, Arc<workers::Owner>), String> {
        let worker = self.worker.bind(serving)?;
        let control = Arc::get_mut(&mut self.control)
            .ok_or("native shadow control published before permanent serving bind")?;
        if control.native_workers.is_some() { return Err("native shadow worker already bound".into()); }
        control.native_workers = Some(Arc::clone(&worker));
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
