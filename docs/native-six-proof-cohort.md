# Native six-child proof and commitment cohort

This explicitly selected successor connects the actual LedgerAppend CommitRequest
service to the retained parked cohort. It is source implementation, not a tested
deployment, successful key admission, or a complete pilot acceptance claim.

## Closed selection and actual ownership

`nativeShadowProofCohortConfiguration/v1` remains five children without the
cleanup protocol. Configuration `/v2` remains the same five plus independent
whole-cohort cleanup. Configuration `/v3` is exact ten fields: the prior nine,
including required cleanup, plus `commitRequestConfiguration`. All six cold C9
configurations must use distinct nonroot UIDs and GIDs. Slot order is fixed:

1. Retrieval
2. Persistence (the existing locked profile where selected)
3. TrustedTime
4. GenerationInstall
5. CommitmentBridge, `nativeProofBridgeLaunch/v2`
6. CommitRequest, `nativeShadowCommitRequestGuestLaunch/v1`

CommitRequest is the actual independently assigned LedgerAppend signing endpoint,
not another generic proof kind. Its only activation is `commit-request-listener`
at FD6. It retains the actual scoped nonexporting HMAC owner, separate from its
assigned LedgerAppend Ed25519 key. The bridge has the existing four inspected
proof sessions plus the actual signed LedgerAppend endpoint and
`commit-request-peer-directory`. Each endpoint assignment is joined to the same
retained parked peer PID/start, sealed executable identity, and independently
assigned final UID/GID before any child release. These are future assigned
credentials, not claims that a still-parked root child has completed exec/drop.

The unchanged parent entrypoint reads the independently protected configuration;
no caller list chooses endpoints. It actually precreates six children, retains
six PIDFDs and executable memfds, validates all six signed C9/image/activation
inventories and inspectors, then sends once to each original child. Partial
release cancels and reaps the entire selected cohort. No automatic resend or
success-to-readiness conversion is introduced.

## Producer and caller

`ParkedProofCohort.start()` retains the real original process cohort.
`original_bytes()` returns the actual six-child observation; `bridge_original()`
still refers to slot five, not the appended signer. `commitment_selected()` calls
the retained owner check and reports only the closed configuration selection.
The ordinary commitment launch caller must require this selection before its
existing `release_proof_cohort` hands off the actual native cohort. Its own five
ordinary serving owners must already be genuinely listening under their original
deadline. That caller supplies real retained activation owners, not a readiness
boolean or arbitrary descriptors.

`sign_precreation` and `sign_release` retain their prior keyword interfaces and
add `commit_request_configuration_raw`. It is mandatory for configuration/v3
and forbidden for v1/v2. They use an existing independently approved signing key;
they create no key or authority. Precreation keeps its existing purpose because
its exact configuration digest already fixes the selected inventory. Six-child
observations and release use `/v2`; release uses the separate
`serverware.nativeShadowProofCohortRelease.signature/v2` domain followed by NUL
and the canonical ASCII payload. Old versions reject the extra role.

`retain_activation_fds(role="commitRequest", ...)` retains the actual sixth
listener and original C9 assignment. `release(release_original=..., transfers=...)`
requires exactly the fixed six keys and consumes each real transfer once. All
wire messages remain <=32768 bytes, each role retains original FD6..69 order,
and the complete one-packet inventory remains <=128 SCM_RIGHTS. Combined overflow
is refused before release; the limit is not multiplied per role.

## Six-child cancellation and recovery

Cleanup uses distinct `/v2` authorization, terminal and result versions and
`serverware.nativeShadowProofCohortCleanup.signature/v2` framing. The existing
separate cleanup key and protected durable journal remain mandatory. A five-child
authorization or terminal is rejected for this selection. Intent is written,
fsynced and read back before signaling any child. All six are signaled before
waiting; each terminal observation comes from its retained original PIDFD and
consuming waitid. Only the complete six-child census is durably recorded.

The caller additionally matches every retained PIDFD identity and terminal state,
then observes parent status zero and reaps that same parent before releasing
activation resources. Lost response allows only same-owner, same-deadline journal
observation, not another termination/release. Partial or unknown cleanup retains
resources and is not represented as success. Startup remains <=30 seconds;
cleanup uses at most 30 seconds within the original lifetime minus the unchanged
250 ms reap reserve. No browser action or recovery renews it.

These are whole-process lifecycle observations only. Per-operation coordinator
`RequestTermination`/`Settle` remains refused; no operation settlement, mount
retirement, secret erasure, native attestation or readiness is inferred. The
separate genuine two-phase final-driver bootstrap is still required to resolve
final exec/drop identity versus pre-signed runtime ordering. This cohort does not
project a parked identity into that driver or relax any independent grant.
