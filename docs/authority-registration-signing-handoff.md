# Registration source-to-signer handoff

Source-only `.126` implementation; unbuilt and unexecuted. The independent
registration signer consumes the four original source-exchange byte strings
and a dedicated signed enrollment grant. It durably consumes one grant attempt
before evidence signing. Public enrollment orchestration is still unfinished.

```text
implemented source branch:
  original signed request/context + signed response/source
  -> actual configured control authentication + membership/query/cutoff replay
                                                        \
                                                         -> durable one-attempt marker
                                                         -> genuine evidence signer
                                                        /
implemented private grant branch (public caller not yet connected):
  dedicated configured issuer + original browser/user/session commitments
  -> signed enrollment grant -> genuine configured grant verification
```

## Original source bytes, not a successful-proof object

`authority_webauthn_registration_source_admission._verify_on_configuration`
receives original request control, request context, response control and source
bytes, plus independently admitted configuration, generation and runtime
identities. It authenticates both controls with their configured role keys
before decoding the returned source observations, then genuinely replays the
primary memberships, query associations and database-cutoff constraints on the
same work allowance.

The dedicated
`authority_webauthn_registration_exchange_signing._produce_on_configuration`
continuation
invokes that admission itself. Selectors and roots come from the authenticated
original source exchange, not separate caller-selected substitutes. The
admission result is ordinary same-call data: the signer does not accept a
caller-supplied successful exchange or row-proof object.

The actual registration producer still derives ceremony scope and complete
stored trust context, verifies the original browser attestation, signs with the
explicit registration-purpose evidence key and assembles the typed request and
original inputs. The verifier/planner source-control keys are not substitutes
for that independent evidence key or its admitted configuration and identity.
Prior publication signature/commit provenance remains an owner responsibility.
Enrollment admission now uses the original dedicated control-plane grant, not
separate caller-supplied user/label/authorization values. Original browser/time
bindings and authenticated source selectors must match that verified grant.

The return remains four ordinary values: the signed evidence envelope,
finalization arguments, typed evidence-admission request and original-input
bytes. No signature token replaces replay of the original exchange.

## Distinct lifetimes

Source controls retain their original live request interval through admission
and signing; expired source controls are not historical signing permission.
The evidence envelope separately uses the configured evidence-purpose lifetime
and original verification time; its expiry is not clipped to the source-control
expiry. The supplied UTC verification time stays unchanged and must match the
authenticated request issuance and database cutoff within configured skew,
precede the original expiry/deadline, and pass the current-window check. These
are different contracts, not interchangeable deadlines. No timestamp is
rewritten to reopen either interval, and a source signature does not create
independent clock authority.

## Accepted enrollment trust decision

The user selected [dedicated control-plane enrollment authorization](enrollment-authorization-decision.md).
The new closed policy, configured issuer and signed-original verifier implement
that private handoff. This trusts the issuer's actual user/session admission;
the independent signer still verifies the grant, browser bindings, source
proofs and attestation. Generic HTTP response and source-role keys are not
enrollment keys.

The concrete replay store publishes and syncs an immutable attempt marker before
evidence signing. Identical retries, reset and automatic expiry cleanup are not
allowed; uncertain I/O fails closed. Its local storage/locks are not independent
anti-rollback authority. Production continuity and capacity management remain
required, as do protected issuer key delivery and authenticated service wiring.

The existing operator and OIDC finish handlers still use their legacy
continuation. This private composition does not redirect those routes, consume
options-time approval again, or authorize successor business execution.

See [the signed source exchange](authority-registration-source-exchange.md) and
[original-evidence signing](authority-original-evidence-signing.md).
