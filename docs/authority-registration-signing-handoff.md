# Registration source-to-signer handoff

Source-only `.125` implementation; unbuilt and unexecuted. The independent
registration signer now has a fixed continuation that consumes the four
original source-exchange byte strings. This closes the source-proof composition,
not the authenticated enrollment handoff or public registration workflow.

```text
implemented source branch:
  original signed request/context + signed response/source
  -> actual configured control authentication + membership/query/cutoff replay
                                                        \
                                                         -> genuine evidence signer
                                                        /
unfinished enrollment branch:
  actual authenticated actor/session + original browser binding
  -> enrollment issuer OR independent signer admission (decision pending)
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
Prior publication signature/commit provenance and genuine enrollment admission
remain owner responsibilities.

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

## Open enrollment trust decision

The current operator and OIDC finish handlers admit actor/session identity
locally. Their existing original-input capture does not export a signer-verifiable
enrollment grant binding that admission to the browser originals. The public
paths still use their existing legacy continuation; this private composition
does not redirect them.

Two alternatives remain under consideration: a dedicated control-plane
enrollment-authorization handoff, or independent user/session validation by the
signer. Neither is selected by this implementation. An authenticated Unix peer
identifies a process, not the current operator or browser session. Likewise,
source-read signatures and stored challenge authorization cannot by themselves
supply the missing current actor/session handoff.

The generic HTTP response-signing key is not reused or implicitly granted an
enrollment purpose. No secret fallback, new issuer provisioning, public route,
credential mutation, custody write or execution authority is introduced. The
chosen enrollment contract must precede public end-to-end integration.

See [the signed source exchange](authority-registration-source-exchange.md) and
[original-evidence signing](authority-original-evidence-signing.md).
