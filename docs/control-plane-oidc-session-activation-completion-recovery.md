# Public earlier-stage completion recovery

The explicit completion-recovery coordinator connects fresh actor authorization,
historical public-control admission, a separate durable attempt, one configured
completion-only exchange and genuine response admission. Its successful result
means only that signed historical completion controls were reconciled. It never
repeats SQL, releases a token, changes a cookie or declares a session active.

## Explicit routes

All four routes are POSTs using the existing closed 64 KiB
`serverware.oidcSessionActivationRecoveryRequest/v1` carrier. An options request
contains only schema, purpose and local digest; the action additionally allows
the existing MFA object. There is no browser-selected profile, packet, target,
pending state, root grant or signed control.

| Action | Route |
| --- | --- |
| Activation completion options | `/api/auth/session/activation/completion/recovery/options` |
| Activation completion recovery | `/api/auth/session/activation/completion/recovery` |
| Consume completion options | `/api/auth/session/activation/consume/completion/recovery/options` |
| Consume completion recovery | `/api/auth/session/activation/consume/completion/recovery` |

Each route chooses a literal source profile. The existing strict framing rejects
ambiguous lengths, oversized chunks, encoded bodies, non-JSON content types and
query strings before accumulation. Both middleware branches recognize these
paths: CSRF uses exact old-cookie possession checks, not generic current-session
authentication. The actual actor still requires the configured origin, old-token
possession, genuine retained target, current roles/trust, fresh target-bound
WebAuthn and configured independent approval.

One original processing window and cumulative work ledger are opened before
parsing and owner work. Options return only a challenge. The action invokes the
actual enrollment owner's corresponding private facade on the same ASGI thread.
The processing allowance is never reopened or widened to accommodate history.

## Original controls and irreversible attempts

The [historical controls helper](control-plane-oidc-session-activation-completion-recovery-controls.md)
loads the exact indexed originals and requires the original SQL-attempt claim.
It genuinely authenticates the historical caller, grant, reservation, signed
snapshot and state acknowledgment against independent parent-v16 pins. Consume
also requires its original exported ciphertext; prepared metadata alone cannot
establish its signed commitments. This is public control admission, not private
AES/history replay or proof from an unsigned SQL result.

```text
fresh actor + exact historical controls
  -> inspect separate target/phase recovery slot
     -> absent: durable claim -> one completion-only socket -> retain raw reply
     -> present: use stored reply only; never another socket
  -> genuine historical completion + state ACK admission
  -> normal actor/trust/startup cleanup
  -> token-free historical reconciliation response
```

The fixed slot is keyed by the finalization target and activation/consume phase,
not a changeable configuration. Its metadata binds the exact authorization,
packet, independently configured endpoint/pending scope digest and original
completion-outcome association. A new actor or configuration cannot obtain a
second socket by changing those pins. Claim, response and readback use bounded
guarded native I/O; any ambiguous publication remains terminal, not retryable.

The raw4 activation or raw6 consume response is stored in a separate immutable
namespace before its status or signatures are interpreted. It never overwrites
an original uncertain response. Storage is only data: a newly returned or reused
reply must pass the [genuine historical response verifier](control-plane-oidc-session-activation-completion-recovery-exchange.md)
inside the fresh actor. Missing or uncertain stored replies do not allow resend.
Existing acknowledged originals must remain byte-identical. Unsigned consume
hints do not become release or packet authority.

The coordinator reserves fixed transport, verification, publication and reload
headroom before the first historical control-bundle body read, within the
unchanged 64 MiB representation ceiling. These are not measured heap/RSS bounds.
The genuine receiving guard remains a separate child through normal trust
cleanup, avoiding an actor/receiver recursion. HTTP success is possible only
after normal actor and startup-lock cleanup; no permission object or private
response original crosses that boundary.

## Truthful response and remaining work

`completion-controls-reconciled` reports a historical fact only. Action responses
keep `sessionState: unknown`, `tokenReleased: false` and
`automaticRetryAllowed: false`. Errors expose fixed bounded data, never exception
messages or private controls. Failures after actor admission are conservatively
unknown, even if this call never reached a socket. No response changes a cookie.

This path does not synthesize a missing release intent, resume an unattempted
consume operation or connect the portal. Returning the new session token still
requires its independently authorized intent/proof/release flow. Missing
originals remain unavailable, not nonexecution or authority to repeat SQL.
The separate post-intent token-recovery route is unchanged. Full recovery and
portal integration, deployment and independent production acceptance must not
be inferred from this completion-only connection. Source only: no build, test,
runtime or provisioning evidence is claimed.

The separate [fresh intent/proof action](control-plane-oidc-session-activation-completion-recovery-release.md)
now continues acknowledged consume originals under a distinct WebAuthn binding,
without repeating completion. It retains and genuinely admits intent/proof data;
it still needs independently selected release authority. Missing local intent or a reconstructed outcome
does not establish whether a private outcome exists. A first-release/checkpoint-zero
path and a retained-outcome/checkpoint-one recovery path require their respective
independent root authority; neither can be inferred from local absence. The
original delivery expiry remains a hard bound, not a timestamp to regenerate.
