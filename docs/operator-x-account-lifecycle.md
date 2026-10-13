# Connected X accounts

This implementation belongs to the ordinary, persistent Serverware workspace;
it is not a second demo or an alternative approval authority. It is feature
gated and **not deployed or accepted against real X**. The running deployment
remains the pair recorded in [project completion](project-completion.md).

## User workflow

1. The operator configures the X OAuth application and explicitly allows the
   provider destination. Configuration alone does not grant posting access.
2. When the app and proxy report the same configuration and policy, an
   administrator starts consent and connects an X account. The callback uses
   PKCE, one-use state and a browser-bound cookie; identity is verified with X.
3. Assign an application the fixed text-post permission. It admits only the
   typed `x.post.v1` operation on `POST https://api.x.com/2/tweets`.
4. Near-expiry tokens refresh automatically through the retained X account
   owner, with the same numeric subject, client, application and rule bindings.
5. Review and disconnect the account. Local access is fenced before provider
   cleanup. This protective action remains available when proxy readiness is
   unavailable; an uncertain cleanup result never means remote revocation was
   confirmed.

This slice does **not** provide a shared daily quota, approval actions, a
host-trusted substitute for measured authority, native enrollment, or general
X API permissions. It does not adopt legacy X credentials or use Google OAuth
configuration. Public proxy DNS and real-provider consent remain separate.

## Recovery and credential boundaries

The browser retains only operation UUIDs, never authorization URLs, state,
codes or tokens. Recovery GETs inspect durable state without resubmission,
provider calls or publication repair. Uncertain work is held for inspection.
Explicit acknowledgement clears only a validated terminal operation.

Provider requests are bounded, one-shot, fixed-origin HTTPS exchanges. Claims
are persisted before contact and private response material is captured before
classification. Original deadlines are not renewed. Token expiry is anchored
conservatively before dispatch, not after delayed persistence. Cleanup material
and journal capacity are reserved before issuing further tokens, so normal
capacity exhaustion cannot disable protective local disconnect.

Generic credential, refresh, cache and injection paths refuse managed-X
markers. The dedicated lease path checks the actual application/rule/policy
before refresh, before subsequent contacts, at adoption, and in the final
credential snapshot. An expired original deadline after audit also prevents
envelope output. Google and X generation-reconciliation capabilities remain
distinct; native/currentness restrictions are unchanged.

## Verification checkpoint

The October 12 source checkpoint has 20 passing isolated SQLite/configuration/
manifest/store tests, 18 refresh/reconciliation component checks, seven lease
boundary checks using real envelope encryption, and four generic-secret
boundary checks. The UI's 15 inert-controller and 14 asset checks also passed.
These are bounded component results, not a complete posting demonstration.

The first mixed test invocation failed during environment setup (missing
scratch directory and process mode). Corrected isolated execution produced the
results above. Catalog timing passed 21 tests with exit zero. Catalog observation
completed all ten assertions, but its outer command timed out with exit 124;
that is not a clean command receipt.

Six rendered desktop/mobile browser groups passed against real assets with
intercepted synthetic APIs, including UUID-only recovery and protective
disconnect with an unavailable gate. The first browser attempt exposed an
incorrect test expectation for an intentionally disabled selector option;
the corrected check passed without a production UI change.

The first joined ASGI attempt completed configuration, consent, grants,
refresh and disconnect against the synthetic provider, then failed in its
second worker when reopening the retained database. The original frame-only
diagnostic was initially misread as a first-start failure; the parent traceback
and `interpretation-correction.md` retain the distinction. X metadata inspection
had created an empty SQLite temporary schema on the borrowed startup connection.
Inspection now checks an existing temp schema without creating one; shadow
refusals and the Google main-only startup guard remain unchanged. The full
four-group lifecycle suite still needs a successful post-fix result.
Compiled Rust, actual SDK through the proxy, retained-state compatibility,
deployment and real-provider acceptance must each be recorded separately
before claiming those boundaries.
Current test evidence is retained in `x-accounts-connected.hWXZjH` and
`catalog-test-environment.8kKB0J` under the operator-workspace evidence directory.
