# Portal admin-token publication inspection and resolution

The embedded operator portal now has an explicit publication panel and a
dedicated approval-queue continuation for the existing
[authorized resolution API](control-plane-admin-token-publication-resolution.md).
This is source integration, not observed browser behavior or a tested pilot.
This lane explicitly uses the [purpose-bound controlled-writer bridge](control-plane-publication-approval-authority.md),
not generic development WebAuthn/approval metadata writes. The bridge and panel
remain unprovisioned and unexecuted; independent cold custody and current physical
authenticator trust must be admitted before the ceremony can succeed.

The panel intentionally uses only an active OIDC administrator cookie. An entered
bearer credential blocks this lane; the operator must explicitly clear it and
refresh cookie status using the existing authentication controls. The panel can
reveal the existing password field for that manual action, but never reads its
value into a request, clears it silently, or changes the API's other supported
authentication modes. Independently usable OIDC/admin access remains necessary
when publication installed a token whose plaintext was lost.

## Explicit sequence

1. Click **Inspect publication history**. The panel rechecks the actual cookie
   before and after the fixed read-only inspection request. It admits bounded,
   closed observation/v1 data and displays only publication IDs, intent digests,
   phases and file-match classifications, never token bytes.
2. Select an inspected attempt, explicitly choose `finalize-installed` or
   `abandon-uninstalled`, and enter an exact reason or leave it empty for null.
   Observed states only restrict available UI actions; they cannot prove exact
   inode/byte eligibility. The server still admits the original files.
3. Click **Fresh passkey + request resolution approval**. The panel rereads the
   selected observation, computes the existing canonical binding for
   `control_plane.token.publication.resolve` / `admin-token`, obtains genuine
   `catchplate.publicationApprovalOptions/v1` options with the exact five-field
   request binding. It checks the closed response, expected
   `publication-approval.request` operation and payload digest, then uses the
   opaque authority challenge for genuine WebAuthn. One resolution POST carries
   `mfa.publicationProfile` and the actual assertion. Options metadata is never a
   successful-verification shortcut or a locally derived generic v1/v2 challenge.
4. Only the exact matching 428 approval-required response creates a page-local
   continuation. A different administrator reviews the exact publication,
   intent, outcome and reason in the existing approval queue. Its dedicated
   handler sends the same exact request binding and approval ID for a fresh
   `publication-approval.decide` ceremony. The server selects that phase from the
   actual different actor and retained pending row. The approval note must be
   null; a nonempty note is refused until the operator explicitly clears it.
   One approval POST carries the profile marker and assertion, not an MFA approval
   ID or generic mutation resubmission loop.
5. After the matching unexpired approval appears in the queue, the requester
   explicitly clicks **After approval: new passkey + resolve once**. This obtains
   a new `publication-approval.consume` assertion. Both its options request and
   resolver MFA object carry the retained approval ID; the server joins the
   actual requester and approved row. The exact target, reason and outcome cannot
   change across this continuation. No old generic v1/v2 options are accepted.
6. Only the closed seven-field success response with matching publication,
   intent/outcome, completion digest and `automaticRetryAllowed: false` is
   displayed as server-reported settlement. Inspection can be refreshed by a
   separate click. No rotation, token disclosure or further mutation follows.

## Currentness and uncertainty

Actor, authentication, policy or credential-trust changes use the portal's
existing context generation to abort in-flight work and discard local approval
state. Target, reason or outcome changes do the same. Actual cookie identity is
checked around ceremonies; the server remains responsible for live identity,
CSRF, assertion signatures, distinct-person approval and exact file admission.
Selecting or rendering JSON creates no authority.

Pending approval and selection are page-local; no assertion, approval or token
is stored in browser storage or logged by this panel. Fixed same-origin fetches
reject redirects, use no-store and bounded duplicate-rejecting JSON parsing.
A single bounded browser-operation watchdog is cancellation, not a renewal of
server challenge/approval expiry or the resolver's original processing clock.

An attempted resolution locks that publication/intent on the page. The sole
exception is its exact approval-required response, which permits one explicit
fresh-authorized continuation, not automatic resend. Lost, refused, malformed,
late or context-changed responses after a mutation attempt remain blocked/unknown.
Changing the outcome or discarding local state does not clear attempt locks.
Approval sends likewise have one-shot page locks. A reload is not recovery
permission; durable server claims and uncertainty remain authoritative.

Inspection remains available in an unknown state and does not clear it. Raw
error bodies are not rendered or logged. Existing resolution claims, incomplete
settlement, malformed/orphaned records and mismatched files require separate
operator handling; this panel offers no retry, rename, deletion, journal repair,
token restoration, archival or approval bypass. Later rotation requires its
own authorization after the server has established a definite terminal anchor.

Implementation: [`portal_admin_token_publication.py`](../catchplate/portal_admin_token_publication.py)
contains the HTML and script fragments; the existing embedded portal supplies
fixed insertion points, auth/context hooks, genuine WebAuthn conversions and
data-only bounded parser/canonical-hash helpers. Existing HTTP paths remain;
the explicit purpose profile is paired in the
[closed schema bundle](../schemas/control-plane-publication-approval.v1.schema.json).
