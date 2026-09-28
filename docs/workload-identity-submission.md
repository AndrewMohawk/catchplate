# Explicit workload certificate submission

This source connects the local workload-identity client and operator portal to
the [guarded issuance action](control-plane-workload-identity-issuance.md).
It is not build, browser, deployment or authenticated-channel evidence. N04
remains open until trust distribution, lifecycle and real workload integration
are complete and verified. The two existing local preparation/admission modes
remain network-free.

## One explicit action at a time

```mermaid
sequenceDiagram
    participant W as Workload owner
    participant O as Requesting operator
    participant C as Control plane
    participant A as Different approver
    participant I as Dedicated issuer
    W->>O: Public packet and signed CSR request; independent issuance grant
    O->>C: Request options for exact originals
    C-->>O: Exact action binding and fresh challenge
    O->>C: Explicit submission with fresh WebAuthn assertion
    C-->>O: 428: approval ID and exact action binding
    A->>C: Separate fresh approval ceremony
    O->>C: Explicit new options request, then fresh assertion and approval ID
    C->>I: Independently admitted grant and exact public originals
    I-->>C: Durably retained certificate original
    C-->>O: Public certificate, not a proxy-authentication claim
    O->>W: Returned certificate for independent local admission
```

The control plane always revalidates current identity, fresh assertion, distinct
approver and independent grant. An options response, retained approval request
or matching digest cannot replace those authorities. No client mints a grant
from a CSR or derives workload issuer trust from the server's reply.

## SDK and CLI boundary

Networking is a separate explicit mode. The client uses one exact HTTPS origin,
an independently selected literal endpoint, pinned CA material and server SPKI.
It uses verified TLS 1.3 and bounded HTTP/1.1, without resolver substitution,
environment proxies, redirects, CONNECT, reconnection or automatic retry.
Control-plane TLS authentication is not enclave attestation or verification of
the separate signed-response evidence protocol.

Operator cookie, CSRF and assertion inputs are protected pinned files, never
inline command-line secrets. Originals remain checked through their use. One
original nonrenewing command budget covers file admission, TLS construction,
network chunks, response handling and local certificate publication. Blocking
native cryptography/filesystem operations still require an outer watchdog;
deadline checks alone cannot interrupt every such operation.

Options retrieval and certificate submission are separate invocations. The
portal provides an explicit receipt-import and passkey-assertion download step
between them; the network client itself does not emulate an authenticator.
Submission binds the supplied assertion to the exact retained options challenge
and action/resource/payload identity; the server performs authoritative assertion
verification. A successful response is not sufficient: the local client admits
the leaf against the retained request, private key and independently pinned issuer
before publishing a usable client certificate.

Each explicit issuance attempt durably claims its protected output directory
before contact. Publication is owner-only and refuses overwrite. A validated,
retained 428 response can supply the approval ID for a separately requested
continuation with fresh options and assertion in a new attempt directory. This
is not global client deduplication, a permission to clear a claim, or proof that
a later attempt will be accepted. The worker's durable nonce/serial policy remains
the actual issuance authority.

A lost response, timeout, malformed response or 412 does not authorize a
continuation or imply that issuance did not occur. Existing attempt artifacts
remain intact. No stage deletes uncertainty, renews an original grant, or repeats
a request automatically. Retained artifacts must exclude raw enrollment packets,
their CA-install capabilities, cookies, assertions and private keys.

`options-response.json` and `submission-response.json` are closed local receipt
envelopes containing the actual HTTP status and an original-byte wrapper
(`base64Url`, `byteCount`, `bytesDigest`) for the exact received JSON body. The
client retains only recognized bounded response shapes, not arbitrary error
text that might echo a capability. Receipt encoding is distinct from the
server's original response bytes. `submission.claim` contains only public
bindings and digests. An approval-continuation input pins the prior retained
receipt with its actual 428 status; a manually entered approval ID is not a
substitute for that input.

### CLI inputs

Use the existing `serverware-enrollment` command with exactly one of
`--request-workload-issuance-options` or `--submit-workload-issuance`.
Neither can be mixed with local prepare/admit or ordinary enrollment networking.

| Input group | Required flags |
| --- | --- |
| Original public inputs | `--workload-packet`, `--workload-packet-signing-key`, `--workload-issuer`, `--workload-authorization`, `--workload-request` |
| Operator transport files | `--workload-tls-ca`, `--workload-cookie`, `--workload-csrf` |
| Independent transport selection | `--workload-origin`, `--workload-endpoint-address`, `--workload-endpoint-port`, `--workload-server-name`, `--workload-server-spki-sha256` |
| Workload/output identity | `--expected-principal`, `--expected-nonce`, `--workload-output-directory`; optional `--workload-timeout-ms` (at most 30000) |
| Submission only | `--workload-private-key`, `--workload-options`, `--workload-assertion`; optional `--workload-approval` for explicit continuation |

Every file flag requires its corresponding `-sha256` flag, containing the
independently supplied `sha256:` digest. `--workload-options` pins the earlier
options receipt; `--workload-approval` pins a retained typed 428 receipt.
Options-only mode rejects submission-only inputs. Output directories must
already exist as current-user-owned mode 0700 directories; each attempt uses
exclusive files and never overwrites a prior attempt.

The origin is an exact `https://` origin without a trailing slash, path, query
or fragment. The endpoint address is literal, not a resolver name. Server name
and origin remain explicitly joined; independently choosing an address does not
disable normal certificate-name verification.

The cookie file holds only the ASCII Cookie header value: either
`serverware_admin=<value>; serverware_csrf=<value>` or
`serverware_oidc_session=<value>; serverware_csrf=<value>` (either ordering).
The CSRF file holds the exact matching CSRF value. Neither file has a header
prefix or trailing newline. Use protected local files; do not paste session
tokens, assertions or private keys into chat, shell arguments or logs. There is
no environment-cookie or browser-storage extraction fallback.

Exit status is **0** for options received or a certificate successfully admitted
locally, **3** for approval required, **4** for an unknown issuance outcome, and
**5** for a recognized refusal. These structured outcomes print their public
receipt summary once. A malformed exchange, transport or local publication
failure exits **1** with safe generic text; retain existing artifacts and do not
infer nonissuance from that code. Automation must not blindly retry any nonzero
result. Existing local modes retain their original behavior.

## Portal boundary

The portal consumes bounded public grant, packet and request files. Private keys
stay on the workload host; the browser does not generate or import them. Inputs
are page-local and are not saved to browser storage or printed to logs.

Request and approval buttons require an active OIDC operator session and use its
current cookie and CSRF path, not an entered bearer credential. Issuance requires
a fresh browser WebAuthn ceremony. Pending approval is a displayed state, not an automatic retry loop:
after a different operator approves, the requester must explicitly continue with
fresh options and another assertion. Auth changes invalidate the page's active
issuance context.

The portal can download public certificate material. Download is not independent
local key/issuer admission, CA installation, completed enrollment or a successful
proxy handshake. No uncertain outcome is displayed as success.

The separate CLI ceremony bridge imports the exact retained options receipt,
checks its same-origin action/challenge/user bindings against the current browser
context, and requests a genuine fresh passkey assertion. Its explicit download
contains that one-use assertion for the CLI input file, not session cookies,
private keys or issuer authority. It never submits an issuance request. Treat
the downloaded assertion as sensitive: move it to a protected current-user-owned
file, set mode 0600 and independently pin its exact bytes before CLI submission.
Browser download permissions alone do not satisfy the CLI's protected-file
contract. This deliberate assertion export is separate from issuance journals,
which continue to exclude assertions. Neither import nor download extends the
original challenge, packet or grant validity.

The current receipt and browser auth-status profile expose the user and current
authentication state, not a stable session ID or the challenge's original
issue/expiry timestamps. The bridge therefore checks the active OIDC user and
invalidates its in-page context on observed auth changes; it does not claim
cryptographic identity of the CLI and browser sessions. The server remains
responsible for checking the actual current cookie and original stored challenge
TTL when submission arrives. Import time is never treated as challenge issue time.

### Operator sequence

Once the independently provisioned service and trust inputs exist:

1. Prepare the local key/CSR/request and obtain the separate authorized grant.
   Keep the original packet, issuer and key pins unchanged throughout the flow.
2. Run the options-only CLI mode into a fresh protected directory. Import its
   exact `options-response.json` into the portal while signed in as the same
   operator user used by the CLI cookie.
3. Use the explicit passkey-and-download action. Protect and pin the downloaded
   assertion file, then submit it with the retained options receipt and original
   workload inputs into a different fresh attempt directory.
4. For a typed 428, have a different operator approve the exact request. Obtain
   fresh options in another directory and perform another passkey ceremony.
   Explicitly submit again with the prior `submission-response.json` as the
   pinned approval input and another fresh attempt directory.
5. On success, use the locally admitted certificate/key descriptions with the
   workload client. A receipt on disk without successful local admission is not
   an accepted identity; a successful admission is not a proved proxy connection.

Stop on unknown or malformed outcomes. This sequence describes authorized
approval continuation, not recovery from ambiguous issuance or a way to refresh
an expired grant. The current source has not executed this sequence.

## Remaining acceptance

After full source freeze, verify the complete options/request/approval/continuation
flow, protected-file changes, wrong origin/peer/issuer/key/SAN, expiry, cancellation,
body bounds, missing/changed originals and interrupted response/publication paths.
Verify each claim against the exact frozen source and artifacts. Then separately
prove the [loaded ingress trust and lifecycle](workload-identity-trust-distribution-plan.md),
mandatory workload mTLS, unchanged provider TLS/egress restrictions and the
independent production custody/release gates. None is established by source alone.
