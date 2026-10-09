# Ordinary-client JSON compatibility

This is an additive source contract, not a deployment or acceptance receipt.
Implementation began separately from the static-acceptance candidate in the
`serverware/ordinary-client-compat` worktree at `0717103b`. The existing static
fixture does not establish acceptance of these new modes.
See the [verification record](ordinary-client-verification.md) for exact tested
snapshots, retained failures and the remaining user-facing acceptance boundary.

## Product boundary

An ordinary application should be able to use a saved credential without
inventing request-field or response-field allowlists. New rules can explicitly
select no optional content filtering within the supported formats below.
Existing rules must not be broadened. A chosen response policy, such as Gmail
message age, is still an enforcement obligation: unsupported combinations must
be refused, not silently treated as unrestricted.

The resource model stays credential/account + application + access rule. Saving
a credential or application grants no access. This change does not alter Google
consent, refresh ownership, enrolled/native lifecycle, approvals or commissioning.
The managed Google profile remains its existing GET/no-request-body contract.

## Additive wire and catalog contract

| Catalog field | Explicit value | Signed adapter/envelope value |
| --- | --- | --- |
| `request_body_mode` | `preserve_json_v1` | `request.bodyMode: bufferedJsonPassthroughV1` |
| `response_mode` | `unfiltered_json_or_empty_v1` | `response.mode: bufferedJsonOrEmpty204V1` |
| Generated response envelope | New response mode only | `bodyPresence: jsonOrEmpty204V1` |

The request field accepts only this explicit new value. Absence preserves the
old no-body/field-constrained behavior and omitted stored/public field; null,
unknown values and a fabricated legacy enum are not supported. Explicit
preservation requires an empty catalog `request_fields` list. The old response
default remains `projected_json`; `unfiltered_json` retains its previous meaning.
Request and response choices are independent. The new modes require a matching
compiler and gate; older gates must reject them, without fallback.

## Request profile

Only `generic.rest` supports `bufferedJsonPassthroughV1`. The required fields
remain `allowedQueryKeys`, `allowedHeaders`, `allowedMediaTypes`, `bodyMode`,
`maxBodyBytes`, `operation` and `valueRules`. `discardHeaders` and
`requiredHeaders` remain optional under their existing contracts. Target,
application, method, query/header membership and credential binding are unchanged.

- `allowedMediaTypes` is exactly `["application/json"]`.
- `maxBodyBytes` is an integer from 1 through 16 MiB; the catalog renders 64 KiB.
- Zero body bytes are allowed, including GET/DELETE. Every nonempty body must
  pass strict JSON validation; whitespace alone is invalid. A present content
  type must be admitted, and a nonempty body requires it.
- The fixed new-mode depth limit is 127 nested JSON containers. Brackets inside
  quoted strings do not count. Every decoded string and key must be valid UTF-8
  text; escaped lone surrogates are refused. Duplicate keys, invalid UTF-8,
  nonfinite/overflowing numbers and integer `-0` are refused by strict parsing.
  Finite `-0.0`/`-0e0` retain their exact spelling. These are format bounds, not
  optional field restrictions; legacy parser behavior is unchanged.
- Preserve the original request bytes, including whitespace, escape and number
  spelling. Parsing does not authorize serialization of the dispatched body.
- `allowedFields` and streaming limits (`maxLineBytes`, `maxItemBytes`,
  `maxEventBytes`, `maxPairBytes`, `maxRecordBytes`, `maxNestedBytes`) are forbidden.
- `operation.jsonFields`/`formFields`, even empty, are forbidden. So are
  `jsonBody`/`formBody` constraints and body-sourced `requestValue`/`valueRules`.
  Existing path/header/query rules remain available. `operation.name`,
  `pathParams` and exact raw `bodySha256Field` remain supported.

The canonical request continues to bind the exact raw body SHA-256, including
the empty-body digest. Validate the final built buffered request against that
commitment before the existing dispatch barrier. Do not change approval digest
versions, consume-on-forward rules, deadlines or retry semantics. An ambiguous
upstream outcome never authorizes an automatic request retry.

## Response profile and 204

The new success profile has exactly `mode`, `bodyFormat`, `maxBodyBytes`,
`contentTypes`, `allowedHeaders` and `error`. Its error profile has exactly the
same first five fields plus `onInvalid`. Both modes are
`bufferedJsonOrEmpty204V1`, `bodyFormat` is `json`, and `contentTypes` is exactly
`["application/json"]`. Limits are positive and bounded by 16 MiB for success
and 64 KiB for errors. `onInvalid` is `block`; existing safe-header bounds apply.
No field projection or streaming controls are accepted in either profile.

Every response envelope must explicitly use `jsonOrEmpty204V1`, the same JSON
content-type contract, and a status list containing 204. Other statuses can be
2xx except 205, or 4xx/5xx. An envelope still admits only its listed statuses;
this is not automatic admission of all those ranges. Envelopes remain
conjunctive, not alternatives. The new envelope on an old response profile is
invalid, as is the new response profile with missing or old envelopes.

- Admitted 204: zero body bytes and no trailers, `Content-Length` or
  `Transfer-Encoding`. A single admitted JSON `Content-Type` metadata value is
  permitted but not required. Never invent a JSON body, content type or framing
  header. Metadata passes the existing header/disclosure release rules.
- Every other admitted status, including errors, requires bounded strict JSON.
  Preserve its exact body bytes after existing raw/decoded disclosure checks.
  Empty 200/errors and redirects do not become successful empty responses.
- Existing response semantic policies remain in force. The existing whole-JSON
  refusals of `slidingWindowLimit`, `weightedBudget`, `traversalBudget` and
  `responseBinding` are retained; no response evidence is silently waived.

The metadata/framing distinction follows [RFC 9110 section 15.3.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.5),
[section 8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6), and
[RFC 9112 sections 6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1)
and [6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3).

An HTTP client library may suppress malformed bytes after a 204 header section.
An empty parsed body alone does not prove the raw upstream sent no extra bytes.
Reject exposed framing violations, disable idle connection reuse for the new
response profile, and test trailing-byte isolation separately. Do not turn a
parsed-body fixture into a raw-wire proof. Existing transport bounds remain.

The Rust gate is the intended transport for this new response profile. Python
engine/adapter validation can inspect exposed headers, body and trailers, but
the legacy Python proxy does not yet own the required connection-isolation
boundary. Marked legacy-transport requests therefore refuse the new 204 profile
before dispatch; existing profiles are unchanged. Implementing and verifying
that legacy transport capability remains open.

## Additive version 2: ordinary response metadata

The isolated Google run exposed a separate incompatibility: its upstream
returned HTTP 200, but ordinary response metadata was outside the catalog's
empty exact header envelope. Hiding response-field controls does not fix this.
Version 2 is an explicit new contract; implementation and verification status
must be recorded separately, not inferred from this specification.

| Layer | Version 2 value |
| --- | --- |
| Catalog `response_mode` | `unfiltered_json_or_empty_v2` |
| Success and error profile `mode` | `bufferedJsonOrEmpty204V2` |
| Every response envelope `bodyPresence` | `jsonOrEmpty204V1` |
| Every response envelope `unlistedHeaderPolicy` | `discardUnselectedV1` |

Only `generic.rest` admits this paired contract. Both success/error modes must
match; their independently bounded size limits and selected safe-header lists
need not be identical. Every envelope requires the new header marker, and the
marker is forbidden on all older profiles. Both directions are validated before
any profile-specific early return. Version 1 JSON/empty-204, request-body,
status, timeout, credential, approval and secret-disclosure obligations remain.
Existing records, omitted fields, compiler output and signed policy hashes must
not change merely because this mode becomes available. New rules select it
explicitly; the UI may prefer it only when advertised. Existing rules retain
their saved mode, including on edit. Google remains exact GET/no-request-body.

Admission of upstream metadata and release to the client are distinct:

- Bound **all parsed physical header occurrences**, before discarding anything:
  at most 128 fields, 65,536 total name/value bytes, 128 bytes per name and 8,192
  per value. Names use ASCII HTTP-token syntax; values admit visible ASCII,
  spaces and tabs, not CR/LF or other controls.
- Scan every physical name and value for reflected credential material before
  discard, shadow/observation processing or an empty-204 early return. Failure
  evidence uses fixed reasons and counts, not arbitrary metadata names/values.
  Do not copy discarded raw metadata into public audit or proof fields.
- Unlisted, nonreserved semantic metadata may be discarded, including repeated
  occurrences. It never becomes an output header merely because admission
  succeeded. Listed headers and all existing predicates remain enforced.
- Each success/error output-header list must be a subset of **every** envelope's
  listed names. Selected output still uses the existing safe-header allowlist
  and disclosure checks. The operator catalog continues to select no additional
  output headers; this is not an unrestricted HTTP-header passthrough.
- Protocol/transport headers retain singleton and dedicated framing/encoding
  checks. Authorization, proxy authorization, Cookie, Set-Cookie and
  `X-Serverware-*` are refused, not generically discarded. Version 2 checks
  lowercase/underscore-to-hyphen aliases for these reserved names; transport
  aliases are also refused. This classifier does not normalize the raw evidence
  or the exact names used by policy predicates.

This describes bounded **parsed** header evidence, not proof of raw bytes hidden
or rejected by the HTTP library. Python validation requires physical fields,
never a dictionary fallback that erases duplicates; the unsupported legacy
Python transport must refuse the mode before dispatch.

The initial V2 implementation must also refuse requests for any existing
buffered/observation proof kind **before credential release or upstream
dispatch**. Existing buffered proofs commit only to selected raw headers, not
the newly consulted discarded metadata; existing observation serializers do
not establish the required empty-204 framing. Do not silently reuse those proof
contracts, export raw discarded metadata, or discover this incompatibility only
after an upstream action. A versioned aggregate-header commitment and verifier,
no-content proof serialization, and native/shadow conformance remain required
full-goal work. Ordinary proxy use without those requested proofs is a separate
supported journey, not a substitute for completing the proof-backed product.

Required new controls include Date/Server/arbitrary metadata admitted but absent
from output; repeated unlisted metadata discarded; selected/listed/protocol
ambiguity, reserved aliases, size/count/control-character violations and
reflected secrets denied; all old modes still refusing the same unlisted
metadata; and real JSON/error/204 finalizer paths. The joined Google fixture
must retain its ordinary upstream headers and reach actual expiry/refresh; do
not alter its response merely to conceal a compatibility failure.

## Agreed operator-only standard-client authentication contract

The catalog, Python/schema, Rust and UI implementation is prepared and has
independent source review. Execution and deployment acceptance remain open;
earlier compatibility results do not cover this option. Ordinary clients need a supported way to authenticate
to the proxy using their existing application token; this is separate from
provider-key injection, OAuth consent and console authentication.

### Signed opt-in and bounded wire form

An operator-profile principal may explicitly add the optional signed field
`proxyAuthorization.basicTransport = {"username": "<application UUID>"}`.
The username must be the canonical lowercase application UUID and exactly match
the existing `tokenId`. The existing `scheme: "Bearer"` and `tokenSha256`
remain authoritative; this does not create a second password or change token
hashing. `expiresAtEpochMs` must be an integer from 1 through
9,007,199,254,740,991, and normal expiry enforcement still applies.

For this opt-in, the outer proxy request may carry
`Proxy-Authorization: Basic <credentials>`. The decoded credentials must be
exactly 80 ASCII bytes: the 36-byte UUID, one colon, and the existing 43-byte
URL-safe application token. Their standard padded Base64 encoding is exactly
108 bytes, with canonical padding; decoding and re-encoding must agree.
Noncanonical encodings, extra separators, whitespace, malformed identities or
incorrect token lengths must not become alternate credentials. Use bounded
parsing shared with the existing digest/authentication path, not a separate
unbounded parser or a new request/approval digest domain. Proxy authentication
material must not be forwarded to the upstream or copied into audit evidence.

Without the signed opt-in, Basic authentication remains unsupported. Existing
Bearer authentication, omitted-field policy output and all established digests
remain unchanged. The new option is limited to the operator profile: policy-v2,
native/enrolled and other non-operator runtimes must refuse it until their own
integration and acceptance are completed. Operator support cannot stand in for
that remaining full-product work.

### Application mode and reviewed changes

The application setting is `proxy_authentication`, with modes `bearer` and
`basic_and_bearer_v1`. An absent saved field keeps the old Bearer interpretation;
availability must not rewrite migrated records or signed policy. New application
API requests default to `bearer`. The UI may select the new mode only when the
exact capability is advertised, and must send the explicit opt-in rather than
infer it from a missing field or general proxy readiness:

```json
{
  "schema": "serverware.operatorProxyAuthentication/v1",
  "modes": ["bearer", "basic_and_bearer_v1"],
  "path": "/api/operator-demo/applications/proxy-authentication"
}
```

Existing applications use the reviewed, catalog/policy-CAS mutation
`POST /api/operator-demo/applications/proxy-authentication` to enable or disable
the option. This preserves application/principal identity, token value and
generation, absolute expiry, credential references and access rules. An assigned
application requires a new signed-policy publication; an unassigned application
mode change grants no access. Neither enabling the mode nor changing transport
may silently renew the token. Disabling Basic must retain the existing Bearer
path, not rotate or recreate the application.

### Acceptance still required

Acceptance must use stock Requests and curl through the actual **HTTPS** proxy,
including their ordinary proxy-username/password handling; a custom CONNECT
implementation or manually manufactured Basic header alone is insufficient.
Verify outer proxy TLS and inner origin/MITM TLS trust separately, including
wrong-outer-CA and wrong-inner-CA refusal. Wrong application identity, incorrect
token and expired token must be denied without upstream dispatch. Retain
positive Bearer and old absent-option controls, plus Basic refusal when disabled.

The private checker must use independently generated outer and inner trust
roots. Stock Requests uses one scoped CA bundle containing both roots; this is
not separate per-layer Requests trust configuration. Removing either required
root must fail. Curl can select the two CA files independently. The catalog's
minimum application-token lifetime remains one hour; focused expiry controls
must not be relabeled as a short fresh-API natural-expiry journey.

Evidence must also establish secret isolation, audit bindings and the real
policy transition, without logging proxy or provider credentials. UI fixtures,
compiler/parser tests, isolated private proxy acceptance and retained live
acceptance are separate results and must be recorded separately. None implies
real-provider, native or production readiness. Implementation and verification
status belong in the [verification record](ordinary-client-verification.md).

## Required cross-layer acceptance

| Control | Required evidence |
| --- | --- |
| Request preservation | Empty and nonempty JSON, escaped strings, whitespace/numeric spelling and exact size/depth boundaries; byte-identical dispatch, not merely equal parsed JSON. |
| Strict refusals | Invalid JSON/UTF-8/surrogates/duplicates/numbers, depth 128, unsupported media, compression and ambiguous framing; no upstream dispatch. |
| Admission parity | Schema plus independent Python/Rust validation reject contradictory fields, body captures, mixed response profiles/envelopes and unknown modes. |
| Approvals | Changed bytes with equal parsed JSON cannot reuse authorization; final-built-body drift blocks before dispatch. Lower-level digest tests are not an actual approval journey. |
| Response preservation | Exact JSON success/error bytes and secret-reflection controls; valid 204 with/without JSON metadata, no synthetic headers. |
| 204 controls | Body, trailers, duplicate/wrong type, all content lengths including zero, transfer encoding and trailing-byte connection isolation. Distinguish observable framing from parser-hidden bytes. |
| Compatibility | Old projected/whole-JSON/no-body rules unchanged, mixed rules and omitted fields preserved through migration/restart, no unrequested policy rewrite. |
| Lifecycle | CAS/audit rollback, actual pending-to-active policy transition and warmed-cache revocation still enforced. |
| Ordinary client | Browser/API rule creation without body/response field declarations, then a real client through CONNECT and scoped CA trust. Synthetic fixtures alone do not establish deployed acceptance. |

## Remaining compatibility and full-goal work

Query ordering is a separate contract change: current canonical wire ordering
must not be relaxed without reconciling request, approval and dispatch
commitments. Form, multipart, text/binary, compression and streaming remain
named unsupported-format work, not hidden Advanced settings. Provider operation
bundles (Gmail pagination/dynamic reads, X account-wide limits, npm prerequisite
reads/publish and requested ECR approvals), real Google consent/refresh proof,
public deployment and native/production acceptance remain independent work.
