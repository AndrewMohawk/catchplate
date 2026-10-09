# Ordinary-client JSON compatibility, version 1

This is an additive source contract, not a deployment or acceptance receipt.
Implementation began separately from the static-acceptance candidate in the
`serverware/ordinary-client-compat` worktree at `0717103b`. The existing static
fixture does not establish acceptance of these new modes.

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
