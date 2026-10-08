# Bounded unprojected JSON responses

`generic.rest` can explicitly opt into `bufferedPassthrough` instead of the
existing projected `json` response mode. This first slice supports JSON only;
it does not complete general text, binary, compressed, or streaming client
compatibility. Credentials and request replacement are separate capabilities.

```json
{
  "mode": "bufferedPassthrough",
  "bodyFormat": "json",
  "maxBodyBytes": 1048576,
  "contentTypes": ["application/json"],
  "allowedHeaders": [],
  "error": {
    "mode": "bufferedPassthrough",
    "bodyFormat": "json",
    "maxBodyBytes": 65536,
    "contentTypes": ["application/json"],
    "allowedHeaders": [],
    "onInvalid": "block"
  }
}
```

Both profiles are mandatory, closed objects: only the displayed keys are
accepted. `bodyFormat` must be `json`; `contentTypes` must be exactly
`["application/json"]`. `allowedFields`, wildcards, streaming knobs and unknown
options are rejected. Success limits are positive integers up to 16 MiB; error
limits are positive integers up to 64 KiB. Both the received body and normalized
inspection representation must fit the selected limit. An oversized inspection
representation fails with `response_inspection_body_too_large`. Existing safe response-header allowlists
apply, with no upstream headers released by default.

The complete body is buffered and strictly parsed, including duplicate-key
rejection. A compact UTF-8 serialization is made only for bounded inspection;
it is never substituted for the received body. Objects, arrays and scalar
values are supported. After successful inspection, the exact original body
bytes are released, preserving whitespace, key order, escapes and number
spelling, including large integer literals. Python and Rust may represent
numbers differently while inspecting them, so identical decisions at a tight
inspection-size boundary are not promised. Both inspect only finite numbers
their existing strict parsers accept; this is not arbitrary-precision numeric
semantic validation. Optional semantic constraints still use their existing
numeric models, rather than the original number spelling.

The response is released as `application/json` with normalized framing. An empty
body is not JSON. Explicit response-envelope status and body-presence policy
still applies; redirects and non-JSON provider errors are blocked. Content
encoding must remain absent or a single `identity` value; this mode does not
decompress responses.

The signed exact destination, request restrictions, upstream trust, status and
header checks, credential-reflection guards, audit behavior and final policy
freshness barriers remain mandatory. In the production Rust data plane, raw
bytes and the normalized inspection representation are both scanned for
credential reflection before the original owned body is released. These checks are defense in depth,
not proof that an upstream cannot encode, transform or otherwise disclose a
credential. Opting into full response content trusts the selected upstream to
return appropriate data; it does not grant a broader destination or scope.

Python remains the credentialless prototype: its adapter validates parsing and
inspection bounds and preserves raw bytes, but this change adds no decoded
credential-inspection hook or credential-bearing forwarding authority there.
The existing Python credential-bearing refusal remains unchanged. Python
adapter tests do not establish production secret-reflection protection.

The new mode is rejected for other adapters, durable policy claims and
`responseBinding`. Existing optional response-value/date constraints still run;
they are not silently removed. Existing `json` still requires its field
projection and existing JSON error profile. Existing `any`, `headersOnly`,
streaming modes, saved defaults and provider-specific profiles are unchanged.
Mixing new and old success/error modes is rejected.

Request bodies retain their existing restrictions: credential-bearing generic
requests support only the current buffered `none`, `json` and `formUrlencoded`
contracts. This response feature does not enable arbitrary request bodies,
placeholder overwrite, Google OAuth integration or general streaming. Future
text/byte formats require explicit admission and runtime tests; unknown formats
fail closed today.
