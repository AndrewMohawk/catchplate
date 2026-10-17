# Per-route credential header replacement

## Operator journey

Store the provider credential once. Create an application, then add an access
rule selecting that credential and the permitted destination and operations.
Choose how this client supplies provider authentication:

- **Add credential automatically:** the client omits the provider credential
  header. Catchplate adds its stored credential after authorization.
- **Replace a dummy header value:** the client sends a configured public
  placeholder. For `Authorization: Bearer CATCHPLATE_PLACEHOLDER`, configure
  the complete value `Bearer CATCHPLATE_PLACEHOLDER`, including the prefix.

The client still authenticates separately to Catchplate using its application
token. That token is not the placeholder and is never provider authentication.
Never paste a real provider secret or application token into the placeholder
field: it is public configuration and appears in client examples.

Response filtering is independent. The basic JSON workflow needs no response
field list. Selected-field filtering retains the explicit projection. Neither
choice implies arbitrary text, binary or streaming support.

The operator API accepts `credential_input: "insert"` (the historical default)
or `credential_input: "replace_exact"` with `placeholder`. Insertion forbids a
supplied placeholder, including null. Two applications can use different input
choices with the same stored credential; the secret is not duplicated.

## Signed contract and compatibility

A signed route may require one exact dummy header value before the Rust data
plane injects its separately stored credential:

```json
{
  "credentialRef": "credential:shared-provider",
  "credentialHeader": {
    "mode": "replaceExact",
    "expectedValue": "Bearer caller-chosen-dummy"
  }
}
```

The target header comes exclusively from that credential's existing `bearer`
or custom `header` injection declaration. No target override or secret copy is
accepted in the route descriptor. Another route can share the same credential
and omit `credentialHeader` to retain insertion-only behavior. The global
`injection.existingHeader` option is not supported.

The descriptor is a closed object with exactly `mode` and `expectedValue`.
The expected value is 1–1024 printable ASCII characters, with no leading or
trailing space. Interior spaces are significant. Matching is against the full
parsed HTTP field value: the existing HTTP parser removes outer SP/HTAB field
whitespace as before, and the replacement helper performs no additional
trimming, substring matching or prefix removal. Direct decision-request values
are compared as supplied, so extra outer spaces do not match there.
Exactly one matching field is required; missing, mismatched and duplicate
fields must deny before credential access or upstream dispatch.

This is a caller-chosen **dummy**, not a real credential. It is public signed
policy data, not encrypted secret storage. Grammar validation cannot determine
whether an operator accidentally pasted a real secret; the UI must explain
that distinction. Secrets remain in credential storage and are injected only
after request authorization.

Replacement cannot target cookies, framing/content headers, hop-by-hop or proxy
authentication headers, or Catchplate internal headers. Reserved names and
principal identity collisions are checked case-insensitively, including
underscore-to-hyphen aliases. `Authorization` is available through bearer
injection, not custom-header injection. Generic allowed/required/discard header
rules cannot turn the replacement target into a caller-forwarded header.

The descriptor is part of the signed route and policy hash. Compiled snapshots
and copies retain its immutable form; v2 route-authority pins include the full
signed route. An absent descriptor is not materialized into existing policy
documents or behavior digests. Explicit null, empty and unknown descriptors
are invalid, not aliases for absence.

Python remains a credentialless prototype. Its early route-admission boundary
unconditionally refuses this new descriptor, even in fixtures without a legacy
transport flag, before credential generation, lease or injection. This change
does not add Python credential forwarding. Compiler/prototype unit tests do not
prove Rust wire matching, credential release or deployed operation.

Deploy a compatible pinned control plane and gate together. Source capability
advertisement is not runtime negotiation; an unsupported gate must not trigger
a silent fallback. See [workspace verification](operator-workspace-verification.md)
for exact checkpoints. Required private acceptance includes replacement,
negative no-dispatch controls, independent insertion using the same credential,
response handling and complete audit verification. The earlier failed private
audit run remains failed and is never overwritten.
