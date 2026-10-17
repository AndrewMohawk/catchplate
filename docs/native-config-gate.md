# Native gate configuration reference

This is the `gate` object inside the [native startup configuration](native-startup-config.md).
Its [closed Rust decoder](../data-plane/decision-gate-rs/src/native_startup_config/gate.rs)
produces ordinary cold inputs and TLS-root configuration, not a running gate or
an admission verdict. The source is unbuilt and unexecuted.

Field names are case-sensitive camelCase; unknown fields are rejected at every
object level. Counts and milliseconds are JSON integers. Unless explicitly
listed as nullable below, fields are required and cannot be `null`. There are
no default sizes, timeouts or service credentials. Optional fields accept
omission or `null`; an empty string/list is not another spelling of absence.

## Identity, trust and checkpoint

| Field | Contract |
| --- | --- |
| `expectedBinarySha256` | Required `sha256:` plus 64 lowercase hexadecimal digits. Later startup compares it with actual executable bytes; this input is not a measurement. |
| `instanceId` | Required canonical SPIFFE ID, at most 4,096 bytes. Also supplies the ingress instance identity. |
| `policyHighWater` | Required closed checkpoint object described below. |
| `policyTrust` | Required closed trust-source object described below. |
| `atomicReleaseAuthorizationEnabled` | Required boolean selecting the existing atomic-release versus separate grant/rate-limit service requirements. It does not authorize an operation. |

`policyHighWater` has exactly these required fields:

| Field | Contract |
| --- | --- |
| `apiVersion` | Exactly `catchplate.policyHighWater/v1`. |
| `policyId` | 1–256 bytes; no surrounding whitespace or control characters. |
| `sequence` | Positive `u64`. |
| `rollbackEpoch` | Positive `u64`. |
| `policyHash` | Canonical `sha256:` digest. |

This camelCase object converts to the existing internal checkpoint type. It
supplies startup's sequence/rollback floors and exact policy commitment; it is
not derived from the incoming candidate and does not prove independent latest
witness state. Actual signed-policy preparation must still join the checkpoint.

`policyTrust` contains required `url`, required `verifier`, and optional/nullable
`expectedQuoteKeyId`. The URL must satisfy the production endpoint checks with
path `/attestation`; a supplied quote-key ID must be a canonical `sha256:`
digest. The source is always an unused attested-control-plane source, never a
file or a caller-supplied successful trust result.

`verifier` is exactly `{executable, arguments, sha256}`. Its path must be an
absolute canonical spelling of at most 4,096 bytes, without traversal or NUL;
the digest is canonical `sha256:`. `arguments` must be exactly `[]`, matching
the actual production contract of one absolute static executable with no
interpreter or arguments. Configuration decoding does not read or measure it;
actual startup retains the existing executable checks.

## Service endpoints and credentials

Every supplied URL is at most 4,096 bytes and must pass the existing production
HTTPS/canonical-endpoint validator with the fixed path below. No endpoint is
learned from a request. Actual native transport additionally requires matching
configured relay assignments.

| URL field | Token field | Fixed path and requirement |
| --- | --- | --- |
| `credentialLeaseUrl` | `credentialLeaseToken` | `/api/data-plane/credential-leases`; both required, non-null strings. |
| `auditUrl` | `auditToken` | `/api/data-plane/audit`; the wire permits omission/null, but production validation requires both. |
| `grantConsumeUrl` | `grantConsumeToken` | `/api/data-plane/grants/consume`; both required when atomic release is disabled; otherwise optional/nullable. |
| `rateLimitConsumeUrl` | `rateLimitConsumeToken` | `/api/data-plane/rate-limits/consume`; token required when atomic release is disabled, URL optional/nullable. |
| `releaseAuthorizationBaseUrl` | `releaseAuthorizationToken` | `/api/data-plane/release-authorizations`; both required when atomic release is enabled; otherwise optional/nullable. |

`managementToken` is always a required string. For every service, a supplied
URL requires its token. Audit requires exact URL/token pairing; for the other
optional services, a token without a URL does not create an endpoint.

Tokens are at most 4 KiB, contain no whitespace/control characters, and pass
the existing production strength check: at least 32 bytes and at least eight
distinct byte values. All configured service tokens must be mutually distinct.
This syntactic check is not proof of randomness or service enrollment.

Real tokens belong only in the independently provisioned configuration/private
mount, never in chat, examples, logs or committed fixtures. There are no
environment-variable or token-file fallback fields inside `gate`.

## Resource and timeout fields

All fields below are required; bounds are inclusive.

| Field | Accepted range |
| --- | --- |
| `grantCacheMax` | 1–1,000,000 entries |
| `gmailProofCacheMax` | 1–1,000,000 entries |
| `credentialLeaseCacheMax` | 1–1,000,000 entries |
| `credentialLeaseRenewalWorkers` | 1–32 |
| `credentialLeaseRenewalQueueCapacity` | 1–65,536 |
| `credentialLeaseRenewalIntervalMs` | 50–1,000 ms |
| `auditQueueMax` | 1–1,000,000 entries |
| `auditBatchMax` | 1–200 records |
| `requestHeadDeadlineMs` | 100–30,000 ms |
| `requestBodyDeadlineMs` | 1,000–600,000 ms |
| `responseWriteDeadlineMs` | 1,000–600,000 ms |

These are bounded settings, not independent capacity admission or new lifetime
authority. The native runtime still owns its original absolute lifetime.

## Inline TLS roots

`controlPlaneTlsRootsPem` and `upstreamTlsRootsPem` are optional/nullable arrays
of PEM strings. A supplied array must contain 1–32 entries, each at most 64 KiB,
with at most 1 MiB total input per list. Each ASCII entry must contain exactly
one complete parseable certificate, with optional surrounding whitespace;
LF and CRLF are supported. Repeated extracted PEM blocks, ignored text, key
blocks and unfinished/additional certificates are rejected.

| Field | Omitted/null | Supplied |
| --- | --- | --- |
| `controlPlaneTlsRootsPem` | Existing built-in TLS roots | Replaces built-in roots with the supplied certificates |
| `upstreamTlsRootsPem` | Existing built-in TLS roots | Adds supplied certificates to the existing built-in roots |

TLS hostname/certificate verification remains enabled. Parsing PEM does not
admit a root's provenance, establish Nitro trust, or enroll a remote service.

## Construction boundary

Conversion invokes the existing native production static validator. Production
mode is fixed on; there is no `isProduction` switch. Filesystem policy,
checkpoint and release-evidence paths; external recipient/proof attestation
commands; imported private keys; snapshots; HTTP clients; shadow/v2 owners;
and native transports are absent by construction. Later
[startup composition](native-startup.md) must create and join the actual owners.
Neither this format nor matching supplied digests grants production activation.
