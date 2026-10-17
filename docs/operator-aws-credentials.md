# AWS credentials in the operator workspace

This component adds local AWS credential management to **Accounts and keys**.
It does not enable ECR publishing, any AWS destination, application access or
native approval. The ordinary workspace does not require a pilot to save keys.

Choose **AWS credentials**, name the saved credential, and enter either:

- A long-term access key ID and secret access key.
- A temporary access key ID, secret access key, session token and future UTC
  expiry in `YYYY-MM-DDTHH:MM:SSZ` form.

The initial supported input profile matches the existing ECR signer: a 20-character
`AKIA`/`ASIA` key ID, a 40-character signing key and, for sessions, a bounded
printable token. These are local format checks, not proof that AWS accepts the
credential or that it has particular permissions. Do not enter credentials in
chat; use the authenticated form.

Temporary credentials require the complete tuple, including the session token
and expiry. Catchplate does not discover host profiles, contact instance
metadata, assume a role or automatically renew imported sessions. AWS documents
the session-token requirement and original expiry in
[using temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html).

## Lifecycle and secret handling

The entire tuple is stored in the existing encrypted credential store, bound to
its credential ID and generation. Catalog metadata contains the credential kind
and supplied expiry, but no access key ID, signing key or session token. Readback
does not reveal those values. Forms clear secret values on submission, dismissal
and navigation; they do not save a browser draft.

**Replace AWS credentials** replaces the complete tuple. It requires the current
catalog revision, policy hash and credential generation. Even identical input
advances the generation. The existing transaction owns encryption, catalog
update and audit together; the old secret is not decrypted for comparison.
An expired session remains visible and can be replaced or removed. Its original
expiry is never extended by a read or failed operation.

**Remove AWS credentials** removes the local encrypted row and retains its
generation and audit history. It does not revoke the key or session at AWS.
Uncertain responses are not retried automatically; inspect saved state first.

## Dispatch boundary

The distinct `aws_sigv4_v1` type cannot be selected for generic header rules,
Connect-an-app permissions, SDK configuration or static-key replacement.
Catalog policy validation, generic credential writers, runtime projection,
lease handling and generic injection reject this type or its markers.
Saving a tuple changes no signed proxy policy and creates no secret lease.

Cards therefore explicitly say **Stored only — ECR publishing not available yet**.
The [AWS integration plan](operator-aws-client-compatibility.md) still requires
the compound exact-image approval, bounded publication state, SigV4 final
dispatch and actual SDK-through-proxy acceptance. The separate
[image preparation component](operator-ecr-image-preparation.md) is not that
approval or publication.

## Local verification (October 11, 2026)

The isolated custody suite passed 12 groups and the real loopback HTTP API suite
passed five, including cold reopen, transactional rollback and secret-leak
checks. The rendered browser suite passed all 12 groups against intercepted
API fixtures; it is not a browser-to-provider acceptance test.

Regression testing also exposed and repaired two existing issues: custom-header
key replacement rejected its required header-name metadata, and shared envelope
readers rejected the ordinary writer's unpadded Base64. The corrected runs passed
14 key-replacement, six release-boundary/OAuth-projection, eight envelope-codec,
10 native-material codec and nine owned-database-connection groups. The native
checks use synthetic keys/owners; they do not commission a native service.

Use `make verify-operator-aws-credentials`, `make verify-operator-aws-browser`
and `make verify-credential-ciphertext-codec` with the documented test dependencies.
Execution receipts and source hashes are retained outside Git in
`catchplate-operator-workspace-evidence/aws-credentials.0oM3vMMf`; earlier failures
are preserved. No AWS request, publication, new pilot or live credential mutation
was part of these checks.
