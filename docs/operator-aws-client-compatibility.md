# AWS ordinary-client compatibility plan

Status: **plan only; not implemented or accepted**. This document proposes a
bounded operator-development feature, not AWS-wide SDK support, a production
credential service, or completion of the native pilot. No AWS access or runtime
validation was performed to prepare it. The earlier observation of local
Boto3/Botocore 1.34.46 source availability is not a tested compatibility pin.

## Product flow and existing source boundary

The intended flow is: save an AWS credential, create/select an application,
choose an ECR permission for one account/region/repository, then copy standard
SDK proxy/trust configuration. Do not ask for response field lists. Application
authentication remains separate from provider credentials and public SDK dummy
credentials. Saving a credential or application grants no AWS access by itself.

The [README ECR example](../README.md#example-yubikey-approved-aws-tee-image-update)
(lines 87–147) requires exact-image, request-triggered hardware approval and
explicitly leaves its integration open. The
[workspace requirements](operator-workspace-requirements.md#what-the-original-examples-imply)
distinguish operation bundles from generic header replacement and optional
content restrictions. Current `CredentialInput` in
[`operator_catalog_inputs.py`](../serverware/operator_catalog_inputs.py) only
admits bearer/header secrets; [`policy_engine.py`](../serverware/policy_engine.py)
`_secret_for_injection`/`_inject_credential` are not an AWS signing interface.

Default permissions must be narrow, explicit presets, not `service:*` or an IAM
administrator policy. Schedules, quotas, content restrictions and human approval
are separate optional choices for a new ordinary-client permission. Existing
policies keep their restrictions; “optional” does not remove the README's
required YubiKey approval from that original publication journey.

## Credential custody and signing contract

- Add a versioned AWS credential type: access key ID plus secret access key,
  optional session token and mandatory expiry when importing temporary access.
  Keep the complete tuple in the existing encrypted credential store; catalog
  responses, audit, browser storage and client downloads must omit it. No new
  vault, ambient host credential-chain lookup or import of bootstrap profiles.
- Treat imported temporary credentials as expiring, not automatically renewable.
  Rotation must use current-generation/CAS guards, preserve assignments and show
  affected applications. Future role/SSO renewal needs its own owner and tests;
  an expired AWS session does not renew an application's proxy identity.
- The client uses explicitly supplied non-authoritative dummy AWS credentials
  so an unmodified SDK can construct requests. Authenticate the application
  independently. Admit only the reviewed dummy-signature shape; reject unknown
  credentials and ambiguous duplicate authentication fields. Dummy signatures
  are not proof of identity, account ownership or permission.
- After route/operation authorization, consume the dummy authentication and
  construct **real SigV4 for the final outbound request** inside Serverware.
  Bind method, URI/query, selected headers, exact body bytes/hash, service,
  region, policy, application and current credential generation. Recheck the
  built request immediately before dispatch; no later rewrite may invalidate
  the signature. Never implement this as replacing `Authorization` alone.
- Own the signing date and temporary security-token header. Bound freshness,
  credential expiry, request deadline and secret lifetime; redact signing
  material and scan responses for credential reflection. Preserve existing
  revocation/lease and uncertain-outcome controls; do not automatically replay
  an uncertain write or silently retry with a different credential generation.

AWS documents the request-bound signature and temporary-token requirements in
[Create a signed AWS API request](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).
Use reviewed signature vectors and an independent verifier, not only agreement
between two wrappers calling the same signing implementation.

## Smallest coherent service slice

Propose one explicit ECR API profile with a fixed regional HTTPS endpoint,
SigV4 service `ecr`, one account and one repository. Require explicit matching
`registryId`; do not assume an omitted value belongs to the configured account.
Admit named actions, not arbitrary `X-Amz-Target`, endpoint overrides or URLs.
The first publication bundle should contain only `BatchCheckLayerAvailability`,
`InitiateLayerUpload`, `UploadLayerPart`, `CompleteLayerUpload` and `PutImage`.
Repository creation/deletion, arbitrary AWS services, presigned URLs, SigV4a,
unsigned/chunked payload signing, redirects and credential-export APIs stay out.

Implement the actual ECR JSON media/header/error contract, including
`application/x-amz-json-1.1`; do not widen generic JSON modes globally. Bound
decoded layer bytes, base64 wire expansion, individual parts, total upload,
manifest size, concurrency and lifetime. Associate returned upload IDs with the
same application/account/region/repository and enforce offsets, digests and
completion state. Check the final manifest against uploaded/authorized layers.
Full supported responses remain available, with framing/disclosure protections
and an explicit bounded selection of metadata needed by the SDK.

These are compound operations: ECR returns an upload ID at
[initiation](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_InitiateLayerUpload.html),
accepts [parts](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_UploadLayerPart.html),
then [completes a layer](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_CompleteLayerUpload.html).
[PutImage](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImage.html)
publishes the manifest after layers exist. Its final image digest is not
available merely because the first upload request arrived.

For the original exact-image approval requirement, obtain and bind the complete
manifest/layer intent **before any protected upload effect**, or design an
explicitly approved bounded staging protocol. Approval only at `PutImage` does
not retrospectively authorize earlier uploads. This unresolved workflow needs
an explicit design decision, not an approval checkbox or fabricated ceremony.

Docker registry authentication uses a different
[ECR authorization-token workflow](https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html).
A Boto3 API fixture does not prove Docker push compatibility; do not return a
real registry token to clients or advertise Docker support from this slice.

## Implementation and acceptance gates

1. Add isolated AWS credential/catalog and ECR policy modules, closed schemas,
   generation-aware broker material, and matching Python/Rust typed admission.
   Add a dispatch signer with an explicit final-request binding; preserve old
   header-injection policies and refuse unsupported controlled/native consumers.
2. Pin one reviewed Boto3/Botocore release and run an unmodified ECR client using
   documented [proxy, CA and retry configuration](https://docs.aws.amazon.com/boto3/latest/guide/configuration.html).
   Use explicit dummy credentials, distinct proxy authentication and verified
   outer/inner TLS trust. No event-hook/header/body rewriting to manufacture
   compatibility, disabled verification, or ambient real AWS credentials.
3. In a fresh isolated fixture, an independent synthetic ECR service must verify
   the actual upstream SigV4 and temporary-token use. Complete a bounded layer
   upload and manifest publication through the real proxy; preserve stock SDK
   results/errors. Test wrong app/account/region/repository/action, bad offsets,
   changed bytes, stale generation, expiry, rotation, reflection and ambiguous
   write outcomes. Set a finite attempt/deadline budget and count actual sends.
4. Only then propose a separately authorized real-AWS check against an existing
   test repository, with exact resource scope, costs, writes and cleanup agreed.
   A synthetic pass is not real AWS acceptance, Docker compatibility, YubiKey
   approval, Nitro deployment or production readiness. R96 remains terminal;
   this plan grants no native retry, enrollment or authority-window extension.

## Inputs still required for real AWS use

An operator must select the account, region, existing test repository, permitted
actions and artifact; supply least-privilege workload credentials through an
approved private file/import channel, including session token and expiry where
applicable; and authorize the bounded cloud effects and cleanup. Never send
keys/tokens in chat or Git. A pasted IAM policy is not evidence of effective
permissions. No root/bootstrap credential is an application default.

[`aws-test-access.md`](aws-test-access.md) records historical discovery access,
expired bootstrap observations and the aggregate under-USD-25 test budget. It
does not establish current ECR permissions or authorize provisioning here.
Source, fixtures and UI can be developed without real credentials; provider
identity/permissions and actual publication require the separate inputs above.
