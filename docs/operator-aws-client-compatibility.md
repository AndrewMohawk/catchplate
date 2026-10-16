# AWS ordinary-client compatibility plan

## Current ordinary ECR integration

The [ECR publication workflow](operator-ecr-publication.md) is now **deployed with
connected synthetic-provider acceptance; real AWS remains unverified**. It connects
saved AWS credentials to an exact client/account/standard-region/repository/tag
permission, verified staging, mandatory host-trusted review, explicit publication
UUID activation and five stock Boto3 actions. It is not Docker push or arbitrary
AWS SDK support. No provider keys reach the client; generic AWS leases remain
closed and the dedicated signer returns only an encrypted exact-request headers
lease. The original deadline is at most 30 minutes, clipped to client/AWS-session
expiry, with no automatic retry after an uncertain write.

The normal `a69503f8` / `ffe0fbe4…` build and connected stock-Boto3 acceptance
passed: all five actions, eight signed requests and eight ACK/audit results in
62.391 seconds with no automatic retries, against a synthetic provider only.
The matching pair is deployed as app `5ae9ae8b…` / gate `53fd9a79…`. The existing
16 destinations and permissions are unchanged, with a 32-origin cap; no AWS
destination or grant was automatically enabled. Public-route/browser checks are
separate and pending. The four retained artifact slots can be reclaimed by explicit
eligible-terminal retirement, never for uncertain/possible-send records; AWS
images and owner/audit history remain untouched. The 1,024-parent lifetime stop
is removed in favor of retained indexed history with ten-record pages. ECR action
and audit events use the existing separately configured notification slots; no
automatic enablement, replay or live receiver proof follows. Focused component
checks passed; locally delivered MCP tools still exclude ECR. See the new guide
and example for the current ordinary contract.

The ordinary example now uses Boto3/Botocore 1.43.114, urllib3 2.8.0 and Requests
2.34.2 with all dependencies pinned. Its eleven focused checks pass against that
maintained environment. The older SDK versions in the historical evidence below
are not the current installation recommendation. The connected result above uses
the maintained SDK; real-provider acceptance remains separate.

## Historical foundation and future native design

The sections below retain the earlier component evidence and native-assurance
design. Hardware/YubiKey enforcement remains a future target, not a claim made
by the ordinary host-trusted implementation.

Historical status: **signing, exact-image preparation, sealed process-local content and
bounded publication planning tested; storage-only credential management
implemented; proxy publication is not implemented or accepted**. This document proposes a
bounded operator-development feature,
not AWS-wide SDK support, a production credential service, or completion of the
native pilot. No AWS requests were sent. The checks exercise local SDK
serialization, signing and simulated responses, not a working AWS connection.

The [exact-image preparation component](operator-ecr-image-preparation.md)
adds actual whole-artifact byte validation and unsigned local copying before
the future approval request. It does not change JIT authority, make the SQLite
demo capable of native approval, or activate an AWS destination or permission.
The [publication planner](operator-ecr-publication-plan.md) supplies bounded
request/response state proposals over that verified image. Durable authority,
currentness checks and actual proxy dispatch remain separate unfinished work.

## Verified foundation (2026-10-10)

[`aws_ecr_signing.py`](../serverware/aws_ecr_signing.py) and
[`aws_ecr_signing.rs`](../data-plane/decision-gate-rs/src/aws_ecr_signing.rs)
implement a closed five-action ECR SigV4 primitive, exact outbound request
comparison, and separate freshness checks. They are **not wired into credential
storage, policy authorization, the proxy dispatch path or the operator UI**.
Signing opaque body bytes does not authorize their JSON contents. A caller must
still supply trusted clocks and recheck current authority, credential generation,
expiry and the request deadline at dispatch; the primitive is not an atomic-send
or revocation barrier.

The retained local checks are:

- Six Boto3/Botocore **1.34.46** SDK-contract groups passed. Five ordinary ECR
  methods prepared requests with explicit public dummy credentials; an audit
  guard denied socket/DNS access, and a sentinel stopped each request before
  HTTP dispatch. No simulated response was presented as a successful upload.
- Ten Python signer groups passed across the initial run and one corrected
  empty-body oracle rerun. The correction accommodates Botocore representing an
  empty prepared body as `None`, while checking the original bytes and requiring
  exact equality for every nonempty body. This was not a full corrected rerun.
- Eleven standalone Rust groups passed using pinned Rust **1.88.0**, including
  twelve literal Botocore signature/canonical-request vectors. The helper ran
  without network access; this was not a new decision-gate build or activation.

Reproducible test sources:
[`test_aws_ecr_signing.py`](../scripts/test_aws_ecr_signing.py),
[`test_aws_ecr_sdk_contract.py`](../scripts/test_aws_ecr_sdk_contract.py), and the
Rust module's embedded tests. Local receipts are retained under
`serverware-operator-workspace-evidence/aws-ecr-signing.EWMxu1ty` (outside Git).
The integration and real-provider acceptance gates below remain open.

## Product flow and existing source boundary

The intended flow is: save an AWS credential, create/select an application,
choose an ECR permission for one account/region/repository, then copy standard
SDK proxy/trust configuration. Do not ask for response field lists. Application
authentication remains separate from provider credentials and public SDK dummy
credentials. Saving a credential or application grants no AWS access by itself.

The [README ECR example](../README.md#example-yubikey-approved-aws-tee-image-update)
requires exact-image, request-triggered hardware approval and
explicitly leaves its integration open. The
[workspace requirements](operator-workspace-requirements.md#what-the-original-examples-imply)
distinguish operation bundles from generic header replacement and optional
content restrictions. Current `CredentialInput` in
[`operator_catalog_inputs.py`](../serverware/operator_catalog_inputs.py) only
admits bearer/header secrets; the separate `AwsSigV4CredentialInput` implements
[encrypted AWS tuple management](operator-aws-credentials.md), without granting
AWS access. [`policy_engine.py`](../serverware/policy_engine.py)
`_secret_for_injection`/`_inject_credential` are not an AWS signing interface.

Default permissions must be narrow, explicit presets, not `service:*` or an IAM
administrator policy. Schedules, quotas, content restrictions and human approval
are separate optional choices for a new ordinary-client permission. Existing
policies keep their restrictions; “optional” does not remove the README's
required YubiKey approval from that original publication journey.

## Credential custody and signing contract

- Implemented storage-only: a versioned AWS credential type with access key ID plus secret access key,
  optional session token and mandatory expiry when importing temporary access.
  The complete tuple stays in the existing encrypted credential store; catalog
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
not retrospectively authorize earlier uploads. The selected preparation and
publication design preserves that requirement; its authoritative continuation
is not yet implemented. An approval checkbox cannot substitute for it.

Docker registry authentication uses a different
[ECR authorization-token workflow](https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html).
A Boto3 API fixture does not prove Docker push compatibility; do not return a
real registry token to clients or advertise Docker support from this slice.

## Implementation and acceptance gates

1. The isolated AWS credential/catalog lifecycle is implemented, but it refuses
   all release and grants. Still add ECR policy modules, closed schemas,
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
