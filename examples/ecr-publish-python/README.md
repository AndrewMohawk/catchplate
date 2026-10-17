# Publish one reviewed image to ECR with Boto3

This example stages an exact image in Catchplate, requests a host-trusted review,
then uses **stock Boto3** to publish that explicitly selected image through the
HTTPS proxy. AWS keys stay in Catchplate. The public dummy AWS credentials in
the script are SDK signing placeholders, not provider credentials or the
Catchplate client login.

This is an ECR API workflow, **not `docker push`**, Docker registry login, an
image build, a multi-platform/index upload, or TEE/YubiKey enforcement. Someone
controlling the Catchplate host remains trusted. The source tests below do not
establish real AWS acceptance or availability in a particular deployment.

Connected verification with the normal `a69503f8` / `ffe0fbe4…` proxy and stock
Boto3 passed in 62.391 seconds against an isolated synthetic provider: all five
actions, eight exactly signed requests, eight correlated ACK/audit records and
no automatic retries. The `15ef645c` app-only UI follow-up is now deployed with the
same proxy; public and read-only browser checks passed without provider calls,
notification delivery or human SSO login. Existing permissions remain unchanged,
with no automatically enabled AWS access. This is not real AWS, Docker
push or hardware acceptance. See the [current verification record](../../docs/operator-ecr-publication.md#evidence-boundary-and-implementation).

## Setup

Use Linux with Python 3.12 and the full repository checkout: the client reuses
Catchplate's existing image verifier, sealed-content holder, and protocol parser.
Install the reviewed dependencies in a private environment before adding client
credentials:

```sh
python3.12 -m venv .venv-ecr
.venv-ecr/bin/python -m pip install -r examples/ecr-publish-python/requirements.txt
```

The maintained SDK is pinned to Boto3/Botocore 1.43.114, with urllib3 2.8.0 and
Requests 2.34.2. All direct and transitive dependencies are pinned and checked at
startup; use this environment rather than older system SDK packages. urllib3
2.8.0 includes the [HTTPS proxy TLS and response-streaming security fixes](https://urllib3.readthedocs.io/en/stable/changelog.html).
The example continues to use [documented SDK proxy/retry configuration](https://docs.aws.amazon.com/boto3/latest/guide/configuration.html),
without transport patches.

In Catchplate, save your AWS credential, select an existing application, and add
an ECR publication permission for one account, region, existing repository and
image tag. Download its private client JSON and the public interception CA.
The AWS credential itself must **not** be in the download or the job environment.
Restrict the downloaded JSON to its owner, for example `chmod 600
catchplate-client.private.json`, and keep it out of Git and logs.

CA paths are relative to the downloaded JSON. `ca_file` verifies intercepted ECR
TLS. Optional `proxy_ca_file` verifies the outer HTTPS proxy/control endpoint;
otherwise the SDK's default public CA bundle is used. Verification is never
disabled. The control URL must equal the configured proxy origin plus
`/v1/ecr/publications`; it does not use the human login/SSO or an administrator
token. The client supplies the application login as HTTP Basic authentication
there, and as CONNECT proxy authentication for SDK calls.

## 1. Prepare exact local bytes

Your source directory must contain `blobs/sha256/<digest hex>` files for one
selected OCI image manifest or Docker schema-2 manifest and every referenced
config/layer blob. This is an OCI-layout-style blob directory, not a Docker-save
tar archive. Select the manifest digest explicitly; no tag or index is resolved.

The destination must not exist; its existing parent must be private (0700) and
owned by you. From the repository root:

```sh
.venv-ecr/bin/python -B -m scripts.prepare_ecr_image_artifact \
  --source /absolute/path/to/image-layout \
  --manifest-digest 'sha256:<exact-manifest-digest>' \
  --destination /absolute/private-parent/new-image-stage
```

Preparation makes no network calls, extracts or executes nothing, and preserves
original manifest bytes. It checks content
integrity, **not** whether the image is runnable or safe. Limits: 4 MiB
manifest/config, 512 MiB per layer, 1 GiB unique blob content, 128 layer references.

## 2. Stage in Catchplate and request review

```sh
.venv-ecr/bin/python -I -B examples/ecr-publish-python/publish.py stage \
  --config /private/catchplate-client.private.json \
  --stage /absolute/private-parent/new-image-stage
```

The script re-verifies the local stage and seals the actual bytes for this run.
It creates one publication, uploads the original manifest and all unique blobs
in sequential chunks of at most 4 MiB, then submits the completed image for
review. This command performs **no ECR requests**.

It prints JSON lines: the newly created publication ID first, then the final
`awaiting_review` status. Save that ID even if a later staging request fails.
Review the exact image digest, account, repository and tag in the Catchplate
console. No background polling or automatic continuation occurs.

```sh
.venv-ecr/bin/python -I -B examples/ecr-publish-python/publish.py status \
  --config /private/catchplate-client.private.json \
  --publication <exact-publication-uuid>
```

## 3. Explicitly publish the approved image

This step writes to the configured AWS repository. Run it only when you intend
to publish the selected image/tag and have reviewed its approved status:

```sh
.venv-ecr/bin/python -I -B examples/ecr-publish-python/publish.py publish \
  --config /private/catchplate-client.private.json \
  --stage /absolute/private-parent/new-image-stage \
  --publication <exact-publication-uuid> \
  --execute-write
```

The client checks the exact publication, application, permission, policy, scope
and artifact identity, then explicitly activates it. It never selects the most
recent approval. Changed local bytes, expired credentials, unapproved state or
scope changes fail before SDK upload.

The SDK performs these five actions, using the exact configured account and
repository on every call:

1. `BatchCheckLayerAvailability`, in batches of at most 100 digests.
2. `InitiateLayerUpload` for each missing unique blob, including the config blob.
3. `UploadLayerPart` sequentially using the advertised supported part size,
   consecutive inclusive offsets and the exact staged bytes.
4. `CompleteLayerUpload` for that exact blob digest.
5. `PutImage` with the original manifest, exact media type, tag and digest.

Already available blobs are not uploaded again. One upload is active at a time.
The publication ID is attached with the documented SDK `user_agent_extra`
setting as `CatchplatePublication/<uuid>`; it selects a publication but is not
authorization. There are no SDK event hooks or patched production transports.
The proxy checks approval/currentness and replaces the dummy AWS signature.

All calls disable automatic retries. The client has finite call/deadline limits
and checks acknowledgments; the proxy enforces bounded ECR responses (stock
Botocore itself buffers nonstreaming responses). A failed, denied, expired,
suspended, or uncertain publication is not resumed by this command. Provider
errors, lost responses, duplicate-image errors and ambiguous writes are not
reported as success. **Inspect the saved publication and audit log instead of
blindly repeating a stage, activation, or publication.**

## Offline checks

```sh
.venv-ecr/bin/python -B examples/ecr-publish-python/test_publish.py
```

Focused tests verify config/CA and identity checks, complete local staging,
immutable byte retention, explicit approval/activation gates, direct Basic-auth
control requests, sanitized failures, and all five real SDK serialization paths.
Only the test intercepts the SDK send boundary and supplies synthetic responses;
sockets and subprocesses are prohibited. No provider keys, live proxy,
container build, cloud upload, or Docker-push acceptance is involved.
