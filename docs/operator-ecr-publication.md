> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Publish one reviewed image to ECR

**Status: normal build, connected stock-Boto3 acceptance and paired deployment
passed; real AWS remains unverified.** Source `a69503f8` with normal
proxy `ffe0fbe4…` completed all five actions in **62.391 seconds** against the
isolated synthetic provider: eight exactly signed requests, eight owner ACKs,
eight proxy ACK/release audit records and no automatic retries. The embedded
schema correction is included in this successful run; the earlier failure
remains retained, not reported as a pass.

The app-only UI follow-up `15ef645c` is deployed as app `86fde364…`, retaining
gate `53fd9a79…` and normal Rust `ffe0fbe4…`; all four services are healthy.
The existing 16 destinations and saved permissions are
unchanged; the destination cap is now 32. No AWS destination or publication grant
was automatically enabled. The artifact root and 8-GiB app memory ceiling are
installed. Verified-TLS public checks passed: console 302 to SSO, lab health 200
and all six Gatus conditions; the proxy's ordinary GET returned 404, not a CONNECT
test. Six read-only internal-app browser GETs confirmed the empty ECR list,
15 ECR audit types and four separate notification slots without errors or mobile
overflow. These checks performed no publication, notification delivery, provider
call or human SSO login. See the [project tracker](project-completion.md).

This ordinary, host-trusted workflow keeps AWS credentials in Catchplate and
uses the [stock Boto3 example](../examples/ecr-publish-python/README.md). It is
not `docker push`, registry login, an image build, generic AWS SDK access or a
TEE/YubiKey approval. An administrator with full host control can bypass it.

## Operator setup

For a new container deployment, enable the optional
[`docker-compose.ecr.yml`](../docker/catchplate-operator-demo/docker-compose.ecr.yml)
overlay while retaining every existing Compose layer. Precreate the empty
`/data/ecr-artifacts` directory in the persistent app volume, owned by the app
UID/GID `10001:10001` with mode `0700`. The overlay sets the app's memory ceiling
to **8 GiB**: at most four active 1-GiB sealed images plus two transient captures
must fit alongside the application and request buffers. The ordinary 1-GiB app
limit cannot support the advertised image size. This is a ceiling, not a memory
reservation; do not change CPU, other services or persisted resources.

1. Save an AWS access-key pair in **Credentials**, or the complete temporary
   tuple including session token and future expiry. Imported sessions do not
   renew automatically. Saving a credential does not test AWS access.
2. Select the exact client and create an **ECR publication** permission for one
   AWS account, standard region, existing repository and image tag. Human review
   of the whole staged image is mandatory for this preset. Only one active ECR
   permission is allowed per client and region; all regional ECR calls use
   `POST /`, so overlapping routes cannot safely select another credential.
3. Approve the exact regional destination
   `https://api.ecr.<region>.amazonaws.com` and wait for the matching application,
   proxy and policy capability. China/GovCloud, FIPS, alternate endpoints and
   arbitrary AWS services are outside this profile.
4. Download the private client JSON and interception CA. The JSON contains the
   Catchplate client login and exact scope, **not AWS keys or session tokens**.
   Keep it owner-only and out of Git/logs. Relative CA paths resolve beside the
   JSON; the optional outer-proxy CA is separate from interception trust.

## Stage, review, then explicitly publish

Prepare one selected OCI or Docker schema-2 manifest and every referenced
config/layer blob using the [image preparation command](operator-ecr-image-preparation.md).
The input is a `blobs/sha256/<digest>` directory, not a Docker-save tar archive.
Preparation validates original bytes and digests; it does not scan, extract,
execute or establish the safety of the image. Multi-platform indexes are not
supported.

Run the example's `stage --config … --stage …` command. It re-verifies and seals
the local bytes, creates a publication, uploads the original manifest and unique
blobs to Catchplate, and requests review. **Staging makes no ECR request.** Save
the exact publication UUID printed first, even if a later staging call fails.
Use `status --config … --publication <uuid>` to inspect that record, not to
automatically retry or create a replacement.

In **Pending actions**, the authenticated administrator selects that publication
and reviews the image digest, verified blob inventory, client, credential
generation, policy, account, region, repository and tag. Approve or deny that
exact intent. Approval alone sends nothing to AWS and does not verify image
safety or AWS entitlement.

The client must then deliberately run:

```sh
python -I -B examples/ecr-publish-python/publish.py publish \
  --config /private/catchplate-client.private.json \
  --stage /absolute/private-parent/image-stage \
  --publication <exact-publication-uuid> --execute-write
```

Use the example's prepared Python environment and full checkout. The command
checks the saved publication and local artifact, explicitly activates that UUID,
then uses unmodified Boto3 methods. It never selects the latest approval. The
machine control API uses the client login at the proxy's
`/v1/ecr/publications`, not a human SSO session or administrator token.

| SDK action | Required binding |
| --- | --- |
| `BatchCheckLayerAvailability` | Only verified unique config/layer digests for this account/repository. |
| `InitiateLayerUpload` | One missing blob upload at a time; retain the returned upload ID and supported part size. |
| `UploadLayerPart` | Consecutive offsets and exact staged bytes. |
| `CompleteLayerUpload` | The fully uploaded blob's exact digest. |
| `PutImage` | Original manifest bytes, media type, image digest and selected tag, after every blob is ready. |

The SDK's publication UUID marker is a selector, not authorization. Catchplate
checks current permission/policy and credential generation before signing each
exact request. The custody-side signer returns an **encrypted exact-request
headers lease** to the proxy, not the AWS credential tuple. Possible-send state
is committed before signed headers leave custody; the proxy validates the
binding before final dispatch. Generic AWS credential leases remain closed.

## Deadlines, outcomes and retained limits

The original publication lifetime is at most **30 minutes from creation**, clipped
to the earlier client-token or AWS-session expiry. Review, activation, individual
calls and process recovery do not renew its wall-clock/monotonic deadline.
The client and proxy disable automatic retries. The example does not resume a
failed, denied, expired, suspended or uncertain publication.

Only a validated, correlated `PutImage` acknowledgment advances the publication
to its published outcome and audit record. Approval, staged bytes or an earlier
successful layer upload is not publication success. A lost response or ambiguous
write may already have affected AWS: preserve the publication and inspect its
status, audit and provider state. Do not replay an uncertain activation/upload,
treat a duplicate-image error as success or delete evidence to try again.

Limits include four active publications and **four retained artifact stages**.
Each stage permits up to 1 GiB unique blob content; manifest/config limits are
4 MiB, individual layers 512 MiB and layer references 128. A retained stage uses
its slot until explicitly retired, even after publication or failure. The former
1,024-parent lifetime stop is removed; publication history remains retained,
with indexed pages of at most ten records and explicit **Load more publications
(read only)** controls. Loading history never selects a publication or starts a
write automatically.

### Retire local staging files

In the selected publication's terminal detail, choose **Retire staged files**,
then **Confirm retire staged files**, or choose **Keep staged files**. Only the
authenticated administrator can retire a `published`, `denied`, `expired` or
`failed` publication with no `possible_send` child. `uncertain` publications are
always refused and continue occupying their retained slot.

Retirement durably records intent before deleting only that publication's local
staging files. It frees a slot without changing the AWS image, publication
outcome, artifact commitment, acknowledged checkpoint or audit history. It does
not delete or reset the parent record. Keep your original local image/backup if
you need the bytes later; retirement removes Catchplate's stored copy.

If the response is lost, use **Check retirement status (read only)**. Only a
server-reported pending cleanup permits **Retry retiring staged files**, followed
by another explicit confirmation. That resumes local deletion, never upload or
publication. A completed retirement is idempotent. There is no automatic garbage
collection, historical-row deletion or manual-filesystem workaround.

### Separate action and audit notifications

The source now projects 15 closed `operator.ecr_publication.*` audit event kinds,
including retirement, into the existing independently configured Slack/webhook
slots. Only `staged` produces an action-required alert. The pending owner,
reviewer, source bindings and original deadline are rechecked before delivery;
an obsolete review alert is suppressed without erasing its historical audit.
The authenticated console link is a locator, not a decision capability.

Configure each action/audit slot and its event filters explicitly; this adds no
automatic enablement or historical replay. Uncertain publication retains its
do-not-retry warning; uncertain notification delivery is not automatically resent.
Retirement messages describe local cleanup, never AWS deletion, and removal
counts cover that cleanup attempt only. Focused notification checks passed, not
live Slack/webhook delivery. Connected ECR publication passed against a synthetic
provider and the matching pair is deployed; real AWS remains unverified. The locally
delivered MCP tools still exclude ECR publication.

## Evidence boundary and implementation

The connected receipt and successful cleanup terminal are retained at
`/srv/catchplate-fast/projects/serverware-operator-workspace-evidence/ecr-gate-connected.K2JfMIlG`.
`result.json` SHA-256:
`cf4c6ce389544af4bda6b5e11ab6d868de2ee566d3bcf97ce7d5f0fcff8cc9a1`;
`terminal.json` SHA-256:
`d701560c0fbe251d2a55a0997522882aa8e48c90a50d1e12f830630bbe91b05a`.
Successful deployment continuation:
`/srv/catchplate-fast/homelab_data/serverware-ecr-rollout.ozBlDVMm/continuation/result.json`
(SHA-256 `5cf7f02e96327f925fc315bc19e39fda87ee5adf305bc3d986417da57634c42b`).
A stale fixture-only checker stopped the original rollout; corrected read-only
checker `8d3e866f` allowed the 11.285-second narrow continuation without repeating
the backup or restarting the app/gate. The original failure remains preserved.
The subsequent `15ef645c` app-only public/browser checks are separate receipts:
`/srv/catchplate-fast/homelab_data/serverware-public-15ef.1EzZXD/public-verification.json`
and `/tmp/serverware-ecr-notifications-readonly.GzHa2v/ui15.jAQjkc/receipt.json`.
The connected acceptance used the normal proxy and stock Boto3 with a synthetic provider, not real
AWS. The separate offline tests intercept SDK sends and are component evidence,
not additional connected acceptance. Core source:
[permission](../catchplate/operator_catalog_ecr.py),
[artifact storage](../catchplate/operator_ecr_artifacts.py),
[publication owner](../catchplate/operator_ecr_publications.py), and
[signing lease](../catchplate/operator_ecr_signing_api.py).
The [historical native planning work](operator-ecr-publication-plan.md) remains
a separate future-assurance target, not a prerequisite silently satisfied by
ordinary host-trusted approval.
