# Publish one reviewed image to ECR

**Status: source implementation under integration, not deployed or verified
against real AWS.** The matching cached Rust build passes; connected proxy
acceptance and deployment are still pending. The recorded live app remains `1eff1fd` with proxy `48953fea…`
and a 16-origin limit; the new 32-origin source limit is not live yet. Check the
[project tracker](project-completion.md) before relying on this capability.
The latest connected attempt reached the control plane but exposed a missing
`$defs` object in the proxy's embedded ECR schema. The correction requires a
warm rebuild; compilation alone did not establish that the gate could start.

This ordinary, host-trusted workflow keeps AWS credentials in Serverware and
uses the [stock Boto3 example](../examples/ecr-publish-python/README.md). It is
not `docker push`, registry login, an image build, generic AWS SDK access or a
TEE/YubiKey approval. An administrator with full host control can bypass it.

## Operator setup

For the container deployment, enable the optional
[`docker-compose.ecr.yml`](../docker/serverware-operator-demo/docker-compose.ecr.yml)
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
   Serverware client login and exact scope, **not AWS keys or session tokens**.
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
blobs to Serverware, and requests review. **Staging makes no ECR request.** Save
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
  --config /private/serverware-client.private.json \
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

The SDK's publication UUID marker is a selector, not authorization. Serverware
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
you need the bytes later; retirement removes Serverware's stored copy.

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
counts cover that cleanup attempt only. Focused component checks passed, not
live Slack/webhook or AWS delivery. Connected acceptance and deployment remain
pending. The locally delivered MCP tools still exclude ECR publication.

## Evidence boundary and implementation

This guide describes inspected source, not new test execution or a live upload.
The example's offline tests intercept SDK sends and use synthetic responses;
they do not establish connected proxy or real-provider acceptance. Core source:
[permission](../serverware/operator_catalog_ecr.py),
[artifact storage](../serverware/operator_ecr_artifacts.py),
[publication owner](../serverware/operator_ecr_publications.py), and
[signing lease](../serverware/operator_ecr_signing_api.py).
The [historical native planning work](operator-ecr-publication-plan.md) remains
a separate future-assurance target, not a prerequisite silently satisfied by
ordinary host-trusted approval.
