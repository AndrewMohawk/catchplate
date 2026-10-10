# Configure proxy destinations without resetting the catalog

The proxy operator owns the list of permitted HTTPS destinations. Allowing a
destination is not an application permission: an app still needs its own active
identity, saved connection and explicit access rule. This workflow changes only
that deployment-level list, not provider accounts, credentials or rule contents.

The retained operator store pins its destination configuration. Editing the
environment alone must not silently replace that pin or force the operator to
discard saved resources. The destination workflow prepares an explicit change
against the current settings, catalog revision and signed-policy hash. A later
controlled cold start consumes exactly that prepared change.

## Operator workflow

1. In **Proxy setup → Proxy destinations**, review the effective destinations.
   Enter the proposed complete list of public HTTPS origins. Review the additions
   and removals before choosing **Prepare change**.
2. Preparation retains a durable operation ID. It does not change current
   permissions, contact a provider, alter deployment files or restart anything.
   If the response is lost, check that operation's result; do not repeat the POST.
3. The deployment owner stops the old app/gate writers and takes a fresh,
   stopped-consistent recovery copy. Configure **both** app and gate with the
   exact prepared origin list, preserving their other settings and retained data.
   Then use the existing controlled paired-restart procedure.
4. A read-only preflight checks the retained review before database initialization.
   The activation transaction checks it again before changing the settings pin,
   recording the activation receipt, advancing the catalog revision and appending
   its audit event together.
5. Verify the matching running app/gate and loaded policy before reopening the
   console. Only then create any desired application grants and test the actual
   provider workflow. Activation alone is not proof of provider connectivity.

**Prepared**, **activation committed**, and **working provider request** are
different outcomes. The browser does not control Docker, restart the application,
write environment files or claim that pending configuration is already active.
Cancellation is a separate explicit operation and does not delete its history.

## Scope and preservation

The target contains 1–16 unique canonical HTTPS origins. Public origins use
port 443, without paths, URL credentials, query strings, wildcards or literal IP
addresses. This is not a private-network routing editor. The synthetic fixture
origin and its CIDR stay unchanged.

An origin used by an active saved rule or the retained signed policy cannot be
removed. Revoke the relevant permissions explicitly first. A configured Google
profile must retain its Gmail origin and exact provider binding. Pending Google
setup and destination setup cannot overlap. Where an empty policy uses the
first configured origin for its permanently expired placeholder route, that
origin and its position remain protected to preserve the signed policy bytes.

Preparation and activation preserve credential ciphertexts and generations,
applications and token verifiers/expiries, access rules, existing audit history,
signed policy bytes/sequence/high-water, and CA/key material. They do not rotate
tokens, renew expired applications, broaden saved rules or create provider
connections. Catalog changes after preparation make the review stale rather
than silently updating its authorization.

## Administrator API

| Route | Purpose |
| --- | --- |
| `GET /api/operator-demo/proxy/upstreams` | Review current settings and change eligibility. |
| `POST /api/operator-demo/proxy/upstreams` | Prepare the exact proposed destination list. |
| `GET /api/operator-demo/proxy/upstreams/{operation_id}` | Recover the owning administrator's retained result. |
| `POST /api/operator-demo/proxy/upstreams/cancel` | Explicitly cancel a pending change against current review pins. |

Preparation accepts only `operation_id`, `allowed_upstreams`,
`expected_settings_digest`, `expected_revision` and `expected_policy_hash` in at
most 8192 bytes. Cancellation accepts `operation_id`, `expected_revision` and
`expected_policy_hash` in at most 2048 bytes. Routes retain the administrator,
exact-Origin, strict-JSON and no-store boundaries. No endpoint accepts secrets,
file paths, shell commands, arbitrary environment assignments or restart inputs.

## Verification and deployment boundary

Source implementation and focused isolated acceptance passed on October 10,
2026. The workflow is now deployed as immutable app `577badff`, paired with the
verified `2bfe5e38` proxy executable. An actual internal browser made 13 read-only
GETs and exercised **Review destination settings** without preparing a change.
Its desktop/mobile screenshots and unchanged-state checks passed. The retained
allowlist remains fixture-only; no live destination change was prepared or
activated. See the [paired rollout evidence and limits](../docker/serverware-operator-demo/README.md#current-notification-enabled-deployment).

- **8/8 connected groups** use real application ASGI handlers, retained SQLite,
  encryption, signing, publication and fresh-process cold startup. They cover
  exact activation and second restart, protected origins, stale/unprepared
  refusal before database initialization, actor-owned lost-acknowledgement
  recovery, preparation/activation audit rollback and Google setup exclusion.
- The activation group preserves a real saved, disabled notification webhook:
  all five notification tables, its separate custody key bytes/inode/mode, and
  successful decryption remain unchanged. No notification worker or send runs.
- **6/6 existing Google setup regression groups**, **23/23 notification-event
  checks**, **5/5 API source-contract checks**, **14/14 pure UI groups** and
  **12/12 asset checks** pass.
- **6/6 intercepted browser groups** cover rendered desktop/mobile controls,
  prepare/cancel, reload and GET-only uncertain-outcome recovery, with inspected
  screenshots. These intercepted responses are UI evidence, not a
  browser-to-live-backend acceptance claim.

The connected and Google suites ran in separate bounded, network-none containers
using cached application image `ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01`,
with exit 0, no OOM and unchanged source hashes. Retained local logs, process
states and source hashes are under
`../serverware-operator-workspace-evidence/upstream-setup.CVVfT8/` relative to the
checkout. Browser screenshots are under `/tmp/serverware-upstreams-browser-vA61Mo/`.

The rollout does not authorize or establish a live destination change. The
current demo still permits only its synthetic upstream, and the waiting native
pilot is unchanged. Actual native commissioning, provider access and production
acceptance remain separate. Matching running app/gate and retained policy were
verified, but activation of a different origin list and actual provider traffic
remain untested on this live deployment.

Use the [retained-state maintenance procedure](../docker/serverware-operator-demo/README.md#approval-and-state-preservation-gate),
preserving the separate notification custody directory with its corresponding
database whenever a destination has been saved there. Historical rollout scripts
contain old pins and must not be rerun as current deployment instructions.
