# Operator demo regression checkpoint — October 10, 2026

This is isolated fixture evidence, not a deployment record. The running demo
was not changed. Notifications were separately committed at `ce0eea92`; the
older immutable candidate tested here does not contain that implementation.

## Exact retained-state upgrade: passed

The network-isolated, read-only-source harness exercised:

- Previous application: `1deb896c35d660eb665ac57ad35789c22280edf9`.
- Candidate application: `8a8d4b06678193d51e2b875a471cbeb7cb1b5ddf`.
- Fresh synthetic SQLite data only; no live database, proxy gate or provider.
- Two credentials, three applications and four access rules, including retained
  revocation, key generations, Basic/Bearer settings, projected/preserved JSON,
  insert/exact replacement and an explicitly fixture-aged expired application.
- Exact retained authority, signed policy, audit/nonces and non-SQLite files
  across upgrade and reopen; integrity checks; no disabled-feature schema or
  custody initialization.

The single connected test passed in 27.288 seconds. The container exited zero
without OOM, including the runner's complete source-manifest checks before and
after the test. Both archives were independently checked against their exact
Git blobs. The test runner's temporary `result.json` did not survive container
exit; the retained evidence is the test log, container inspection and frozen
harness, not a recovered JSON receipt.

Evidence directory:
`serverware-operator-workspace-evidence/retained-ui-upgrade.A2wXUDU2`.

The expired application was created with a module-local synthetic clock. This
does not establish natural token expiry or proxy enforcement at expiry.

## Exact application/gate stock-client regression: failed checkpoint

The same immutable candidate was paired with the unchanged normal gate:
`e7529b4484228ebdbf2be1ebb471a80a78a3e127673f0bc6dcb4921db92489e2`.
The fixture had its own internal-only network, fresh data, synthetic trust
roots and no published ports. Actual container isolation, gate executable,
shared publication lock, checker network and curl executable were checked.

The one-shot checker observed four successful Requests/curl/Bearer requests,
eight authentication refusals and four TLS controls. Its final audit checkpoint
then failed with `audit changed after drained checkpoint`; exit status was one.
The run is **not accepted**, and it was not automatically repeated.

A read-only post-run projection found 61 audit records, including 31 scoped
lease-issuance records: 16 `generationMetadata` and 15 `dispatchSecret`.
The normal development gate renews hot lease scopes independently of its audit
delivery queue. Therefore zero gate queue depth does not establish that the
application's directly committed lease-audit log has stopped growing. Any
checker correction must preserve every prior row and fully validate the final
inventory, identities, policy, binary and credential generation; merely
ignoring added rows is not an acceptable fix.

The checker now revalidates a fresh complete snapshot after the first drained
checkpoint. It requires every previously observed row/hash to remain, permits
only additional fully validated lease records, and preserves intermediate
history if another drain is needed. Ten pure regression groups pass, including
wrong bindings/generations, changed or missing history, unexpected added events,
queue failure, saturated views and failed chain verification. This is a
checker-only correction: the failed runtime run remains failed, and a fresh
isolated run with the separately pinned corrected checker is still required.

Evidence directory:
`serverware-operator-workspace-evidence/private-retained-pair.mw9wyo1O`.
It retains the failed checker output, actual isolation/container/network
receipts, safe audit metadata and lease projections. An initial empty diagnostic
projection used an incorrect event-type prefix; it is retained separately and
was not used to validate lease fields. The corrected reader made no changes.

The fixture services were stopped, their temporary containers/network removed,
and their data and evidence retained. No live token was rotated or renewed, no
saved demo resources were deleted, and no provider or native hardware was used.

The live UI rollout remains pending its own reviewed backup, retained-state and
browser verification. This record does not authorize a native pilot restart or
turn isolated notification tests into live notification acceptance.
