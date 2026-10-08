# Operator audit retry integration: 2026-10-08

## Change and scope

The immutable legacy audit retry implementation from `9ed47022` and `a2eab4b3`
is integrated on operator source base
`3f145fd7250cede66f4f5abfff3918edd790fbe9`.
New operator/native modules and existing classification/Signer fixes are
preserved rather than replaced with the older audit branch.

Once a legacy audit batch may have reached the receiver, the sender retains
its exact serialized body and event IDs until an authenticated acknowledgement
resolves it. Fresh events cannot merge with that original, and a later signed
413 cannot split an earlier possibly committed batch. Failures before sending
are distinguished from uncertain transport outcomes; a definitely rejected
batch can still split. Required and optional in-flight events share the queue
capacity bound. Health includes pending retry batch/event counts.

This is bounded **in-process, non-production retry ownership**, not a durable
crash-recovery journal. Measured/native audit retains its separate owner and
transport. This checkpoint does not change or restart a deployed service,
establish live end-to-end sender/receiver operation, or close native-pilot or
production acceptance.

## Exact Rust verification

The frozen input inventory contains **714 files**: Cargo manifests, Rust source,
and embedded compile-time inputs. It is not a manifest of the entire checkout.
The dirty audit additions are included explicitly. Source checks before and
after the test batch matched; the same manifest was checked again before commit.

- [714-input manifest](../../serverware-operator-audit-evidence/serverware-operator-audit-build.p9RGBK/source.sha256):
  `d25106e1fc21979b6833e89f99f19107fa4a1851d4a8f431aa18bb7d0c92f491`
- [Exact 39 test names](../../serverware-operator-audit-evidence/serverware-operator-audit-build.p9RGBK/selected-test-names.txt):
  `c2f45d8193f70da9adc305addf0cbfb7f0314a35299f0a1d285d1f563eedcdef`
- [Test receipt](../../serverware-operator-audit-evidence/serverware-operator-audit-build.p9RGBK/test-receipt.json):
  `969593791709bfb311e0e471abd039ada8da667a55bd901f37b165c7fda5dfb0`

The batch ran from `2026-10-08T19:22:32Z` to `19:29:56Z`, using Rust 1.92.0,
the release test profile, locked/offline dependencies, four Cargo jobs and one
test thread. Bounds were four CPUs, 12 GiB memory, no swap, 128 tasks, 45 minutes,
nice 10 and idle I/O priority. It compiled the test executable once, then ran
the named cases individually without recompiling each filter.

| Exact test group | Passed |
| --- | ---: |
| Immutable retry and typed send certainty | 8 |
| Existing audit, ACK, reservation and release controls | 12 |
| Operator development profile | 10 |
| Existing synthetic development sandbox | 6 |
| Development/native leaf-cache separation | 3 |
| **Total** | **39** |

All 39 retained individual logs report one passed case and zero failures or
ignored cases. The test executable SHA-256 is
`e351763ae7eb2f8f8fc852713b7bcaccd8da3408163be8ef1e8459b7e38a978b`.
This is a targeted regression batch, not the complete Rust suite. This test
checkpoint did not build a deployable release executable; any subsequent
release build requires its own evidence and is not implied by this receipt.

## Python receiver and classification verification

The [isolated receiver evidence directory](../../serverware-operator-audit-evidence/receiver-20261008-5AZVl5/receipt.json)
retains the receipt, logs, inventory review, before/after manifests and checked
`SHA256SUMS`. Receipt SHA-256:
`34214c7de64e6a0339f198c6bd23c9066faa9062bb10267f506ad55bebba8d5c`.

Checks used the cached dependency image
`sha256:ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01`,
with network disabled, read-only source/root, UID/GID 10001, one CPU, 1 GiB
memory with no additional swap, 96 PIDs, dropped capabilities and private
ephemeral SQLite storage. No live state was mutated.

- `python -B scripts/test_internal_service_auth.py --audit-retry-only` passed:
  **11 direct asynchronous route requests**, **4 appended rows**,
  **4 immutable replays**, **5 rejected requests**, exact-body acknowledgement
  binding, and a complete verified SQLite audit chain. It uses the real parser,
  service-token check and receiver transaction, not a mock store. It does not
  exercise HTTP/TLS transport or signed-ACK middleware.
- `python -B scripts/test_authority_api_classification.py` initially failed one
  stale fixture assertion: the operator inventory contains **156**, not the
  older **147**, dedicated-workflow operations. Only that expected count and
  its explanatory comment changed. The corrected **6 tests passed**, retaining
  disjointness, completeness, negative checks, generic-route denial prefixes,
  and actual full application import. No application guard was relaxed.
- Existing `python -B scripts/test_legacy_audit_scheduling.py` passed all
  **5 tests**, covering receive-loop responsiveness, bounded workers and
  cancellation, parser/error behavior, and measured/legacy separation.

The initial 1,649-file Python input manifest and corrected 1,650-file manifest
each matched their own before/after observation. The corrected inventory also
includes the existing scheduling test. These focused checks do not enter the
ASGI lifespan or perform full database bootstrap.

The readonly browser checker and `scripts/private_operator_audit/` are separate
preparation work and are deliberately excluded from this audit integration
commit. They are not evidence of a live audit retry walkthrough.
