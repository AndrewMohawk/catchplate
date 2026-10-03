#!/usr/bin/env python3
"""Real synthetic signed-package/history round trip, not live launch custody.

All keys, receipt claims and artifact descriptors are test data. The actual
package, configuration, cohort and archive validators run without mocks. No
process observation, database currentness, physical custody or restart is
established by this cryptographic historical-input fixture.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.authority_history_roundtrip_fixture import build_package
from serverware import authority_artifact_spec as artifact
from serverware import authority_historical_archive as history
from serverware import authority_local_cohort as local_cohort
from serverware import authority_local_historical_archive as producer

SECOND = 10**9
canonical = artifact.canonical_json_bytes


def public_key(root):
    return artifact.strict_base64url_encode(root.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def signed_archive(payload, root):
    message = history.cohort._domain_digest(history.SCHEMA, canonical(payload)).encode("ascii")
    return dict(schema=history.SCHEMA, payload=payload,
        signature=artifact.strict_base64url_encode(root.sign(message)))


def cohort_and_snapshot(fixture, *, label, start, end):
    """Sign synthetic receipt assertions, then independently validate originals."""
    package, verified = fixture["package"], fixture["verified"]
    configuration, root = fixture["configuration"], fixture["root"]
    payload = configuration["payload"]
    digest = history.cohort._domain_digest(history.configuration.CONFIG_SCHEMA, canonical(payload))
    context = dict(
        selected=dict(schema=local_cohort.RUNTIME_SCHEMA, issuedAtUnixNanos=start,
            expiresAtUnixNanos=start + SECOND,
            runtimeValidity=dict(issuedAtEpochNs=start, expiresAtEpochNs=end)),
        rootPublic=root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        configurationDigest=digest, generationDigest=verified.generation_digest,
        packageDigest=verified.package_digest, generationSequence=verified.generation_sequence,
        static=history.cohort._static_configuration(payload), service=payload,
        identities={role: (producer.sha((label + role + "-manifest").encode("ascii")),
            producer.sha((label + role + "-request").encode("ascii"))) for role in history.cohort.ROLES})
    raw, _ = local_cohort._signed_cohort(context, root, now_unix_ns=start)
    envelope = json.loads(raw)
    # Do not fabricate a HistoricalSnapshot. This validates the complete real
    # package/trust/configuration/cohort signatures and all interval joins.
    snapshot = history._entry_snapshot(dict(configurationEnvelope=configuration,
        artifactPackage=package, artifactTrustState=fixture["trust_state"],
        configurationRootPublicKeyBase64Url=public_key(root), attestationCohort=envelope,
        validFromEpochNs=start, validUntilEpochNs=end, configurationDigest=digest))
    return envelope, snapshot


def archive_approval(fixture, previous_runtime, *, start, end):
    originals = dict(currentPackage=canonical(fixture["package"]),
        currentTrustState=canonical(fixture["trust_state"]),
        currentConfiguration=canonical(fixture["configuration"]),
        previousPackage=canonical(fixture["package"]),
        previousTrustState=canonical(fixture["trust_state"]),
        previousConfiguration=canonical(fixture["configuration"]),
        previousRuntimeEvidence=canonical(previous_runtime))
    selected = dict(schema=producer.SCHEMA, purpose=producer.PURPOSE,
        rootDelegation=producer.DELEGATION,
        originalSha256={name: producer.sha(raw) for name, raw in originals.items()},
        configurationRootPublicKeyBase64Url=public_key(fixture["root"]),
        previousConfigurationRootPublicKeyBase64Url=public_key(fixture["root"]),
        bootIdDigest=producer.sha(b"synthetic-history-roundtrip-boot"),
        issuedAtBoottimeNs=100, deadlineBoottimeNs=100 + SECOND,
        issuedAtUnixNanos=start, expiresAtUnixNanos=start + SECOND,
        runtimeValidity=dict(issuedAtEpochNs=start, expiresAtEpochNs=end))
    return selected, originals


def issue_archive(fixture, previous_runtime, *, start, end):
    selected, originals = archive_approval(fixture, previous_runtime, start=start, end=end)
    prepared = producer.prepare(canonical(selected), originals, boot=selected["bootIdDigest"],
        now_boottime_ns=100, now_unix_ns=start)
    raw = producer._sign_archive(prepared, fixture["root"])
    return raw, selected, originals


class HistoricalArchiveRoundTrip(unittest.TestCase):
    def test_complete_populated_history_is_produced_and_admitted_unchanged(self):
        fixture = build_package()
        now = fixture["now_epoch_ns"]
        self.assertEqual(fixture["verified"].disposition, "CurrentExactRetry")
        # A completed older cohort has a deliberately narrower archive. Its
        # authority is expired at the new synthetic evaluation time, not renewed.
        oldest, old_snapshot = cohort_and_snapshot(fixture, label="oldest",
            start=now - 30 * SECOND, end=now - 10 * SECOND)
        old_start, old_end = now - 29 * SECOND, now - 11 * SECOND
        initial = signed_archive(dict(schema=history.SCHEMA, purpose=history.PURPOSE,
            sourceRevision=history.authority.SOURCE_REVISION,
            configurationDigest=old_snapshot.configuration_digest,
            generationDigest=fixture["verified"].generation_digest,
            issuedAtEpochNs=old_start, expiresAtEpochNs=old_end, entries=[]), fixture["root"])
        initial_admitted = history._admit_on_startup(original_bytes=canonical(initial),
            current_snapshot=old_snapshot, current_root_public_key=fixture["root"].public_key(),
            now_epoch_ns=old_start)
        self.assertEqual(len(initial_admitted.records), 1)

        previous_start, previous_end = now - 9 * SECOND, now + 40 * SECOND
        previous, previous_snapshot = cohort_and_snapshot(fixture, label="previous",
            start=previous_start, end=previous_end)
        first_raw, _, _ = issue_archive(fixture,
            dict(schema=producer.RUNTIME_SCHEMA, currentCohort=oldest, historicalArchive=initial),
            start=previous_start, end=previous_end)
        first = json.loads(first_raw)
        first_admitted = history._admit_on_startup(original_bytes=first_raw,
            current_snapshot=previous_snapshot, current_root_public_key=fixture["root"].public_key(),
            now_epoch_ns=previous_start)
        self.assertEqual(len(first_admitted.records), 2)
        oldest_entry = first["payload"]["entries"][0]
        self.assertEqual((oldest_entry["validFromEpochNs"], oldest_entry["validUntilEpochNs"]),
            (old_start, old_end))

        current_end = now + 120 * SECOND
        _, current_snapshot = cohort_and_snapshot(fixture, label="current", start=now, end=current_end)
        second_raw, selected, originals = issue_archive(fixture,
            dict(schema=producer.RUNTIME_SCHEMA, currentCohort=previous, historicalArchive=first),
            start=now, end=current_end)
        second = json.loads(second_raw)
        final = history._admit_on_startup(original_bytes=second_raw,
            current_snapshot=current_snapshot, current_root_public_key=fixture["root"].public_key(),
            now_epoch_ns=now)
        self.assertEqual(final.archive_bytes, second_raw)
        self.assertEqual(len(final.records), 3)
        self.assertEqual((final.valid_from_epoch_ns, final.valid_until_epoch_ns), (now, current_end))
        self.assertEqual(sum(canonical(entry) == canonical(oldest_entry)
            for entry in second["payload"]["entries"]), 1)
        self.assertEqual({(entry["validFromEpochNs"], entry["validUntilEpochNs"])
            for entry in second["payload"]["entries"]}, {(old_start, old_end), (previous_start, previous_end)})
        self.assertLess(old_end, now)
        # Nearby refusal: the seven independent input pins are not derived
        # again from changed bytes or silently replaced by an empty archive.
        changed = deepcopy(originals)
        changed["previousRuntimeEvidence"] += b" "
        with self.assertRaises(ValueError):
            producer.prepare(canonical(selected), changed, boot=selected["bootIdDigest"],
                now_boottime_ns=100, now_unix_ns=now)


if __name__ == "__main__":
    unittest.main()
