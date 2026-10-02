#!/usr/bin/env python3
"""Synthetic signed source-complete enrollment controls, not live DB/launch proof."""
import ast
import copy
import inspect
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scripts.authority import local_registration_enrollment as cli
from scripts.test_authority_local_enrollment_configuration import fixture as configuration_fixture, prepare as configure, public_row
from serverware import authority_local_cohort as cohort_issuer
from serverware import authority_local_registration_enrollment as local

PIN = "sha256:" + "1" * 64
ERRORS = (ValueError, KeyError, InvalidSignature)


def work():
    return local._ValidationWork(local.QueryReadValidationLimits())


def fixture():
    # These public keys, complete empty vector, files and cohort identities are
    # synthetic test inputs. Nothing here is an observed installed owner.
    selection, base, _, root = configuration_fixture()
    prepared = configure(selection)
    config = local.document(prepared["configurationApprovalOriginal"], local.io.MAX_PUBLIC)
    payload = local.document(config["payloadOriginal"].encode("ascii"), local.io.MAX_PUBLIC)
    payload["credentialReleaseTrust"]["maximumReceiptAgeNs"] = 300_000_000_000
    digest = local.configuration.capability.plan._frame(local.configuration.CONFIG_SCHEMA, (local.canonical(payload),), work())
    service_raw = local.canonical(dict(schema=local.local.generator.SERVICE_CONFIGURATION_SCHEMA, payload=payload,
        signature=local.spec.strict_base64url_encode(root.sign(local.local.signature_message("authority-service", payload)))))
    generation = dict(schema=local.configuration.GENERATION_SCHEMA, sequence=0, digest=PIN, predecessorDigest=None,
        minimumRollbackSequence=0, operationManifestDigest=local.current.authority.OPERATION_MANIFEST_DIGEST,
        configurationPayloadBindings=[dict(fileDigest=local.sha(service_raw), payloadDigest=digest,
            payloadSchema=local.configuration.CONFIG_SCHEMA, role="authority-service")],
        configurationBindingDigest=payload["generationBindingDigest"], roleBindingDigests=payload["roleBindingDigests"])
    selected_times = {name: base[name] for name in ("bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs",
        "issuedAtUnixNanos", "expiresAtUnixNanos")}
    context = dict(selected=selected_times,
        rootPublic=root.public_key().public_bytes(local.Encoding.Raw, local.PublicFormat.Raw),
        service=payload, static=local.cohort._static_configuration(payload), configurationDigest=digest,
        generationDigest=PIN, generationSequence=0, packageDigest=PIN,
        identities={role: (local.sha((role+"-manifest").encode()), local.sha((role+"-request").encode())) for role in local.cohort.ROLES})
    cohort_raw, _ = cohort_issuer._signed_cohort(context, root, now_unix_ns=base["issuedAtUnixNanos"])
    rows = [public_row(row, Ed25519PrivateKey.from_private_bytes(bytes([30+index])*32).public_key())
        for index, row in enumerate(local.keys.chain_roster())]
    chain = local.canonical(dict(schema=local.keys.CHAIN_INVENTORY_SCHEMA, approvalSha256=PIN,
        directory=dict(device=1, inode=5), keys=rows, claims=local.keys.CLAIMS,
        publicRosterSha256=local.sha(local.canonical({row["purpose"]:row["publicKeyBase64Url"] for row in rows})),
        **{name+"Sha256":local.sha(selection[name+"Original"].encode("ascii")) for name in local.INVENTORIES[:3]}))
    vector_module, ledger = local.current.vector, work()
    vector, profiles = vector_module._source_on_work(ledger)
    empty = vector_module.roots._primary_empty_root(ledger)
    vector["primaryRoots"] = [dict(table=table, rootRevision=0, rootDigest=empty, leafCount=0)
        for table in vector_module.PRIMARY_TABLES]
    vector["countedRoots"] = [dict(indexId=name, table=profile.table, countedProfile=vector_module.counted.PROFILE,
        projectionDigest=profile.projection_digest, projectionManifestDigest=vector["projectionManifestDigest"],
        indexRevision=0, rootDigest=vector_module.counted.empty_node(profile, "").digest, leafCount=0)
        for name, profile in profiles.items()]
    vector_raw = vector_module._encode_on_work(vector, work=ledger)
    selected = dict(schema=local.SCHEMA, purpose=local.PURPOSE, rootDelegation=local.DELEGATION,
        configurationRootPublicKeyBase64Url=base["configurationRootPublicKeyBase64Url"], generation=generation,
        artifactPackageDigest=PIN, databaseId="synthetic-registration-db", measurements={row["purpose"]:PIN for row in rows},
        callerIds=dict(execution="synthetic-execution", finalization="synthetic-finalization"),
        contextDirectory=dict(path=local.DIRECTORY, device=1, inode=6), issuerPrivateKeyFd=202, requestTimeoutSeconds=1,
        maximumControlAgeNs=10_000_000_000, maximumGrantAgeNs=10_000_000_000,
        maximumAuthorizationAgeNs=10_000_000_000, maximumClockSkewNs=1_000_000_000, maximumRecords=64,
        **selected_times, **{name+"Original":selection[name+"Original"] for name in local.INVENTORIES[:3]},
        registrationChainKeyInventoryOriginal=chain.decode("ascii"))
    for name, raw in (("serviceConfiguration", service_raw), ("cohort", cohort_raw), ("initialVector", vector_raw)):
        selected[name+"Original"], selected[name+"Sha256"] = raw.decode("ascii"), local.sha(raw)
    return selected, root


def prepare(selected, ledger=None):
    return local.prepare(local.canonical(selected), boot=selected["bootIdDigest"],
        now_boottime_ns=selected["issuedAtBoottimeNs"], now_unix_ns=selected["issuedAtUnixNanos"],
        work=work() if ledger is None else ledger)


class RegistrationEnrollmentControls(unittest.TestCase):
    def test_signer_session_cap_real_signature_and_expired_original_refusal(self):
        from serverware import registration_evidence_signer_bootstrap as signer
        from serverware.authority_local_limits import LOCAL_SESSION_MAX_NS
        self.assertEqual(LOCAL_SESSION_MAX_NS, 7_200_000_000_000)
        self.assertEqual(signer.MAX_RECEIPT_AGE_NS, LOCAL_SESSION_MAX_NS)
        # Synthetic component claims and a real test-key signature; this is not
        # a running signer, measured closure, hardware assertion, or admission.
        root = Ed25519PrivateKey.from_private_bytes(b"\x35" * 32)
        claims = dict(schema=signer.ATTESTATION_PAYLOAD_SCHEMA,
            sourceRevision=signer.authority.SOURCE_REVISION, role=signer.ROLE,
            processMode=signer.PROCESS_MODE, trustMode="trusted-host-local",
            sessionIdentityDigest=PIN, measurementDigest=PIN, runtimeClosureDigest=PIN,
            signingSpkiDigest=PIN, issuedAtEpochNs=100,
            expiresAtEpochNs=100 + LOCAL_SESSION_MAX_NS, coLocated=True,
            hardwareBacked=False, nativeStageZero=False, hsmBackedKeys=False,
            teeVerified=False, externalWitnessVerified=False)
        with patch.object(signer.clock.time, "time_ns", return_value=200), \
                patch.object(signer.clock.time, "monotonic_ns", return_value=100):
            raw = signer._produce_attestation_on_work(claims=claims,
                root_private_key=root, root_public_key=root.public_key(), work=work())
            _, admitted, interval, _, _ = signer._read_attestation(
                raw, root.public_key(), LOCAL_SESSION_MAX_NS, work())
            self.assertEqual(admitted, claims)
            self.assertEqual(interval, (100, 100 + LOCAL_SESSION_MAX_NS))
            for changes in ({"expiresAtEpochNs": 101 + LOCAL_SESSION_MAX_NS},
                            {"expiresAtEpochNs": True}, {"trustMode": "external-production"}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    signer._produce_attestation_on_work(claims={**claims, **changes},
                        root_private_key=root, root_public_key=root.public_key(), work=work())
        with patch.object(signer.clock.time, "time_ns", return_value=claims["expiresAtEpochNs"]), \
                patch.object(signer.clock.time, "monotonic_ns", return_value=100):
            with self.assertRaises(signer.RegistrationEvidenceSignerBootstrapError):
                signer._read_attestation(raw, root.public_key(), LOCAL_SESSION_MAX_NS, work())

    @patch.dict(os.environ, {"SERVERWARE_RELEASE_CHANNEL": "dev"})
    def test_five_existing_producers_join_signed_outer_bootstrap(self):
        selected, root = fixture()
        plan = local._WorkPlan()
        prepare(selected, plan.take("acquire-public-inputs"))
        context = prepare(selected, plan.take("recheck-public-inputs"))
        outputs = local._compose(context, root, plan, lambda: None)
        self.assertEqual(plan.next_stage, len(local.WORK_STAGES))
        self.assertEqual(set(outputs), set(local.OUTPUTS))
        result = local.bootstrap._admit_on_work(bootstrap_bytes=outputs["controlPlaneBootstrap"],
            runtime_root_public_key=root.public_key(), expected_configuration_digest=context["configurationDigest"], work=work())
        self.assertEqual(result.generation["sequence"], 0)
        self.assertEqual(result.execution.current_root_enrollment_bytes, outputs["currentRootEnrollment"])
        self.assertEqual(result.finalization.grant_enrollment_bytes, outputs["grantEnrollment"])
        self.assertEqual(result.execution.context_directory, (1, 6))
        self.assertNotEqual(result.execution.caller_public_key.public_bytes(local.Encoding.Raw, local.PublicFormat.Raw),
            result.finalization.caller_public_key.public_bytes(local.Encoding.Raw, local.PublicFormat.Raw))

    def test_tampered_signed_configuration_and_cohort_refuse(self):
        for name in ("serviceConfiguration", "cohort"):
            selected, _ = fixture()
            value = local.document(selected[name+"Original"].encode(), local.io.MAX_PUBLIC)
            value["signature"] = local.spec.strict_base64url_encode(b"x"*64)
            raw = local.canonical(value)
            selected[name+"Original"], selected[name+"Sha256"] = raw.decode(), local.sha(raw)
            with self.assertRaises(ERRORS): prepare(selected)

    def test_package_generation_and_vector_are_not_inferred(self):
        selected, _ = fixture()
        for change in (lambda v:v.update(artifactPackageDigest="sha256:"+"2"*64),
                lambda v:v["generation"].update(sequence=1),
                lambda v:v.update(initialVectorOriginal="{}", initialVectorSha256=local.sha(b"{}"))):
            changed = copy.deepcopy(selected); change(changed)
            with self.assertRaises(ERRORS): prepare(changed)

    def test_chain_key_or_prior_inventory_cannot_be_rebound(self):
        selected, _ = fixture()
        value = local.document(selected["registrationChainKeyInventoryOriginal"].encode(), local.io.MAX_PUBLIC)
        value["pilotKeyInventorySha256"] = "sha256:"+"2"*64
        selected["registrationChainKeyInventoryOriginal"] = local.canonical(value).decode()
        with self.assertRaises(ERRORS): prepare(selected)

    def test_original_caps_and_future_fd_layout_are_closed(self):
        selected, _ = fixture()
        for changes in (dict(issuerPrivateKeyFd=203), dict(issuerPrivateKeyFd=204),
                dict(deadlineBoottimeNs=selected["issuedAtBoottimeNs"]), dict(rootDelegation="arbitrary-signing"),
                dict(expiresAtUnixNanos=selected["expiresAtUnixNanos"]+1), dict(newGrant=True)):
            with self.assertRaises(ERRORS): prepare(dict(selected, **changes))

    def test_source_only_borrowed_owner_uses_fixed_work_and_no_sql_or_generation(self):
        tree = ast.parse(inspect.getsource(local))
        names = [node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        self.assertNotIn("generate", names)
        self.assertNotIn("connect", names)
        self.assertNotIn("execute", names)
        self.assertNotIn("close", names)  # Borrowed FDs are never closed by this owner.
        self.assertIn("_produce_v4_on_work", names)
        budgets = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "_ValidationWork"]
        self.assertEqual(len(budgets), 1)  # Only the fixed one-use phase allocator constructs ledgers.
        self.assertIn("config.PRODUCTION_IMAGE", inspect.getsource(local.LocalRegistrationEnrollment.__init__))

    def test_work_schedule_is_exactly_seven_once_only_bounded_ledgers(self):
        plan = local._WorkPlan()
        with self.assertRaises(ValueError): plan.take(local.WORK_STAGES[1])
        ledgers = []
        for name in local.WORK_STAGES:
            ledgers.append(plan.take(name))
            with self.assertRaises(ValueError): plan.take(name)
        self.assertEqual(len(ledgers), 7)
        self.assertEqual(len({id(ledger) for ledger in ledgers}), 7)
        self.assertEqual(local.WORK_STAGES[2:], local.OUTPUTS)
        self.assertTrue(all(ledger.limits == local.QueryReadValidationLimits() for ledger in ledgers))
        self.assertEqual(local.MAX_AGGREGATE_WORK, tuple(7 * value for value in (
            local.accounting.MAX_HASHES, local.accounting.MAX_INPUT_BYTES, local.accounting.MAX_JSON_NODES)))
        with self.assertRaises(ValueError): plan.take(local.WORK_STAGES[0])

    def test_cli_has_only_fixed_public_approval_key_and_directory_slots(self):
        args = ["--approval-fd", "10", "--approval-sha256", PIN, "--signing-key-fd", "11", "--context-directory-fd", "12"]
        self.assertEqual(cli.arguments(args)["context_directory_fd"], 12)
        for bad in (args+["--reset", "1"], args[:-1]+["10"], args[:1]+["010"]+args[2:]):
            with self.assertRaises(ValueError): cli.arguments(bad)


if __name__ == "__main__": unittest.main()
