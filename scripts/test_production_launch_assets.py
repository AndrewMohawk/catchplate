#!/usr/bin/env python3
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import itertools
import json
import os
import re
import shlex
import stat
import struct
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))
import generate_production_launch_manifest as generator


ROOT = SCRIPT_DIRECTORY.parent
MANIFEST_SCHEMA_PATH = (
    ROOT / "schemas" / "production-launch-manifest.v3.schema.json"
)
RUST_LAUNCHER_PATH = (
    ROOT
    / "data-plane"
    / "decision-gate-rs"
    / "src"
    / "bin"
    / "serverware-production-launcher.rs"
)
EXPECTED_INPUTS = {name for name, _argument in generator.INPUT_ARGUMENTS}
EXPECTED_OUTPUTS = {name for name, _argument in generator.OUTPUT_ARGUMENTS}
EXPECTED_AUTHORIZATION = {
    "authorizationScope",
    "deploymentAudience",
    "deploymentIdentitySha256",
    "freshnessAuthority",
    "monotonicWitness",
    "releaseSequence",
    "rollbackEpoch",
}
EXPECTED_MANIFEST_FIELDS = {
    "apiVersion",
    "kind",
    "releaseRoot",
    "stateDirectory",
    "sourceTreeDigest",
    "authorization",
    "launchAttemptJournal",
    "globalRoleRegistry",
    "nonceRollbackAssurance",
    "productionEnv",
    "python",
    "scripts",
    "composeFile",
    "inputs",
    "outputs",
}
FORBIDDEN_AUTHORIZATION_KEYS = {
    "authorizationenvelope",
    "authorizationkey",
    "authorizationkeypath",
    "authorizationpublickey",
    "authorizationresponse",
    "authorizationsignature",
    "authorizationsocket",
    "authorizationsocketpath",
    "authoritykey",
    "authoritykeypath",
    "authoritypublickey",
    "authoritysocket",
    "authoritysocketpath",
    "launchauthoritykey",
    "launchauthoritypublickey",
    "launchauthoritysocket",
    "launchauthorization",
    "launchauthorizationresponse",
}
FORBIDDEN_UNIT_AUTHORIZATION_PATTERNS = (
    re.compile(r"--(?:launch-)?authority-(?:key|public-key|socket)(?:=|\s|$)", re.IGNORECASE),
    re.compile(r"--authorization-(?:response|signature|key|public-key|socket)(?:=|\s|$)", re.IGNORECASE),
    re.compile(
        r"(?:launch[-_.]?authority|authorization)[-_.]?(?:response|signature|key|public[-_.]?key|socket)",
        re.IGNORECASE,
    ),
    re.compile(r"\bauthority[-_.]?(?:key|public[-_.]?key|socket)\b", re.IGNORECASE),
    re.compile(r"\b(?:SERVERWARE_)?(?:LAUNCH_)?AUTHORITY_(?:KEY|PUBLIC_KEY|SOCKET)\b"),
    re.compile(r"/run/serverware/launch-authority\.sock"),
    re.compile(r"serverware\.launchAuthorization/"),
)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def public_spki_der(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_spki_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def minimal_cpython_elf(
    *,
    machine: int = generator.ELF_MACHINE_X86_64,
    symbol: bytes = b"Py_BytesMain",
    needed: bytes = b"libpython3.11.so.1.0",
) -> bytes:
    dynamic_strings = b"\0" + symbol + b"\0" + needed + b"\0"
    symbol_offset = 1
    needed_offset = 1 + len(symbol) + 1
    dynamic_symbols = b"\0" * generator.ELF64_SYMBOL_SIZE + struct.pack(
        "<IBBHQQ", symbol_offset, 0, 0, 0, 0, 0
    )
    dynamic_entries = struct.pack("<qQqQ", generator.ELF_DYNAMIC_NEEDED, needed_offset, 0, 0)
    program_offset = generator.ELF64_HEADER_SIZE
    data_offset = program_offset + generator.ELF64_PROGRAM_HEADER_SIZE
    string_offset = data_offset
    symbol_table_offset = string_offset + len(dynamic_strings)
    dynamic_offset = symbol_table_offset + len(dynamic_symbols)
    section_offset = dynamic_offset + len(dynamic_entries)
    section_count = 4
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\0" * 9,
        3,
        machine,
        1,
        0,
        program_offset,
        section_offset,
        0,
        generator.ELF64_HEADER_SIZE,
        generator.ELF64_PROGRAM_HEADER_SIZE,
        1,
        generator.ELF64_SECTION_HEADER_SIZE,
        section_count,
        0,
    )
    program_header = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, section_offset, section_offset, 4096)

    def section(
        section_type: int,
        offset: int,
        size: int,
        *,
        link: int = 0,
        entry_size: int = 0,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            0,
            section_type,
            0,
            0,
            offset,
            size,
            link,
            0,
            1,
            entry_size,
        )

    sections = b"".join(
        (
            section(0, 0, 0),
            section(generator.ELF_SECTION_STRTAB, string_offset, len(dynamic_strings)),
            section(
                generator.ELF_SECTION_DYNSYM,
                symbol_table_offset,
                len(dynamic_symbols),
                link=1,
                entry_size=generator.ELF64_SYMBOL_SIZE,
            ),
            section(
                generator.ELF_SECTION_DYNAMIC,
                dynamic_offset,
                len(dynamic_entries),
                link=1,
                entry_size=generator.ELF64_DYNAMIC_SIZE,
            ),
        )
    )
    return header + program_header + dynamic_strings + dynamic_symbols + dynamic_entries + sections


class Fixture:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.release = base / "release"
        self.state = base / "state"
        self.etc = base / "etc" / "serverware"
        self.release.mkdir()
        self.state.mkdir()
        self.etc.mkdir(parents=True)

        self.stdlib = self.release / "runtime" / "python" / "lib" / "python3.11"
        self.lib_dynload = self.stdlib / "lib-dynload"
        self.vendor = self.release / "vendor"
        self.import_roots = [self.release, self.stdlib, self.lib_dynload, self.vendor]
        for path in self.import_roots:
            path.mkdir(parents=True, exist_ok=True)

        self.files: dict[str, Path] = {}
        self.files["production_env"] = self.write(
            self.etc / "production-readiness.env",
            b"SERVERWARE_COMPLETION_VERIFICATION_MODE=readiness\n",
        )
        self.files["python"] = self.write(
            self.release / "runtime" / "python" / "bin" / "python3",
            minimal_cpython_elf(),
        )
        self.files["python"].chmod(0o755)
        self.files["extension_module"] = self.write(
            self.lib_dynload / "_ssl.cpython-311-x86_64-linux-gnu.so",
            b"extension-module-fixture\n",
        )
        self.files["preflight_script"] = self.write(
            self.release / "scripts" / "production_host_preflight.py", b"print('preflight')\n"
        )
        self.files["runner_script"] = self.write(
            self.release / "scripts" / "run_production_readiness.py", b"print('runner')\n"
        )
        self.files["compose_file"] = self.write(
            self.release / "docker-compose.production.yml", b"services: {}\n"
        )
        for index, (manifest_name, argument_name) in enumerate(generator.INPUT_ARGUMENTS):
            self.files[argument_name.replace("-", "_")] = self.write(
                self.release / "evidence" / f"{argument_name}.fixture", f"{index}:{manifest_name}\n".encode("ascii")
            )

        self.trust_arguments = self.write_trust_contract()
        self.output_paths = {
            argument_name.replace("-", "_"): self.state / f"{argument_name}.json"
            for _manifest_name, argument_name in generator.OUTPUT_ARGUMENTS
        }
        self.pipeline_metadata_path = self.base / "launch-pipeline-metadata.json"

    @staticmethod
    def write(path: Path, content: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def write_trust_contract(self) -> list[str]:
        keys = {
            name: Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
            for index, name in enumerate(
                (
                    "launch_authority",
                    "witness",
                    "witness_store",
                    "witness_tls",
                    "nonce_evidence",
                    "nonce_verifier_state",
                    "nonce_store_attestation",
                    "policy_activation",
                    "policy_identity",
                    "reproducible_build",
                ),
                start=1,
            )
        }
        key_ids = {
            name: sha256_prefixed(public_spki_der(key))
            for name, key in keys.items()
        }
        self.trust_keys = keys
        self.trust_key_ids = key_ids
        for argument_name, key_name in (
            ("policy_trusted_public_key", "policy_identity"),
            ("policy_activation_trusted_public_key", "policy_activation"),
            ("reproducible_build_trusted_public_key", "reproducible_build"),
        ):
            self.files[argument_name].write_bytes(public_spki_pem(keys[key_name]))

        nonce_assurance = {
            "apiVersion": "serverware.nonceAuthorityAssurance/v1",
            "administrativeDomainSha256": "sha256:" + "1a" * 32,
            "assuranceEvidenceSha256": "sha256:" + "1b" * 32,
            "assuranceEvidenceType": "linearizableCasOperatorAttestation",
            "assuranceLevel": "productionRollbackProtected",
            "authorityEpoch": 1,
            "authorityGeneration": 1,
            "authorityIdentitySha256": "sha256:" + "1c" * 32,
            "backendClass": "independentlyAdministeredLinearizableCas",
            "productionEligible": True,
            "rollbackProtection": {
                "administrativeRollbackResistance": True,
                "backendAttestationRequired": True,
                "exactSuccessorRequired": True,
                "freshVerifierChallengeRequired": True,
                "keyProtection": "nonExportableKmsHsm",
                "mechanism": "linearizableCasWithRollbackProtectedStorage",
                "stateCommitment": "hashChainedLinearizableCommitment",
                "verifierStateStoreClass": (
                    "independentlyAdministeredLinearizableCas"
                ),
            },
        }
        nonce_assurance_sha256 = sha256_prefixed(
            generator.canonical_json_value(nonce_assurance)
        )
        nonce_contract = {
            "apiVersion": generator.NONCE_ROLLBACK_ASSURANCE_PINS_VERSION,
            "independentVerifierPins": {
                "expectedNonceAuthorityAssuranceIssuerSpkiSha256": key_ids[
                    "nonce_evidence"
                ],
                "expectedNonceAuthorityAssuranceSha256": (
                    nonce_assurance_sha256
                ),
            },
            "publicConfigPins": {
                "nonceAuthorityAssurance": nonce_assurance,
                "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url": (
                    b64url(public_spki_der(keys["nonce_evidence"]))
                ),
                "nonceAuthorityAssuranceSha256": nonce_assurance_sha256,
                "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url": (
                    b64url(public_spki_der(keys["nonce_verifier_state"]))
                ),
                "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256": (
                    "sha256:" + "1d" * 32
                ),
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256": (
                    "sha256:" + "1e" * 32
                ),
                "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url": (
                    b64url(public_spki_der(keys["nonce_store_attestation"]))
                ),
                "nonceAuthorityVerifierStateStoreIdentitySha256": (
                    "sha256:" + "1f" * 32
                ),
            },
        }
        nonce_pins = self.write(
            self.etc / "nonce-rollback-assurance-pins.json",
            generator.canonical_json(nonce_contract),
        )
        nonce_pins.chmod(0o400)

        witness_identity = "sha256:" + "2a" * 32
        witness_administrative_domain = "sha256:" + "2b" * 32
        witness_store_statement = {
            "assuranceIssuerKeyId": key_ids["witness_store"],
            "witnessKeyId": key_ids["witness"],
            "witnessIdentitySha256": witness_identity,
            "witnessAdministrativeDomainSha256": (
                witness_administrative_domain
            ),
            "storeIdentitySha256": "sha256:" + "2c" * 32,
            "storeAdministrativeDomainSha256": "sha256:" + "2d" * 32,
            "storeClass": "independentlyAdministeredLinearizableCas",
            "rollbackResistance": "externally-witnessed-monotonic",
            "independentAdministration": True,
        }
        witness_store_unsigned = {
            "apiVersion": generator.WITNESS_STORE_ASSURANCE_API_VERSION,
            "kind": generator.WITNESS_STORE_ASSURANCE_KIND,
            "statement": witness_store_statement,
        }
        witness_store_assurance = {
            **witness_store_unsigned,
            "signature": b64url(
                keys["witness_store"].sign(
                    generator.WITNESS_STORE_ASSURANCE_API_VERSION.encode(
                        "ascii"
                    )
                    + b"\0"
                    + generator.canonical_json_value(witness_store_unsigned)
                )
            ),
        }
        witness_store_bytes = generator.canonical_json_value(
            witness_store_assurance
        )
        witness_store_path = self.write(
            self.etc / "launch-authority-witness-store-assurance.json",
            witness_store_bytes,
        )
        witness_store_path.chmod(0o400)
        self.witness_store_path = witness_store_path
        self.witness_store_statement = witness_store_statement

        roles = {
            "launchAuthority": key_ids["launch_authority"],
            "launchAuthorityWitness": key_ids["witness"],
            "launchAuthorityWitnessStoreAssurance": key_ids["witness_store"],
            "launchAuthorityWitnessTls": key_ids["witness_tls"],
            "nonceAuthorityAssuranceEvidence": key_ids["nonce_evidence"],
            "nonceAuthorityVerifierState": key_ids["nonce_verifier_state"],
            "nonceAuthorityVerifierStateStoreAttestation": key_ids[
                "nonce_store_attestation"
            ],
            "policyActivation": key_ids["policy_activation"],
            "policyIdentity": key_ids["policy_identity"],
            "reproducibleBuild": key_ids["reproducible_build"],
        }
        global_role_registry = {
            "apiVersion": generator.GLOBAL_ROLE_REGISTRY_API_VERSION,
            "claimScope": generator.GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE,
            "roles": roles,
            "rolesOutsideClaim": list(generator.GLOBAL_ROLES_OUTSIDE_CLAIM),
        }
        global_role_registry_path = self.write(
            self.etc / "production-launch-global-role-registry.json",
            generator.canonical_json(global_role_registry),
        )
        global_role_registry_path.chmod(0o400)

        return [
            "--expected-launch-authority-key-id",
            key_ids["launch_authority"],
            "--global-role-registry",
            str(global_role_registry_path),
            "--expected-global-role-registry-pins-sha256",
            sha256_prefixed(global_role_registry_path.read_bytes()),
            "--launch-authority-witness-signing-public-key-spki-base64url",
            b64url(public_spki_der(keys["witness"])),
            "--expected-launch-authority-witness-key-id",
            key_ids["witness"],
            "--launch-authority-witness-identity-sha256",
            witness_identity,
            "--launch-authority-witness-administrative-domain-sha256",
            witness_administrative_domain,
            "--launch-authority-witness-store-assurance-sha256",
            sha256_prefixed(witness_store_bytes),
            "--launch-authority-witness-store-assurance",
            str(witness_store_path),
            "--launch-authority-witness-store-assurance-issuer-public-key-spki-base64url",
            b64url(public_spki_der(keys["witness_store"])),
            "--expected-launch-authority-witness-store-assurance-issuer-key-id",
            key_ids["witness_store"],
            "--nonce-rollback-assurance-pins",
            str(nonce_pins),
            "--expected-nonce-rollback-assurance-pins-sha256",
            sha256_prefixed(nonce_pins.read_bytes()),
        ]

    def rewrite_witness_store_assurance(
        self,
        statement_updates: dict[str, object],
        *,
        signer_name: str = "witness_store",
    ) -> None:
        statement = {
            **self.witness_store_statement,
            **statement_updates,
            "assuranceIssuerKeyId": self.trust_key_ids[signer_name],
        }
        unsigned = {
            "apiVersion": generator.WITNESS_STORE_ASSURANCE_API_VERSION,
            "kind": generator.WITNESS_STORE_ASSURANCE_KIND,
            "statement": statement,
        }
        envelope = {
            **unsigned,
            "signature": b64url(
                self.trust_keys[signer_name].sign(
                    generator.WITNESS_STORE_ASSURANCE_API_VERSION.encode(
                        "ascii"
                    )
                    + b"\0"
                    + generator.canonical_json_value(unsigned)
                )
            ),
        }
        encoded = generator.canonical_json_value(envelope)
        self.witness_store_path.write_bytes(encoded)
        self.witness_store_path.chmod(0o400)
        self.witness_store_statement = statement
        replacements = {
            "--launch-authority-witness-store-assurance-sha256": (
                sha256_prefixed(encoded)
            ),
            "--launch-authority-witness-store-assurance-issuer-public-key-spki-base64url": (
                b64url(public_spki_der(self.trust_keys[signer_name]))
            ),
            "--expected-launch-authority-witness-store-assurance-issuer-key-id": (
                self.trust_key_ids[signer_name]
            ),
        }
        for name, value in replacements.items():
            index = self.trust_arguments.index(name)
            self.trust_arguments[index + 1] = value

    def argv(self, manifest_path: Path) -> list[str]:
        argv = [
            "--output",
            str(manifest_path),
            "--pipeline-metadata-out",
            str(self.pipeline_metadata_path),
            "--release-root",
            str(self.release),
            "--state-directory",
            str(self.state),
            "--source-tree-digest",
            "sha256:" + "01" * 32,
            "--deployment-audience",
            "production.us-east-1:primary",
            "--deployment-identity-sha256",
            "sha256:" + "23" * 32,
            "--release-sequence",
            "42",
            "--rollback-epoch",
            "0",
            "--production-env",
            str(self.files["production_env"]),
            "--python",
            str(self.files["python"]),
        ]
        argv.extend(self.trust_arguments)
        for path in self.import_roots:
            argv.extend(("--python-import-root", str(path)))
        argv.extend(
            (
                "--preflight-script",
                str(self.files["preflight_script"]),
                "--runner-script",
                str(self.files["runner_script"]),
                "--compose-file",
                str(self.files["compose_file"]),
            )
        )
        for _manifest_name, argument_name in generator.INPUT_ARGUMENTS:
            argv.extend((f"--{argument_name}", str(self.files[argument_name.replace("-", "_")])))
        for _manifest_name, argument_name in generator.OUTPUT_ARGUMENTS:
            argv.extend((f"--{argument_name}", str(self.output_paths[argument_name.replace("-", "_")])))
        return argv


def replace_argument(argv: list[str], name: str, value: str) -> list[str]:
    changed = list(argv)
    index = changed.index(name)
    changed[index + 1] = value
    return changed


def remove_argument(argv: list[str], name: str) -> list[str]:
    changed = list(argv)
    index = changed.index(name)
    del changed[index : index + 2]
    return changed


def remove_argument_value(argv: list[str], name: str, value: str) -> list[str]:
    changed = list(argv)
    for index in range(len(changed) - 1):
        if changed[index] == name and changed[index + 1] == value:
            del changed[index : index + 2]
            return changed
    raise AssertionError(f"argument pair not found: {name} {value}")


def parsed(argv: list[str]):
    return generator.build_parser().parse_args(argv)


def load_manifest_schema() -> dict[str, object]:
    return json.loads(MANIFEST_SCHEMA_PATH.read_text(encoding="utf-8"))


def snake_to_camel(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part[:1].upper() + part[1:] for part in rest)


def rust_struct_fields(source: str, struct_name: str) -> set[str]:
    match = re.search(
        rf"struct {re.escape(struct_name)} \{{(?P<body>.*?)^\}}",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"Rust launcher omits {struct_name}")
    header = source[max(0, match.start() - 240) : match.start()]
    if "deny_unknown_fields" not in header:
        raise AssertionError(f"Rust launcher leaves {struct_name} open")
    fields = {
        snake_to_camel(field)
        for field in re.findall(
            r"^\s+([a-z][a-z0-9_]*)\s*:",
            match.group("body"),
            re.MULTILINE,
        )
    }
    if not fields:
        raise AssertionError(f"Rust launcher {struct_name} has no fields")
    return fields


def schema_object_fields(
    loaded: dict[str, object],
    definition: str | None,
) -> set[str]:
    node = (
        loaded
        if definition is None
        else loaded["$defs"][definition]  # type: ignore[index]
    )
    if not isinstance(node, dict):
        raise AssertionError(f"manifest schema definition is invalid: {definition}")
    properties = node.get("properties")
    required = node.get("required")
    if (
        node.get("type") != "object"
        or node.get("additionalProperties") is not False
        or not isinstance(properties, dict)
        or not isinstance(required, list)
        or set(required) != set(properties)
    ):
        raise AssertionError(
            f"manifest schema object is not exact and closed: {definition}"
        )
    return set(properties)


def expect_manifest_error(argv: list[str], message: str) -> None:
    try:
        generator.generate(parsed(argv))
    except generator.ManifestError:
        return
    raise AssertionError(message)


def expect_main_error(argv: list[str], message: str) -> None:
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            generator.main(argv)
        except SystemExit as exc:
            if exc.code != 0:
                return
    raise AssertionError(message)


def expect_main_error_contains(
    argv: list[str],
    expected_detail: str,
    message: str,
) -> None:
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        try:
            generator.main(argv)
        except SystemExit as exc:
            if exc.code != 0 and expected_detail in stderr.getvalue():
                return
    raise AssertionError(f"{message}: {stderr.getvalue()}")


def assert_closed_authorization(record: object, label: str, *, example: bool = False) -> None:
    if not isinstance(record, dict) or set(record) != EXPECTED_AUTHORIZATION:
        raise AssertionError(f"{label} is not a closed authorization configuration")
    if record["authorizationScope"] != "trusted-host-readiness":
        raise AssertionError(f"{label}.authorizationScope is not readiness-only")
    if record["freshnessAuthority"] != "trusted-host-wall-clock":
        raise AssertionError(f"{label}.freshnessAuthority overstates secure time")
    audience = record["deploymentAudience"]
    if not isinstance(audience, str) or generator.DEPLOYMENT_AUDIENCE_RE.fullmatch(audience) is None:
        raise AssertionError(f"{label}.deploymentAudience is invalid")
    identity = record["deploymentIdentitySha256"]
    if not isinstance(identity, str) or (
        generator.DIGEST_RE.fullmatch(identity) is None
        and not (example and identity == "sha256:<64-lowercase-hex>")
    ):
        raise AssertionError(f"{label}.deploymentIdentitySha256 is invalid")
    release_sequence = record["releaseSequence"]
    rollback_epoch = record["rollbackEpoch"]
    if (
        isinstance(release_sequence, bool)
        or not isinstance(release_sequence, int)
        or not 1 <= release_sequence <= generator.JSON_SAFE_INTEGER_MAX
    ):
        raise AssertionError(f"{label}.releaseSequence is not a positive JSON-safe integer")
    if (
        isinstance(rollback_epoch, bool)
        or not isinstance(rollback_epoch, int)
        or not 0 <= rollback_epoch <= generator.JSON_SAFE_INTEGER_MAX
    ):
        raise AssertionError(f"{label}.rollbackEpoch is not a nonnegative JSON-safe integer")
    witness = record["monotonicWitness"]
    expected_witness_fields = {
        "administrativeDomainSha256",
        "identitySha256",
        "signingKeyId",
        "signingPublicKeySpkiDerBase64url",
        "storeAssurance",
        "storeAssuranceIssuerKeyId",
        "storeAssuranceIssuerPublicKeySpkiDerBase64url",
        "storeAssuranceSha256",
    }
    if not isinstance(witness, dict) or set(witness) != expected_witness_fields:
        raise AssertionError(f"{label}.monotonicWitness is not closed")
    store_assurance = witness["storeAssurance"]
    if (
        not isinstance(store_assurance, dict)
        or set(store_assurance)
        != {"apiVersion", "kind", "statement", "signature"}
        or store_assurance["apiVersion"]
        != generator.WITNESS_STORE_ASSURANCE_API_VERSION
        or store_assurance["kind"] != generator.WITNESS_STORE_ASSURANCE_KIND
    ):
        raise AssertionError(
            f"{label}.monotonicWitness.storeAssurance is not current"
        )
    expected_statement_fields = {
        "assuranceIssuerKeyId",
        "witnessKeyId",
        "witnessIdentitySha256",
        "witnessAdministrativeDomainSha256",
        "storeIdentitySha256",
        "storeAdministrativeDomainSha256",
        "storeClass",
        "rollbackResistance",
        "independentAdministration",
    }
    if (
        not isinstance(store_assurance["statement"], dict)
        or set(store_assurance["statement"]) != expected_statement_fields
    ):
        raise AssertionError(
            f"{label}.monotonicWitness.storeAssurance.statement is not closed"
        )


def assert_no_authorization_material(value: object, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in FORBIDDEN_AUTHORIZATION_KEYS:
                raise AssertionError(f"{label} embeds forbidden authorization material at {key}")
            assert_no_authorization_material(child, label)
    elif isinstance(value, list):
        for child in value:
            assert_no_authorization_material(child, label)
    elif isinstance(value, str) and value == "/run/serverware/launch-authority.sock":
        raise AssertionError(f"{label} configures the launcher-compiled authority socket")


def assert_launch_attempt_journal(
    record: object,
    state_directory: str,
    label: str,
) -> None:
    expected = {
        "apiVersion": generator.ATTEMPT_JOURNAL_API_VERSION,
        "path": str(Path(state_directory) / generator.ATTEMPT_JOURNAL_FILE_NAME),
        "lockPath": str(
            Path(state_directory) / generator.ATTEMPT_JOURNAL_LOCK_FILE_NAME
        ),
        "domain": generator.ATTEMPT_JOURNAL_DOMAIN,
        "maxBytes": generator.MAX_ATTEMPT_JOURNAL_BYTES,
        "consistencyScope": generator.ATTEMPT_JOURNAL_CONSISTENCY_SCOPE,
        "rollbackAuthority": generator.ATTEMPT_JOURNAL_ROLLBACK_AUTHORITY,
    }
    if record != expected:
        raise AssertionError(f"{label} is not the fixed v3 journal contract")


def assert_global_role_registry_binding(
    record: object,
    label: str,
    *,
    example: bool = False,
) -> None:
    expected_fields = {
        "apiVersion",
        "canonicalProfile",
        "claimScope",
        "registry",
        "registrySha256",
        "pinsFile",
    }
    if not isinstance(record, dict) or set(record) != expected_fields:
        raise AssertionError(f"{label} is not a closed registry binding")
    if (
        record["apiVersion"] != generator.GLOBAL_ROLE_REGISTRY_BINDING_API_VERSION
        or record["canonicalProfile"] != generator.CANONICAL_JSON_PROFILE
        or record["claimScope"] != generator.GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE
    ):
        raise AssertionError(f"{label} has the wrong registry identity")
    registry = record["registry"]
    if (
        not isinstance(registry, dict)
        or set(registry)
        != {"apiVersion", "claimScope", "roles", "rolesOutsideClaim"}
        or registry["apiVersion"] != generator.GLOBAL_ROLE_REGISTRY_API_VERSION
        or registry["claimScope"] != generator.GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE
        or registry["rolesOutsideClaim"]
        != list(generator.GLOBAL_ROLES_OUTSIDE_CLAIM)
        or not isinstance(registry["roles"], dict)
        or set(registry["roles"]) != set(generator.GLOBAL_ROLE_NAMES)
    ):
        raise AssertionError(f"{label}.registry is not the closed role registry")
    role_ids = list(registry["roles"].values())
    if not example and (
        any(
            not isinstance(value, str)
            or generator.DIGEST_RE.fullmatch(value) is None
            for value in role_ids
        )
        or len(set(role_ids)) != len(role_ids)
    ):
        raise AssertionError(f"{label}.registry roles are not pairwise distinct SPKIs")
    pins_file = record["pinsFile"]
    if (
        not isinstance(pins_file, dict)
        or set(pins_file) != {"path", "sha256"}
        or not str(pins_file["path"]).startswith("/")
        or not str(pins_file["sha256"]).startswith("sha256:")
        or not str(record["registrySha256"]).startswith("sha256:")
    ):
        raise AssertionError(f"{label} omits its independent registry pins")
    if not example:
        canonical_registry = generator.canonical_json_value(registry)
        expected_registry_sha256 = sha256_prefixed(canonical_registry)
        expected_pins_bytes = canonical_registry + b"\n"
        if record["registrySha256"] != expected_registry_sha256:
            raise AssertionError(
                f"{label}.registrySha256 does not bind the canonical registry"
            )
        pins_path = Path(pins_file["path"])
        if (
            pins_path.read_bytes() != expected_pins_bytes
            or pins_file["sha256"]
            != sha256_prefixed(expected_pins_bytes)
        ):
            raise AssertionError(
                f"{label}.pinsFile does not bind the exact registry file"
            )


def assert_nonce_rollback_binding(
    record: object,
    label: str,
    *,
    example: bool = False,
) -> None:
    expected_fields = {
        "apiVersion",
        "canonicalProfile",
        "contract",
        "contractSha256",
        "enforcement",
        "pinsFile",
        "purpose",
    }
    if not isinstance(record, dict) or set(record) != expected_fields:
        raise AssertionError(f"{label} is not a closed nonce assurance binding")
    contract = record["contract"]
    if (
        record["apiVersion"]
        != generator.NONCE_ROLLBACK_ASSURANCE_BINDING_VERSION
        or record["canonicalProfile"] != generator.CANONICAL_JSON_PROFILE
        or record["enforcement"] != "native-launcher-measured"
        or record["purpose"] != "readiness-only"
        or not isinstance(contract, dict)
        or set(contract)
        != {"apiVersion", "independentVerifierPins", "publicConfigPins"}
        or contract["apiVersion"]
        != generator.NONCE_ROLLBACK_ASSURANCE_PINS_VERSION
    ):
        raise AssertionError(f"{label} has the wrong nonce assurance identity")
    pins_file = record["pinsFile"]
    if (
        not isinstance(pins_file, dict)
        or set(pins_file) != {"path", "sha256"}
        or not str(pins_file["path"]).startswith("/")
        or not str(pins_file["sha256"]).startswith("sha256:")
        or not str(record["contractSha256"]).startswith("sha256:")
    ):
        raise AssertionError(f"{label} omits exact nonce assurance pins")
    if not example:
        canonical_contract = generator.canonical_json_value(contract)
        expected_contract_sha256 = sha256_prefixed(canonical_contract)
        expected_pins_bytes = canonical_contract + b"\n"
        pins_path = Path(pins_file["path"])
        if record["contractSha256"] != expected_contract_sha256:
            raise AssertionError(
                f"{label}.contractSha256 does not bind the canonical contract"
            )
        if (
            pins_path.read_bytes() != expected_pins_bytes
            or pins_file["sha256"] != sha256_prefixed(expected_pins_bytes)
        ):
            raise AssertionError(
                f"{label}.pinsFile does not bind the exact nonce assurance file"
            )


def assert_no_unit_authorization_overrides(unit: str, label: str) -> None:
    for pattern in FORBIDDEN_UNIT_AUTHORIZATION_PATTERNS:
        if pattern.search(unit):
            raise AssertionError(f"{label} embeds or configures launch authorization material: {pattern.pattern}")


def test_independent_administration_pairwise_contract() -> None:
    expected_bindings = (
        "launchAuthority.signingKeyId",
        "launchAuthorityWitness.signingKeyId",
        "launchAuthorityWitness.identitySha256",
        "launchAuthorityWitness.administrativeDomainSha256",
        "launchAuthorityWitnessStore.identitySha256",
        "launchAuthorityWitnessStore.administrativeDomainSha256",
        "launchAuthorityWitnessStore.assuranceIssuerKeyId",
    )
    if generator.INDEPENDENT_ADMINISTRATION_BINDINGS != expected_bindings:
        raise AssertionError(
            "independent-administration binding inventory is incomplete"
        )
    valid = {
        label: "sha256:" + f"{index:02x}" * 32
        for index, label in enumerate(expected_bindings, start=1)
    }
    generator.require_pairwise_distinct_bindings(valid)
    for left, right in itertools.combinations(valid, 2):
        hostile = dict(valid)
        hostile[right] = hostile[left]
        try:
            generator.require_pairwise_distinct_bindings(hostile)
        except generator.ManifestError as exc:
            if left not in str(exc) or right not in str(exc):
                raise AssertionError(
                    "pairwise-separation rejection did not identify both "
                    f"colliding bindings: {left}, {right}"
                ) from exc
        else:
            raise AssertionError(
                "independentAdministration accepted collision between "
                f"{left} and {right}"
            )


def manifest_path_locations(manifest: dict[str, object]) -> list[tuple[object, ...]]:
    locations: list[tuple[object, ...]] = [
        ("releaseRoot",),
        ("stateDirectory",),
        ("launchAttemptJournal", "path"),
        ("launchAttemptJournal", "lockPath"),
        ("globalRoleRegistry", "pinsFile", "path"),
        ("nonceRollbackAssurance", "pinsFile", "path"),
        ("productionEnv", "path"),
        ("python", "path"),
        ("composeFile", "path"),
    ]
    python_record = manifest["python"]
    scripts = manifest["scripts"]
    inputs = manifest["inputs"]
    outputs = manifest["outputs"]
    if (
        not isinstance(python_record, dict)
        or not isinstance(scripts, dict)
        or not isinstance(inputs, dict)
        or not isinstance(outputs, dict)
    ):
        raise AssertionError("generated manifest path containers are malformed")
    locations.extend(
        ("python", "importRoots", index, "path")
        for index, _record in enumerate(python_record["importRoots"])
    )
    locations.extend(("scripts", name, "path") for name in scripts)
    locations.extend(("inputs", name, "path") for name in inputs)
    locations.extend(("outputs", name) for name in outputs)
    return locations


def test_generator() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary).resolve()
        fixture = Fixture(base)
        original_env_root = generator.PRODUCTION_ENV_ROOT
        original_state_directory = generator.PRODUCTION_STATE_DIRECTORY
        generator.PRODUCTION_ENV_ROOT = fixture.etc
        try:
            expect_main_error_contains(
                fixture.argv(base / "noncanonical-state.json"),
                "state directory must be /var/lib/serverware/production-proof",
                "default production CLI accepted a noncanonical state directory",
            )
            generator.PRODUCTION_STATE_DIRECTORY = fixture.state
            first = base / "launch-one.json"
            second = base / "launch-two.json"
            first_unit = base / "serverware-one.service"
            second_unit = base / "serverware-two.service"
            launcher_path = "/opt/serverware/launchers/sha256-" + "ab" * 32 + "/serverware-production-launcher"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                if generator.main(
                    fixture.argv(first)
                    + [
                        "--systemd-unit-out",
                        str(first_unit),
                        "--launcher-path",
                        launcher_path,
                        "--print-sha256",
                    ]
                ) != 0:
                    raise AssertionError("generator returned a non-zero status")
            if generator.main(fixture.argv(second)) != 0:
                raise AssertionError("second generator invocation returned a non-zero status")
            if generator.main(
                fixture.argv(first)
                + ["--systemd-unit-out", str(second_unit), "--launcher-path", launcher_path]
            ) != 0:
                raise AssertionError("repeated concrete-unit generation returned a non-zero status")

            first_bytes = first.read_bytes()
            if first_bytes != second.read_bytes():
                raise AssertionError("identical inputs did not produce deterministic manifest bytes")
            expected_printed_digest = f"sha256:{hashlib.sha256(first_bytes).hexdigest()}"
            if stdout.getvalue().strip() != expected_printed_digest:
                raise AssertionError("--print-sha256 did not print the exact manifest-byte digest")
            if stat.S_IMODE(os.lstat(first).st_mode) != 0o400:
                raise AssertionError("manifest output mode is not 0400")
            if stat.S_IMODE(os.lstat(first_unit).st_mode) != 0o444:
                raise AssertionError("generated systemd unit mode is not 0444")
            if first_unit.read_bytes() != second_unit.read_bytes():
                raise AssertionError("identical launcher inputs did not produce deterministic systemd unit bytes")
            unit_text = first_unit.read_text(encoding="utf-8")
            if "<launcher-sha256>" in unit_text or "<manifest-sha256>" in unit_text:
                raise AssertionError("generated systemd unit contains an unresolved placeholder")
            expected_exec_start = f"ExecStart={launcher_path} --manifest {first}"
            generated_exec = [line for line in unit_text.splitlines() if line.startswith("Exec")]
            if generated_exec != [expected_exec_start]:
                raise AssertionError(f"generated systemd unit has an open launcher command: {generated_exec}")
            if "Type=oneshot\nRemainAfterExit=yes\n" not in unit_text:
                raise AssertionError(
                    "generated systemd unit does not retain the completed "
                    "runtime cycle for InvocationID verification"
                )
            if "--manifest-sha256" in unit_text:
                raise AssertionError("generated systemd unit bypasses launcher measurement of the manifest bytes")
            assert_no_unit_authorization_overrides(unit_text, "generated systemd unit")
            for dependency in ("After", "Wants", "Requires"):
                line = next((line for line in unit_text.splitlines() if line.startswith(f"{dependency}=")), "")
                if "serverware-launch-authority-relay.socket" not in line:
                    raise AssertionError(f"generated systemd unit omits the authority relay {dependency} dependency")
            skip_directives = [
                line
                for line in unit_text.splitlines()
                if re.match(r"^(?:Condition|Assert)[A-Za-z0-9]+=", line)
            ]
            if skip_directives:
                raise AssertionError(
                    "generated systemd unit can skip ExecStart through "
                    f"Condition/Assert directives: {skip_directives}"
                )
            if f"ReadWritePaths={fixture.state} /run/docker.sock" not in unit_text:
                raise AssertionError("generated systemd unit does not restrict writes to the selected state directory")
            if "ReadOnlyPaths=/run/serverware" not in unit_text:
                raise AssertionError("generated systemd unit does not mount the relay directory read-only")
            if "RuntimeDirectory=" in unit_text:
                raise AssertionError("generated proof unit claims relay runtime-directory lifecycle")
            if any(shell in unit_text for shell in ("/bin/sh", "/bin/bash", "/usr/bin/env", "ExecStartPre=")):
                raise AssertionError("generated systemd unit contains a shell or preparatory command")

            manifest = json.loads(first_bytes)
            if first_bytes != generator.canonical_json(manifest):
                raise AssertionError("manifest output is not canonical JSON")
            manifest_schema = load_manifest_schema()
            Draft202012Validator.check_schema(manifest_schema)
            manifest_validator = Draft202012Validator(manifest_schema)
            manifest_validator.validate(manifest)
            for location in manifest_path_locations(manifest):
                value: object = manifest
                for component in location:
                    if isinstance(component, int):
                        if not isinstance(value, list):
                            raise AssertionError(
                                f"manifest path location is not an array: {location}"
                            )
                        value = value[component]
                    else:
                        if not isinstance(value, dict):
                            raise AssertionError(
                                f"manifest path location is not an object: {location}"
                            )
                        value = value[component]
                if (
                    not isinstance(value, str)
                    or generator.PRODUCTION_MANIFEST_PATH_RE.fullmatch(value)
                    is None
                    or not value.isascii()
                ):
                    raise AssertionError(
                        f"generated manifest path is outside the ASCII contract: {location}"
                    )
                for hostile_path in (
                    "/opt/serverware/\N{LATIN SMALL LETTER E WITH ACUTE}",
                    "/opt/serverware/trailing-newline\n",
                ):
                    hostile = json.loads(json.dumps(manifest))
                    target: object = hostile
                    for component in location[:-1]:
                        if isinstance(component, int):
                            target = target[component]
                        else:
                            target = target[component]
                    target[location[-1]] = hostile_path
                    if not tuple(manifest_validator.iter_errors(hostile)):
                        raise AssertionError(
                            "manifest schema accepted an unsafe production path "
                            + ".".join(str(component) for component in location)
                        )
            for path in (
                (),
                ("authorization",),
                ("authorization", "monotonicWitness"),
                (
                    "authorization",
                    "monotonicWitness",
                    "storeAssurance",
                ),
                ("launchAttemptJournal",),
                ("globalRoleRegistry",),
                ("globalRoleRegistry", "registry"),
                ("globalRoleRegistry", "registry", "roles"),
                ("nonceRollbackAssurance",),
                ("nonceRollbackAssurance", "contract"),
                (
                    "nonceRollbackAssurance",
                    "contract",
                    "independentVerifierPins",
                ),
                (
                    "nonceRollbackAssurance",
                    "contract",
                    "publicConfigPins",
                ),
                ("python",),
                ("scripts",),
                ("inputs",),
                ("outputs",),
            ):
                hostile = json.loads(json.dumps(manifest))
                target = hostile
                for component in path:
                    target = target[component]
                target["unknown"] = True
                errors = tuple(manifest_validator.iter_errors(hostile))
                if not errors:
                    raise AssertionError(
                        "manifest schema accepted an unknown field at "
                        + (".".join(path) or "root")
                    )
            for role in generator.GLOBAL_ROLE_NAMES:
                hostile = json.loads(json.dumps(manifest))
                hostile["globalRoleRegistry"]["registry"]["roles"].pop(role)
                errors = tuple(manifest_validator.iter_errors(hostile))
                if not errors:
                    raise AssertionError(
                        "manifest schema accepted a missing global role: "
                        + role
                    )
            if set(manifest) != EXPECTED_MANIFEST_FIELDS:
                raise AssertionError(f"manifest has an open or incomplete top-level schema: {set(manifest)}")
            if manifest["apiVersion"] != generator.API_VERSION or manifest["kind"] != generator.KIND:
                raise AssertionError("manifest identity is incorrect")
            assert_closed_authorization(manifest["authorization"], "manifest.authorization")
            assert_no_authorization_material(manifest, "manifest")
            if {
                key: manifest["authorization"][key]
                for key in (
                    "authorizationScope",
                    "deploymentAudience",
                    "deploymentIdentitySha256",
                    "freshnessAuthority",
                    "releaseSequence",
                    "rollbackEpoch",
                )
            } != {
                "authorizationScope": "trusted-host-readiness",
                "deploymentAudience": "production.us-east-1:primary",
                "deploymentIdentitySha256": "sha256:" + "23" * 32,
                "freshnessAuthority": "trusted-host-wall-clock",
                "releaseSequence": 42,
                "rollbackEpoch": 0,
            }:
                raise AssertionError("manifest authorization fields do not match the required CLI inputs")
            assert_launch_attempt_journal(
                manifest["launchAttemptJournal"],
                str(fixture.state),
                "manifest.launchAttemptJournal",
            )
            assert_global_role_registry_binding(
                manifest["globalRoleRegistry"],
                "manifest.globalRoleRegistry",
            )
            assert_nonce_rollback_binding(
                manifest["nonceRollbackAssurance"],
                "manifest.nonceRollbackAssurance",
            )
            pipeline_metadata_bytes = (
                fixture.pipeline_metadata_path.read_bytes()
            )
            pipeline_metadata = json.loads(
                pipeline_metadata_bytes,
                object_pairs_hook=generator.reject_json_pairs,
                parse_float=generator.reject_json_value,
                parse_constant=generator.reject_json_value,
            )
            expected_pipeline_metadata = {
                "apiVersion": generator.PIPELINE_METADATA_API_VERSION,
                "canonicalProfile": generator.CANONICAL_JSON_PROFILE,
                "finalCompletionCompatible": False,
                "incompatibleWith": [
                    generator.INCOMPATIBLE_FINAL_PIPELINE
                ],
                "kind": "ServerwareLaunchPipelineMetadata",
                "manifestApiVersion": generator.API_VERSION,
                "manifestKind": generator.KIND,
                "manifestSha256": sha256_prefixed(first_bytes),
                "nonceRollbackAssurancePins": manifest[
                    "nonceRollbackAssurance"
                ]["contract"],
                "nonceRollbackAssurancePinsFile": manifest[
                    "nonceRollbackAssurance"
                ]["pinsFile"],
                "nonceRollbackAssurancePinsSha256": manifest[
                    "nonceRollbackAssurance"
                ]["pinsFile"]["sha256"],
                "nonceRollbackAssuranceContractSha256": manifest[
                    "nonceRollbackAssurance"
                ]["contractSha256"],
                "projectionOfManifestSha256": sha256_prefixed(
                    first_bytes
                ),
                "pipeline": generator.PIPELINE,
                "purpose": "readiness-only",
                "authorizationScope": manifest["authorization"][
                    "authorizationScope"
                ],
                "freshnessAuthority": manifest["authorization"][
                    "freshnessAuthority"
                ],
                "monotonicWitness": manifest["authorization"][
                    "monotonicWitness"
                ],
                "launchAttemptJournal": manifest[
                    "launchAttemptJournal"
                ],
                "globalRoleRegistry": manifest["globalRoleRegistry"],
                "runtimeBoundary": (
                    "legacy host Docker with /dev/nsm; never accepted as "
                    "Manifest v6 final completion"
                ),
            }
            if (
                pipeline_metadata != expected_pipeline_metadata
                or pipeline_metadata_bytes
                != generator.canonical_json(pipeline_metadata)
            ):
                raise AssertionError(
                    "pipeline metadata is not the exact canonical projection "
                    "of the current v3 manifest"
                )
            if set(manifest["inputs"]) != EXPECTED_INPUTS or set(manifest["outputs"]) != EXPECTED_OUTPUTS:
                raise AssertionError("manifest input/output maps are not closed")
            if set(manifest["scripts"]) != {"preflight", "runner"}:
                raise AssertionError("manifest script roles are not closed")
            if set(manifest["python"]) != {"path", "sha256", "importRoots"}:
                raise AssertionError("python record is not closed")
            import_roots = manifest["python"]["importRoots"]
            if [record.get("path") for record in import_roots] != [
                str(path) for path in fixture.import_roots
            ]:
                raise AssertionError("python import-root order was not preserved")
            if any(
                set(record) != {"path", "sha256"}
                or generator.DIGEST_RE.fullmatch(str(record.get("sha256", ""))) is None
                for record in import_roots
            ):
                raise AssertionError("python import roots are not closed tree-digest records")
            added_module = fixture.import_roots[0] / "added_module.py"
            added_module.write_bytes(b"VALUE = 1\n")
            changed_manifest, _ = generator.generate(parsed(fixture.argv(base / "changed.json")))
            if (
                changed_manifest["python"]["importRoots"][0]["sha256"]
                == import_roots[0]["sha256"]
            ):
                raise AssertionError("python import-root digest ignored added executable code")
            added_module.unlink()
            extension_module = fixture.files["extension_module"]
            original_extension_bytes = extension_module.read_bytes()
            extension_module.write_bytes(original_extension_bytes + b"changed\n")
            extension_manifest, _ = generator.generate(
                parsed(fixture.argv(base / "changed-extension.json"))
            )
            if (
                extension_manifest["python"]["importRoots"][2]["sha256"]
                == import_roots[2]["sha256"]
            ):
                raise AssertionError(
                    "python lib-dynload digest ignored changed extension-module bytes"
                )
            extension_module.write_bytes(original_extension_bytes)
            expected_python_digest = "sha256:" + hashlib.sha256(fixture.files["python"].read_bytes()).hexdigest()
            if manifest["python"]["sha256"] != expected_python_digest:
                raise AssertionError("python executable was not hashed correctly")

            valid_python = fixture.files["python"].read_bytes()
            invalid_python_cases = (
                ("shebang", b"#!/usr/bin/python3\n"),
                ("non-ELF", b"arbitrary executable bytes\n"),
                (
                    "wrong architecture",
                    minimal_cpython_elf(machine=183),
                ),
                (
                    "generic ELF executable",
                    minimal_cpython_elf(symbol=b"main", needed=b"libc.so.6"),
                ),
                (
                    "CPython symbol without compatible libpython",
                    minimal_cpython_elf(needed=b"libpython3.12.so.1.0"),
                ),
            )
            for label, invalid_python in invalid_python_cases:
                fixture.files["python"].write_bytes(invalid_python)
                expect_manifest_error(
                    fixture.argv(base / f"bad-python-{label.replace(' ', '-')}.json"),
                    f"generator accepted {label} as production Python",
                )
            fixture.files["python"].write_bytes(valid_python)
            fixture.files["python"].chmod(0o644)
            expect_manifest_error(
                fixture.argv(base / "non-executable-python.json"),
                "generator accepted a non-executable production Python",
            )
            fixture.files["python"].chmod(0o755)
            if any(not Path(value).is_relative_to(fixture.state) for value in manifest["outputs"].values()):
                raise AssertionError("an output escaped the state directory")
            if "argv" in first_bytes.decode("utf-8") or "arguments" in first_bytes.decode("utf-8"):
                raise AssertionError("manifest exposes an arbitrary argument surface")

            boundary_argv = replace_argument(
                fixture.argv(base / "boundary.json"),
                "--release-sequence",
                str(generator.JSON_SAFE_INTEGER_MAX),
            )
            boundary_argv = replace_argument(
                boundary_argv,
                "--rollback-epoch",
                str(generator.JSON_SAFE_INTEGER_MAX),
            )
            boundary_manifest, _ = generator.generate(parsed(boundary_argv))
            if boundary_manifest["authorization"]["releaseSequence"] != generator.JSON_SAFE_INTEGER_MAX:
                raise AssertionError("generator rejected or changed the maximum JSON-safe release sequence")
            if boundary_manifest["authorization"]["rollbackEpoch"] != generator.JSON_SAFE_INTEGER_MAX:
                raise AssertionError("generator rejected or changed the maximum JSON-safe rollback epoch")

            for value in ("", ".production", "Production", "production/east", "production-\N{LATIN SMALL LETTER E WITH ACUTE}", "a" * 129):
                expect_manifest_error(
                    replace_argument(fixture.argv(base / "bad-audience.json"), "--deployment-audience", value),
                    f"generator accepted invalid deployment audience {value!r}",
                )
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "bad-identity.json"),
                    "--deployment-identity-sha256",
                    "sha256:" + "AB" * 32,
                ),
                "generator accepted an invalid deployment identity digest",
            )
            for value in ("0", "-1", "01", "1.0", str(generator.JSON_SAFE_INTEGER_MAX + 1)):
                expect_manifest_error(
                    replace_argument(fixture.argv(base / "bad-release-sequence.json"), "--release-sequence", value),
                    f"generator accepted invalid release sequence {value!r}",
                )
            for value in ("-1", "00", "1.0", str(generator.JSON_SAFE_INTEGER_MAX + 1)):
                expect_manifest_error(
                    replace_argument(fixture.argv(base / "bad-rollback-epoch.json"), "--rollback-epoch", value),
                    f"generator accepted invalid rollback epoch {value!r}",
                )

            symlink = fixture.release / "evidence" / "symlink.fixture"
            symlink.symlink_to(fixture.files["production_images_build"])
            expect_manifest_error(
                replace_argument(fixture.argv(base / "bad-symlink.json"), "--production-images-build", str(symlink)),
                "generator accepted a symlink input",
            )

            target = fixture.files["production_images_build"]
            traversal = str(target.parent / ".." / target.parent.name / target.name)
            expect_manifest_error(
                replace_argument(fixture.argv(base / "bad-traversal.json"), "--production-images-build", traversal),
                "generator accepted a non-normalized traversal path",
            )
            for hostile_path in (
                "/opt/serverware/release with space/input.json",
                "/opt/serverware/release-\N{LATIN SMALL LETTER E WITH ACUTE}/input.json",
                "/opt/serverware/release%2fescape/input.json",
                "/opt/serverware/release\\escape/input.json",
                "/opt/serverware/release\tcontrol/input.json",
                "/" + "a" * generator.MAX_PRODUCTION_MANIFEST_PATH_BYTES,
            ):
                expect_manifest_error(
                    replace_argument(
                        fixture.argv(base / "bad-path-syntax.json"),
                        "--production-images-build",
                        hostile_path,
                    ),
                    "generator accepted a path outside the printable-ASCII "
                    f"production grammar: {hostile_path!r}",
                )
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "bad-output.json"), "--config-out", str(base / "outside-state.json")
                ),
                "generator accepted an output outside the state directory",
            )
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "journal-output-collision.json"),
                    "--config-out",
                    str(
                        fixture.state
                        / generator.ATTEMPT_JOURNAL_FILE_NAME
                    ),
                ),
                "generator accepted an output colliding with the launch journal",
            )
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "journal-lock-output-collision.json"),
                    "--config-out",
                    str(
                        fixture.state
                        / generator.ATTEMPT_JOURNAL_LOCK_FILE_NAME
                    ),
                ),
                "generator accepted an output colliding with the launch journal lock",
            )
            symlink_output = fixture.state / "symlink-output.json"
            symlink_output.symlink_to(base / "outside-state.json")
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "bad-symlink-output.json"), "--config-out", str(symlink_output)
                ),
                "generator accepted a symlink output",
            )
            nested_output = fixture.state / "nested" / "config.json"
            nested_output.parent.mkdir()
            expect_manifest_error(
                replace_argument(fixture.argv(base / "bad-nested-output.json"), "--config-out", str(nested_output)),
                "generator accepted an unknown nested output path",
            )
            duplicate_output_argv = replace_argument(
                fixture.argv(base / "bad-duplicate-output.json"),
                "--claims-file",
                str(fixture.output_paths["config_out"]),
            )
            expect_manifest_error(duplicate_output_argv, "generator accepted duplicate output paths")
            expect_manifest_error(
                replace_argument(fixture.argv(base / "bad-directory.json"), "--bench", str(fixture.release / "evidence")),
                "generator accepted a non-file immutable input",
            )

            for required_argument in (
                "--pipeline-metadata-out",
                "--deployment-audience",
                "--deployment-identity-sha256",
                "--release-sequence",
                "--rollback-epoch",
                "--expected-launch-authority-key-id",
                "--global-role-registry",
                "--expected-global-role-registry-pins-sha256",
                "--launch-authority-witness-signing-public-key-spki-base64url",
                "--expected-launch-authority-witness-key-id",
                "--launch-authority-witness-identity-sha256",
                "--launch-authority-witness-administrative-domain-sha256",
                "--launch-authority-witness-store-assurance-sha256",
                "--launch-authority-witness-store-assurance",
                "--launch-authority-witness-store-assurance-issuer-public-key-spki-base64url",
                "--expected-launch-authority-witness-store-assurance-issuer-key-id",
                "--nonce-rollback-assurance-pins",
                "--expected-nonce-rollback-assurance-pins-sha256",
            ):
                expect_main_error(
                    remove_argument(fixture.argv(base / "missing-authorization-field.json"), required_argument),
                    f"generator accepted missing required argument {required_argument}",
                )

            without_release_root = remove_argument(
                fixture.argv(base / "missing-release-root-import.json"),
                "--python-import-root",
            )
            expect_manifest_error(
                without_release_root,
                "generator accepted an import closure that omitted the complete release root",
            )

            without_lib_dynload = remove_argument_value(
                fixture.argv(base / "missing-lib-dynload.json"),
                "--python-import-root",
                str(fixture.lib_dynload),
            )
            expect_manifest_error(
                without_lib_dynload,
                "generator accepted an import closure that omitted lib-dynload",
            )
            without_vendor = remove_argument_value(
                fixture.argv(base / "missing-vendor.json"),
                "--python-import-root",
                str(fixture.vendor),
            )
            expect_manifest_error(
                without_vendor,
                "generator accepted an import closure that omitted vendor",
            )

            reordered = fixture.argv(base / "reordered-import-roots.json")
            stdlib_index = reordered.index(str(fixture.stdlib))
            dynload_index = reordered.index(str(fixture.lib_dynload))
            reordered[stdlib_index], reordered[dynload_index] = (
                reordered[dynload_index],
                reordered[stdlib_index],
            )
            expect_manifest_error(
                reordered,
                "generator accepted Python import roots in a different sys.path order",
            )

            if generator.PYTHON_STDLIB_DIRECTORY_RE.fullmatch("python3.011") is not None:
                raise AssertionError("generator accepted a non-canonical CPython stdlib version")

            extra_root = fixture.release / "extra-python-root"
            extra_root.mkdir()
            expect_manifest_error(
                fixture.argv(base / "extra-import-root.json")
                + ["--python-import-root", str(extra_root)],
                "generator accepted an extra Python import root",
            )

            extension_module.unlink()
            expect_manifest_error(
                fixture.argv(base / "empty-lib-dynload.json"),
                "generator accepted lib-dynload without extension modules",
            )
            extension_module.write_bytes(original_extension_bytes)

            alternate_python = fixture.write(
                fixture.release / "runtime" / "python" / "bin" / "python3.11",
                minimal_cpython_elf(),
            )
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "alternate-python.json"),
                    "--python",
                    str(alternate_python),
                ),
                "generator accepted a Python executable outside the fixed runtime path",
            )

            expect_main_error(
                fixture.argv(base / "missing-launcher.json") + ["--systemd-unit-out", str(base / "missing.service")],
                "generator accepted --systemd-unit-out without --launcher-path",
            )
            expect_main_error(
                fixture.argv(base / "relative-launcher.json")
                + ["--systemd-unit-out", str(base / "relative.service"), "--launcher-path", "relative/launcher"],
                "generator accepted a relative launcher path",
            )
            expect_main_error(
                fixture.argv(base / "python-launcher.json")
                + [
                    "--systemd-unit-out",
                    str(base / "python.service"),
                    "--launcher-path",
                    "/usr/bin/python3",
                ],
                "generator allowed systemd to invoke Python directly",
            )
            expect_main_error(
                fixture.argv(base / "whitespace-launcher.json")
                + [
                    "--systemd-unit-out",
                    str(base / "whitespace.service"),
                    "--launcher-path",
                    "/opt/serverware/launcher path",
                ],
                "generator accepted whitespace in the launcher path",
            )
            expect_main_error(
                fixture.argv(base / "control-launcher.json")
                + [
                    "--systemd-unit-out",
                    str(base / "control.service"),
                    "--launcher-path",
                    "/opt/serverware/launcher\npath",
                ],
                "generator accepted a control character in the launcher path",
            )
            expect_main_error(
                fixture.argv(base / "manifest with space.json"),
                "generator accepted whitespace in the manifest output path",
            )
            expect_main_error(
                fixture.argv(base / "unsafe-percent.json")
                + [
                    "--systemd-unit-out",
                    str(base / "unsafe-percent.service"),
                    "--launcher-path",
                    "/opt/serverware/launcher%p",
                ],
                "generator accepted a systemd specifier in the launcher path",
            )
            unit_symlink = base / "unit-symlink.service"
            unit_symlink.symlink_to(base / "outside.service")
            expect_main_error(
                fixture.argv(base / "unit-symlink-manifest.json")
                + ["--systemd-unit-out", str(unit_symlink), "--launcher-path", launcher_path],
                "generator replaced a symlink systemd-unit output",
            )

            with contextlib.redirect_stderr(io.StringIO()):
                try:
                    generator.build_parser().parse_args(fixture.argv(base / "bad-argv.json") + ["--arbitrary-argv", "x"])
                except SystemExit as exc:
                    if exc.code == 0:
                        raise AssertionError("unknown launcher argument exited successfully")
                else:
                    raise AssertionError("generator accepted an arbitrary launcher argument")
            for forbidden_argument in (
                "--authorization-response",
                "--authorization-signature",
                "--authorization-key",
                "--authority-socket",
                "--launch-authority-public-key",
            ):
                expect_main_error(
                    fixture.argv(base / "forbidden-authorization-argument.json")
                    + [forbidden_argument, "forbidden"],
                    f"generator accepted forbidden authorization override {forbidden_argument}",
                )
            launch_authority_key_id = fixture.trust_key_ids[
                "launch_authority"
            ]
            fixture.rewrite_witness_store_assurance(
                {"witnessIdentitySha256": launch_authority_key_id}
            )
            expect_manifest_error(
                replace_argument(
                    fixture.argv(base / "colliding-administration.json"),
                    "--launch-authority-witness-identity-sha256",
                    launch_authority_key_id,
                ),
                "generator accepted a validly signed witness-store assurance "
                "whose witness identity collides with the launch authority",
            )
        finally:
            generator.PRODUCTION_STATE_DIRECTORY = original_state_directory
            generator.PRODUCTION_ENV_ROOT = original_env_root


def test_manifest_schema_source_contract() -> None:
    loaded = load_manifest_schema()
    Draft202012Validator.check_schema(loaded)
    rust_source = RUST_LAUNCHER_PATH.read_text(encoding="utf-8")
    struct_contracts = (
        ("LaunchManifest", None),
        (
            "LaunchAuthorizationConfiguration",
            "launchAuthorizationConfiguration",
        ),
        (
            "LaunchAuthorityWitnessConfiguration",
            "launchAuthorityWitnessConfiguration",
        ),
        (
            "LaunchAuthorityWitnessStoreAssuranceEnvelope",
            "launchAuthorityWitnessStoreAssuranceEnvelope",
        ),
        (
            "LaunchAuthorityWitnessStoreAssuranceStatement",
            "launchAuthorityWitnessStoreAssuranceStatement",
        ),
        (
            "LaunchAttemptJournalConfiguration",
            "launchAttemptJournalConfiguration",
        ),
        ("GlobalRoleRegistryBinding", "globalRoleRegistryBinding"),
        ("GlobalRoleRegistry", "globalRoleRegistry"),
        ("FileRecord", "fileRecord"),
        ("PythonRecord", "pythonRecord"),
        ("ImportRootRecord", "importRootRecord"),
        ("ScriptsRecord", "scriptsRecord"),
        ("Inputs", "inputs"),
        ("Outputs", "outputs"),
        (
            "NonceRollbackAssuranceBinding",
            "nonceRollbackAssuranceBinding",
        ),
        ("NonceRollbackAssurancePins", "nonceRollbackAssurancePins"),
        ("IndependentVerifierPins", "independentVerifierPins"),
        ("PublicConfigPins", "publicConfigPins"),
        ("NonceAuthorityAssurance", "nonceAuthorityAssurance"),
        ("NonceRollbackProtection", "nonceRollbackProtection"),
    )
    for rust_struct, schema_definition in struct_contracts:
        rust_fields = rust_struct_fields(rust_source, rust_struct)
        schema_fields = schema_object_fields(loaded, schema_definition)
        if rust_fields != schema_fields:
            raise AssertionError(
                f"manifest schema/Rust field drift for {rust_struct}: "
                f"{schema_fields ^ rust_fields}"
            )

    if schema_object_fields(loaded, None) != EXPECTED_MANIFEST_FIELDS:
        raise AssertionError("manifest schema/generator top-level fields drifted")
    if (
        schema_object_fields(
            loaded, "launchAuthorizationConfiguration"
        )
        != EXPECTED_AUTHORIZATION
    ):
        raise AssertionError("manifest schema/generator authorization fields drifted")
    if schema_object_fields(loaded, "inputs") != EXPECTED_INPUTS:
        raise AssertionError("manifest schema/generator input fields drifted")
    if schema_object_fields(loaded, "outputs") != EXPECTED_OUTPUTS:
        raise AssertionError("manifest schema/generator output fields drifted")
    if (
        schema_object_fields(loaded, "globalRoles")
        != set(generator.GLOBAL_ROLE_NAMES)
    ):
        raise AssertionError("manifest schema/generator global roles drifted")
    rust_role_names_match = re.search(
        r"const GLOBAL_ROLE_NAMES: \[&str; \d+\] = \[(?P<body>.*?)\];",
        rust_source,
        re.DOTALL,
    )
    rust_role_names = (
        set(re.findall(r'"([^"]+)"', rust_role_names_match.group("body")))
        if rust_role_names_match is not None
        else set()
    )
    if rust_role_names != set(generator.GLOBAL_ROLE_NAMES):
        raise AssertionError(
            "manifest schema/generator/Rust global role names drifted"
        )
    exact_rust_role_key_set_check = (
        "let expected_roles = GLOBAL_ROLE_NAMES\n"
        "        .into_iter()\n"
        "        .map(str::to_string)\n"
        "        .collect::<BTreeSet<_>>();\n"
        "    let actual_roles = binding\n"
        "        .registry\n"
        "        .roles\n"
        "        .keys()\n"
        "        .cloned()\n"
        "        .collect::<BTreeSet<_>>();\n"
        "    if actual_roles != expected_roles {\n"
        "        return Err(LauncherError::new(\n"
        '            "globalRoleRegistry omitted, added, or claimed an unsupported role",\n'
        "        ));\n"
        "    }"
    )
    if exact_rust_role_key_set_check not in rust_source:
        raise AssertionError(
            "Rust launcher no longer imperatively rejects an inexact global "
            "role key set after BTreeMap deserialization"
        )

    definitions = loaded["$defs"]
    if not isinstance(definitions, dict):
        raise AssertionError("manifest schema definitions are invalid")
    absolute_path = definitions["absolutePath"]
    if (
        absolute_path.get("type") != "string"
        or absolute_path.get("minLength") != 2
        or absolute_path.get("maxLength")
        != generator.MAX_PRODUCTION_MANIFEST_PATH_BYTES
        or absolute_path.get("pattern")
        != generator.PRODUCTION_MANIFEST_PATH_PATTERN
        or absolute_path.get("not")
        != {
            "anyOf": [
                {"pattern": r"(^|/)\.{1,2}(/|$)|//"},
                {"pattern": r"[^/A-Za-z0-9._+@:-]"},
            ]
        }
    ):
        raise AssertionError(
            "manifest schema and generator printable-ASCII path contracts drifted"
        )
    separation_comment = definitions[
        "launchAuthorityWitnessStoreAssuranceStatement"
    ].get("$comment", "")
    for binding in generator.INDEPENDENT_ADMINISTRATION_BINDINGS:
        if binding not in separation_comment:
            raise AssertionError(
                "manifest schema omits relational independent-administration "
                f"binding: {binding}"
            )
    outside_claim = definitions["globalRoleRegistry"]["properties"][
        "rolesOutsideClaim"
    ]["prefixItems"]
    if [item["const"] for item in outside_claim] != list(
        generator.GLOBAL_ROLES_OUTSIDE_CLAIM
    ):
        raise AssertionError(
            "manifest schema/generator outside-claim roles drifted"
        )

    assurance = definitions["nonceAuthorityAssurance"]
    schema_profiles = {
        (
            option["properties"]["assuranceEvidenceType"]["const"],
            option["properties"]["backendClass"]["const"],
            option["properties"]["rollbackProtection"]["properties"][
                "keyProtection"
            ]["const"],
            option["properties"]["rollbackProtection"]["properties"][
                "mechanism"
            ]["const"],
            option["properties"]["rollbackProtection"]["properties"][
                "stateCommitment"
            ]["const"],
            option["properties"]["rollbackProtection"]["properties"][
                "verifierStateStoreClass"
            ]["const"],
        )
        for option in assurance["oneOf"]
    }
    generator_profiles = {
        (
            profile["assuranceEvidenceType"],
            profile["backendClass"],
            profile["keyProtection"],
            profile["rollbackMechanism"],
            profile["stateCommitment"],
            profile["verifierStateStoreClass"],
        )
        for profile in generator.PRODUCTION_NONCE_ASSURANCE_PROFILES.values()
    }
    if schema_profiles != generator_profiles:
        raise AssertionError("manifest schema/generator nonce profiles drifted")
    for profile in schema_profiles:
        for value in profile:
            if f'"{value}"' not in rust_source:
                raise AssertionError(
                    f"Rust launcher omits schema nonce profile value: {value}"
                )

    schema_identity = loaded["properties"]
    if (
        schema_identity["apiVersion"]["const"] != generator.API_VERSION
        or schema_identity["kind"]["const"] != generator.KIND
        or (
            f'const LAUNCH_MANIFEST_API_VERSION: &str = '
            f'"{generator.API_VERSION}";'
        )
        not in rust_source
        or (
            f'const LAUNCH_MANIFEST_KIND: &str = "{generator.KIND}";'
        )
        not in rust_source
    ):
        raise AssertionError("manifest v3 identity drifted across contracts")
    rust_path_contract = (
        "const MAX_PRODUCTION_MANIFEST_PATH_BYTES: usize = "
        f"{generator.MAX_PRODUCTION_MANIFEST_PATH_BYTES};",
        "fn require_safe_ascii_path(path: &Path, label: &str) -> Result<()>",
        "fn validate_manifest_path_encoding(manifest: &LaunchManifest) -> Result<()>",
        "validate_manifest_path_encoding(manifest)?;",
        "byte.is_ascii_alphanumeric()",
        "matches!(*byte, b'.' | b'_' | b'+' | b'@' | b':' | b'-')",
    )
    for required in rust_path_contract:
        if required not in rust_source:
            raise AssertionError(
                "Rust launcher printable-ASCII path contract drifted: "
                + required
            )
    for label in (
        "releaseRoot",
        "stateDirectory",
        "launchAttemptJournal.path",
        "launchAttemptJournal.lockPath",
        "globalRoleRegistry.pinsFile.path",
        "nonceRollbackAssurance.pinsFile.path",
        "productionEnv.path",
        "python.path",
        "python.importRoots[",
        "scripts.preflight.path",
        "scripts.runner.path",
        "composeFile.path",
        "inputs.",
        "outputs.configOut",
        "outputs.claimsFile",
        "outputs.nitroEvidenceOut",
        "outputs.readinessOut",
        "outputs.completionProofOut",
        "outputs.proxyProofSummaryOut",
        "outputs.productionHostPreflight",
    ):
        if label not in rust_source:
            raise AssertionError(
                "Rust launcher omits production path validation for " + label
            )


def assert_file_record(record: object, label: str) -> None:
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise AssertionError(f"{label} is not a closed file record")
    if not isinstance(record["path"], str) or not record["path"].startswith("/"):
        raise AssertionError(f"{label} path is not absolute")
    if record["sha256"] != "sha256:<64-lowercase-hex>":
        raise AssertionError(f"{label} does not document its required SHA-256 pin")


def test_example() -> None:
    example = json.loads(
        (ROOT / "ops" / "production-release-launch.json.example").read_text(
            encoding="utf-8"
        ),
        object_pairs_hook=generator.reject_json_pairs,
        parse_float=generator.reject_json_value,
        parse_constant=generator.reject_json_value,
    )
    if set(example) != EXPECTED_MANIFEST_FIELDS:
        raise AssertionError(f"example top-level schema is not closed: {set(example)}")
    if example["apiVersion"] != generator.API_VERSION or example["kind"] != generator.KIND:
        raise AssertionError("example manifest identity is incorrect")
    assert_closed_authorization(example["authorization"], "example.authorization", example=True)
    assert_no_authorization_material(example, "example manifest")
    release_root = "/opt/serverware/releases/<source-digest>"
    state_directory = "/var/lib/serverware/production-proof"
    if example["releaseRoot"] != release_root or example["stateDirectory"] != state_directory:
        raise AssertionError("example does not use the documented immutable release and mutable state roots")
    assert_launch_attempt_journal(
        example["launchAttemptJournal"],
        state_directory,
        "example.launchAttemptJournal",
    )
    assert_global_role_registry_binding(
        example["globalRoleRegistry"],
        "example.globalRoleRegistry",
        example=True,
    )
    assert_nonce_rollback_binding(
        example["nonceRollbackAssurance"],
        "example.nonceRollbackAssurance",
        example=True,
    )
    assert_file_record(example["productionEnv"], "productionEnv")
    if not example["productionEnv"]["path"].startswith("/etc/serverware/"):
        raise AssertionError("example production env is not under /etc/serverware")
    assert_file_record({key: example["python"][key] for key in ("path", "sha256")}, "python")
    if set(example["python"]) != {"path", "sha256", "importRoots"}:
        raise AssertionError("example python record is not closed")
    if not example["python"]["importRoots"]:
        raise AssertionError("example omits closed Python import roots")
    expected_import_root_paths = [
        release_root,
        release_root + "/runtime/python/lib/python3.11",
        release_root + "/runtime/python/lib/python3.11/lib-dynload",
        release_root + "/vendor",
    ]
    if [value.get("path") for value in example["python"]["importRoots"]] != expected_import_root_paths:
        raise AssertionError("example Python import roots do not match the closed sys.path order")
    if any(
        set(value) != {"path", "sha256"}
        or (
            str(value["path"]) != release_root
            and not str(value["path"]).startswith(release_root + "/")
        )
        or not str(value["sha256"]).startswith("sha256:")
        for value in example["python"]["importRoots"]
    ):
        raise AssertionError("example Python import root escapes the immutable release")
    if set(example["scripts"]) != {"preflight", "runner"}:
        raise AssertionError("example script map is not closed")
    for name, record in example["scripts"].items():
        assert_file_record(record, f"scripts.{name}")
    assert_file_record(example["composeFile"], "composeFile")
    if set(example["inputs"]) != EXPECTED_INPUTS:
        raise AssertionError("example immutable input map is incomplete")
    for name, record in example["inputs"].items():
        assert_file_record(record, f"inputs.{name}")
        if not record["path"].startswith(release_root + "/"):
            raise AssertionError(f"example immutable input escapes releaseRoot: {name}")
    if set(example["outputs"]) != EXPECTED_OUTPUTS:
        raise AssertionError("example output map is incomplete")
    for name, value in example["outputs"].items():
        if Path(value).parent != Path(state_directory):
            raise AssertionError(f"example output is not a direct state-directory child: {name}")


def test_make_python_runtime_contract() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    variable = (
        "PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD ?= "
        "$(PRODUCTION_RELEASE_PYTHON_STDLIB)/lib-dynload"
    )
    if variable not in makefile:
        raise AssertionError("Makefile does not define the exact production lib-dynload root")
    if (
        "PRODUCTION_RELEASE_PYTHON_STDLIB ?= "
        "$(PRODUCTION_RELEASE_ROOT)/runtime/python/lib/python3.11"
    ) not in makefile:
        raise AssertionError("Makefile production Python default is not aligned to 3.11")
    expected_order = [
        '--python-import-root "$(PRODUCTION_RELEASE_ROOT)"',
        '--python-import-root "$(PRODUCTION_RELEASE_PYTHON_STDLIB)"',
        '--python-import-root "$(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)"',
        '--python-import-root "$(PRODUCTION_RELEASE_PYTHON_VENDOR)"',
    ]
    positions = [makefile.find(value) for value in expected_order]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise AssertionError("Makefile does not preserve the closed production sys.path order")
    if 'test -d "$(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)"' not in makefile:
        raise AssertionError("Makefile does not fail closed when production lib-dynload is missing")
    for required in (
        "build-production-python-runtime:",
        "--target production-python-runtime-artifact",
        "SERVERWARE_PRODUCTION_PYTHON_RUNTIME_ARTIFACT=",
    ):
        if required not in makefile:
            raise AssertionError(f"Makefile omits production Python artifact wiring: {required}")


def test_make_readiness_invocation_contract() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    inventory_match = re.search(
        r"^override PRODUCTION_READINESS_EXPECTED_OUTPUTS := \\\n"
        r"(?P<body>(?:\t.*\n)+)",
        makefile,
        re.MULTILINE,
    )
    if inventory_match is None:
        raise AssertionError(
            "Makefile omits the immutable production readiness output inventory"
        )
    make_output_files = set(
        re.findall(
            r"\$\(PRODUCTION_STATE_DIRECTORY\)/([A-Za-z0-9._+-]+)",
            inventory_match.group("body"),
        )
    )
    manifest_output_files = {
        "configOut": "production-readiness-config.json",
        "claimsFile": "production-readiness-claims.json",
        "nitroEvidenceOut": "nitro-kms-evidence.json",
        "readinessOut": "production-readiness.json",
        "completionProofOut": "serverware-completion-proof.json",
        "proxyProofSummaryOut": "proxy-response-proof-summary.json",
        "productionHostPreflight": "production-host-preflight.json",
    }
    if set(manifest_output_files) != EXPECTED_OUTPUTS:
        raise AssertionError(
            "source fixture manifest output inventory drifted from OUTPUT_ARGUMENTS"
        )
    if make_output_files != set(manifest_output_files.values()):
        raise AssertionError(
            "Make readiness output inventory does not exactly match every "
            f"manifest output: {make_output_files ^ set(manifest_output_files.values())}"
        )
    output_arguments = dict(generator.OUTPUT_ARGUMENTS)
    for field, filename in manifest_output_files.items():
        expected_argument = (
            f'--{output_arguments[field]} '
            f'"$(PRODUCTION_STATE_DIRECTORY)/{filename}"'
        )
        if expected_argument not in makefile:
            raise AssertionError(
                "Make manifest generation and readiness inventory drifted for "
                f"{field}: {expected_argument}"
            )
    if (
        "override PRODUCTION_READINESS_INVOCATION_RECEIPT := "
        "$(PRODUCTION_STATE_DIRECTORY)/run-production-readiness-final.receipt"
        not in makefile
    ):
        raise AssertionError(
            "Makefile omits the fixed per-invocation readiness receipt"
        )
    if (
        "override PRODUCTION_READINESS_INVOCATION_LOCK := "
        "$(PRODUCTION_STATE_DIRECTORY)/run-production-readiness-final.lock"
        not in makefile
    ):
        raise AssertionError(
            "Makefile omits the fixed exclusive readiness invocation lock"
        )

    target_match = re.search(
        r"^run-production-readiness-final:\n(?P<body>(?:\t.*\n)+)",
        makefile,
        re.MULTILINE,
    )
    if target_match is None:
        raise AssertionError(
            "Makefile omits run-production-readiness-final recipe"
        )
    target = target_match.group("body")
    cleanup = (
        'for output in $(PRODUCTION_READINESS_EXPECTED_OUTPUTS) "$$receipt"; do'
    )
    stop = '/usr/bin/systemctl stop "$$unit"'
    start = '/usr/bin/systemctl start "$$unit"'
    post_start_outputs = (
        "for output in $(PRODUCTION_READINESS_EXPECTED_OUTPUTS); do"
    )
    receipt_publish = '/usr/bin/ln -- "$$receipt_tmp" "$$receipt"'
    positions = [
        target.find(stop),
        target.find(cleanup),
        target.find(start),
        target.find(post_start_outputs),
        target.find(receipt_publish),
    ]
    if any(position < 0 for position in positions) or positions != sorted(
        positions
    ):
        raise AssertionError(
            "Make readiness cleanup, execution, output verification, and "
            "no-replace receipt publication are missing or reordered"
        )
    required_fragments = (
        "test ! -e \"$$output\" && test ! -L \"$$output\"",
        "/usr/bin/rm -- \"$$output\"",
        'test "$$unit" = "serverware-production-release-proof.service"',
        "for directory in /var /var/lib /var/lib/serverware "
        '"$$state_directory"; do',
        "flock --exclusive --nonblock 9",
        '"/proc/$$$$/fd/9"',
        "readiness invocation lock descriptor identity changed",
        "readiness invocation lock path identity changed",
        "--property=ConditionResult --value",
        "--property=Result --value",
        "--property=ExecMainCode --value",
        "--property=ExecMainStatus --value",
        "--property=ActiveState --value",
        "--property=SubState --value",
        "--property=InvocationID --value",
        "--property=ExecMainStartTimestampMonotonic --value",
        "--property=ExecMainExitTimestampMonotonic --value",
        'test "$$condition_result" = yes',
        'test "$$result" = success',
        'test "$$exec_main_code" = exited',
        'test "$$exec_main_status" = 0',
        'test "$$active_state" = active',
        'test "$$sub_state" = exited',
        'test "$$invocation_id" != "$$previous_invocation_id"',
        "output_identity_before=$$(stat -Lc",
        "output_identity_after=$$(stat -Lc",
        "completionProofIdentity=%s",
        "completionProofSha256=%s",
        "manifestIdentity=%s",
        "manifestSha256=%s",
        "output=%s|%s|%s",
        'test ! -e "$$receipt_tmp" && test ! -L "$$receipt_tmp"',
        'test "$$(stat -Lc \'%u:%g:%a:%h:%F\' "$$receipt")" = '
        '"0:0:400:1:regular file"',
    )
    for fragment in required_fragments:
        if fragment not in target:
            raise AssertionError(
                "Make readiness invocation contract omits: " + fragment
            )
    if re.search(
        r"(?:^|[;\t ])(?:mv|/usr/bin/mv)\b[^\n]*\$\$receipt",
        target,
    ):
        raise AssertionError(
            "Make readiness receipt publication may overwrite an existing path"
        )
    if target.count(receipt_publish) != 1:
        raise AssertionError(
            "Make readiness receipt must have one no-replace publication point"
        )


def test_systemd_unit() -> None:
    unit = (ROOT / "ops" / "systemd" / "serverware-production-release-proof.service").read_text(encoding="utf-8")
    if unit != generator.SYSTEMD_UNIT_TEMPLATE:
        raise AssertionError("embedded concrete-unit template drifted from the checked-in audited systemd unit")
    active = [line.strip() for line in unit.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    directives: dict[str, list[str]] = {}
    for line in active:
        if line.startswith("["):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise AssertionError(f"invalid active systemd line: {line}")
        directives.setdefault(key, []).append(value)

    for forbidden in (
        "Environment",
        "EnvironmentFile",
        "PassEnvironment",
        "LoadCredential",
        "LoadCredentialEncrypted",
        "SetCredential",
        "SetCredentialEncrypted",
        "ImportCredential",
        "ExecStartPre",
        "WorkingDirectory",
    ):
        if forbidden in directives:
            raise AssertionError(f"systemd unit includes forbidden ambient launcher directive: {forbidden}")
    skip_directives = sorted(
        key
        for key in directives
        if key.startswith("Condition") or key.startswith("Assert")
    )
    if skip_directives:
        raise AssertionError(
            "systemd unit can skip or short-circuit ExecStart through "
            f"Condition/Assert directives: {skip_directives}"
        )
    unexpected_exec = sorted(key for key in directives if key.startswith("Exec") and key != "ExecStart")
    if unexpected_exec:
        raise AssertionError(f"systemd unit includes additional executable directives: {unexpected_exec}")
    if (
        directives.get("Type") != ["oneshot"]
        or directives.get("RemainAfterExit") != ["yes"]
        or directives.get("User") != ["root"]
        or directives.get("Group") != ["root"]
    ):
        raise AssertionError("systemd service is not a root oneshot")
    if directives.get("UMask") != ["0077"]:
        raise AssertionError("systemd service does not set UMask=0077")

    exec_start = directives.get("ExecStart", [])
    if len(exec_start) != 1:
        raise AssertionError("systemd service must have exactly one ExecStart")
    command = shlex.split(exec_start[0])
    if command[1:] != [
        "--manifest",
        "/etc/serverware/production-release-launch.json",
    ]:
        raise AssertionError(f"launcher receives arguments outside the closed manifest path: {command}")
    if not re.fullmatch(
        r"/opt/serverware/launchers/sha256-<launcher-sha256>/serverware-production-launcher", command[0]
    ):
        raise AssertionError("ExecStart does not select a content-addressed native launcher")
    if any(shell in exec_start[0] for shell in ("/bin/sh", "/bin/bash", "/usr/bin/env", " -c ")):
        raise AssertionError("ExecStart uses a shell or environment trampoline")
    if "python" in Path(command[0]).name.lower() or any(".py" in argument.lower() for argument in command[1:]):
        raise AssertionError("systemd unit invokes Python directly instead of the native launcher")
    assert_no_unit_authorization_overrides(unit, "checked-in systemd unit")

    expected_dependencies = {
        "After": {"network-online.target", "docker.service", "serverware-launch-authority-relay.socket"},
        "Wants": {"network-online.target", "serverware-launch-authority-relay.socket"},
        "Requires": {"docker.service", "serverware-launch-authority-relay.socket"},
    }
    for directive, expected in expected_dependencies.items():
        values = directives.get(directive, [])
        if len(values) != 1 or set(shlex.split(values[0])) != expected:
            raise AssertionError(f"systemd dependency mismatch for {directive}: {values}")

    required_exact = {
        "NoNewPrivileges": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "PrivateDevices": "yes",
        "PrivateIPC": "yes",
        "RestrictSUIDSGID": "yes",
        "LockPersonality": "yes",
        "MemoryDenyWriteExecute": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes",
        "ProtectKernelLogs": "yes",
        "ProtectControlGroups": "yes",
        "ProtectClock": "yes",
        "ProtectHostname": "yes",
        "RestrictNamespaces": "yes",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "DevicePolicy": "closed",
    }
    for key, expected in required_exact.items():
        if directives.get(key) != [expected]:
            raise AssertionError(f"systemd hardening mismatch for {key}: {directives.get(key)}")
    if directives.get("CapabilityBoundingSet") != [""] or directives.get("AmbientCapabilities") != [""]:
        raise AssertionError("systemd service does not drop all capabilities")
    if directives.get("DeviceAllow") != ["/dev/nsm rw"] or directives.get("BindReadOnlyPaths") != ["-/dev/nsm"]:
        raise AssertionError("systemd service does not document and constrain the NSM exception")
    if (
        "This legacy readiness pipeline exposes NSM to a host Docker workload."
        not in unit
    ):
        raise AssertionError(
            "systemd service does not retain the exact template explanation "
            "for its NSM device exception"
        )
    expected_writes = {
        "/var/lib/serverware/production-proof",
        "/run/docker.sock",
    }
    write_paths = directives.get("ReadWritePaths", [])
    if len(write_paths) != 1 or set(shlex.split(write_paths[0])) != expected_writes:
        raise AssertionError(f"systemd service has an open or incomplete write set: {write_paths}")
    if directives.get("ReadOnlyPaths") != ["/run/serverware"]:
        raise AssertionError("proof service does not keep the relay socket directory read-only")
    if "RuntimeDirectory" in directives or "RuntimeDirectoryMode" in directives:
        raise AssertionError("proof service must not own or remove the relay runtime directory")

    relay_socket_unit = (
        ROOT / "ops/systemd/serverware-launch-authority-relay.socket"
    ).read_text(encoding="utf-8")
    for required in (
        "ListenSequentialPacket=/run/serverware/launch-authority.sock",
        "SocketUser=root",
        "SocketGroup=root",
        "SocketMode=0600",
        "DirectoryMode=0711",
        "RemoveOnStop=yes",
    ):
        if required not in relay_socket_unit:
            raise AssertionError(
                f"relay socket unit does not exclusively own runtime lifecycle: {required}"
            )


def main() -> None:
    test_independent_administration_pairwise_contract()
    test_generator()
    test_manifest_schema_source_contract()
    test_example()
    test_make_python_runtime_contract()
    test_make_readiness_invocation_contract()
    test_systemd_unit()
    print("production launch asset tests passed")


if __name__ == "__main__":
    main()
