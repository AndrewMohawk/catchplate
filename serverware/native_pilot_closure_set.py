"""Unsigned static closure sets with explicit, closed profile selection.

These are data validators, not independent approval, assignment verification,
signing, installation, native process ownership or a runnable pilot profile.
The complete independently selected manifests are supplied; no observation,
timestamp, key, provenance statement or authority is invented. A successor
assignment must separately authorize BOTH roots under explicit new semantics.
Legacy assignment/proof-scope manifest and policy fields are not reinterpreted.
"""
from __future__ import annotations

import copy
import json

from serverware import native_pilot_window_authority as window
from serverware import native_shadow_nitro_profile as p

API = "serverware.nativeCustodyExecutionClosureSet/v1"
ROLES = ("retrieval", "persistence", "trustedTime", "generationInstall", "commitRequest",
    "ingressAdmission", "terminalAppend", "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit", "bridge")
GENESIS_API = "serverware.nativePublicationGenesisClosureSet/v1"
GENESIS_ROLES = ("publicationGenesisRetrieval", "publicationGenesis", "publicationGenesisCoordinator")
PUBLICATION_API = "serverware.nativeCustodyExecutionClosureSet/v2"
PUBLICATION_ROLES = ROLES[:-1] + ("publicationReconciliation", "bridge")
MAX_BYTES = 12 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
FIELDS = ("apiVersion", "members", "setRootSha256", "seccompSetRootSha256")
MANIFEST_FIELDS = ("apiVersion", "profile", "imageSha256", "workerExecutableSha256", "seccompPolicy",
    "runtimeConfigurationSha256", "buildProvenance", "manifestSha256")
PROVENANCE_FIELDS = ("sourceTreeSha256", "dependencyLockSha256", "buildRecipeSha256", "toolchainClosureSha256",
    "provenanceStatementSha256", "transparencyLogEntrySha256", "reproducibleBuildRequired", "provenanceSha256")
LEAF_DOMAIN = b"serverware.nativeCustodyExecutionClosureSetLeaf/v1"
ROOT_DOMAIN = b"serverware.nativeCustodyExecutionClosureSetRoot/v1"
SECCOMP_DOMAIN = b"serverware.nativeCustodySeccompSetRoot/v1"
GENESIS_LEAF_DOMAIN = b"serverware.nativePublicationGenesisClosureSetLeaf/v1"
GENESIS_ROOT_DOMAIN = b"serverware.nativePublicationGenesisClosureSetRoot/v1"
GENESIS_SECCOMP_DOMAIN = b"serverware.nativePublicationGenesisSeccompSetRoot/v1"
PUBLICATION_LEAF_DOMAIN = b"serverware.nativeCustodyExecutionClosureSetLeaf/v2"
PUBLICATION_ROOT_DOMAIN = b"serverware.nativeCustodyExecutionClosureSetRoot/v2"
PUBLICATION_SECCOMP_DOMAIN = b"serverware.nativeCustodySeccompSetRoot/v2"


def _profile(api_version):
    p.require(type(api_version) is str)
    if api_version == API:
        return ROLES, LEAF_DOMAIN, ROOT_DOMAIN, SECCOMP_DOMAIN
    if api_version == GENESIS_API:
        return GENESIS_ROLES, GENESIS_LEAF_DOMAIN, GENESIS_ROOT_DOMAIN, GENESIS_SECCOMP_DOMAIN
    p.require(api_version == PUBLICATION_API)
    return PUBLICATION_ROLES, PUBLICATION_LEAF_DOMAIN, PUBLICATION_ROOT_DOMAIN, PUBLICATION_SECCOMP_DOMAIN


def _manifest(value, role, *, api_version=API):
    p.fields(value, MANIFEST_FIELDS)
    roles, _, _, _ = _profile(api_version)
    p.require(role in roles)
    version = "2" if role == "bridge" else "1"
    p.require(value["apiVersion"] == "serverware.nativeCustodyExecutionClosure/v" + version
        and value["profile"] == ("measured-bootstrap-late-runtime-static-amd64-v1" if role == "bridge"
            else "sealed-memfd-squashfs-static-amd64-v1"))
    for name in ("imageSha256", "workerExecutableSha256", "runtimeConfigurationSha256", "manifestSha256"):
        p.digest(value[name])
    # Reuse public structural commitments; Rust retains the full exact compiler
    # and actual installed-filter/image checks. This is not a second compiler.
    window._seccomp(value["seccompPolicy"])
    p.require(value["seccompPolicy"]["architecture"] == "x86-64")
    provenance = p.fields(value["buildProvenance"], PROVENANCE_FIELDS)
    p.require(provenance["reproducibleBuildRequired"] is True)
    for name in PROVENANCE_FIELDS:
        if name != "reproducibleBuildRequired":
            p.digest(provenance[name])
    p.require(provenance["provenanceSha256"] == p.framed(b"serverware.policyShadowCustodyBuildProvenance/v1",
        (p.canonical([provenance[name] for name in PROVENANCE_FIELDS[:-1]]),)))
    p.require(value["manifestSha256"] == p.framed(value["apiVersion"].encode("ascii"),
        (p.canonical([value[name] for name in MANIFEST_FIELDS[:-1]]),)))
    raw = p.canonical(value)
    p.require(len(raw) <= MAX_MANIFEST)
    return raw


def _roots(members, *, api_version=API):
    roles, leaf_domain, root_domain, seccomp_domain = _profile(api_version)
    p.require(type(members) is list and len(members) == len(roles))
    leaves, policies = [], []
    for role, member in zip(roles, members, strict=True):
        p.fields(member, ("role", "manifest"))
        p.require(member["role"] == role)
        raw = _manifest(member["manifest"], role, api_version=api_version)
        # Exactly canonical [role, full manifest]. Validate each manifest under
        # its existing node/size caps, not one pooled cap across the whole set.
        leaf_raw = b"[" + p.canonical(role) + b"," + raw + b"]"
        leaves.append(p.framed(leaf_domain, (leaf_raw,)))
        policies.append([role, member["manifest"]["seccompPolicy"]["structurallyVerifiedPolicySha256"]])
    return (p.framed(root_domain, (p.canonical(leaves),)),
        p.framed(seccomp_domain, (p.canonical(policies),)), leaves)


def _wire(value):
    # Called only after closed member/manifest validation. Same ASCII/integer
    # canonical bytes as p.canonical, without pooling all validated trees.
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    p.require(0 < len(raw) <= MAX_BYTES)
    return raw


def _value(value, *, api_version=API):
    p.fields(value, FIELDS)
    p.require(value["apiVersion"] == api_version)
    root, seccomp_root, leaves = _roots(value["members"], api_version=api_version)
    p.require(p.digest(value["setRootSha256"]) == root
        and p.digest(value["seccompSetRootSha256"]) == seccomp_root)
    return leaves


def set_original(members: list, *, api_version=API) -> bytes:
    """Compose supplied manifests under one explicit API; default stays v1."""
    members = copy.deepcopy(members)
    root, seccomp_root, _ = _roots(members, api_version=api_version)
    value = {"apiVersion": api_version, "members": members, "setRootSha256": root, "seccompSetRootSha256": seccomp_root}
    return _wire(value)


def validate(original: bytes, *, api_version=API) -> dict:
    """Verify closed static grammar/commitments, not provenance or authority."""
    p.require(type(original) is bytes and 0 < len(original) <= MAX_BYTES)
    value = json.loads(original.decode("ascii"), object_pairs_hook=p._pairs,
        parse_float=p._reject, parse_constant=p._reject)
    _value(value, api_version=api_version)
    p.require(_wire(value) == original)
    return value


def require_binding(original: bytes, *, expected_set_root: str, expected_seccomp_set_root: str, api_version=API) -> dict:
    """Compare separately authenticated expected roots; never authenticate them.

    The caller must independently admit their actual assignment/profile source.
    Supplying this document's own hashes does not establish that authority.
    """
    value = validate(original, api_version=api_version)
    p.require(value["setRootSha256"] == p.digest(expected_set_root)
        and value["seccompSetRootSha256"] == p.digest(expected_seccomp_set_root))
    return value


def leaf_binding(validated: dict, role: str, *, api_version=API) -> dict:
    """Return explicit data commitments for one fixed role, never a live owner."""
    value = copy.deepcopy(validated)
    leaves = _value(value, api_version=api_version)
    _wire(value)
    roles, _, _, _ = _profile(api_version)
    p.require(type(role) is str and role in roles)
    index = roles.index(role)
    manifest = value["members"][index]["manifest"]
    return {"role": role, "setRootSha256": value["setRootSha256"],
        "seccompSetRootSha256": value["seccompSetRootSha256"],
        "manifestSha256": manifest["manifestSha256"], "leafSha256": leaves[index],
        "structurallyVerifiedPolicySha256": manifest["seccompPolicy"]["structurallyVerifiedPolicySha256"]}
