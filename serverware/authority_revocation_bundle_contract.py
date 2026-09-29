"""Hash-free closed shapes for already-owned revocation retention documents.

The caller must complete its bounded capture before these checks. They do not
copy, encode, parse or authenticate evidence, and return no verification token.
The genuine mixed verifier still checks source declarations, primary proofs,
counted frontiers, mutation effects and every observed address association.
"""
from __future__ import annotations

from serverware import authority_contract
from serverware import authority_complete_query as complete
from serverware import authority_index_contract as counted
from serverware import authority_root_transition as primary_wire
from serverware.authority_query_read_work import MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES


BUNDLE_SCHEMA = "serverware.policyAuthorityRevocationProofBundle/v1"
BUNDLE_PROFILE = "serverware.policyAuthorityRevocationProofBundleProfile/v1"
TRANSITION_SCHEMA = "serverware.policyAuthorityRevocationReadWriteTransition/v1"
TRANSITION_PROFILE = "serverware.policyAuthorityRevocationReadWriteTransitionProfile/v1"
PUBLIC_BUNDLE_SCHEMA = "serverware.policyAuthorityRevocationProofBundle/v2"
PUBLIC_BUNDLE_PROFILE = "serverware.policyAuthorityRevocationProofBundleProfile/v2"
PUBLIC_TRANSITION_SCHEMA = "serverware.policyAuthorityRevocationReadWriteTransition/v2"
PUBLIC_TRANSITION_PROFILE = "serverware.policyAuthorityRevocationReadWriteTransitionProfile/v2"
MAX_COMPACT_BYTES = 65536
MAX_COMPACT_NODES = 1024

BUNDLE_FIELDS = frozenset({"schema", "profile", "sourceRevision", "inputs"})
INPUT_FIELDS = frozenset({
    "operation", "arguments", "cutoffUs", "queries", "businessBeforeRoots",
    "authorizationBeforeRoots", "selectedRows", "beforeProofs", "queryFrontiers",
    "countedBeforeHeads", "mutations", "writeFrontiers", "requestDigest",
    "assertionBinding", "queryReads",
})
TRANSITION_FIELDS = frozenset({
    "schema", "profile", "sourceRevision", "operation", "requestDigest", "cutoffUs",
    "assertionBinding", "countedProfile", "projectionManifestDigest", "proofBundleDigest",
    "primaryTransition", "indexBeforeHeads", "indexAfterHeads", "metrics",
})
HEAD_FIELDS = frozenset({"indexId", "indexRevision", "rootDigest", "leafCount"})
PHASE_FIELDS = ("generation", "declarationBinding", "observationValidation",
                "pointBinding", "proofWork", "completeBinding")
WORK_FIELDS = frozenset({"hashWork", "inputBytes", "jsonNodes"})
_SELECTED_FIELDS = frozenset({"table", "key", "keyDigest", "present", "row", "contractSelector"})
_MUTATION_FIELDS = frozenset({"templateId", "operation", "table", "key", "keyDigest", "expectedRow", "row"})
_PROOF_FIELDS = frozenset({"schema", "table", "key", "keyDigest", "present", "rowDigest",
    "leafDigest", "rootRevision", "rootDigest", "siblings", "proofDigest"})
_LEVEL_FIELDS = frozenset({"depth", "pathPrefix", "selectedNibble", "childDigests"})
_QUERY_FIELDS = frozenset({"operation", "role", "selectorItems", "maximumRows"})
_READ_FIELDS = frozenset({"queryId", "declaredQueryJson", "resolvedQueryJson", "addresses", "returnedRowCount"})
_ADDRESS_FIELDS = frozenset({"table", "keyJson", "keyDigest", "present"})
_ASSERTION_FIELDS = frozenset({"credentialRecordId", "challengeId"})
_MAX_HEADS = 11
_QUERY_COUNT = 6
_MAX_READS = 50
_MAX_OUTSIDE_PREFIXES = 4800
_SPEC = authority_contract.operation_spec(complete.OPERATION)
_MAX_SELECTED = _SPEC["maximumQueryRows"]
_MAX_MUTATIONS = _SPEC["maximumMutations"]
_MAX_WRITE_FRONTIER = 16 * (1 + counted.KEY_NIBBLES * 2 * min(_MAX_SELECTED, _MAX_MUTATIONS))
_WORK_BOUNDS = {"hashWork": MAX_HASHES, "inputBytes": MAX_INPUT_BYTES, "jsonNodes": MAX_JSON_NODES}


class RevocationBundleContractError(ValueError):
    pass


def _object(value, fields, label):
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(key) is not str or len(key) > 64 for key in value)
            or set(value) != fields):
        raise RevocationBundleContractError(f"revocation retained {label} is not a closed object")


def _array(value, maximum, label, *, minimum=0):
    if type(value) is not list or not minimum <= len(value) <= maximum:
        raise RevocationBundleContractError(f"revocation retained {label} is not a bounded array")


def _text(value, maximum=128, *, minimum=1):
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise RevocationBundleContractError("revocation retained text is not an exact bounded string")


def _integer(value, maximum=counted.I64_MAX, *, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RevocationBundleContractError("revocation retained integer is not an exact bounded value")


def _boolean(value):
    if type(value) is not bool:
        raise RevocationBundleContractError("revocation retained presence is not an exact boolean")


def _digest(value):
    _text(value, 71, minimum=71)
    if not value.startswith("sha256:") or any(character not in "0123456789abcdef" for character in value[7:]):
        raise RevocationBundleContractError("revocation retained digest is not canonical SHA-256")


def _hex(value, maximum, *, minimum=0):
    _text(value, maximum, minimum=minimum)
    if any(character not in "0123456789abcdef" for character in value):
        raise RevocationBundleContractError("revocation retained path is not bounded lowercase hexadecimal")


def _literal(value, expected):
    if type(value) is not str or value != expected:
        raise RevocationBundleContractError("revocation retained source schema, profile or operation changed")


def _assertion(value):
    if public_binding(value):
        from serverware import authority_public_webauthn_revocation as public
        public.binding_shape(value)
        return
    _object(value, _ASSERTION_FIELDS, "assertion binding")
    for identity in value.values():
        _text(identity, 1024)


def public_binding(value):
    from serverware import authority_public_webauthn_revocation as public
    return type(value) is dict and value.get("schema") == public.BINDING_SCHEMA


def profile(binding, *, transition=False):
    if public_binding(binding):
        return ((PUBLIC_TRANSITION_SCHEMA, PUBLIC_TRANSITION_PROFILE) if transition else
            (PUBLIC_BUNDLE_SCHEMA, PUBLIC_BUNDLE_PROFILE))
    return (TRANSITION_SCHEMA, TRANSITION_PROFILE) if transition else (BUNDLE_SCHEMA, BUNDLE_PROFILE)


def _key(value):
    if type(value) is not dict or not 1 <= len(value) <= 32:
        raise RevocationBundleContractError("revocation retained primary key is not a bounded object")
    for name, scalar in value.items():
        _text(name)
        if type(scalar) is str:
            _text(scalar, MAX_INPUT_BYTES, minimum=0)
        elif type(scalar) is int:
            if scalar.bit_length() > 16384:
                raise RevocationBundleContractError("revocation retained key integer is too large")
        elif type(scalar) is not bool:
            raise RevocationBundleContractError("revocation retained key has a non-scalar value")


def _row(value):
    if value is not None and type(value) is not dict:
        raise RevocationBundleContractError("revocation retained full row is not an object or null")


def _roots(value):
    _array(value, authority_contract.MAX_QUERY_PROOFS, "primary roots")
    for root in value:
        _object(root, primary_wire.ROOT_FIELDS, "primary root")
        _text(root["table"])
        _integer(root["rootRevision"])
        _digest(root["rootDigest"])
        _integer(root["leafCount"])


def _root_pair(business, authorization):
    _roots(business)
    _roots(authorization)
    if not business or len(business) + len(authorization) > authority_contract.MAX_QUERY_PROOFS:
        raise RevocationBundleContractError("revocation retained primary root classes exceed their inventory")


def _heads(value):
    _array(value, _MAX_HEADS, "counted heads", minimum=5)
    for head in value:
        _object(head, HEAD_FIELDS, "counted head")
        _text(head["indexId"])
        _integer(head["indexRevision"])
        _digest(head["rootDigest"])
        _integer(head["leafCount"])


def _proof(value):
    _object(value, _PROOF_FIELDS, "primary proof")
    _literal(value["schema"], "serverware.policyAuthorityRadixMultiproof/v3")
    _text(value["table"])
    _key(value["key"])
    _boolean(value["present"])
    _integer(value["rootRevision"])
    for name in ("keyDigest", "leafDigest", "rootDigest", "proofDigest"):
        _digest(value[name])
    if value["rowDigest"] is not None:
        _digest(value["rowDigest"])
    _array(value["siblings"], authority_contract.TREE_DEPTH, "primary sibling levels",
           minimum=authority_contract.TREE_DEPTH)
    for level in value["siblings"]:
        _object(level, _LEVEL_FIELDS, "primary sibling level")
        _integer(level["depth"], authority_contract.TREE_DEPTH - 1)
        _hex(level["pathPrefix"], authority_contract.TREE_DEPTH - 1)
        _hex(level["selectedNibble"], 1, minimum=1)
        _array(level["childDigests"], authority_contract.TREE_RADIX, "primary child vector",
               minimum=authority_contract.TREE_RADIX)
        for digest in level["childDigests"]:
            _digest(digest)


def _frontier(value, maximum):
    _array(value, maximum, "counted frontier")
    for terminal in value:
        if type(terminal) is not dict or type(terminal.get("kind")) is not str:
            raise RevocationBundleContractError("revocation retained frontier kind is invalid")
        if terminal["kind"] == "leaf":
            _object(terminal, frozenset({"kind", "key", "primaryKeyDigest", "primaryRowDigest"}), "index leaf")
            _hex(terminal["key"], counted.KEY_NIBBLES, minimum=counted.KEY_NIBBLES)
            _digest(terminal["primaryKeyDigest"])
            _digest(terminal["primaryRowDigest"])
        elif terminal["kind"] == "opaque":
            _object(terminal, frozenset({"kind", "prefix", "digest", "count"}), "opaque index subtree")
            _hex(terminal["prefix"], counted.KEY_NIBBLES, minimum=1)
            _digest(terminal["digest"])
            _integer(terminal["count"], minimum=1)
        else:
            raise RevocationBundleContractError("revocation retained frontier kind is unknown")


def validate_inputs_shape(inputs) -> None:
    """Close one captured normalized graph; this does not verify its evidence."""
    _object(inputs, INPUT_FIELDS, "inputs")
    _literal(inputs["operation"], complete.OPERATION)
    if type(inputs["arguments"]) is not dict or len(inputs["arguments"]) > complete.MAX_ARGUMENT_FIELDS:
        raise RevocationBundleContractError("revocation retained arguments exceed their bounded object shape")
    _integer(inputs["cutoffUs"], minimum=-(2**63))
    _digest(inputs["requestDigest"])
    _assertion(inputs["assertionBinding"])
    _array(inputs["queries"], _QUERY_COUNT, "complete declarations", minimum=_QUERY_COUNT)
    for query in inputs["queries"]:
        _object(query, _QUERY_FIELDS, "complete declaration")
        _literal(query["operation"], complete.OPERATION)
        _text(query["role"])
        _integer(query["maximumRows"], complete.CASCADE_MAX, minimum=1)
        _array(query["selectorItems"], 2, "selector pairs")
        for pair in query["selectorItems"]:
            _array(pair, 2, "selector pair", minimum=2)
            _text(pair[0])
            if type(pair[1]) is str:
                _text(pair[1], 1024)
            else:
                _integer(pair[1], minimum=-(2**63))
    _root_pair(inputs["businessBeforeRoots"], inputs["authorizationBeforeRoots"])
    _array(inputs["selectedRows"], _MAX_SELECTED, "selected rows")
    for selected in inputs["selectedRows"]:
        _object(selected, _SELECTED_FIELDS, "selected row")
        _text(selected["table"])
        _key(selected["key"])
        _digest(selected["keyDigest"])
        _boolean(selected["present"])
        _row(selected["row"])
        if selected["contractSelector"] is not None:
            raise RevocationBundleContractError("revocation retained selector annotation is not source admitted")
    _array(inputs["beforeProofs"], len(inputs["selectedRows"]), "before proofs",
           minimum=len(inputs["selectedRows"]))
    for proof in inputs["beforeProofs"]:
        _proof(proof)
    _array(inputs["mutations"], _MAX_MUTATIONS, "mutations")
    for mutation in inputs["mutations"]:
        _object(mutation, _MUTATION_FIELDS, "mutation")
        _text(mutation["templateId"])
        _text(mutation["table"])
        if type(mutation["operation"]) is not str or mutation["operation"] not in ("INSERT", "UPDATE", "DELETE"):
            raise RevocationBundleContractError("revocation retained mutation opcode is invalid")
        _key(mutation["key"])
        _digest(mutation["keyDigest"])
        _row(mutation["expectedRow"])
        _row(mutation["row"])
    _heads(inputs["countedBeforeHeads"])
    _array(inputs["queryFrontiers"], _QUERY_COUNT, "query frontiers", minimum=_QUERY_COUNT)
    for frontier in inputs["queryFrontiers"]:
        _object(frontier, frozenset({"queryId", "frontier"}), "query frontier")
        _text(frontier["queryId"], 1024)
        _frontier(frontier["frontier"], _MAX_OUTSIDE_PREFIXES + complete.CASCADE_MAX)
    _array(inputs["writeFrontiers"], _MAX_HEADS, "write frontiers")
    for frontier in inputs["writeFrontiers"]:
        _object(frontier, frozenset({"indexId", "frontier"}), "write frontier")
        _text(frontier["indexId"])
        _frontier(frontier["frontier"], _MAX_WRITE_FRONTIER)
    _array(inputs["queryReads"], _MAX_READS, "query observations", minimum=1)
    address_count = 0
    for record in inputs["queryReads"]:
        _object(record, _READ_FIELDS, "query observation")
        _text(record["queryId"], 1024)
        # No ASCII scan or encoding here. The actual restoration worker pays
        # for encoding, then genuine immutable constructors validate ASCII.
        _text(record["declaredQueryJson"], MAX_INPUT_BYTES, minimum=2)
        _text(record["resolvedQueryJson"], MAX_INPUT_BYTES, minimum=2)
        _integer(record["returnedRowCount"], _MAX_SELECTED)
        _array(record["addresses"], _MAX_SELECTED - address_count, "observed addresses")
        address_count += len(record["addresses"])
        for address in record["addresses"]:
            _object(address, _ADDRESS_FIELDS, "observed address")
            _text(address["table"])
            _text(address["keyJson"], MAX_INPUT_BYTES, minimum=2)
            _digest(address["keyDigest"])
            _boolean(address["present"])


def validate_bundle_shape(value) -> None:
    """Validate only the closed envelope and bounded captured input shapes."""
    _object(value, BUNDLE_FIELDS, "proof bundle")
    _object(value["inputs"], INPUT_FIELDS, "inputs")
    schema, selected_profile = profile(value["inputs"]["assertionBinding"])
    _literal(value["schema"], schema)
    _literal(value["profile"], selected_profile)
    _literal(value["sourceRevision"], authority_contract.SOURCE_REVISION)
    validate_inputs_shape(value["inputs"])


def _primary_transition(value):
    _object(value, primary_wire.TRANSITION_FIELDS, "primary transition")
    _literal(value["schema"], primary_wire.TRANSITION_SCHEMA)
    _literal(value["profile"], primary_wire.TRANSITION_PROFILE)
    _root_pair(value["businessBeforeRoots"], value["authorizationBeforeRoots"])
    _root_pair(value["businessAfterRoots"], value["authorizationAfterRoots"])
    bounds = {"selectedRows": _MAX_SELECTED, "mutations": _MAX_MUTATIONS,
        "proofVectors": _MAX_SELECTED * authority_contract.TREE_DEPTH,
        "proofChildSlots": _MAX_SELECTED * authority_contract.TREE_DEPTH * authority_contract.TREE_RADIX,
        "recomputedAncestors": _MAX_MUTATIONS * authority_contract.TREE_DEPTH,
        "hashWork": authority_contract.TREE_DEPTH + 2 + _MAX_SELECTED * (2 * authority_contract.TREE_DEPTH + 8),
        "inputBytes": MAX_INPUT_BYTES, "jsonNodes": MAX_JSON_NODES}
    _object(value["metrics"], frozenset(bounds), "primary transition metrics")
    for name, maximum in bounds.items():
        _integer(value["metrics"][name], maximum)


def validate_transition_shape(value) -> None:
    """Check compact shape and metric sums, never recompute claimed effects.

    MAX_COMPACT_BYTES/NODES are enforced by the caller's metered copier and
    encoder. This helper deliberately performs no serialization to find sizes.
    """
    _object(value, TRANSITION_FIELDS, "transition")
    schema, selected_profile = profile(value["assertionBinding"], transition=True)
    _literal(value["schema"], schema)
    _literal(value["profile"], selected_profile)
    _literal(value["sourceRevision"], authority_contract.SOURCE_REVISION)
    _literal(value["operation"], complete.OPERATION)
    _digest(value["requestDigest"])
    _integer(value["cutoffUs"], minimum=-(2**63))
    _assertion(value["assertionBinding"])
    _literal(value["countedProfile"], counted.PROFILE)
    _digest(value["projectionManifestDigest"])
    _digest(value["proofBundleDigest"])
    _primary_transition(value["primaryTransition"])
    _heads(value["indexBeforeHeads"])
    _heads(value["indexAfterHeads"])
    metrics = value["metrics"]
    _object(metrics, frozenset(PHASE_FIELDS) | WORK_FIELDS, "transition metrics")
    for phase in PHASE_FIELDS:
        _object(metrics[phase], WORK_FIELDS, "phase metrics")
        for name, maximum in _WORK_BOUNDS.items():
            _integer(metrics[phase][name], maximum)
    for name, maximum in _WORK_BOUNDS.items():
        _integer(metrics[name], maximum)
        if metrics[name] != sum(metrics[phase][name] for phase in PHASE_FIELDS):
            raise RevocationBundleContractError("revocation retained metric sum differs from its phases")
