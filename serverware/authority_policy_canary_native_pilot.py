"""Explicit compiler-signed native pilot inventory and exact membership proofs.

No generic policy principal list is pilot permission. Only the complete
inventory inside the actual independently signed compiler analysis is used.
Old constrained/7 remains a separate unchanged profile.
"""
from serverware import authority_policy_canary as p
from serverware import authority_policy_canary_native_opening as framing

MODE = "constrained-native-inventory-v1"
FIELDS = frozenset({"mode", "principalSetRootSha256", "routeSetRootSha256", "maximumRequests",
    "maximumDurationNanos", "maximumWriteRequests", "cells", "principalSha256s", "routeSha256s"})
MAX_MEMBERS = 128


def _leaves(values, lane):
    p.require(lane in {"Principal", "Route"} and type(values) is list and 1 <= len(values) <= MAX_MEMBERS)
    for value in values:
        p.digest(value)
    p.require(values == sorted(set(values)), "approved pilot inventory must be complete, sorted and unique")
    return [framing.framed("serverware.policyPilot" + lane + "Leaf/v1", value.encode("ascii")) for value in values]


def _node(left, right):
    return framing.framed("serverware.policyPilotMembershipNode/v1", bytes.fromhex(left[7:]), bytes.fromhex(right[7:]))


def root(values, lane):
    level = _leaves(values, lane)
    while len(level) > 1:
        level = [_node(level[n], level[n + 1]) if n + 1 < len(level) else level[n] for n in range(0, len(level), 2)]
    return level[0]


def validate(value):
    from serverware import db
    p.require(type(value) is dict and set(value) == FIELDS and value["mode"] == MODE)
    for lane in ("Principal", "Route"):
        p.require(root(value[lane.lower() + "Sha256s"], lane) == value[lane.lower() + "SetRootSha256"],
            "signed native pilot inventory does not match its independently approved root")
    for name in ("maximumRequests", "maximumDurationNanos"):
        db._candidate_authority_int(name, value[name], minimum=1)
    db._candidate_authority_int("maximumWriteRequests", value["maximumWriteRequests"])
    p.require(value["maximumWriteRequests"] <= value["maximumRequests"])
    cells = db._policy_authority_semantic_expansion_cells("native pilot cells", value["cells"], maximum=128, allow_empty=False)
    p.require(cells == value["cells"] and all(
        cell["pilotPrincipalSetRootSha256"] == value["principalSetRootSha256"]
        and cell["pilotRouteSetRootSha256"] == value["routeSetRootSha256"] for cell in cells))
    return value


def _proof(values, lane, selected):
    level = _leaves(values, lane)
    p.require(selected in values, "observed identity is outside the signed approved pilot inventory")
    index, proof, leaf = values.index(selected), [], level[values.index(selected)]
    while len(level) > 1:
        if index % 2:
            proof.append({"siblingSide": "left", "siblingSha256": level[index - 1]})
        elif index + 1 < len(level):
            proof.append({"siblingSide": "right", "siblingSha256": level[index + 1]})
        level = [_node(level[n], level[n + 1]) if n + 1 < len(level) else level[n] for n in range(0, len(level), 2)]
        index //= 2
    return leaf, proof


def membership(pilot, binding, cells):
    from serverware import db
    if not cells:
        return None
    validate(pilot)
    p.require(all(cell in pilot["cells"] for cell in cells))
    principal, principal_proof = _proof(pilot["principalSha256s"], "Principal", binding["principalSha256"])
    route, route_proof = _proof(pilot["routeSha256s"], "Route", binding["routeSha256"])
    value = {"principalLeafSha256": principal, "principalProof": principal_proof,
        "routeLeafSha256": route, "routeProof": route_proof}
    return db._policy_authority_pilot_membership("native approved pilot membership", value,
        authority_binding=binding, expansion_cells=cells)


def compiler_key(assignment, signing_key_id, public_key):
    """Assignment is an actual verified original at each production caller."""
    from cryptography.hazmat.primitives import serialization
    framing._keys(assignment)  # Full independent-role inventories and roots.
    authority = assignment["authorityKeyIndependence"]
    bindings = authority["bindings"]
    p.require(type(bindings) is list and 25 <= len(bindings) <= 256)
    selected = [key for key in bindings if key["role"] == "compiler-analysis" and key["scopeSha256"] == assignment["assignmentId"]]
    p.require(len(selected) == 1)
    key = selected[0]
    p.require(set(key) == {"role", "scopeSha256", "keyAlgorithm", "keyId", "keySpkiSha256", "keyMaterialSha256"})
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    spki = p.sha256(der)
    material = framing.framed("serverware.policyAuthorityPublicKeyMaterial/v1", b"ed25519", der)
    p.require(key["keyAlgorithm"].lower() == "ed25519" and signing_key_id == key["keyId"] == key["keySpkiSha256"] == spki
        and key["keyMaterialSha256"] == material, "signer is not the independently assigned compiler key")
    return spki


def admit(state, item, assignment_row):
    """Extra native variant binding after the real static signature admission."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from serverware import db
    pilot = validate(db.loads(item["pilot_restrictions_json"], None))
    state.charge(4 * (len(pilot["principalSha256s"]) + len(pilot["routeSha256s"])) + len(pilot["cells"]))
    state.static("canary_assignment", assignment_row, "assignment",
        db._candidate_authority_signed_record(assignment_row, current_prefix="assignment"), persist=False)
    assignment = db.loads(assignment_row["assignment_payload_json"], None)
    head = state.one("policy_authority_trusted_key_heads", evidence_kind="compiler_analysis")
    key = state.one("policy_authority_trusted_keys", evidence_kind="compiler_analysis", key_revision=head["head_key_revision"])
    raw = db._candidate_authority_b64url("compiler public key", key["public_key_base64url"], expected_bytes=32)
    compiler_key(assignment, item["signing_key_id"], Ed25519PublicKey.from_public_bytes(raw))
    return pilot
