"""Exact successor to OAuth Setup revision three; never a proxy-ready receipt."""
from collections.abc import Mapping

from serverware import authority_oauth_setup as setup
from serverware import authority_policy_candidate as candidate
from serverware import authority_publication_approval as assertions

canonical, require, digest, sha256 = setup.canonical, setup.require, setup.digest, setup.sha256
OP_BIND = "setup.policy.bind-candidate"
OPERATIONS = ASSERTION_OPERATIONS = frozenset({OP_BIND})
TABLE = "setup_policy_continuations"
HTTP_SCHEMA = "serverware.setupPolicyCandidateRequest/v1"
OPTIONS_SCHEMA = "serverware.setupPolicyCandidateOptions/v1"
MAX_ARGUMENT_BYTES = 2 * 1024 * 1024
MAX_ROW_BYTES = MAX_ARGUMENT_BYTES + setup.MAX_ROW_BYTES + 8192
FIELDS = frozenset({"actor_id", "control_plane_configuration_digest", "credential_policy", "request"})
REQUEST_FIELDS = frozenset({"setupBinding", "credentialId", "credentialVersion", "generationClaimOriginal",
    "routePolicyDigest", "assignmentDigest", "issuedAtEpochNs", "expiresAtEpochNs"})
ROW_FIELDS = frozenset({"session_id", "revision", "phase", "owner_id", "setup_original", "setup_sha256",
    "credential_id", "credential_version", "generation_request_id", "generation_claim_sha256",
    "generation_publication_digest", "candidate_id", "canary_id", "artifact_envelope_digest",
    "assignment_envelope_digest", "policy_hash", "route_policy_digest", "assignment_digest",
    "request_original", "request_digest", "configuration_digest", "created_at", "expires_at"})


def claim_original(text):
    require(type(text) is str)
    raw = text.encode("ascii")
    row = setup.document(raw, candidate.MAX_ORIGINAL_BYTES * 2)
    require(candidate.row_original(row) == raw and row["publication_envelope_digest"] is not None)
    return row


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    setup.text(value["actor_id"], 1024)
    require(value["actor_id"].startswith("oidc:"))
    digest(value["control_plane_configuration_digest"])
    assertions.policy(value["credential_policy"])
    request = value["request"]
    require(type(request) is dict and set(request) == REQUEST_FIELDS)
    bound = setup.binding(request["setupBinding"])
    require(bound["revision"] == 3 and bound["ownerId"] == value["actor_id"]
        and bound["currentAssigneeId"] in {None, value["actor_id"]})
    setup.identifier(request["credentialId"])
    require(type(request["credentialVersion"]) is int and request["credentialVersion"] == 1)
    claim_original(request["generationClaimOriginal"])
    digest(request["routePolicyDigest"]); digest(request["assignmentDigest"])
    issued, expires = candidate.epoch(request["issuedAtEpochNs"]), candidate.epoch(request["expiresAtEpochNs"])
    require(issued % 1000 == 0 and expires % 1000 == 0 and 0 < expires - issued <= 30_000_000_000
        and expires <= bound["expiresAtEpochNs"])
    original = {name: value[name] for name in FIELDS}
    require(len(canonical(original)) <= MAX_ARGUMENT_BYTES)
    return original


def reviewed_assignment(session, management):
    """Use the exact bundle already admitted by controlled native publication.

    This computes only the reviewed association. It does not replace policy
    compilation, signature admission, policy activation or runtime permission.
    """
    bundle = management["candidatePolicyBundle"]
    require(type(bundle) is dict and type(bundle.get("routes")) is list
        and type(bundle.get("principals")) is list)
    routes = [row for row in bundle["routes"] if type(row) is dict and row.get("id") == session["route_id"]]
    principals = [row for row in bundle["principals"] if type(row) is dict and row.get("id") == session["principal_id"]]
    require(len(routes) == len(principals) == 1)
    route = routes[0]
    require(type(route.get("principals")) is list and (session["principal_id"] in route["principals"] or "*" in route["principals"])
        and route.get("credentialRef") == session["credential_id"])
    from serverware.policy_bundle import policy_hash
    assignment = {"principalId": session["principal_id"], "routeId": session["route_id"],
        "credentialId": session["credential_id"], "credentialVersion": session["credential_version"],
        "policyHash": policy_hash(bundle), "routePolicyDigest": sha256(canonical(route))}
    return assignment, sha256(canonical(assignment))


def row_original(value):
    require(type(value) is dict and set(value) == ROW_FIELDS and type(value["revision"]) is int
        and value["revision"] == 0 and value["phase"] == "candidate_bound")
    args_raw = value["request_original"].encode("ascii")
    args = arguments(OP_BIND, setup.document(args_raw, MAX_ARGUMENT_BYTES))
    require(canonical(args) == args_raw)
    session_raw = value["setup_original"].encode("ascii")
    session = setup.document(session_raw, setup.MAX_ROW_BYTES)
    require(setup.row_original(session) == session_raw and setup.row_binding(session) == args["request"]["setupBinding"]
        and session["phase"] == "credential_activated" and session["revision"] == 3
        and session["status"] == "active" and session["terminal_at"] is None)
    claim = claim_original(args["request"]["generationClaimOriginal"])
    bound = candidate.context(setup.document(claim["context_json"].encode("ascii"), 8192))
    assignment, assignment_digest = reviewed_assignment(session, candidate.management_original(claim["management_request_json"]))
    expected = {"session_id": session["id"], "owner_id": args["actor_id"], "setup_sha256": sha256(session_raw),
        "credential_id": session["credential_id"], "credential_version": session["credential_version"],
        "generation_request_id": claim["request_id"], "generation_claim_sha256": sha256(args["request"]["generationClaimOriginal"].encode("ascii")),
        "generation_publication_digest": claim["publication_envelope_digest"], "candidate_id": bound["candidateId"],
        "canary_id": bound["canaryId"], "artifact_envelope_digest": bound["artifactEnvelopeDigest"],
        "assignment_envelope_digest": bound["assignmentEnvelopeDigest"], "policy_hash": assignment["policyHash"],
        "route_policy_digest": assignment["routePolicyDigest"], "assignment_digest": assignment_digest,
        "configuration_digest": args["control_plane_configuration_digest"], "expires_at": session["expires_at"]}
    require(all(value[name] == expected_value for name, expected_value in expected.items())
        and args["request"]["credentialId"] == session["credential_id"]
        and args["request"]["credentialVersion"] == session["credential_version"]
        and args["request"]["routePolicyDigest"] == assignment["routePolicyDigest"]
        and args["request"]["assignmentDigest"] == assignment_digest)
    digest(value["request_digest"]); setup.epoch(value["created_at"])
    raw = canonical(value)
    require(len(raw) <= MAX_ROW_BYTES)
    return raw


def request_digest(operation, value):
    from serverware import authority_contract as contract
    from serverware import authority_request_commitment as commitment
    values = arguments(operation, value, typed="businessIntent" in value)
    typed = {**values, "businessIntent": contract.synthesize_business_intent(operation, values)}
    return commitment.framed_digest("serverware.policyAuthorityV9Request/v1", canonical({
        "schema": "serverware.policyAuthorityV9Authorization/v1", "operation": operation,
        "handler": contract.operation_spec(operation)["handler"], "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": commitment._authorization_arguments(typed)}))
