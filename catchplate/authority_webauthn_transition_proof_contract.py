"""Closed source shapes for three successor transition proof documents.

These checks operate on bounded, owned lossless JSON. They do not authenticate
requests, originals, rows, query completeness, roots or effects. Full row and
result JSON remains subject to genuine primary and semantic replay. Only the
generic retained primary-proof/frontier shapes are reused; no revocation or
evidence-admission plan protocol is widened. Source pins are import-time source
metadata, not request-work hashes or independently admitted root authority.
"""
from __future__ import annotations

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_complete_query as complete
from catchplate import authority_complete_query_batch as batch
from catchplate import authority_complete_read_write as read_write
from catchplate import authority_contract as authority
from catchplate import authority_index_projection as projection
from catchplate import authority_primary_contract as primary
from catchplate import authority_revocation_bundle_contract as retained
from catchplate import authority_revocation_plan_contract as shape


SCHEMA = "catchplate.policyAuthorityWebAuthnTransitionProof/v1"
IDENTITY_DOMAIN = "catchplate.policyAuthorityWebAuthnTransitionProofIdentity/v1"
MAX_BYTES, MAX_NODES, MAX_DEPTH = shape.MAX_PAYLOAD_BYTES, shape.MAX_JSON_NODES, shape.MAX_JSON_DEPTH
OPERATIONS = frozenset({complete.REGISTRATION_OPERATION, complete.STAGE_OPERATION, "webauthn.trust.complete"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "operation", "operationManifestDigest",
    "queryManifestDigest", "authorizationManifestDigest", "handlerContractDigest", "request",
    "inputsDigest", "databaseCutoffUs", "businessBeforeRoots", "authorizationBeforeRoots",
    "selectedRows", "beforeProofs", "queryReads", "countedBeforeHeads", "queryFrontiers",
    "writeFrontiers", "transition", "businessAfterRoots", "authorizationAfterRoots", "countedAfterHeads"})
HEAD_FIELDS = retained.HEAD_FIELDS
QUERY_READ_FIELDS, QUERY_ADDRESS_FIELDS = retained._READ_FIELDS, retained._ADDRESS_FIELDS
QUERY_FRONTIER_FIELDS = frozenset({"queryId", "frontier"})
WRITE_FRONTIER_FIELDS = frozenset({"indexId", "frontier"})
TRANSITION_FIELDS = frozenset({"mutations", "result", "kernelWorkUnits", "workUnits"})
QUERY_MANIFEST_DIGEST = primary.source_query_manifest_digest()
AUTHORIZATION_MANIFEST_DIGEST = primary.source_authorization_manifest_digest()
SPECS = {operation: authority.operation_spec(operation) for operation in OPERATIONS}
HANDLER_DIGESTS = {operation: authority.handler_contract_digest(operation) for operation in OPERATIONS}
BUSINESS_TABLES = {operation: tuple(sorted(set(spec["businessReads"]) | set(spec["businessWrites"])))
    for operation, spec in SPECS.items()}
AUTHORIZATION_TABLES = {operation: tuple(sorted(spec["authorizationReads"])) for operation, spec in SPECS.items()}
_TEMPLATES = {operation: {item["templateId"]: item for item in spec["mutationTemplates"]}
    for operation, spec in SPECS.items()}


class WebAuthnTransitionProofContractError(ValueError):
    pass


def _operation(operation):
    if type(operation) is not str or operation not in OPERATIONS:
        raise WebAuthnTransitionProofContractError("transition proof operation is not source fixed")
    return SPECS[operation]


def _family(operation, arguments):
    _operation(operation)
    if operation == "webauthn.trust.complete":
        return {"query_count": 0, "head_count": 3, "max_frontier_rows": 0}
    return complete.family_limits(operation, arguments=arguments)


def _head_ids(operation, arguments):
    """Hash-free full potential union; actual declarations are rebound later."""
    spec = _operation(operation)
    identities = {index_id for table in spec["businessWrites"]
        for index_id in projection.index_ids_for_table(table)}
    if operation != "webauthn.trust.complete":
        identities.update(complete._role(operation, role).index_id
            for role in complete.family_roles(operation, arguments=arguments))
    if not 1 <= len(identities) <= len(projection.INDEX_IDS):
        raise WebAuthnTransitionProofContractError("transition counted-head inventory is invalid")
    return tuple(sorted(identities))


def _roots(values, tables):
    retained._array(values, len(tables), "transition primary roots", minimum=len(tables))
    for root, table in zip(values, tables):
        shape._object(root, retained.primary_wire.ROOT_FIELDS, "transition primary root")
        shape._literal(root["table"], table)
        shape._integer(root["rootRevision"])
        shape._integer(root["leafCount"])
        shape._digest(root["rootDigest"])


def _key(value, table):
    retained._key(value)
    shape._object(value, frozenset(primary.PRIMARY_KEY_COLUMNS[table]), "transition source primary key")


def _request(value, operation):
    shape._object(value, shape.TYPED_REQUEST_FIELDS, "transition typed request")
    shape._literal(value["schema"], shape.TYPED_REQUEST_SCHEMA)
    shape._literal(value["operation"], operation)
    shape._literal(value["handler"], SPECS[operation]["handler"])
    shape._literal(value["operationManifestDigest"], authority.OPERATION_MANIFEST_DIGEST)
    for name in ("operationId", "requestDigest"):
        shape._digest(value[name])
    shape._bounded_object(value["arguments"], complete.MAX_ARGUMENT_FIELDS, "transition arguments")


def _heads(values, identities):
    retained._array(values, len(identities), "transition counted heads", minimum=len(identities))
    for value, identity in zip(values, identities):
        shape._object(value, HEAD_FIELDS, "transition counted head")
        shape._literal(value["indexId"], identity)
        shape._integer(value["indexRevision"])
        shape._digest(value["rootDigest"])
        shape._integer(value["leafCount"])


def _reads(values, operation):
    spec = _operation(operation)
    maximum = spec["maximumQueryRows"]
    tables = BUSINESS_TABLES[operation] + AUTHORIZATION_TABLES[operation]
    retained._array(values, maximum, "transition query reads", minimum=1)
    total, identities = 0, set()
    for record in values:
        shape._object(record, QUERY_READ_FIELDS, "transition query read")
        shape._text(record["queryId"], 1024)
        if record["queryId"] in identities:
            raise WebAuthnTransitionProofContractError("transition query reads repeat an identity")
        identities.add(record["queryId"])
        for name in ("declaredQueryJson", "resolvedQueryJson"):
            shape._text(record[name], MAX_BYTES, minimum=2)
        shape._integer(record["returnedRowCount"], maximum)
        retained._array(record["addresses"], maximum - total, "transition query addresses")
        total += len(record["addresses"])
        if operation == "webauthn.trust.complete" and len(record["addresses"]) != 1:
            raise WebAuthnTransitionProofContractError("completion query requires one exact PK address")
        present = 0
        for address in record["addresses"]:
            shape._object(address, QUERY_ADDRESS_FIELDS, "transition query address")
            shape._text(address["table"])
            if address["table"] not in tables:
                raise WebAuthnTransitionProofContractError("transition query table is outside its source inventory")
            shape._text(address["keyJson"], MAX_BYTES, minimum=2)
            shape._digest(address["keyDigest"])
            retained._boolean(address["present"])
            present += int(address["present"])
        if present != record["returnedRowCount"]:
            raise WebAuthnTransitionProofContractError("transition returned count differs from its address presence")


def _transition(value, operation):
    spec = SPECS[operation]
    shape._object(value, TRANSITION_FIELDS, "transition effects")
    retained._array(value["mutations"], spec["maximumMutations"], "transition mutations")
    framework = 0
    for mutation in value["mutations"]:
        shape._object(mutation, retained._MUTATION_FIELDS, "transition mutation")
        table = mutation["table"]
        shape._text(table)
        if table not in spec["businessWrites"]:
            raise WebAuthnTransitionProofContractError("transition mutation table is not source writable")
        _key(mutation["key"], table)
        shape._digest(mutation["keyDigest"])
        shape._digest(mutation["templateId"])
        template = _TEMPLATES[operation].get(mutation["templateId"])
        if (template is None or template["table"] != table
                or type(mutation["operation"]) is not str
                or template["mutation"] != mutation["operation"]):
            raise WebAuthnTransitionProofContractError("transition mutation differs from its source template")
        old, new = mutation["expectedRow"], mutation["row"]
        if ((mutation["operation"] == "INSERT" and (old is not None or type(new) is not dict))
                or (mutation["operation"] == "UPDATE" and (type(old) is not dict or type(new) is not dict))
                or (mutation["operation"] == "DELETE" and (type(old) is not dict or new is not None))):
            raise WebAuthnTransitionProofContractError("transition mutation lifecycle is invalid")
        framework += int(table == capacity.AGGREGATE_TABLE and mutation["key"] == {"aggregate_id": capacity.AGGREGATE_ID})
    if framework > 1 or len(value["mutations"]) - framework > spec["maximumBusinessMutations"]:
        raise WebAuthnTransitionProofContractError("transition mutations exceed business/framework slots")
    shape._json_root(value["result"])
    shape._integer(value["kernelWorkUnits"], spec["maximumBusinessWorkUnits"], minimum=1)
    shape._integer(value["workUnits"], spec["maximumWorkUnits"], minimum=1)


def _frontiers(value, operation, arguments):
    family = _family(operation, arguments)
    retained._array(value["queryFrontiers"], family["query_count"], "transition query frontiers",
        minimum=family["query_count"])
    total, query_ids = 0, set()
    for item in value["queryFrontiers"]:
        shape._object(item, QUERY_FRONTIER_FIELDS, "transition query frontier")
        shape._text(item["queryId"], 1024)
        if item["queryId"] in query_ids:
            raise WebAuthnTransitionProofContractError("transition query frontiers repeat an identity")
        query_ids.add(item["queryId"])
        maximum = batch.MAX_OUTSIDE_PREFIXES + family["max_frontier_rows"]
        retained._array(item["frontier"], maximum, "transition query frontier terminals")
        total += len(item["frontier"])
        if total > MAX_NODES // 9:
            raise WebAuthnTransitionProofContractError("transition frontiers exceed their shared node ceiling")
        retained._frontier(item["frontier"], maximum)
    expected = tuple(sorted({index_id for mutation in value["transition"]["mutations"]
        for index_id in projection.index_ids_for_table(mutation["table"])}))
    retained._array(value["writeFrontiers"], len(expected), "transition write frontiers", minimum=len(expected))
    maximum = read_write._source_sizes(SPECS[operation])[2]
    for item, identity in zip(value["writeFrontiers"], expected):
        shape._object(item, WRITE_FRONTIER_FIELDS, "transition write frontier")
        shape._literal(item["indexId"], identity)
        retained._array(item["frontier"], maximum, "transition write frontier terminals")
        total += len(item["frontier"])
        if total > MAX_NODES // 9:
            raise WebAuthnTransitionProofContractError("transition frontiers exceed their shared node ceiling")
        retained._frontier(item["frontier"], maximum)


def validate_payload_shape(value):
    """Close the original graph; genuine replay must verify every relationship."""
    shape._object(value, PAYLOAD_FIELDS, "successor transition proof")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    operation = value["operation"]
    spec = _operation(operation)
    for name, expected in (("operationManifestDigest", authority.OPERATION_MANIFEST_DIGEST),
            ("queryManifestDigest", QUERY_MANIFEST_DIGEST),
            ("authorizationManifestDigest", AUTHORIZATION_MANIFEST_DIGEST),
            ("handlerContractDigest", HANDLER_DIGESTS[operation])):
        shape._literal(value[name], expected)
    shape._digest(value["inputsDigest"])
    shape._integer(value["databaseCutoffUs"], minimum=1)
    _request(value["request"], operation)
    for prefix, tables in (("business", BUSINESS_TABLES[operation]),
                           ("authorization", AUTHORIZATION_TABLES[operation])):
        _roots(value[prefix + "BeforeRoots"], tables)
        _roots(value[prefix + "AfterRoots"], tables)
    tables = BUSINESS_TABLES[operation] + AUTHORIZATION_TABLES[operation]
    retained._array(value["selectedRows"], spec["maximumQueryRows"], "transition selections", minimum=1)
    retained._array(value["beforeProofs"], len(value["selectedRows"]), "transition primary proofs",
        minimum=len(value["selectedRows"]))
    framework = 0
    for selected in value["selectedRows"]:
        shape._object(selected, retained._SELECTED_FIELDS, "transition selected row")
        table = selected["table"]
        shape._text(table)
        if table not in tables:
            raise WebAuthnTransitionProofContractError("transition selection is outside its source inventory")
        _key(selected["key"], table)
        shape._digest(selected["keyDigest"])
        retained._boolean(selected["present"])
        if (selected["contractSelector"] is not None
                or selected["present"] and type(selected["row"]) is not dict
                or not selected["present"] and selected["row"] is not None):
            raise WebAuthnTransitionProofContractError("transition selected row lifecycle changed")
        framework += int(table == capacity.AGGREGATE_TABLE and selected["key"] == {"aggregate_id": capacity.AGGREGATE_ID})
    if framework > 1 or len(value["selectedRows"]) - framework > spec["maximumBusinessQueryRows"]:
        raise WebAuthnTransitionProofContractError("transition selections exceed business/framework slots")
    for proof in value["beforeProofs"]:
        retained._proof(proof)
        if proof["table"] not in tables:
            raise WebAuthnTransitionProofContractError("transition proof table is outside its source inventory")
        _key(proof["key"], proof["table"])
    _reads(value["queryReads"], operation)
    _transition(value["transition"], operation)
    identities = _head_ids(operation, value["request"]["arguments"])
    _heads(value["countedBeforeHeads"], identities)
    _heads(value["countedAfterHeads"], identities)
    _frontiers(value, operation, value["request"]["arguments"])
