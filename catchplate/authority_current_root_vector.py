"""Complete source-owned primary/count root vectors, without root authority.

This closed computation commits every primary table in the complete authority
read/write/authorization union and every counted projection. Operation-local
root classes and selected index subsets cannot substitute for that inventory.
Original canonical bytes, source manifests, descriptor revisions and counts
are validated on the caller's existing work; no allowance is created here.

A matching digest proves neither population, enrollment, currentness, shared
database/snapshot provenance nor permission to reserve or execute anything.
Empty descriptors are admitted spellings, never inferred genesis. There is no
SQL, network, clock, signing, durable state or successful-authority carrier.
"""
from __future__ import annotations

from catchplate import authority_complete_query_batch as capture
from catchplate import authority_contract as authority
from catchplate import authority_index_contract as counted
from catchplate import authority_index_projection as projection
from catchplate import authority_index_range as ranges
from catchplate import authority_primary_contract as primary
from catchplate import authority_radix_mutation as radix
from catchplate import authority_revocation_plan as framing
from catchplate import authority_revocation_proof_bundle as encoding
from catchplate import authority_revocation_roots as roots
from catchplate import authority_revocation_wire as wire


SCHEMA = "catchplate.policyAuthorityCompleteRootVector/v1"
IDENTITY_DOMAIN = "catchplate.policyAuthorityCompleteRootVectorIdentity/v1"
PRIMARY_INVENTORY_SCHEMA = "catchplate.policyAuthorityPrimaryRootInventory/v1"
MAX_BYTES = 64 * 1024
MAX_NODES = 4096
MAX_DEPTH = 4
PRIMARY_TABLES = tuple(sorted(primary.PRIMARY_KEY_COLUMNS))
INDEX_IDS = tuple(sorted(projection.INDEX_IDS))
_FIELDS = frozenset({"schema", "schemaVersion", "sourceRevision", "operationManifestDigest",
    "queryManifestDigest", "authorizationManifestDigest", "primaryInventoryDigest",
    "projectionManifestDigest", "primaryRoots", "countedRoots"})
_DIGEST_FIELDS = ("operationManifestDigest", "queryManifestDigest", "authorizationManifestDigest",
    "primaryInventoryDigest", "projectionManifestDigest")
_PRIMARY_FIELDS = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})
_COUNTED_FIELDS = frozenset({"indexId", "table", "countedProfile", "projectionDigest",
    "projectionManifestDigest", "indexRevision", "rootDigest", "leafCount"})


class CurrentRootVectorError(ValueError):
    pass


def _closed(value, fields, label):
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(name) is not str or len(name) > 128 for name in value)
            or set(value) != fields):
        raise CurrentRootVectorError(label + " is not a closed exact object")


def _literal(value, expected, label):
    if type(value) is not type(expected) or value != expected:
        raise CurrentRootVectorError(label + " differs from its source contract")


def _shape(document):
    """Bound the entire shallow graph before copying or native hashing."""
    _closed(document, _FIELDS, "complete root vector")
    _literal(document["schema"], SCHEMA, "vector schema")
    _literal(document["schemaVersion"], authority.SCHEMA_VERSION, "database schema version")
    _literal(document["sourceRevision"], authority.SOURCE_REVISION, "source revision")
    for name in _DIGEST_FIELDS:
        counted._digest(document[name], name)
    primary_values, index_values = document["primaryRoots"], document["countedRoots"]
    if type(primary_values) is not list or len(primary_values) != len(PRIMARY_TABLES):
        raise CurrentRootVectorError("primary vector is not the complete source inventory")
    if type(index_values) is not list or len(index_values) != len(INDEX_IDS):
        raise CurrentRootVectorError("counted vector is not the complete source inventory")
    for table, row in zip(PRIMARY_TABLES, primary_values):
        _closed(row, _PRIMARY_FIELDS, "primary root")
        _literal(row["table"], table, "primary table/order")
        radix._counter(row["rootRevision"], "primary root revision")
        radix._counter(row["leafCount"], "primary leaf count")
        counted._digest(row["rootDigest"], "primary root digest")
    for identity, row in zip(INDEX_IDS, index_values):
        _closed(row, _COUNTED_FIELDS, "counted root")
        _literal(row["indexId"], identity, "counted identity/order")
        _literal(row["table"], projection._definition(identity).table, "counted table")
        _literal(row["countedProfile"], counted.PROFILE, "counted profile")
        for name in ("projectionDigest", "projectionManifestDigest", "rootDigest"):
            counted._digest(row[name], name)
        for name in ("indexRevision", "leafCount"):
            counted._count(row[name])


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise CurrentRootVectorError("complete root vector exceeds its structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            raise CurrentRootVectorError("complete root vector exceeds its node bound")
        return result


def _manifest_digest(domain, document, work):
    """Use the actual length-framed source-manifest hash, not vector framing."""
    size, _nodes = work.prepare_encoding(document)
    domain_size = work.prepare_utf8(domain)
    work.charge(hashes=1, input_bytes=16 + domain_size + size)
    return roots._callback(work, primary._manifest_digest, domain, document)


def _source_on_work(work):
    capture._SharedLedger(work)
    # This is the complete source relation closure, never an operation argument
    # or a database-discovered catalogue. Existing source coverage also checks
    # the exact primary-key map used by actual primary proof consumers.
    primary._require_coverage()
    required = tuple(sorted({table for spec in authority.OPERATIONS.values()
        for category in ("businessReads", "businessWrites", "authorizationReads")
        for table in spec[category]}))
    if (not required or required != PRIMARY_TABLES
            or tuple(sorted(primary.PRIMARY_KEY_COLUMNS)) != PRIMARY_TABLES
            or not INDEX_IDS or len(set(projection.INDEX_IDS)) != len(INDEX_IDS)
            or tuple(sorted(projection.INDEX_IDS)) != INDEX_IDS
            or any(projection._definition(identity).table not in PRIMARY_TABLES for identity in INDEX_IDS)):
        raise CurrentRootVectorError("complete root inventory differs from measured source")
    query = primary.source_query_manifest()
    authorization = primary.source_authorization_manifest()
    profiles = {(entry["indexContract"], entry["proofKind"]) for entry in query}
    if len(profiles) != 1:
        raise CurrentRootVectorError("primary root/proof profiles are not one exact source contract")
    root_profile, proof_profile = next(iter(profiles))
    inventory = {"schema": PRIMARY_INVENTORY_SCHEMA, "schemaVersion": authority.SCHEMA_VERSION,
        "treeDepth": authority.TREE_DEPTH, "treeRadix": authority.TREE_RADIX,
        "rootProfile": root_profile, "proofProfile": proof_profile,
        "tables": [{"table": table, "keyColumns": list(primary.PRIMARY_KEY_COLUMNS[table])}
            for table in PRIMARY_TABLES]}
    bindings = {"schema": SCHEMA, "schemaVersion": authority.SCHEMA_VERSION,
        "sourceRevision": authority.SOURCE_REVISION,
        "operationManifestDigest": authority.OPERATION_MANIFEST_DIGEST,
        "queryManifestDigest": _manifest_digest("catchplate.policyAuthorityQueryManifest/v1", query, work),
        "authorizationManifestDigest": _manifest_digest(
            "catchplate.policyAuthorityAuthorizationManifest/v1", authorization, work),
        "primaryInventoryDigest": _manifest_digest(PRIMARY_INVENTORY_SCHEMA, inventory, work)}
    counted_profiles = {}
    for identity in INDEX_IDS:
        descriptor = projection._definition(identity).document()
        size, _nodes = work.prepare_encoding(descriptor, ensure_ascii=False)
        domain_size = work.prepare_utf8(projection.PROJECTION_DOMAIN)
        work.charge(hashes=1, input_bytes=16 + domain_size + size)
        counted_profiles[identity] = counted.validate_profile(
            roots._callback(work, projection.profile_for, identity))
    # Preserve the projection module's genuine manifest ordering; roots alone
    # use global identity order. Sorting this document would change its domain.
    descriptors = [projection._definition(identity).document() for identity in projection.INDEX_IDS]
    size, _nodes = work.prepare_encoding(descriptors, ensure_ascii=False)
    domain_size = work.prepare_utf8(projection.MANIFEST_DOMAIN)
    work.charge(hashes=1, input_bytes=16 + domain_size + size)
    bindings["projectionManifestDigest"] = roots._callback(work, projection.projection_manifest_digest)
    return bindings, counted_profiles


def _source_bindings_on_work(*, work):
    """Return ordinary source header fields; no caller roots are supplied."""
    bindings, _profiles = _source_on_work(work)
    return bindings


def _validate_owned(document, work):
    bindings, profiles = _source_on_work(work)
    for name, expected in bindings.items():
        work.prepare_comparison(document[name], expected)
        _literal(document[name], expected, name)
    # Prepay the actual primary helper's conservative cold 65-hash ladder once.
    # PrimaryRoot uses that same actual cached empty helper; no digest is
    # invented from a count or used to fill a missing descriptor.
    roots._primary_empty_root(work)
    counts = {}
    for row in document["primaryRoots"]:
        checked = radix.PrimaryRoot(row["table"], row["rootRevision"], row["rootDigest"], row["leafCount"])
        counts[checked.table] = checked.leaf_count
    for row in document["countedRoots"]:
        profile = profiles[row["indexId"]]
        work.prepare_comparison(row["projectionDigest"], profile.projection_digest)
        _literal(row["projectionDigest"], profile.projection_digest, "counted projection")
        work.prepare_comparison(row["projectionManifestDigest"], bindings["projectionManifestDigest"])
        _literal(row["projectionManifestDigest"], bindings["projectionManifestDigest"], "counted manifest")
        node = counted.validate_counted_node(counted.CountedNode(row["rootDigest"], row["leafCount"]))
        ranges._prepare_empty_work(profile, "", work)
        empty = roots._callback(work, counted.empty_node, profile, "")
        if ((node.count == 0) != (node.digest == empty.digest)
                or row["indexRevision"] == 0 and node.count != 0
                or node.count > counts[profile.table]):
            raise CurrentRootVectorError("counted root empty/revision/primary-count relationship is invalid")
    return document


def _capture_on_work(document, *, work):
    """Own and validate a complete vector; the returned dict is not authority."""
    ledger = capture._SharedLedger(work)
    _shape(document)
    owned = _Capture(ledger, maximum_bytes=MAX_BYTES).visit(document)
    return _validate_owned(owned, work)


def _encode_on_work(document, *, work):
    owned = _capture_on_work(document, work=work)
    return encoding._bounded_wire(owned, capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES)


def _decode_on_work(original_bytes, *, work):
    """Require exact original canonical bytes and genuine full source closure."""
    if type(original_bytes) is not bytes or not 2 <= len(original_bytes) <= MAX_BYTES:
        raise CurrentRootVectorError("complete root vector is not bounded original bytes")
    decoded = wire._decode_object(original_bytes, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture_on_work(decoded, work=work)
    encoded = encoding._bounded_wire(owned, capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES)
    work.charge(input_bytes=len(encoded) + len(original_bytes))
    if encoded != original_bytes:
        raise CurrentRootVectorError("complete root vector original bytes are not canonical")
    return owned


def _digest_on_work(original_bytes, *, work):
    """Digest genuinely validated original bytes, never a claimed vector ID."""
    _decode_on_work(original_bytes, work=work)
    return framing._frame(IDENTITY_DOMAIN, (original_bytes,), work)
