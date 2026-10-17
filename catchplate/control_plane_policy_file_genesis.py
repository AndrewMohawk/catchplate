"""Actual finalized-genesis lock owner, not a missing-file inference or activation."""
from __future__ import annotations

from catchplate.authority_store import policy_file_genesis_sql as sql
from catchplate.control_plane_policy_file_authority import CurrentPolicyAuthority


class GenesisPolicyAuthority(CurrentPolicyAuthority):
    SQL = sql
    DSN_PATH = "CATCHPLATE_POLICY_FILE_GENESIS_DSN_PATH"
    DSN_SHA = "CATCHPLATE_POLICY_FILE_GENESIS_DSN_SHA256"

    def check(self):
        from catchplate.control_plane_policy_file_publication import _require, _signed
        self._check_held_connection()
        bound = self.publication.material_binding
        _require(bound["kind"] == "genesis-materialize" and bound["expectedFileSha256"] is None)
        original = read_original(self)
        _, trust, actual = _signed(self.publication.raw)
        _require(trust == self.publication.trust and all(bound[key] == value for key, value in actual.items()))
        if self.original is None:
            self.original = original
        else:
            _require(original == self.original)
        self._configure()
        self._contract()
        self.publication.check()


def read_original(owner):
    """Data from the actual fixed connection; no permission object is returned."""
    from catchplate.control_plane_policy_file_publication import _require, _sha
    from catchplate.authority_policy_file_approval import canonical
    bound = owner.publication.material_binding
    with owner.connection.cursor() as cursor:
        row = cursor.execute("SELECT catchplate_metadata.catchplate_policy_file_genesis_lock(%s,%s) AS original",
            (bound["genesisPreparationDigest"], bound["genesisFinalizationDigest"])).fetchone()
    original = row["original"]
    _require(type(original) is dict and set(original) == {"schema", "current", "originals", "backendPid", "transactionId"}
        and original["schema"] == sql.CONTRACT and len(canonical(original)) <= 32 * 1024 * 1024
        and type(original["backendPid"]) is int and original["backendPid"] > 0
        and type(original["transactionId"]) is str and original["transactionId"].isdigit())
    current, originals = original["current"], original["originals"]
    _require(type(current) is dict and set(current) == {"policyId", "sequence", "rollbackEpoch", "policyHash",
        "genesisPreparationDigest", "genesisFinalizationDigest"}
        and all(current[key] == bound[key] for key in current)
        and type(originals) is dict and set(originals) == {"preparation", "finalization", "signatureEvidence",
            "transition", "inclusion", "inclusionEvidence"})
    preparation, inclusion = originals["preparation"], originals["inclusion"]
    # Independently authenticated retained DB records supply these original
    # bytes. Caller hashes cannot select a missing/unfinished genesis.
    for record, prefix in ((preparation, "genesis"), (inclusion, "inclusion_receipt")):
        for part in ("envelope", "payload"):
            key = prefix + "_" + part
            encoded = record[key + "_json"]
            _require(type(encoded) is str and 0 < len(encoded.encode("utf-8")) <= 1024 * 1024
                and _sha(encoded.encode("utf-8")) == record[key + "_digest"])
    high_water = {"scope": "active", "policyId": bound["policyId"], "sequence": bound["sequence"],
        "rollbackEpoch": bound["rollbackEpoch"], "policyHash": bound["policyHash"]}
    _require(_sha(canonical(high_water)) == preparation["high_water_digest"]
        == originals["finalization"]["high_water_digest"])
    return original
