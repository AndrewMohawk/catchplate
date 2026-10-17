"""Bounded credential row originals for currentness observations.

Static creation admits a 1 MiB secret, whose stored ciphertext exceeds the
OAuth row bound. This kind dispatch preserves OAuth's existing serializer and
validates only the existing version-one static row format. It does not admit
a holder, establish a deployment binding, decrypt material or authorize a
static currentness operation; those remain the purpose kernel's responsibility.
"""
from catchplate import authority_oauth_refresh as refresh
from catchplate import authority_static_credential_create as static
from catchplate import credential_ciphertext


# The creation original bounds the name to at most 2 MiB of canonical JSON.
# Its native envelope is below 1.4 MiB, and stored public metadata is at most
# 16 KiB before the row's string escaping. Keep an explicit whole-row bound
# covering those existing domains without widening OAuth's 512 KiB limit.
MAX_STATIC_ROW_BYTES = 4 * 1024 * 1024


def credential_original(row):
    """Return exact canonical row bytes, not a verified-custody carrier."""
    value = dict(row)
    if value.get("kind") == "oauth2":
        return refresh.credential_original(value)

    static.require(set(value) == refresh.CREDENTIAL_FIELDS
        and type(value["kind"]) is str and value["kind"] in static.KINDS)
    static.identifier(value["id"])
    for name, item in value.items():
        if name != "credential_version":
            static.require(type(item) is str or item is None and name in {
                "revocation_error", "revocation_requested_at"})
    # Bound input strings before metadata parsing, envelope decoding or JSON
    # encoding. The final canonical byte bound also counts escaping overhead.
    static.require(sum(len(item) for item in value.values() if type(item) is str)
        <= MAX_STATIC_ROW_BYTES)
    value["name"].encode("utf-8", errors="strict")
    static.require(len(static.canonical(value["name"])) <= static.MAX_ARGUMENT_BYTES)
    from catchplate import native_static_credential_rotation as rotation_material
    material = static.material if value["credential_version"] == 1 else rotation_material
    material.envelope_fields({name: value[name] for name in material.ENVELOPE_FIELDS})
    metadata = credential_ciphertext.metadata(value["metadata"])
    static.metadata(metadata)
    static.require(metadata.get("oauth") is not True
        and static.canonical(metadata).decode("ascii") == value["metadata"])
    raw = static.canonical(value)
    static.require(len(raw) <= MAX_STATIC_ROW_BYTES)
    return raw
