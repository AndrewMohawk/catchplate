"""Representation-preserving JSON at the Serverware/Sigstore boundary.

ProtoJSON serializes Rekor int64 fields as decimal strings. Only the explicit
bundle/proof/image-signatures scopes below admit them. Validation never edits
the input: signed statements, canonicalizedBody, SETs and checkpoint text keep
their original representations. This is parsing, not cryptographic authority.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

PROFILE = "serverware.canonicalJson/integer-string-bool-null-array-object-nfc-v1"
SIGNED_MAX = (1 << 63) - 1
Path = tuple[str | int, ...]


def require(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_nonnegative_int64(value: Any, label: str) -> int:
    if type(value) is int:
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value):
        # Bound before conversion, including Python's decimal conversion limit.
        require(len(value) <= 19, f"{label} is outside int64 range")
        parsed = int(value)
    else:
        raise ValueError(f"{label} is invalid")
    require(0 <= parsed <= SIGNED_MAX, f"{label} is outside int64 range")
    return parsed


def counter_field(name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    return normalized == "ordinal" or normalized.endswith(
        ("generation", "epoch", "sequence", "treesize", "index")
    )


def validate_string(value: str, label: str) -> None:
    require("\x00" not in value, f"{label} contains NUL")
    require(all(not 0xD800 <= ord(c) <= 0xDFFF for c in value), f"{label} contains a Unicode surrogate")
    require(unicodedata.normalize("NFC", value) == value, f"{label} is not Unicode NFC")


def validate_profile(
    value: Any, *, label: str, depth: int = 0, field_name: str | None = None,
    foreign_paths: frozenset[Path] = frozenset(), path: Path = (),
) -> None:
    require(depth <= 64, f"{label} exceeds the canonical JSON nesting limit")
    if path in foreign_paths:
        parse_nonnegative_int64(value, f"{label} {'/'.join(map(str, path))}")
        return
    if field_name is not None and counter_field(field_name):
        require(type(value) is int and value >= 0, f"{label} {field_name} must be an unsigned integer")
    if isinstance(value, dict):
        require(len(value) <= 100_000, f"{label} has too many object fields")
        for key, child in value.items():
            require(isinstance(key, str), f"{label} contains a non-string object key")
            validate_string(key, f"{label} object key")
            validate_profile(child, label=label, depth=depth + 1, field_name=key,
                             foreign_paths=foreign_paths, path=path + (key,))
    elif isinstance(value, list):
        require(len(value) <= 100_000, f"{label} has too many array items")
        for index, child in enumerate(value):
            validate_profile(child, label=label, depth=depth + 1,
                             foreign_paths=foreign_paths, path=path + (index,))
    elif isinstance(value, str):
        validate_string(value, label)
    elif value is None or isinstance(value, bool):
        return
    elif type(value) is int:
        require(-(1 << 63) <= value <= SIGNED_MAX,
                f"{label} integer is outside the canonical signed 64-bit profile")
    else:
        raise ValueError(f"{label} contains a value outside {PROFILE}")


def _object(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def _one(value: dict[str, Any], names: tuple[str, ...], label: str) -> str:
    present = [name for name in names if name in value]
    require(len(present) == 1, f"{label} requires exactly one of {', '.join(names)}")
    return present[0]


def _proof_paths(value: Any, path: Path, paths: set[Path]) -> None:
    proof = _object(value, "Sigstore inclusion proof")
    for names in (("logIndex", "log_index"), ("treeSize", "tree_size")):
        paths.add(path + (_one(proof, names, "Sigstore inclusion counter"),))
    _one(proof, ("rootHash", "root_hash"), "Sigstore inclusion root")


def _bundle_paths(value: Any, path: Path, paths: set[Path]) -> None:
    bundle = _object(value, "Sigstore bundle")
    # Keep the existing camel/snake compatibility, but never select one of two
    # conflicting representations. A name elsewhere gets no exemption.
    material_key = _one(bundle, ("verificationMaterial", "verification_material"), "Sigstore verification material")
    material = _object(bundle[material_key], "Sigstore verification material")
    candidates = [(path + (material_key, name), material[name])
                  for name in ("tlogEntries", "transparencyLogEntries", "transparencyLog") if name in material]
    if "tlogEntries" in bundle:
        candidates.append((path + ("tlogEntries",), bundle["tlogEntries"]))
    require(len(candidates) == 1, "Sigstore bundle requires exactly one transparency entry location")
    entry_path, entries = candidates[0]
    if isinstance(entries, list):
        require(entries, "Sigstore bundle is missing transparency log entries")
        require(len(entries) == 1, "Sigstore bundle requires exactly one transparency entry")
        entry_path += (0,)
        entry = _object(entries[0], "Sigstore transparency entry")
    else:
        entry = _object(entries, "Sigstore transparency entry")
    for names in (("logIndex", "log_index"), ("integratedTime", "integrated_time")):
        paths.add(entry_path + (_one(entry, names, "Sigstore transparency counter"),))
    inclusion_key = _one(entry, ("inclusionProof", "inclusion_proof"), "Sigstore inclusion proof")
    _proof_paths(entry[inclusion_key], entry_path + (inclusion_key,), paths)
    for names in (("logId", "logID", "log_id"), ("canonicalizedBody", "canonicalized_body"),
                  ("inclusionPromise", "inclusion_promise")):
        # Presence/authentication remains the verifier's responsibility; forbid
        # ambiguity even for fields not needed to classify numeric paths.
        if any(name in entry for name in names):
            _one(entry, names, "Sigstore transparency field")
    signature_key = _one(bundle, ("messageSignature", "message_signature"), "Sigstore message signature")
    signature = _object(bundle[signature_key], "Sigstore message signature")
    _one(signature, ("messageDigest", "message_digest"), "Sigstore message digest")


def _transparency_paths(value: Any, path: Path, paths: set[Path]) -> None:
    transparency = _object(value, "Sigstore transparency")
    for field in ("log_index", "integrated_time"):
        require(field in transparency, f"Sigstore transparency is missing {field}")
        paths.add(path + (field,))
    _proof_paths(transparency.get("inclusion_proof"), path + ("inclusion_proof",), paths)


def _response_paths(value: Any, path: Path, paths: set[Path]) -> None:
    response = _object(value, "Sigstore response")
    _bundle_paths(response.get("bundle"), path + ("bundle",), paths)
    _transparency_paths(response.get("transparency"), path + ("transparency",), paths)


def validate(value: Any, *, scope: str = "serverware", label: str = "canonical JSON value") -> None:
    paths: set[Path] = set()
    if scope == "bundle":
        _bundle_paths(value, (), paths)
    elif scope == "response":
        _response_paths(value, (), paths)
    elif scope == "transparency":
        _transparency_paths(value, (), paths)
    elif scope == "image-signatures":
        document = _object(value, "image signatures")
        require(document.get("apiVersion") == "serverware.imageSignatures/v1"
                and document.get("kind") == "ImageSignatureBundle", "unsupported image signatures schema")
        images = document.get("images")
        require(isinstance(images, list) and 0 < len(images) <= 100_000, "image signatures must contain bounded images")
        for index, image in enumerate(images):
            image = _object(image, "image signature entry")
            if "sigstore" in image:
                _response_paths(image["sigstore"], ("images", index, "sigstore"), paths)
        if "bundle_signature" in document:
            _response_paths(document["bundle_signature"], ("bundle_signature",), paths)
        metadata = _object(document.get("metadata"), "image signature metadata")
        if "bundleSigstore" in metadata:
            _response_paths(metadata["bundleSigstore"], ("metadata", "bundleSigstore"), paths)
    else:
        require(scope == "serverware", "unknown canonical JSON scope")
    validate_profile(value, label=label, foreign_paths=frozenset(paths))


def canonical_json(value: Any, *, scope: str = "serverware") -> str:
    validate(value, scope=scope)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def statement_json(value: dict[str, Any], *, kind: str | None = None) -> str:
    # This dispatch is used only at a Sigstore statement signing/verifying sink,
    # never the generic Serverware parser. Explicit request kinds must agree.
    image_bundle = value.get("apiVersion") == "serverware.imageSignatures/v1"
    if kind is not None:
        require((kind == "image-signature-bundle") == image_bundle,
                "Sigstore request kind does not match statement schema")
    return canonical_json(value, scope="image-signatures" if image_bundle else "serverware")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise ValueError(f"non-integer JSON number is not permitted: {value}")


def parse_json(data: str | bytes) -> Any:
    """Reject ambiguous JSON before choosing any protocol-specific scope."""
    if isinstance(data, bytes):
        # json.loads(bytes) otherwise auto-detects UTF-16/32. Artifacts use the
        # same UTF-8-only transport as the ordinary Serverware snapshot loader.
        data = data.decode("utf-8")
    return json.loads(data, object_pairs_hook=_unique_object,
                      parse_float=_reject_number, parse_constant=_reject_number)


def load_json(data: str | bytes, *, scope: str) -> dict[str, Any]:
    value = _object(parse_json(data), "JSON artifact")
    validate(value, scope=scope)
    return value
