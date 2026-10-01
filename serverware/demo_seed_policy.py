"""Demo data admission against existing authority, never policy publication."""
from __future__ import annotations

from serverware import policy_bundle as bundles


class DemoSeedPolicyError(ValueError):
    pass


def require_demo_semantics(raw: dict) -> None:
    """Compare policy content only; this function does not verify authority."""
    expected = bundles.demo_policy_bundle("cred-demo-bearer")
    metadata = raw.get("metadata") if isinstance(raw, dict) else None
    if (
        not isinstance(metadata, dict)
        or set(metadata) != set(expected["metadata"]) | {"signingKeyId", "signature"}
        or any(
            type(metadata.get(name)) is not int
            or metadata[name] < expected["metadata"][name]
            for name in ("sequence", "rollbackEpoch")
        )
        or any(
            not isinstance(metadata.get(name), str) or not metadata[name]
            for name in ("signingKeyId", "signature")
        )
    ):
        raise DemoSeedPolicyError("commissioned demo policy metadata does not match")
    # Only authority-controlled counters and signature identity may differ.
    # Canonical comparison preserves JSON types and every route, principal,
    # credential, denial default, adapter and constraint, including extra keys.
    expected["metadata"].update({
        name: metadata[name]
        for name in ("sequence", "rollbackEpoch", "signingKeyId", "signature")
    })
    if bundles.canonical_json(raw) != bundles.canonical_json(expected):
        raise DemoSeedPolicyError("commissioned policy does not have exact demo semantics")


def require_commissioned_demo_policy() -> bundles.PolicySnapshot:
    """Return only a signed, currently committed, semantically exact policy."""
    try:
        snapshot = bundles.get_policy_snapshot()
        if snapshot is None:
            raise DemoSeedPolicyError("no verified committed demo policy is available")
        require_demo_semantics(snapshot.raw)
        # Revalidate current authority after comparison, before the caller's
        # first data mutation. This never stages or advances policy authority.
        bundles.enforce_policy_high_water(snapshot)
        return snapshot
    except DemoSeedPolicyError:
        raise
    except Exception as exc:
        raise DemoSeedPolicyError("committed demo policy authority is unavailable") from exc
