"""Metadata-only operator recovery over the actual cold-started custody owner.

The HTTP boundary supplies refreshed admin admission and CSRF enforcement.
These functions never create an owner, return retained originals, forward a
write, clear an attempt, or infer remote absence from a failed lookup. A fresh
reconciliation performs the actual existing readback and exact-original check;
its result is still an unsigned observation, not business completion.
"""
from __future__ import annotations

from serverware import control_plane_custody_startup as startup


class CustodyRecoveryUnavailable(RuntimeError):
    pass


class CustodyRecordNotFound(LookupError):
    """Only the local inventory lacks this digest; says nothing about remote state."""


class CustodyRecordNotAttempted(ValueError):
    pass


def _owner():
    from serverware import control_plane_custody_client as client

    owner = startup.require_started()
    if type(owner) is not client.ControlPlaneCustodyClient:
        raise CustodyRecoveryUnavailable("custody recovery is not configured")
    return owner


def _inventory(owner):
    from serverware import control_plane_custody_client as client
    from serverware import control_plane_custody_journal as journal

    entries = client.ControlPlaneCustodyClient.inventory(owner)
    if (type(entries) is not tuple or len(entries) > journal.MAX_RECORDS
            or any(type(entry) is not journal.JournalEntry for entry in entries)):
        raise CustodyRecoveryUnavailable("custody inventory is unavailable")
    return entries


def _entry(owner, local_digest):
    from serverware import control_plane_custody_journal as journal

    digest = journal._digest(local_digest)
    selected = next((entry for entry in _inventory(owner) if entry.digest == digest), None)
    if selected is None:
        raise CustodyRecordNotFound("local custody record was not found")
    return selected


def _metadata(entry):
    # Whitelist metadata explicitly; never serialize a prepared record or use
    # dataclass/asdict reflection that might later start exposing originals.
    return {"localDigest": entry.digest, "family": entry.family,
        "selector": entry.selector, "sourceRevision": entry.source_revision,
        "preparedBytes": entry.prepared_bytes, "attempted": entry.attempted,
        "observed": entry.observed}


def _observation(owner, local_digest):
    from serverware import control_plane_custody_client as client
    from serverware import control_plane_custody_observations as observations

    observation = client.ControlPlaneCustodyClient.observation(owner, local_digest)
    if observation is None:
        return None
    if type(observation) is not observations.Observation or observation.local_digest != local_digest:
        raise CustodyRecoveryUnavailable("custody observation is unavailable")
    return {"localDigest": observation.local_digest,
        "retainedRecordDigest": observation.retained_record_digest,
        # Decimal text preserves nanosecond identity in ordinary JSON clients
        # whose numeric representation cannot exactly hold positive I63 values.
        "retainedAtEpochNs": str(observation.retained_at_epoch_ns),
        "configurationDigest": observation.configuration_digest,
        "sourceRevision": observation.source_revision}


def inventory():
    """Return at most the existing journal ceiling of metadata-only entries."""
    try:
        entries = _inventory(_owner())
        return {"schema": "serverware.controlPlaneCustodyInventory/v1",
            "records": [_metadata(entry) for entry in entries], "count": len(entries)}
    except Exception:
        # Neither filesystem paths, transport errors nor original byte values
        # are suitable for the public operator response.
        raise CustodyRecoveryUnavailable("custody recovery is unavailable") from None


def inspect_record(local_digest):
    """Read local metadata and validate stored observation identity, not freshness."""
    try:
        owner = _owner()
        entry = _entry(owner, local_digest)
        observed = _observation(owner, entry.digest)
        # A concurrent reconciliation may publish the first observation after
        # the inventory snapshot. Use the actual checked observation here.
        metadata = _metadata(entry)
        metadata["observed"] = observed is not None
        if observed is not None:
            # The journal only admits an observation with an existing attempt.
            # Preserve that implication if another thread advanced the state
            # after the earlier metadata snapshot.
            metadata["attempted"] = True
        return {"schema": "serverware.controlPlaneCustodyRecord/v1",
            "record": metadata, "observation": observed, "freshReadback": False}
    except CustodyRecordNotFound:
        raise
    except Exception:
        raise CustodyRecoveryUnavailable("custody recovery is unavailable") from None


def reconcile(local_digest):
    """Perform one explicit read-only remote lookup; never resend retention."""
    from serverware import control_plane_custody_client as client

    try:
        owner = _owner()
        entry = _entry(owner, local_digest)
        # Only the fixed legacy families have a delivery/readback protocol.
        # Execution grants and unknown future families are retention-only here.
        if entry.family not in ("evidence", "transition"):
            raise CustodyRecordNotAttempted("local custody record does not support delivery readback")
        if entry.attempted is not True:
            raise CustodyRecordNotAttempted("local custody record has no delivery attempt")
        # This exact method performs fresh authenticated readback, compares all
        # original bytes and durably records the first successful observation.
        # Do not expose the returned raw plan bodies to the HTTP caller.
        returned = client.ControlPlaneCustodyClient.reconcile(owner, entry.digest)
        observed = _observation(owner, entry.digest)
        if (observed is None or type(returned) is not tuple
                or len(returned) not in (5, 6)
                or (returned[-2], str(returned[-1]))
                    != (observed["retainedRecordDigest"], observed["retainedAtEpochNs"])):
            raise CustodyRecoveryUnavailable("custody readback observation is unavailable")
        metadata = _metadata(entry)
        metadata["observed"] = True
        return {"schema": "serverware.controlPlaneCustodyRecord/v1",
            "record": metadata, "observation": observed, "freshReadback": True}
    except (CustodyRecordNotFound, CustodyRecordNotAttempted):
        raise
    except Exception:
        # Failure is uncertainty, never an absence result or permission to retry.
        raise CustodyRecoveryUnavailable("custody reconciliation outcome is unavailable") from None
