"""Native-only projection checks after the fixed original-to-result factory.

These are data invariants, never signature or provenance admission. The native
detail owner commits the result profile, all actual receipts and this result.
The old Fleet comparison validator is deliberately not changed.
"""
from catchplate import authority_policy_canary as p
from catchplate import authority_policy_canary_native_opening as f

FIELDS = frozenset({"classification", "captureMode", "upstreamStatus", "exactResponseBodyBytes",
    "exactResponseBodySha256", "physicalResponseHeaderCount", "physicalResponseHeadersSha256",
    "exactResponseCommitmentSha256", "activeValidation", "candidateValidation", "unavailableMarkerSha256",
    "transportCaptureReceiptSha256", "runtimeAttestationSha256", "peerIdentitySha256",
    "physicalResponseFraming", "responseProofSha256"})
EXACT = FIELDS - {"classification", "captureMode", "unavailableMarkerSha256", "responseProofSha256"}


def fixed_class(final, dispatched, candidate, active_dispatch, candidate_dispatch):
    if final == "deny" and candidate == "deny":
        return "not-applicable-both-deny"
    if not (final == "allow" and dispatched):
        return "not-applicable-active-not-dispatched"
    if candidate not in {"permit", "conditional"}:
        return "not-comparable-candidate-not-dispatchable"
    if active_dispatch != candidate_dispatch:
        return "not-comparable-dispatch-commitment-mismatch"
    return None


def validate(label, value, *, obligation, active_snapshot_digest, candidate_snapshot_digest,
        final_active_outcome, upstream_dispatch_authorized, active_dispatch_commitment_digest,
        candidate_dispatch_commitment_digest, candidate_outcome):
    from catchplate import db
    p.require(type(value) is dict and set(value) == FIELDS, label + " is not the closed native comparison")
    kind, mode = value["classification"], value["captureMode"]
    p.require(kind in db._POLICY_AUTHORITY_RESPONSE_CLASSES and mode in db._POLICY_AUTHORITY_RESPONSE_CAPTURE_MODES)
    p.digest(value["responseProofSha256"])
    fixed = fixed_class(final_active_outcome, upstream_dispatch_authorized == 1, candidate_outcome,
        active_dispatch_commitment_digest, candidate_dispatch_commitment_digest)
    if fixed is not None:
        p.require(kind == fixed)
    else:
        p.require(kind not in {"not-applicable-both-deny", "not-applicable-active-not-dispatched",
            "not-comparable-candidate-not-dispatchable", "not-comparable-dispatch-commitment-mismatch"})
    active = candidate = None
    if mode == "bounded-exact":
        p.require(value["unavailableMarkerSha256"] is None and all(value[name] is not None for name in EXACT))
        db._candidate_authority_int("native response status", value["upstreamStatus"], minimum=100, maximum=599)
        for name in ("exactResponseBodyBytes", "physicalResponseHeaderCount"):
            db._candidate_authority_int(name, value[name])
        for name in ("exactResponseBodySha256", "physicalResponseHeadersSha256", "exactResponseCommitmentSha256",
                "transportCaptureReceiptSha256", "runtimeAttestationSha256", "peerIdentitySha256"):
            p.digest(value[name])
        p.require(value["physicalResponseFraming"] in {"no-body", "content-length", "chunked", "close-delimited"})
        commitment = f.material("catchplate.policyShadowExactResponse/v1", [value["upstreamStatus"],
            value["exactResponseBodyBytes"], value["exactResponseBodySha256"], value["physicalResponseHeaderCount"],
            value["physicalResponseHeadersSha256"]])
        p.require(commitment == value["exactResponseCommitmentSha256"]
            and value["responseProofSha256"] == f.material("catchplate.policyShadowAuthenticatedResponseProof/v1",
                [commitment, value["transportCaptureReceiptSha256"], value["runtimeAttestationSha256"],
                    value["peerIdentitySha256"], value["physicalResponseFraming"]]))
        active = db._policy_authority_bound_response_validation("native active validation", value["activeValidation"])
        candidate = db._policy_authority_bound_response_validation("native candidate validation", value["candidateValidation"])
        for validation, snapshot in ((active, active_snapshot_digest), (candidate, candidate_snapshot_digest)):
            p.require(validation["policySnapshotSha256"] == snapshot and validation["exactResponseCommitmentSha256"] == commitment)
        # The factory compares the genuine released entity/status/media, not the
        # incompatible native-release versus adapter-transformation labels.
        if kind.startswith("comparable-"):
            p.require(active["outcome"] in {"accepted", "rejected"} and candidate["outcome"] in {"accepted", "rejected"})
            if kind == "comparable-identical":
                p.require(active["outcome"] == candidate["outcome"]
                    and active["validationResultSha256"] == candidate["validationResultSha256"])
            elif kind == "comparable-validation-match":
                p.require(active["outcome"] == candidate["outcome"])
            else:
                p.require(active["outcome"] != candidate["outcome"]
                    or active["validationResultSha256"] != candidate["validationResultSha256"])
        else:
            p.require(kind == fixed or kind == "not-comparable-candidate-validator-unavailable")
    else:
        p.require(all(value[name] is None for name in EXACT))
        p.digest(value["unavailableMarkerSha256"])
        p.require((mode == "not-dispatched" and fixed is not None)
            or (mode == "streaming-unavailable" and kind == "not-comparable-active-response-unavailable"))
    if obligation is not None and obligation["disposition"] == "applied":
        # An unsafe noncomparable observation still retains the real attempted
        # rule/response association. Native readiness rejects its class; this
        # binding is not a declaration that the obligation was satisfied.
        p.require(mode == "bounded-exact"
            and obligation["exactResponseCommitmentSha256"] == value["exactResponseCommitmentSha256"]
            and active["responseConstraintsRootSha256"] == obligation["activeConstraintsRootSha256"]
            and candidate["responseConstraintsRootSha256"] == obligation["candidateConstraintsRootSha256"]
            and obligation["appliedObligationsRootSha256"] == f.framed("catchplate.policyShadowAppliedResponseObligations/v1",
                *(obligation[name].encode("ascii") for name in ("obligationRootSha256", "activeConstraintsRootSha256",
                    "candidateConstraintsRootSha256", "exactResponseCommitmentSha256"))))
    elif obligation is not None:
        p.require(mode == "not-dispatched" and kind in {"not-applicable-both-deny", "not-applicable-active-not-dispatched"}
            and not (final_active_outcome == "allow" and upstream_dispatch_authorized == 1)
            and obligation["candidateOutcome"] == candidate_outcome)
    return value


def pilot_profile(value, analysis_mode, cells):
    from catchplate import authority_policy_canary_native_pilot as pilot
    if analysis_mode == "no-expansion":
        p.require(value == {"mode": "not-applicable"})
    else:
        pilot.validate(value)
        p.require(value["cells"] == cells)
