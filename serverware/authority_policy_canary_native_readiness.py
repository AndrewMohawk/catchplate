"""Explicit native derivation permission and closed identifier-only request.

The embedded policy is not self-authority: verifier AND planner compare it to
the exact independently signed current configuration before the kernel runs.
No native signer is relabelled as the legacy Fleet activation-readiness key.
"""
from serverware import authority_policy_canary as p

FIELD = "policyCanaryNativeReadinessPolicy"
SCHEMA = "serverware.policyCanaryNativeReadinessAuthorityPolicy/v1"
REQUEST = "serverware.nativePolicyReadinessRequest/v1"
RESULT = "serverware.nativePolicyReadinessResult/v1"
CORE = "serverware.nativePolicyReadinessCore/v1"
FIELDS = frozenset({"schema", "deploymentId", "issuedAtEpochNs", "expiresAtEpochNs", "maximumReadinessAgeNanos", "canaries"})
REQUEST_FIELDS = frozenset({"apiVersion", "canary_id", "instance_id", "boot_id", "assignment_envelope_digest",
    "assignment_payload_digest", "final_checkpoint_sha256", "readiness_policy"})
MAX_REQUEST = 16384
MAX_RESULT = 262144
MAX_FLEET = 32


def validate_policy(value, *, payload=None, root_key=None):
    if value is None:
        return None
    p.require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA)
    p.component(value["deploymentId"])
    issued, expires = p.epoch(value["issuedAtEpochNs"]), p.epoch(value["expiresAtEpochNs"])
    p.require(0 < expires - issued <= 86_400_000_000_000 and type(value["maximumReadinessAgeNanos"]) is int
        and 1_000_000_000 <= value["maximumReadinessAgeNanos"] <= 300_000_000_000)
    canaries = value["canaries"]
    p.require(type(canaries) is list and 1 <= len(canaries) <= MAX_FLEET)
    identities = []
    for item in canaries:
        p.require(type(item) is dict and set(item) == {"canaryId", "assignmentSha256"})
        p.text(item["canaryId"], 256); p.digest(item["assignmentSha256"])
        identities.append((item["canaryId"], item["assignmentSha256"]))
    p.require(identities == sorted(set(identities)) and len(p.canonical(value)) <= MAX_REQUEST // 2)
    return value


def request(value):
    p.require(type(value) is dict and set(value) == REQUEST_FIELDS and value["apiVersion"] == REQUEST
        and len(p.canonical(value)) <= MAX_REQUEST)
    p.text(value["canary_id"], 256); p.component(value["instance_id"])
    for field in ("boot_id", "assignment_envelope_digest", "assignment_payload_digest", "final_checkpoint_sha256"):
        p.digest(value[field])
    selected = validate_policy(value["readiness_policy"])
    p.require(selected is not None and {"canaryId": value["canary_id"], "assignmentSha256": value["assignment_envelope_digest"]}
        in selected["canaries"])
    return value


def verify_batch(original, *, configuration_payload, root_key, now_epoch_ns, before_original):
    batch = p.batch(original)
    for event in batch["events"]:
        value = event["record"]
        if event["kind"] != "readiness" or value.get("apiVersion") != REQUEST:
            continue
        request(value)
        selected = validate_policy(configuration_payload.get(FIELD), payload=configuration_payload, root_key=root_key)
        p.require(len(batch["events"]) == 1 and selected is not None
            and p.canonical(value["readiness_policy"]) == p.canonical(selected)
            and selected["issuedAtEpochNs"] <= now_epoch_ns < selected["expiresAtEpochNs"],
            "native readiness derivation has no current independently selected permission")
        # Purpose admission is repeated by the real verifier AND planner. The
        # same complete before-state is separately authenticated by the planner;
        # signatures over a caller's proposed subset do not prove completeness.
        before = p.document(before_original.encode("ascii"), p.MAX_ARGUMENT)
        try:
            from serverware import authority_policy_canary_finalization_policy as finalization
        except ImportError as error:
            raise ValueError("native finalization purpose verifier is unavailable") from error
        matched = 0
        for row in before[p.TABLE]:
            if row["canary_id"] != value["canary_id"]:
                continue
            p.row_original(row)
            for prior in p.batch(row["batch_original"])["events"]:
                checkpoint = prior["record"]
                if prior["kind"] != "checkpoint" or checkpoint.get("apiVersion") != "serverware.nativeCumulativeCheckpoint/v2":
                    continue
                if checkpoint.get("seal") is None or checkpoint.get("assignment_envelope_digest") != value["assignment_envelope_digest"]:
                    continue
                finalization.verify_record(checkpoint["heartbeat"], configuration_payload, root_key, now_epoch_ns)
                matched += 1
        p.require(0 < matched <= MAX_FLEET, "readiness lacks currently admitted finalization originals")
