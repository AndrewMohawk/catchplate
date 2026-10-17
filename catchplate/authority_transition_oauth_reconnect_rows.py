"""Actual context row joins for the one-shot active-family replacement."""
from datetime import datetime, timezone
from catchplate import authority_oauth_reconnect as profile
from catchplate import authority_oauth_refresh as refresh
from catchplate import authority_oauth_exchange as exchange
from catchplate import authority_oauth_activation_policy as enrollment
from catchplate import authority_oauth_family_retirement as family
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared
from catchplate import authority_transition_credential_currentness as currentness
from catchplate import authority_credential_currentness as current


def stored(text, bound=profile.MAX_ROW_BYTES):
    profile.require(type(text) is str)
    return profile.document(text.encode("ascii"), bound)


def iso(epoch):
    seconds, nanos = divmod(epoch, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=nanos // 1000).isoformat()


def epoch(text):
    return shared._database_epoch_ns(exchange.timestamp(text))


def grant(values):
    return profile.grant_document(profile.decoded(values["authorization_original"], profile.MAX_GRANT_BYTES))["payload"]


def affected(journal, expected):
    value = profile.lineages_codec.array_document(journal["original_affected_json"].encode("ascii"), profile.MAX_ROW_BYTES)
    profile.require(len(value) == len(expected["affectedLineages"]))
    result = []
    for pair, pin in zip(value, expected["affectedLineages"]):
        profile.require(type(pair) is dict and set(pair) == profile.AFFECTED_ORIGINAL_FIELDS)
        row = stored(pair["credentialOriginal"], 512 * 1024)
        head = stored(pair["generationOriginal"], 8192)
        profile.require(profile.sha256(refresh.credential_original(row)) == pin["credentialRowSha256"]
            and profile.sha256(refresh.generation_original(head)) == pin["generationRowSha256"]
            and row["id"] == head["credential_id"] == pin["credentialId"]
            and row["credential_version"] == head["last_version"] == pin["credentialVersion"])
        result.append((row, head))
    return result


def metadata(row):
    value = shared._canonical_stored_mapping(row["metadata"], "reconnect credential metadata")
    profile.require(value.get("oauth") is True and value.get("provider_identity_verified") is True)
    for name in ("provider_subject", "provider_account"):
        profile.material.text(value.get(name), 512)
    profile.require(value.get("provider_id") in {"google", "x"})
    return value


def before_members(context, expected):
    result = []
    for pin in expected["affectedLineages"]:
        row = shared._row(context.exact("credentials", {"id": pin["credentialId"]}), "actual reconnect lineage")
        head = shared._row(context.exact("credential_generations", {"credential_id": pin["credentialId"]}), "actual generation")
        value = metadata(row)
        profile.require(row["kind"] == "oauth2" and row["lifecycle_status"] == "active"
            and row["revocation_error"] is None and row["revocation_requested_at"] is None
            and row["credential_version"] == head["last_version"] == pin["credentialVersion"]
            and head["credential_id"] == row["id"]
            and profile.sha256(refresh.credential_original(row)) == pin["credentialRowSha256"]
            and profile.sha256(refresh.generation_original(head)) == pin["generationRowSha256"]
            and value["provider_id"] == expected["providerId"] and value["provider_subject"] == expected["providerSubject"]
            and value["provider_account"] == expected["providerAccount"])
        if row["id"] == expected["credentialId"]:
            profile.require(profile.sha256(profile.canonical(value)) == expected["metadataSha256"])
        result.append((row, head))
    return result


def exact_application(values, expected, target):
    raw = profile.activation.enrollment_bytes(values["enrollment_original"])
    application = enrollment.enrollment_document(raw)["payload"]
    value = metadata(target)
    profile.require(value.get("oauth_application_owner") == enrollment.association(raw)
        and value["provider_id"] == application["providerId"] == expected["providerId"]
        and value.get("oauth_client_id" if expected["providerId"] == "google" else "x_app_id") == application["clientId"] == expected["clientId"])


def complete_family(context, expected):
    # The planner has reconstructed each entire root, including both retirement
    # populations; these are not count-only or sampled absence observations.
    actual = []
    for selected in context.present_rows("credentials"):
        row = shared._row(selected, "complete credential population")
        if row["kind"] != "oauth2":
            continue
        value = metadata(row)
        if value["provider_id"] == expected["providerId"] and value["provider_subject"] == expected["providerSubject"]:
            profile.require(row["lifecycle_status"] == "active", "inactive or previously fenced family needs its separate successor")
            actual.append(row["id"])
    profile.require(sorted(actual) == [item["credentialId"] for item in expected["affectedLineages"]],
        "signed affected family is not the entire authenticated local population")
    for selected in context.present_rows("pending_oauth_credentials"):
        row = shared._row(selected, "complete pending population")
        value = shared._canonical_stored_mapping(row["metadata"], "pending provider metadata")
        profile.require(not (value.get("provider_id") == expected["providerId"] and value.get("provider_subject") == expected["providerSubject"]),
            "existing same-family pending material requires explicit prior resolution")
    for selected in context.present_rows("setup_sessions"):
        row = shared._row(selected, "complete Setup population")
        profile.require(not (row["status"] == "active" and row.get("credential_id") in actual),
            "active Setup cannot silently adopt a reconnected generation")
    family.require_open_from_population(context, expected["providerId"], expected["providerSubject"])


def journal(context, values, *, fenced=True):
    expected = grant(values)
    selected = context.exact(profile.JOURNAL_TABLE, {"id": expected["authorizationId"]})
    row = shared._row(selected, "actual reconnect authorization")
    profile.journal_original(row)
    profile.require(row["authorization_original"] == profile.decoded(values["authorization_original"], profile.MAX_GRANT_BYTES).decode("ascii")
        and row["authorization_sha256"] == profile.sha256(row["authorization_original"].encode("ascii"))
        and row["enrollment_original"] == profile.activation.enrollment_bytes(values["enrollment_original"]).decode("ascii")
        and row["actor_id"] == expected["requesterId"] and row["credential_policy_json"] == profile.canonical(values["credential_policy"]).decode("ascii")
        and row["expires_at"] == iso(expected["expiresAtEpochNs"]) and row["status"] == ("fenced" if fenced else "authorized"))
    authorization = profile.arguments(profile.OP_AUTHORIZE, stored(row["authorize_arguments_json"], profile.MAX_ARGUMENT_BYTES))
    profile.require(authorization["authorization_original"] == values["authorization_original"]
        and authorization["actor_id"] == expected["requesterId"]
        and authorization["credential_policy"] == values["credential_policy"])
    profile.digest(row["authorize_request_digest"])
    return selected, row, expected


def fenced_members(context, row, expected, *, committed=None):
    originals = affected(row, expected)
    actual_barriers = profile.barriers(profile.lineages_codec.array_document(row["currentness_barriers_json"].encode("ascii"), 16384), expected["affectedLineages"])
    claim = profile.arguments(profile.OP_FENCE, stored(row["fence_arguments_json"], profile.MAX_ARGUMENT_BYTES))
    profile.require(claim["request"]["currentnessBarriers"] == actual_barriers
        and claim["authorization_original"] == profile.encoded(row["authorization_original"].encode("ascii")))
    for (before, head), barrier in zip(originals, actual_barriers):
        actual = shared._row(context.exact("credentials", {"id": before["id"]}), "retained fenced credential")
        actual_head = shared._row(context.exact("credential_generations", {"credential_id": before["id"]}), "retained generation")
        replacement = before["id"] == expected["credentialId"] and committed is not None
        desired = committed if replacement else {**before,
            "lifecycle_status": "reconnect_pending" if before["id"] == expected["credentialId"] else "reconnect_fenced", "updated_at": row["updated_at"]}
        profile.require(actual == desired and actual_head == ({**head, "last_version": head["last_version"] + 1,
            "updated_at": committed["updated_at"]} if replacement else head))
        _, root = currentness.require_root(context, before["id"], before["credential_version"])
        _, retained, _ = currentness._barrier(context, root, root["barrier_id"], barrier["barrierSha256"])
        profile.require(root["status"] == retained["status"] == "consumed" and retained["consume_request_digest"] == row["fence_request_digest"])
    family.require_open(context, expected["providerId"], expected["providerSubject"])
    return originals


def block_pending_family(context, provider, subject):
    """Fixed existing complete-population consumers only, never a bypass flag."""
    profile.require(context.operation in {"oauth.pending.stage", "oauth.measured-exchange.stage", "oauth.measured-setup.stage",
        "oauth.pending.activate", "oauth.setup.activate"})
    for selected in context.present_rows("credentials"):
        row = shared._row(selected, "complete reconnect-fence population")
        if row["kind"] == "oauth2" and row["lifecycle_status"] == "reconnect_pending":
            value = metadata(row)
            profile.require(value["provider_id"] != provider or value["provider_subject"] != subject,
                "actual pending family replacement blocks competing staging or activation")
