"""Selected public slots, not approval, signature or resource authority."""
from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_adopted_ordinary as ordinary
from catchplate import native_pilot_ordinary_publication_authority as publication
from catchplate import native_pilot_publication_adoption_profile as adoption
from catchplate import native_pilot_publication_profiles as profiles
from catchplate import native_pilot_bridge_runtime as bridge_runtime

p = generation.p
LIMITS = {"publication-adoption": adoption.MAX_AUTHORIZATION,
    "driver-phase-two-public": bridge_runtime.MAX_BRIDGE_INPUT,
    "ordinary-launch": 65536, "cohort-configuration": 32768,
    **{"ordinary-publication-" + role: publication.MAX_OUTPUT for role in ordinary.ROLES},
    **{"ordinary-initial-history-" + role: generation.MAX_BYTES for role in ordinary.ROLES}}
DESTINATIONS = {purpose: profiles.DESTINATIONS.get(purpose,
    "/etc/catchplate/native-pilot-inputs/" + purpose + ".json") for purpose in LIMITS}


def shape(purpose, raw):
    p.require(type(purpose) is str and purpose in LIMITS)
    if purpose == "driver-phase-two-public":
        from catchplate import native_pilot_phase_two_publication as phase_two
        return phase_two.shape(raw, adopted=True)
    if purpose in ("ordinary-launch", "cohort-configuration"):
        profiles._configuration("ordinary-launch" if purpose == "ordinary-launch" else "cohort-config",
            None, raw, LIMITS[purpose], adopted=True)
        return
    if purpose.startswith("ordinary-initial-history-"):
        profiles._initial_history(purpose.removeprefix("ordinary-initial-history-"), raw,
            LIMITS[purpose], adopted=True)
        return
    value = p.fields(p.document(raw, LIMITS[purpose]),
        ("payload", "signature") if purpose == "publication-adoption" else ("payload", "signatureBase64url"))
    p.decoded(value["signature"] if purpose == "publication-adoption" else value["signatureBase64url"], size=64)
    if purpose == "publication-adoption":
        payload = p.fields(value["payload"], adoption.PAYLOAD_FIELDS)
        p.require(payload["apiVersion"] == "catchplate.nativePublicationAdoptionAuthorization/v2")
        p.require(p.integer(payload["issuedAtUnixNanos"]) < p.integer(payload["expiresAtUnixNanos"])
            and p.integer(payload["issuedAtBoottimeNanos"]) < p.integer(payload["expiresAtBoottimeNanos"]))
    else:
        payload = p.fields(value["payload"], publication.PAYLOAD)
        p.require(payload["apiVersion"] == publication.GRANT_API
            and payload["purpose"] == "native-policy-publication-state"
            and payload["serviceRole"] == purpose.removeprefix("ordinary-publication-"))
    return value
