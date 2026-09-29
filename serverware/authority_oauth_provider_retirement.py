"""Permanent, opt-in local provider retirement; never inferred account identity.

The independently scoped metadata deployment owns this record. Its presence
blocks new issuance/use for the whole provider, not just a caller-selected
application or subject. There is deliberately no expiry, delete or reopen API.
"""
import uuid

from serverware import authority_transition_quota as shared
from serverware import authority_oauth_refresh as scalar

TABLE = "oauth_provider_retirements"
FIELDS = frozenset({"id", "provider_id", "deployment_id", "authorization_sha256",
    "source_profile", "exchange_id", "claim_request_digest", "created_at"})


def provider_id(provider):
    scalar.require(provider in {"google", "x"})
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "serverware.oauthProviderRetirement/v1:" + provider))


def query(operation, provider):
    return shared._query(operation=operation, name="oauth_provider_retirement", table=TABLE,
        key={"id": provider_id(provider)})


def require_open(context, provider):
    scalar.require(not context.exact(TABLE, {"id": provider_id(provider)})["present"],
        "independently authorized provider-wide retirement blocks new issuance and use")
