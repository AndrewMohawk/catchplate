from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("SERVERWARE_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "serverware.sqlite3"
MITMPROXY_CONF_DIR = DATA_DIR / "mitmproxy"
CA_INSTALL_SESSIONS_PATH = Path(os.getenv("SERVERWARE_CA_INSTALL_SESSIONS", str(DATA_DIR / "ca-install-sessions.json")))
MASTER_KEY_PATH = DATA_DIR / "master.key"
KEY_RELEASE_STATE_PATH = Path(os.getenv("SERVERWARE_KEY_RELEASE_STATE", str(DATA_DIR / "key-release-state.json")))
TEE_QUOTE_SIGNING_KEY_PATH = Path(os.getenv("SERVERWARE_TEE_QUOTE_SIGNING_KEY", str(DATA_DIR / "dev-tee-quote-ed25519.pem")))
RESPONSE_SIGNING_KEY_PATH = Path(os.getenv("SERVERWARE_RESPONSE_SIGNING_KEY", str(DATA_DIR / "response-signing-ed25519.pem")))
TEE_QUOTE_PROVIDER = os.getenv("SERVERWARE_TEE_QUOTE_PROVIDER", "dev-signed-quote").strip()
TEE_QUOTE_COMMAND = os.getenv("SERVERWARE_TEE_QUOTE_COMMAND", "").strip()
TEE_QUOTE_VERIFY_COMMAND = os.getenv("SERVERWARE_TEE_QUOTE_VERIFY_COMMAND", "").strip()
TEE_PLATFORM = os.getenv("SERVERWARE_TEE_PLATFORM", "none-dev").strip()
POLICY_BUNDLE_PATH = Path(os.getenv("SERVERWARE_POLICY_BUNDLE", str(DATA_DIR / "policy-bundle.json")))
POLICY_CANARY_STATE_PATH = Path(os.getenv("SERVERWARE_POLICY_CANARY_STATE", str(DATA_DIR / "policy-canary-state.json")))
POLICY_CANARY_BUNDLE_PATH = Path(os.getenv("SERVERWARE_POLICY_CANARY_BUNDLE", str(DATA_DIR / "policy-canary-bundle.json")))
POLICY_SIGNING_KEY_PATH = Path(os.getenv("SERVERWARE_POLICY_SIGNING_KEY", str(DATA_DIR / "policy-signing-ed25519.pem")))
POLICY_SIGNING_PUBLIC_KEY_PATH = Path(os.getenv("SERVERWARE_POLICY_SIGNING_PUBLIC_KEY", str(DATA_DIR / "policy-signing-ed25519.pub.pem")))
ADMIN_TOKEN_PATH = DATA_DIR / "admin.token"
RBAC_BINDINGS_PATH = Path(os.getenv("SERVERWARE_RBAC_BINDINGS", str(DATA_DIR / "rbac-bindings.json")))
RELEASE_PROVENANCE_PATH = Path(os.getenv("SERVERWARE_RELEASE_PROVENANCE", str(DATA_DIR / "release-provenance.json")))
IMAGE_SIGNATURES_PATH = Path(os.getenv("SERVERWARE_IMAGE_SIGNATURES", str(DATA_DIR / "image-signatures.json")))
DECISION_GATE_CA_CERT_PATH = Path(os.getenv("SERVERWARE_DECISION_GATE_CA_CERT", str(DATA_DIR / "decision-gate-ca-cert.pem")))
DECISION_GATE_CA_KEY_PATH = Path(os.getenv("SERVERWARE_DECISION_GATE_CA_KEY", str(DATA_DIR / "decision-gate-ca-key.pem")))
SCHEMA_DIR = Path(os.getenv("SERVERWARE_SCHEMA_DIR", str(PROJECT_ROOT / "schemas")))
OAUTH_STATE_PATH = Path(os.getenv("SERVERWARE_OAUTH_STATE_PATH", str(DATA_DIR / "oauth-states.json")))
OAUTH_STATE_TTL_SECONDS = int(os.getenv("SERVERWARE_OAUTH_STATE_TTL_SECONDS", "600"))

WEB_HOST = os.getenv("SERVERWARE_WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("SERVERWARE_WEB_PORT", "3000"))
WEB_TLS_CERT_FILE = os.getenv("SERVERWARE_WEB_TLS_CERT_FILE", "").strip()
WEB_TLS_KEY_FILE = os.getenv("SERVERWARE_WEB_TLS_KEY_FILE", "").strip()
PROXY_HOST = os.getenv("SERVERWARE_PROXY_HOST", "0.0.0.0")
PROXY_PORT = int(os.getenv("SERVERWARE_PROXY_PORT", "8080"))
PUBLIC_URL = os.getenv("SERVERWARE_PUBLIC_URL", f"http://localhost:{WEB_PORT}")
GOOGLE_OAUTH_CLIENT_ID = os.getenv("SERVERWARE_GOOGLE_OAUTH_CLIENT_ID", "").strip()
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
GOOGLE_OAUTH_REDIRECT_URI = os.getenv("SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI", f"{PUBLIC_URL}/api/oauth/callback/google").strip()
X_OAUTH_CLIENT_ID = os.getenv("SERVERWARE_X_OAUTH_CLIENT_ID", os.getenv("SERVERWARE_TWITTER_OAUTH_CLIENT_ID", "")).strip()
X_OAUTH_CLIENT_SECRET = os.getenv("SERVERWARE_X_OAUTH_CLIENT_SECRET", os.getenv("SERVERWARE_TWITTER_OAUTH_CLIENT_SECRET", "")).strip()
X_OAUTH_REDIRECT_URI = os.getenv("SERVERWARE_X_OAUTH_REDIRECT_URI", os.getenv("SERVERWARE_TWITTER_OAUTH_REDIRECT_URI", f"{PUBLIC_URL}/api/oauth/callback/x")).strip()
ADMIN_USER_ID = os.getenv("SERVERWARE_ADMIN_USER", "user:admin")
ADMIN_ROLES = tuple(
    role.strip()
    for role in os.getenv(
        "SERVERWARE_ADMIN_ROLES",
        "admin,approver,auditor,policy_author,policy_publisher,credential_owner",
    ).split(",")
    if role.strip()
)
OIDC_ENABLED = os.getenv("SERVERWARE_OIDC_ENABLED", "0") == "1"
OIDC_ISSUER = os.getenv("SERVERWARE_OIDC_ISSUER", "").strip()
OIDC_AUDIENCE = os.getenv("SERVERWARE_OIDC_AUDIENCE", "").strip()
OIDC_JWKS_JSON = os.getenv("SERVERWARE_OIDC_JWKS_JSON", "").strip()
OIDC_JWKS_PATH = Path(os.getenv("SERVERWARE_OIDC_JWKS_PATH", str(DATA_DIR / "oidc-jwks.json")))
OIDC_ROLE_CLAIM = os.getenv("SERVERWARE_OIDC_ROLE_CLAIM", "serverware_roles").strip() or "serverware_roles"
OIDC_SUBJECT_CLAIM = os.getenv("SERVERWARE_OIDC_SUBJECT_CLAIM", "sub").strip() or "sub"
OIDC_ALLOWED_ALGORITHMS = tuple(
    item.strip()
    for item in os.getenv("SERVERWARE_OIDC_ALLOWED_ALGORITHMS", "RS256,ES256,EdDSA").split(",")
    if item.strip()
)
OIDC_LEEWAY_SECONDS = int(os.getenv("SERVERWARE_OIDC_LEEWAY_SECONDS", "60"))
WEBAUTHN_RP_ID = os.getenv("SERVERWARE_WEBAUTHN_RP_ID", "localhost")
WEBAUTHN_ORIGIN = os.getenv("SERVERWARE_WEBAUTHN_ORIGIN", PUBLIC_URL)
WEBAUTHN_RP_NAME = os.getenv("SERVERWARE_WEBAUTHN_RP_NAME", "Serverware")
WEBAUTHN_BOOTSTRAP_TOKEN = os.getenv("SERVERWARE_WEBAUTHN_BOOTSTRAP_TOKEN", "")
WEBAUTHN_TRUST_ROOTS_PATH = Path(os.getenv("SERVERWARE_WEBAUTHN_TRUST_ROOTS", str(DATA_DIR / "webauthn-trust-roots.pem")))
WEBAUTHN_TRUST_BUNDLE_PATH = Path(os.getenv("SERVERWARE_WEBAUTHN_TRUST_BUNDLE", str(DATA_DIR / "webauthn-trust-bundle.json")))
WEBAUTHN_TRUST_BUNDLE_STATE_PATH = Path(
    os.getenv("SERVERWARE_WEBAUTHN_TRUST_BUNDLE_STATE", str(DATA_DIR / "webauthn-trust-bundle-state.json"))
)
WEBAUTHN_TRUST_SIGNING_KEY_PATH = Path(
    os.getenv("SERVERWARE_WEBAUTHN_TRUST_SIGNING_KEY", str(DATA_DIR / "webauthn-trust-signing-ed25519.pem"))
)
WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY_PATH = Path(
    os.getenv("SERVERWARE_WEBAUTHN_TRUST_SIGNING_PUBLIC_KEY", str(DATA_DIR / "webauthn-trust-signing-ed25519.pub.pem"))
)
DEV_AUTHENTICATOR_ENABLED = os.getenv("SERVERWARE_DEV_AUTHENTICATOR", "0") == "1"
CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED = os.getenv("SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED", "0") == "1"
CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION = (
    os.getenv("SERVERWARE_CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION", "0") == "1"
)
CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES = tuple(
    item.strip()
    for item in os.getenv("SERVERWARE_CONTROL_PLANE_MUTATION_ALLOWED_AUTHENTICATOR_CLASSES", "").split(",")
    if item.strip()
)
CONTROL_PLANE_TWO_PERSON_REQUIRED = os.getenv("SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED", "0") == "1"
CONTROL_PLANE_TWO_PERSON_TTL_SECONDS = int(os.getenv("SERVERWARE_CONTROL_PLANE_TWO_PERSON_TTL_SECONDS", "300"))
CONTROL_PLANE_TWO_PERSON_ACTIONS = tuple(
    item.strip()
    for item in os.getenv(
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS",
        "credential.create,credential.update,credential.delete,route.create,route.update,route.delete,policy.publish,webauthn.credential.register,rbac.role.change,rbac.deprovision,control_plane.token.rotate,break_glass.grant",
    ).split(",")
    if item.strip()
)
DIRECT_CA_DOWNLOAD_ENABLED = os.getenv("SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED", "1") == "1"
CA_INSTALL_SESSION_TTL_SECONDS = int(os.getenv("SERVERWARE_CA_INSTALL_SESSION_TTL_SECONDS", "300"))
POLICY_PUBLISH_DRY_RUN_REQUIRED = os.getenv("SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED", "0") == "1"
POLICY_CANARY_REQUIRED = os.getenv("SERVERWARE_POLICY_CANARY_REQUIRED", "0") == "1"
POLICY_CANARY_MIN_OBSERVATION_SECONDS = int(os.getenv("SERVERWARE_POLICY_CANARY_MIN_OBSERVATION_SECONDS", "0"))
POLICY_CANARY_MIN_AUDIT_EVENTS = int(os.getenv("SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS", "0"))
POLICY_CANARY_MAX_DENIALS = int(os.getenv("SERVERWARE_POLICY_CANARY_MAX_DENIALS", "0"))
POLICY_MIN_SEQUENCE = int(os.getenv("SERVERWARE_POLICY_MIN_SEQUENCE", "0"))
POLICY_MIN_ROLLBACK_EPOCH = int(os.getenv("SERVERWARE_POLICY_MIN_ROLLBACK_EPOCH", "0"))
SECRET_LEASE_TTL_SECONDS = float(os.getenv("SERVERWARE_SECRET_LEASE_TTL_SECONDS", "5"))
AUDIT_QUEUE_MAX = int(os.getenv("SERVERWARE_AUDIT_QUEUE_MAX", "10000"))
AUDIT_ANCHOR_URL = os.getenv("SERVERWARE_AUDIT_ANCHOR_URL", "").rstrip("/")
AUDIT_ANCHOR_TOKEN = os.getenv("SERVERWARE_AUDIT_ANCHOR_TOKEN", "")
AUDIT_ANCHOR_CA_BUNDLE = os.getenv("SERVERWARE_AUDIT_ANCHOR_CA_BUNDLE", "").strip()
AUDIT_ANCHOR_INTERVAL_SECONDS = float(os.getenv("SERVERWARE_AUDIT_ANCHOR_INTERVAL_SECONDS", "2"))
AUDIT_ANCHOR_TIMEOUT_SECONDS = float(os.getenv("SERVERWARE_AUDIT_ANCHOR_TIMEOUT_SECONDS", "10"))
GRANT_STORE_BACKEND = os.getenv("SERVERWARE_GRANT_STORE_BACKEND", "sqlite").strip().lower()
GRANT_STORE_POSTGRES_DSN = os.getenv("SERVERWARE_GRANT_STORE_POSTGRES_DSN", "")
GRANT_STORE_CONNECT_TIMEOUT_SECONDS = int(os.getenv("SERVERWARE_GRANT_STORE_CONNECT_TIMEOUT_SECONDS", "5"))
AUDIT_STORE_BACKEND = os.getenv("SERVERWARE_AUDIT_STORE_BACKEND", "sqlite").strip().lower()
AUDIT_STORE_POSTGRES_DSN = os.getenv("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", "")
AUDIT_STORE_CONNECT_TIMEOUT_SECONDS = int(os.getenv("SERVERWARE_AUDIT_STORE_CONNECT_TIMEOUT_SECONDS", "5"))
METADATA_STORE_BACKEND = os.getenv("SERVERWARE_METADATA_STORE_BACKEND", "sqlite").strip().lower()
METADATA_STORE_POSTGRES_DSN = os.getenv("SERVERWARE_METADATA_STORE_POSTGRES_DSN", "")
METADATA_STORE_CONNECT_TIMEOUT_SECONDS = int(os.getenv("SERVERWARE_METADATA_STORE_CONNECT_TIMEOUT_SECONDS", "5"))
DECISION_GATE_BASE = os.getenv("SERVERWARE_DECISION_GATE_BASE", "").rstrip("/")
DECISION_GATE_TIMEOUT_SECONDS = float(os.getenv("SERVERWARE_DECISION_GATE_TIMEOUT_SECONDS", "2"))
DATA_PLANE_INSTANCE_ID = os.getenv("SERVERWARE_DATA_PLANE_INSTANCE_ID", "").strip()
DATA_PLANE_CREDENTIAL_LEASE_TOKEN = os.getenv("SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN", "").strip()
DATA_PLANE_AUDIT_INGEST_TOKEN = os.getenv("SERVERWARE_DATA_PLANE_AUDIT_TOKEN", "").strip()
DATA_PLANE_GRANT_CONSUME_TOKEN = os.getenv("SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN", "").strip()
DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN = os.getenv("SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN", "").strip()
DATA_PLANE_MANAGEMENT_TOKEN = os.getenv("SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN", "").strip()
# serverware.runtime still publishes development grants to the Rust management API
# through this internal symbol. It must never reuse an ingest or consume credential.
DATA_PLANE_AUDIT_TOKEN = DATA_PLANE_MANAGEMENT_TOKEN
DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED = (
    os.getenv("SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED", "0") == "1"
)
DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND = os.getenv(
    "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND",
    "",
).strip()
DATA_PLANE_UID = int(os.getenv("SERVERWARE_DATA_PLANE_UID", "10001"))
DATA_PLANE_GID = int(os.getenv("SERVERWARE_DATA_PLANE_GID", "10001"))
KEY_RELEASE_REQUIRED = os.getenv("SERVERWARE_KEY_RELEASE_REQUIRED", "1") == "1"
KEY_RELEASE_ALLOW_DEBUG = os.getenv("SERVERWARE_KEY_RELEASE_ALLOW_DEBUG", "1") == "1"
KEY_RELEASE_COMMAND = os.getenv("SERVERWARE_KEY_RELEASE_COMMAND", "").strip()
MASTER_KEY_UNSEAL_COMMAND = os.getenv("SERVERWARE_MASTER_KEY_UNSEAL_COMMAND", "").strip()
NITRO_NSM_UNSEAL_COMMAND_TEMPLATE = os.getenv("SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE", "").strip()
KEY_RELEASE_MIN_ROLLBACK_EPOCH = int(os.getenv("SERVERWARE_KEY_RELEASE_MIN_ROLLBACK_EPOCH", "1"))
KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST = os.getenv("SERVERWARE_KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST", "1") == "1"
RELEASE_CHANNEL = os.getenv("SERVERWARE_RELEASE_CHANNEL", "dev")
EXPECTED_DATA_PLANE_BINARY_DIGEST = os.getenv("SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST") or None


_DEVELOPMENT_RELEASE_CHANNELS = {"dev", "development", "local", "test"}
_INTERNAL_SERVICE_TOKENS = {
    "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": DATA_PLANE_CREDENTIAL_LEASE_TOKEN,
    "SERVERWARE_DATA_PLANE_AUDIT_TOKEN": DATA_PLANE_AUDIT_INGEST_TOKEN,
    "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN": DATA_PLANE_GRANT_CONSUME_TOKEN,
    "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN": DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN,
    "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN": DATA_PLANE_MANAGEMENT_TOKEN,
}


def validate_internal_service_auth() -> None:
    if RELEASE_CHANNEL.strip().lower() in _DEVELOPMENT_RELEASE_CHANNELS:
        return
    if not DATA_PLANE_INSTANCE_ID.startswith("spiffe://") or len(DATA_PLANE_INSTANCE_ID) <= len("spiffe://"):
        raise RuntimeError("production requires SERVERWARE_DATA_PLANE_INSTANCE_ID as a non-empty SPIFFE ID")
    for name, token in _INTERNAL_SERVICE_TOKENS.items():
        if len(token.encode("utf-8")) < 32 or len(set(token)) < 8:
            raise RuntimeError(f"production requires {name} with at least 32 high-entropy bytes")
    token_items = list(_INTERNAL_SERVICE_TOKENS.items())
    for index, (left_name, left_token) in enumerate(token_items):
        for right_name, right_token in token_items[index + 1 :]:
            if left_token == right_token:
                raise RuntimeError(f"production requires distinct internal service credentials: {left_name} and {right_name}")


def ensure_data_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    MITMPROXY_CONF_DIR.mkdir(parents=True, exist_ok=True)
