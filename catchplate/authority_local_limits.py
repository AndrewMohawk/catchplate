"""Prospective limits for development trusted-host-local setup and sessions.

These ceilings do not renew original issue timestamps or signed expiries.
They do not select production assurance or extend WebAuthn/action deadlines.
"""

LOCAL_SETUP_MAX_NS = 5400 * 1_000_000_000
LOCAL_SESSION_MAX_NS = 7200 * 1_000_000_000
