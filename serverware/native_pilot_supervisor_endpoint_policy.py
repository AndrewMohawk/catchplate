"""Static independent endpoint preparation policy, never future observations.

The explicit fresh-ledger profile contains no predicted assignment, production
binding, proof scope, receipt or manifest. Those originals are derived only by
the separately retained measured recipe and actual process-owned request path.
This grammar checks a selected existing directory's path, not its existence,
ownership, permissions, contents or kernel custody; the real directory owner
must establish and retain those properties before preparation is approved.
"""
from __future__ import annotations

import copy

from serverware import native_shadow_nitro_profile as p

API = "serverware.nativePilotSupervisorEndpointPolicy/v2"
FIELDS = ("apiVersion", "initialization", "objectDirectory", "peerExpectations")
PEER_FIELDS = ("cgroupPathSha256", "securityLabelSha256", "configurationGenerationSha256")


def validate_policy(fragment) -> dict:
    """Check the complete static fragment; never open or provision its path."""
    p.fields(fragment, FIELDS)
    p.require(fragment["apiVersion"] == API and fragment["initialization"] == "fresh-ledger")
    path = fragment["objectDirectory"]
    p.require(type(path) is str and path.isascii() and path.startswith("/")
        and 1 < len(path) <= 4096 and "\0" not in path)
    parts = path.split("/")[1:]
    p.require(3 <= len(parts) <= 32
        and all(part not in ("", ".", "..") and len(part) <= 255 for part in parts))
    expected = p.fields(fragment["peerExpectations"], PEER_FIELDS)
    for digest in expected.values():
        p.require(p.digest(digest) != p.sha(b""))
    return copy.deepcopy(fragment)
