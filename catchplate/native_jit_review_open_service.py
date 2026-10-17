"""Selection boundary for the protected review service.

Opening is not yet selectable. The current reader and receipt kernel need a
dedicated bounded plan/commit path and actual commit-owner acknowledgment before
a cold admitted service can be installed here. The legacy executor cannot
carry their larger retained originals or establish that acknowledgment.

The portal can exercise its public protocol in isolated tests, but ordinary
startup, environment flags and caller-created objects cannot enable it. This
explicit unavailable boundary preserves the existing capability until that
connected owner is implemented; it is not a working review adapter.
"""
from __future__ import annotations


def selected():
    """No admitted complete opening owner exists in the current assembly."""
    return None
