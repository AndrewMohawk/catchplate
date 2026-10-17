"""Source-owned audit outbox limit shared by legacy and authority admission.

This limit is not a count proof. Every writer must separately establish and
maintain the pending-plus-claimed population under its admitted transaction.
"""

MAX_PENDING = 100_000
