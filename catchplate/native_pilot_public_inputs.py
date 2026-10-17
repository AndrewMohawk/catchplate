"""Retained public originals for the fixed privileged native pilot conductor.

Pins select only independently provisioned public fixtures below INPUT_ROOT.
This reader does not install inputs, parse private keys, execute supplied code,
verify a service grant, infer authority, or create any runtime resource. Cold
control/launch files and credential descriptors keep their existing owners.
"""
from __future__ import annotations

import os
import threading

from catchplate import native_shadow_nitro_profile as p
from catchplate.native_shadow_proof_cohort_control import _Original

INPUT_ROOT = "/etc/catchplate/native-pilot-inputs/"
MAX_ORIGINALS = 128
MAX_PUBLIC_BYTES = 32 * 1024 * 1024
_TOKEN = object()


class PublicInputs:
    """Same-process retained files, not a reconstructed launch capability.

    The conductor must retain this owner on unknown cleanup and call close()
    only after its actual pilot owners have completed their required cleanup.
    There is deliberately no automatic context-manager cleanup or finalizer:
    this reader cannot determine whether the separate pilot has retired.
    """

    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid = os.getpid()
        self._closed = False
        self._entries = {}
        self._bytes = 0

    @classmethod
    def open(cls):
        p.require(cls is PublicInputs)
        owner = cls(_TOKEN)
        owner._origin()
        return owner

    def _origin(self):
        p.require(not self._closed and os.getpid() == self._pid
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def read(self, pin, *, maximum):
        """Return literal pinned bytes; every use enforces its own size bound.

        A path cannot be rebound to another digest within this owner. Reusing a
        previously admitted file for a smaller purpose still checks its actual
        length against that purpose's bound; the initial limit is not authority
        to weaken a later caller. Files and protected ancestors remain open.
        """
        self._origin()
        p.fields(pin, ("path", "sha256"))
        path, digest = pin["path"], p.digest(pin["sha256"])
        p.require(type(path) is str and path.startswith(INPUT_ROOT)
            and len(path) > len(INPUT_ROOT))
        p.integer(maximum, maximum=MAX_PUBLIC_BYTES)
        if path in self._entries:
            expected, original = self._entries[path]
            p.require(digest == expected and len(original.raw) <= maximum)
            original.check()
        else:
            p.require(len(self._entries) < MAX_ORIGINALS and self._bytes < MAX_PUBLIC_BYTES)
            # The actual loader refuses an oversized file before reading it;
            # remaining aggregate capacity also bounds this first acquisition.
            bound = min(maximum, MAX_PUBLIC_BYTES - self._bytes)
            original = _Original(path, bound, digest, mode=0o400)
            self._entries[path] = (digest, original)
            self._bytes += len(original.raw)
        self._origin()
        original.check()
        return original.raw

    def document(self, pin, *, maximum):
        """Parse the existing canonical public JSON grammar, retaining bytes.

        Parsing is not signature verification or admission. Purpose-specific
        receiving owners still authenticate and bind these exact originals.
        """
        raw = self.read(pin, maximum=maximum)
        value = p.document(raw, maximum)
        self._origin()
        self._entries[pin["path"]][1].check()
        return value

    def check(self):
        self._origin()
        p.require(len(self._entries) <= MAX_ORIGINALS
            and self._bytes == sum(len(original.raw) for _, original in self._entries.values())
            and self._bytes <= MAX_PUBLIC_BYTES)
        for _, original in self._entries.values():
            original.check()
        self._origin()

    def close(self):
        """Caller asserts its genuine cleanup is complete, not a new proof.

        No freshness/path recheck is required to release descriptors after
        cleanup: an input may have become invalid while the pilot was stopping.
        Closing this reader never closes, signals, or reaps a pilot process.
        """
        if self._closed:
            return
        self._origin()
        self._closed = True
        for _, original in reversed(tuple(self._entries.values())):
            original.close()
        self._entries.clear()
        self._bytes = 0
