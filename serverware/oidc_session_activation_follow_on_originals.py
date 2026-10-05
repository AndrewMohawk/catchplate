"""Fixed inherited sealed originals for the six genuine follow-on deliveries.

This replaces protected-file intake only. It does not sign, admit a request,
create work/clocks, select an operation or replace any existing root verifier.
The root signer is read only at the original entrypoint's post-admission step.
"""
from __future__ import annotations

import fcntl
import os
import array
import socket
import struct

from serverware import oidc_session_activation_release_entrypoint as ownership
from serverware import registration_execution_authorizer_entrypoint as sealed

FIRST_FD = 50
MAX_BYTES = 64 * 1024 * 1024
OUTPUT_FD = 49
OUTPUT_MARKER = b"SWCO\x00\x00\x00\x01"


def _output_rows(profile):
    if profile == 'consume-worker':
        from serverware import oidc_session_activation_delivery_planner_entrypoint as fixed
        return OUTPUT_MARKER, ((fixed.BOOTSTRAP_FD, fixed.MAX_BOOTSTRAP_BYTES),
            (fixed.HISTORY_FD, fixed.MAX_HISTORY_BYTES))
    if profile == 'proof-worker':
        from serverware import oidc_session_activation_release_proof_entrypoint as fixed
        return b'SWPO\x00\x00\x00\x01', ((fixed.BOOTSTRAP_FD, fixed.MAX_BOOTSTRAP_BYTES),)
    raise RuntimeError('follow-on sealed return profile differs')


def _return_originals(profile, *, owned, work, current):
    """Return the actual admitted sealed originals to their root supervisor.

    This is custody only: the receiver independently verifies both originals.
    It occurs once before permanent drop and does not change the worker roster.
    """
    marker, rows = _output_rows(profile)
    current()
    ownership._claim(OUTPUT_FD, owned)
    channel = socket.socket(fileno=OUTPUT_FD)
    try:
        if (channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET
                or struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET,
                    socket.SO_PEERCRED, struct.calcsize('3i'))) != (os.getppid(), 0, 0)):
            raise RuntimeError('consume original return channel is not the original root parent')
        pins = tuple(sealed._sealed_identity(fd, maximum) for fd, maximum in rows)
        work.charge(input_bytes=4096)
        current()
        sent = channel.sendmsg((marker,), [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array('i', (fd for fd, _maximum in rows)))], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
        if sent != len(marker) or pins != tuple(sealed._sealed_identity(fd, maximum) for fd, maximum in rows):
            raise RuntimeError('consume original transfer is uncertain; no retry')
        current()
    finally:
        if channel.detach() != OUTPUT_FD or not ownership._close_owned_descriptor(OUTPUT_FD, owned):
            raise RuntimeError('consume original return channel close is uncertain')


def roster(profile):
    """Closed source roles; no caller-provided paths, descriptors or limits."""
    if profile == 'consume-issuer':
        from serverware import oidc_session_activation_consume_input_issuer_entrypoint as entry
    elif profile == 'proof-issuer':
        from serverware import oidc_session_activation_release_proof_input_issuer_entrypoint as entry
    elif profile == 'consume-worker':
        from serverware import oidc_session_activation_consume_dynamic_entrypoint as entry
    elif profile == 'proof-worker':
        from serverware import oidc_session_activation_release_proof_dynamic_entrypoint as entry
    elif profile == 'grant-issuer':
        from serverware import oidc_session_activation_release_grant_issuer_entrypoint as entry
    elif profile == 'release-worker':
        from serverware import oidc_session_activation_release_dynamic_entrypoint as entry
    else:
        raise RuntimeError('sealed follow-on source profile differs')
    if profile.endswith('-issuer'):
        rows = tuple((path, maximum, False) for path, _target, maximum in entry._TRUST_FILES)
        rows += ((entry.KEY_PATH, entry.MAX_KEY_BYTES, True),)
    else:
        rows = tuple((path, maximum, False) for path, maximum in entry._PUBLIC_FILES)
    return tuple((FIRST_FD + index, *row) for index, row in enumerate(rows))


class _Originals:
    def __init__(self, profile, owned):
        if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
            raise RuntimeError('sealed follow-on intake must be the actual root delivery')
        self.pid, self.owned = os.getpid(), owned
        self.rows = roster(profile)
        self.pins, self.consumed = {}, set()
        total = 0
        for descriptor, _path, maximum, private in self.rows:
            ownership._claim(descriptor, owned)
            pin = sealed._sealed_identity(descriptor, maximum, private=private)
            self.pins[descriptor] = pin
            total += pin[0][6]
        if total > MAX_BYTES:
            raise RuntimeError('sealed follow-on originals exceed existing aggregate capacity')

    def open(self, path, maximum, *, work, current, private=False, expected_size=None, retained_bytes=0):
        if os.getpid() != self.pid or type(private) is not bool:
            raise RuntimeError('sealed follow-on original owner changed')
        matches = [row for row in self.rows if row[1:] == (path, maximum, private)]
        if len(matches) != 1:
            raise RuntimeError('sealed follow-on original is not source selected')
        descriptor = matches[0][0]
        if descriptor in self.consumed:
            raise RuntimeError('sealed follow-on original cannot be acquired twice')
        current()
        pin = sealed._sealed_identity(descriptor, maximum, private=private)
        if pin != self.pins[descriptor] or (expected_size is not None and pin[0][6] != expected_size):
            raise RuntimeError('sealed follow-on original protection/size changed')
        if type(retained_bytes) is not int or retained_bytes < 0 or retained_bytes + 2 * pin[0][6] > MAX_BYTES:
            raise RuntimeError('sealed follow-on original exceeds retained capacity')
        work.charge(input_bytes=2 * pin[0][6])
        self.consumed.add(descriptor)  # No retry after uncertain descriptor duplication.
        duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, 3)
        ownership._claim(duplicate, self.owned)
        if sealed._sealed_identity(duplicate, maximum, private=private) != pin:
            raise RuntimeError('sealed follow-on duplicate differs')
        if not ownership._close_owned_descriptor(descriptor, self.owned):
            raise RuntimeError('sealed follow-on source close is uncertain')
        current()
        return duplicate

    def read(self, path, maximum, *, owned, work, current):
        if owned is not self.owned:
            raise RuntimeError('sealed follow-on read changed descriptor owner')
        descriptor = self.open(path, maximum, work=work, current=current)
        current()
        raw, pin = sealed._read_original(descriptor, maximum)
        if pin != sealed._sealed_identity(descriptor, maximum):
            raise RuntimeError('sealed follow-on read changed original')
        if not ownership._close_owned_descriptor(descriptor, owned):
            raise RuntimeError('sealed follow-on duplicate close is uncertain')
        current()
        return raw
