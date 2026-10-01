"""Kernel peer facts for the observation-only cold rendezvous accept.

These primitives do not authorize a peer, transfer custody or construct a
listener. The caller retains the actual socket and acquired PIDFD before any
validation, and applies its independently approved root identity and clocks.
"""
from __future__ import annotations

import os
import select
import socket
import stat
import struct

from serverware import native_pilot_adopted_intake as intake
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_shadow_nitro_originals as originals

p = io.p
API = "serverware.nativePilotGenesisReceiverObservation/v1"
SO_PEERPIDFD = 77
_CREDENTIALS = struct.Struct("=iII")


def acquire_pidfd(channel):
    """The returned real kernel FD must immediately enter the caller's owner."""
    return struct.unpack("=i", channel.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4))[0]


def peer_identity(channel, peer_fd, *, boot):
    """Check one actual live socket peer; no numeric-PID ownership fallback."""
    p.require(type(peer_fd) is int and peer_fd >= 3 and not os.get_inheritable(peer_fd)
        and channel.family == socket.AF_UNIX
        and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
        and channel.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0)
    channel.getpeername()
    p.require(not select.select([peer_fd], [], [], 0)[0])
    peer = _CREDENTIALS.unpack(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size))
    pid, uid, gid = peer
    p.require(pid > 1 and pid != os.getpid() and io.pidfd_pid(peer_fd) == pid
        and originals._boot() == boot)
    start = intake._sender_start(pid)
    namespace = os.stat("/proc/" + str(pid) + "/ns/time")
    p.require((namespace.st_dev, namespace.st_ino) == boot[1:])
    with open("/proc/" + str(pid) + "/status", "rt", encoding="ascii") as stream:
        status = stream.read(16385)
    p.require(len(status) <= 16384)
    for label, expected in (("Uid:", uid), ("Gid:", gid)):
        rows = [line.split()[1:] for line in status.splitlines() if line.startswith(label)]
        p.require(len(rows) == 1 and len(rows[0]) == 4 and all(number.isascii() and number.isdecimal()
            and int(number) == expected for number in rows[0]))
    info = os.fstat(channel.fileno())
    p.require(stat.S_ISSOCK(info.st_mode) and not channel.get_inheritable()
        and not select.select([peer_fd], [], [], 0)[0] and io.pidfd_pid(peer_fd) == pid
        and intake._sender_start(pid) == start and originals._boot() == boot
        and _CREDENTIALS.unpack(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size)) == peer)
    again = os.stat("/proc/" + str(pid) + "/ns/time")
    p.require((again.st_dev, again.st_ino) == boot[1:])
    return dict(pid=pid, uid=uid, gid=gid, startTimeTicks=start)
