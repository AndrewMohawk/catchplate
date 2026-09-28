"""Bounded local issuance claims, not certificate or rollback authority.

The actual issuer startup lends its already admitted, exclusively flocked
directory descriptor. This owner never opens a path outside that directory,
signs, deletes a claim, renews a nonce, or closes/unlocks the borrowed lease.
A signed checkpoint is a minimum chain prefix; valid extensions are accepted.
It does not establish the latest state against a privileged host rollback.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import stat

from serverware.authority_query_read_work import _ValidationWork
from serverware.authority_witness_journal import WitnessJournalIO


ISSUER_UID = ISSUER_GID = 65492
MAX_RECORDS = 1024
MAX_BYTES = 64 * 1024 * 1024
MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_ASSOCIATION_BYTES = 16 * 1024
MAX_CLAIM_BYTES = 80 + MAX_ASSOCIATION_BYTES
MAX_RECORD_BYTES = 80 + 32 + MAX_CERTIFICATE_BYTES
MAX_OPERATION_RESERVATION_BYTES = 2 * 1024 * 1024
_CLAIM_MAGIC = b"SWIJC001"
_COMPLETE_MAGIC = b"SWIJO001"
_SLOT_DOMAIN = b"serverware.workloadIdentityIssuanceSlot/v1\x00"
_ZERO = bytes(32)
_DIGEST_FIELDS = (3, 5, 6, 7, 8, 9, 10, 11, 12)
_MATERIAL_FIELDS = ("journal_namespace", "journal_device", "journal_inode",
    "journal_uid", "journal_gid", "journal_quota_bytes",
    "journal_maximum_records", "journal_checkpoint")


class IssuerJournalError(RuntimeError):
    pass


def _fail(message):
    raise IssuerJournalError(message)


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("issuer journal integer exceeds its fixed bound")


def _digest_value(value):
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        _fail("issuer journal digest is not canonical")
    return value


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
        metadata.st_mode, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns)


def _hash(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _association(value, work):
    # This closed scalar record is supplied only after genuine grant/request
    # verification. It is never accepted as signature or certificate authority.
    if type(value) is not tuple or len(value) != 17:
        _fail("issuer journal requires the exact association tuple")
    fields = []
    for index, item in enumerate(value):
        if index < 13:
            maximum = 512 if index in (1, 2) else 128
            if type(item) is not str or not 1 <= len(item) <= maximum:
                _fail("issuer journal association text exceeds its bound")
            if any(ord(character) < 32 or ord(character) == 127 for character in item):
                _fail("issuer journal association text contains controls")
            work.charge(input_bytes=4 * len(item))
            try:
                original = item.encode("utf-8")
            except UnicodeError as exc:
                raise IssuerJournalError("issuer journal association text is invalid") from exc
            if len(original) > maximum:
                _fail("issuer journal association UTF-8 exceeds its bound")
            if index in (0, 4) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", item) is None:
                _fail("issuer journal namespace or grant ID is not canonical")
            if index in _DIGEST_FIELDS:
                _digest_value(item)
        elif index == 13:
            _integer(item, 1, 2**159 - 1)
            original = item.to_bytes(20, "big")
        elif index in (14, 15):
            _integer(item, 0, 253402300799)
            original = item.to_bytes(8, "big")
        else:
            if type(item) is not bytes or not 2 <= len(item) <= 8192:
                _fail("issuer journal SAN original exceeds its bound")
            # This is A's exact canonical SAN-only original, never a packet,
            # certificate, token or caller-selected JSON document.
            original = item
        fields.append(original)
    if value[14] >= value[15]:
        _fail("issuer journal certificate interval is empty")
    size = 4 * len(fields) + sum(map(len, fields))
    if size > MAX_ASSOCIATION_BYTES:
        _fail("issuer journal association exceeds its fixed frame")
    work.charge(input_bytes=2 * size)
    encoded = b"".join(len(field).to_bytes(4, "big") + field for field in fields)
    return value, encoded


def _decode_association(raw, work):
    if type(raw) is not bytes or not 68 <= len(raw) <= MAX_ASSOCIATION_BYTES:
        _fail("issuer journal association frame is malformed")
    work.charge(input_bytes=2 * len(raw))
    offset, fields = 0, []
    for index in range(17):
        if offset + 4 > len(raw):
            _fail("issuer journal association length is truncated")
        size = int.from_bytes(raw[offset:offset + 4], "big")
        offset += 4
        limit = 8192 if index == 16 else 512 if index in (1, 2) else 128
        if not 1 <= size <= limit or size > len(raw) - offset:
            _fail("issuer journal association field exceeds its bound")
        field = raw[offset:offset + size]
        offset += size
        if index < 13:
            try:
                fields.append(field.decode("utf-8"))
            except UnicodeError as exc:
                raise IssuerJournalError("issuer journal association UTF-8 is invalid") from exc
        elif index in (13, 14, 15):
            if size != (20 if index == 13 else 8):
                _fail("issuer journal association integer is not fixed-width")
            fields.append(int.from_bytes(field, "big"))
        else:
            fields.append(field)
    if offset != len(raw):
        _fail("issuer journal association has trailing bytes")
    result, canonical = _association(tuple(fields), work)
    if canonical != raw:
        _fail("issuer journal association is not canonical")
    return result


def _slot(association, work):
    fields = tuple(value.encode("utf-8") for value in association[:3])
    raw = _SLOT_DOMAIN + b"".join(len(value).to_bytes(4, "big") + value for value in fields)
    return _hash(raw, work)


def _name(sequence, kind, slot):
    return f"{sequence:08d}-{kind}-" + slot[7:]


def _parse_name(name):
    if type(name) is not str or re.fullmatch(r"[0-9]{8}-[co]-[0-9a-f]{64}", name) is None:
        _fail("issuer journal contains an unknown or temporary name")
    sequence = int(name[:8])
    _integer(sequence, 1, MAX_RECORDS)
    return sequence, name[9], "sha256:" + name[11:]


def _decode(raw, work):
    if type(raw) is not bytes or not 81 <= len(raw) <= MAX_RECORD_BYTES:
        _fail("issuer journal record exceeds its fixed frame")
    if raw[:8] not in (_CLAIM_MAGIC, _COMPLETE_MAGIC):
        _fail("issuer journal record has an unknown schema")
    work.charge(input_bytes=len(raw))
    sequence = int.from_bytes(raw[8:16], "big")
    _integer(sequence, 1, MAX_RECORDS)
    previous = None if raw[16:48] == _ZERO else "sha256:" + raw[16:48].hex()
    slot = "sha256:" + raw[48:80].hex()
    if raw[:8] == _CLAIM_MAGIC:
        association = _decode_association(raw[80:], work)
        if _slot(association, work) != slot:
            _fail("issuer journal claim differs from its nonce slot")
        return sequence, "c", previous, slot, association
    if not 1 <= len(raw) - 112 <= MAX_CERTIFICATE_BYTES:
        _fail("issuer journal certificate record has an invalid length")
    return sequence, "o", previous, slot, ("sha256:" + raw[80:112].hex(), raw[112:])


@dataclass(frozen=True, slots=True)
class _IssuerClaim:
    state: str
    association: tuple
    serial_number: int
    not_before_epoch_seconds: int
    not_after_epoch_seconds: int
    certificate_bytes: bytes | None


class WorkloadIdentityIssuerJournal:
    """One source owner over a borrowed, root-startup-owned singleton lease."""

    __slots__ = ("_material", "_work", "_base", "_configuration", "_pid",
        "_directory_fd", "_closed", "_io", "_stamp_value", "_records",
        "_slots", "_serials", "_pending", "_head", "_used_bytes", "_pin")

    def __init__(self, *, material, directory_fd, work, current, maximum_original_bytes):
        from serverware import workload_identity_issuer_bootstrap as bootstrap

        if type(self) is not WorkloadIdentityIssuerJournal or type(material) is not bootstrap._IssuerMaterial:
            _fail("issuer journal requires the actual admitted bootstrap material")
        if type(work) is not _ValidationWork or not callable(current):
            _fail("issuer journal requires original work and current guard")
        _integer(directory_fd, 0, 2**31 - 1)
        self._material, self._work, self._base = material, work, current
        self._configuration = tuple(getattr(material, field) for field in _MATERIAL_FIELDS)
        namespace, device, inode, uid, gid, quota, records, checkpoint = self._configuration
        if type(namespace) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", namespace) is None:
            _fail("issuer journal namespace is not canonical")
        for value, minimum, maximum in ((device, 0, 2**64 - 1), (inode, 1, 2**64 - 1),
                (quota, 4096, MAX_BYTES), (records, 2, MAX_RECORDS)):
            _integer(value, minimum, maximum)
        if uid != ISSUER_UID or gid != ISSUER_GID or type(uid) is not int or type(gid) is not int or records % 2:
            _fail("issuer journal owner or record quota is not the fixed profile")
        if type(checkpoint) is not tuple or len(checkpoint) != 2:
            _fail("issuer journal checkpoint is not a fixed pair")
        _integer(checkpoint[0], 0, records)
        if checkpoint[0] == 0:
            if checkpoint[1] is not None:
                _fail("empty issuer checkpoint must have no head")
        else:
            _digest_value(checkpoint[1])
        self._pid, self._directory_fd, self._closed = os.getpid(), directory_fd, False
        self._pin = (material, work, current, self._configuration, self._pid, directory_fd)
        self._io, self._stamp_value = None, None
        self._records, self._slots, self._serials, self._pending = {}, {}, set(), {}
        self._head, self._used_bytes = None, 0
        self._capacity(maximum_original_bytes)
        guard = self._guard(work, current)
        try:
            self._directory(guard)
            self._io = self._native(guard, lambda: WitnessJournalIO(directory_fd,
                maximum_record_bytes=MAX_RECORD_BYTES))
            self._stamp_value = self._stamp(guard)

            def scan():
                before = self._stamp(guard)
                inventory, total = self._inventory(guard)
                # Actual whole-scan work is refused before the first body;
                # bodies are then released one at a time, not retained wholesale.
                if 16 * total + MAX_OPERATION_RESERVATION_BYTES > work.limits.max_input_bytes - work.input_bytes:
                    _fail("issuer journal scan exceeds remaining original work")
                checkpoint_seen = checkpoint[0] == 0
                for name in sorted(inventory):
                    raw, identity = self._read(name, guard, synchronize=True)
                    if identity != inventory[name]:
                        _fail("issuer journal changed during startup scan")
                    sequence, kind, previous, slot, value = _decode(raw, work)
                    if (sequence != len(self._records) + 1 or previous != self._head
                            or name != _name(sequence, kind, slot)):
                        _fail("issuer journal chain is not exact and contiguous")
                    digest = _hash(raw, work)
                    self._adopt(name, digest, identity, kind, slot, value)
                    if sequence == checkpoint[0]:
                        if digest != checkpoint[1]:
                            _fail("issuer journal differs from its minimum checkpoint")
                        checkpoint_seen = True
                if not checkpoint_seen or self._stamp(guard) != before:
                    _fail("issuer journal is below its checkpoint or changed during scan")
                self._reserved_quota()
                self._compare_inventory(inventory)
                return before

            self._stamp_value = self._io.recover(scan)
            guard()
        except BaseException:
            self.close()
            raise

    def _capacity(self, maximum):
        _integer(maximum, 1, MAX_OPERATION_RESERVATION_BYTES)
        # Metadata for every maximum record plus one selected original's
        # frame/codec/publication/readback captures. Parent cold graphs are
        # separately reserved by the actual service before calling this owner.
        required = self._configuration[6] * 1024 + 8 * MAX_RECORD_BYTES + 8 * MAX_CLAIM_BYTES + 64 * 1024
        if required > maximum:
            _fail("issuer journal exceeds its supplied representation slice")

    def _guard(self, work, current):
        if work is not self._work or type(work) is not _ValidationWork or not callable(current):
            _fail("issuer journal cannot replace its original work or guard")

        def live():
            if (type(self) is not WorkloadIdentityIssuerJournal
                    or self._material is not self._pin[0] or self._work is not self._pin[1]
                    or self._base is not self._pin[2] or self._configuration is not self._pin[3]
                    or (self._pid, self._directory_fd) != self._pin[4:]
                    or os.getpid() != self._pid or self._closed
                    or (os.geteuid(), os.getegid()) != (ISSUER_UID, ISSUER_GID)
                    or tuple(getattr(self._material, field) for field in _MATERIAL_FIELDS) != self._configuration):
                _fail("issuer journal source owner or cold binding changed")
            self._base()
            if current is not self._base:
                current()
        return live

    def _native(self, current, callback):
        current()
        self._work.charge(input_bytes=1)
        limits, metrics = self._work.limits, self._work.metrics
        ceiling = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
        try:
            return callback()
        finally:
            if (self._work.limits is not limits or self._work.metrics != metrics
                    or (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) != ceiling):
                _fail("issuer journal native operation changed original work")
            current()

    def _resource(self, current, callback, cleanup):
        current()
        self._work.charge(input_bytes=1)
        limits, metrics = self._work.limits, self._work.metrics
        ceiling = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
        result = callback()
        try:
            if (self._work.limits is not limits or self._work.metrics != metrics
                    or (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) != ceiling):
                _fail("issuer journal resource operation changed original work")
            current()
            return result
        except BaseException:
            cleanup(result)
            raise

    def _directory(self, current):
        metadata = self._native(current, lambda: os.fstat(self._directory_fd))
        if (not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_nlink < 1 or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid)
                != self._configuration[1:5]):
            _fail("issuer journal directory differs from its admitted identity")
        return metadata

    def _stamp(self, current):
        metadata = self._directory(current)
        return metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns

    def _file_identity(self, metadata, name):
        _sequence, kind, _slot_value = _parse_name(name)
        maximum = MAX_CLAIM_BYTES if kind == "c" else MAX_RECORD_BYTES
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_nlink != 1 or metadata.st_dev != self._configuration[1]
                or (metadata.st_uid, metadata.st_gid) != (ISSUER_UID, ISSUER_GID)
                or not 81 <= metadata.st_size <= maximum):
            _fail("issuer journal record metadata is not fixed private immutable material")
        return _identity(metadata)

    def _inventory(self, current):
        result, total = {}, 0
        iterator = self._resource(current, lambda: os.scandir(self._directory_fd), lambda item: item.close())
        with iterator:
            while True:
                entry = self._native(current, lambda: next(iterator, None))
                if entry is None:
                    break
                if len(result) >= self._configuration[6]:
                    _fail("issuer journal record quota is exceeded")
                name = entry.name
                _parse_name(name)
                self._work.charge(input_bytes=1024)
                if name in result:
                    _fail("issuer journal has a duplicate name")
                metadata = self._native(current, lambda: os.stat(name,
                    dir_fd=self._directory_fd, follow_symlinks=False))
                result[name] = self._file_identity(metadata, name)
                total += metadata.st_size
                if total > self._configuration[5]:
                    _fail("issuer journal byte quota is exceeded")
        current()
        return result, total

    def _compare_inventory(self, inventory):
        if len(inventory) != len(self._records):
            _fail("issuer journal acquired or lost a record")
        for name, identity in inventory.items():
            if name not in self._records or identity != self._records[name][1]:
                _fail("issuer journal retained record identity changed")

    def _continuity(self, current):
        self._io.require_ready()
        if self._stamp(current) != self._stamp_value:
            _fail("issuer journal directory changed outside this source owner")
        inventory, total = self._inventory(current)
        self._compare_inventory(inventory)
        if total != self._used_bytes or self._stamp(current) != self._stamp_value:
            _fail("issuer journal changed during continuity checks")

    def _read(self, name, current, *, synchronize=False):
        descriptor = self._resource(current, lambda: os.open(name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=self._directory_fd), os.close)
        try:
            before = self._native(current, lambda: os.fstat(descriptor))
            identity = self._file_identity(before, name)
            self._work.charge(input_bytes=2 * before.st_size)
            result = bytearray()
            while len(result) < before.st_size:
                part = self._native(current, lambda: os.read(descriptor,
                    min(64 * 1024, before.st_size - len(result))))
                if not part:
                    _fail("issuer journal record was truncated")
                result.extend(part)
            if self._native(current, lambda: os.read(descriptor, 1)):
                _fail("issuer journal record grew while reading")
            if synchronize:
                self._native(current, lambda: os.fsync(descriptor))
            after = self._native(current, lambda: os.fstat(descriptor))
            named = self._native(current, lambda: os.stat(name,
                dir_fd=self._directory_fd, follow_symlinks=False))
            if identity != _identity(after) or identity != _identity(named):
                _fail("issuer journal record changed during exact readback")
            return bytes(result), identity
        finally:
            try:
                current()
            finally:
                os.close(descriptor)
            current()

    def _reserved_quota(self, *, extra_claim=0):
        pending = sum(1 for _claim, complete in self._slots.values() if complete is None)
        if (len(self._records) + pending + (2 if extra_claim else 0) > self._configuration[6]
                or self._used_bytes + pending * MAX_RECORD_BYTES
                    + (extra_claim + MAX_RECORD_BYTES if extra_claim else 0) > self._configuration[5]):
            _fail("issuer journal cannot retain every claimed certificate within quota")

    def _adopt(self, name, digest, identity, kind, slot, value):
        if kind == "c":
            if value[0] != self._configuration[0] or slot in self._slots:
                _fail("issuer journal claim changes namespace or reuses a nonce")
            serial = value[12], value[13]
            if serial in self._serials:
                _fail("issuer journal issuer serial already belongs to another slot")
            self._serials.add(serial)
            self._slots[slot] = name, None
        else:
            if slot not in self._slots or self._slots[slot][1] is not None:
                _fail("issuer journal completion lacks one exact claim")
            claim_name = self._slots[slot][0]
            if value[0] != self._records[claim_name][0]:
                _fail("issuer journal completion changes its claim association")
            self._slots[slot] = claim_name, name
        self._records[name] = digest, identity
        self._used_bytes += identity[6]
        self._head = digest

    def _publish(self, kind, slot, payload, current):
        self._continuity(current)
        sequence = len(self._records) + 1
        magic = _CLAIM_MAGIC if kind == "c" else _COMPLETE_MAGIC
        previous = _ZERO if self._head is None else bytes.fromhex(self._head[7:])
        size = 80 + len(payload)
        if size > (MAX_CLAIM_BYTES if kind == "c" else MAX_RECORD_BYTES):
            _fail("issuer journal publication exceeds its fixed bound")
        self._work.charge(input_bytes=3 * size + 256)
        raw = magic + sequence.to_bytes(8, "big") + previous + bytes.fromhex(slot[7:]) + payload
        name = _name(sequence, kind, slot)
        # This fixed primitive invokes the inherited guard around each native
        # step. It is not wrapped in a no-work-mutation callback: that guard
        # genuinely consumes the service's original work ledger.
        self._io.publish("pending-" + name, name, raw, _current=current)
        observed, identity = self._read(name, current)
        if observed != raw:
            _fail("issuer journal publication differs from durable readback")
        digest = _hash(observed, self._work)
        decoded = _decode(observed, self._work)
        inventory, total = self._inventory(current)
        if name not in inventory or inventory[name] != identity:
            _fail("issuer journal publication lacks its exact named file")
        old = dict(inventory)
        del old[name]
        self._compare_inventory(old)
        if total != self._used_bytes + len(raw):
            _fail("issuer journal publication changed unrelated retained bytes")
        self._adopt(name, digest, identity, kind, slot, decoded[4])
        self._stamp_value = self._stamp(current)
        self._continuity(current)
        return name, digest

    def _selected(self, name, current):
        raw, identity = self._read(name, current)
        digest = _hash(raw, self._work)
        if (digest, identity) != self._records[name]:
            _fail("issuer journal selected record differs from its retained identity")
        return _decode(raw, self._work)[4]

    def claim(self, *, association, work, current, maximum_original_bytes):
        self._capacity(maximum_original_bytes)
        guard = self._guard(work, current)
        guard()
        with self._io.ready():
            try:
                held, encoded = _association(association, work)
                if held[0] != self._configuration[0]:
                    _fail("issuer journal claim changes the configured namespace")
                slot = _slot(held, work)
                self._continuity(guard)
                if slot in self._slots:
                    # Re-entry never rehabilitates an earlier new-receipt lease.
                    self._pending.pop(slot, None)
                    claim_name, complete_name = self._slots[slot]
                    retained = self._selected(claim_name, guard)
                    work.charge(input_bytes=2 * len(encoded))
                    if retained != held:
                        _fail("issuer journal refuses a changed nonce association")
                    certificate = None
                    state = "unknown"
                    if complete_name is not None:
                        claim_digest, certificate = self._selected(complete_name, guard)
                        if claim_digest != self._records[claim_name][0]:
                            _fail("issuer journal complete result changes its original claim")
                        state = "complete"
                    self._continuity(guard)
                    guard()
                    return _IssuerClaim(state, held, held[13], held[14], held[15], certificate)
                if (held[12], held[13]) in self._serials:
                    _fail("issuer journal refuses a repeated issuer serial")
                self._reserved_quota(extra_claim=80 + len(encoded))
                self._publish("c", slot, encoded, guard)
                result = _IssuerClaim("new", held, held[13], held[14], held[15], None)
                self._pending[slot] = result, encoded
                guard()
                return result
            except BaseException:
                self._io.poison()
                raise

    def complete(self, *, claim, certificate_bytes, work, current, maximum_original_bytes):
        self._capacity(maximum_original_bytes)
        guard = self._guard(work, current)
        guard()
        with self._io.ready():
            try:
                if type(claim) is not _IssuerClaim or claim.state != "new":
                    _fail("issuer journal completion requires its same-handle new claim")
                held, encoded = _association(claim.association, work)
                slot = _slot(held, work)
                pending = self._pending.pop(slot, None)
                if (pending is None or pending[0] is not claim or pending[1] != encoded
                        or claim.certificate_bytes is not None or claim.serial_number != held[13]
                        or claim.not_before_epoch_seconds != held[14]
                        or claim.not_after_epoch_seconds != held[15]):
                    _fail("issuer journal new claim is spent or changed")
                if type(certificate_bytes) is not bytes or not 1 <= len(certificate_bytes) <= MAX_CERTIFICATE_BYTES:
                    _fail("issuer journal certificate original exceeds its bound")
                self._continuity(guard)
                claim_name, complete_name = self._slots[slot]
                if complete_name is not None or self._selected(claim_name, guard) != held:
                    _fail("issuer journal completion no longer matches its one claim")
                work.charge(input_bytes=2 * len(certificate_bytes) + 32)
                payload = bytes.fromhex(self._records[claim_name][0][7:]) + certificate_bytes
                complete_name, _digest = self._publish("o", slot, payload, guard)
                _claim_digest, retained = self._selected(complete_name, guard)
                if retained != certificate_bytes:
                    _fail("issuer journal completed certificate readback differs")
                self._continuity(guard)
                guard()
                return retained
            except BaseException:
                self._io.poison()
                raise

    def close(self):
        """Poison only; root startup owns the borrowed descriptor and flock."""
        if os.getpid() != self._pid:
            _fail("forked process cannot close the issuer journal")
        self._closed = True
        if self._io is not None:
            self._io.poison()
        self._pending.clear()
