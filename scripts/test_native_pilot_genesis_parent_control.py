#!/usr/bin/env python3
"""Pure wire/ELF controls only: no native process, protected input or owner."""
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from catchplate import custody_generation_grants as codec
from catchplate import native_pilot_genesis_parent_control as control
from catchplate import native_pilot_genesis_parent_control_io as io


def elf(kinds=(1,)):
    raw = bytearray(64 + 56 * len(kinds) + 32)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    for a, b, value in ((16, 18, 2), (18, 20, 62), (20, 24, 1),
                        (32, 40, 64), (54, 56, 56), (56, 58, len(kinds))):
        raw[a:b] = value.to_bytes(b - a, "little")
    for index, kind in enumerate(kinds):
        start = 64 + 56 * index
        raw[start:start + 4] = kind.to_bytes(4, "little")
        if kind == 2:
            raw[start + 8:start + 16] = (len(raw) - 32).to_bytes(8, "little")
            raw[start + 32:start + 40] = (32).to_bytes(8, "little")
    return raw


def frame():
    # Deliberately NOT an authenticated fixture. Only the private framing
    # guard is tested; finish also requires the real fixed native execution.
    scope = {"issuedAtBoottimeNanos": 10, "expiresAtBoottimeNanos": 20,
             "timeNamespaceInode": (1 << 64) - 1}
    value = {"completion": {"apiVersion": "catchplate.nativePublicationGenesisCompletion/v1",
        "prepared": {"core": {"genesis": {"scope": scope}}}, "stored": {},
        "receiptOriginal": "{}", "completedAtBoottimeNanos": 11, "signature": "unverified"},
        "durable": {"completedAtBoottimeNanos": 12}, "current": {"completedAtBoottimeNanos": 13}}
    return scope, value


class Controls(unittest.TestCase):
    def test_independent_control_pins_are_closed(self):
        value = {"apiVersion": control.CONTROL_API,
            **{key: "sha256:" + "1" * 64 for key in
               ("controllerExecutableSha256", "configurationSha256", "precreationSha256")}}
        self.assertEqual(control._control(codec.canonical(value)), value)
        for mutation in ({"executablePath": "/another/executable"}, {"apiVersion": "old"},
                         {"controllerExecutableSha256": "sha256:" + "0" * 64}):
            with self.assertRaises(ValueError):
                control._control(codec.canonical(value | mutation))

    def test_static_elf_exact_native_architecture(self):
        raw = elf()
        io.require_static_elf(bytes(raw))
        raw[16:18] = (3).to_bytes(2, "little")
        io.require_static_elf(bytes(raw))
        for at, value in ((4, 1), (5, 2), (18, 183), (20, 2)):
            bad = raw.copy()
            bad[at] = value
            with self.assertRaises(ValueError):
                io.require_static_elf(bytes(bad))

    def test_no_interpreter_or_needed_shared_library(self):
        with self.assertRaises(ValueError):
            io.require_static_elf(bytes(elf((1, 3))))
        raw = elf((1, 2))
        io.require_static_elf(bytes(raw))  # Static PIE without DT_NEEDED.
        raw[-32:-24] = (1).to_bytes(8, "little")
        with self.assertRaises(ValueError):
            io.require_static_elf(bytes(raw))

    def test_elf_table_dynamic_bounds_and_load_required(self):
        with self.assertRaises(ValueError):
            io.require_static_elf(bytes(elf((0,))))
        for a, b, value in ((32, 40, 10000), (54, 56, 55), (56, 58, 0), (56, 58, 257)):
            raw = elf()
            raw[a:b] = value.to_bytes(b - a, "little")
            with self.assertRaises(ValueError):
                io.require_static_elf(bytes(raw))
        raw = elf((1, 2))
        raw[152:160] = (31).to_bytes(8, "little")
        with self.assertRaises(ValueError):
            io.require_static_elf(bytes(raw))

    def test_bundle_framing_preserves_native_u64_and_exact_scope(self):
        scope, value = frame()
        raw = codec.canonical(value)
        self.assertEqual(control._bundle(raw, scope), value)
        with self.assertRaises(ValueError):
            control._bundle(raw, scope | {"timeNamespaceInode": (1 << 64) - 2})

    def test_bundle_rejects_extra_truncated_noncanonical_or_bad_order(self):
        scope, value = frame()
        raw = codec.canonical(value)
        for bad in (raw[:-1], raw + b"\n", codec.canonical(value | {"ready": True})):
            with self.assertRaises(ValueError):
                control._bundle(bad, scope)
        for completed in (9, 20):
            bad = copy.deepcopy(value)
            bad["completion"]["completedAtBoottimeNanos"] = completed
            with self.assertRaises(ValueError):
                control._bundle(codec.canonical(bad), scope)

    def test_kernel_credentials_keep_unsigned_uid_gid(self):
        actual = (123, (1 << 32) - 2, (1 << 32) - 3)
        self.assertEqual(io._UCRED.unpack(io._UCRED.pack(*actual)), actual)


if __name__ == "__main__":
    unittest.main()
