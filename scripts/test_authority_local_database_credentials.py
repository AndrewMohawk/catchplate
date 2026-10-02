#!/usr/bin/env python3
"""Actual synthetic certificate/file controls; no PostgreSQL admission claim."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import authority_local_database_credentials as local
from scripts.authority import local_database_credentials as cli


def selection(*, include_reader=False, now_unix_ns=None):
    now = (int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp()) * 10**9
           if now_unix_ns is None else now_unix_ns)
    selected = dict(schema=local.APPROVAL_SCHEMA, database="serverware", databaseRoles=dict(
        metadata="pilot_metadata_runtime", audit="pilot_audit_runtime",
        verifier="pilot_authority_verifier", executor="pilot_authority_executor"),
        includeAuditReader=include_reader, host="database.serverware.local", port=5432,
        clientNetwork="192.0.2.0/24", intendedOwners={}, outputDirectory=dict(device=1, inode=2),
        bootIdDigest="sha256:" + "a"*64, issuedAtBoottimeNs=100,
        deadlineBoottimeNs=60_000_000_100, issuedAtUnixNanos=now,
        expiresAtUnixNanos=now+60_000_000_000, certificateNotBefore=now//10**9-60,
        certificateNotAfter=now//10**9+86400)
    selected["intendedOwners"] = {purpose:dict(uid=65000+index, gid=65000+index)
        for index, purpose in enumerate(["server", *local.role_roster(selected)])}
    for purpose, uid in (("planner", 65518), ("planner-writer", 65519), ("verifier", 65520),
                         ("issuer", 65521), ("executor", 65522)):
        selected["intendedOwners"][purpose] = dict(uid=uid, gid=uid)
    return selected, now


def fixture(*, now_unix_ns=None):
    selected, now = selection(now_unix_ns=now_unix_ns)
    raw = local.canonical(selected)
    selected = local.approval(raw)
    values = local.material(selected, approval_sha256=local.sha(raw), issued_at_unix_ns=now, check=lambda:None)
    return dict(selected=selected, material=values, now_unix_ns=now,
        originals={purpose:values[purpose+".issuance.json"] for purpose in local.role_roster(selected)})


def filesystem_scenario():
    import fcntl
    import stat
    import time
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    from serverware.authority_witness_journal import JournalConflict
    selected, _ = selection()
    with tempfile.TemporaryDirectory(prefix="local-database-issuer-") as path:
        os.chmod(path, 0o700)
        directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        source = os.memfd_create("synthetic-local-database-approval", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        try:
            info = os.fstat(directory)
            selected["outputDirectory"] = dict(device=info.st_dev, inode=info.st_ino)
            selected["bootIdDigest"] = local._boot()
            now, boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            selected.update(issuedAtUnixNanos=now, expiresAtUnixNanos=now+30_000_000_000,
                issuedAtBoottimeNs=boot, deadlineBoottimeNs=boot+30_000_000_000,
                certificateNotBefore=now//10**9-60, certificateNotAfter=now//10**9+86400)
            raw = local.canonical(selected)
            os.write(source, raw)
            os.fchmod(source, 0o400)
            fcntl.fcntl(source, fcntl.F_ADD_SEALS, local.io.SEALS)
            owner = local.LocalDatabaseCredentialIssuer(approval_fd=source, approval_sha256=local.sha(raw), output_directory_fd=directory)
            try: owner.run(); owner.check()
            finally: owner.close()
            names = os.listdir(directory)
            assert len(names) == 55 and "inventory.json" in names and not any(name.startswith(".") for name in names)
            assert "pg_hba.fragment" in names and (Path(path)/"pg_hba.fragment").read_bytes().startswith(b"hostssl ")
            inventory = local.document((Path(path)/"inventory.json").read_bytes(), local.MAX_DOCUMENT)
            for name, row in inventory["files"].items():
                original = (Path(path)/name).read_bytes()
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink) == (0, 0, 0o400, 1)
                assert (row["sha256"], row["bytes"]) == (local.sha(original), len(original))
            for purpose in local.role_roster(selected):
                key = serialization.load_pem_private_key((Path(path)/(purpose+".key.pem")).read_bytes(), password=None)
                cert = x509.load_pem_x509_certificate((Path(path)/(purpose+".cert.pem")).read_bytes())
                assert local._public_key(key.public_key()) == local._public_key(cert.public_key())
            try:
                local.LocalDatabaseCredentialIssuer(approval_fd=source, approval_sha256=local.sha(raw), output_directory_fd=directory)
            except ValueError: pass
            else: raise AssertionError("populated staging directory was accepted")
            held = os.open("inventory.json", os.O_RDONLY, dir_fd=directory)
            try:
                try: local._rename_noreplace(directory, "server.cert.pem", "inventory.json")
                except JournalConflict: pass
                else: raise AssertionError("atomic no-replace replaced inventory")
                assert os.fstat(held).st_ino == os.stat("inventory.json", dir_fd=directory).st_ino
            finally: os.close(held)
        finally:
            os.close(source); os.close(directory)


class LocalDatabaseCredentialControls(unittest.TestCase):
    def test_closed_roster_matches_foundation_and_optional_reader_is_separate(self):
        selected, _ = selection()
        self.assertEqual(len(local.role_roster(selected)), 12)
        self.assertNotIn("serverware_policy_authority_owner", local.role_roster(selected).values())
        from serverware import authority_contract
        self.assertEqual(local.FIXED_ROLES["successor-issuer"], authority_contract.SUCCESSOR_ISSUER_ROLE)
        self.assertEqual(local.FIXED_ROLES["completion-reader"], authority_contract.COMPLETION_READER_ROLE)
        selected["includeAuditReader"] = True
        self.assertEqual(len(local.role_roster(selected)), 13)
        from serverware import authority_local_audit_reader
        self.assertEqual(local.role_roster(selected)["audit-inclusion-reader"], authority_local_audit_reader.ROLE)
        selected["databaseRoles"]["metadata"] = "serverware_policy_authority_owner"
        with self.assertRaises(ValueError): local.role_roster(selected)

    def test_exact_approval_time_network_and_owner_bounds(self):
        selected, _ = selection()
        self.assertEqual(local.approval(local.canonical(selected)), selected)
        for field, value in (("clientNetwork", "0.0.0.0/0"), ("clientNetwork", "192.0.2.1/24"),
                ("host", "db host"), ("port", True), ("deadlineBoottimeNs", 100+local.MAX_OPERATION_NS+1),
                ("certificateNotAfter", selected["certificateNotBefore"]+local.MAX_CERTIFICATE_SECONDS+1), ("extra", True)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                local.approval(local.canonical(dict(selected, **{field:value})))

    def test_real_ca_client_signatures_and_existing_service_identity_fields(self):
        f = fixture()
        for role in ("verifier", "planner", "planner-writer", "issuer", "executor"):
            raw = f["originals"][role]
            identity = local.issuance(raw, purpose=role)
            self.assertEqual(identity["databaseRole"], local.role_roster(f["selected"])[role])
            self.assertEqual(identity["tlsClientDn"], "CN="+identity["databaseRole"])
            self.assertEqual(identity["credentialIssuanceDigest"], local.sha(raw))
            self.assertTrue(identity["tlsClientSerial"].isdigit())
        self.assertEqual(len({local.issuance(raw)["tlsClientSerial"] for raw in f["originals"].values()}), 12)

    def test_rebinding_wrong_ca_and_claimed_installation_refuse(self):
        first, second = fixture(), fixture()
        original = local.document(first["originals"]["issuer"], local.MAX_DOCUMENT)
        wrong_ca = local.document(second["originals"]["issuer"], local.MAX_DOCUMENT)["caCertificateOriginal"]
        for change in (dict(databaseRole="wrong_role"), dict(purpose="executor"), dict(caCertificateOriginal=wrong_ca),
                       dict(claims=dict(local.CLAIMS, credentialInstalled=True)), dict(extra=True)):
            with self.subTest(change=list(change)), self.assertRaises(Exception):
                local.issuance(local.canonical(dict(original, **change)), purpose="issuer")

    def test_verify_full_dsns_and_scoped_hba_do_not_claim_role_grants(self):
        f = fixture()
        from psycopg.conninfo import conninfo_to_dict
        for purpose, role in local.role_roster(f["selected"]).items():
            dsn = conninfo_to_dict(f["material"][purpose+".dsn"].decode("ascii"))
            self.assertEqual(dsn["user"], role)
            self.assertEqual(dsn["sslmode"], "verify-full")
            self.assertEqual(dsn["sslkey"], local.RUNTIME_DIRECTORY+"/"+purpose+"/private-key.pem")
            self.assertNotIn("password", dsn)
        hba = f["material"]["pg_hba.fragment"].decode("ascii")
        self.assertEqual(hba.count(" cert clientname=CN\n"), 12)
        self.assertNotIn(" trust", hba)
        self.assertNotIn("serverware_policy_authority_owner", hba)
        self.assertFalse(local.CLAIMS["databaseSessionObserved"])

    def test_actual_private_staging_readback_and_no_replace(self):
        env = {key:value for key,value in os.environ.items() if not key.startswith("SERVERWARE_")}
        with tempfile.TemporaryDirectory(prefix="local-db-test-data-") as path:
            env.update(SERVERWARE_DATA_DIR=path, SERVERWARE_RELEASE_CHANNEL="dev", SERVERWARE_PROCESS_MODE="metadata-bootstrap")
            program = "import sys; sys.path.insert(0,sys.argv[1]); from scripts.test_authority_local_database_credentials import filesystem_scenario; filesystem_scenario()"
            result = subprocess.run([sys.executable,"-I","-B","-c",program,str(ROOT)], env=env,
                cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_fixed_cli_refuses_aliases_paths_and_nonoffline_modes(self):
        argv = ["--approval-fd", "3", "--approval-sha256", "sha256:"+"a"*64, "--output-directory-fd", "4"]
        self.assertEqual(cli.arguments(argv)["output_directory_fd"], 4)
        for wrong in (argv+["--path", "/tmp"], [*argv[:-1], "3"], [argv[0], "03", *argv[2:]], []):
            with self.assertRaises(ValueError): cli.arguments(wrong)


if __name__ == "__main__": unittest.main()
