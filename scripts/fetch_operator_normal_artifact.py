#!/usr/bin/env python3
"""Fetch one trusted normal build for the same compiler inputs, not app commit.

Hosted setup only. No build, execution, provider access or automatic fallback.
The GitHub token is used only with api.github.com, never the signed download URL.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = "AndrewMohawk/serverware"
API = "https://api.github.com/repos/" + REPOSITORY
ZIP_LIMIT, JSON_LIMIT = 128 * 1024**2, 8 * 1024**2


def require(value):
    if not value:
        raise ValueError("normal artifact refused")


def document(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def validate_run(run, run_id, workflow):
    require(type(run) is dict and run["id"] == run_id and type(run["run_attempt"]) is int
        and 0 < run["run_attempt"] < 2**63 and run["event"] == "workflow_dispatch"
        and run["status"] == "completed" and run["conclusion"] == "success"
        and run["path"] == workflow and run["head_branch"] == "main"
        and re.fullmatch(r"[0-9a-f]{40}", run["head_sha"])
        and run["repository"]["full_name"] == REPOSITORY
        and run["head_repository"]["full_name"] == REPOSITORY)


def select_artifact(payload, run, identity):
    require(type(payload) is dict and type(payload["total_count"]) is int
        and payload["total_count"] == len(payload["artifacts"]) <= 8)
    matches = [row for row in payload["artifacts"]
        if row["name"] == "serverware-normal-proxy-" + identity]
    require(len(matches) == 1)
    row = matches[0]
    require(type(row["id"]) is int and row["id"] > 0 and row["expired"] is False
        and type(row["size_in_bytes"]) is int and 0 < row["size_in_bytes"] <= ZIP_LIMIT
        and re.fullmatch(r"sha256:[0-9a-f]{64}", row["digest"])
        and row["workflow_run"]["id"] == run["id"]
        and row["workflow_run"]["head_sha"] == run["head_sha"]
        and row["workflow_run"]["head_branch"] == "main")
    return row


def archive_files(raw, artifact):
    require(type(raw) is bytes and 0 < len(raw) <= ZIP_LIMIT
        and "sha256:" + hashlib.sha256(raw).hexdigest() == artifact["digest"])
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        rows = archive.infolist()
        require(len(rows) == 2 and {row.filename for row in rows} == {"normal.json", "serverware-decision-gate"})
        result = {}
        for row in rows:
            mode = row.external_attr >> 16
            require(not row.is_dir() and not row.flag_bits & 1
                and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                and 0 < row.file_size <= (JSON_LIMIT if row.filename == "normal.json" else 512 * 1024**2))
            result[row.filename] = archive.read(row)
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, target):
        return None


class GitHub:
    def __init__(self, token):
        require(type(token) is str and token and "\n" not in token and "\r" not in token)
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, limit=JSON_LIMIT, *, archive=False):
        require(path.startswith("/") and not path.startswith("//"))
        request = urllib.request.Request(API + path, headers={"Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Serverware-hosted-normal-artifact/1"})
        try:
            response = self.opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            if not archive or error.code != 302:
                raise
            target = error.headers.get("Location", "")
            error.close()
            parsed = urllib.parse.urlsplit(target)
            require(len(target) <= 8192 and parsed.scheme == "https" and not parsed.username
                and not parsed.password and parsed.port in (None, 443) and not parsed.fragment
                and parsed.hostname is not None and parsed.hostname.endswith((".blob.core.windows.net", ".githubusercontent.com")))
            # Do not carry the GitHub Authorization header to artifact storage.
            response = self.opener.open(urllib.request.Request(target,
                headers={"User-Agent": "Serverware-hosted-normal-artifact/1"}), timeout=20)
        with response:
            require(response.status == 200)
            raw = response.read(limit + 1)
            require(len(raw) <= limit)
            return raw

    def json(self, path):
        return document(self.request(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and sys.platform == "linux" and os.getuid() == os.geteuid() != 0
        and re.fullmatch(r"[1-9][0-9]{0,18}", args.run_id))
    source = Path(__file__).resolve().parents[1]
    output = args.output
    require(output.is_absolute() and output.parent.resolve() == Path(os.environ["RUNNER_TEMP"]).resolve()
        and output.name == "serverware-normal-proxy" and not output.exists() and not output.is_symlink())
    os.umask(0o077)
    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(source), *arguments], timeout=30,
            env={"PATH":"/usr/bin:/bin", "LANG":"C.UTF-8"}, stderr=subprocess.DEVNULL)
    current = git("rev-parse", "HEAD").decode().strip()
    require(current == os.environ["GITHUB_SHA"] and not git("status", "--porcelain=v1", "--untracked-files=all"))
    specification = importlib.util.spec_from_file_location("normal_runner", source / "scripts/run_native_jit_review_rust.py")
    producer = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(producer)
    identity = producer.normal_input_identity(source,
        producer.normal_git_files(git("ls-tree", "-rz", "--full-tree", current)))
    github = GitHub(os.environ["GH_TOKEN"])
    run = github.json("/actions/runs/" + args.run_id)
    validate_run(run, int(args.run_id), producer.NORMAL_WORKFLOW)
    jobs = github.json(f"/actions/runs/{args.run_id}/attempts/{run['run_attempt']}/jobs?per_page=100")
    require(jobs["total_count"] == len(jobs["jobs"]) <= 8)
    normal_jobs = [job for job in jobs["jobs"] if job["name"] == "normal-proxy"]
    require(len(normal_jobs) == 1 and normal_jobs[0]["status"] == "completed"
        and normal_jobs[0]["conclusion"] == "success" and normal_jobs[0]["head_sha"] == run["head_sha"])
    for name in (producer.NORMAL_RUNNER, producer.NORMAL_WORKFLOW):
        entry = github.json("/contents/" + name + "?ref=" + run["head_sha"])
        require(entry["type"] == "file" and entry["encoding"] == "base64" and entry["path"] == name)
        body = base64.b64decode(entry["content"].replace("\n", ""), validate=True)
        require(body == producer.read(source / name)
            and hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest() == entry["sha"])
    artifact = select_artifact(github.json("/actions/runs/" + args.run_id + "/artifacts?per_page=100"),
        run, producer.identity_digest(identity))
    files = archive_files(github.request(f"/actions/artifacts/{artifact['id']}/zip", ZIP_LIMIT, archive=True), artifact)
    receipt = document(files["normal.json"])
    producer.verify_normal_receipt(receipt, files["serverware-decision-gate"], identity)
    require(receipt["sourceRevision"] == run["head_sha"]
        and receipt["runnerSourceSha256"] == producer.sha(source / producer.NORMAL_RUNNER)
        and receipt["github"] == {"repository":REPOSITORY, "runId":run["id"], "runAttempt":run["run_attempt"],
            "workflowPath":producer.NORMAL_WORKFLOW, "job":"normal-proxy"}
        and not git("status", "--porcelain=v1", "--untracked-files=all"))
    selection = {"schema":"serverware.selectedNormalRust/v1", "ok":True, "appCommit":current,
        "buildCommit":receipt["sourceRevision"], "buildRunId":run["id"], "buildRunAttempt":run["run_attempt"],
        "artifactId":artifact["id"], "artifactZipSha256":artifact["digest"].removeprefix("sha256:"),
        "receiptSha256":hashlib.sha256(files["normal.json"]).hexdigest(),
        "buildInputIdentity":receipt["buildInputIdentity"], "binarySha256":receipt["binary"]["sha256"],
        "binaryBytes":receipt["binary"]["bytes"], "reusedArtifact":True, "compiledInThisRun":False,
        "executed":False, "deployed":False}
    output.mkdir(mode=0o700)
    for name, raw in {**files, "selection.json":json.dumps(selection, sort_keys=True).encode()+b"\n"}.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), 0o555 if name == "serverware-decision-gate" else 0o444)
    print(json.dumps(selection, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # HTTP exceptions can contain signed URLs. Never print exception text.
        print(json.dumps({"ok":False, "stage":"normal-artifact-selection", "errorType":type(error).__name__}), flush=True)
        raise SystemExit(1)
