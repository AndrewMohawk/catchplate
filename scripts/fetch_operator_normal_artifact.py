#!/usr/bin/env python3
"""Fetch one trusted normal build for the same compiler inputs, not app commit.

Hosted setup by default; --local-operator explicitly admits the canonical clean
main checkout and a fresh output under an owner-only local NVMe job directory.
No build, execution, provider access or automatic fallback. Local credentials
come from the existing GitHub CLI login, in memory only. The GitHub token is
used only with api.github.com, never the signed download URL.
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
LOCAL_SOURCE = Path("/home/catchplate/serverware")
LOCAL_OUTPUT_ROOT = Path("/srv/catchplate-fast/tmp")


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


def validate_invocation(*, local_operator, environment, platform, uid, euid, source, run_id):
    require(type(local_operator) is bool and platform == "linux" and uid == euid != 0
        and type(run_id) is str and re.fullmatch(r"[1-9][0-9]{0,18}", run_id))
    if local_operator:
        require(source == LOCAL_SOURCE and environment.get("GITHUB_ACTIONS") in (None, ""))
    else:
        require(environment.get("GITHUB_ACTIONS") == "true"
            and environment.get("GITHUB_REPOSITORY") == REPOSITORY)


def validate_local_output_shape(output):
    require(output.is_absolute() and output.name == "serverware-normal-proxy"
        and output.parent.parent == LOCAL_OUTPUT_ROOT
        and re.fullmatch(r"serverware-normal-artifact\.[A-Za-z0-9]{6,32}", output.parent.name))


def validate_private_directory(info, uid):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid
        and stat.S_IMODE(info.st_mode) == 0o700)


def validate_output(output, *, local_operator, environment):
    require(output.is_absolute() and output.name == "serverware-normal-proxy"
        and not output.exists() and not output.is_symlink())
    if local_operator:
        validate_local_output_shape(output)
        require(output.parent.resolve(strict=True) == output.parent)
        validate_private_directory(output.parent.lstat(), os.getuid())
    else:
        require(output.parent.resolve() == Path(environment["RUNNER_TEMP"]).resolve())


def validate_local_checkout(current, branch, origin, status):
    require(type(current) is str and re.fullmatch(r"[0-9a-f]{40}", current)
        and branch == b"refs/heads/main\n"
        and origin == ("https://github.com/" + REPOSITORY + ".git\n").encode("ascii")
        and status == b"")


def validate_remote_main(reference, current):
    require(type(reference) is dict and reference.get("ref") == "refs/heads/main"
        and type(reference.get("object")) is dict and reference["object"].get("type") == "commit"
        and type(current) is str and re.fullmatch(r"[0-9a-f]{40}", current)
        and reference["object"].get("sha") == current)


def local_credential_environment(environment):
    # Do not inherit ambient token, debug, proxy or GitHub CLI host/config
    # overrides. Select only the operator's existing normal github.com login.
    require(environment.get("HOME") == str(LOCAL_SOURCE.parent)
        and not environment.get("GH_CONFIG_DIR"))
    return {"HOME": environment["HOME"], "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
        "GH_HOST": "github.com", "GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0"}


def local_token(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 8192)
    value = raw.removesuffix(b"\n")
    require(re.fullmatch(rb"[A-Za-z0-9_]+", value))
    return value.decode("ascii")


def read_local_token(environment):
    result = subprocess.run(["/usr/bin/gh", "auth", "token", "--hostname", "github.com"],
        env=local_credential_environment(environment), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=False)
    require(result.returncode == 0)
    return local_token(result.stdout)


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
    def __init__(self, token, *, local_operator=False):
        require(type(token) is str and token and "\n" not in token and "\r" not in token)
        require(type(local_operator) is bool)
        self.token = token
        self.user_agent = ("Serverware-local-normal-artifact/1" if local_operator
            else "Serverware-hosted-normal-artifact/1")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, limit=JSON_LIMIT, *, archive=False):
        require(path.startswith("/") and not path.startswith("//"))
        request = urllib.request.Request(API + path, headers={"Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": self.user_agent})
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
                headers={"User-Agent": self.user_agent}), timeout=20)
        with response:
            require(response.status == 200)
            raw = response.read(limit + 1)
            require(len(raw) <= limit)
            return raw

    def json(self, path):
        return document(self.request(path))


def selection_receipt(receipt, run, artifact, original, current, *, local_operator):
    selection = {"schema":"serverware.selectedNormalRust/v1", "ok":True, "appCommit":current,
        "buildCommit":receipt["sourceRevision"], "buildRunId":run["id"], "buildRunAttempt":run["run_attempt"],
        "artifactId":artifact["id"], "artifactZipSha256":artifact["digest"].removeprefix("sha256:"),
        "receiptSha256":hashlib.sha256(original).hexdigest(),
        "buildInputIdentity":receipt["buildInputIdentity"], "binarySha256":receipt["binary"]["sha256"],
        "binaryBytes":receipt["binary"]["bytes"], "reusedArtifact":True, "compiledInThisRun":False,
        "executed":False, "deployed":False}
    if local_operator:
        selection["consumer"] = {"mode":"local-operator", "githubActions":False,
            "sourceBranch":"main", "remoteMainCommit":current}
    return selection


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--local-operator", action="store_true", help="explicit local operator download only; "
        "requires clean canonical main and an existing mode-0700 NVMe serverware-normal-artifact.<suffix> parent")
    return parser.parse_args(argv)


def main():
    args = parse_arguments()
    source = Path(__file__).resolve().parents[1]
    validate_invocation(local_operator=args.local_operator, environment=os.environ,
        platform=sys.platform, uid=os.getuid(), euid=os.geteuid(), source=source, run_id=args.run_id)
    output = args.output
    validate_output(output, local_operator=args.local_operator, environment=os.environ)
    os.umask(0o077)
    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(source), *arguments], timeout=30,
            env={"PATH":"/usr/bin:/bin", "LANG":"C.UTF-8"}, stderr=subprocess.DEVNULL)
    current = git("rev-parse", "HEAD").decode().strip()
    def check_source():
        require(git("rev-parse", "HEAD").decode().strip() == current)
        status = git("status", "--porcelain=v1", "--untracked-files=all")
        if args.local_operator:
            validate_local_checkout(current, git("symbolic-ref", "--quiet", "HEAD"),
                git("remote", "get-url", "origin"), status)
        else:
            require(current == os.environ["GITHUB_SHA"] and not status)
    check_source()
    specification = importlib.util.spec_from_file_location("normal_runner", source / "scripts/run_native_jit_review_rust.py")
    producer = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(producer)
    identity = producer.normal_input_identity(source,
        producer.normal_git_files(git("ls-tree", "-rz", "--full-tree", current)))
    github = GitHub(read_local_token(os.environ) if args.local_operator else os.environ["GH_TOKEN"],
        local_operator=args.local_operator)
    if args.local_operator:
        validate_remote_main(github.json("/git/ref/heads/main"), current)
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
            "workflowPath":producer.NORMAL_WORKFLOW, "job":"normal-proxy"})
    if args.local_operator:
        validate_remote_main(github.json("/git/ref/heads/main"), current)
    check_source()
    selection = selection_receipt(receipt, run, artifact, files["normal.json"], current,
        local_operator=args.local_operator)
    validate_output(output, local_operator=args.local_operator, environment=os.environ)
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
