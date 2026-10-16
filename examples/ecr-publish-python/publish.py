#!/usr/bin/env python3
"""Explicit exact-image ECR publication with stock Boto3 and no AWS credentials."""
from contextlib import ExitStack, contextmanager
import argparse
import base64
import hashlib
import importlib.util
from importlib.metadata import version
import json
import logging
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
from urllib.parse import quote
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from serverware import ecr_image_artifact as artifact
from serverware import ecr_image_custody as custody
from serverware import ecr_sdk_protocol as protocol

_spec = importlib.util.spec_from_file_location("serverware_common_client", ROOT / "examples/common-apps/request.py")
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)

SCHEMA = "serverware.awsEcrPublicationClient/v1"
CONTROL_PATH = "/v1/ecr/publications"
PART_BYTES = 4 * 1024 * 1024
CONTROL_RESPONSE_BYTES = 256 * 1024
PINS = {"boto3": "1.43.114", "botocore": "1.43.114", "certifi": "2026.7.22",
    "charset-normalizer": "3.5.2", "idna": "3.20", "jmespath": "1.1.0",
    "python-dateutil": "2.9.0.post0", "requests": "2.34.2", "s3transfer": "0.19.2",
    "six": "1.17.0", "urllib3": "2.8.0"}
CLIENT_ACCESS = "AKIAIOSFODNN7EXAMPLE"
CLIENT_SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
STATES = {"staging", "awaiting_review", "approved", "active", "suspended", "published", "denied", "expired", "failed", "uncertain"}
SCOPE_FIELDS = ("registry_id", "region", "repository_name", "image_tag")
FAILURE = ("ECR client stopped. Inspect the selected publication and Serverware audit log. "
    "A write may have an unknown outcome; nothing was retried. Do not blindly repeat staging, activation or publication.")


class ClientError(ValueError):
    def __init__(self):
        super().__init__(FAILURE)


def require(condition):
    if not condition:
        raise ClientError()


def uuid(value):
    require(type(value) is str and str(UUID(value)) == value and UUID(value).version == 4)
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
    return value


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def fresh(config):
    expiry = config.get("token_expires_at_epoch_ms")
    require(type(expiry) is int and time.time_ns() // 1_000_000 < expiry <= 2**53 - 1)


def load_configuration(path):
    """Read the console download, never an AWS key or arbitrary control endpoint."""
    failed = False
    try:
        path = Path(path).absolute()
        config = common.strict_json(common.read_file(path, 65536).decode("utf-8"))
        require(type(config) is dict and config.get("schema") == SCHEMA
            and config.get("operation_bundle") == "aws_ecr_publish_v1")
        for field in ("application_id", "access_rule_id"):
            uuid(config.get(field))
        digest(config.get("expected_policy_hash"))
        protocol.Scope(config.get("registry_id"), config.get("region"), config.get("repository_name"))
        require(type(config.get("image_tag")) is str
            and re.fullmatch(r"[!-~]{1,300}", config["image_tag"]) is not None)
        require(config.get("proxy_authentication") == "basic_and_bearer_v1"
            and config.get("proxy_username") == config["application_id"])
        token = config.get("proxy_password")
        require(type(token) is str and 1 <= len(token) <= 8192
            and all(33 <= ord(c) <= 126 for c in token))
        proxy = common.https_url(config.get("proxy_url"), origin=True)
        config["proxy_url"] = "https://" + proxy.netloc
        require(config.get("control_api_url") == config["proxy_url"] + CONTROL_PATH)
        for field in ("ca_file", "proxy_ca_file"):
            value = config.get(field)
            if field == "proxy_ca_file" and value is None:
                continue
            require(type(value) is str and 0 < len(value) <= 4096 and not any(ord(c) < 32 for c in value))
            config[field] = str((path.parent / value).resolve())
            common.public_ca(config[field])
        config.setdefault("proxy_ca_file", None)
        config["_proxy_url"] = "https://" + quote(config["proxy_username"], safe="") + ":" + quote(token, safe="") + "@" + proxy.netloc
        fresh(config)
    except Exception:
        failed = True
    if failed:
        raise ClientError()
    return config


def isolate_environment():
    """Call before importing the SDK; no ambient AWS profiles, endpoints or proxy."""
    for name in list(os.environ):
        if name.startswith(("AWS_", "BOTO_")) or name.lower() in {
                "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ssl_cert_file", "ssl_cert_dir",
                "requests_ca_bundle", "curl_ca_bundle", "sslkeylogfile"}:
            os.environ.pop(name, None)
    os.environ.update(AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
        BOTO_CONFIG="/dev/null", AWS_EC2_METADATA_DISABLED="true")
    logging.disable(logging.CRITICAL)


def check_versions():
    require(all(version(package) == expected for package, expected in PINS.items()))


def outer_ca(config):
    from botocore.httpsession import get_cert_path
    return config["proxy_ca_file"] or get_cert_path(True)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ClientError()


class Control:
    """Direct HTTPS to the configured proxy origin, not through a proxy or SSO."""
    def __init__(self, config):
        self.config = config
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile=outer_ca(config))
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())

    def call(self, method, suffix="", body=None, *, binary=False):
        failed = False
        try:
            fresh(self.config)
            require(method in {"GET", "POST"} and type(suffix) is str
                and (suffix == "" or re.fullmatch(r"/[0-9a-f-]{36}(?:/(?:manifest|submit|activate)|/blobs/[0-9a-f]{64}/parts/(?:0|[1-9][0-9]*))?", suffix)))
            require(body is None if method == "GET" else type(body) is bytes and len(body) <= PART_BYTES)
            authorization = base64.b64encode((self.config["proxy_username"] + ":" + self.config["proxy_password"]).encode("ascii")).decode("ascii")
            headers = {"Authorization": "Basic " + authorization, "Accept": "application/json", "Accept-Encoding": "identity"}
            if body is not None:
                headers["Content-Type"] = "application/octet-stream" if binary else "application/json"
            request = Request(self.config["control_api_url"] + suffix, data=body, headers=headers, method=method)
            with self.opener.open(request, timeout=30) as response:
                require(response.status in {200, 201, 202}
                    and response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() == "application/json"
                    and response.headers.get("Content-Encoding", "identity").lower() == "identity")
                raw = response.read(CONTROL_RESPONSE_BYTES + 1)
                require(0 < len(raw) <= CONTROL_RESPONSE_BYTES)
            value = common.strict_json(raw.decode("utf-8"))
            require(type(value) is dict)
        except Exception:
            failed = True
        if failed:
            raise ClientError()
        return value


def publication(value, config, identifier=None, image=None):
    require(type(value) is dict and value.get("schema") == "serverware.ecrPublication/v1"
        and value.get("assurance") == "host-trusted" and value.get("status") in STATES)
    uuid(value.get("id"))
    require(identifier is None or value["id"] == identifier)
    require(value.get("application_id") == config["application_id"]
        and value.get("access_rule_id") == config["access_rule_id"]
        and value.get("policy_hash") == config["expected_policy_hash"]
        and value.get("scope") == {name: config[name] for name in SCOPE_FIELDS})
    digest(value.get("manifest_digest"))
    digest(value.get("artifact_sha256"))
    require(type(value.get("expires_at_epoch_ms")) is int and 0 < value["expires_at_epoch_ms"] <= 2**53 - 1
        and type(value.get("revision")) is int and 0 <= value["revision"] <= 2**53 - 1)
    if image is not None:
        require(value["manifest_digest"] == image.manifest.digest and value["artifact_sha256"] == image.commitment_sha256)
        if value.get("artifact") is not None:
            require(value["artifact"] == image.commitment())
    return value


def summary(value):
    """Only validated metadata; never reflect free-form server error/review text."""
    return {key: value[key] for key in ("id", "status", "assurance", "scope", "manifest_digest", "artifact_sha256", "expires_at_epoch_ms", "revision")}


@contextmanager
def open_stage(path):
    """Reverify a complete private stage and retain immutable bytes for this run."""
    with ExitStack() as stack:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        directory = os.open(path, flags | os.O_DIRECTORY)
        stack.callback(os.close, directory)
        info = os.fstat(directory)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
        require(set(os.listdir(directory)) == {"stage.json", "manifest.json", "artifact.json", "blobs"})
        blob_directory = os.open("blobs", flags | os.O_DIRECTORY, dir_fd=directory)
        stack.callback(os.close, blob_directory)

        def reader(parent, name, maximum):
            stream = os.fdopen(os.open(name, flags | os.O_NONBLOCK, dir_fd=parent), "rb")
            stack.enter_context(stream)
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o600
                and 0 < metadata.st_size <= maximum)
            return stream

        marker = common.strict_json(reader(directory, "stage.json", 4096).read(4097))
        require(type(marker) is dict and set(marker) == {"schema", "artifactSha256", "manifestDigest", "unsigned"}
            and marker["schema"] == "serverware.ecrArtifactStage/v1" and marker["unsigned"] is True)
        manifest = reader(directory, "manifest.json", artifact.MAX_MANIFEST_BYTES).read(artifact.MAX_MANIFEST_BYTES + 1)
        description = artifact.parse_manifest(manifest)
        require(description.manifest.digest == marker["manifestDigest"]
            and set(os.listdir(blob_directory)) == {blob.digest[7:] for blob in description.blobs})
        readers = {blob.digest: reader(blob_directory, blob.digest[7:], blob.size) for blob in description.blobs}
        sealed = stack.enter_context(custody.capture(manifest, readers))
        commitment = reader(directory, "artifact.json", artifact.MAX_MANIFEST_BYTES).read(artifact.MAX_MANIFEST_BYTES + 1)
        require(commitment == encoded(sealed.image.commitment())
            and "sha256:" + hashlib.sha256(commitment).hexdigest() == marker["artifactSha256"]
            and sealed.image.commitment_sha256 == marker["artifactSha256"])
        yield sealed


def stage(config, sealed, control, on_created=lambda value: None):
    image = sealed.image
    value = publication(control.call("POST", body=encoded({
        "application_id": config["application_id"], "access_rule_id": config["access_rule_id"],
        "expected_policy_hash": config["expected_policy_hash"],
        "manifest_digest": image.manifest.digest, "artifact_sha256": image.commitment_sha256})), config, image=image)
    require(value["status"] == "staging")
    identifier = value["id"]
    on_created(summary(value))  # Preserve the exact ID even if later upload fails.
    prefix = "/" + identifier
    publication(control.call("POST", prefix + "/manifest", image.manifest_bytes, binary=True), config, identifier, image)
    for blob in image.blobs:
        for offset in range(0, blob.size, PART_BYTES):
            body = sealed.read_blob(blob.digest, offset, min(PART_BYTES, blob.size - offset))
            publication(control.call("POST", prefix + "/blobs/" + blob.digest[7:] + "/parts/" + str(offset), body, binary=True), config, identifier, image)
    value = publication(control.call("POST", prefix + "/submit", b"{}"), config, identifier, image)
    require(value["status"] == "awaiting_review" and value.get("artifact") == image.commitment())
    return summary(value)


@contextmanager
def sdk_client(config, identifier):
    """Only documented SDK configuration; no event hooks or transport patches."""
    import boto3
    from botocore.config import Config
    check_versions()
    uuid(identifier)
    credentials = {"aws_access_key_id": CLIENT_ACCESS, "aws_secret_access_key": CLIENT_SECRET, "aws_session_token": None}
    client = boto3.Session(region_name=config["region"], **credentials).client("ecr", **credentials,
        region_name=config["region"], endpoint_url="https://api.ecr." + config["region"] + ".amazonaws.com/",
        verify=config["ca_file"], config=Config(signature_version="v4", defaults_mode="legacy",
            retries={"mode": "standard", "total_max_attempts": 1}, connect_timeout=10, read_timeout=30,
            max_pool_connections=1, proxies={"https": config["_proxy_url"]},
            proxies_config={"proxy_ca_bundle": outer_ca(config), "proxy_use_forwarding_for_https": False},
            user_agent_extra="ServerwarePublication/" + identifier, ignore_configured_endpoint_urls=True,
            use_dualstack_endpoint=False, use_fips_endpoint=False))
    try:
        yield client
    finally:
        client.close()


def upload(config, identifier, sealed, client, expires_at):
    """Five ECR actions, one upload at a time, exact bytes, no retries/resume."""
    image, calls = sealed.image, 0
    scope = protocol.Scope(config["registry_id"], config["region"], config["repository_name"])
    deadline = time.monotonic() + min(1800, max(0, (expires_at - time.time_ns() // 1_000_000) / 1000))

    def call(method, action, **fields):
        nonlocal calls
        fresh(config)
        require(calls < 4096 and time.monotonic() < deadline and time.time_ns() // 1_000_000 < expires_at)
        fields = {"registryId": scope.registry_id, "repositoryName": scope.repository_name, **fields}
        wire = dict(fields)
        if "layerPartBlob" in wire:
            wire["layerPartBlob"] = base64.b64encode(wire["layerPartBlob"]).decode("ascii")
        request = protocol.parse_request(scope=scope, action=action, body=encoded(wire))
        calls += 1
        value = getattr(client, method)(**fields)
        require(type(value) is dict and type(value.get("ResponseMetadata")) is dict
            and value["ResponseMetadata"].get("HTTPStatusCode") == 200)
        raw = encoded({key: item for key, item in value.items() if key != "ResponseMetadata"})
        return protocol.parse_response(request, status=200, body=raw)

    ready = set()
    blobs = list(image.blobs)
    for first in range(0, len(blobs), 100):
        batch = blobs[first:first + 100]
        response = call("batch_check_layer_availability", "BatchCheckLayerAvailability", layerDigests=[blob.digest for blob in batch])
        sizes = {blob.digest: blob.size for blob in batch}
        require(all(sizes[name] == size for name, size in response.layer_sizes))
        ready.update(response.available_digests)
    for blob in blobs:
        if blob.digest in ready:
            continue
        response = call("initiate_layer_upload", "InitiateLayerUpload")
        upload_id, part_size = response.upload_id, response.part_size
        for offset in range(0, blob.size, part_size):
            body = sealed.read_blob(blob.digest, offset, min(part_size, blob.size - offset))
            call("upload_layer_part", "UploadLayerPart", uploadId=upload_id, partFirstByte=offset,
                partLastByte=offset + len(body) - 1, layerPartBlob=body)
        call("complete_layer_upload", "CompleteLayerUpload", uploadId=upload_id, layerDigests=[blob.digest])
    response = call("put_image", "PutImage", imageManifest=image.manifest_bytes.decode("utf-8"),
        imageManifestMediaType=image.manifest.media_type, imageTag=config["image_tag"], imageDigest=image.manifest.digest)
    return {"id": identifier, "status": "published", "manifest_digest": response.image_digest,
        "image_tag": response.image_tag, "sdk_calls": calls, "automatic_retries": 0}


def publish(config, identifier, sealed, control, execute_write=False):
    require(execute_write is True)
    uuid(identifier)
    value = publication(control.call("GET", "/" + identifier), config, identifier, sealed.image)
    require(value["status"] == "approved" and value.get("artifact") == sealed.image.commitment()
        and time.time_ns() // 1_000_000 < value["expires_at_epoch_ms"])
    # Build/validate all local SDK prerequisites before consuming activation.
    with sdk_client(config, identifier) as client:
        active = publication(control.call("POST", "/" + identifier + "/activate", b"{}"), config, identifier, sealed.image)
        require(active["status"] == "active" and active["expires_at_epoch_ms"] <= value["expires_at_epoch_ms"])
        return upload(config, identifier, sealed, client, active["expires_at_epoch_ms"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("stage", "status", "publish"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        if name in {"stage", "publish"}:
            command.add_argument("--stage", type=Path, required=True)
        if name in {"status", "publish"}:
            command.add_argument("--publication", required=True)
        if name == "publish":
            command.add_argument("--execute-write", action="store_true", required=True)
    args = parser.parse_args(argv)
    try:
        isolate_environment()
        check_versions()
        config = load_configuration(args.config)
        control = Control(config)
        if args.command == "status":
            identifier = uuid(args.publication)
            result = summary(publication(control.call("GET", "/" + identifier), config, identifier))
        else:
            with open_stage(args.stage) as sealed:
                if args.command == "stage":
                    result = stage(config, sealed, control, on_created=lambda value: print(json.dumps(value, sort_keys=True), flush=True))
                else:
                    result = publish(config, args.publication, sealed, control, args.execute_write)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Exception, KeyboardInterrupt):
        print(FAILURE, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
