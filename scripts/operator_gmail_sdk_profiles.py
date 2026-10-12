"""Closed Node/Python Gmail fixture vectors; no SDK calls or mutable selection.

These are independent literal wire oracles, not request serializers. The
unchanged Go fixture remains its own default contract. No provider values live
here: Basic app credentials and actual OAuth tokens are never recorded.
"""

CLIENTS = ("node", "python")
CASES = ("list_page_1", "message_metadata_1", "list_page_2", "message_metadata_2")
COMMANDS = {
    "node": ("/node", "/app/examples/google-gmail-node/client.mjs"),
    "python": ("/example-python/bin/python", "-I", "-B", "/app/examples/google-gmail-python/gmail.py"),
}
SOURCES = ("examples/google-gmail-node/client.mjs", "examples/google-gmail-node/package.json",
    "examples/google-gmail-node/package-lock.json", "examples/google-gmail-python/gmail.py",
    "examples/google-gmail-python/requirements.txt")
NODE_VERSION = "25.5.0"
PYTHON_VERSION = "3.12.14"
NODE_SHA256 = "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d"
NODE_MODULES = "examples/google-gmail-node/node_modules"
PYTHON_PACKAGES = "/example-python/lib/python3.12/site-packages"
OBSERVATION_SCHEMA = "serverware.privateGmailSdkObservations/v2"
CHECK_SCHEMA = "serverware.privateGmailSdkCheck/v2"
SDK_HEADERS = {
    "node": {"accept": "application/json", "user-agent": "google-api-nodejs-client/9.2.0 (gzip)",
        "x-goog-api-client": "gdcl/9.2.0 gl-node/25.5.0"},
    "python": {"accept": "application/json", "user-agent": "(gzip)",
        "x-goog-api-client": "gdcl/2.201.0 gl-python/3.12.14"},
}
QUERIES = {
    "node": (
        "maxResults=5&labelIds=INBOX",
        "format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date",
        "maxResults=5&labelIds=INBOX&pageToken=next%2Bpage%20%2F%3D",
        "format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date"),
    "python": (
        "maxResults=5&labelIds=INBOX&alt=json",
        "format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date&alt=json",
        "maxResults=5&labelIds=INBOX&pageToken=next%2Bpage+%2F%3D&alt=json",
        "format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date&alt=json"),
}
FAILURES = {
    "node": b"Gmail example failed; check configuration, permissions and service audit logs.\n",
    "python": b"Gmail read failed; check application permission, proxy trust and the operator audit log.\n",
}
PHASES = tuple(client + ":" + phase for phase in
    ("first", "refreshed", "wrong_outer_ca", "wrong_inner_ca", "wrong_app", "revoked") for client in CLIENTS)
PAIR_CASES = tuple(client + ":" + case for client in CLIENTS for case in CASES)


def targets(go_targets):
    return {client + ":" + case: {**go_targets[case], "raw_query": QUERIES[client][index]}
        for client in CLIENTS for index, case in enumerate(CASES)}


def provider_headers(case):
    client, _, operation = case.partition(":")
    if client not in CLIENTS or operation not in CASES:
        raise ValueError("unknown paired Gmail case")
    # HttpRequest.execute/Requests sends an explicit empty Content-Length;
    # Rust retains that framing in canonical_forwarded_request_headers.
    return {"host": "gmail.googleapis.com", **SDK_HEADERS[client],
        **({"content-length": "0"} if client == "python" else {})}


def split_phase(value):
    if value not in PHASES:
        raise ValueError("unknown paired Gmail phase")
    return tuple(value.split(":"))
