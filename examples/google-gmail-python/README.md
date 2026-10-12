# Gmail read-only job — official Python SDK

Uses Google's `google-api-python-client` Gmail discovery client, with normal
`users().messages().list(...).execute()` and `get(...).execute()` calls. It reads
at most two INBOX pages of five messages each, then retrieves only those returned
IDs with `format=metadata` and `From`, `Subject`, `Date` headers. It never sends,
modifies, deletes or downloads attachments.

The SDK's documented [`http=` transport seam](https://googleapis.github.io/google-api-python-client/docs/epy/googleapiclient.discovery-module.html#build)
is implemented with Requests here. Stock `httplib2` does not supply the required
TLS-to-HTTPS-proxy hop with independent trust roots; this is explicitly a small
transport adapter, not a claim that stock `httplib2` works unchanged. The SDK
still constructs paths, ordered repeated query parameters and decoded results.
No private Google token or Google client credentials belong in this program.

## Operator prerequisites

In the ordinary Serverware workspace:

1. Configure Google and connect the intended account with the Gmail read-only
   preset. Real account consent is a separate operator action.
2. Save an application with **Basic proxy authentication** and a finite token.
3. Grant that application **Read Gmail → Official Gmail SDK** for the connected
   account. The grant must be `gmail_read_v1`, `orderedFormV1`, with exact dummy
   replacement `serverware-gmail-placeholder-v1`, and its policy must be loaded.
   Existing curl/insertion-only permissions are not automatically upgraded.
4. Copy the application ID, proxy URL and downloaded proxy CA from the workspace.
   Your client must be able to reach the HTTPS proxy. A public DNS/routing block
   still prevents a real client job; this example does not bypass it.

No pilot or native commissioning is required for this ordinary workflow. The
proxy owns account-token refresh; this SDK process cannot refresh Google tokens.

## Install and run

Tested with CPython 3.12.3. `requirements.txt` pins the complete 22-package
resolution actually installed for this example on Linux, including official
[`google-api-python-client` 2.201.0](https://pypi.org/project/google-api-python-client/2.201.0/).
It contains version pins, not an artifact-hash lock or a vendored dependency tree.

```sh
cd examples/google-gmail-python
python3.12 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: -r requirements.txt
.venv/bin/python -m pip check

export SERVERWARE_PROXY_URL='https://your-proxy.example:443'
export SERVERWARE_APP_ID='your-saved-application-uuid'
export SERVERWARE_CA_FILE='/absolute/path/to/serverware-ca.pem'
read -r -s -p 'Application proxy token: ' SERVERWARE_PROXY_TOKEN
echo
export SERVERWARE_PROXY_TOKEN
.venv/bin/python gmail.py
unset SERVERWARE_PROXY_TOKEN
```

The `read` command above is for Bash. Use your shell's private-input mechanism;
do not paste the token into source files, command-line arguments or shell history.
`.env.example` is a reference only; no `.env` file is loaded.

`SERVERWARE_CA_FILE` trusts only the intercepted Gmail TLS connection. For an
outer proxy certificate signed by a private CA, additionally set
`SERVERWARE_PROXY_CA_FILE` to that separate absolute public CA file. Otherwise
the outer connection uses the pinned certifi public roots. Do not combine or
swap these roles, disable TLS verification or supply private keys as CA files.

The job emits only a bounded summary, for example:

```json
{"pages":2,"messages_read":6,"more_pages":true}
```

`more_pages: true` means the sample was bounded, not that the entire mailbox was
read. Message IDs, subjects, senders, dates, snippets, bodies and tokens are never
printed. Any failure exits 1 with a fixed message; consult the operator audit
without enabling HTTP debug logging or printing exception objects.

## Transport and bounds

- HTTPS proxy only; explicit Basic CONNECT identity is distinct from the public
  dummy provider bearer. No direct fallback, netrc, ambient proxies or bypasses.
- A clean, isolated child environment excludes Google ADC, mTLS, proxy/CA
  overrides and TLS key-log settings. Bundled discovery makes no discovery call.
  Calling the internal `--child` mode with ambient variables fails closed.
- GET only at `https://gmail.googleapis.com/gmail/v1/users/me/messages` and
  returned-ID children. Duplicate IDs, pagination cycles and malformed tokens
  fail closed. URLs over 2,048 characters fail before the SDK's GET-to-POST
  fallback; the program does not widen permission to accommodate them.
- At most 12 requests, 5-second connection/10-second socket-read timeouts,
  110-second transport budget and a 120-second parent process deadline.
- SDK and transport retries are both zero. Redirect/error responses stop before
  response buffering or redirect preparation. Successful JSON is limited to
  1 MiB; unexpected compression, duplicate JSON keys, malformed framing or a
  returned message ID mismatch fail. No response body is included in errors.

## Verification and remaining evidence

```sh
.venv/bin/python -B -m unittest -v test_gmail
```

On 2026-10-12, all 13 groups passed in the isolated CPython 3.12.3 environment;
`pip check` also passed. Tests use the **real pinned Google SDK and Requests**
with a synthetic send boundary. An audit hook forbids socket operations. They
check SDK pagination/query bytes, request limits, no retry/redirect, secret-free
output, clean child configuration, Basic CONNECT separation, and separate CA
roles using real certificates and in-memory TLS handshakes.

This is not yet a Python-through-Serverware end-to-end acceptance result. The
existing Go SDK's joined fixture receipt does not prove this Python transport.
A separate isolated run through the actual app and Rust proxy, then any
authorized real-account job, remains distinct evidence. No provider account,
Google request, proxy deployment or live configuration was changed here.
