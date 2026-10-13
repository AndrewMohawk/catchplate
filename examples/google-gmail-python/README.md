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
2. Select or create a client with a finite token. New guided clients receive
   standard proxy login. For an existing Bearer-only client, use
   **Clients → Enable standard client login** to enable HTTP Basic on CONNECT.
3. Grant that client **Read Gmail → Official Gmail SDK** for the connected
   account. The grant must be `gmail_read_v1`, `orderedFormV1`, with exact dummy
   replacement `serverware-gmail-placeholder-v1`, and its policy must be loaded.
   Existing curl/insertion-only permissions are not automatically upgraded.
4. In current-source **Proxy setup**, choose **Python** under **Gmail SDK language**
   for this project's Bash recipe and private configuration. Prepare the virtual
   environment below before supplying the application token; the recipe does not
   install dependencies. See the [deployment record](../../docker/serverware-operator-demo/README.md)
   for the live release.
5. Copy the application ID, proxy URL and downloaded interception CA from the workspace.
   Your client must be able to reach the HTTPS proxy; this example does not
   bypass network policy or supply real Google consent.

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

Those are component checks, separate from the later
[joined Node/Python acceptance](../../docs/operator-gmail-job-verification.md#current-node-python-and-go-sdk-acceptance--isolated-jobs-passed)
at source `330d9e9f`. The pair passed in 178.576 seconds using both actual
entrypoints through the app and normal Rust proxy with verified TLS against a
synthetic Google service. Sixteen provider reads spanned the original token
expiry, one automatic refresh advanced generation 1 to 2, and eight
TLS/application/revocation denial controls added no provider arrivals. Durable
audit verification and cleanup passed. This includes the generated Python SDK
and its Requests adapter, not unchanged `httplib2` or an inferred Go result.

The isolated run did not establish real Google consent, provider entitlement or
a live-account job. Deployed UI/repair checks and the separately recorded
[public synthetic-route verification](../../docs/operator-public-proxy-verification.md)
have their own scope; neither establishes real Google access.
