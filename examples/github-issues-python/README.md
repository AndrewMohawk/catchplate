# GitHub issues with Python and PyGithub

Read up to 100 open issues from **one explicitly permitted repository**, following
pagination with normal PyGithub methods. This example is read only: it never
creates an issue or comment. GitHub's issues list may include pull requests.

The operator stores the real GitHub credential in Serverware. This program gets
only a limited Serverware application login. Its GitHub authorization is the
public placeholder `token serverware-github-placeholder-v1`; the proxy replaces
that value after checking the application's permission. Do not provide a real
GitHub token to this program.

## Operator setup

GitHub App verification/save requires the operator to allow
`https://api.github.com` before provider contact. **Save and verify GitHub App**
checks the App, installation and repository and obtains a scoped token before
saving. A PAT may instead be saved untested while the upstream is disabled;
neither connection can be granted or used until the upstream is enabled.

1. Choose **GitHub**, then a **personal access token (PAT)** or **GitHub App**
   connection. A PAT needs a name and token. An App needs a name, App ID,
   installation ID, private-key PEM, exact repository owner/name and Issues
   access; choose `read` for this read-only client. Install the App for that
   repository with the required permission in GitHub first.
2. Create an application with **Basic proxy authentication** enabled; retain its
   application ID and one-time application token.
3. Give that application the **GitHub issues: read** permission for exactly the
   owner and repository you will set below (`github_issues_read_v1`).
4. Copy the HTTPS proxy URL and download its interception CA from **Proxy**.
   The outer HTTPS proxy endpoint must use a certifi-trusted certificate. This
   example does not support an independently configured private outer CA.

No generic permission, repository-metadata route, `/user` or `/rate_limit` grant
is needed. The named issues permission, not this client, is the authority boundary.

Serverware keeps the App private key encrypted server-side and automatically
obtains and renews short-lived installation tokens. It does not renew PATs or the
client's Serverware application token. The App's repository/Issues ceiling and
the application's saved grant both apply; this remains the existing issues and
comments preset, not arbitrary GitHub APIs, git, GraphQL or Actions/workflow
management. This program remains read only even if the connection permits writes.

App token reuse requires a 65-second expiry margin. A failed mint is not retried
in the same call. A later separately authorized lease may attempt fresh
authentication after a 60-second backoff; this is not a repository-request retry.

A GitHub App installation is not a GitHub OAuth user-login flow, and its App ID
is not `SERVERWARE_APP_ID`. PyGithub still receives only the public dummy. Never
put the private key, JWT or installation token in this project's environment.
The new App flow is **not yet verified against real GitHub**;
[App lifecycle synthetic verification is recorded separately](../../docs/operator-github-client-compatibility.md#github-app-feature-verification-checkpoint).

## Run

Python 3.10+ on Linux/macOS, using a dedicated virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

export SERVERWARE_PROXY_URL='https://your-proxy-host:443'
export SERVERWARE_APP_ID='your-application-uuid'
export SERVERWARE_CA_FILE='/absolute/path/serverware-ca.pem'
export SERVERWARE_GITHUB_OWNER='your-owner'
export SERVERWARE_GITHUB_REPO='your-repository'
read -rsp 'Serverware application token: ' SERVERWARE_PROXY_TOKEN; echo
export SERVERWARE_PROXY_TOKEN

.venv/bin/python -B issues.py --limit 100
unset SERVERWARE_PROXY_TOKEN
```

Use your actual values; the placeholder host and application UUID above are not
built-in accounts. `SERVERWARE_PROXY_URL` must have no credentials, path, query or
fragment. Leave `SERVERWARE_PROXY_CA_FILE` unset: it is explicitly rejected, even
if empty, rather than silently ignored. Ambient GitHub credentials, proxy/NO_PROXY
settings, Python paths and Requests CA overrides are not passed into the child.

The output is JSON containing issue numbers, states and titles (titles are limited
to 512 characters). The SDK uses pages of 30; the example stops at your limit.
Errors have fixed redacted text. Check the operator audit log for the reason;
do not enable SDK/HTTP debug logging to diagnose authentication.

## Transport and credential tradeoff

[PyGithub 2.10.0](https://pypi.org/project/PyGithub/2.10.0/) has no documented
per-client proxy-authentication setting. This launcher therefore constructs a
standard `HTTPS_PROXY` URL **only in a short-lived child process environment**, from
the separate application ID and token. The URL contains percent-encoded Basic
userinfo; it is not printed, written to a config file, placed in command arguments,
or added to the parent environment. The child does not launch subprocesses, and
SDK/HTTP logging is disabled. Nevertheless, same-user process inspection, a
debugger or a process dump can reveal that environment. **This is not URL-free
credential handling.** Requests itself [warns about credentials in proxy environment
variables](https://requests.readthedocs.io/en/latest/user/advanced/#proxies).
Use an application-scoped, revocable token on a trusted workstation.

The launcher builds a temporary, client-only CA bundle from the pinned certifi
roots plus the downloaded Serverware CA; it removes that file after the child
exits. PyGithub's `verify` option remains enabled. The reviewed Requests/urllib3
transport uses this **same bundle for both the outer HTTPS proxy and the inner
GitHub TLS connection**. These are not independently isolated trust policies.
No system trust store, certifi installation, SDK class or outgoing request is
modified. See [PyGithub's transport](https://github.com/PyGithub/PyGithub/blob/v2.10.0/github/Requester.py),
[Requests' TLS pool selection](https://github.com/psf/requests/blob/v2.34.2/src/requests/adapters.py)
and [urllib3's proxy TLS inheritance](https://github.com/urllib3/urllib3/blob/2.8.0/src/urllib3/connection.py).

The normal SDK call is `Github(..., lazy=True).get_repo("owner/repo").get_issues(...)`.
Lazy construction avoids the unsupported repository-metadata GET. Stock pagination
follows the proxy-released `Link` header; this example does not rewrite it. Transport
retries are disabled with the SDK's documented `retry=None`; each HTTP timeout is
10 seconds, with a 60-second launcher limit and no command retry.

## Offline checks and evidence boundary

```bash
.venv/bin/python -B test_issues.py
```

The tests exercise real PyGithub pagination and final Requests serialization with
synthetic responses at the send boundary. They check placeholder authorization,
separate Basic proxy credentials, minimal child environment, CA pool settings,
lazy route selection and fixed errors. A socket audit hook is installed after
dependency imports (urllib3 may probe local IPv6 support during import).

These tests are **offline checks, not proxy/TLS/GitHub integration evidence**.
All eight groups passed locally on 2026-10-10 with the pinned dependencies.

The later 2026-10-10 [actual-entrypoint acceptance](../../docs/operator-github-client-compatibility.md#checked-in-node-python-and-go-examples)
passed this launcher and its SDK child through the normal Rust proxy using
Python 3.12.14, verified TLS and a synthetic GitHub service. Two-page reads
succeeded; wrong-application and wrong-repository attempts were denied before
dispatch. The client-only combined CA trust remains the tradeoff described above.
No real GitHub request or public deployment is established by that isolated run.
That historical static-token fixture does not establish GitHub App installation
authentication or automatic token renewal.

A saved operator permission, valid app token and running proxy are still needed
to run against your repository. The four
SDK/transport/trust dependencies are pinned in `requirements.txt`; this is not a
hash-locked inventory of all transitive packages.
