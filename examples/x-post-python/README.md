# One text-only X post with the official Python SDK

**Posting integration is not yet available or end-to-end verified.** This is a
client example, not a working operator grant, provider entitlement check or
deployment claim. Do not use the existing username-read preset as posting
authorization. No real X or proxy requests were made to develop this example.

The pinned official [xdk 0.10.6 release](https://pypi.org/project/xdk/0.10.6/) uses
`Client(access_token=...)` for OAuth2 user context. Its actual
[posting method](https://github.com/xdevplatform/xdk-python/blob/1eb87aecea2d8b5ea340558fbe7426bc98e3a25b/xdk/posts/client.py#L1148)
is `client.posts.create(body=CreateRequest(text=text))`: one POST to
`https://api.x.com/2/tweets`. This example calls that method unchanged, with only
the public dummy `serverware-x-post-placeholder-v1`. Never give this program a
real X token. Future Serverware posting support must admit the request and
replace the dummy with the separately stored, authorized user credential.

There is no media, reply, quote, thread, delete, token exchange, refresh, lookup
or automatic retry. Each invocation needs `SERVERWARE_X_POST_CONFIRM=post-once`.
This is an intent check, not durable deduplication: manually running it twice
can create two posts once posting support becomes available.

## Future use, only after the paired posting integration is available

Create a new environment, from this directory:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Obtain an explicitly authorized posting grant, application ID/token,
interception CA and any separate outer-proxy CA from the operator. Never bypass
TLS or fall back to a direct X request. `.env.example` is reference only.

```bash
export SERVERWARE_PROXY_URL='https://your-proxy-host:443'
export SERVERWARE_APP_ID='your-application-uuid'
export SERVERWARE_CA_FILE='/absolute/path/serverware-ca.pem'
# Optional private OUTER proxy CA:
# export SERVERWARE_PROXY_CA_FILE='/absolute/path/proxy-ca.pem'
read -rsp 'Serverware application token: ' SERVERWARE_PROXY_TOKEN; echo
export SERVERWARE_PROXY_TOKEN
export SERVERWARE_X_POST_TEXT='An explicitly reviewed text-only post'
export SERVERWARE_X_POST_CONFIRM=post-once
.venv/bin/python -B post.py
unset SERVERWARE_PROXY_TOKEN SERVERWARE_X_POST_CONFIRM SERVERWARE_X_POST_TEXT
```

Text must be 1–16,384 UTF-8 bytes, without NUL or invalid Unicode. LF, tab and CR
are preserved, not normalized. The actual SDK-generated text-only JSON must fit
32,768 bytes; JSON escaping can make that limit tighter. There is no naïve
280-codepoint rule or claim that every admitted string satisfies X entitlement,
weighted-length or content rules.

Success is only `{"status":201,"id":"123456789"}` with the returned 1–20 digit decimal
post ID, never the text or provider response. It means a qualifying response was
observed, not an independent readback of the post.

## Unknown outcomes: do not replay

Exit 2 means **outcome unknown**. A withheld HTTP 409, timeout, connection loss,
invalid response, non-201 response or failure after invocation cannot establish
that no post occurred. The child has a 60-second wall deadline; killing a local
process cannot undo or prove cancellation of a remote operation. Consult the
operator audit and X before deciding on any new action. The client never polls,
refreshes a token, retries or automatically starts another post.

Exit 1 is local preparation failure before the SDK invocation. Errors use fixed
text only; response bodies, exceptions, tokens and submitted text are not logged.
Do not enable HTTP/SDK debug logging. The program does not implement durable
cross-process once-only execution or a remote cancellation protocol.

## Transport and credential boundaries

The [pinned SDK client](https://github.com/xdevplatform/xdk-python/blob/1eb87aecea2d8b5ea340558fbe7426bc98e3a25b/xdk/client.py)
exposes a Requests session. As in the reviewed username example, a local Requests
adapter sets 5-second connect/10-second read timeouts and zero retries. It checks
the prepared method, target, dummy and text-only body without rewriting them,
allows only one send, refuses redirects and limits decoded response bytes to
64 KiB. No OAuth client, token dictionary or refresh configuration is supplied.

Both certificate and hostname checks remain enabled. Inner TLS uses a temporary
0600 bundle containing certifi roots plus the interception CA. Outer proxy TLS
has a separate certifi-backed context plus only the optional outer CA; it does
not automatically trust the interception CA. No system trust store is changed.

Basic CONNECT authentication contains the Serverware application ID/token only;
the inner Authorization header contains the public X dummy. The credentialed
proxy URL exists only in memory, never command arguments or output. The launcher
passes only explicit Serverware inputs to one isolated Python child. Requests
`trust_env=False` disables ambient proxies, bypass lists, netrc and CA overrides.
The application token and text remain visible to sufficiently privileged
same-user process inspection; use a trusted workstation and scoped token.

## Offline tests

```bash
.venv/bin/python -B test_post.py -v
```

Tests use the actual pinned SDK serialization/model parsing and substitute only
the final Requests send. Socket and subprocess audit hooks forbid test network
or child-process execution. Coverage includes one POST, access-token-only auth,
confirmation/byte limits, both verified TLS configurations, no replay on 409 or
lost responses, no redirects, isolated environment and secret-free output.
These are not real TLS handshakes, proxy admission or provider acceptance.
All 14 offline groups passed on Python 3.12.3 with the pinned packages.

The six direct SDK/transport dependencies are pinned, not a hash-locked inventory
of every transitive package. The linked release source is publishing commit
`1eb87aecea2d8b5ea340558fbe7426bc98e3a25b`.
