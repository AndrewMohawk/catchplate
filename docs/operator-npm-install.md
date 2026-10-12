# npm installation permission

The additive `npm_install_v1` permission is separate from metadata lookup and
publication. Select an npm connection, a standard-proxy-login application and
the exact package names to permit, including every dependency. No old permission
is broadened, and no package dependency is granted automatically.

The UI offers this permission only when the same policy-loaded proxy health
response advertises `serverware.operatorNpmInstallGate/v1` and the operator has
approved `https://registry.npmjs.org`. One application cannot combine this grant
with another active registry permission. Existing credentials, permission rows
and policy history are preserved.

One catalog permission signs three `npm.install.v1` routes:

| Mode | Request | Response limit |
| --- | --- | --- |
| Metadata | GET an explicitly listed package | 1 MiB JSON |
| Tarball | GET a listed package's versioned registry archive | 8 MiB gzip; 32 MiB decoded inspection |
| Audit | POST the fixed bulk-advisory endpoint for listed packages | 1 MiB JSON |

Supported provider errors are bounded to 64 KiB. Audit request bodies are at
most 64 KiB compressed and 256 KiB decoded, with a strict duplicate-free
package/version map. Inner gzip requests require an authenticated CONNECT and
the signed audit route; other inner requests and management intake remain
identity-only. The ordinary TLS edge separately tolerates npm's copied gzip
header on an exact, bodyless registry CONNECT, only with a current app token
and that app's validated audit grant before opening the tunnel. This does not
admit an encoded CONNECT body or change native intake.
Original compressed bytes, content encoding and content length
are bound into the canonical request and checked against the built upstream
request. Concatenated/trailing gzip members and invalid checksums are refused.

Responses preserve admitted bytes. Both compressed and decoded tarball bytes
are checked for credential reflection. This is not an archive extraction,
package safety, malware or lifecycle-script review. The proxy's durable request
audit is separate from npm's dependency-vulnerability advisory request.

## Client example and verification boundary

[The stock npm example](../examples/npm-registry/README.md) copies only reviewed
project and lock inputs into a fresh output directory, disables lifecycle
scripts, keeps default npm audit enabled and leaves installed or partial output
available for inspection. It never runs `npm ci` in the original project.
Both TLS layers remain verified. The application has only its proxy credential
and a fixed public provider placeholder, not the real npm token.

The isolated acceptance scenario adds a dependency publication, installation,
cold `ci` and an intentional advisory failure to the existing metadata/publish
controls. Its expected evidence includes actual installed package bytes, the
transitive dependency, unchanged `ci` lock bytes, original gzip commitments,
distinct durable audit attempts, and all prior denial controls. A successful
mocked check or compilation is not that acceptance result.

Current candidate status: focused Python, catalog, Node and fixture-oracle
checks and 125 compiled Rust controls passed. The first real stock-npm run
stopped at the third publication with a credential-preparation 503, before
installation. Its state and cleanup receipts are preserved in
`npm-install-acceptance.Jg4Pc6mt`; it is not a successful acceptance result.

The repair candidate keeps ordinary static credential metadata warm in the
background but obtains secrets on demand in the foreground. This prevents a
request from joining a background secret-renewal flight that can become
ineligible while waiting for publication. Existing five-second leases, exact
generation checks, request deadlines and native/Google behavior are unchanged.
Closed diagnostic categories distinguish these failures without logging
credentials. That repair passed its compiled controls, but the second stock-npm
run (`npm-install-acceptance.oyag53ql`) stopped at the same publication with a
different final-pair freshness failure. Its cleanup completed and its receipts
are preserved. The stopped database, read with its WAL, shows a five-second
secret issued while the older generation had less than one second remaining.
Preparation must reserve the secret-fetch budget before acquiring that secret;
an already-fresh cached pair still needs no acquisition. The corrected path
retains the original deadline and exact generation pin, without retrying
the provider request or extending any issued lease. The corrected Rust path
passed all 128 selected regressions. Its stock-npm run
(`npm-install-acceptance.SFxf8yI5`) completed all three publications, then stopped
at the first installation metadata request: the synthetic registry incorrectly
required abbreviated metadata while pinned npm's Arborist requests full JSON.
This was an upstream fixture 400, not another credential-preparation failure.
The fixture/checker correction keeps standalone pacote metadata unchanged and
reuses the verified Rust binary because no compilation input changes. The next
run (`npm-install-acceptance.UQcyBVGi`) completed installation, including exact
published bytes, the transitive dependency, generated lock and default audit.
It then failed at cold `ci`, before any additional upstream request was recorded.
The original fixed error envelope did not identify which client stage failed;
that evidence does not establish a cause. All failed runs remain preserved with
completed cleanup. Full stock-npm acceptance is still required. The ordinary
live app is unchanged by these source commits.
The diagnostic run (`npm-install-acceptance.qjwx36xS`) again passed install and
identified `E400` from stock npm during cold `ci`. A separate loopback-only
wire probe observed three bodyless outer CONNECTs carrying `Content-Encoding:
gzip`, with no Content-Length or Transfer-Encoding. Pinned npm's cached proxy
agent copies the first origin request's headers into CONNECT; cold `ci` starts
with the gzip advisory request, while install starts with metadata. The default
outer parser rejects that encoding before authentication. The wire probe's
overall result remains failed because it recorded a socket error after the
deliberate 400 responses; its header observations are not proxy acceptance.
The source correction is limited to that bodyless CONNECT case. Its compiled
regressions and a complete stock-client rerun are still required before deployment.
Public proxy DNS repair and real npm
account entitlement remain separate unverified requirements. No pilot is needed
to open or use the persistent operator app.
