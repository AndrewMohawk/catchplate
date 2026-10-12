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
package/version map. Only authenticated CONNECT requests matching the signed
audit route can use gzip; ordinary and management request intake remain
identity-only. Original compressed bytes, content encoding and content length
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
must retain the original deadline and exact generation pin, without retrying
the provider request or extending any issued lease. Compiled regression and
stock-npm acceptance of this remaining repair are still required. The ordinary
live app is unchanged by these source commits.
Public proxy DNS repair and real npm
account entitlement remain separate unverified requirements. No pilot is needed
to open or use the persistent operator app.
