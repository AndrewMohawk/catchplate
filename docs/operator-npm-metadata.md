> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# npm package metadata

The additive `npm.metadata.v1` profile supports **reading package metadata**.
It is not an installation or publication preset. The existing `npm.registry`
write adapter and its approval requirements are unchanged.

## Operator workflow

1. Store an npm token as a named connection. Storage does not verify its npm
   account or permissions and does not grant an application access.
2. Choose an application and select **Read package metadata**. List the exact
   package names, including any scope. One grant can contain up to 64 names.
3. Configure the ordinary client with the application's proxy authentication,
   the proxy CA, and the displayed registry-scoped placeholder. The npm token
   remains on the server.

This operation is intended for `npm view` and `pacote.manifest`. Package
installation, tarball downloads, audit POSTs, publishing, provider 2FA and
approval are not part of this profile. It grants no automatic dependency access.
Do not label this permission “Install packages” or “Publish packages.”

## Authority and response limits

Only bodyless metadata GETs to `https://registry.npmjs.org` are allowed. Package
names are an explicit sorted allowlist, not wildcards or arbitrary URLs. Scoped
names use the canonical encoded package path. Queries, HEAD, redirects,
tarballs and writes are refused. A provider's `dist.tarball` field is metadata,
not authority to fetch that URL.

The profile preserves complete strict JSON, including dynamic version,
dependency and dist-tag fields. A successful document must name the requested
package. Success responses are bounded to 1 MiB; selected JSON errors to 64 KiB.
Credential-reflection checks inspect the response before release. Bounded
unselected HTTP metadata is checked and discarded. HTTP compression offers are
discarded by this explicit request profile; encoded upstream responses remain
unsupported. No response-field configuration is required.

There is one active metadata grant per application. Put all its selected names
in that grant. Overlapping single-segment registry GET rules are refused rather
than depending on rule order. Revoke the old grant before replacing it; no
existing grant is silently expanded.

## Verification boundary

On **2026-10-10**, the isolated end-to-end metadata fixture passed using stock
Node **25.5.0**, npm **11.8.0**, pacote **21.0.4** and npm-registry-fetch **19.1.1**.
Actual `npm view` and `pacote.manifest` calls used the app-scoped HTTPS proxy,
registry-scoped placeholder and additive CA trust. No client transport was
replaced, and TLS verification remained enabled. Retries were explicitly set
to zero; default retry behavior was not tested.

The fixture exercised the actual catalog handlers, custody, policy publication,
compiled Rust gate, synthetic TLS registry and committed audit records:

- Seven upstream metadata attempts had seven unique audit attempt IDs. Five
  responses were released, including the expected JSON 404. Package-name
  mismatch and credential reflection each blocked a response.
- Wrong application, unlisted package and wrong placeholder were each denied
  before any credential lease or upstream request.
- Scoped and unscoped names passed with full JSON and vendor metadata JSON.
  Whole upstream body hashes/lengths matched the response audit records.
- Runtime inspection verified the private shared network namespace, no external
  route or host ports, expected executable, read-only source and shared policy
  publication lock. The fixture completed in 73 seconds; only its temporary
  containers were removed. Private runtime files and receipts were retained.

The accepted source is `dc68a571e42760360a5ddfc6387d2094319629e4`. The normal
Rust binary was genuinely compiled from
`8cbe796422241afe4f4a1e1fc3898456a103453e`, with SHA-256
`2bfe5e384d7e9c655de70704c25350c16336c55a2584fc59f363f12164f297d6`.
The later harness-only change left all production directories and all 493
compiler inputs byte-identical, so the accepted run reused that binary without
another build. Private receipts are retained under
`/srv/catchplate-fast/tmp/serverware-npm-fixture-runner.NBT63N`:

| Receipt | SHA-256 |
| --- | --- |
| `checker.stdout.log` | `2379584087bada7f55404a03f8882f2bffe243a62653136fc172be2354b392be` |
| `run-npm.receipt.json` | `0bcf8ef26a9b51e409d8be649507fd4ecb24b05ddb9772249e6ede2674ac1c3a` |

Earlier attempts caught a missing embedded-schema `$defs` and a disposable
numeric user's missing home directory. Both failed runs were cleaned up and
retained separately. The schema now supplies a real referenced definition; the
strict loader is unchanged. The fixture supplies a private home only to its
disposable Node/npm processes, with fixed-field diagnostics that omit raw errors.

Supporting checks passed: 15 Python adapter/schema groups, 10 connected npm
catalog groups, nine pure fixture groups, 12 UI groups and six rendered-browser
groups. The browser cases intercepted backend responses and did not themselves
execute a proxy request. The authored Rust unit regressions were not executed;
release compilation and actual gate startup/client acceptance were executed.

This is **private synthetic metadata acceptance**, not real npm account access,
public registry/DNS acceptance, installation, publication, or production release.
No real provider was contacted. The implementation is now deployed in the
[retained operator demo pair](../docker/serverware-operator-demo/README.md#current-notification-enabled-deployment):
app `577badff` and actual executable `2bfe5e38`. That code-only rollout preserved
the fixture-only allowlist and all saved resources; it did not create an npm
connection or execute another proxy request. All retained application tokens
are expired. The waiting native pilot retains its separate frozen source.
Actual native-key notification and hardware acceptance are also separate from
these client results.

The broader installation/publishing requirements remain in
[ordinary npm client compatibility](operator-npm-client-compatibility.md).
