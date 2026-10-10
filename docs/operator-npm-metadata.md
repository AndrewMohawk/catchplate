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

The source implementation and its synthetic client fixture are being verified.
They are not yet a deployed npm feature or evidence of real npm account access.
The currently waiting native pilot remains on its frozen source snapshot.

The broader installation/publishing requirements remain in
[ordinary npm client compatibility](operator-npm-client-compatibility.md).
