# Offline guest credential-delivery producer

`scripts/sign_native_guest_credential_delivery.py` produces the exact signed
original accepted by [guest-local custody startup](response-v2-guest-credential-delivery.md).
This is source-only, unbuilt and unexecuted. It does not provision role secrets,
launch the cohort, produce a Nitro quote or establish independent administration.

## Inputs and authority

Run it only inside the independently authorized provisioning environment, never
the untrusted build worker. Supply four distinct inherited, fully sealed,
owner-only anonymous memfds:

| Flag | Exact original |
| --- | --- |
| `--signing-seed-fd` | 32-byte Ed25519 delivery-authority seed |
| `--configuration-fd` | Complete cold custody configuration, at most 256 KiB |
| `--payload-fd` | Closed canonical delivery payload, at most 64 KiB |
| `--generation-root-fd` | Exact 32-byte generation public root, not its private key |

`--configuration-sha256` is the independently selected full configuration pin.
The command disables core dumps and process dumpability before reading private
inputs. It accepts no secret value, key pathname or environment override. Python
and cryptographic-library copies are not claimed completely erased afterward.

The payload is `$defs/payload` in the [paired schema](../schemas/response-v2-guest-credential-delivery.v1.schema.json).
Its generation, role, configuration hash, exact file pins and original guest
boot/window must already have independent authorization. The producer does not
read its own host boot ID or clock to fill guest fields. It does not choose a
fresh window, renew an old one or sign a configuration assembled from observed
runtime state without approval. Keep one coherent admitted original startup
deadline across the seven role deliveries.

## Exact output and checks

Stdout contains only the signed canonical UTF-8 envelope, **without a trailing
newline**, bounded to 64 KiB. The signature domain, raw-public-key SHA256 identity,
canonical unpadded base64url and positive-u64 decimal timestamp strings match the
Rust consumer. The payload has no floating-point numbers. Configuration hashes
use the original bytes, never a Python reserialization of unrelated numeric
fields. Do not append a newline before hashing/installing the delivered original.

The signer must match the explicitly assigned cold delivery public key and must
differ from the supplied generation root and every runtime role key. The payload
must name the same full configuration, hardware topology generation and exact
selected role-key paths/public hashes. Only state-authority carries bootstrap
manifests; other roles carry explicit null. Duplicate/conflicting paths and role
assignments, private/public path aliases, wrong pins and oversized windows fail.
No role seed is an input to this producer; their preapproved hashes are data.

These are signing-input consistency checks, not a second runtime verifier. The
producer does not authenticate the topology/generation/TEE evidence, prove the
current guest boot/time, inspect guest filesystem ownership or derive the role
public keys from deployed seeds. The actual Rust owner repeats full signed
generation admission, exact current guest boot/time and protected original
checks, including seed-derived key association. A freshly signed envelope cannot
replace that evidence or make an invalid configuration valid.

## Installation boundary

The authorized installer must durably install the exact signed envelope as a
root-owned single-link `0400` or `0444` file and deliver its exact SHA256 to the
fixed guest CLI. The nonroot service needs the permitted readable form. Role
credentials remain distinct role-owned single-link `0400` originals at their
signed paths. This command neither writes nor chmods those files and never copies
private seeds into an OCI image, EIF or release manifest. Encrypted role-secret
provisioning, cohort supervision, durable backend, peer measurement and genuine
quote production remain unfinished deployment work.
