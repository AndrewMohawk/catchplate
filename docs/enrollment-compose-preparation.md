# Preparing enrollment's single deployment artifact

Source `.128`; the preparer is implemented but has not been executed. No
deployment artifact, rendered Compose model or production acceptance is claimed.

## Decision

The existing native launcher, provenance, readiness and completion contracts
bind one `composeFile`. Supplying an extra overlay only to one command would
leave the other consumers checking a different deployment. The chosen design
keeps that single-file contract: prepare one immutable standalone Compose JSON
artifact from the fixed production base and, only when enabled, the fixed
enrollment overlay. Enroll that artifact through the existing release process.
No ambient `COMPOSE_FILE` setting or extra runtime `-f` is introduced.

[`scripts/prepare_enrollment_compose.py`](../scripts/prepare_enrollment_compose.py)
accepts an independently supplied runtime-root public key, expected configuration
digest and original signed enrollment bootstrap. It performs genuine bootstrap
admission before choosing enabled/disabled behavior. Those independent trust
inputs must themselves come from the provisioner or release authority; the
resulting artifact or sidecar cannot authorize its own root or configuration.

## Offline preparation contract

The command requires:

- `--bootstrap-file`: the original signed enrollment bootstrap.
- `--runtime-root-public-key-file`: the independently admitted Ed25519 public key.
- `--expected-configuration-digest`: the independently admitted configuration.
- `--output`: a new output file beside the fixed production Compose base.

The source base is always `docker-compose.production.yml`; the only permitted
overlay is `docker-compose.enrollment.yml`. Enabled enrollment adds exactly its
fixed read-only private-key bind, with host-path creation disabled. Disabled
enrollment leaves the base model unchanged and requires no dummy secret.
This is a narrow merge, not a generic caller-controlled YAML overlay facility.

The output is deterministic standalone Compose JSON with interpolation tokens
preserved, plus `<output>.provenance.json`. The sidecar records preparation
inputs, enabled state and output identity; it is not signed release approval or
runtime evidence. Stable bounded regular-file reads and fresh-only publication
prevent silent input replacement or overwriting an existing release artifact.
The two-file publication is not transactional: a failure can leave a complete
artifact without its sidecar. Such a partial pair grants no approval and is not
automatically deleted, overwritten or retried.

The preparer uses the existing locked PyYAML 6.0.3 dependency, with bounded safe
parsing and rejection of aliases, explicit tags, duplicate/non-string keys and
merge keys. It does not execute Compose, interpolate environment values, start
containers, read private signing keys or generate credentials. Version matching
alone does not prove dependency custody: the exact lock and complete parser/
interpreter/source closure still belong to immutable preparation.

## Path and release boundaries

Relative security/configuration paths in the base retain their original project
directory semantics. The command therefore requires output beside that base;
placing the JSON arbitrarily elsewhere is not a supported portable deployment.
For a staged release, retain the source-relative directory layout and freeze the
generated artifact there through the approved preparation process. Do not run
this in a source checkout that must remain byte-identical to its frozen commit.

The final artifact, its preparation inputs and dependencies must be independently
enrolled in provenance and the launch manifest. Existing readiness/completion
checks must run against that exact measured artifact. The sidecar does not grant
production promotion, establish a real Nitro/KMS boundary or provision the signer
and witness services. Production execution remains unverified.
