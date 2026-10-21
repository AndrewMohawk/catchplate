# Keeping deployments private

This repository contains source, generic examples and synthetic test fixtures.
Deployments supply their own domains, storage paths, OAuth applications, provider
credentials, signing keys, private client configurations and operator identities.
Keep that material outside the checkout or in ignored local configuration.
Never commit a real provider key merely to make an example runnable.

Before publishing a branch or release:

1. Review the staged diff, including filenames, commit messages and author email.
2. Scan the full reachable Git history, not just the latest checkout. For example,
   run `gitleaks git --log-opts='--all' --redact=100 --ignore-gitleaks-allow`.
   Review findings: key-format checks, filenames and explicit synthetic values can
   be false positives. Do not suppress an entire source or test directory.
3. Review images and generated artifacts separately. Text scanning cannot establish
   that a screenshot contains no account details or private hostnames.
4. Check releases, Actions logs/artifacts, discussions, comments, Wiki history,
   branches, tags and pull-request refs before changing repository visibility.
5. Rotate any real credential that was committed. Deleting a line or rewriting
   history does not revoke the credential or remove copies held elsewhere.

History rewriting changes commit IDs and invalidates signatures and old source
pins. Use fresh clones afterward; merging an old branch can reintroduce removed
history. Independently rebuild and verify release artifacts from the new source
identity rather than relabeling an old signed artifact.
Before retiring old history, migrate any deployed client-source download pins to
an accepted revision that will exist in the publication repository. A source
template update alone does not migrate a running instance or saved client files.

GitHub retains some cached commits and read-only pull-request refs that a force
push cannot remove. Follow [GitHub's sensitive-data removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
and obtain any required server-side purge, or publish from a new repository with
no contaminated refs. A local scan is not proof of server-side erasure.

The publication scrub is a privacy measure, not a production-readiness review or
a guarantee that every possible secret can be detected automatically.
