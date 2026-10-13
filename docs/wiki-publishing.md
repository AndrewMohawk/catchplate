> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Publish the operator guide to GitHub Wiki

The [GitHub Wiki](https://github.com/AndrewMohawk/serverware/wiki) is the operator
documentation home. `docs/wiki/` is its reviewed, versioned source in this
repository. Publishing the application repository does **not** publish its Wiki:
GitHub stores Wiki pages in a separate `serverware.wiki.git` repository. Its
default branch supplies the live pages; the initial page must be created on
GitHub before cloning. See [GitHub's publishing instructions](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages#adding-or-editing-wiki-pages-locally).

## Resolve the recorded publication blocker

The [publication handoff](project-completion.md#current-checkpoint--october-13-access-continuation-and-operator-guide)
records an enabled Wiki whose authenticated Git repository returned
`Repository not found`. The browser had no authenticated GitHub session, so
missing initialization and an access problem were not distinguished. This is
the previously observed state, not a new remote check or a publication-success
claim.

An authorized repository maintainer must open the Wiki while signed into
GitHub. If it offers **Create the first page**, keep the title **Home**, paste
the reviewed contents of `docs/wiki/Home.md`, and save it. This is a one-time
initialization action; do not repeat it if a Home page already exists. If the
Wiki already contains pages or Git access still fails after initialization,
investigate existing access rather than creating a new PAT, requesting a
secret in chat, or expanding CI permissions. Continue with publication only
after the existing Wiki repository is accessible.

Because this repository is private, also confirm that its owner's GitHub plan
supports private-repository Wikis. GitHub documents this support for Pro, Team
and Enterprise plans; Free supports Wikis on public repositories only. See
[Wiki availability](https://docs.github.com/en/communities/documenting-your-project-with-wikis).
An enabled Wiki setting and repository administrator access do not by themselves
establish plan eligibility or initial-page creation. The current owner's plan
has not been established, so plan eligibility is a check, not a diagnosed cause
of `Repository not found`. Do not change repository visibility, purchase a plan
or create a replacement public repository to bypass this check.

## Prepare an isolated publication checkout

Use a dedicated Bash shell from the application repository after review,
commit and push to `main`. Stop on failed checks. Publish claims for the actual
verified revision, not an in-progress SDK graph. These commands use existing
`gh` credentials without changing global Git configuration or printing secrets.

```bash
set -euo pipefail
wiki_source=$(git rev-parse --show-toplevel)
test "$(git -C "$wiki_source" branch --show-current)" = main
test -z "$(git -C "$wiki_source" status --porcelain)"
wiki_source_commit=$(git -C "$wiki_source" rev-parse HEAD)
wiki_git() {
  git -c credential.helper= -c 'credential.helper=!gh auth git-credential' "$@"
}
wiki_git -C "$wiki_source" fetch origin main
test "$wiki_source_commit" = "$(git -C "$wiki_source" rev-parse origin/main)"
wiki_publish_dir=$(mktemp -d /srv/catchplate-fast/tmp/serverware-wiki-publish.XXXXXXXX)
wiki_checkout="$wiki_publish_dir/wiki"
wiki_git clone https://github.com/AndrewMohawk/serverware.wiki.git "$wiki_checkout"
wiki_branch=$(git -C "$wiki_checkout" branch --show-current)
wiki_base_commit=$(git -C "$wiki_checkout" rev-parse HEAD)
test -n "$wiki_branch"
test -z "$(git -C "$wiki_checkout" status --porcelain)"
```

Run each block only if the preceding checks succeeded. A clone failure is a
stop, not permission to create a replacement repository or reuse another
publisher's checkout. Preserve the fresh directory for diagnosis.

## Copy and review exactly the maintained pages

These thirteen guides plus `_Sidebar.md` are the publication allowlist. Do not use
`rsync --delete`, remove other Wiki pages, or copy the whole application checkout.

```bash
wiki_pages=(
  Home.md Getting-started.md Credentials-and-providers.md Clients-and-recipes.md
  GitHub-App-setup.md OAuth-provider-setup.md Custom-API-credentials.md
  Permissions-and-policies.md Proxy-and-CA.md Notifications-and-audit.md
  Operations-and-maintenance.md Troubleshooting.md Capability-matrix-and-glossary.md
  _Sidebar.md
)
for wiki_page in "${wiki_pages[@]}"; do
  test -f "$wiki_source/docs/wiki/$wiki_page"
  test ! -L "$wiki_source/docs/wiki/$wiki_page"
  test ! -L "$wiki_checkout/$wiki_page"
  cp -- "$wiki_source/docs/wiki/$wiki_page" "$wiki_checkout/$wiki_page"
done
git -C "$wiki_checkout" add -- "${wiki_pages[@]}"
git -C "$wiki_checkout" diff --cached --check
git -C "$wiki_checkout" diff --cached --stat
git -C "$wiki_checkout" diff --cached -- "${wiki_pages[@]}"
```

Inspect the complete diff before continuing. Wiki-only edits are not disposable:
if copying replaces a newer explanation or another maintainer's work, stop,
reconcile it into the reviewed source, and prepare a fresh publication checkout.
If the staged diff is empty, no commit or push is necessary. Do not use a reset,
force push, or automatic conflict resolution to make publication succeed.

## Commit and push without replacing concurrent work

After review, confirm both the source and remote Wiki still match the prepared
inputs. Use the Wiki's existing branch; do not assume that it is named `main`.

```bash
test "$wiki_source_commit" = "$(git -C "$wiki_source" rev-parse HEAD)"
test -z "$(git -C "$wiki_source" status --porcelain)"
wiki_git -C "$wiki_checkout" fetch origin
test "$wiki_base_commit" = "$(git -C "$wiki_checkout" rev-parse '@{upstream}')"
git -C "$wiki_checkout" commit -m "docs: sync operator guide from $wiki_source_commit"
wiki_git -C "$wiki_checkout" push origin "HEAD:$wiki_branch"
```

Stop if the fetch comparison or push fails. Preserve the local commit and
reconcile concurrent remote changes explicitly; never force the push. The
normal push also rejects a conflicting remote update occurring after the fetch.

## Verify publication, then record it

Open the rendered GitHub Wiki Home page, sidebar and each of the twelve linked
guides, including the three provider-setup walkthroughs. Confirm page titles,
tables, code blocks, internal navigation, and links
to repository examples and evidence anchors. A successful Git push alone is not
rendered-page verification. Record the application source commit, Wiki commit,
publication time and actual verification result in the project handoff. Only
then replace its pending-publication wording; do not claim real-provider,
deployment or hardware acceptance from documentation publication.

Keep the owned checkout until the result is recorded. Publication does not
authorize changes to deployment, login, providers, secrets or workflows.
