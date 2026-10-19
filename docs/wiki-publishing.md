> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Publish the operator guide to GitHub Wiki

The [versioned operator and developer guide](wiki/Home.md) is usable now in this
repository or a local checkout. Its relative page links do not depend on the
separate GitHub Wiki, which has not been published. Wiki availability must not
block reading or using the guide.

The [GitHub Wiki](https://github.com/AndrewMohawk/catchplate/wiki) remains an
optional publication target for the reviewed `docs/wiki/` source. Publishing the
application repository does **not** publish its Wiki:
GitHub stores Wiki pages in a separate `catchplate.wiki.git` repository. Its
default branch supplies the live pages; the initial page must be created on
GitHub before cloning. See [GitHub's publishing instructions](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages#adding-or-editing-wiki-pages-locally).

## Resolve the recorded publication blocker

The checks below were made against the pre-rename Serverware Wiki. The repository
is now Catchplate; its rename does not prove Wiki initialization or publication.
Use the current remote above only after resolving access, and retain the old
failures as historical observations. See [rename status](catchplate-rename.md).

The [publication handoff](project-completion.md#current-checkpoint--october-13-access-continuation-and-operator-guide)
records an enabled Wiki whose authenticated Git repository returned
`Repository not found`. A fresh October 14 check confirmed `has_wiki: true`
and administrator access to the private application repository, but the Wiki
Git check using the existing GitHub CLI credential helper still returned
`Repository not found` (exit 128). The earlier browser check had no authenticated
GitHub session. Missing initialization and Wiki access remain undistinguished;
the source guides have not been published to the Wiki. The October 15 late-day
recheck again confirmed `private: true`, `has_wiki: true` and administrator
access, while the authenticated Wiki Git lookup still returned the same error.
The October 16 authenticated `ls-remote` recheck again returned `Repository not
found` (exit 128); no access-state change or Wiki publication was established.

An authorized repository maintainer must open the Wiki while signed into
GitHub. If it offers **Create the first page**, keep the title **Home** and link
to the [versioned guide](wiki/Home.md) until the reviewed pages are published
below. Do not paste the unrendered source: its relative `.md` links target the
application repository, not Wiki routes. This is a one-time
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
was not returned by the authenticated account API, so plan eligibility is a
check, not a diagnosed cause
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
wiki_publish_dir=$(mktemp -d /srv/catchplate-fast/tmp/catchplate-wiki-publish.XXXXXXXX)
wiki_checkout="$wiki_publish_dir/wiki"
wiki_git clone https://github.com/AndrewMohawk/catchplate.wiki.git "$wiki_checkout"
wiki_branch=$(git -C "$wiki_checkout" branch --show-current)
wiki_base_commit=$(git -C "$wiki_checkout" rev-parse HEAD)
test -n "$wiki_branch"
test -z "$(git -C "$wiki_checkout" status --porcelain)"
```

Run each block only if the preceding checks succeeded. A clone failure is a
stop, not permission to create a replacement repository or reuse another
publisher's checkout. Preserve the fresh directory for diagnosis.

## Render and review exactly the maintained pages

These thirteen guides plus `_Sidebar.md` are the publication allowlist. Do not use
`rsync --delete`, remove other Wiki pages, or copy the whole application checkout.
Source navigation uses `Page.md#section`. The bounded renderer below changes
only known sibling-page links to Wiki URLs in the isolated checkout, preserving
fragments, external links and repository/evidence links. The source stays
unchanged. It needs Node.js (built-in modules only), not an application build or
package installation. Render all pages successfully before staging any changes.

```bash
wiki_pages=(
  Home.md Getting-started.md Credentials-and-providers.md Clients-and-recipes.md
  GitHub-App-setup.md OAuth-provider-setup.md Custom-API-credentials.md
  Permissions-and-policies.md Proxy-and-CA.md Notifications-and-audit.md
  Operations-and-maintenance.md Troubleshooting.md Capability-matrix-and-glossary.md
  _Sidebar.md
)
node - "$wiki_source" "$wiki_checkout" "${wiki_pages[@]}" <<'JS'
const fs = require('node:fs');
const path = require('node:path');
const [source, checkout, ...pages] = process.argv.slice(2);
const known = new Set(pages);
if (pages.length !== 14 || known.size !== 14 ||
    pages.some(page => !/^[A-Za-z0-9_-]+\.md$/.test(page))) {
  throw new Error('Unexpected publication page allowlist');
}
const rendered = pages.map(page => {
  const input = path.join(source, 'docs/wiki', page);
  const output = path.join(checkout, page);
  const stat = fs.lstatSync(input);
  let outputStat;
  try { outputStat = fs.lstatSync(output); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 128 * 1024 ||
      (outputStat && !outputStat.isFile())) {
    throw new Error('Unsafe or oversized publication page: ' + page);
  }
  const text = fs.readFileSync(input, 'utf8').replace(
    /\]\(([A-Za-z0-9_-]+\.md)(#[^\s)]*)?\)/g,
    (_match, target, fragment = '') => {
      if (!known.has(target)) throw new Error('Unknown guide page: ' + target);
      return '](https://github.com/AndrewMohawk/catchplate/wiki/' +
        target.slice(0, -3) + fragment + ')';
    }
  );
  return {output, text};
});
for (const {output, text} of rendered) fs.writeFileSync(output, text);
JS
git -C "$wiki_checkout" add -- "${wiki_pages[@]}"
git -C "$wiki_checkout" diff --cached --check
git -C "$wiki_checkout" diff --cached --stat
git -C "$wiki_checkout" diff --cached -- "${wiki_pages[@]}"
```

Inspect the complete diff before continuing, including converted navigation.
Wiki-only edits are not disposable: if rendering replaces a newer explanation or another maintainer's work, stop,
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
