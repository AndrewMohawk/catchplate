> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Publish the operator guide to GitHub Wiki

The [versioned operator and developer guide](wiki/Home.md) is usable now in this
repository or a local checkout. It is also published to the separate
[Catchplate Wiki](https://github.com/AndrewMohawk/catchplate/wiki). The versioned
files remain authoritative and reviewable; updating them does not automatically
update the Wiki.

Publishing the application repository does **not** publish its Wiki:
GitHub stores Wiki pages in a separate `catchplate.wiki.git` repository. Its
default branch supplies the live pages. See [GitHub's publishing instructions](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages#adding-or-editing-wiki-pages-locally).

## Current publication state

The public Wiki was initialized and the reviewed pages were published on
November 6, 2026. Clone and fast-forward the existing Wiki repository for
updates. If Git access fails, investigate the existing repository or credentials;
do not create a replacement repository, request a secret in chat, or force-push
around concurrent work.

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

These fourteen guides plus `_Sidebar.md` are the publication allowlist. Do not use
`rsync --delete`, remove other Wiki pages, or copy the whole application checkout.
Source navigation uses `Page.md#section` for Wiki siblings and relative paths
for versioned repository documents and examples. The bounded renderer below
changes known sibling-page links to Wiki URLs and resolves repository-relative
Markdown files to public `blob/main` URLs in the isolated checkout. It preserves
fragments and external links. The source stays unchanged. It needs Node.js
(built-in modules only), not an application build or package installation.
Render all pages successfully before staging any changes.

```bash
wiki_pages=(
  Home.md How-Catchplate-works.md Getting-started.md Credentials-and-providers.md Clients-and-recipes.md
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
if (pages.length !== 15 || known.size !== 15 ||
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
  const siblingLinks = fs.readFileSync(input, 'utf8').replace(
    /\]\(([A-Za-z0-9_-]+\.md)(#[^\s)]*)?\)/g,
    (_match, target, fragment = '') => {
      if (!known.has(target)) throw new Error('Unknown guide page: ' + target);
      return '](https://github.com/AndrewMohawk/catchplate/wiki/' +
        target.slice(0, -3) + fragment + ')';
    }
  );
  const text = siblingLinks.replace(
    /\]\(((?:\.\.\/)+(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.md)(#[^\s)]*)?\)/g,
    (_match, target, fragment = '') => {
      const repositoryPath = path.posix.normalize(path.posix.join('docs/wiki', target));
      const repositoryFile = path.join(source, ...repositoryPath.split('/'));
      const repositoryStat = fs.lstatSync(repositoryFile);
      if ((!repositoryPath.startsWith('docs/') && !repositoryPath.startsWith('examples/')) ||
          repositoryPath.includes('..') || !repositoryStat.isFile() || repositoryStat.isSymbolicLink()) {
        throw new Error('Unsafe repository guide link: ' + target);
      }
      return '](https://github.com/AndrewMohawk/catchplate/blob/main/' +
        repositoryPath + fragment + ')';
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

Open the rendered GitHub Wiki Home page, sidebar and each of the thirteen linked
guides, including the three provider-setup walkthroughs. Confirm page titles,
tables, code blocks, internal navigation, and links
to repository examples and evidence anchors. A successful Git push alone is not
rendered-page verification. Record the application source commit, Wiki commit,
publication time and actual verification result in the project handoff. Only
then replace its pending-publication wording; do not claim real-provider,
deployment or hardware acceptance from documentation publication.

Keep the owned checkout until the result is recorded. Publication does not
authorize changes to deployment, login, providers, secrets or workflows.
