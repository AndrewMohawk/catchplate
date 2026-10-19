# Set up a GitHub App for issue reads

[Home](Home.md) · [Credentials](Credentials-and-providers.md) · [Client recipes](Clients-and-recipes.md)

This example lets a workload read issues and comments in one repository without
receiving a GitHub credential. The **GitHub App** is the provider integration;
the **Catchplate client** is your script or CI job. They have different IDs and
credentials.

You need permission to register/install an App for the repository's owner.
Catchplate must offer GitHub App connections and approve `https://api.github.com`
under **Proxy setup**. Installation grants GitHub-side access; a separate
Catchplate permission grants the workload access.

## 1. Register a read-only App in GitHub

For this example, create the App under the account that owns the repository:
your personal account, or the organization's settings if you have the required
management rights.

1. Open that account's **Settings → Developer settings → GitHub Apps**, then
   start a new registration.
2. Pick a unique, descriptive name and a homepage URL, such as your Catchplate
   console or documentation URL.
3. This connection uses installation authentication, not user OAuth: leave the
   callback/setup URLs unused and do not enable user authorization or device
   flow. Disable the webhook's **Active** checkbox; this read job needs no
   webhook receiver.
4. Set the permissions described below, restrict installation to the owning
   account, then create the App.

These choices follow GitHub's [registration procedure](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app).

Set repository **Issues** access to **Read-only** and keep
the required read-only Metadata access. Do not add Contents, Actions,
administration, organization or account permissions for this job. GitHub's
[issue-list endpoint](https://docs.github.com/en/rest/issues/issues#list-repository-issues)
supports installation tokens with Issues read access. If you later need
Catchplate's create-issue/comment preset, review that as a separate write grant;
broader provider permissions alone do not enable it.

## 2. Install it and copy the App ID

Open the App's settings, choose **Install App**, and install it on the account
containing your repository. Choose **Only select repositories**, select just
the intended repository, and complete installation. Follow any required
organization approval rather than requesting broader access. [GitHub installation instructions](https://docs.github.com/en/apps/using-github-apps/installing-your-own-github-app).

- **App ID:** the numeric App ID shown in the App's settings. Do not copy its
  OAuth client ID. [GitHub's App/installation identity guide](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation).
- **Installation ID:** you normally do not need to find this. Catchplate
  discovers and verifies the existing installation for your App and repository
  when you save. If you already know the ID and want to require an exact match,
  enter it under **Advanced: specify an installation ID**. This is the
  installation's ID, not the repository ID.

## 3. Generate a private key and save the connection

In the App's settings, open **Credentials → Key pairs → New key** and securely
retain the downloaded PEM. GitHub's current [private-key instructions](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps#generating-private-keys)
describe this flow; older GitHub screens may call it **Generate a private key**.
Never put the PEM in the example project, a workflow secret, chat or a screenshot.

In Catchplate, open **Credentials → GitHub App** and fill in:

The expandable **Connect a GitHub App installation** guide links to the provider
instructions if you still need to register or install the App. Field-format
hints remain visible while that guide is closed.

| Catchplate field | Value for this example |
| --- | --- |
| Credential name | A useful label, such as `Issue reader — team repository` |
| GitHub App ID | The numeric App ID from GitHub |
| Repository owner / name | Exact owner and repository name, entered separately; no URL or `.git` suffix |
| Maximum issue permission for this connection | **Read issues and comments** |
| GitHub App private key (PEM) | Complete downloaded private-key PEM, including its boundary lines |
| Advanced: Installation ID (optional) | Leave blank for automatic discovery, or supply the numeric ID to require an exact match |

Choose **Save and verify GitHub App**. This contacts GitHub to check the App,
installation, repository and permission and obtain a scoped installation token
before saving. Catchplate encrypts the private key and renews installation tokens
server-side. The verified installation ID is saved and stays pinned during
renewal and key replacement; automatic discovery applies only to initial setup.
Catchplate does not install the App or add repositories. Saving creates no
Catchplate client or permission. The form clears
the PEM; it is not available in client configuration. [Implemented connection contract](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-github-client-compatibility.md#operator-journey).

## 4. Give one client read access and run it

1. On the saved credential, choose **Use with a client**. Create or select the
   workload's Catchplate client. Keep the tab open until its new one-time token
   is saved in the private configuration; copying the raw token is optional.
2. Grant **Read issues and comments** for the saved repository. Wait for the
   permission to become active; provider verification is not policy activation.
3. Stay on setup's final screen and download its private client configuration
   and public CA together. If returning later, select that client/permission in
   **Proxy setup → Connect a client**; the old one-time token is not recoverable.
4. Choose a language under **Run a prepared example** and follow its preparation
   and run commands. The [GitHub Node/Python/Go recipes](Clients-and-recipes.md#nodejs-python-and-go-read-github-issues)
   consume the complete file with `--config`; no owner, repository or proxy-login
   variables need retyping. Prepare dependencies before supplying the private file.
5. Check the read result and its matching **Audit log** outcome. An empty issue
   list can be a valid result. Treat private-repository output as private.

`CATCHPLATE_APP_ID` is now the **Catchplate client's UUID**, not either GitHub ID.
The SDK gets a public dummy value; the proxy substitutes the authorized provider
credential. The workload receives no App PEM, JWT or installation token. Its
Catchplate proxy token still expires independently of GitHub-token renewal.

## Alternative: use a personal access token

For the same read job, create a fine-grained PAT in your GitHub personal settings
under **Developer settings → Personal access tokens → Fine-grained tokens**.
Choose an expiry, the correct resource owner, only the intended repository and
Issues read access. If organizational approval is required, wait for it. Check
GitHub's [PAT creation instructions and limitations](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token)
before selecting this alternative.

In Catchplate choose **GitHub → Personal access token** and save its name and
token, then follow step 4 above. PAT saving does not verify GitHub access or renew
the token. The same separate client permission and proxy/CA setup are required;
do not put the PAT in the SDK's environment.

## Rotate the App key without rebuilding access

Generate another key for the **same GitHub App**, retaining the old key during
the change. GitHub supports overlapping keys and requires explicit deletion of
retired keys. [GitHub key management](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps).

In **Credentials**, use **Replace GitHub App private key** when offered. Review
the saved repository and affected clients, submit the new PEM, inspect the saved
result and run a permitted read. Then retire the old key in GitHub separately.
Catchplate retains the credential, clients and permissions; this operation does
not revoke already-issued GitHub tokens or recall in-flight requests. After a
lost response, inspect saved state instead of submitting again. [Replacement procedure](Operations-and-maintenance.md#replace-a-github-app-private-key-without-losing-assignments).

## Troubleshooting and verification scope

- **App option unavailable:** check the advertised capability and approved
  `api.github.com` destination; a generic key is not an App-connection substitute.
- **Verification refused:** recheck numeric IDs, matching App PEM, installation
  repository selection, Issues rights and organization approval. Never paste
  secrets into an error report or repeatedly submit after an uncertain result.
- **Provider permissions changed:** existing installations must approve added
  rights. Catchplate's saved connection ceiling and client permissions remain
  separate. [GitHub permission changes](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app#about-changes-to-permissions).
- **Saved but the client is refused:** check client-token expiry/login mode,
  exact repository, loaded policy and both TLS trust paths; see
  [Troubleshooting](Troubleshooting.md).

The repository records [isolated App-through-proxy SDK verification](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-github-app-verification.md),
not a successful job against your GitHub installation. This guide was checked
against the current Catchplate fields and official GitHub documentation; writing
it did not create an App, contact an authenticated provider API or verify a real
GitHub job. Finish with your intended read and its audit outcome.
