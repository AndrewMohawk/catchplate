# Credentials and providers

[Home](https://github.com/AndrewMohawk/serverware/wiki/Home) · [Supported capabilities](https://github.com/AndrewMohawk/serverware/wiki/Capability-matrix-and-glossary) · [Rotation and reauthorization](https://github.com/AndrewMohawk/serverware/wiki/Operations-and-maintenance)

A credential is a provider account or key stored by Serverware. It is not your console login or a client's proxy token. Saving one grants no client access.

## Save once, assign separately

Open **Credentials → Add credential**, choose the provider, enter a descriptive name and complete its form. After saving, choose **Back to Credentials** to stop, or **Set up access for a client** to assign it. A saved card's **Use with a client** reuses that exact credential without retrieving or reentering its secret.

Provider options are capability-dependent. An unavailable destination or unsupported operation must be configured first; saving a manual key does not turn it into a provider-specific connection. Response filtering belongs to a permission, not credential storage. [Shared editor](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/workspace_connect.js).

## GitHub: personal access token or GitHub App

**Personal access token:** choose **GitHub → Personal access token**, name it and enter a token limited to the intended repository and Issues rights. Saving does not check its provider validity or renew it.

**GitHub App:** first create/install the App in GitHub for the required repository. In Serverware choose **GitHub → GitHub App**, then supply:

- A connection name.
- Numeric GitHub **App ID**, not its OAuth client ID.
- Numeric installation ID.
- Exact repository owner/name.
- The connection's maximum Issues access: read, or read/create.
- The App private-key PEM.

**Save and verify GitHub App** contacts GitHub to verify the App, installation, repository and permission before saving. Unlike a plain key save, it is a provider operation. Serverware holds the private key and renews scoped installation tokens server-side. Your SDK receives neither the PEM nor an installation token.

Then assign **Read issues and comments** or **Read and create issues/comments** to a client. A read-only App cannot grant writes. App IDs and installation IDs are not Serverware client IDs. Existing provider-side permissions do not override the narrower Serverware grant. [GitHub contract and key replacement](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-github-client-compatibility.md).

## Google: connect an account for Gmail reads

1. The proxy operator configures the Google OAuth application under **Proxy setup**; see [provider application setup](https://github.com/AndrewMohawk/serverware/wiki/Proxy-and-CA).
2. In **Credentials → Add credential**, choose Google when available, label the account, and use **Continue to Google**.
3. Return to Serverware and let it reconcile the exact saved account. If the result is uncertain, use the offered status check rather than starting another consent attempt.
4. Explicitly use that account with a client and grant **Read Gmail**. Choose **Official Gmail SDK** for the supplied Node/Python/Go projects, or the supported custom HTTP option for your own client.

Do not paste Google access or refresh tokens into a manual-key form. The current profile is Gmail read-only, not Calendar, Drive, mail sending or arbitrary Google APIs. A saved account can remain visible even if this instance cannot offer its Gmail client-access bundle; saving it alone grants nothing. Serverware manages provider-token renewal, but that does not renew the client's Serverware token or prove current provider health.

For an existing account needing fresh consent, use **Reauthorize Google** when offered; do not disconnect it merely to renew consent. See [reauthorization](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-google-reauthorization.md) and the [Gmail job contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-gmail-job-verification.md).

## npm: choose the grant that matches the job

Choose **npm** and store a least-privilege token for the intended registry packages. Saving neither verifies nor renews it. Provider-side expiration and publication requirements still apply.

After assigning a client, choose separately:

- **Read package metadata** for metadata lookup only.
- **Install packages and run npm audit** for listed packages and their explicitly listed dependency closure, including the supported registry tarballs and npm advisory request.
- **Publish package** for one exact package/tag, optionally restricted to daily UTC hours.

A metadata grant does not permit installation, and installation does not permit publication. Serverware does not discover and grant all transitive dependencies automatically. One client cannot combine conflicting active registry grants. [Metadata](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-npm-metadata.md), [installation](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-npm-install.md), [publication](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-npm-publish.md).

## X: app-only lookup and account posting are different credentials

For **X · username lookup**, store the app-only bearer token—not a user OAuth token, API secret or full Authorization header. Assign one exact lowercase username, without `@`, URL or wildcard. This preset cannot post.

Account-authorized text posting is a separate managed OAuth flow, offered only when the operator has configured X and the instance advertises the matching capability. Connect the account through that flow, then assign the text-posting permission explicitly. It is not enabled by importing an app-only bearer token. Where advertised, a daily posting-attempt limit is shared across clients using the verified X account; uncertain attempts still count. No media, replies or arbitrary X API access is implied. [Read preset](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-provider-presets.md), [account lifecycle](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-x-account-lifecycle.md), [shared quotas](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-x-posting-quotas.md).

## Alchemy: selected-chain status reads

Choose **Alchemy · chain status** and enter only the API/access key—not a URL, wallet key, Notify token or Authorization header. Assign the client one approved chain, Ethereum mainnet or Sepolia. The preset allows `eth_chainId` and `eth_blockNumber` with empty parameters; it does not sign/send transactions or grant general JSON-RPC access. Saving the key does not verify provider entitlement. [Alchemy contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-provider-presets.md#fixed-x-and-alchemy-contracts).

## Manual API key: Bearer or custom header

Choose **Manual API key**, name the credential, and select how the provider expects it: a Bearer token or one custom header such as `X-API-Key`. Enter the provider secret without inventing an OAuth lifecycle. Later, a permission selects automatic insertion or exact public-dummy replacement, the approved origin, exact path and methods. This covers supported JSON APIs, not every authentication scheme, SDK or webhook. [Ordinary JSON contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/ordinary-client-compatibility.md).

## AWS: storage only

When offered in **Credentials**, select **AWS credentials — storage only**. Store either a long-term access-key pair, or the complete temporary tuple: access key ID, secret, session token and future UTC expiry. Imported sessions are not renewed automatically.

These encrypted credentials cannot currently be assigned to client permissions or used for ECR publishing. Do not put them into a generic custom-header rule as a workaround. AWS removal is local storage removal, not AWS-side revocation. [AWS storage boundary](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-aws-credentials.md).
