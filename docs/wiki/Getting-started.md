# Get your first client working

[Home](Home.md) · [Provider choices](Credentials-and-providers.md) · [Client recipes](Clients-and-recipes.md)

Use a small, read-only job first: for example, a script that reads issues from one GitHub repository. You need console access, a provider credential with the required provider-side rights, and a client environment that can reach the advertised proxy.

Do not enter secrets in chat, issue comments or checked-in example files. The provider secret goes into the authenticated **Credentials** form. The workload receives only its own Serverware proxy token.

Need to create the provider integration first? Use the [GitHub App walkthrough](GitHub-App-setup.md) or [Google/X OAuth setup](OAuth-provider-setup.md). For your own JSON API, use the [custom Bearer/header example](Custom-API-credentials.md).

## 1. Save the provider credential

1. Open **Credentials** and choose a provider directly. GitHub personal access tokens and GitHub Apps have separate choices.
2. Paste the key or complete the provider's required details. The suggested credential name is already filled in; change it if you want.
3. Choose **Save credential** and review the saved result. No client, proxy token or permission is created. Ordinary key forms also support Enter to save.

For Google, use the offered consent flow instead of pasting access or refresh tokens into the manual-key form. If the provider is unavailable, follow [provider setup](Proxy-and-CA.md); do not imitate a missing provider preset with a generic key.

## 2. Assign a client

1. On the saved credential, choose **Use with a client**, or choose **Set up access for a client** from the saved receipt.
2. Select an existing client, or create one named after the workload, such as `Issue triage worker`.
3. For a new client, choose an appropriate token lifetime and save the token privately when it is shown once. The default is 30 days; available lifetimes range from one hour to 90 days.
4. Keep the page open until you have downloaded the client configuration in step 4 below. Then use the explicit save-and-clear action. Reloading cannot recover the token.

Selecting a saved credential reuses its exact identity; you do not need to reenter the provider secret. Several clients can share a credential while keeping separate tokens and permissions. Creating a client identity alone grants no access.

## 3. Grant only the needed operation

1. Choose a provider preset, such as **Read issues and comments**.
2. Enter the exact scope it requests: for GitHub, repository owner and name.
3. Review the credential, client and permitted action, then explicitly save the permission.
4. Wait for the exact saved policy to be active. **Saved · activation pending** is not the same as **Active**; use **Refresh activation** if needed.

For supported JSON jobs, you do not need request/response field lists unless you want optional content restrictions. The preset supplies its supported defaults. Existing restricted permissions are not silently broadened. See [Permissions](Permissions-and-policies.md).

## 4. Configure the actual client

1. Open **Proxy setup** and select the client and permission.
2. Copy the advertised proxy endpoint; the console address is not the forward proxy.
3. Choose **Download CA certificate**. Trust this public CA only in the intended client, with TLS verification still enabled.
4. Select the matching recipe or connection template. For the supplied SDK examples, prepare dependencies using that project's README before supplying the client token.
5. For the supplied GitHub, Gmail, npm, Alchemy and X examples, choose **Download private client config** while the page still holds the token. Save it beside the CA and run the prepared example with `--config /path/serverware-client.private.json`. The example imports its proxy login and saved scope, so those values need not be retyped.
6. Alternatively, supply the client token privately as `SERVERWARE_PROXY_TOKEN` and follow the environment-based recipe. Never substitute the real provider secret. Posting and publishing always require their separate explicit local inputs and confirmation.

**Download private client config** is available only while the page holds the matching one-time token. The download contains that token: keep it private and out of Git. A copied recipe or downloaded config does not execute a request.

## 5. Check the job and its audit outcome

Run the intended read from the environment where the client will actually run. Confirm its result, then open **Audit log** and find the matching client/permission outcome. A rendered page, a successful save or a green policy status alone does not verify the whole job.

For an owned disposable test client, you can also verify removal of access: revoke its permission, wait for revocation to be enforced, and repeat the same read expecting refusal. Do not revoke a shared production permission just to test the interface. Already-dispatched requests cannot be recalled.

If a save or provider write times out, use [uncertain-result recovery](Troubleshooting.md) rather than repeating it automatically.

## Optional synthetic check

Resources used only for the local connection check appear in collapsed **Connection-check resources** sections on the Credentials, Clients and Permissions pages. They do not count toward ordinary setup progress. To reuse one deliberately, expand its section and choose **Use with a client**, or enable **Include saved connection-check resources** in setup. Revoked records remain in a separate history section; nothing is deleted or disabled by this grouping.

**Overview → Diagnostics → Inspect synthetic connection check** shows explicitly selected saved fixture permissions. It does not create resources, renew tokens or send a request. Only use made-up provider keys for this fixture; it is not Google, GitHub or npm acceptance. Follow the existing [diagnostic walkthrough](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-demo.md#optional-diagnostic-connection-check) if you want this separate test.

Sources: [operator walkthrough](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-demo.md), [GitHub contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-github-client-compatibility.md), [client lifecycle implementation](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/workspace_applications.js).
