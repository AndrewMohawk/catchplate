# Get your first client working

[Home](https://github.com/AndrewMohawk/serverware/wiki/Home) · [Provider choices](https://github.com/AndrewMohawk/serverware/wiki/Credentials-and-providers) · [Client recipes](https://github.com/AndrewMohawk/serverware/wiki/Clients-and-recipes)

Use a small, read-only job first: for example, a script that reads issues from one GitHub repository. You need console access, a provider credential with the required provider-side rights, and a client environment that can reach the advertised proxy.

Do not enter secrets in chat, issue comments or checked-in example files. The provider secret goes into the authenticated **Credentials** form. The workload receives only its own Serverware proxy token.

Need to create the provider integration first? Use the [GitHub App walkthrough](https://github.com/AndrewMohawk/serverware/wiki/GitHub-App-setup) or [Google/X OAuth setup](https://github.com/AndrewMohawk/serverware/wiki/OAuth-provider-setup). For your own JSON API, use the [custom Bearer/header example](https://github.com/AndrewMohawk/serverware/wiki/Custom-API-credentials).

## 1. Save the provider credential

1. Open **Credentials → Add credential**.
2. Select the provider. For GitHub, choose a personal access token or an existing GitHub App installation; these have different inputs and verification behavior.
3. Give it a useful name, such as `Issue triage — GitHub`, and complete the provider form.
4. Save and review the returned credential. Saving in this mode creates no client, token or permission.

For Google, use the offered consent flow instead of pasting access or refresh tokens into the manual-key form. If the provider is unavailable, follow [provider setup](https://github.com/AndrewMohawk/serverware/wiki/Proxy-and-CA); do not imitate a missing provider preset with a generic key.

## 2. Assign a client

1. On the saved credential, choose **Use with a client**, or choose **Set up access for a client** from the saved receipt.
2. Select an existing client, or create one named after the workload, such as `Issue triage worker`.
3. For a new client, choose an appropriate token lifetime and save the token privately when it is shown once. The default is 30 days; available lifetimes range from one hour to 90 days.
4. Complete the explicit save-and-clear action after recording the token. Reloading cannot recover it.

Selecting a saved credential reuses its exact identity; you do not need to reenter the provider secret. Several clients can share a credential while keeping separate tokens and permissions. Creating a client identity alone grants no access.

## 3. Grant only the needed operation

1. Choose a provider preset, such as **Read issues and comments**.
2. Enter the exact scope it requests: for GitHub, repository owner and name.
3. Review the credential, client and permitted action, then explicitly save the permission.
4. Wait for the exact saved policy to be active. **Saved · activation pending** is not the same as **Active**; use **Refresh activation** if needed.

For supported JSON jobs, you do not need request/response field lists unless you want optional content restrictions. The preset supplies its supported defaults. Existing restricted permissions are not silently broadened. See [Permissions](https://github.com/AndrewMohawk/serverware/wiki/Permissions-and-policies).

## 4. Configure the actual client

1. Open **Proxy setup** and select the client and permission.
2. Copy the advertised proxy endpoint; the console address is not the forward proxy.
3. Choose **Download CA certificate**. Trust this public CA only in the intended client, with TLS verification still enabled.
4. Select the matching recipe or connection template. For the supplied SDK examples, prepare dependencies using that project's README before supplying the client token.
5. Supply the client token privately as `SERVERWARE_PROXY_TOKEN`. Use the displayed client ID/login mode and CA path. Follow the recipe's exact public placeholder, if any; never substitute the real provider secret.

**Download private client config** is available only while the page holds the matching one-time token. The download contains that token: keep it private and out of Git. A copied recipe or downloaded config does not execute a request.

## 5. Check the job and its audit outcome

Run the intended read from the environment where the client will actually run. Confirm its result, then open **Audit log** and find the matching client/permission outcome. A rendered page, a successful save or a green policy status alone does not verify the whole job.

For an owned disposable test client, you can also verify removal of access: revoke its permission, wait for revocation to be enforced, and repeat the same read expecting refusal. Do not revoke a shared production permission just to test the interface. Already-dispatched requests cannot be recalled.

If a save or provider write times out, use [uncertain-result recovery](https://github.com/AndrewMohawk/serverware/wiki/Troubleshooting) rather than repeating it automatically.

## Optional synthetic check

**Overview → Diagnostics → Inspect synthetic connection check** shows explicitly selected saved fixture permissions. It does not create resources, renew tokens or send a request. Only use made-up provider keys for this fixture; it is not Google, GitHub or npm acceptance. Follow the existing [diagnostic walkthrough](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-demo.md#optional-diagnostic-connection-check) if you want this separate test.

Sources: [operator walkthrough](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-demo.md), [GitHub contract](https://github.com/AndrewMohawk/serverware/blob/main/docs/operator-github-client-compatibility.md), [client lifecycle implementation](https://github.com/AndrewMohawk/serverware/blob/main/serverware/operator_demo_web/workspace_applications.js).
