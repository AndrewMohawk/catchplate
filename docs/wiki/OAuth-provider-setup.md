# Google and X OAuth setup

[Home](Home.md) · [Credentials](Credentials-and-providers.md) · [Proxy setup](Proxy-and-CA.md) · [Client recipes](Clients-and-recipes.md)

OAuth setup has three separate steps:

| Step | Who does it | Result |
| --- | --- | --- |
| Configure the provider application | Catchplate operator | Stores the provider-issued OAuth client ID and secret for this instance |
| Connect an account | The account owner, through provider consent | A saved Google/X credential; no client permission yet |
| Grant client access | The operator/user managing permissions | An explicit supported permission; create a Catchplate client and its proxy token only if needed |

An OAuth **client ID** identifies Catchplate to Google/X. A Catchplate **client ID** identifies your script, service or CI job to the proxy. They are not interchangeable. Provider secrets and account tokens stay on the server; do not put them in recipes, GitHub Actions variables, screenshots or this wiki.

The October 13 deployment checkpoint records **Google and X as unconfigured**. The steps below describe available workflows, not completed real-provider acceptance. Check the current UI before proceeding. [Deployment record](https://github.com/AndrewMohawk/catchplate/blob/main/docker/catchplate-operator-demo/README.md#current-checkpoint--october-13-access-continuation-update).

## Google: operator application setup

1. Sign in as a Catchplate administrator. Open **Proxy setup → Google provider settings → Review Google provider settings**. Copy its exact authorized redirect URI. Its path is `/api/oauth/callback/google` on the public console origin—not the forward-proxy hostname.
2. In your Google Cloud project, enable the **Gmail API**. Configure **Google Auth platform → Branding, Audience and Data Access**, declaring the fixed scopes below. Choose the appropriate audience; when testing an external app, add the intended Google accounts as test users. [Google's consent setup](https://developers.google.com/workspace/guides/configure-oauth-consent), [Gmail API enablement](https://developers.google.com/workspace/gmail/api/quickstart/python#enable_the_api).
3. Under **Google Auth platform → Clients**, create a **Web application** OAuth client. Register the exact Catchplate redirect URI, including scheme, hostname and path. This is not a desktop client or service-account setup. Keep the resulting client ID and secret private. [Google's web-server client setup](https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred).
4. Back in Catchplate, enter **Google OAuth client ID** and **Google OAuth application secret**. Review the displayed callback, scopes and proposed `https://gmail.googleapis.com` destination. Select **Prepare Google configuration** once.
5. Preparation stores inactive encrypted configuration. The deployment owner must perform the separately controlled app/proxy cold restart and verify the exact prepared configuration. Refresh the review until it reports activated **and** the matching pair ready for consent. Preparation alone does not restart anything or contact Google. [Managed activation procedure](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-provider-configuration.md#operator-configuration-workflow).

The fixed `gmail_readonly` profile requests exactly:

```text
email
https://www.googleapis.com/auth/gmail.readonly
openid
```

These scopes cover Gmail reading and account identity; they do not configure Drive, Calendar, sending mail or arbitrary Google APIs. Gmail read-only is a restricted scope: review Google's verification requirements before offering the app beyond its intended test/internal audience. External apps left in **Testing** receive seven-day refresh tokens for this Gmail profile; automatic renewal does not remove that provider limit. [Gmail scope requirements](https://developers.google.com/workspace/gmail/api/auth/scopes), [Google refresh-token expiration](https://developers.google.com/identity/protocols/oauth2/#expiration).

If Prepare's response is lost, use **Check operation result (read only)**; do not submit another Prepare. This first-configuration form is not a secret-rotation or OAuth-client replacement tool. Do not combine managed configuration with the legacy external-secret-file deployment recipe.

## Google: connect or reauthorize an account

1. When consent is available, open **Credentials** and choose the Google account connection, enter an account label, then **Continue to Google**. This is separate from a Google Gemini API key. Save and clear any one-time Catchplate client token before navigating away.
2. Choose the intended Google account and consent. Return to the same Catchplate console and inspect the saved account; use **Refresh Google status** if the result is uncertain. Do not paste access/refresh tokens or manually replay a callback URL.
3. Select **Use this credential for a client** and grant **Read Gmail** separately. Choose **Official Gmail SDK** for the supplied Node/Python/Go examples, then configure the proxy token and CA. The supported client operations are message listing and message reads, not the entire Gmail API. [Gmail job contract](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-gmail-job-verification.md).

For an existing account needing fresh consent, use its **Reauthorize Google** action when offered. Review the same account and affected clients, then continue to Google. Use **Check saved status** after returning. Successful reauthorization preserves the credential identity, existing permissions and Catchplate client tokens; it neither expands access nor renews those client tokens. A pending replacement is not active until confirmed. Missing eligibility, changed assignments or a provider-configuration error needs operator review—not disconnect-and-add or repeated consent. [Reauthorization contract](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-google-reauthorization.md).

## X: operator application setup

1. In **Proxy setup → X (Twitter) application**, select **Review X application settings**, then **Copy callback URL**. The exact path is `/api/oauth/callback/x` on the public console origin.
2. In your X developer application's authentication settings, enable **OAuth 2.0** and use a confidential application type, such as **Web App** or **Automated App or bot**. Register the exact callback URL. Obtain the OAuth **Client ID** and **Client secret** from the application's keys/settings—not an API key/secret pair or app-only bearer token. Follow the official guide for the current developer-console controls. [X OAuth application setup](https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code#app-settings).
3. Enter those two fields in Catchplate and choose **Save X application** once. This saves settings immediately, without a restart. It does not contact X, add an approved proxy destination, connect an account or grant posting.
4. Confirm `https://api.x.com` is approved under **Proxy destinations** and the matching loaded app/proxy policy is ready. Destination changes have their own reviewed activation procedure. Continue only when the account-consent capability is offered. [Proxy destinations](Proxy-and-CA.md#let-the-proxy-reach-a-new-provider).

The fixed `x_text_post_v1` profile uses PKCE and a confidential client secret, with exactly:

```text
offline.access
tweet.read
tweet.write
users.read
```

`offline.access` supports provider-token renewal; it does not extend the separate Catchplate client token. X API entitlement remains a separate provider requirement. Catchplate does not offer replacement of a saved X application here. Recover an uncertain save with **Check result**, never another Save. [Configuration contract](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_x_oauth_profile.py), [configuration UI](https://github.com/AndrewMohawk/catchplate/blob/main/catchplate/operator_demo_web/workspace_x_configuration.js).

## X: connect an account and grant posting

In **Credentials → Connect an X account**, enter a connection name and choose **Continue to X** when enabled. Save any one-time Catchplate client token before leaving. Consent authorizes the saved OAuth application; it does not publish anything. After consent, choose **Return to Catchplate**. Use **Check result** until the saved account is confirmed, then **Acknowledge result**, complete **I reviewed the saved state**, and select **Use this account**.

Grant **Publish text as this X account** to a client separately. The supported operation is text-only `POST /2/tweets`; no media, replies, quotes, threads or general X API access. An optional daily posting-attempt limit is shared across clients using the verified account. Follow the [posting examples and limits](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-x-posting.md); never automatically repeat an uncertain post.

Automatic refresh is supported, but there is no Google-style **Reauthorize** action for X. If recovery is needed, inspect the retained operation/account status with the deployment operator. **Review X disconnect** is a separate protective action affecting the listed connections and permissions for that X client/account—not in-place reauthorization or a harmless refresh button. [X account lifecycle](https://github.com/AndrewMohawk/catchplate/blob/main/docs/operator-x-account-lifecycle.md).

**X · username lookup** is a different app-only bearer credential. It does not use this account-consent flow and cannot authorize posting.

## If setup is unavailable

- A hidden/disabled provider action is not fixed by storing its OAuth secret as a manual API key. Ask the deployment operator to review the advertised capability, pending configuration, approved destination and exact loaded policy.
- A redirect mismatch means the provider registration and displayed callback differ; do not substitute the proxy URL or loosen callback validation.
- Saved configuration, consent, loaded policy and a successful provider job are separate checkpoints. Verify the intended client operation after setup; none of these forms performs that test for you.
