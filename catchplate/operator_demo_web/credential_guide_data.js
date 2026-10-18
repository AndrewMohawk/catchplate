// Contextual acquisition help, not credential validation or authorization policy.
// Keep provider links public and free of account identifiers or secret values.
const operatorCredentialGuides = Object.freeze({
  github_token: {
    title: 'Get a GitHub personal access token',
    steps: [
      'In GitHub Settings → Developer settings → Personal access tokens, create a fine-grained token with an expiry.',
      'Choose the repository owner and only the repositories you need. Set Issues to Read-only for reads, or Read and write for creating issues and comments.',
      'Copy the generated token here. Your organization may need to approve it before it can access a private repository.'
    ],
    links: [{label: 'GitHub: create a personal access token', url: 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens'}],
    fields: {secret: {placeholder: 'github_pat_… or ghp_…', hint: 'Example prefixes only. Paste the complete token without Bearer, quotes or a command. For an App private key, choose GitHub App instead.'}}
  },
  github_app: {
    title: 'Connect a GitHub App installation',
    steps: [
      'Register a GitHub App in Developer settings. Give it repository Issues read permission, or read and write only if you need issue/comment creation.',
      'Install the App on the intended account and select only the repositories it should access.',
      'In the App settings, copy its App ID and generate a private key. Open the downloaded PEM and copy the complete contents.',
      'Enter one installed repository below. Leave Installation ID blank to let Catchplate find and verify the matching installation.'
    ],
    links: [
      {label: 'GitHub: register an App', url: 'https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app'},
      {label: 'GitHub: install your App', url: 'https://docs.github.com/en/apps/using-github-apps/installing-your-own-github-app'},
      {label: 'GitHub: generate a private key', url: 'https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps'}
    ],
    fields: {
      app_id: {placeholder: 'Numeric App ID', hint: 'Use the App ID from the GitHub App settings, not its OAuth Client ID.'},
      owner: {placeholder: 'your-organization', hint: 'The repository owner: a GitHub organization or username, without a URL.'},
      repo: {placeholder: 'your-repository', hint: 'The repository name only, without the owner or a .git suffix.'},
      private_key: {placeholder: '-----BEGIN RSA PRIVATE KEY-----\n…\n-----END RSA PRIVATE KEY-----', hint: 'Paste the complete downloaded PEM, including its BEGIN and END lines. This is not a PAT, OAuth client secret or webhook secret.'},
      installation_id: {placeholder: 'Optional: numeric installation ID', hint: 'Usually leave blank. If supplied, it must identify this App installation and match the selected repository.'}
    }
  },
  npm: {
    title: 'Get an npm granular access token',
    steps: [
      'On npmjs.com, open your profile → Access Tokens and generate a granular token with an expiry.',
      'Select only the packages or scopes you need. Use Read-only for metadata/install, or Read and write (publish and stage) only for the publishing preset.',
      'Leave organization administration disabled. For unattended publishing, review npm’s separate Bypass 2FA option; Catchplate cannot satisfy an interactive npm challenge.',
      'Copy the token value here, not an .npmrc line or your npm password.'
    ],
    links: [{label: 'npm: create a granular token', url: 'https://docs.npmjs.com/creating-and-viewing-access-tokens/'}],
    fields: {secret: {placeholder: 'Paste your npm granular token', hint: 'Paste only the token, without _authToken= or Bearer. A stage-only token does not authorize direct publishing.'}}
  },
  aws_long_term: {
    title: 'Add a dedicated AWS access key',
    steps: [
      'Prefer a short-lived AWS session when possible. If using a long-term key, create it for a dedicated IAM user, never the root user.',
      'For the ECR image preset, allow BatchCheckLayerAvailability, InitiateLayerUpload, UploadLayerPart, CompleteLayerUpload and PutImage on only the intended repository ARN.',
      'In that IAM user’s Security credentials, create an access key and copy the matching access key ID and secret access key. AWS shows the secret only when it is created.'
    ],
    links: [
      {label: 'AWS: manage IAM access keys', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html'},
      {label: 'AWS: ECR repository permissions', url: 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push-iam.html'}
    ],
    fields: {
      access_key_id: {placeholder: 'AKIA…', hint: 'Long-term access key IDs start with AKIA. Use the ID paired with the secret below, not an account ID or role ARN.'},
      secret_access_key: {placeholder: '40-character secret access key', hint: 'Use the secret issued with this access key ID. Do not paste an ECR login password or a credentials file.'}
    }
  },
  aws_session: {
    title: 'Add a temporary AWS session',
    steps: [
      'Obtain temporary credentials through your approved AWS role/session process, such as STS AssumeRole.',
      'For the ECR image preset, limit the role to BatchCheckLayerAvailability, InitiateLayerUpload, UploadLayerPart, CompleteLayerUpload and PutImage on the intended repository ARN.',
      'Copy the access key ID, secret access key, session token and expiration from the same issued session. Catchplate does not discover or automatically renew this session.'
    ],
    links: [
      {label: 'AWS: use temporary credentials', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html'},
      {label: 'AWS: ECR repository permissions', url: 'https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push-iam.html'}
    ],
    fields: {
      access_key_id: {placeholder: 'ASIA…', hint: 'Temporary access key IDs start with ASIA. Use the ID from this session, not a different long-term access key.'},
      secret_access_key: {placeholder: 'Paste this session’s secret access key', hint: 'All three credential values must come from the same AWS session.'},
      session_token: {placeholder: 'Paste the complete AWS session token', hint: 'Required for temporary credentials. Do not shorten it or paste the entire STS JSON response.'},
      expires_at: {placeholder: 'YYYY-MM-DDTHH:mm:ssZ', hint: 'Use the actual AWS expiration in UTC, ending in Z. Entering a later time cannot extend the session.'}
    }
  },
  x: {
    title: 'Get an X app-only bearer token',
    steps: [
      'Open your app in the X Developer Console and find its Keys and tokens settings.',
      'Copy its app-only Bearer Token. Your X API access and billing must permit the username lookup endpoint.',
      'Use this credential for app-only username lookup. To post as an account, connect an X account through OAuth instead.'
    ],
    links: [{label: 'X: app-only bearer tokens', url: 'https://docs.x.com/fundamentals/authentication/oauth-2-0/bearer-tokens'}],
    fields: {secret: {placeholder: 'Paste the app-only bearer token', hint: 'The token value only, without Bearer. Not an API key/secret pair, OAuth Client ID or account password.'}}
  },
  alchemy: {
    title: 'Get an Alchemy app API key',
    steps: [
      'In the Alchemy Dashboard, open Apps and create or choose an app for this use.',
      'Enable Ethereum and the intended supported network: Mainnet or Sepolia. Catchplate’s preset reads chain ID and block number.',
      'Copy the API key from the app details page, not its HTTP or WebSocket endpoint URL.'
    ],
    links: [{label: 'Alchemy: create an API key', url: 'https://www.alchemy.com/docs/create-an-api-key'}],
    fields: {secret: {placeholder: 'Paste your Alchemy app API key', hint: 'Only the key value. Do not paste the full RPC URL, a wallet private key or a seed phrase.'}}
  },
  manual: {
    title: 'Add a key for another API',
    steps: [
      'Open your provider’s official API documentation and credential settings to create a key for this use.',
      'Limit the key to the required resources and operations. Choose Bearer token or API-key header to match the provider’s documented authentication.',
      'Paste the secret value here. Saving a credential does not grant client access: add a permission for the exact destination and request you want to allow.'
    ],
    links: [],
    fields: {secret: {placeholder: 'Paste the provider’s secret value', hint: 'Do not paste a curl command, JSON credentials document or account password. For Bearer authentication, omit the Bearer prefix.'}}
  },
  google: {
    title: 'Connect a Google account for Gmail',
    steps: [
      'Your Catchplate operator must configure and activate a Google OAuth application first. A Gemini API key cannot connect a mailbox.',
      'Choose Connect Google, sign in to the intended account on Google’s consent page and review the requested Gmail read-only access.',
      'After returning here, add the client’s Gmail permission. No Google password or manually copied access token is needed.'
    ],
    links: [{label: 'Google: Gmail API scopes', url: 'https://developers.google.com/workspace/gmail/api/auth/scopes'}],
    fields: {}
  },
  x_account: {
    title: 'Connect an X account with consent',
    steps: [
      'Your Catchplate operator must configure an X OAuth 2.0 application first. An app-only bearer token is a different credential.',
      'Choose Connect X and authorize the intended account. The current connection requests tweet.read, tweet.write, users.read and offline.access.',
      'After consent, grant the client its text-post permission separately. App-only username lookup uses the other X credential type. Do not copy account tokens or enter your X password here.'
    ],
    links: [{label: 'X: account authorization and scopes', url: 'https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code'}],
    fields: {}
  },
  google_application: {
    title: 'Set up the operator’s Google OAuth application',
    steps: [
      'In a Google Cloud project, enable the Gmail API and configure the Google Auth Platform consent screen and audience. Add test users if the app is in testing.',
      'Create an OAuth client of type Web application. Add the exact callback URL shown here as an authorized redirect URI.',
      'Copy the OAuth Client ID and Client secret into these fields. The Gmail connection requests gmail.readonly plus account identity scopes.',
      'Complete Catchplate’s configuration review and activation before connecting accounts. Google may require verification for wider use of Gmail’s restricted scope.'
    ],
    links: [
      {label: 'Google: configure consent and audience', url: 'https://developers.google.com/workspace/guides/configure-oauth-consent'},
      {label: 'Google: create a web OAuth client', url: 'https://developers.google.com/identity/protocols/oauth2/web-server'}
    ],
    fields: {
      client_id: {placeholder: '…apps.googleusercontent.com', hint: 'Use the Web application client’s ID, not a project ID, service-account email or Gemini API key.'},
      client_secret: {placeholder: 'Paste the matching OAuth Client secret', hint: 'The secret for that same Web application client, not the downloaded JSON document or a Google account password.'}
    }
  },
  x_application: {
    title: 'Set up the operator’s X OAuth application',
    steps: [
      'In the X Developer Console, enable OAuth 2.0 in your app’s user authentication settings. Choose a confidential client such as Web App.',
      'Register the exact callback URL shown here. This connection uses tweet.read, tweet.write, users.read and offline.access.',
      'Copy the OAuth 2.0 Client ID and Client Secret into these fields, then finish the configuration review. Users still need to connect and consent separately.'
    ],
    links: [{label: 'X: OAuth client setup', url: 'https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code'}],
    fields: {
      client_id: {placeholder: 'Paste the OAuth 2.0 Client ID', hint: 'Not the app ID, API key or app-only bearer token.'},
      client_secret: {placeholder: 'Paste the OAuth 2.0 Client Secret', hint: 'Use the confidential client’s secret, not the OAuth 1.0a API secret or an account access token.'}
    }
  },
  openai: {
    title: 'Get an OpenAI API key',
    steps: [
      'In the OpenAI API dashboard, choose the project for this application and create a project API key.',
      'If you restrict the key, allow creating Responses and access to the model you will select. Check the project’s API billing and limits.',
      'Copy the key here. A ChatGPT subscription or browser sign-in token is not an API key.'
    ],
    links: [
      {label: 'OpenAI: create an API key', url: 'https://developers.openai.com/api/docs/quickstart'},
      {label: 'OpenAI: key permissions', url: 'https://help.openai.com/en/articles/8867743-assign-api-key-permissions'}
    ],
    fields: {secret: {placeholder: 'Paste your OpenAI project API key', hint: 'Paste only the API key, without Bearer. You will choose the allowed model when adding a permission.'}}
  },
  anthropic: {
    title: 'Get an Anthropic API key',
    steps: [
      'Open the Claude Console’s API keys settings and create a key for the intended workspace.',
      'Choose a single-workspace key with access to the Messages API. This preset does not send the extra workspace header required by multi-workspace keys.',
      'Check that the workspace can use your selected model and has API billing available, then copy the key here.'
    ],
    links: [
      {label: 'Anthropic: get a Claude API key', url: 'https://platform.claude.com/docs/en/get-api-key'},
      {label: 'Anthropic: API authentication', url: 'https://platform.claude.com/docs/en/api/overview'}
    ],
    fields: {secret: {placeholder: 'Paste your Anthropic API key', hint: 'Use a Claude Console API key, not a Claude browser session, subscription login or cloud-provider credential.'}}
  },
  gemini: {
    title: 'Get a Gemini Developer API key',
    steps: [
      'Open Google AI Studio, select or import the intended Google Cloud project, and create an API key.',
      'Use a key enabled for the Gemini API. For an older unrestricted key, follow Google’s current restriction or replacement instructions.',
      'Copy the key here. This is the Gemini Developer API path, not Google account OAuth or Vertex AI service-account authentication.'
    ],
    links: [{label: 'Google: create and manage Gemini keys', url: 'https://ai.google.dev/gemini-api/docs/api-key'}],
    fields: {secret: {placeholder: 'Paste your Gemini Developer API key', hint: 'Use the key from Google AI Studio, not OAuth client credentials or service-account JSON.'}}
  },
  openrouter: {
    title: 'Get an OpenRouter API key',
    steps: [
      'In OpenRouter, open API Keys and create a separate key for this application.',
      'Set a provider-side credit limit and expiry, and ensure you can use the intended model. Catchplate’s per-request output limit is not a spending budget.',
      'Copy the key here. Choose a specific provider/model ID when adding the permission, not an automatic router.'
    ],
    links: [{label: 'OpenRouter: API keys and credit limits', url: 'https://openrouter.ai/docs/api_reference/authentication'}],
    fields: {secret: {placeholder: 'Paste your OpenRouter API key', hint: 'Use an OpenRouter key, not an OpenAI key or a key from the model’s own provider.'}}
  },
  slack: {
    title: 'Get a Slack bot token',
    steps: [
      'Create or open a Slack app. In OAuth & Permissions, add the Bot Token Scope chat:write.',
      'Install or reinstall the app in the intended workspace, then invite its bot to the channel it should post in.',
      'Copy the Bot User OAuth Token here. Incoming webhook URLs belong in Notifications, not this credential form.'
    ],
    links: [
      {label: 'Slack: create and install an app', url: 'https://docs.slack.dev/quickstart/'},
      {label: 'Slack: message permissions', url: 'https://docs.slack.dev/reference/methods/chat.postMessage/'}
    ],
    fields: {secret: {placeholder: 'xoxb-…', hint: 'Bot tokens commonly begin xoxb-. This is a format hint, not a prefix restriction. Paste the complete token, not a webhook URL, app-level token or Bearer prefix.'}}
  },
  discord: {
    title: 'Get a Discord bot token',
    steps: [
      'Create an application in the Discord Developer Portal and open its Bot settings to obtain a bot token.',
      'Install the bot in the intended server and allow View Channel and Send Messages in the target text channel. Administrator permission is not needed.',
      'Copy the bot token here. Resetting an existing token invalidates its old value, so coordinate with any other users of that bot.'
    ],
    links: [{label: 'Discord: create and install a bot', url: 'https://docs.discord.com/developers/quick-start/getting-started'}],
    fields: {secret: {placeholder: 'Paste the Discord bot token', hint: 'Raw bot token only; Catchplate adds Bot to the authorization header. Not a webhook URL, client secret or user token.'}}
  },
  notion: {
    title: 'Get a Notion internal connection token',
    steps: [
      'Ask a workspace owner to create an internal connection in the Notion Developer portal.',
      'Enable Read content only, then share the intended page with that connection. Creating a token alone does not give it page access.',
      'Copy the connection’s API token from its Configuration tab. Catchplate permissions separately select a page or block to read.'
    ],
    links: [
      {label: 'Notion: create an internal connection', url: 'https://developers.notion.com/guides/get-started/internal-connections'},
      {label: 'Notion: read capabilities', url: 'https://developers.notion.com/reference/capabilities'}
    ],
    fields: {secret: {placeholder: 'Paste the Notion connection API token', hint: 'The complete internal connection token, not a page URL, page ID or OAuth client secret.'}}
  },
  stripe: {
    title: 'Get a restricted Stripe read-only key',
    steps: [
      'Start in a Stripe sandbox or test environment. Open API keys and create a restricted key for this application.',
      'Give it Read permission for Balance and/or Customers, matching the preset you will use. Leave unrelated resources and write permissions disabled.',
      'Copy the restricted key here. Use a live-mode key only when you deliberately want to read live account data.'
    ],
    links: [{label: 'Stripe: API keys and restricted permissions', url: 'https://docs.stripe.com/keys'}],
    fields: {secret: {placeholder: 'rk_test_…', hint: 'Example: a test-mode restricted key. Use a live key only deliberately; publishable browser keys and webhook signing secrets cannot authorize these reads.'}}
  },
  resend: {
    title: 'Get a sending-only Resend API key',
    steps: [
      'In Resend, verify the domain you intend to send email from.',
      'Open API Keys and create a key with Sending access, restricted to that domain instead of Full access.',
      'Copy the key here. When adding a permission, select the exact sender and recipient this application may use.'
    ],
    links: [
      {label: 'Resend: manage API keys', url: 'https://resend.com/docs/dashboard/api-keys/introduction'},
      {label: 'Resend: sending-only permissions', url: 'https://resend.com/docs/api-reference/api-keys/create-api-key'}
    ],
    fields: {secret: {placeholder: 'Paste your Resend API key', hint: 'Use a sending-only API key for the verified sender domain, not an SMTP password or webhook signing secret.'}}
  },
  gitlab: {
    title: 'Get a GitLab read API token',
    steps: [
      'On GitLab.com, prefer a project access token from the project’s Settings → Access tokens when your plan supports it.',
      'Select read_api, an expiry, and a role able to read that project’s issues. Repository Git permissions alone do not authorize the issues API.',
      'If project tokens are unavailable, a personal read_api token is an alternative, but it can reach other projects your account can access.',
      'Copy the token here. The Catchplate permission will select one numeric project ID; this preset targets GitLab.com.'
    ],
    links: [
      {label: 'GitLab: create a project access token', url: 'https://docs.gitlab.com/user/project/settings/project_access_tokens/'},
      {label: 'GitLab: access token scopes', url: 'https://docs.gitlab.com/security/tokens/access_token_scopes/'}
    ],
    fields: {secret: {placeholder: 'Paste your GitLab access token', hint: 'Token value only; Catchplate supplies the PRIVATE-TOKEN header. Not a deploy token, SSH key or account password.'}}
  },
  cloudflare: {
    title: 'Get a scoped Cloudflare API token',
    steps: [
      'In the Cloudflare dashboard, open My Profile → API Tokens and create a custom API token.',
      'Use Zone → Zone → Read for zone listing, or Zone → DNS → Read for DNS-record listing. Restrict resources to the intended zones.',
      'Review the permissions and expiry, then copy the generated token. These presets do not need DNS Edit access.'
    ],
    links: [{label: 'Cloudflare: create a scoped API token', url: 'https://developers.cloudflare.com/fundamentals/api/get-started/create-token/'}],
    fields: {secret: {placeholder: 'Paste your Cloudflare API token', hint: 'Use an API token, not the Global API Key, Origin CA key or account email. Paste the token value without Bearer.'}}
  },
  sentry: {
    title: 'Get a Sentry issue-read auth token',
    steps: [
      'In your Sentry organization’s Settings → Custom Integrations, create an Internal Integration.',
      'Give it Issue & Event Read permission (event:read), then save and copy its authentication token.',
      'Use the intended organization and numeric project ID in the Catchplate permission. This preset reads issues from sentry.io.'
    ],
    links: [
      {label: 'Sentry: create an authentication token', url: 'https://docs.sentry.io/api/guides/create-auth-token/'},
      {label: 'Sentry: API permissions', url: 'https://docs.sentry.io/api/permissions/'}
    ],
    fields: {secret: {placeholder: 'Paste your Sentry authentication token', hint: 'Use an API auth token with event:read, not a project DSN or client key used to send error events.'}}
  }
});
