//! Cold public half of operator-google-v1. The gate never opens the OAuth
//! client-secret file and this profile grants no consent or native authority.
use super::*;

pub(super) const CAPABILITY: &str = "operator-google-v1";
pub(super) const ORIGIN: &str = "https://gmail.googleapis.com";
const SCOPES: [&str; 3] = [
    "email",
    "https://www.googleapis.com/auth/gmail.readonly",
    "openid",
];

fn refused() -> String {
    "operator Google public profile refused".to_owned()
}

pub(super) struct Profile {
    client_id: String,
    binding_digest: String,
}

impl Profile {
    pub(super) fn parse(
        flag: Option<&str>,
        operator: bool,
        client_id: Option<&str>,
        redirect_uri: Option<&str>,
    ) -> Result<Option<Self>, String> {
        match flag {
            None | Some("") => return Ok(None),
            Some(CAPABILITY) if operator => {}
            _ => return Err(refused()),
        }
        let client_id = client_id.ok_or_else(refused)?;
        let prefix = client_id
            .strip_suffix(".apps.googleusercontent.com")
            .ok_or_else(refused)?;
        if !(1..=200).contains(&prefix.len())
            || !prefix.as_bytes()[0].is_ascii_alphanumeric()
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err(refused());
        }
        let redirect_uri = redirect_uri.ok_or_else(refused)?;
        let host = redirect_uri
            .strip_prefix("https://")
            .and_then(|value| value.strip_suffix("/api/oauth/callback/google"))
            .ok_or_else(refused)?;
        if host.len() > 253
            || !host.contains('.')
            || host.parse::<IpAddr>().is_ok()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
            || ["localhost", "local", "internal", "invalid", "test"]
                .iter()
                .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
        {
            return Err(refused());
        }
        let binding_digest = digest_json_ensure_ascii(&json!({
            "schema":"catchplate.operatorGoogleProfile/v1",
            "profile":CAPABILITY,"provider_id":"google","client_id":client_id,
            "redirect_uri":redirect_uri,"permission_preset":"gmail_readonly",
            "scopes":SCOPES,"api_origins":[ORIGIN],
            "authorization_url":"https://accounts.google.com/o/oauth2/v2/auth",
            "token_url":"https://oauth2.googleapis.com/token",
            "revocation_url":"https://oauth2.googleapis.com/revoke",
            "identity_url":"https://openidconnect.googleapis.com/v1/userinfo",
        }));
        Ok(Some(Self {
            client_id: client_id.to_owned(),
            binding_digest,
        }))
    }

    pub(super) fn from_environment(operator: bool) -> Result<Option<Self>, String> {
        Self::parse(
            env::var("CATCHPLATE_OPERATOR_GOOGLE_PROFILE")
                .ok()
                .as_deref(),
            operator,
            env::var("CATCHPLATE_GOOGLE_OAUTH_CLIENT_ID")
                .ok()
                .as_deref(),
            env::var("CATCHPLATE_GOOGLE_OAUTH_REDIRECT_URI")
                .ok()
                .as_deref(),
        )
    }

    pub(super) fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    fn google_credential(&self, credential: &Credential) -> Result<bool, String> {
        if credential.kind() != "oauth2"
            || normalized_credential_provider(&credential.provider) != "google"
        {
            return Ok(false);
        }
        if credential.provider != "google"
            || credential.oauth_client_id() != Some(self.client_id.as_str())
            || credential
                .provider_subject
                .as_ref()
                .is_none_or(|subject| subject.is_empty())
            || credential.scopes().collect::<Vec<_>>() != SCOPES
            || credential.injection.get("type").and_then(Value::as_str) != Some("bearer")
            || credential.injection.get("header").and_then(Value::as_str) != Some("Authorization")
            || credential.injection.get("field").and_then(Value::as_str) != Some("access_token")
        {
            return Err(refused());
        }
        Ok(true)
    }

    pub(super) fn validate_snapshot(&self, snapshot: &Snapshot) -> Result<(), String> {
        for credential in snapshot.credentials.values() {
            self.google_credential(credential)?;
        }
        for route in &snapshot.routes {
            if route
                .credential_ref
                .as_ref()
                .and_then(|id| snapshot.credentials.get(id))
                .map(|credential| self.google_credential(credential))
                .transpose()?
                .unwrap_or(false)
                && (route.scheme != "https"
                    || route.host != "gmail.googleapis.com"
                    || route.port != 443
                    || route.methods.iter().any(|method| method != "GET"))
            {
                return Err(refused());
            }
        }
        Ok(())
    }

    pub(super) fn scope_admitted(
        &self,
        snapshot: &Snapshot,
        scope: &CredentialLeaseScope,
    ) -> Result<bool, String> {
        let Some(credential) = snapshot.credentials.get(&scope.credential_id) else {
            return Err(refused());
        };
        if !self.google_credential(credential)? {
            return Ok(false);
        }
        validate_credential_lease_scope(snapshot, scope)?;
        let route = snapshot
            .routes
            .iter()
            .find(|route| route.id == scope.route_id)
            .ok_or_else(refused)?;
        if route.scheme != "https"
            || route.host != "gmail.googleapis.com"
            || route.port != 443
            || route.methods.is_empty()
            || route.methods.iter().any(|method| method != "GET")
        {
            return Err(refused());
        }
        Ok(true)
    }
}
