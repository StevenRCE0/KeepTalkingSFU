//! The APNs provider: token (ES256 JWT) authentication over HTTP/2.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use url::Url;

use super::handle::{Environment, Handle};

/// Apple refuses a provider token older than an hour and throttles one
/// renewed more often than every twenty minutes.
const TOKEN_LIFETIME: Duration = Duration::from_secs(50 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub struct ApnsConfig {
    pub key_id: String,
    pub team_id: String,
    /// The `AuthKey_<KEYID>.p8` key, DER.
    pub key_pkcs8: Vec<u8>,
    pub production_url: Url,
    pub development_url: Url,
}

impl ApnsConfig {
    pub fn new(key_id: String, team_id: String, key_pkcs8: Vec<u8>) -> Self {
        Self {
            key_id,
            team_id,
            key_pkcs8,
            production_url: Url::parse("https://api.push.apple.com").expect("valid"),
            development_url: Url::parse("https://api.sandbox.push.apple.com").expect("valid"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Alert { collapse_id: String },
    Background,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApnsOutcome {
    pub status: u16,
    /// Apple's `reason` on a refusal, empty on success.
    pub reason: String,
}

pub struct Apns {
    client: reqwest::Client,
    key: EcdsaKeyPair,
    rng: SystemRandom,
    key_id: String,
    team_id: String,
    production_url: Url,
    development_url: Url,
    token: Mutex<Option<(Arc<str>, Instant)>>,
}

impl Apns {
    pub fn new(config: ApnsConfig) -> Result<Self> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &config.key_pkcs8, &rng)
            .map_err(|err| anyhow!("APNs key is not a P-256 PKCS#8 key: {err}"))?;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .http2_prior_knowledge()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("APNs client")?;
        Ok(Self {
            client,
            key,
            rng,
            key_id: config.key_id,
            team_id: config.team_id,
            production_url: config.production_url,
            development_url: config.development_url,
            token: Mutex::new(None),
        })
    }

    pub async fn send(&self, handle: &Handle, delivery: &Delivery, body: Vec<u8>) -> Result<ApnsOutcome> {
        let outcome = self.post(handle, delivery, body.clone(), false).await?;
        if outcome.status == 403 && outcome.reason == "ExpiredProviderToken" {
            return self.post(handle, delivery, body, true).await;
        }
        Ok(outcome)
    }

    async fn post(
        &self,
        handle: &Handle,
        delivery: &Delivery,
        body: Vec<u8>,
        renew: bool,
    ) -> Result<ApnsOutcome> {
        let base = match handle.environment {
            Environment::Production => &self.production_url,
            Environment::Development => &self.development_url,
        };
        let url = base.join(&format!("/3/device/{}", hex(&handle.token)))?;
        let mut request = self
            .client
            .post(url)
            .bearer_auth(self.token(renew)?)
            .header("apns-topic", &handle.apns_topic)
            .header("content-type", "application/json")
            .body(body);
        request = match delivery {
            Delivery::Alert { collapse_id } => request
                .header("apns-push-type", "alert")
                .header("apns-priority", "10")
                .header("apns-collapse-id", collapse_id),
            // APNs rejects a background push at any other priority.
            Delivery::Background => request
                .header("apns-push-type", "background")
                .header("apns-priority", "5"),
        };
        let response = request.send().await.context("APNs request")?;
        let status = response.status().as_u16();
        if status == 200 {
            return Ok(ApnsOutcome { status, reason: String::new() });
        }
        let body = response.bytes().await.unwrap_or_default();
        let reason = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| value.get("reason")?.as_str().map(str::to_owned))
            .unwrap_or_default();
        Ok(ApnsOutcome { status, reason })
    }

    fn token(&self, renew: bool) -> Result<Arc<str>> {
        let mut cached = self.token.lock().expect("token lock");
        if !renew
            && let Some((token, minted)) = cached.as_ref()
            && minted.elapsed() < TOKEN_LIFETIME
        {
            return Ok(token.clone());
        }
        let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::json!({ "alg": "ES256", "kid": self.key_id }).to_string(),
        );
        let claims =
            URL_SAFE_NO_PAD.encode(serde_json::json!({ "iss": self.team_id, "iat": iat }).to_string());
        let input = format!("{header}.{claims}");
        let signature = self
            .key
            .sign(&self.rng, input.as_bytes())
            .map_err(|_| anyhow!("signing the APNs token"))?;
        let token: Arc<str> = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)).into();
        *cached = Some((token.clone(), Instant::now()));
        Ok(token)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
