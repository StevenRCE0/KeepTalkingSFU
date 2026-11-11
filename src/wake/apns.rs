//! Apple Push Notification service: token (ES256 JWT) authentication over
//! HTTP/2.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use serde_json::{Map, Value, json};
use url::Url;

use super::{HANDLE_ID_KEY, Kind, Outcome, status};

/// APNs refuses a larger body.
pub const MAX_BODY_LEN: usize = 4096;
/// Apple refuses a provider token older than an hour and throttles one
/// renewed more often than every twenty minutes.
const TOKEN_LIFETIME: Duration = Duration::from_secs(50 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development = 0,
    Production = 1,
}

impl Environment {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Development),
            1 => Some(Self::Production),
            _ => None,
        }
    }
}

/// `environment(u8) ‖ u8 len ‖ topic ‖ u8 len ‖ token`. The topic is the
/// app's bundle id, sent as `apns-topic`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApnsAddress {
    pub environment: Environment,
    pub topic: String,
    pub token: Vec<u8>,
}

impl ApnsAddress {
    pub fn encode(&self, out: &mut BytesMut) {
        out.put_u8(self.environment as u8);
        out.put_u8(self.topic.len() as u8);
        out.put_slice(self.topic.as_bytes());
        out.put_u8(self.token.len() as u8);
        out.put_slice(&self.token);
    }

    pub fn decode(body: &mut Bytes) -> Result<Self> {
        ensure!(body.remaining() >= 1, "truncated address");
        let environment = Environment::from_byte(body.get_u8()).context("unknown environment")?;
        let topic = String::from_utf8(take_short(body)?.to_vec())?;
        let token = take_short(body)?.to_vec();
        ensure!(!topic.is_empty() && !token.is_empty(), "empty topic or token");
        ensure!(body.is_empty(), "trailing bytes in address");
        Ok(Self {
            environment,
            topic,
            token,
        })
    }

    /// Whether `encode` can carry it.
    pub fn is_encodable(&self) -> bool {
        self.topic.len() <= u8::MAX as usize && self.token.len() <= u8::MAX as usize
    }
}

fn take_short(body: &mut Bytes) -> Result<Bytes> {
    ensure!(body.remaining() >= 1, "truncated");
    let len = body.get_u8() as usize;
    ensure!(body.remaining() >= len, "truncated");
    Ok(body.split_to(len))
}

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

    /// Context and action wakes are alerts collapsing by handle, so a newer
    /// one replaces the one on screen; revocations are background pushes.
    pub async fn send(
        &self,
        address: &ApnsAddress,
        kind: Kind,
        handle_id: &str,
        payload: &[u8],
    ) -> Outcome {
        let body = match body(kind, handle_id, payload) {
            Ok(body) => body,
            Err(err) => return Outcome::new(status::BAD_REQUEST, format!("{err:#}")),
        };
        if body.len() > MAX_BODY_LEN {
            return Outcome::new(status::TOO_LARGE, "over the APNs body limit");
        }
        let mut outcome = self.post(address, kind, handle_id, body.clone(), false).await;
        if outcome.status == 403 && outcome.reason == "ExpiredProviderToken" {
            outcome = self.post(address, kind, handle_id, body, true).await;
        }
        outcome
    }

    async fn post(
        &self,
        address: &ApnsAddress,
        kind: Kind,
        handle_id: &str,
        body: Vec<u8>,
        renew: bool,
    ) -> Outcome {
        match self.try_post(address, kind, handle_id, body, renew).await {
            Ok(outcome) => outcome,
            Err(err) => Outcome::new(status::UNREACHABLE, format!("{err:#}")),
        }
    }

    async fn try_post(
        &self,
        address: &ApnsAddress,
        kind: Kind,
        handle_id: &str,
        body: Vec<u8>,
        renew: bool,
    ) -> Result<Outcome> {
        let base = match address.environment {
            Environment::Production => &self.production_url,
            Environment::Development => &self.development_url,
        };
        let url = base.join(&format!("/3/device/{}", hex(&address.token)))?;
        let mut request = self
            .client
            .post(url)
            .bearer_auth(self.token(renew)?)
            .header("apns-topic", &address.topic)
            .header("content-type", "application/json")
            .body(body);
        request = match kind {
            Kind::Context | Kind::Action => request
                .header("apns-push-type", "alert")
                .header("apns-priority", "10")
                .header("apns-collapse-id", handle_id),
            // APNs rejects a background push at any other priority.
            Kind::Revocation => request
                .header("apns-push-type", "background")
                .header("apns-priority", "5"),
        };
        let response = request.send().await.context("APNs request")?;
        let status = response.status().as_u16();
        if status == status::OK {
            return Ok(Outcome::new(status, ""));
        }
        let body = response.bytes().await.unwrap_or_default();
        let reason = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| value.get("reason")?.as_str().map(str::to_owned))
            .unwrap_or_default();
        Ok(Outcome::new(status, reason))
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

/// `{"aps": …, <kind key>: payload, "kt_wake_handle": id}`. The `aps` text
/// shows only when the device's notification service extension can't
/// resolve the real content.
pub fn body(kind: Kind, handle_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let payload: Value = serde_json::from_slice(payload).context("payload is not JSON")?;
    ensure!(payload.is_object(), "payload is not a JSON object");
    let alert = |title: &str, body: &str| {
        json!({
            "alert": { "title": title, "body": body },
            "sound": "default",
            "content-available": 1,
            "mutable-content": 1,
        })
    };
    let aps = match kind {
        Kind::Context => alert("New KeepTalking activity", "Open KeepTalking to catch up."),
        Kind::Action => alert("Action approval requested", "Open KeepTalking to review it."),
        Kind::Revocation => json!({ "content-available": 1 }),
    };
    let mut body = Map::new();
    body.insert("aps".into(), aps);
    body.insert(kind.data_key().into(), payload);
    body.insert(HANDLE_ID_KEY.into(), Value::String(handle_id.into()));
    Ok(serde_json::to_vec(&Value::Object(body))?)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SDK budgets 4096 − 256 bytes for the context wake it seals.
    #[test]
    fn the_sdk_budget_fits_every_alert() {
        let ciphertext = "k".repeat(4096 - 256 - r#"{"ciphertext":""}"#.len());
        let payload = format!(r#"{{"ciphertext":"{ciphertext}"}}"#);
        let id = uuid::Uuid::new_v4().to_string();
        for kind in [Kind::Context, Kind::Action] {
            let body = body(kind, &id, payload.as_bytes()).unwrap();
            assert!(body.len() <= MAX_BODY_LEN, "{kind:?}: {}", body.len());
        }
    }

    #[test]
    fn a_payload_must_be_a_json_object() {
        assert!(body(Kind::Context, "id", b"[1]").is_err());
        assert!(body(Kind::Context, "id", b"nope").is_err());
        let sent: Value =
            serde_json::from_slice(&body(Kind::Revocation, "id", br#"{"a":1}"#).unwrap()).unwrap();
        assert_eq!(sent["kt_context_revoke"]["a"], 1);
        assert_eq!(sent[HANDLE_ID_KEY], "id");
        assert_eq!(sent["aps"], json!({ "content-available": 1 }));
    }
}
