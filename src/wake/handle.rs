//! Wake handles: a device's APNs address, sealed so only this service can
//! read it. Holding a handle is the only way to wake that device.

use anyhow::{Context, Result, anyhow, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};

pub const MIN_SECRET_LEN: usize = 32;
const VERSION: u8 = 1;
const AAD: &[u8] = b"keeptalking/wake/1 handle";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    ContextMessage = 1,
    ActionAuthorisation = 2,
}

impl Purpose {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::ContextMessage),
            2 => Some(Self::ActionAuthorisation),
            _ => None,
        }
    }
}

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

/// What a sealed handle holds. `id` is the one part the device sees again:
/// it rides every push, so the device maps it back to what it minted the
/// handle for without the service ever learning that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    pub id: [u8; 16],
    pub purpose: Purpose,
    pub environment: Environment,
    /// The app's bundle id, sent as `apns-topic`.
    pub apns_topic: String,
    pub token: Vec<u8>,
}

impl Handle {
    fn encode(&self) -> BytesMut {
        let mut out = BytesMut::with_capacity(21 + self.apns_topic.len() + self.token.len());
        out.put_u8(VERSION);
        out.put_slice(&self.id);
        out.put_u8(self.purpose as u8);
        out.put_u8(self.environment as u8);
        out.put_u8(self.apns_topic.len() as u8);
        out.put_slice(self.apns_topic.as_bytes());
        out.put_u8(self.token.len() as u8);
        out.put_slice(&self.token);
        out
    }

    fn decode(mut body: Bytes) -> Result<Self> {
        ensure!(body.remaining() >= 20, "truncated handle");
        ensure!(body.get_u8() == VERSION, "unknown handle version");
        let id: [u8; 16] = body.split_to(16)[..].try_into().expect("16 bytes");
        let purpose = Purpose::from_byte(body.get_u8()).context("unknown purpose")?;
        let environment = Environment::from_byte(body.get_u8()).context("unknown environment")?;
        let topic_len = body.get_u8() as usize;
        ensure!(body.remaining() > topic_len, "truncated handle");
        let apns_topic = String::from_utf8(body.split_to(topic_len).to_vec())?;
        let token_len = body.get_u8() as usize;
        ensure!(body.remaining() == token_len, "truncated handle");
        Ok(Self {
            id,
            purpose,
            environment,
            apns_topic,
            token: body.to_vec(),
        })
    }
}

pub struct HandleSealer {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl HandleSealer {
    pub fn new(secret: &[u8]) -> Result<Self> {
        ensure!(
            secret.len() >= MIN_SECRET_LEN,
            "the wake handle secret needs at least {MIN_SECRET_LEN} bytes"
        );
        let derived = Sha256::new().chain_update(AAD).chain_update(secret).finalize();
        let key = UnboundKey::new(&AES_256_GCM, &derived).map_err(|_| anyhow!("handle key"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            rng: SystemRandom::new(),
        })
    }

    /// `nonce(12) ‖ ciphertext ‖ tag(16)`.
    pub fn seal(&self, handle: &Handle) -> Result<Bytes> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce).map_err(|_| anyhow!("no randomness"))?;
        let mut sealed = handle.encode();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(AAD),
                &mut sealed,
            )
            .map_err(|_| anyhow!("sealing a handle"))?;
        let mut out = BytesMut::with_capacity(NONCE_LEN + sealed.len());
        out.put_slice(&nonce);
        out.put_slice(&sealed);
        Ok(out.freeze())
    }

    pub fn open(&self, sealed: &[u8]) -> Result<Handle> {
        ensure!(sealed.len() > NONCE_LEN, "truncated handle");
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| anyhow!("bad nonce"))?;
        let mut buf = ciphertext.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(AAD), &mut buf)
            .map_err(|_| anyhow!("not a handle this service sealed"))?;
        Handle::decode(Bytes::copy_from_slice(plain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle() -> Handle {
        Handle {
            id: [7; 16],
            purpose: Purpose::ContextMessage,
            environment: Environment::Production,
            apns_topic: "dev.keeptalking.app".into(),
            token: vec![0xAB; 32],
        }
    }

    #[test]
    fn handles_round_trip_and_differ_each_seal() {
        let sealer = HandleSealer::new(&[1; 32]).unwrap();
        let a = sealer.seal(&handle()).unwrap();
        let b = sealer.seal(&handle()).unwrap();
        assert_ne!(a, b);
        assert_eq!(sealer.open(&a).unwrap(), handle());
    }

    #[test]
    fn another_secret_or_a_flipped_byte_is_refused() {
        let sealer = HandleSealer::new(&[1; 32]).unwrap();
        let sealed = sealer.seal(&handle()).unwrap();
        assert!(HandleSealer::new(&[2; 32]).unwrap().open(&sealed).is_err());
        let mut tampered = sealed.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(sealer.open(&tampered).is_err());
    }

    #[test]
    fn short_secrets_are_refused() {
        assert!(HandleSealer::new(&[1; 31]).is_err());
    }
}
