//! X25519 key generation for `wgproxyrs genkey`.
//!
//! Uses boringtun's re-exported x25519 types exclusively, so keys produced
//! here are byte-compatible with the tunnel core by construction.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::OsRng;

/// A freshly generated WireGuard keypair, base64-encoded as in `.conf` files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub private_key_b64: String,
    pub public_key_b64: String,
}

pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    KeyPair {
        private_key_b64: B64.encode(secret.to_bytes()),
        public_key_b64: B64.encode(public.to_bytes()),
    }
}

/// Derive the public key (raw bytes) for a raw 32-byte private key.
pub fn public_from_private(private: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private);
    PublicKey::from(&secret).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_32_byte_base64_and_roundtrip() {
        let kp = generate_keypair();
        let priv_bytes = B64.decode(&kp.private_key_b64).unwrap();
        let pub_bytes = B64.decode(&kp.public_key_b64).unwrap();
        assert_eq!(priv_bytes.len(), 32);
        assert_eq!(pub_bytes.len(), 32);
        let raw: [u8; 32] = priv_bytes.try_into().unwrap();
        assert_eq!(public_from_private(&raw).as_slice(), pub_bytes.as_slice());
    }

    #[test]
    fn two_generations_differ() {
        assert_ne!(generate_keypair(), generate_keypair());
    }
}
