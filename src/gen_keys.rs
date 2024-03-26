use chacha20::Key;
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::zeroize::Zeroize;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey,EncodePrivateKey, EncodePublicKey};
use p256::PublicKey;
use p256::SecretKey as PrivateKey;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

pub fn get_randomizer(seed: Option<[u8; 32]>) -> ChaChaRng {
    if let Some(seed) = seed{
        ChaChaRng::from_seed(seed)
    } else {
        ChaChaRng::from_entropy()
    }
}
