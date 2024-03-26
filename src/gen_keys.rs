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

pub fn get_keypair(seed: Option<[u8; 32]>) -> (PrivateKey, PublicKey) {
    let mut rng = get_randomizer(seed);

    let private_key = PrivateKey::random(&mut rng);
    let public_key = private_key.public_key();

    (private_key, public_key)
}
