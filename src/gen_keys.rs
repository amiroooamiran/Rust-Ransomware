use std::fs::File;
use std::io::{self, Write};
use std::io::stdout;

use chacha20::Key;
use hkdf::Hkdf;

use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::zeroize::Zeroize;

use p256::pkcs8::DecodePrivateKey;
use p256::pkcs8::DecodePublicKey;
use p256::pkcs8::EncodePrivateKey;
use p256::pkcs8::EncodePublicKey;

use p256::PublicKey;
use p256::SecretKey as PrivateKey;

use rand_chacha::rand_core::{RngCore, SeedableRng};

use rand_chacha::ChaChaRng;
use sha2::digest::Output;

// Generate random keys
pub fn get_randomizer(seed: Option<[u8; 32]>) -> ChaChaRng {
    if let Some(seed) = seed {
        ChaChaRng::from_seed(seed)
    } else {
        ChaChaRng::from_entropy()
    }
}

// Generate a public and private key
#[allow(dead_code)]
pub fn get_keypair(seed: Option<[u8; 32]>) -> (PrivateKey, PublicKey) {
    let mut rng = get_randomizer(seed);

    let private_key = PrivateKey::random(&mut rng);
    let public_key = private_key.public_key();

    (private_key, public_key)
}

// convart Bytes of the keys to pem format
#[allow(dead_code)]
pub fn dump_asym_keys(
    priv_key: &PrivateKey,
    pub_key: &PublicKey,
    out: Option<&str>,
) -> io::Result<()> {
    let priv_pem_result = priv_key.to_pkcs8_pem(Default::default());
    let pub_pem_result = pub_key.to_public_key_pem(Default::default());

    let priv_pem = match priv_pem_result {
        Ok(pem) => pem,
        Err(err) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to convert private key to PEM: {}", err),
            ))
        }
    };

    let pub_pem = match pub_pem_result {
        Ok(pem) => pem,
        Err(err) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to convert public key to PEM: {}", err),
            ))
        }
    };

    let (mut priv_writer, mut pub_writer): (Box<dyn Write>, Box<dyn Write>) = match out {
        Some(name) => {
            let priv_file = format!("{}.priv", name);
            let pub_file = format!("{}.pub", name);

            (
                Box::new(File::create(&priv_file)?),
                Box::new(File::create(&pub_file)?),
            )
        }
        None => (Box::new(io::stdout()), Box::new(io::stdout())),
    };

    priv_writer.write_all(priv_pem.as_bytes())?;
    pub_writer.write_all(pub_pem.as_bytes())?;

    Ok(())
}

// Reads the private key from `priv_file` and the public key from `pub_file`
#[allow(dead_code)]
pub fn import_asym_keys(priv_file: &str, pub_file: &str) -> (PrivateKey, PublicKey) {
    let pub_key = PublicKey::read_public_key_pem_file(pub_file).unwrap();
    let priv_key = PrivateKey::read_pkcs8_pem_file(priv_file).unwrap();
    (priv_key, pub_key)
}

/// Derives a symmetric key using Diffie-Hellman key exchange.
/// Utilizes the private and public keys provided to derive a symmetric key
/// through the Diffie-Hellman key exchange protocol. Returns the derived key.
#[allow(dead_code)]
pub fn get_symmetric_key(priv_key: &PrivateKey, pub_key: &PublicKey) -> Key {
    let salt = b"Version 1";
    let info = b"For Educational Purposes Only!";
    let shared_secret = diffie_hellman(priv_key.to_nonzero_scalar(), pub_key.as_affine());
    let hkdf = shared_secret.extract::<sha2::Sha256>(Some(salt));
    let mut key: [u8; 32] = [0; 32]; //256-bit keys

    hkdf.expand(info, &mut key).unwrap();

    let rc = Key::clone_from_slice(&key);

    key.zeroize();

    rc
}

#[allow(dead_code)]
