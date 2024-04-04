mod gen_keys;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use chacha20poly1305::Nonce;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "Rust-Ransomware")]
struct Args {
    #[clap(short, long)]
    input: String,
}

fn main() {
    let args = Args::parse();

    let (priv1, pub1) = gen_keys::get_keypair(None);
    let _ = gen_keys::dump_asym_keys(&priv1, &pub1, None);
    println!("");

    let (priv2, pub2) = gen_keys::get_keypair(None);
    let _ = gen_keys::dump_asym_keys(&priv2, &pub2, None);
    println!("");

    let enc_key = gen_keys::get_symmetric_key(&priv1, &pub1);
    let dec_key = gen_keys::get_symmetric_key(&priv2, &pub2);

    assert_eq!(enc_key, dec_key);

    println!("enc_key = {:?}", enc_key);
    println!("");
    println!("enc_key = {:?}", dec_key);
    println!("");

}
