use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use std::io::{Read, Write};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short = "k")]
    key: String,
    #[structopt(short = "n")]
    nonce: String,
}

const BUF_SIZE: usize = 16 * 1024;

fn main() {
    let args = Cli::from_args();
    let decoded_key = &base64::decode(&args.key).unwrap();
    if decoded_key.len() != 32 {
        panic!("Key must be 32 bytes long");
    }
    let key = Key::from_slice(&decoded_key);
    let decoded_nonce = &base64::decode(&args.nonce).unwrap();
    if decoded_nonce.len() != 12 {
        panic!("Nonce must be 12 bytes long");
    }
    let nonce = Nonce::from_slice(&decoded_nonce);
    let mut cipher = ChaCha20::new(&key, &nonce);
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    let mut buf = [0u8; BUF_SIZE];
    while let Ok(n) = std::io::stdin().lock().read(&mut buf) {
        if n == 0 {
            break;
        }
        cipher.apply_keystream(&mut buf[..n]);
        let _ = writer.write(&buf[..n]);
    }
}
