use hex_literal::hex;
use hmac::{digest::generic_array::GenericArray, Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

struct JWT<T>
where
    //Trait bound
    T: Serialize + for<'de> Deserialize<'de>,
{
    header: Header,
    payload: T,
    signature: String,
}
struct Header {
    alg: String,
    typ: String,
}

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let provided_256_bit_key = b"secret key";
    let cipher = cipher_hs256(provided_256_bit_key);
    println!("okay");
}

fn signature_jwt(alghoritm: &str) -> Header {
    let header = Header {
        alg: String::from(alghoritm),
        typ: String::from("JWT"),
    };
    header
}

fn cipher_hs256(bytes: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(bytes).expect("HMAC can take key of any size");
    mac.update(b"input message");
    let result = mac.finalize();
    let cipher = result.into_bytes();
    cipher.to_vec()
}
