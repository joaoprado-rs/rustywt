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
#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
}
type HmacSha256 = Hmac<Sha256>;

fn main() {
    let jwt = generate_jwt_token();
    println!("okay - {}", jwt);
}

fn header_jwt(alghoritm: &str) -> Header {
     Header {
        alg: String::from(alghoritm),
        typ: String::from("JWT"),
    }
}

fn cipher_hs256(bytes: &[u8], input_message: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(bytes)
        .expect("Failed to initialize HMAC-SHA-256: ensure the provided key is valid and meets the required size.");
    mac.update(input_message.as_bytes());
    let result = mac.finalize();
    let cipher = result.into_bytes();
    cipher.to_vec()
}

fn generate_jwt_token() -> String {
    let header = header_jwt("HS256");
    let header_encoded = base64_url::encode(&serde_json::to_string(&header).unwrap());

    let payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"iat\":1516239022}";
    let payload_encoded = base64_url::encode(payload);

    let signature = format!("{}.{}", header_encoded, payload_encoded);

    let provided_256_bit_key = b"secret key";
    let signature = cipher_hs256(provided_256_bit_key, &signature);
    let signature_encoded = base64_url::encode(&signature);
    format!("{}.{}.{}",
            header_encoded,
            payload_encoded,
            signature_encoded)
}
