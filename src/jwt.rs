use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use base64_url;
use crate::header::Header;

type HmacSha256 = Hmac<Sha256>;

pub struct JWT<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
  pub header: Header,
  pub payload: T,
  pub signature: String,
}

impl<T> JWT<T>
where
    T: Serialize + for<'de> Deserialize<'de>,
{
  pub fn new(algorithm: &str, claims: T, key: String) -> Self {
    let header = Header::new(algorithm);

    let header_encoded = base64_url::encode(&serde_json::to_string(&header).unwrap());
    let payload_encoded = base64_url::encode(&serde_json::to_string(&claims).unwrap());

    let signing_input = format!("{}.{}", header_encoded, payload_encoded);
    let signature = Self::cipher_hs256(key.as_bytes(), &signing_input);
    let signature_encoded = base64_url::encode(&signature);

    Self {
      header,
      payload: claims,
      signature: signature_encoded,
    }
  }

  pub fn to_string(&self) -> String {
    let header_encoded = base64_url::encode(&serde_json::to_string(&self.header).unwrap());
    let payload_encoded = base64_url::encode(&serde_json::to_string(&self.payload).unwrap());
    format!("{}.{}.{}", header_encoded, payload_encoded, self.signature)
  }

  fn cipher_hs256(bytes: &[u8], input_message: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(bytes)
        .expect("Failed to initialize HMAC-SHA-256: ensure the provided key is valid and meets the required size.");
    mac.update(input_message.as_bytes());
    mac.finalize().into_bytes().to_vec()
  }
}