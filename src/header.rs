use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Header {
  pub alg: String,
  pub typ: String,
}

impl Header {
  pub fn new(algorithm: &str) -> Self {
    Self {
      alg: algorithm.to_string(),
      typ: "JWT".to_string(),
    }
  }
}