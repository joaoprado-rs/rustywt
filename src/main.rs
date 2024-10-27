use rustywt::jwt::JWT;

fn main() {
  let payload = serde_json::json!({"name": "joao.prado-rs"});
  let jwt = JWT::new("HS256", payload, "secret key".to_string());
  println!("Generated JWT: {}", jwt.to_string());
}