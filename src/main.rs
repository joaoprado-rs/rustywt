use serde::{Deserialize, Serialize};

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

fn main() {
    println!("HS256");
    let header = signature_jwt("HS256");
}

fn signature_jwt(alghoritm: &str) -> Header {
    let header = Header {
        alg: String::from(alghoritm),
        typ: String::from("JWT"),
    };
    header
}
