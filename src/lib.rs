#![allow(dead_code)]

extern crate openssl;
extern crate rustc_serialize;

use openssl::crypto::hash::Hasher;
use openssl::crypto::hash::Type;
use openssl::crypto::hmac::hmac;
use openssl::crypto::rsa::RSA;

use rustc_serialize::base64::{self, ToBase64, FromBase64};
use rustc_serialize::json::{self, ToJson, Json};

use std::collections::BTreeMap;

// A public struct for a jwt header
#[derive(Debug)]
pub struct Header {
  alg: Alg,
  typ: String 
}

// implement a Header
impl Header {
  pub fn new(alg: Alg) -> Header {
    Header { alg: alg, typ: String::from("JWT") }
  }
}

impl ToJson for Header {
  fn to_json(&self) -> json::Json {
    let mut obj = BTreeMap::new();
    obj.insert(String::from("typ"), self.typ.to_json());
    obj.insert(String::from("alg"), self.alg.to_string().to_json());
    println!("{:?}", obj);
    Json::Object(obj)
  }
}

// List of algorithms from https://jwt.io
#[derive(Clone, Copy, Debug)]
pub enum Alg {
  HS256
  /* HS384,
  HS512,
  RS256,
  RS384,
  RS512,
  ES256,
  ES384,
  ES512 */
}

impl ToString for Alg {
  fn to_string(&self) -> String {
    match *self {
      Alg::HS256 => String::from("HS256")
    }
  }
}

pub type Payload = BTreeMap<String, json::Json>;

fn prepare_input(alg: &Alg, payload: Payload) -> String {
  let header = Header::new(*alg);
  let header_json = header.to_json();
  let header_enc = base64_url_encode(header_json.to_string().as_bytes());

  let p = payload.into_iter().map(|(k, v)| (k, v.to_json())).collect();
  let payload_json = Json::Object(p);
  let payload_enc = base64_url_encode(payload_json.to_string().as_bytes());

  // Format encoded pieces in JWT format
  format!("{}.{}", header_enc, payload_enc)
}

fn sign(header: Header, payload: Payload, secret: String) -> String {
  let input = prepare_input(&header.alg, payload);
  
  let sig = match header.alg {
    Alg::HS256 => sign_hmac(header.alg, &input, secret),
  };

  format!("{}.{}", input, sig)
}

fn sign_hmac(alg: Alg, input: &str, secret: String) -> String {
  let typ = match alg {
    Alg::HS256 => Type::SHA256
  };

  let hmac = hmac(typ, secret.as_bytes(), input.as_bytes());
  base64_url_encode(&hmac)
}

fn base64_url_encode(bytes: &[u8]) -> String {
  bytes.to_base64(base64::URL_SAFE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::base64_url_encode;
    use super::sign;
    use rustc_serialize::json::{self, ToJson, Json};

    #[test]
    fn test_header_base64_encoding() {
      let h = Header::new(Alg::HS256);
      let encoded = base64_url_encode(h.to_json().to_string().as_bytes());
      assert_eq!(encoded, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
    }

    #[test]
    fn test_payload_base64_encoding() {
      let mut pl = Payload::new();
      pl.insert(String::from("k1"), "v1".to_json());
      pl.insert(String::from("k2"), "v2".to_json());
      pl.insert(String::from("k3"), "v3".to_json());

      let p = pl.into_iter().map(|(k, v)| (k, v.to_json())).collect();
      let json = Json::Object(p);
      let encoded = base64_url_encode(json.to_string().as_bytes());

      assert_eq!(encoded, "eyJrMSI6InYxIiwiazIiOiJ2MiIsImszIjoidjMifQ")
    }

    #[test]
    fn test_jwt_hs256_encoding() {
      let header = Header::new(Alg::HS256);
      let mut pl = Payload::new();
      let secret = String::from("mashedtaters");

      pl.insert(String::from("k101"), "v101".to_json());
      pl.insert(String::from("k202"), "v202".to_json());
      pl.insert(String::from("k303"), "v303".to_json());

      let token = sign(header, pl, secret);
      assert_eq!(token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrMTAxIjoidjEwMSIsImsyMDIiOiJ2MjAyIiwiazMwMyI6InYzMDMifQ.Dw0y4DddfnUuSM-lZLxlvyE-8TdeEEg9H8KNQ6GE0Bc")
    }
}
