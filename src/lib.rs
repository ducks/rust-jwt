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
use std::str;

// A public struct for a jwt header
#[derive(Clone, Debug)]
pub struct Header {
    alg: Alg,
    typ: String,
}

// implement a Header
impl Header {
    pub fn new(alg: Alg) -> Header {
        Header {
            alg: alg,
            typ: String::from("JWT"),
        }
    }
}

impl ToJson for Header {
    fn to_json(&self) -> json::Json {
        let mut obj = BTreeMap::new();
        obj.insert(String::from("typ"), self.typ.to_json());
        obj.insert(String::from("alg"), self.alg.to_string().to_json());
        Json::Object(obj)
    }
}

// List of algorithms from https://jwt.io
#[derive(Clone, Copy, Debug)]
pub enum Alg {
    HS256,
    HS384,
    HS512, /* RS256,
            * RS384,
            * RS512,
            * ES256,
            * ES384,
            * ES512 */
}

impl Alg {
    pub fn new(alg: &str) -> Alg {
        match alg {
            "HS256" => Alg::HS256,
            "HS384" => Alg::HS384,
            "HS512" => Alg::HS512,
            _ => Alg::HS256,
        }
    }
}

impl ToString for Alg {
    fn to_string(&self) -> String {
        match *self {
            Alg::HS256 => String::from("HS256"),
            Alg::HS384 => String::from("HS384"),
            Alg::HS512 => String::from("HS512"),
        }
    }
}

pub type Payload = BTreeMap<String, json::Json>;

#[derive(Debug)]
pub enum Error {
    JWTSignatureInvalid,
    JWTInvalid,
}

fn prepare_input(alg: &Alg, payload: Payload) -> String {
    let header_enc = encode_header(&alg);
    let payload_enc = encode_payload(payload);

    // Format encoded pieces in JWT format
    format!("{}.{}", header_enc, payload_enc)
}

fn encode_header(alg: &Alg) -> String {
    let header = Header::new(*alg);
    let header_json = header.to_json();
    base64_url_encode(header_json.to_string().as_bytes())
}

fn encode_payload(payload: Payload) -> String {
    let pl = payload.into_iter().map(|(k, v)| (k, v.to_json())).collect();
    let pl_json = Json::Object(pl);
    base64_url_encode(pl_json.to_string().as_bytes())
}

fn encode_signature(sig: &[u8]) -> String {
    base64_url_encode(sig)
}

pub fn encode(alg: Alg, payload: Payload, secret: String) -> String {
    let header_enc = encode_header(&alg);
    let payload_enc = encode_payload(payload);
    let sig = sign(header_enc.clone(), payload_enc.clone(), secret, &alg);
    let sig_enc = encode_signature(&sig);

    format!("{}.{}.{}", header_enc, payload_enc, sig_enc)
}

fn sign(header: String, payload: String, secret: String, alg: &Alg) -> Vec<u8> {
    let input = format!("{}.{}", header, payload);

    let sig = match *alg {
        Alg::HS256 => hmac(Type::SHA256, secret.as_bytes(), input.as_bytes()),
        Alg::HS384 => hmac(Type::SHA384, secret.as_bytes(), input.as_bytes()),
        Alg::HS512 => hmac(Type::SHA512, secret.as_bytes(), input.as_bytes()),
    };

    sig.ok().unwrap()
}

pub fn decode(token: String, secret: String, alg: &Alg) -> Result<(Header, Payload), Error> {
    match explode_token(token) {
        Some((header, payload, sig, header_enc, pl_enc)) => {
            let expected = sign(header_enc, pl_enc, secret, alg);
            let expected_enc = encode_signature(&expected);

            if sig != expected_enc {
                Err(Error::JWTSignatureInvalid)
            } else {
                Ok((header, payload))
            }
        }

        None => Err(Error::JWTInvalid),
    }
}

fn explode_token(token: String) -> Option<(Header, Payload, String, String, String)> {
    let chunks: Vec<&str> = token.split(".").collect();
    // TODO: Check length of chunks

    let header_chunk = chunks[0];
    let pl_chunk = chunks[1];
    let crypto_chunk = chunks[2];
    let header_enc = String::from(header_chunk);
    let pl_enc = String::from(pl_chunk);

    let header = decode_header(header_chunk);
    let payload = decode_payload(pl_chunk);
    let sig = String::from(crypto_chunk);
    Some((header, payload, sig.clone(), header_enc, pl_enc))
}

fn decode_header(header_chunk: &str) -> Header {
    let json = base64_to_json(header_chunk);
    let btree = json_to_btree(json);
    let alg = btree.get("alg").unwrap();
    Header::new(Alg::new(alg.to_string().as_str()))
}

fn decode_payload(payload_chunk: &str) -> Payload {
    let json = base64_to_json(payload_chunk);
    json_to_btree(json)
}

fn base64_url_encode(bytes: &[u8]) -> String {
    bytes.to_base64(base64::URL_SAFE)
}

fn base64_to_json(input: &str) -> Json {
    let bytes = input.as_bytes().from_base64().unwrap();
    let s = str::from_utf8(&bytes).unwrap();
    Json::from_str(s).unwrap()
}

fn json_to_btree(input: Json) -> BTreeMap<String, json::Json> {
    match input {
        Json::Object(obj) => {
            obj.into_iter()
                .map(|(k, v)| {
                    (k,
                     match v {
                        Json::Object(o) => Json::Object(o),
                        Json::String(s) => Json::String(s),
                        _ => unreachable!(),
                    })
                })
                .collect()
        }
        _ => unreachable!(),
    }
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
        let mut pl = Payload::new();
        let secret = String::from("mashedtaters");

        pl.insert(String::from("k101"), "v101".to_json());
        pl.insert(String::from("k202"), "v202".to_json());
        pl.insert(String::from("k303"), "v303".to_json());

        let token = encode(Alg::HS256, pl, secret);
        assert_eq!(token,
                   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                    eyJrMTAxIjoidjEwMSIsImsyMDIiOiJ2MjAyIiwiazMwMyI6InYzMDMifQ.\
                    Dw0y4DddfnUuSM-lZLxlvyE-8TdeEEg9H8KNQ6GE0Bc")
    }

    #[test]
    fn test_jwt_hs256_decode() {
        let header = Header::new(Alg::HS256);
        let mut pl = Payload::new();
        let secret = String::from("tcT%V$*vj*wOsX*TGi1sRkJGU^7@q#1I");

        pl.insert(String::from("k1010"), "v1010".to_json());
        pl.insert(String::from("k2020"), "v2020".to_json());
        pl.insert(String::from("k3030"), "v3030".to_json());

        let token = encode(Alg::HS256, pl, secret.clone());
        let expected = decode(token, secret, &Alg::HS256);

        assert!(expected.is_ok())
    }

    #[test]
    fn test_jwt_hs384_decode() {
        let header = Header::new(Alg::HS384);
        let mut pl = Payload::new();
        let secret = String::from("2&V8b4qTXqk74PaRjHg@W0Nvf!tRt^*o");

        pl.insert(String::from("k1010"), "v1010".to_json());
        pl.insert(String::from("k2020"), "v2020".to_json());
        pl.insert(String::from("k3030"), "v3030".to_json());

        let token = encode(Alg::HS384, pl, secret.clone());
        let expected = decode(token, secret, &Alg::HS384);

        assert!(expected.is_ok())
    }

    #[test]
    fn test_jwt_hs512_decode() {
        let header = Header::new(Alg::HS512);
        let mut pl = Payload::new();
        let secret = String::from("C0LmFz$jF72K8J%iwjrxp$RC0r6EPHll");

        pl.insert(String::from("k1010"), "v1010".to_json());
        pl.insert(String::from("k2020"), "v2020".to_json());
        pl.insert(String::from("k3030"), "v3030".to_json());

        let token = encode(Alg::HS512, pl, secret.clone());
        let expected = decode(token, secret, &Alg::HS512);

        assert!(expected.is_ok())
    }
}
