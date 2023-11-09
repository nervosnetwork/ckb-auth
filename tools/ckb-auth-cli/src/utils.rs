#![allow(unused)]

use anyhow::{anyhow, Error};

pub(crate) fn decode_string(s: &str, encoding: &str) -> Result<Vec<u8>, Error> {
    match encoding {
        "hex" => Ok(hex::decode(s)?),
        "base64" => {
            use base64::{engine::general_purpose, Engine as _};
            Ok(general_purpose::STANDARD.decode(s)?)
        }
        "base58" => Ok(bs58::decode(s).into_vec()?),
        "base58_monero" => {
            let b = base58_monero::decode(s)?;
            Ok(b)
        }
        _ => Err(anyhow!("Unknown encoding {}", encoding)),
    }
}

pub(crate) fn encode_to_string<T: AsRef<[u8]>>(s: T, encoding: &str) -> Result<String, Error> {
    match encoding {
        "hex" => Ok(hex::encode(s)),
        "base64" => {
            use base64::{engine::general_purpose, Engine as _};
            Ok(general_purpose::STANDARD.encode(s))
        }
        "base58" => Ok(bs58::encode(s).into_string()),
        _ => Err(anyhow!("Unknown encoding {}", encoding)),
    }
}

pub fn calculate_sha256(buf: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut c = Sha256::new();
    c.update(buf);
    c.finalize().into()
}

pub fn calculate_ripemd160(buf: &[u8]) -> [u8; 20] {
    use mbedtls::hash::*;
    let mut md = Md::new(Type::Ripemd).unwrap();
    md.update(buf).expect("hash ripemd update");
    let mut out = [0u8; 20];
    md.finish(&mut out).expect("hash ripemd finish");

    out
}
