#![no_std]
extern crate alloc;
use core::mem::transmute;

#[cfg(target_arch = "riscv64")]
pub mod ckb_auth;

#[derive(Clone)]
pub enum AuthAlgorithmIdType {
    Ckb = 0,
    Ethereum = 1,
    Eos = 2,
    Tron = 3,
    Bitcoin = 4,
    Dogecoin = 5,
    CkbMultisig = 6,
    SchnorrOrTaproot = 7,
    Rsa = 8,
    Iso97962 = 9,
    Litecoin = 10,
    Cardano = 11,
    Monero = 12,
    Solana = 13,
    Ripple = 14,
    Secp256r1 = 15,
    OwnerLock = 0xFC,
}

pub enum CkbAuthTypesError {
    UnknowAlgorithmID,
    EncodeArgs,
}

impl Into<u8> for AuthAlgorithmIdType {
    fn into(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AuthAlgorithmIdType {
    type Error = CkbAuthTypesError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (value >= AuthAlgorithmIdType::Ckb.into()
            && value <= AuthAlgorithmIdType::Iso97962.into())
            || value == AuthAlgorithmIdType::OwnerLock.into()
        {
            Ok(unsafe { transmute(value) })
        } else {
            Err(CkbAuthTypesError::UnknowAlgorithmID)
        }
    }
}

#[derive(Clone)]
pub enum EntryCategoryType {
    // Exec = 0,
    DynamicLinking = 1,
    Spawn = 2,
}

impl TryFrom<u8> for EntryCategoryType {
    type Error = CkbAuthTypesError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            // 0 => Ok(Self::Exec),
            1 => Ok(Self::DynamicLinking),
            2 => Ok(Self::Spawn),
            _ => Err(CkbAuthTypesError::EncodeArgs),
        }
    }
}

pub struct CkbAuthType {
    pub algorithm_id: AuthAlgorithmIdType,
    pub pubkey_hash: [u8; 20],
}
