#![no_std]
extern crate alloc;
use core::mem::transmute;

#[cfg(target_arch = "riscv64")]
pub mod ckb_auth;

#[cfg(target_arch = "riscv64")]
use alloc::ffi::NulError;
#[cfg(target_arch = "riscv64")]
use log::info;

#[cfg(target_arch = "riscv64")]
use ckb_std::error::SysError;
#[cfg(not(target_arch = "riscv64"))]
type SysError = u64;

#[derive(Clone)]
pub enum AuthAlgorithmIdType {
    Ckb = 0,
    Ethereum = 1,
    Eos = 2,
    Tron = 3,
    Bitcoin = 4,
    Dogecoin = 5,
    CkbMultisig = 6,
    Schnorr = 7,
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

impl Into<u8> for AuthAlgorithmIdType {
    fn into(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AuthAlgorithmIdType {
    type Error = CkbAuthError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (value >= AuthAlgorithmIdType::Ckb.into()
            && value <= AuthAlgorithmIdType::Iso97962.into())
            || value == AuthAlgorithmIdType::OwnerLock.into()
        {
            Ok(unsafe { transmute(value) })
        } else {
            Err(CkbAuthError::UnknowAlgorithmID)
        }
    }
}

#[derive(Debug)]
pub enum CkbAuthError {
    UnknowAlgorithmID,
    DynamicLinkingUninit,
    LoadDLError,
    LoadDLFuncError,
    RunDLError,
    ExecError(SysError),
    SignatureMissing,
    EncodeArgs,
}

#[cfg(target_arch = "riscv64")]
impl From<SysError> for CkbAuthError {
    fn from(err: SysError) -> Self {
        info!("Exec error: {:?}", err);
        Self::ExecError(err)
    }
}

#[cfg(target_arch = "riscv64")]
impl From<NulError> for CkbAuthError {
    fn from(err: NulError) -> Self {
        info!("Exec encode args failed: {:?}", err);
        Self::EncodeArgs
    }
}

#[derive(Clone)]
pub enum EntryCategoryType {
    // Exec = 0,
    DynamicLinking = 1,
    #[cfg(feature = "ckb2023")]
    Spawn = 2,
}

impl TryFrom<u8> for EntryCategoryType {
    type Error = CkbAuthError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            // 0 => Ok(Self::Exec),
            1 => Ok(Self::DynamicLinking),
            #[cfg(feature = "ckb2023")]
            2 => Ok(Self::Spawn),
            _ => Err(CkbAuthError::EncodeArgs),
        }
    }
}

pub struct CkbAuthType {
    pub algorithm_id: AuthAlgorithmIdType,
    pub pubkey_hash: [u8; 20],
}
