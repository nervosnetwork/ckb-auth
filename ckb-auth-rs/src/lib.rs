#![no_std]
extern crate alloc;

use alloc::ffi::NulError;
use ckb_std::syscalls::SysError;
use log::info;

pub mod ckb_auth;
// pub mod error;

pub use ckb_auth_types::{AuthAlgorithmIdType, CkbAuthType, CkbAuthTypesError, EntryCategoryType};

#[derive(Debug)]
pub enum CkbAuthError {
    UnknowAlgorithmID,
    DynamicLinkingUninit,
    LoadDLError,
    LoadDLFuncError,
    RunDLError,
    ExecError(SysError),
    EncodeArgs,
}

impl From<SysError> for CkbAuthError {
    fn from(err: SysError) -> Self {
        info!("Exec error: {:?}", err);
        Self::ExecError(err)
    }
}

impl From<NulError> for CkbAuthError {
    fn from(err: NulError) -> Self {
        info!("Exec encode args failed: {:?}", err);
        Self::EncodeArgs
    }
}

impl From<CkbAuthTypesError> for CkbAuthError {
    fn from(err: CkbAuthTypesError) -> Self {
        match err {
            CkbAuthTypesError::UnknowAlgorithmID => Self::UnknowAlgorithmID,
            CkbAuthTypesError::EncodeArgs => Self::EncodeArgs,
        }
    }
}
