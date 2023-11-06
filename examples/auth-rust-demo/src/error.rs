use ckb_auth_rs::CkbAuthError;
use ckb_std::error::SysError;

/// Error
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Add customized errors here...
    ArgsError,
    WitnessError,
    GeneratedMsgError,
    LoadDLError,
    RunAuthError,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

impl From<CkbAuthError> for Error {
    fn from(value: CkbAuthError) -> Self {
        use CkbAuthError::*;
        match value {
            UnknowAlgorithmID => Self::Encoding,
            LoadDLError => Self::LoadDLError,
            LoadDLFuncError => Self::LoadDLError,
            RunDLError => Self::RunAuthError,
            _ => panic!("unexpected error"),
        }
    }
}
