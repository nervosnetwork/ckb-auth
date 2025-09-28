extern crate alloc;

use crate::{CkbAuthError, CkbAuthType, CkbEntryType, EntryCategoryType};
use alloc::ffi::CString;
use alloc::format;
use ckb_std::high_level::{exec_cell, spawn_cell};
use ckb_std::syscalls::wait;
use hex::encode;

#[cfg(feature = "enable-dynamic-library")]
use super::ckb_auth_dl::ckb_auth_dl;

pub fn ckb_auth(
    entry: &CkbEntryType,
    id: &CkbAuthType,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<(), CkbAuthError> {
    match entry.entry_category {
        EntryCategoryType::Exec => ckb_auth_exec(entry, id, signature, message),
        #[cfg(feature = "enable-dynamic-library")]
        EntryCategoryType::DynamicLibrary => ckb_auth_dl(entry, id, signature, message),
        EntryCategoryType::Spawn => ckb_auth_spawn(entry, id, signature, message),
    }
}

fn ckb_auth_spawn(
    entry: &CkbEntryType,
    id: &CkbAuthType,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<(), CkbAuthError> {
    let algorithm_id_str = CString::new(format!("{:02X?}", id.algorithm_id.clone() as u8,))?;
    let signature_str = CString::new(format!("{}", encode(signature)))?;
    let message_str = CString::new(format!("{}", encode(message)))?;
    let pubkey_hash_str = CString::new(format!("{}", encode(id.pubkey_hash)))?;

    let args = [
        algorithm_id_str.as_c_str(),
        signature_str.as_c_str(),
        message_str.as_c_str(),
        pubkey_hash_str.as_c_str(),
    ];

    let pid = spawn_cell(&entry.code_hash, entry.hash_type, &args, &[])?;
    let exit_code = wait(pid)?;
    if exit_code != 0 {
        return Err(CkbAuthError::VerifyFailed);
    }
    Ok(())
}

fn ckb_auth_exec(
    entry: &CkbEntryType,
    id: &CkbAuthType,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<(), CkbAuthError> {
    let algorithm_id_str = CString::new(format!("{:02X?}", id.algorithm_id.clone() as u8,))?;
    let signature_str = CString::new(format!("{}", encode(signature)))?;
    let message_str = CString::new(format!("{}", encode(message)))?;
    let pubkey_hash_str = CString::new(format!("{}", encode(id.pubkey_hash)))?;

    let args = [
        algorithm_id_str.as_c_str(),
        signature_str.as_c_str(),
        message_str.as_c_str(),
        pubkey_hash_str.as_c_str(),
    ];

    exec_cell(&entry.code_hash, entry.hash_type, &args)?;
    Ok(())
}
