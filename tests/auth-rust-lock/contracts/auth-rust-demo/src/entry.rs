// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;
// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
// use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://docs.rs/ckb-std/

use crate::error::Error;

use ckb_auth_rs::{
    ckb_auth, generate_sighash_all, AuthAlgorithmIdType, CkbAuthError, CkbAuthType, CkbEntryType,
    EntryCategoryType,
};
#[cfg(feature = "enable-dynamic-library")]
use ckb_auth_rs::{ckb_auth_prepare, RECOMMEND_PREFILLED_LEN};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, core::ScriptHashType, prelude::*},
    high_level::{load_script, load_witness_args},
};

#[cfg(feature = "enable-dynamic-library")]
static mut SECP_DATA: [u8; RECOMMEND_PREFILLED_LEN] = [0u8; RECOMMEND_PREFILLED_LEN];

pub fn main() -> Result<(), Error> {
    let mut pubkey_hash = [0u8; 20];
    let auth_id: u8;
    let entry_type: u8;
    let hash_type: ScriptHashType;
    let mut code_hash = [0u8; 32];

    // get message
    let message = generate_sighash_all().map_err(|_| Error::GeneratedMsgError)?;
    let mut signature = {
        let script = load_script()?;
        let args: Bytes = script.args().unpack();
        if args.len() != 55 {
            return Err(Error::ArgsError);
        }
        auth_id = args[0] as u8;
        pubkey_hash.copy_from_slice(&args[1..21]);
        code_hash.copy_from_slice(&args[21..53]);
        hash_type = match args[53] as u8 {
            0 => ScriptHashType::Data,
            1 => ScriptHashType::Type,
            2 => ScriptHashType::Data1,
            4 => ScriptHashType::Data1, // TODO ckb-std 0.14.3 does not support Data2 yet
            _ => {
                return Err(Error::ArgsError);
            }
        };
        entry_type = args[54] as u8;

        let witness_args =
            load_witness_args(0, Source::GroupInput).map_err(|_| Error::WitnessError)?;

        witness_args
            .lock()
            .to_opt()
            .ok_or(CkbAuthError::SignatureMissing)?
            .raw_data()
    };

    let id = CkbAuthType {
        algorithm_id: AuthAlgorithmIdType::try_from(auth_id).map_err(|f| CkbAuthError::from(f))?,
        pubkey_hash: pubkey_hash,
    };

    match id.algorithm_id {
        AuthAlgorithmIdType::Ripple => {
            let l = signature[signature.len() - 1] as usize;
            if l >= signature.len() {
                return Err(Error::ArgsError);
            }
            signature = Bytes::from(signature[..signature.len() - l].to_vec());
        }
        _ => {}
    }

    let entry = CkbEntryType {
        code_hash,
        hash_type,
        entry_category: EntryCategoryType::try_from(entry_type)
            .map_err(|f| CkbAuthError::from(f))
            .unwrap(),
    };
    #[cfg(feature = "enable-dynamic-library")]
    let secp_data = {
        let mut len: usize = RECOMMEND_PREFILLED_LEN;
        ckb_auth_prepare(
            &entry,
            id.algorithm_id.clone(),
            unsafe { &mut SECP_DATA },
            &mut len,
        )?;
        unsafe { &SECP_DATA }
    };
    #[cfg(not(feature = "enable-dynamic-library"))]
    let secp_data = &mut [0u8; 1];

    ckb_auth(&entry, secp_data, &id, &signature, &message)?;
    // ckb_auth can be invoked multiple times for different signatures. Here we
    // use the same one to demo the usage.
    ckb_auth(&entry, secp_data, &id, &signature, &message)?;

    Ok(())
}
