extern crate alloc;

use crate::{CkbAuthError, CkbAuthType, CkbEntryType, EntryCategoryType};
use alloc::collections::BTreeMap;
use alloc::ffi::CString;
use alloc::format;
use alloc::vec::Vec;
#[cfg(feature = "ckb2023")]
use ckb_std::high_level::spawn_cell;
use ckb_std::{
    ckb_types::core::ScriptHashType,
    dynamic_loading_c_impl::{CKBDLContext, Library, Symbol},
};
use core::mem::size_of_val;
use hex::encode;

pub fn ckb_auth(
    entry: &CkbEntryType,
    id: &CkbAuthType,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<(), CkbAuthError> {
    match entry.entry_category {
        // EntryCategoryType::Exec => ckb_auth_exec(entry, id, signature, message),
        EntryCategoryType::DynamicLinking => ckb_auth_dl(entry, id, signature, message),
        #[cfg(feature = "ckb2023")]
        EntryCategoryType::Spawn => ckb_auth_spawn(entry, id, signature, message),
    }
}

#[cfg(feature = "ckb2023")]
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

    spawn_cell(&entry.code_hash, entry.hash_type, &args, 8, &mut Vec::new())?;
    Ok(())
}

type DLContext = CKBDLContext<[u8; 512 * 1024]>;
type CkbAuthValidate = unsafe extern "C" fn(
    auth_algorithm_id: u8,
    signature: *const u8,
    signature_size: u32,
    message: *const u8,
    message_size: u32,
    pubkey_hash: *mut u8,
    pubkey_hash_size: u32,
) -> i32;

const EXPORTED_FUNC_NAME: &str = "ckb_auth_validate";

struct CKBDLLoader {
    pub context: DLContext,
    pub context_used: usize,
    pub loaded_lib: BTreeMap<[u8; 33], Library>,
}

static mut G_CKB_DL_LOADER: Option<CKBDLLoader> = None;
impl CKBDLLoader {
    pub fn get() -> &'static mut Self {
        unsafe {
            match G_CKB_DL_LOADER.as_mut() {
                Some(v) => v,
                None => {
                    G_CKB_DL_LOADER = Some(Self::new());
                    G_CKB_DL_LOADER.as_mut().unwrap()
                }
            }
        }
    }

    fn new() -> Self {
        Self {
            context: unsafe { DLContext::new() },
            context_used: 0,
            loaded_lib: BTreeMap::new(),
        }
    }

    fn get_lib(
        &mut self,
        code_hash: &[u8; 32],
        hash_type: ScriptHashType,
    ) -> Result<&Library, CkbAuthError> {
        let mut lib_key = [0u8; 33];
        lib_key[..32].copy_from_slice(code_hash);
        lib_key[32] = hash_type as u8;

        let has_lib = match self.loaded_lib.get(&lib_key) {
            Some(_) => true,
            None => false,
        };

        if !has_lib {
            let size = size_of_val(&self.context);
            let lib = self
                .context
                .load_with_offset(code_hash, hash_type, self.context_used, size)
                .map_err(|_| CkbAuthError::LoadDLError)?;
            self.context_used += lib.consumed_size();
            self.loaded_lib.insert(lib_key.clone(), lib);
        };
        Ok(self.loaded_lib.get(&lib_key).unwrap())
    }

    pub fn get_validate_func<T>(
        &mut self,
        code_hash: &[u8; 32],
        hash_type: ScriptHashType,
        func_name: &str,
    ) -> Result<Symbol<T>, CkbAuthError> {
        let lib = self.get_lib(code_hash, hash_type)?;

        let func: Option<Symbol<T>> = unsafe { lib.get(func_name.as_bytes()) };
        if func.is_none() {
            return Err(CkbAuthError::LoadDLFuncError);
        }
        Ok(func.unwrap())
    }
}

fn ckb_auth_dl(
    entry: &CkbEntryType,
    id: &CkbAuthType,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<(), CkbAuthError> {
    let func: Symbol<CkbAuthValidate> = CKBDLLoader::get().get_validate_func(
        &entry.code_hash,
        entry.hash_type,
        EXPORTED_FUNC_NAME,
    )?;

    let mut pub_key = id.pubkey_hash.clone();
    let rc_code = unsafe {
        func(
            id.algorithm_id.clone().into(),
            signature.as_ptr(),
            signature.len() as u32,
            message.as_ptr(),
            message.len() as u32,
            pub_key.as_mut_ptr(),
            pub_key.len() as u32,
        )
    };

    match rc_code {
        0 => Ok(()),
        _ => Err(CkbAuthError::RunDLError),
    }
}
