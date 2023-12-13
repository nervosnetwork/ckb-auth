use crate::{CkbAuthError, CkbAuthType, CkbEntryType};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use ckb_std::{
    ckb_types::core::ScriptHashType,
    dynamic_loading_c_impl::{CKBDLContext, Library, Symbol},
};
use core::mem::size_of;

#[cfg(feature = "dynamic-library-memory-200")]
type DLContext = CKBDLContext<[u8; 200 * 1024]>;

#[cfg(feature = "dynamic-library-memory-400")]
type DLContext = CKBDLContext<[u8; 400 * 1024]>;

#[cfg(feature = "dynamic-library-memory-600")]
type DLContext = CKBDLContext<[u8; 600 * 1024]>;

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
    pub context: Box<DLContext>,
    pub context_used: usize,
    pub loaded_lib: BTreeMap<[u8; 33], Library>,
}

lazy_static::lazy_static! {
    static ref G_DL_CONTEXT: DLContext = unsafe { DLContext::new() };
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
            context: unsafe {
                let dl_ctx: &DLContext = &G_DL_CONTEXT;
                Box::from_raw(dl_ctx as *const DLContext as *mut DLContext)
            },
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
            let size = size_of::<DLContext>();
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

pub fn ckb_auth_dl(
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
