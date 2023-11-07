pub mod generate_sighash_all;

pub use blake2b_rs::{Blake2b, Blake2bBuilder};

pub const CKB_PERSONALIZATION: &[u8] = b"ckb-default-hash";
pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_PERSONALIZATION)
        .build()
}
