use crate::error::Error;
use crate::utils::new_blake2b;
use blake2b_rs::Blake2b;
use ckb_std::ckb_constants::{InputField, Source};
use ckb_std::high_level::load_tx_hash;
use ckb_std::syscalls::{load_cell, load_input_by_field, load_witness, SysError};

pub const MAX_WITNESS_SIZE: usize = 32768;
pub const ONE_BATCH_SIZE: usize = 32768;

#[allow(dead_code)]
pub fn generate_sighash_all() -> Result<[u8; 32], Error> {
    let mut temp = [0u8; MAX_WITNESS_SIZE];

    // Load witness of first input.
    let mut read_len = load_witness(&mut temp, 0, 0, Source::GroupInput)?;
    let witness_len = read_len;
    if read_len > MAX_WITNESS_SIZE {
        read_len = MAX_WITNESS_SIZE;
    }

    // Load signature.
    if read_len < 20 {
        return Err(Error::Encoding);
    }
    let lock_length = u32::from_le_bytes(temp[16..20].try_into().unwrap()) as usize;
    if read_len < 20 + lock_length {
        return Err(Error::Encoding);
    }
    // Clear lock field to zero, then digest the first witness
    // lock_bytes_seg.ptr actually points to the memory in temp buffer.
    temp[20..20 + lock_length].fill(0);

    // Load tx hash.
    let tx_hash = load_tx_hash()?;

    // Prepare sign message.
    let mut blake2b_ctx = new_blake2b();
    blake2b_ctx.update(&tx_hash);
    blake2b_ctx.update(&(witness_len as u64).to_le_bytes());
    blake2b_ctx.update(&temp[..read_len]);

    // Remaining of first witness.
    if read_len < witness_len {
        load_and_hash_witness(&mut blake2b_ctx, read_len, 0, Source::GroupInput, false)?;
    }

    // Digest same group witnesses.
    let mut i = 1;
    loop {
        let sysret = load_and_hash_witness(&mut blake2b_ctx, 0, i, Source::GroupInput, true);
        match sysret {
            Err(SysError::IndexOutOfBound) => break,
            Err(x) => return Err(x.into()),
            Ok(_) => i += 1,
        }
    }

    // Digest witnesses that not covered by inputs.
    let mut i = calculate_inputs_len()?;

    loop {
        let sysret = load_and_hash_witness(&mut blake2b_ctx, 0, i, Source::Input, true);
        match sysret {
            Err(SysError::IndexOutOfBound) => break,
            Err(x) => return Err(x.into()),
            Ok(_) => i += 1,
        }
    }
    let mut msg = [0u8; 32];
    blake2b_ctx.finalize(&mut msg);
    Ok(msg)
}

fn load_and_hash_witness(
    ctx: &mut Blake2b,
    start: usize,
    index: usize,
    source: Source,
    hash_length: bool,
) -> Result<(), SysError> {
    let mut temp = [0u8; ONE_BATCH_SIZE];
    let len = load_witness(&mut temp, start, index, source)?;
    if hash_length {
        ctx.update(&(len as u64).to_le_bytes());
    }
    let mut offset = if len > ONE_BATCH_SIZE {
        ONE_BATCH_SIZE
    } else {
        len
    };
    ctx.update(&temp[..offset]);
    while offset < len {
        let current_len = load_witness(&mut temp, start + offset, index, source)?;
        let current_read = if current_len > ONE_BATCH_SIZE {
            ONE_BATCH_SIZE
        } else {
            current_len
        };
        ctx.update(&temp[..current_read]);
        offset += current_read;
    }
    Ok(())
}

fn calculate_inputs_len() -> Result<usize, Error> {
    let mut temp = [0u8; 8];
    let mut i = 0;
    loop {
        let sysret = load_input_by_field(&mut temp, 0, i, Source::Input, InputField::Since);
        match sysret {
            Err(SysError::IndexOutOfBound) => break,
            Err(x) => return Err(x.into()),
            Ok(_) => i += 1,
        }
    }
    Ok(i)
}

#[allow(dead_code)]
fn calculate_outputs_len() -> Result<usize, Error> {
    let mut temp = [0u8; 8];
    let mut i = 0;
    loop {
        let sysret = load_cell(&mut temp, 0, i, Source::Output);
        match sysret {
            Err(SysError::IndexOutOfBound) => break,
            Err(SysError::LengthNotEnough(_)) => i += 1,
            Err(x) => return Err(x.into()),
            Ok(_) => i += 1,
        }
    }
    Ok(i)
}
