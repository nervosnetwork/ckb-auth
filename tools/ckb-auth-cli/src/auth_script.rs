use anyhow::{anyhow, Error};
use ckb_auth_types::AuthAlgorithmIdType;
use ckb_vm::cost_model::estimate_cycles;
use ckb_vm::registers::{A0, A1, A2, A3, A4, A5, A7};
use ckb_vm::{Bytes, Memory, Register, SupportMachine, Syscalls};
use hex::encode;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref AUTH_CODE: Bytes = Bytes::from(&include_bytes!("../../../build/auth")[..]);
    pub static ref CKB_SECP256K1_DATA: Bytes =
        Bytes::from(&include_bytes!("../../../build/secp256k1_data_20210801")[..]);
}

const CKB_SECP256K1_DATA_HASH: [u8; 32] = [
    151, 153, 190, 226, 81, 185, 117, 184, 44, 69, 160, 33, 84, 206, 40, 206, 200, 156, 88, 83,
    236, 193, 77, 18, 183, 184, 204, 207, 193, 158, 10, 244,
];

pub struct DebugSyscall {}
impl<Mac: SupportMachine> Syscalls<Mac> for DebugSyscall {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), ckb_vm::error::Error> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, ckb_vm::error::Error> {
        let code = &machine.registers()[A7];

        match code.to_i32() {
            2081 => self.ecall_load_cell_by_field(machine),
            2092 => self.ecall_load_cell_data(machine),
            2177 => self.ecall_debug(machine),
            _ => Ok(false),
        }
    }
}
impl DebugSyscall {
    fn ecall_debug<Mac: SupportMachine>(
        &mut self,
        machine: &mut Mac,
    ) -> Result<bool, ckb_vm::error::Error> {
        let mut addr = machine.registers()[A0].to_u64();
        let mut buffer = Vec::new();

        loop {
            let byte = machine
                .memory_mut()
                .load8(&Mac::REG::from_u64(addr))?
                .to_u8();
            if byte == 0 {
                break;
            }
            buffer.push(byte);
            addr += 1;
        }

        let s = String::from_utf8(buffer).unwrap();
        println!("{:?}", s);

        Ok(true)
    }

    fn ecall_load_cell_by_field<Mac: SupportMachine>(
        &mut self,
        machine: &mut Mac,
    ) -> Result<bool, ckb_vm::error::Error> {
        let addr = machine.registers()[A0].to_u64();
        let addr_len_ptr = machine.registers()[A1].clone();
        let addr_size = machine.memory_mut().load64(&addr_len_ptr)?.to_u64();

        let index = machine.registers()[A3].to_u64();
        let source = machine.registers()[A4].to_u64();
        let field = machine.registers()[A5].to_u64();

        if index == 0 && source == 3 && field == 1 {
            let data_len = CKB_SECP256K1_DATA_HASH.len() as u64;
            let offset = std::cmp::min(data_len, machine.registers()[A2].to_u64());
            let full_size = data_len - offset;
            let real_size = std::cmp::min(addr_size, full_size);
            machine.memory_mut().store_bytes(
                addr,
                &CKB_SECP256K1_DATA_HASH[offset as usize..(offset + real_size) as usize],
            )?;
            machine.set_register(A0, Mac::REG::from_u8(0));
            return Ok(true);
        }

        Ok(false)
    }

    fn ecall_load_cell_data<Mac: SupportMachine>(
        &mut self,
        machine: &mut Mac,
    ) -> Result<bool, ckb_vm::error::Error> {
        let addr = machine.registers()[A0].to_u64();
        let addr_len_ptr = machine.registers()[A1].clone();
        let addr_size = machine.memory_mut().load64(&addr_len_ptr)?.to_u64();

        let index = machine.registers()[A3].to_u64();
        let source = machine.registers()[A4].to_u64();
        let field = machine.registers()[A5].to_u64();

        if index == 0 && source == 3 && field == 0 {
            let data_len = CKB_SECP256K1_DATA.len() as u64;
            let offset = std::cmp::min(data_len, machine.registers()[A2].to_u64());
            let full_size = data_len - offset;
            let real_size = std::cmp::min(addr_size, full_size);
            machine.memory_mut().store_bytes(
                addr,
                &CKB_SECP256K1_DATA[offset as usize..(offset + real_size) as usize],
            )?;
            machine.set_register(A0, Mac::REG::from_u8(0));
            return Ok(true);
        }

        Ok(false)
    }
}

pub fn run_auth_exec(
    algorithm_id: AuthAlgorithmIdType,
    pubkey_hash: &[u8],
    message: &[u8],
    sign: &[u8],
) -> Result<(), Error> {
    let args_algorithm_id = format!("{:02X?}", algorithm_id as u8);
    let args_sign = encode(sign);
    let args_msg = encode(message);
    let args_pubkey_hash = encode(pubkey_hash);

    // println!(
    //     "ckb-vm args: \n{}\n{}\n{}\n{}",
    //     args_algorithm_id, args_sign, args_msg, args_pubkey_hash
    // );

    let asm_core = ckb_vm::machine::asm::AsmCoreMachine::new(
        ckb_vm::ISA_IMC | ckb_vm::ISA_B | ckb_vm::ISA_MOP,
        ckb_vm::machine::VERSION1,
        u64::MAX,
    );
    let core = ckb_vm::DefaultMachineBuilder::new(asm_core)
        .instruction_cycle_func(Box::new(estimate_cycles))
        .syscall(Box::new(DebugSyscall {}))
        .build();
    let mut machine = ckb_vm::machine::asm::AsmMachine::new(core);
    machine
        .load_program(
            &AUTH_CODE,
            &[
                Bytes::copy_from_slice(args_algorithm_id.as_bytes()),
                Bytes::copy_from_slice(args_sign.as_bytes()),
                Bytes::copy_from_slice(args_msg.as_bytes()),
                Bytes::copy_from_slice(args_pubkey_hash.as_bytes()),
            ],
        )
        .expect("load auth_code failed");
    let exit = machine.run().expect("run failed");

    if exit != 0 {
        Err(anyhow!("verify failed, return code: {}", exit))
    } else {
        Ok(())
    }
}
