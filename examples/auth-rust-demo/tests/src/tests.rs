// use super::*;
// use ckb_testtool::ckb_error::Error;
// use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
// use ckb_testtool::context::Context;

// const MAX_CYCLES: u64 = 10_000_000;

// // error numbers
// const ERROR_EMPTY_ARGS: i8 = 5;

// fn assert_script_error(err: Error, err_code: i8) {
//     let error_string = err.to_string();
//     assert!(
//         error_string.contains(format!("error code {} ", err_code).as_str()),
//         "error_string: {}, expected_error_code: {}",
//         error_string,
//         err_code
//     );
// }

// #[test]
// fn test_success() {}
