This directory contains all the test code of ckb-auth


## Directory Structure

```
├── Makefile
├── auth-c-lock
├── auth-rust-lock
├── auth-c-tests
├── auth-spawn-tests
└── bin
```

* The `ckb-auth` is just a library for other contracts to call. For testing purposes, here is a complete contract implemented for testing `auth-c-lock` and `auth-rust-lock`.
* In `auth-rust-lock` there exists a simple test for testing `ckb-auth-rs`.
* `auth-c-tests` tests the ckb-auth library, including various scenarios.
* `auth-spawn-tests` uses ckb-debugger to test some typical scenarios, including tests for cardano and ripple.
* `bin` is not in the repositorie. It is a temporary directory created after calling `make install-all`.
* The tools are installed in the `bin`, because the specified version needs to be used here to prevent conflicts.
* Take the above, after installation, there will be two files: `.crates.toml` and `.crates2.json`. These two were created by cargo.


| Directory         | Description                               |
| ----------------- | ----------------------------------------- |
| auth-c-lock       | C language contract                       |
| auth-rust-lock    | Rust contract                             |
| auth-c-tests      | test ckb-auth                             |
| auth-spawn-tests  | test uses ckb-debugger                    |
| bin               | Tools needed for testing and chain        |

