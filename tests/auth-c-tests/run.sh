cd ../..
make -f examples/auth-c-demo/Makefile all-via-docker
cd tests/auth_rust
cargo test
