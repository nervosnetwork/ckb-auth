cd ../..
make -f examples/auth-demo/Makefile all-via-docker
cd tests/auth_rust
cargo test
