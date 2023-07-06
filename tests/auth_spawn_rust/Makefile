CKB_DEBUGGER ?= ckb-debugger

all: \
	auth-spawn-success \
	auth-spawn-rust-success

auth-spawn-success:
	cargo run --bin auth-spawn-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock

auth-spawn-rust-success:
	cd ../.. && capsule build
	cargo run --bin auth-spawn-rust-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock

ripple-success:
	cd ../.. && capsule build
	cargo run --bin ripple-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock

install:
	wget 'https://github.com/XuJiandong/ckb-standalone-debugger/releases/download/ckb2023-0621/ckb-debugger-linux-x64.tar.gz'
	tar zxvf ckb-debugger-linux-x64.tar.gz
	mv ckb-debugger ~/.cargo/bin/ckb-debugger
	wget https://github.com/nervosnetwork/capsule/releases/download/v0.9.2/capsule_v0.9.2_x86_64-linux.tar.gz
	tar xzvf capsule*.tar.gz
	mv capsule_*/capsule ~/.cargo/bin
	cargo install moleculec --git https://github.com/nervosnetwork/molecule.git --rev 1306c29c529ab375e0368ffeb691bd8c7bbf0403
