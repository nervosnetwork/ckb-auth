CKB_DEBUGGER ?= ckb-debugger

all: \
	auth-spawn-success \
	auth-spawn-rust-success \
	cardano-success \
	ripple-success

auth-spawn-success:
	cargo run --bin auth-spawn-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock

auth-spawn-rust-success:
	cargo run --bin auth-spawn-rust-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock

cardano-success:
	./tools/gen_cardano_signature.sh
	cargo run --bin cardano-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock

ripple-success:
	cargo run --bin ripple-success > tx.json
	${CKB_DEBUGGER} --tx-file=tx.json -s lock
