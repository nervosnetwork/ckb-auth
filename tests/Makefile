

all: \
	c-tests \
	spawn-tests

build-examples:
	cd .. && make -f examples/auth-demo/Makefile all-via-docker
	cd ../examples/auth-rust-demo && capsule build && mv build/debug/auth-rust-demo ../../build

c-tests:
	cd auth-c-tests && cargo test

spawn-tests:
	cd auth-spawn-tests && make all

install_all: \
	install_ckb_debugger \
	install_capsule \
	install_moleculec \
	install_litecoin_tools \
	install_monero_tools \
	install_solana_tools \
	install_cardano_tools

install_ckb_debugger:
	wget 'https://github.com/XuJiandong/ckb-standalone-debugger/releases/download/ckb2023-0621/ckb-debugger-linux-x64.tar.gz'
	tar zxvf ckb-debugger-linux-x64.tar.gz
	mv ckb-debugger ~/.cargo/bin/ckb-debugger

install_capsule:
	wget https://github.com/nervosnetwork/capsule/releases/download/v0.10.2/capsule_v0.10.2_x86_64-linux.tar.gz
	tar xzvf capsule*.tar.gz
	mv capsule_*/capsule ~/.cargo/bin

install_moleculec:
	cargo install moleculec --git https://github.com/nervosnetwork/molecule.git --rev 1306c29c529ab375e0368ffeb691bd8c7bbf0403

install_litecoin_tools:
	tarball=litecoin.tar.gz
	wget -O "$tarball" https://download.litecoin.org/litecoin-0.21.2.2/linux/litecoin-0.21.2.2-x86_64-linux-gnu.tar.gz
	tar xvzf "$tarball"
	sudo cp -r litecoin-*/* /usr/local/
	litecoin-cli --help

install_monero_tools:
	tarball=monero-wallet-cli.tar.gz
	wget -O "$tarball" https://downloads.getmonero.org/cli/monero-linux-x64-v0.18.2.2.tar.bz2
	tar xvaf "$tarball"
	sudo cp -r monero-*/* /usr/local/bin/
	monero-wallet-cli --help

install_solana_tools:
	tarball=solana-release-x86_64-unknown-linux-gnu.tar.bz2
	wget -O "$tarball" https://github.com/solana-labs/solana/releases/download/v1.16.1/solana-release-x86_64-unknown-linux-gnu.tar.bz2
	tar xvaf "$tarball"
	sudo cp -r solana-*/* /usr/local/
	solana --help
	solana-keygen new --force --no-bip39-passphrase

install_cardano_tools:
	mkdir -p bin
	cd bin && wget ${CARDANO_LOCK_TOOLS_URL} && tar -xf `basename -- $(CARDANO_LOCK_TOOLS_URL)`
