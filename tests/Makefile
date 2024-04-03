

# This may cause insufficient storage space, so add clean
all: \
	build-auth-lock \
	c-tests \
	clean-c-tests \
	rust-demo-tests \
	clean-rust-demo-tests \
	spawn-tests \
	clean-spawn-tests \
	rust-demo-tests-no-def-features \
	rust-demo-tests-only-ckb2023 \
	rust-demo-tests-only-dl

all-with-clang: \
	build-auth-lock-with-clang \
	c-tests \
	clean-c-tests \
	spawn-tests \
	clean-spawn-tests

all_tests:
	c-tests \
	spawn-tests

build-auth-rust-lock:
	export PATH=$(shell pwd)/bin/:"$(PATH)" && \
		cd auth-rust-lock && \
		capsule build --release && \
		cp build/release/auth-rust-demo ../../build

build-auth-lock: build-auth-rust-lock
	cd .. && make -f tests/auth-c-lock/Makefile all-via-docker

build-auth-lock-with-clang: build-auth-rust-lock
	cd .. && make -f tests/auth-c-lock/Makefile.clang all

c-tests:
	export PATH=$(shell pwd)/bin/:"$(PATH)" && cd auth-c-tests && cargo test

clean-c-tests:
	rm -rf auth-c-tests/target

rust-demo-tests:
	export PATH=$(shell pwd)/bin/:"$(PATH)" && cd auth-rust-lock/ && capsule build && capsule test

clean-rust-demo-tests:
	export PATH=$(shell pwd)/bin/:"$(PATH)" && cd auth-rust-lock/ && capsule clean

rust-demo-tests-no-def-features: clean-rust-demo-tests
	export PATH=$(shell pwd)/bin/:"$(PATH)" && \
	cd auth-rust-lock && \
	capsule build -- --no-default-features && \
	cd tests && \
	cargo test --no-default-features

rust-demo-tests-only-ckb2023: clean-rust-demo-tests
	export PATH=$(shell pwd)/bin/:"$(PATH)" && \
	cd auth-rust-lock && \
	capsule build -- --no-default-features --features="ckb2023" && \
	cd tests && \
	cargo test --no-default-features --features="ckb2023"

rust-demo-tests-only-dl: clean-rust-demo-tests
	export PATH=$(shell pwd)/bin/:"$(PATH)" && \
	cd auth-rust-lock && \
	capsule build -- --no-default-features --features="enable-dynamic-library" && \
	cd tests && \
	cargo test --no-default-features --features="enable-dynamic-library"

spawn-tests:
	export PATH=`pwd`/bin/:"$(PATH)" && cd auth-spawn-tests && make all

clean-spawn-tests:
	rm -rf auth-spawn-tests/target

install-all: \
	install-ckb-tools \
	install-litecoin-tools \
	install-solana-tools \
	install-cardano-tools

# 	install-monero-tools

install-ckb-tools: \
	bin \
	install-ckb-debugger \
	install-capsule \
	install-cross

install-ckb-debugger:
ifeq ($(shell uname),Darwin)
	cargo install --git https://github.com/nervosnetwork/ckb-standalone-debugger ckb-debugger --tag v0.111.0 --root ./
else ifeq ($(shell uname),Linux)
	wget -nv 'https://github.com/nervosnetwork/ckb-standalone-debugger/releases/download/v0.111.0/ckb-debugger-linux-x64.tar.gz'
	tar zxvf ckb-debugger-linux-x64.tar.gz
	mv ckb-debugger bin/ckb-debugger
	rm -rf LICENSE ckb-debugger-linux-x64.tar.gz
endif

install-capsule:
ifeq ($(shell uname),Darwin)
	cargo install ckb-capsule --version "0.10.2" --root ./
else ifeq ($(shell uname), Linux)
	wget -nv https://github.com/nervosnetwork/capsule/releases/download/v0.10.2/capsule_v0.10.2_x86_64-linux.tar.gz
	tar xzvf capsule*.tar.gz
	mv capsule_*/capsule bin
	rm -rf capsule_v0.10.2_x86_64-linux capsule_v0.10.2_x86_64-linux.tar.gz
endif

install-cross:
	cargo install cross --git https://github.com/cross-rs/cross --root ./

litecoin_tools_url=
monero_tools_url=
solana_tools_url=
cardano_tools_url=
ifeq ($(shell uname),Darwin)
	litecoin_tools_url = https://download.litecoin.org/litecoin-0.21.2.2/osx/litecoin-0.21.2.2-osx64.tar.gz
	cardano_tools_url = https://update-cardano-mainnet.iohk.io/cardano-node-releases/cardano-node-8.0.0-macos.tar.gz
	ifeq ($(shell uname -m),arm64)
		solana_tools_url = https://github.com/solana-labs/solana/releases/download/v1.16.1/solana-release-aarch64-apple-darwin.tar.bz2
		monero_tools_url = https://downloads.getmonero.org/cli/monero-mac-armv8-v0.18.2.2.tar.bz2
	else
		solana_tools_url = https://github.com/solana-labs/solana/releases/download/v1.16.1/solana-release-x86_64-apple-darwin.tar.bz2
		monero_tools_url = https://downloads.getmonero.org/cli/monero-mac-x64-v0.18.2.2.tar.bz2
	endif

else ifeq ($(shell uname), Linux)
	litecoin_tools_url = https://download.litecoin.org/litecoin-0.21.2.2/linux/litecoin-0.21.2.2-x86_64-linux-gnu.tar.gz
	monero_tools_url = https://downloads.getmonero.org/cli/monero-linux-x64-v0.18.2.2.tar.bz2
	solana_tools_url = https://github.com/solana-labs/solana/releases/download/v1.16.1/solana-release-x86_64-unknown-linux-gnu.tar.bz2
	cardano_tools_url = https://update-cardano-mainnet.iohk.io/cardano-node-releases/cardano-node-8.0.0-linux.tar.gz
endif

install-litecoin-tools:
	wget -nv $(litecoin_tools_url)
	tar xvf `basename -- $(litecoin_tools_url)`
	cp -r litecoin-*/bin/* ./bin
	rm -rf litecoin*
	bin/litecoin-cli --version

# install-monero-tools:
# 	wget -nv $(monero_tools_url)
# 	tar xvf `basename -- $(monero_tools_url)`
# 	cp -r monero-*/* bin
# 	rm -rf monero-* bin/ANONYMITY_NETWORKS.md bin/README.md bin/LICENSE
# 	bin/monero-wallet-cli --version

install-solana-tools:
	wget -nv $(solana_tools_url)
	tar xvf `basename -- $(solana_tools_url)`
	cp -r solana-*/bin/* bin
	rm -rf solana-*
	bin/solana --version
	bin/solana-keygen new --force --no-bip39-passphrase

install-cardano-tools:
	wget -nv $(cardano_tools_url)
	tar xvf `basename -- $(cardano_tools_url)` -C bin
	rm -rf cardano-*

bin:
	mkdir -p bin

clean: \
	clean-c-tests \
	clean-rust-demo-tests \
	clean-spawn-tests
