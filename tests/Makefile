

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
	rust-demo-tests-only-spawn \
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
		make build && \
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
	export PATH=$(shell pwd)/bin/:"$(PATH)" && \
	cd auth-rust-lock/ && \
	make build && \
	cd tests && \
	cargo test

clean-rust-demo-tests:
	export PATH=$(shell pwd)/bin/:"$(PATH)" && cd auth-rust-lock/ && make clean

rust-demo-tests-no-def-features: clean-rust-demo-tests
	export PATH=$(shell pwd)/bin/:"$(PATH)" && \
	cd auth-rust-lock && \
	CARGO_ARGS="--no-default-features" make build && \
	cd tests && \
	cargo test --no-default-features

rust-demo-tests-only-spawn: clean-rust-demo-tests
	export PATH=$(shell pwd)/bin/:"$(PATH)" && \
	cd auth-rust-lock && \
	CARGO_ARGS="--no-default-features" make build && \
	cd tests && \
	cargo test --no-default-features

rust-demo-tests-only-dl: clean-rust-demo-tests
	export PATH=$(shell pwd)/bin/:"$(PATH)" && \
	cd auth-rust-lock && \
	CARGO_ARGS="--no-default-features --features=\"enable-dynamic-library\"" make build && \
	cd tests && \
	cargo test --no-default-features --features="enable-dynamic-library"

spawn-tests:
	export PATH=`pwd`/bin/:"$(PATH)" && cd auth-spawn-tests && make all

clean-spawn-tests:
	rm -rf auth-spawn-tests/target

install-all: \
	install-riscv-tools \
	install-ckb-tools \
	install-litecoin-tools \
	install-cardano-tools

# 	install-monero-tools

install-ckb-tools: \
	bin \
	install-ckb-debugger

CKB_DEBUGGER_VERSION := v1.1.1
CKB_DEBUGGER_ARCHIVE := ckb-debugger_$(CKB_DEBUGGER_VERSION)_x86_64-unknown-linux-gnu.tar.gz

install-ckb-debugger:
ifeq ($(shell uname),Darwin)
	cargo install --git https://github.com/nervosnetwork/ckb-standalone-debugger ckb-debugger --tag $(CKB_DEBUGGER_VERSION) --root ./
else ifeq ($(shell uname),Linux)
	wget -nv 'https://github.com/nervosnetwork/ckb-standalone-debugger/releases/download/$(CKB_DEBUGGER_VERSION)/$(CKB_DEBUGGER_ARCHIVE)'
	tar zxvf $(CKB_DEBUGGER_ARCHIVE)
	mv ckb-debugger bin/ckb-debugger
	rm -rf LICENSE $(CKB_DEBUGGER_ARCHIVE)
endif

litecoin_tools_url=
monero_tools_url=
cardano_tools_url=
ifeq ($(shell uname),Darwin)
	litecoin_tools_url = https://download.litecoin.org/litecoin-0.21.2.2/osx/litecoin-0.21.2.2-osx64.tar.gz
	cardano_tools_url = https://update-cardano-mainnet.iohk.io/cardano-node-releases/cardano-node-8.0.0-macos.tar.gz
	ifeq ($(shell uname -m),arm64)
		monero_tools_url = https://downloads.getmonero.org/cli/monero-mac-armv8-v0.18.2.2.tar.bz2
	else
		monero_tools_url = https://downloads.getmonero.org/cli/monero-mac-x64-v0.18.2.2.tar.bz2
	endif

else ifeq ($(shell uname), Linux)
	litecoin_tools_url = https://download.litecoin.org/litecoin-0.21.2.2/linux/litecoin-0.21.2.2-x86_64-linux-gnu.tar.gz
	monero_tools_url = https://downloads.getmonero.org/cli/monero-linux-x64-v0.18.2.2.tar.bz2
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

install-cardano-tools:
	wget -nv $(cardano_tools_url)
	tar xvf `basename -- $(cardano_tools_url)` -C bin
	rm -rf cardano-*

install-riscv-tools:
	rustup target add riscv64imac-unknown-none-elf

bin:
	mkdir -p bin

clean: \
	clean-c-tests \
	clean-rust-demo-tests \
	clean-spawn-tests
