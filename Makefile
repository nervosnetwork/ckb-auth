TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
AR := $(TARGET)-ar

CFLAGS := -g -O3 -fPIC \
		-Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -Wno-dangling-pointer \
		-fno-builtin-printf -fno-builtin-memcmp \
		-nostdinc -nostdlib -nostartfiles -fvisibility=hidden \
		-fdata-sections -ffunction-sections

LDFLAGS := -Wl,-static -Wl,--gc-sections

INCLUDE_SECP256K1_CFLAGS = -I deps/secp256k1-20210801/src -I deps/secp256k1-20210801
INCLUDE_CKB_STD_CFLAGS = -I deps/ckb-c-stdlib-2023 -I deps/ckb-c-stdlib-2023/libc -I deps/ckb-c-stdlib-2023/molecule
INCLUDE_CFLAGS := $(INCLUDE_SECP256K1_CFLAGS) $(INCLUDE_CKB_STD_CFLAGS) -I c -I build -I deps/mbedtls/include -I deps/ed25519/src -I c/cardano/nanocbor

AUTH_CFLAGS := $(CFLAGS) $(INCLUDE_CFLAGS) -Wno-array-bounds -Wno-stringop-overflow
PASSED_MBEDTLS_CFLAGS := $(CFLAGS) -DCKB_DECLARATION_ONLY -I ../../ckb-c-stdlib-2023/libc

SECP256K1_SRC_20210801 := deps/secp256k1-20210801/src/ecmult_static_pre_context.h

CFLAGS_LIBECC := -fno-builtin -DUSER_NN_BIT_LEN=256 -DWORDSIZE=64 -DWITH_STDLIB -DWITH_CKB -DCKB_DECLARATION_ONLY -fPIC -g -O3
LIBECC_OPTIMIZED_PATH := deps/libecc
LIBECC_OPTIMIZED_FILES := ${LIBECC_OPTIMIZED_PATH}/build/libarith.a ${LIBECC_OPTIMIZED_PATH}/build/libec.a ${LIBECC_OPTIMIZED_PATH}/build/libsign.a
CFLAGS_LIBECC_OPTIMIZED = -I ../ckb-c-stdlib-2023 -I ../ckb-c-stdlib-2023/libc -I ../ckb-c-stdlib-2023/molecule $(CFLAGS_LIBECC) -DWITH_LL_U256_MONT
CFLAGS_LINK_TO_LIBECC_OPTIMIZED := -fno-builtin -fno-builtin-printf -DWORDSIZE=64 -DWITH_STDLIB -DWITH_CKB -I ${LIBECC_OPTIMIZED_PATH}/src -I ${LIBECC_OPTIMIZED_PATH}/src/external_deps

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-jammy-20230214
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:d3f649ef8079395eb25a21ceaeb15674f47eaa2d8cc23adc8bcdae3d5abce6ec

all:  build/secp256k1_data_info_20210801.h $(SECP256K1_SRC_20210801) deps/mbedtls/library/libmbedcrypto.a build/auth_libecc build/auth build/always_success

all-via-docker: ${PROTOCOL_HEADER}
	mkdir -p build
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make all"

build/always_success: c/always_success.c
	$(CC) $(AUTH_CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/secp256k1_data_info_20210801.h: build/dump_secp256k1_data_20210801
	$<

build/dump_secp256k1_data_20210801: c/dump_secp256k1_data_20210801.c $(SECP256K1_SRC_20210801)
	mkdir -p build
	gcc -I deps/ckb-c-stdlib-2023 -I deps/secp256k1-20210801/src -I deps/secp256k1-20210801 -o $@ $<

$(SECP256K1_SRC_20210801):
	cd deps/secp256k1-20210801 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

$(LIBECC_OPTIMIZED_FILES): libecc

libecc:
	make -C ${LIBECC_OPTIMIZED_PATH} LIBECC_WITH_LL_U256_MONT=1 CC=${CC} LD=${LD} CFLAGS="$(CFLAGS_LIBECC_OPTIMIZED)"

deps/mbedtls/library/libmbedcrypto.a:
	cp deps/mbedtls-config-template.h deps/mbedtls/include/mbedtls/config.h
	make -C deps/mbedtls/library APPLE_BUILD=0 AR=$(AR) CC=${CC} LD=${LD} CFLAGS="${PASSED_MBEDTLS_CFLAGS}" LDFLAGS="${LDFLAGS}" libmbedcrypto.a

build/nanocbor/%.o: c/cardano/nanocbor/%.c
	mkdir -p build/nanocbor
	$(CC) -c -DCKB_DECLARATION_ONLY -I c/cardano -I c/cardano/nanocbor $(AUTH_CFLAGS) $(LDFLAGS) -o $@ $^
build/libnanocbor.a: build/nanocbor/encoder.o build/nanocbor/decoder.o
	$(AR) cr $@ $^
build/ed25519/%.o: deps/ed25519/src/%.c
	mkdir -p build/ed25519
	$(CC) -c -DCKB_DECLARATION_ONLY $(AUTH_CFLAGS) $(LDFLAGS) -o $@ $^
build/libed25519.a: build/ed25519/sign.o build/ed25519/verify.o build/ed25519/sha512.o build/ed25519/sc.o build/ed25519/keypair.o \
					build/ed25519/key_exchange.o build/ed25519/ge.o build/ed25519/fe.o build/ed25519/add_scalar.o
	$(AR) cr $@ $^

build/auth: c/auth.c c/cardano/cardano_lock_inc.h c/ripple.h deps/mbedtls/library/libmbedcrypto.a build/libed25519.a build/libnanocbor.a
	$(CC) $(AUTH_CFLAGS) $(LDFLAGS) -fPIE -pie -Wl,--dynamic-list c/auth.syms -o $@ $^
	cp $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@
	ls -l $@

build/auth_libecc: c/auth_libecc.c $(LIBECC_OPTIMIZED_FILES)
	$(CC) $(AUTH_CFLAGS) $(CFLAGS_LINK_TO_LIBECC_OPTIMIZED) $(LDFLAGS) -fPIE -pie -Wl,--dynamic-list c/auth.syms -o $@ $^
	cp $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@
	ls -l $@

fmt:
	clang-format -i -style="{BasedOnStyle: Google, IndentWidth: 4}" c/*.c c/*.h

clean:
	rm -rf build/*.debug
	rm -f build/auth build/auth_libecc build/auth_demo build/auth-rust-demo
	rm -rf build/secp256k1_data_info_20210801.h build/dump_secp256k1_data_20210801
	rm -rf build/ed25519 build/libed25519.a build/nanocbor build/libnanocbor.a
	cd deps/secp256k1-20210801 && [ -f "Makefile" ] && make clean
	make -C deps/mbedtls/library clean
	make -C deps/libecc clean

.PHONY: all all-via-docker

