TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -g \
		-Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function \
		-fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostdlib -nostartfiles \
		-fvisibility=hidden -fdata-sections -ffunction-sections \
		-I deps/secp256k1/src \
		-I deps/secp256k1 \
		-I deps/ckb-c-std-lib \
		-I deps/ckb-c-std-lib/libc \
		-I deps/ckb-c-std-lib/molecule \
		-I c \
		-I build
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
AUTH_CFLAGS=$(subst ckb-c-std-lib,ckb-c-stdlib-2023,$(CFLAGS)) -Wno-dangling-pointer -Wno-array-bounds -Wno-stringop-overflow

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-jammy-20230214
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:d3f649ef8079395eb25a21ceaeb15674f47eaa2d8cc23adc8bcdae3d5abce6ec
CLANG_FORMAT_DOCKER := \
	kason223/clang-format@sha256:3cce35b0400a7d420ec8504558a02bdfc12fd2d10e40206f140c4545059cd95d

all: \
	build/auth_c_lock \
	build/auth_c_lock_disable_dl

all-via-docker:
	docker run --platform linux/amd64 --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make -f tests/auth-c-lock/Makefile all"

build/auth_c_lock: tests/auth-c-lock/auth_c_lock.c c/ckb_auth.h
	$(CC) $(AUTH_CFLAGS) $(LDFLAGS) -o $@ $^
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

build/auth_c_lock_disable_dl: tests/auth-c-lock/auth_c_lock.c c/ckb_auth.h
	$(CC) $(AUTH_CFLAGS) $(LDFLAGS) -DCKB_AUTH_DISABLE_DYNAMIC_LIB -o $@ $^
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

ALL_C_SOURCE := \
	tests/auth-c-lock/auth_c_lock.c

fmt:
	clang-format -i $(ALL_C_SOURCE)

fmt-via-docker:
	docker run -u `id -u`:`id -g` --rm -v `pwd`:/code ${CLANG_FORMAT_DOCKER} bash -c \
		"cd code && clang-format -i $(ALL_C_SOURCE)"

clean:
	rm -rf build/auth_c_lock
