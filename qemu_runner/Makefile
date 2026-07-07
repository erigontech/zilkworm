# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# ========== Architecture selection ==========
# Default to riscv32im, can be overridden: make ARCH=rv64
ARCH ?= rv32

ifeq ($(ARCH),rv64)
  BUILD_DIR := $(CURDIR)/build64
  CMAKE_TOOLCHAIN := $(CURDIR)/cmake/riscv64im.cmake
  LINKER_SCRIPT := $(CURDIR)/qemu-xpack-64.ld
  QEMU_SYSTEM := qemu-system-riscv64
  START_ASM := start64.S
else
  BUILD_DIR := $(CURDIR)/build
  CMAKE_TOOLCHAIN := $(CURDIR)/cmake/riscv32im.cmake
  LINKER_SCRIPT := $(CURDIR)/qemu-xpack.ld
  QEMU_SYSTEM := qemu-system-riscv32
  START_ASM := start.S
endif

ELF := $(BUILD_DIR)/z6m_debug

EEST_SHA := $(shell python3 -c "import json;print(json.load(open('$(CURDIR)/../test-fixtures.json'))['eest_stable']['sha256'][:12])" 2>/dev/null)
EEST_MFBD_DIR ?= $(CURDIR)/../test-fixtures-cache/mfbd-$(EEST_SHA)

CMAKE_FLAGS := \
	-DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN) \
	-DCMAKE_EXE_LINKER_FLAGS="-T$(LINKER_SCRIPT) -z norelro" \
	-DSTART_ASM=$(START_ASM) \
	-DQEMU_SYSTEM=$(QEMU_SYSTEM) \
	-DQEMU_DEBUG=ON \
	-G "Unix Makefiles" \
	-Wno-dev

.PHONY: xpack-elf xpack-elf-eest xpack-elf-eest-json \
	eest-blockchain-tests eest-blockchain-tests-json \
	eest-mfbd-build rerun-ctest rerun-ctest-json \
	gdb rlp-qemu qemu-eest-stdio qemu-eest-fileio \
	eest-rv32 eest-rv64 clean clean-all clean-temp

eest-mfbd-build:
	$(MAKE) -C $(CURDIR)/.. eest-mfbd-build EEST_MFBD_DIR=$(EEST_MFBD_DIR)

xpack-elf:
	cmake -B$(BUILD_DIR) -S. $(CMAKE_FLAGS) -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(BUILD_DIR) -j$$(nproc) --verbose

xpack-elf-eest: eest-mfbd-build
	cmake -B$(BUILD_DIR) -S. $(CMAKE_FLAGS) -DCMAKE_BUILD_TYPE=Release \
		-DBUILD_TESTING=ON \
		-DEEST_MFBD_DIR=$(EEST_MFBD_DIR)
	cmake --build $(BUILD_DIR) -j$$(nproc) --verbose

eest-blockchain-tests: xpack-elf-eest
	ctest --test-dir $(BUILD_DIR) --parallel --output-on-failure

rerun-ctest: xpack-elf-eest
	ctest --test-dir $(BUILD_DIR) --parallel --output-on-failure -V --timeout 7200

EEST_JSON_DIR ?= $(CURDIR)/../test-fixtures-cache/eest_stable/fixtures/blockchain_tests

xpack-elf-eest-json:
	cmake -B$(BUILD_DIR) -S. $(CMAKE_FLAGS) -DCMAKE_BUILD_TYPE=Release \
		-DBUILD_TESTING=ON \
		-DEEST_JSON_DIR=$(EEST_JSON_DIR)
	cmake --build $(BUILD_DIR) -j$$(nproc) --verbose

eest-blockchain-tests-json: xpack-elf-eest-json
	ctest --test-dir $(BUILD_DIR) --parallel --output-on-failure

rerun-ctest-json: xpack-elf-eest-json
	ctest --test-dir $(BUILD_DIR) --parallel --output-on-failure -V --timeout 7200

# ========== Convenience targets ==========
eest-rv32:
	$(MAKE) ARCH=rv32 eest-blockchain-tests

eest-rv64:
	$(MAKE) ARCH=rv64 eest-blockchain-tests

# ========== QEMU runners ==========
gdb:
	riscv-none-elf-gdb -q -ex "target remote :1234" -x .gdbinit $(ELF)

## make rlp-qemu file-name=../prover/temp/blocks/2347866/uni...bin
rlp-qemu: xpack-elf
	@if [ -z "$(file-name)" ]; then echo "Usage: make rlp-qemu file-name=path/to.bin (ARCH=$(ARCH))"; exit 1; fi
	@mkdir -p $(CURDIR)/temp
	@N=$$(wc -c <"$(file-name)"); \
	{ printf "%u\n" $$N; cat "$(file-name)"; } > $(CURDIR)/temp/stdin_payload.bin
	@echo "QEMU waiting for GDB on :1234..."
	cd $(CURDIR)/temp && $(QEMU_SYSTEM) -M virt -m 2G -nographic \
		-bios $(ELF) -S -gdb tcp::1234 \
		-chardev stdio,mux=on,id=stdio0 \
		-serial chardev:stdio0 \
		-semihosting-config enable=on,chardev=stdio0 \
		-mon chardev=stdio0,mode=readline

qemu-eest-stdio: xpack-elf-eest
	@if [ -z "$(file-name)" ]; then echo "Usage: make qemu-eest-stdio file-name=path/to.bin (ARCH=$(ARCH))"; exit 1; fi
	@mkdir -p $(CURDIR)/temp
	@N=$$(wc -c <"$(file-name)"); \
	{ printf "%u\n" $$N; cat "$(file-name)"; } > $(CURDIR)/temp/stdin_payload.bin
	cd $(CURDIR)/temp && $(QEMU_SYSTEM) -M virt -m 2G -nographic \
		-bios $(ELF) \
		-chardev stdio,mux=on,id=stdio0 \
		-serial chardev:stdio0 \
		-semihosting-config enable=on,chardev=stdio0 \
		-mon chardev=stdio0,mode=readline

qemu-eest-fileio: xpack-elf-eest
	@if [ -z "$(file-name)" ]; then echo "Usage: make qemu-eest-fileio file-name=path/to.bin (ARCH=$(ARCH))"; exit 1; fi
	@mkdir -p $(CURDIR)/temp
	@rm -f $(CURDIR)/temp/semihost.log $(CURDIR)/temp/serial.log
	@N=$$(wc -c <"$(file-name)"); \
	{ printf "%u\n" $$N; cat "$(file-name)"; } > $(CURDIR)/temp/stdin_payload.bin
	cd $(CURDIR)/temp && $(QEMU_SYSTEM) -M virt -m 2G -display none \
		-bios $(ELF) \
		-monitor none \
		-serial none \
		-chardev file,id=shlog,path=semihost.log \
		-semihosting-config enable=on,target=native,chardev=shlog

clean:
	rm -rf $(BUILD_DIR)

clean-all:
	rm -rf $(CURDIR)/build $(CURDIR)/build64

clean-temp:
	rm -f $(CURDIR)/temp/stdin_payload.bin $(CURDIR)/temp/semihost.log $(CURDIR)/temp/serial.log
