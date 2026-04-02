BUILD_DIR := $(CURDIR)/build
# CMAKE_TOOLCHAIN := $(CURDIR)/cmake/riscv32im-clang.cmake
CMAKE_TOOLCHAIN := $(CURDIR)/cmake/riscv32im.cmake
LINKER_SCRIPT := $(CURDIR)/link.x
START_ASM := start.S

ELF := $(BUILD_DIR)/z6m_guest


zilkworm:
	@mkdir -p $(BUILD_DIR)/zilkworm
	cmake -B$(BUILD_DIR)/zilkworm -S../.. \
		-DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN) \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_MESSAGE_LOG_LEVEL=VERBOSE \
		-DCMAKE_VERBOSE_MAKEFILE=ON \
		-DCMAKE_INSTALL_PREFIX=$(BUILD_DIR)/zilkworm-install \
	    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
		-G "Unix Makefiles" \
		-DAIRBENDER=ON \
		-Wno-dev
	cmake --build $(BUILD_DIR)/zilkworm -j --target install

z6m_guest: zilkworm
	cmake -B$(BUILD_DIR) -S. \
		-DCMAKE_TOOLCHAIN_FILE=$(CMAKE_TOOLCHAIN) \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_MESSAGE_LOG_LEVEL=VERBOSE \
		-DCMAKE_VERBOSE_MAKEFILE=ON \
		-G "Unix Makefiles" \
		-DSTART_ASM=$(START_ASM) \
		-DBUILD_TESTING=ON \
		-DTESTS_DIR=$(CURDIR)/../third_party/eest-fixtures/blockchain_tests \
		-Wno-dev
	cmake --build $(BUILD_DIR) -j --verbose