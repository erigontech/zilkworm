SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c
.PHONY: z6m_guest z6m_prover eest-prover-test z6m_eest_convert eest-blockchain-tests \
        execute-block selftest tests eest-rlp-build \
        eest-blockchain-tests-json eest-prover-test-json tests-json

clean: 
	rm -rf prover/guest_hypercube/build/
	rm -rf prover/target
	
z6m_guest:
	cmake -S prover/guest_hypercube -B prover/guest_hypercube/build \
		-DCMAKE_TOOLCHAIN_FILE=$(CURDIR)/prover/guest_hypercube/cmake/riscv64im-sp1.cmake \
		-DCMAKE_BUILD_TYPE=Release \
		-DSP1=ON
	cmake --build prover/guest_hypercube/build -j$$(nproc)
z6m_prover: z6m_guest
	cd prover && cargo build --release --manifest-path prover_hypercube/Cargo.toml

test_hc: z6m_prover
	prover/target/release/z6m_prover execute --block-number 23540896 --data-dir prover/prover_turbo/temp

z6m_guest_turbo:
	rm -r prover/target/elf-compilation/riscv32im-succinct-zkvm-elf/release/build/z6m_guest-* || true
	(cd prover/guest_turbo && cargo prove build)

z6m_prover_turbo: z6m_guest_turbo
	cd prover && cargo build --release --manifest-path prover_turbo/Cargo.toml

execute-block: z6m_prover
	prover/target/release/z6m_prover execute --file-name prover/temp/blocks/23519000/unifiedBlockAndStateRlp23519000.bin

SELFTEST_JSON := third_party/eest-fixtures/blockchain_tests/static/state_tests/stExample/add11.json
SELFTEST_RLP  := build/selftest.rlp

selftest: z6m_prover z6m_eest_convert
	@mkdir -p $(dir $(SELFTEST_RLP))
	$(EEST_CONVERT_BIN) emit --json $(SELFTEST_JSON) --index 0 > $(SELFTEST_RLP)
	prover/target/release/z6m_prover execute --file-name $(SELFTEST_RLP)

TESTS_LOG_DIR := target/logs

tests: z6m_prover eest-rlp-build
	@mkdir -p $(TESTS_LOG_DIR)/$(TESTS_SUBDIR)
	prover/target/release/z6m_prover --test-service \
		--test-dir $(EEST_RLP_DIR)/$(TESTS_SUBDIR) \
		--execution-log-dir $(TESTS_LOG_DIR)/$(TESTS_SUBDIR)

.DELETE_ON_ERROR:

EEST_CONVERT_BIN := prover/target/release/z6m_eest_convert

# Phony: delegate freshness to cargo's own incremental build (~ms when up-to-date).
z6m_eest_convert:
	cd prover && cargo build --release --manifest-path common/Cargo.toml \
		--no-default-features --features eest-convert --bin z6m_eest_convert

# Batched-RLP fixtures tree, produced by `z6m_eest_convert bulk-convert` from
# the third_party/eest-fixtures submodule (sparse-checkout in CI). The output
# is content-addressed by the eest-fixtures sha so different submodule
# checkouts coexist in third_party/eest-fixtures-rlp/dev-<sha>/. CI overrides
# EEST_RLP_DIR with a cache-keyed path.
EEST_SHA := $(shell git -C third_party/eest-fixtures rev-parse --short=12 HEAD 2>/dev/null)
EEST_RLP_DIR ?= $(CURDIR)/third_party/eest-fixtures-rlp/dev-$(EEST_SHA)

# Skip the converter run if the output dir already has a manifest from a
# previous successful build. To force regeneration: `rm $(EEST_RLP_DIR)/manifest.json`.
eest-rlp-build: z6m_eest_convert
	@if [ -f "$(EEST_RLP_DIR)/manifest.json" ]; then \
	    echo "  $(EEST_RLP_DIR) already populated; skipping bulk-convert"; \
	else \
	    mkdir -p "$(EEST_RLP_DIR)"; \
	    $(EEST_CONVERT_BIN) bulk-convert \
	        --input-dir $(CURDIR)/third_party/eest-fixtures/blockchain_tests \
	        --output-dir "$(EEST_RLP_DIR)/blockchain_tests"; \
	    printf '{"eest_sha":"%s"}\n' "$(EEST_SHA)" > "$(EEST_RLP_DIR)/manifest.json"; \
	fi

eest-blockchain-tests: eest-rlp-build
	cmake -B build/eest -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
		-DEEST_RLP_DIR=$(EEST_RLP_DIR)
	cmake --build build/eest
	ctest --test-dir build/eest --parallel

eest-prover-test: z6m_prover eest-rlp-build
	prover/target/release/z6m_prover --test-service --test-dir $(EEST_RLP_DIR)

EEST_JSON_DIR ?= $(CURDIR)/third_party/eest-fixtures

eest-blockchain-tests-json:
	cmake -B build/eest-json -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
		-DEEST_JSON_DIR=$(EEST_JSON_DIR)
	cmake --build build/eest-json
	ctest --test-dir build/eest-json --parallel

eest-prover-test-json: z6m_prover
	prover/target/release/z6m_prover --test-service --test-dir $(EEST_JSON_DIR)

tests-json: z6m_prover
	@mkdir -p $(TESTS_LOG_DIR)/$(TESTS_SUBDIR)
	prover/target/release/z6m_prover --test-service \
		--test-dir $(EEST_JSON_DIR)/$(TESTS_SUBDIR) \
		--execution-log-dir $(TESTS_LOG_DIR)/$(TESTS_SUBDIR)
