# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c
.PHONY: z6m_guest z6m_prover eest-prover-test z6m_eest_convert eest-blockchain-tests \
        execute-block selftest tests eest-mfbd-build \
        eest-blockchain-tests-json eest-prover-test-json tests-json \
        sp1-benchmark-corpus sp1-benchmark

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
SELFTEST_MFBD := build/selftest.mfbd

selftest: z6m_prover z6m_eest_convert
	@mkdir -p $(dir $(SELFTEST_MFBD))
	$(EEST_CONVERT_BIN) emit --json $(SELFTEST_JSON) --index 0 > $(SELFTEST_MFBD)
	prover/target/release/z6m_prover execute --file-name $(SELFTEST_MFBD)

TESTS_LOG_DIR := target/logs

tests: z6m_prover eest-mfbd-build
	@mkdir -p $(TESTS_LOG_DIR)/$(TESTS_SUBDIR)
	prover/target/release/z6m_prover --test-service \
		--test-dir $(EEST_MFBD_DIR)/$(TESTS_SUBDIR) \
		--execution-log-dir $(TESTS_LOG_DIR)/$(TESTS_SUBDIR)

.DELETE_ON_ERROR:

EEST_CONVERT_BIN := build/zilk_core/dev/cli/eest_to_flat_bundle

# Build the C++ eest_to_flat_bundle binary (emit / bulk-convert). Phony — cmake handles freshness.
z6m_eest_convert:
	cmake -DCMAKE_BUILD_TYPE=Release -B build -G Ninja -S .
	cmake --build build --target eest_to_flat_bundle -j$$(nproc)

# MFBD fixtures tree, produced by the C++ `eest_to_flat_bundle bulk-convert`.
# Content-addressed by the eest-fixtures sha so different submodule
# checkouts coexist in third_party/eest-fixtures-mfbd/dev-<sha>/. CI
# overrides EEST_MFBD_DIR with a cache-keyed path.
EEST_SHA := $(shell git -C third_party/eest-fixtures rev-parse --short=12 HEAD 2>/dev/null)
EEST_MFBD_DIR ?= $(CURDIR)/third_party/eest-fixtures-mfbd/dev-$(EEST_SHA)

# Regenerate the MFBD corpus whenever it is missing OR the converter binary
# changed. The binary hash covers every transitive source that affects the
# output bytes (eest_to_flat_bundle.cpp, direct_state_builder.cpp, flat_bundle.*,
# account.hpp, ...); ninja only relinks it when those change, so the hash is
# stable across no-op runs and self-heals a stale corpus automatically.
eest-mfbd-build: z6m_eest_convert
	@conv_sha=$$(sha256sum "$(EEST_CONVERT_BIN)" | cut -c1-16); \
	if [ -f "$(EEST_MFBD_DIR)/manifest.json" ] && \
	   grep -q "\"converter_sha\": *\"$$conv_sha\"" "$(EEST_MFBD_DIR)/manifest.json"; then \
	    echo "  $(EEST_MFBD_DIR) up to date (converter $$conv_sha); skipping bulk-convert"; \
	else \
	    echo "  Regenerating MFBD corpus (converter $$conv_sha)"; \
	    rm -rf "$(EEST_MFBD_DIR)/blockchain_tests" "$(EEST_MFBD_DIR)/manifest.json"; \
	    mkdir -p "$(EEST_MFBD_DIR)"; \
	    $(EEST_CONVERT_BIN) bulk-convert \
	        --input-dir $(CURDIR)/third_party/eest-fixtures/blockchain_tests \
	        --output-dir "$(EEST_MFBD_DIR)/blockchain_tests"; \
	    printf '{"eest_sha":"%s","converter_sha":"%s"}\n' "$(EEST_SHA)" "$$conv_sha" > "$(EEST_MFBD_DIR)/manifest.json"; \
	fi

eest-blockchain-tests: eest-mfbd-build
	cmake -B build/eest -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
		-DEEST_MFBD_DIR=$(EEST_MFBD_DIR)
	cmake --build build/eest
	ctest --test-dir build/eest --parallel

eest-prover-test: z6m_prover eest-mfbd-build
	prover/target/release/z6m_prover --test-service --test-dir $(EEST_MFBD_DIR)

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

# SP1 benchmark corpus: flat MFBD bundles converted from the raw mainnet
# witness blocks under $(BENCH_SRC_DIR)/<N>/unifiedBlockAndStateRlp<N>.bin.
BENCH_CORPUS_DIR ?= temp/200_benchmark_blocks_mfbd_v2
BENCH_SRC_DIR    ?= temp/200_benchmark_blocks

# Rebuild the benchmark corpus by converting each raw witness block to MFBD
# with the C++ legacy_to_flat_bundle CLI.
sp1-benchmark-corpus:
	cmake -DCMAKE_BUILD_TYPE=Release -B build -G Ninja -S .
	cmake --build build --target legacy_to_flat_bundle -j$$(nproc)
	@echo "  Regenerating SP1 benchmark corpus into $(BENCH_CORPUS_DIR)"
	@for d in $(BENCH_SRC_DIR)/*/; do \
		N=$$(basename $$d); \
		src=$$d/unifiedBlockAndStateRlp$$N.bin; \
		[ -f $$src ] || { echo "  skip $$N (no $$src)"; continue; }; \
		mkdir -p $(BENCH_CORPUS_DIR)/$$N; \
		build/zilk_core/dev/cli/legacy_to_flat_bundle $$src $(BENCH_CORPUS_DIR)/$$N/flatWitnessBundle$$N.mfbd; \
	done
	@echo "  SP1 benchmark corpus ready in $(BENCH_CORPUS_DIR)"

# Run the SP1 benchmark. Regenerate the corpus and rebuild the prover first.
sp1-benchmark: z6m_prover sp1-benchmark-corpus
	python3 tools/scripts/sp1_benchmark.py --dir $(BENCH_CORPUS_DIR)