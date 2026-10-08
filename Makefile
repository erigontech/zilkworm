# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

# Auto-detect global xPacks riscv-none-elf-gcc if installed
XPACKS_MAC := $(shell ls -1d $(HOME)/Library/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/.content/bin 2>/dev/null | head -n 1)
XPACKS_LINUX := $(shell ls -1d $(HOME)/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/.content/bin 2>/dev/null | head -n 1)

ifneq ($(XPACKS_MAC),)
export PATH := $(XPACKS_MAC):$(PATH)
else ifneq ($(XPACKS_LINUX),)
export PATH := $(XPACKS_LINUX):$(PATH)
endif

.PHONY: test-fixtures \
        z6m_guest z6m_prover eest-prover-test z6m_eest_convert eest-blockchain-tests \
        execute-block selftest tests eest-mfbd-build \
        eest-blockchain-tests-json eest-prover-test-json tests-json \
        eest-zkevm-tests zkevm-fixtures \
        sp1-benchmark-corpus sp1-benchmark derive_vk ere-bin \
        ere-workload-checkout ere-fixtures ere-validate ere-compare \
        release-artifacts \
        zkevm-benchmark-fixtures z6m_guest_slib z6m_prover_slib slib-benchmark \
        slib-mainnet-corpus slib-mainnet-benchmark

clean: 
	rm -rf prover/guest_hypercube/build/
	rm -rf prover/target
	
# USE_HASH_KEY=ON enables node-store account recovery.
USE_HASH_KEY ?= OFF
z6m_guest:
	cmake -S prover/guest_hypercube -B prover/guest_hypercube/build \
		-DCMAKE_TOOLCHAIN_FILE=$(CURDIR)/prover/guest_hypercube/cmake/riscv64im-sp1.cmake \
		-DCMAKE_BUILD_TYPE=Release \
		-DSP1=ON \
		-DUSE_HASH_KEY=$(USE_HASH_KEY)
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

# Pinned EEST fixture releases (test-fixtures.json, erigon-style manifest):
# `make test-fixtures` downloads, sha256-verifies and extracts every entry
# into test-fixtures-cache/<key>/. Re-runs are no-ops while the pin matches.
FIXTURES_CACHE := $(CURDIR)/test-fixtures-cache
# Manifest key selecting which pinned corpus to run. Override to eest_devnet
# to run the Glamsterdam devnet fixtures instead of the stable release.
EEST_KEY ?= eest_stable
EEST_FIXTURES_DIR := $(FIXTURES_CACHE)/$(EEST_KEY)/fixtures

test-fixtures:
	tools/test-fixtures.sh test-fixtures.json $(FIXTURES_CACHE)

SELFTEST_JSON := $(EEST_FIXTURES_DIR)/blockchain_tests/for_osaka/ported_static/stExample/add11/add11.json
SELFTEST_MFBD := build/selftest.mfbd

selftest: z6m_prover z6m_eest_convert test-fixtures
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
# Content-addressed by the pinned tarball sha (test-fixtures.json) so
# different pins coexist in test-fixtures-cache/mfbd-<sha>/. CI overrides
# EEST_MFBD_DIR with a cache-keyed path.
EEST_SHA := $(shell python3 -c "import json;print(json.load(open('test-fixtures.json'))['$(EEST_KEY)']['sha256'][:12])" 2>/dev/null)
EEST_MFBD_DIR ?= $(FIXTURES_CACHE)/mfbd-$(EEST_SHA)

# Regenerate the MFBD corpus whenever it is missing OR the converter binary
# changed. The binary hash covers every transitive source that affects the
# output bytes (eest_to_flat_bundle.cpp, direct_state_builder.cpp, flat_bundle.*,
# account.hpp, ...); ninja only relinks it when those change, so the hash is
# stable across no-op runs and self-heals a stale corpus automatically.
eest-mfbd-build: z6m_eest_convert
	@conv_sha=$$(sha256sum "$(EEST_CONVERT_BIN)" | cut -c1-16); \
	if [ -f "$(EEST_MFBD_DIR)/manifest.json" ] && \
	   grep -q "\"converter_sha\": *\"$$conv_sha\"" "$(EEST_MFBD_DIR)/manifest.json"; then \
	    echo "  $(EEST_MFBD_DIR) up to date (converter $$conv_sha); skipping fixtures fetch + bulk-convert"; \
	else \
	    echo "  Regenerating MFBD corpus (converter $$conv_sha)"; \
	    tools/test-fixtures.sh test-fixtures.json $(FIXTURES_CACHE) $(EEST_KEY); \
	    rm -rf "$(EEST_MFBD_DIR)/blockchain_tests" "$(EEST_MFBD_DIR)/manifest.json"; \
	    mkdir -p "$(EEST_MFBD_DIR)"; \
	    $(EEST_CONVERT_BIN) bulk-convert \
	        --input-dir $(EEST_FIXTURES_DIR)/blockchain_tests \
	        --output-dir "$(EEST_MFBD_DIR)/blockchain_tests"; \
	    printf '{"eest_sha":"%s","converter_sha":"%s"}\n' "$(EEST_SHA)" "$$conv_sha" > "$(EEST_MFBD_DIR)/manifest.json"; \
	fi

eest-blockchain-tests: eest-mfbd-build
	cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
		-DEEST_MFBD_DIR=$(EEST_MFBD_DIR)
	cmake --build build
	ctest --test-dir build --parallel

eest-prover-test: z6m_prover eest-mfbd-build
	prover/target/release/z6m_prover --test-service --test-dir $(EEST_MFBD_DIR)

EEST_JSON_DIR ?= $(EEST_FIXTURES_DIR)/blockchain_tests

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

# tests-zkevm StatelessInputBytes fixtures. These are ordinary blockchain_test
# JSON cases except that blocks[0] carries a `statelessInputBytes` hex field —
# the SSZ/slib stateless input the HashState read-side backend consumes. Sourced
# from the ethereum/execution-specs release `tests-zkevm@v0.8.0` (asset
# fixtures_zkevm.tar.gz, ~524 MiB), a sibling corpus to the pinned eest_stable one.
ZKEVM_RELEASE_TAG  := tests-zkevm@v0.8.0
ZKEVM_RELEASE_REPO := ethereum/execution-specs
ZKEVM_FIXTURES_DIR := $(FIXTURES_CACHE)/zkevm_stateless/fixtures
ZKEVM_JSON_DIR ?= $(ZKEVM_FIXTURES_DIR)/blockchain_tests

# Download + extract the tests-zkevm fixtures. Mirrors eest-mfbd-build's
# fixtures fetch (staged .tmp dir, `fixtures/blockchain_tests` allowlist, skip
# when already present) but via `gh release download` instead of the
# sha256-pinned test-fixtures.json manifest: the 524 MiB tarball has not been
# fetched/pinned yet, and adding an unverifiable entry to test-fixtures.json
# would break `make test-fixtures`, which verifies every manifest key. Once the
# tarball is pinned this can move to the manifest idiom like eest_stable.
zkevm-fixtures:
	@dst="$(FIXTURES_CACHE)/zkevm_stateless"; \
	tarball="$(FIXTURES_CACHE)/fixtures_zkevm.tar.gz"; \
	if [ -d "$$dst/fixtures/blockchain_tests" ]; then \
	    echo "  zkevm fixtures present at $$dst; skipping download"; \
	else \
	    mkdir -p "$(FIXTURES_CACHE)"; \
	    echo "  downloading $(ZKEVM_RELEASE_TAG) fixtures_zkevm.tar.gz (~524 MiB) from $(ZKEVM_RELEASE_REPO)"; \
	    gh release download '$(ZKEVM_RELEASE_TAG)' --repo $(ZKEVM_RELEASE_REPO) \
	        -p 'fixtures_zkevm.tar.gz' -D "$(FIXTURES_CACHE)" --clobber; \
	    echo "  extracting fixtures/blockchain_tests"; \
	    rm -rf "$$dst.tmp" "$$dst"; mkdir -p "$$dst.tmp"; \
	    tar --no-same-owner --no-same-permissions -xzf "$$tarball" -C "$$dst.tmp" fixtures/blockchain_tests; \
	    mv "$$dst.tmp" "$$dst"; \
	    echo "  zkevm fixtures ready at $$dst"; \
	fi

# Run the tests-zkevm StatelessInputBytes corpus through HashState (flag-on build in build/zkevm).
# See docs/hashstate.md, "Build flag and test targets".
eest-zkevm-tests: zkevm-fixtures
	cmake -B build/zkevm -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
		-DZ6M_HASH_STATE=ON \
		-DEEST_JSON_DIR=$(ZKEVM_JSON_DIR)
	cmake --build build/zkevm
	ctest --test-dir build/zkevm --parallel

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

# The same mainnet blocks for HashState: binary SLIB envelopes (block RLP plus
# statelessInputBytes), converted from the same raw witness files by legacy_to_slib_fixture.
SLIB_MAINNET_DIR ?= temp/200_benchmark_blocks_slib

slib-mainnet-corpus:
	cmake -DCMAKE_BUILD_TYPE=Release -B build -G Ninja -S .
	cmake --build build --target legacy_to_slib_fixture -j$$(nproc)
	@echo "  Converting $(BENCH_SRC_DIR) into HashState fixtures in $(SLIB_MAINNET_DIR)"
	@for d in $(BENCH_SRC_DIR)/*/; do \
		N=$$(basename $$d); \
		src=$$d/unifiedBlockAndStateRlp$$N.bin; \
		[ -f $$src ] || { echo "  skip $$N (no $$src)"; continue; }; \
		mkdir -p $(SLIB_MAINNET_DIR)/$$N; \
		build/zilk_core/dev/cli/legacy_to_slib_fixture $$src $(SLIB_MAINNET_DIR)/$$N/statelessInput$$N.slib || exit 1; \
	done
	@echo "  HashState mainnet corpus ready in $(SLIB_MAINNET_DIR)"

# Run the mainnet benchmark blocks through the HashState guest.
slib-mainnet-benchmark: z6m_prover_slib slib-mainnet-corpus
	python3 tools/scripts/sp1_benchmark.py --dir $(SLIB_MAINNET_DIR) --slib

# Stage release artifacts into ./temp/
RELEASE_DIR := temp
RELEASE_BINS := \
	prover/guest_hypercube/build/z6m_guest.elf:z6m_guest_hypercube.elf \
	prover/target/release/z6m_prover:z6m_prover_hypercube \
	build/zilk_core/dev/cli/state_transition:state_transition_linux_x86_64

release-artifacts:
	@mkdir -p $(RELEASE_DIR)
	@names=""; \
	for pair in $(RELEASE_BINS); do \
	    src=$${pair%%:*}; dst=$${pair##*:}; \
	    if [ ! -f "$$src" ]; then echo "missing: $$src" >&2; exit 1; fi; \
	    cp "$$src" "$(RELEASE_DIR)/$$dst"; \
	    names="$$names $$dst"; \
	done; \
	(cd $(RELEASE_DIR) && sha256sum $$names > SHA256SUMS.txt)
	@echo "release artifacts staged in $(RELEASE_DIR)/:"
	@ls -l $(RELEASE_DIR)/z6m_guest_hypercube.elf $(RELEASE_DIR)/z6m_prover_hypercube $(RELEASE_DIR)/state_transition_linux_x86_64 $(RELEASE_DIR)/SHA256SUMS.txt
	@echo "--- $(RELEASE_DIR)/SHA256SUMS.txt ---"
	@cat $(RELEASE_DIR)/SHA256SUMS.txt

# =============================================================================
# HashState/slib SP1 cycle benchmark (tests-zkevm-benchmark@v0.8.2, Amsterdam)
# =============================================================================
# See docs/hashstate.md, "SP1 cycle benchmark".

# The curated compute benchmark corpus: single heavy Amsterdam blocks packed to
# fixed 10M/30M/60M gas budgets. Same on-wire schema (0x1501 || SSZ) as the
# eest-zkevm-tests corpus, only the content differs. Sourced from the
# ethereum/execution-specs release tests-zkevm-benchmark@v0.8.2 (single asset
# fixtures_zkevm-benchmark.tar.gz, ~495 MiB). Mirrors the zkevm-fixtures idiom.
ZKEVM_BENCH_RELEASE_TAG  := tests-zkevm-benchmark@v0.8.2
ZKEVM_BENCH_RELEASE_REPO := ethereum/execution-specs
ZKEVM_BENCH_FIXTURES_DIR := $(FIXTURES_CACHE)/zkevm_benchmark/fixtures
ZKEVM_BENCH_JSON_DIR ?= $(ZKEVM_BENCH_FIXTURES_DIR)/blockchain_tests

# Download + extract the benchmark fixtures. Idempotent: skips when already
# present. Same staged-.tmp / blockchain_tests-allowlist / gh-release-download
# shape as zkevm-fixtures; the tarball is not yet pinned in test-fixtures.json,
# so it uses `gh release download` rather than the sha256-verified manifest.
zkevm-benchmark-fixtures:
	@dst="$(FIXTURES_CACHE)/zkevm_benchmark"; \
	tarball="$(FIXTURES_CACHE)/fixtures_zkevm-benchmark.tar.gz"; \
	if [ -d "$$dst/fixtures/blockchain_tests" ]; then \
	    echo "  zkevm-benchmark fixtures present at $$dst; skipping download"; \
	else \
	    mkdir -p "$(FIXTURES_CACHE)"; \
	    echo "  downloading $(ZKEVM_BENCH_RELEASE_TAG) fixtures_zkevm-benchmark.tar.gz (~495 MiB) from $(ZKEVM_BENCH_RELEASE_REPO)"; \
	    gh release download '$(ZKEVM_BENCH_RELEASE_TAG)' --repo $(ZKEVM_BENCH_RELEASE_REPO) \
	        -p 'fixtures_zkevm-benchmark.tar.gz' -D "$(FIXTURES_CACHE)" --clobber; \
	    echo "  extracting fixtures/blockchain_tests"; \
	    rm -rf "$$dst.tmp" "$$dst"; mkdir -p "$$dst.tmp"; \
	    tar --no-same-owner --no-same-permissions -xzf "$$tarball" -C "$$dst.tmp" fixtures/blockchain_tests; \
	    mv "$$dst.tmp" "$$dst"; \
	    echo "  zkevm-benchmark fixtures ready at $$dst"; \
	fi

# The prover embeds a fixed ELF path (prover_hypercube/build.rs -> include_elf!
# ".../guest_hypercube/build/z6m_guest.elf"), so the slib guest ELF must land
# there. We build the flag-ON guest in a DEDICATED tree ($(GUEST_SLIB_BUILD)) so
# the normal OFF build cache is never contaminated with Z6M_HASH_STATE=ON, then
# stage the ELF at the embed path. (A fresh tree also re-applies the blst SP1
# patch via its PATCH_COMMAND.)
GUEST_SLIB_BUILD := prover/guest_hypercube/build-slib
GUEST_EMBED_ELF  := prover/guest_hypercube/build/z6m_guest.elf

z6m_guest_slib:
	cmake -S prover/guest_hypercube -B $(GUEST_SLIB_BUILD) \
		-DCMAKE_TOOLCHAIN_FILE=$(CURDIR)/prover/guest_hypercube/cmake/riscv64im-sp1.cmake \
		-DCMAKE_BUILD_TYPE=Release \
		-DSP1=ON \
		-DZ6M_HASH_STATE=ON
	cmake --build $(GUEST_SLIB_BUILD) -j$$(nproc)
	@mkdir -p $(dir $(GUEST_EMBED_ELF))
	cp $(GUEST_SLIB_BUILD)/z6m_guest.elf $(GUEST_EMBED_ELF)

# Build the prover embedding the slib guest ELF. Uses cargo directly rather than
# the z6m_prover target, because z6m_prover depends on z6m_guest, which would
# rebuild the OFF (DirectState) ELF over the staged slib one before embedding.
z6m_prover_slib: z6m_guest_slib
	cd prover && cargo build --release --manifest-path prover_hypercube/Cargo.toml

# slib benchmark run knobs. (Comments kept on their own lines: a trailing inline
# comment would leave whitespace in the value and corrupt the paths.)
SLIB_BENCH_WORK  ?= temp/slib_benchmark
# one-case-per-file JSONs:
SLIB_BENCH_CASES ?= $(SLIB_BENCH_WORK)/cases
# cycle_stats.py-format log:
SLIB_BENCH_LOG   ?= $(SLIB_BENCH_WORK)/execution.log
# per-block (per-case) cycles:
SLIB_BENCH_CSV   ?= $(SLIB_BENCH_WORK)/per_case.csv
SLIB_PROVER      := prover/target/release/z6m_prover

# Run the HashState/slib guest over every benchmark case, one prover run per case, and collect cycles.
# See docs/hashstate.md, "SP1 cycle benchmark".
slib-benchmark: zkevm-benchmark-fixtures z6m_prover_slib
	@echo "  [slib-benchmark] splitting fixtures into one-case-per-file ..."
	@rm -rf "$(SLIB_BENCH_CASES)"; mkdir -p "$(SLIB_BENCH_CASES)" "$(SLIB_BENCH_WORK)"
	python3 tools/scripts/slib_split_fixtures.py \
		--in "$(ZKEVM_BENCH_JSON_DIR)" --out "$(SLIB_BENCH_CASES)"
	@echo "  [slib-benchmark] running each case through z6m_prover execute --is-test ..."
	@: > "$(SLIB_BENCH_LOG)"; \
	echo "case,gas_used,cycles,prover_gas,syscall_count" > "$(SLIB_BENCH_CSV)"; \
	i=0; \
	for f in $$(find "$(SLIB_BENCH_CASES)" -name '*.json' | sort); do \
	    i=$$((i+1)); name=$$(basename "$$f" .json); \
	    line=$$($(SLIB_PROVER) execute --is-test --file-name "$$f" 2>/dev/null \
	        | grep -oE 'Executed block [0-9]+ \(gas_used=[0-9]+, cycles=[0-9]+, prover_gas=[0-9]+, syscall_count=[0-9]+\)') || true; \
	    if [ -z "$$line" ]; then echo "  WARN: no cycle line for $$name"; continue; fi; \
	    g=$$(echo "$$line" | grep -oE 'gas_used=[0-9]+'      | cut -d= -f2); \
	    c=$$(echo "$$line" | grep -oE 'cycles=[0-9]+'        | cut -d= -f2); \
	    p=$$(echo "$$line" | grep -oE 'prover_gas=[0-9]+'    | cut -d= -f2); \
	    s=$$(echo "$$line" | grep -oE 'syscall_count=[0-9]+' | cut -d= -f2); \
	    echo "$$name,$$g,$$c,$$p,$$s" >> "$(SLIB_BENCH_CSV)"; \
	    echo "block $$i executed, gas_used=$$g, cycle_count=$$c, prover_gas=$$p  # $$name" >> "$(SLIB_BENCH_LOG)"; \
	    printf '  %-64s cycles=%s gas=%s\n' "$$name" "$$c" "$$g"; \
	done
	@echo "  [slib-benchmark] per-case cycles (per block): $(SLIB_BENCH_CSV)"
	@echo "  [slib-benchmark] summarizing with tools/stats/cycle_stats.py ..."
	python3 tools/stats/cycle_stats.py --filename "$(SLIB_BENCH_LOG)" \
		--output "$(SLIB_BENCH_WORK)/cycle_stats.png" --no-display \
	    || echo "  (cycle_stats.py needs matplotlib+scipy; raw per-case numbers are in $(SLIB_BENCH_CSV))"

# ERE benchmark integration: build the SP1 guest ELF + VK as expected by ere-hosts.
ERE_BIN_DIR ?= $(CURDIR)/build/ere-bin
ERE_GUEST_NAME ?= stateless-validator-zilkworm-sp1
ERE_ELF := $(ERE_BIN_DIR)/$(ERE_GUEST_NAME).elf
ERE_VK := $(ERE_BIN_DIR)/$(ERE_GUEST_NAME).vk
DERIVE_VK_BIN := prover/target/release/derive_vk

derive_vk:
	cargo build --release -p z6m_stateless_validator --bin derive_vk --features vk-derive

ere-bin: z6m_guest derive_vk
	@mkdir -p $(ERE_BIN_DIR)
	cp prover/guest_hypercube/build/z6m_guest.elf $(ERE_ELF)
	SP1_PROVER=mock $(DERIVE_VK_BIN) $(ERE_ELF) $(ERE_VK)
	@echo "ere-bin staged at $(ERE_BIN_DIR):"
	@ls -la $(ERE_BIN_DIR)

# ERE benchmark integration: validation/comparison.
ERE_WORKLOAD_REPO   ?= https://github.com/eth-act/zkevm-benchmark-workload.git
ERE_WORKLOAD_BRANCH ?= master
ERE_WORKLOAD_DIR    ?= $(CURDIR)/temp/zkevm-benchmark-workload
ERE_FIXTURE_FILTER  ?= 10M # scopes generation for tractable local runs. default: 10M-gas fixtures, i.e. the 1077-fixture subset
ERE_TIMEOUT         ?= 60m
ERE_FIXTURE_ENV     := EF_TEST_TRIE=default RUST_MIN_STACK=16388608 RUST_LOG=info
ERE_RUN_ENV         := RUST_LOG=info

ere-workload-checkout:
	@if [ ! -d "$(ERE_WORKLOAD_DIR)/.git" ]; then \
	    echo "cloning $(ERE_WORKLOAD_REPO) ($(ERE_WORKLOAD_BRANCH)) into $(ERE_WORKLOAD_DIR)"; \
	    git clone --branch $(ERE_WORKLOAD_BRANCH) $(ERE_WORKLOAD_REPO) "$(ERE_WORKLOAD_DIR)"; \
	else \
	    echo "using existing workload checkout at $(ERE_WORKLOAD_DIR)"; \
	fi

ere-fixtures: ere-workload-checkout
	cd "$(ERE_WORKLOAD_DIR)" && $(ERE_FIXTURE_ENV) \
	    cargo run -p witness-generator-cli --release -- \
	        tests $(if $(ERE_FIXTURE_FILTER),--include $(ERE_FIXTURE_FILTER))

ere-validate: ere-fixtures
	cd "$(ERE_WORKLOAD_DIR)" && $(ERE_RUN_ENV) \
	    cargo run -p ere-hosts --release -- --zkvms sp1 --timeout $(ERE_TIMEOUT) \
	        stateless-validator --execution-client zilkworm
	python3 $(CURDIR)/tools/ere_compare.py --validate 'zilkworm-*' "$(ERE_WORKLOAD_DIR)/zkevm-metrics"

ere-compare: ere-fixtures
	cd "$(ERE_WORKLOAD_DIR)" && $(ERE_RUN_ENV) \
	    cargo run -p ere-hosts --release -- --zkvms sp1 --timeout $(ERE_TIMEOUT) \
	        stateless-validator --execution-client reth
	cd "$(ERE_WORKLOAD_DIR)" && $(ERE_RUN_ENV) \
	    cargo run -p ere-hosts --release -- --zkvms sp1 --timeout $(ERE_TIMEOUT) \
	        stateless-validator --execution-client zilkworm
	python3 $(CURDIR)/tools/ere_compare.py "$(ERE_WORKLOAD_DIR)/zkevm-metrics"

