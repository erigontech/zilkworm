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
        z6m_guest z6m_guest_airbender z6m_prover z6m_prover_airbender \
        eest-prover-test z6m_eest_convert eest-blockchain-tests \
        execute-block selftest tests eest-mfbd-build \
        eest-blockchain-tests-json eest-prover-test-json tests-json \
        eest-zkevm-tests zkevm-fixtures \
        sp1-benchmark-corpus sp1-benchmark derive_vk ere-bin \
        ere-workload-checkout ere-fixtures ere-bin-link ere-validate ere-cost ere-compare \
        release-artifacts \
        zkevm-benchmark-fixtures z6m_guest_slib z6m_prover_slib slib-benchmark

clean: 
	rm -rf prover/guest_hypercube/build/
	rm -rf prover/target
	
# USE_HASH_KEY=ON enables node-store account recovery. For the hypercube guest only: the
# Airbender guest's own Makefile defaults it ON (don't export this one, which would turn it off).
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

z6m_guest_airbender:
	$(MAKE) -C prover/guest_airbender z6m_guest

z6m_prover_airbender: z6m_guest_airbender
	cd prover/prover_airbender && cargo build --release

test_hc: z6m_prover
	prover/target/release/z6m_prover execute --block-number 23540896 --data-dir prover/prover_turbo/temp

z6m_guest_turbo:
	rm -r prover/target/elf-compilation/riscv32im-succinct-zkvm-elf/release/build/z6m_guest-* || true
	(cd prover/guest_turbo && cargo prove build)

z6m_prover_turbo: z6m_guest_turbo
	cd prover && cargo build --release --manifest-path prover_turbo/Cargo.toml

execute-block: z6m_prover
	prover/target/release/z6m_prover execute --file-name prover/temp/blocks/23519000/unifiedBlockAndStateRlp23519000.bin

# Pinned EEST fixtures (test-fixtures.json): downloaded, sha256-verified, extracted to test-fixtures-cache/<key>/.
FIXTURES_CACHE := $(CURDIR)/test-fixtures-cache
# Manifest key selecting which pinned corpus to run.
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

z6m_eest_convert:
	cmake -DCMAKE_BUILD_TYPE=Release -B build -G Ninja -S .
	cmake --build build --target eest_to_flat_bundle -j$$(nproc)

# MFBD corpus, keyed by the pinned tarball sha; CI overrides EEST_MFBD_DIR.
EEST_SHA := $(shell python3 -c "import json;print(json.load(open('test-fixtures.json'))['$(EEST_KEY)']['sha256'][:12])" 2>/dev/null)
EEST_MFBD_DIR ?= $(FIXTURES_CACHE)/mfbd-$(EEST_SHA)

# Regenerates the corpus when missing or when the converter binary's hash changed.
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

# tests-zkevm fixtures: blockchain_test JSON whose blocks carry a `statelessInputBytes` field; the cache dir carries the version.
ZKEVM_RELEASE_VERSION := v21.0.7
ZKEVM_RELEASE_TAG  := tests-zkevm@$(ZKEVM_RELEASE_VERSION)
ZKEVM_RELEASE_REPO := ethereum/execution-specs
ZKEVM_FIXTURES_DIR := $(FIXTURES_CACHE)/zkevm_stateless-$(ZKEVM_RELEASE_VERSION)/fixtures
ZKEVM_JSON_DIR ?= $(ZKEVM_FIXTURES_DIR)/blockchain_tests

# Fetched with `gh release download`, not test-fixtures.json: `make test-fixtures` verifies every manifest key's sha256.
zkevm-fixtures:
	@dst="$(FIXTURES_CACHE)/zkevm_stateless-$(ZKEVM_RELEASE_VERSION)"; \
	tarball="$(FIXTURES_CACHE)/fixtures_zkevm-$(ZKEVM_RELEASE_VERSION).tar.gz"; \
	if [ -d "$$dst/fixtures/blockchain_tests" ]; then \
	    echo "  zkevm fixtures present at $$dst; skipping download"; \
	else \
	    mkdir -p "$(FIXTURES_CACHE)"; \
	    echo "  downloading $(ZKEVM_RELEASE_TAG) fixtures_zkevm.tar.gz (~595 MiB) from $(ZKEVM_RELEASE_REPO)"; \
	    gh release download '$(ZKEVM_RELEASE_TAG)' --repo $(ZKEVM_RELEASE_REPO) \
	        -p 'fixtures_zkevm.tar.gz' -O "$$tarball" --clobber; \
	    echo "  extracting fixtures/blockchain_tests"; \
	    rm -rf "$$dst.tmp" "$$dst"; mkdir -p "$$dst.tmp"; \
	    tar --no-same-owner --no-same-permissions -xzf "$$tarball" -C "$$dst.tmp" fixtures/blockchain_tests; \
	    mv "$$dst.tmp" "$$dst"; \
	    echo "  zkevm fixtures ready at $$dst"; \
	fi

# Flag-on (Z6M_HASH_STATE) build in build/zkevm.
eest-zkevm-tests: zkevm-fixtures
	cmake -B build/zkevm -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
		-DZ6M_HASH_STATE=ON \
		-DEEST_JSON_DIR=$(ZKEVM_JSON_DIR)
	cmake --build build/zkevm
	ctest --test-dir build/zkevm --parallel

BENCH_CORPUS_DIR ?= temp/200_benchmark_blocks_mfbd_v2
BENCH_SRC_DIR    ?= temp/200_benchmark_blocks

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

sp1-benchmark: z6m_prover sp1-benchmark-corpus
	python3 tools/scripts/sp1_benchmark.py --dir $(BENCH_CORPUS_DIR)

RELEASE_DIR := temp
# Recursive: $(ERE_VK) is defined below.
RELEASE_BINS = \
	prover/guest_hypercube/build/z6m_guest.elf:z6m_guest_hypercube_mfbd.elf \
	prover/guest_hypercube/build/z6m_guest.vk:z6m_guest_hypercube_mfbd.vk \
	$(ERE_ELF):$(ERE_GUEST_NAME)-$(ERE_SP1_SDK_VERSION).elf \
	$(ERE_VK):$(ERE_GUEST_NAME)-$(ERE_SP1_SDK_VERSION).vk \
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
	@ls -l $(foreach pair,$(RELEASE_BINS),$(RELEASE_DIR)/$(lastword $(subst :, ,$(pair)))) $(RELEASE_DIR)/SHA256SUMS.txt
	@echo "--- $(RELEASE_DIR)/SHA256SUMS.txt ---"
	@cat $(RELEASE_DIR)/SHA256SUMS.txt

ZKEVM_BENCH_RELEASE_VERSION := v21.0.5
ZKEVM_BENCH_RELEASE_TAG  := tests-zkevm-benchmark@$(ZKEVM_BENCH_RELEASE_VERSION)
ZKEVM_BENCH_ASSET        := fixtures_zkevm-benchmark_0030M.tar.gz
ZKEVM_BENCH_RELEASE_REPO := ethereum/execution-specs
ZKEVM_BENCH_FIXTURES_DIR := $(FIXTURES_CACHE)/zkevm_benchmark-$(ZKEVM_BENCH_RELEASE_VERSION)/fixtures
ZKEVM_BENCH_JSON_DIR ?= $(ZKEVM_BENCH_FIXTURES_DIR)/blockchain_tests

zkevm-benchmark-fixtures:
	@dst="$(FIXTURES_CACHE)/zkevm_benchmark-$(ZKEVM_BENCH_RELEASE_VERSION)"; \
	tarball="$(FIXTURES_CACHE)/$(ZKEVM_BENCH_ASSET)"; \
	if [ -d "$$dst/fixtures/blockchain_tests" ]; then \
	    echo "  zkevm-benchmark fixtures present at $$dst; skipping download"; \
	else \
	    mkdir -p "$(FIXTURES_CACHE)"; \
	    echo "  downloading $(ZKEVM_BENCH_RELEASE_TAG) $(ZKEVM_BENCH_ASSET) from $(ZKEVM_BENCH_RELEASE_REPO)"; \
	    gh release download '$(ZKEVM_BENCH_RELEASE_TAG)' --repo $(ZKEVM_BENCH_RELEASE_REPO) \
	        -p '$(ZKEVM_BENCH_ASSET)' -D "$(FIXTURES_CACHE)" --clobber; \
	    echo "  extracting fixtures/blockchain_tests"; \
	    rm -rf "$$dst.tmp" "$$dst"; mkdir -p "$$dst.tmp"; \
	    tar --no-same-owner --no-same-permissions -xzf "$$tarball" -C "$$dst.tmp" fixtures/blockchain_tests; \
	    mv "$$dst.tmp" "$$dst"; \
	    echo "  zkevm-benchmark fixtures ready at $$dst"; \
	fi

# Dedicated tree: keeps Z6M_HASH_STATE=ON out of the default build cache.
GUEST_SLIB_BUILD := prover/guest_hypercube/build-slib

z6m_guest_slib:
	cmake -S prover/guest_hypercube -B $(GUEST_SLIB_BUILD) \
		-DCMAKE_TOOLCHAIN_FILE=$(CURDIR)/prover/guest_hypercube/cmake/riscv64im-sp1.cmake \
		-DCMAKE_BUILD_TYPE=Release \
		-DSP1=ON \
		-DZ6M_HASH_STATE=ON
	cmake --build $(GUEST_SLIB_BUILD) -j$$(nproc)

# Z6M_GUEST_ELF: staging a copy blocks z6m_guest relinks.
z6m_prover_slib: z6m_guest_slib
	cd prover && Z6M_GUEST_ELF=$(CURDIR)/$(GUEST_SLIB_BUILD)/z6m_guest.elf \
		cargo build --release --manifest-path prover_hypercube/Cargo.toml

SLIB_BENCH_WORK  ?= temp/slib_benchmark
SLIB_BENCH_CASES ?= $(SLIB_BENCH_WORK)/cases
SLIB_BENCH_LOG   ?= $(SLIB_BENCH_WORK)/execution.log
SLIB_BENCH_CSV   ?= $(SLIB_BENCH_WORK)/per_case.csv
SLIB_PROVER      := prover/target/release/z6m_prover

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

ERE_BIN_DIR ?= $(CURDIR)/build/ere-bin
ERE_GUEST_NAME ?= stateless-validator-zilkworm-sp1
ERE_ELF := $(ERE_BIN_DIR)/$(ERE_GUEST_NAME).elf
ERE_VK := $(ERE_BIN_DIR)/$(ERE_GUEST_NAME).vk
# Must equal the SP1 version ere resolves (ere-bin-link checks).
ERE_SP1_SDK_VERSION := $(shell sed -nE 's/^sp1-sdk = \{ git = "https:\/\/github\.com\/succinctlabs\/sp1", tag = "([^"]+)".*/\1/p' prover/stateless_validator/Cargo.toml)
$(if $(ERE_SP1_SDK_VERSION),,$(error cannot read the sp1-sdk tag from prover/stateless_validator/Cargo.toml))
DERIVE_VK_BIN := prover/target/release/derive_vk

derive_vk:
	cargo build --release -p z6m_stateless_validator --bin derive_vk --features vk-derive

z6m_guest_vk: z6m_guest derive_vk
	SP1_PROVER=mock $(DERIVE_VK_BIN) prover/guest_hypercube/build/z6m_guest.elf prover/guest_hypercube/build/z6m_guest.vk

# The ERE guest is the HashState build; the DirectState (MFBD) guest is z6m_guest.
ere-bin: z6m_guest_slib derive_vk
	@mkdir -p $(ERE_BIN_DIR)
	cp $(GUEST_SLIB_BUILD)/z6m_guest.elf $(ERE_ELF)
	SP1_PROVER=mock $(DERIVE_VK_BIN) $(ERE_ELF) $(ERE_VK)
	@echo "ere-bin staged at $(ERE_BIN_DIR):"
	@ls -la $(ERE_BIN_DIR)

ERE_WORKLOAD_REPO   ?= https://github.com/eth-act/zkevm-benchmark-workload.git
ERE_WORKLOAD_BRANCH ?= master
ERE_WORKLOAD_DIR    ?= $(CURDIR)/temp/zkevm-benchmark-workload
ERE_FIXTURE_FILTER  ?= 10M # scopes generation for tractable local runs. default: 10M-gas fixtures, i.e. the 1077-fixture subset
ERE_TIMEOUT         ?= 60m
ERE_IMAGE_REGISTRY  ?= ghcr.io/eth-act/ere
ERE_BIN_PATH        ?=
# Needed while the workload [patch]es ere-guests (build.rs cannot derive the URL from a path dependency).
ERE_RETH_ARTIFACT_URL ?= $(shell python3 $(CURDIR)/tools/ere_workload.py "$(ERE_WORKLOAD_DIR)" reth-artifact-url 2>/dev/null)
ERE_INPUT_FOLDER    ?= $(FIXTURES_CACHE)/ere-sepolia/eest_batch
ERE_GEN_FIXTURES    ?=
ERE_FIXTURE_ENV     := EF_TEST_TRIE=default RUST_MIN_STACK=16388608 RUST_LOG=info
ERE_RUN_ENV         := ERE_IMAGE_REGISTRY=$(ERE_IMAGE_REGISTRY) RUST_LOG=info

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

# ere-hosts loads <bin-path>/$(ERE_GUEST_NAME)-<SP1 SDK version>.{elf,vk}.
ere-bin-link:
	v=$$(python3 tools/ere_workload.py "$(ERE_WORKLOAD_DIR)" sp1-sdk-version) && \
	if [ "$$v" != "$(ERE_SP1_SDK_VERSION)" ]; then \
	    echo "the workload's ere resolves SP1 $$v, derive_vk builds against $(ERE_SP1_SDK_VERSION): bump prover/stateless_validator/Cargo.toml" >&2; exit 1; \
	fi && \
	for ext in elf vk; do ln -sf $(ERE_GUEST_NAME).$$ext "$(abspath $(ERE_BIN_PATH))/$(ERE_GUEST_NAME)-$$v.$$ext"; done

ere-validate: $(if $(ERE_GEN_FIXTURES),ere-fixtures) $(if $(ERE_BIN_PATH),ere-bin-link)
	cd "$(ERE_WORKLOAD_DIR)" && $(ERE_RUN_ENV) \
	    cargo run -p ere-hosts --release -- --zkvms sp1 --force-rerun --timeout $(ERE_TIMEOUT) \
	        $(if $(ERE_BIN_PATH),--bin-path $(abspath $(ERE_BIN_PATH)),) stateless-validator --execution-client zilkworm --input-folder $(abspath $(ERE_INPUT_FOLDER))
	python3 $(CURDIR)/tools/ere_compare.py --validate 'zilkworm-*' "$(ERE_WORKLOAD_DIR)/zkevm-metrics"

ere-cost: $(if $(ERE_GEN_FIXTURES),ere-fixtures) $(if $(ERE_BIN_PATH),ere-bin-link)
	cd "$(ERE_WORKLOAD_DIR)" && $(ERE_RUN_ENV) \
	    cargo run -p ere-hosts --release -- --zkvms sp1 --force-rerun --timeout $(ERE_TIMEOUT) --action estimate-cost \
	        $(if $(ERE_BIN_PATH),--bin-path $(abspath $(ERE_BIN_PATH)),) stateless-validator --execution-client zilkworm --input-folder $(abspath $(ERE_INPUT_FOLDER))
	python3 $(CURDIR)/tools/ere_compare.py --table 'zilkworm-*' "$(ERE_WORKLOAD_DIR)/zkevm-metrics"
	python3 $(CURDIR)/tools/ere_compare.py --cost 'zilkworm-*' "$(ERE_WORKLOAD_DIR)/zkevm-metrics"

# `make ere-compare -o ere-cost` reuses an earlier ere-cost.
ere-compare: ere-cost
	cd "$(ERE_WORKLOAD_DIR)" && url="$(ERE_RETH_ARTIFACT_URL)" && $(ERE_RUN_ENV) \
	    cargo run -p ere-hosts --release -- --zkvms sp1 --force-rerun --timeout $(ERE_TIMEOUT) --action estimate-cost \
	        $${url:+--guest-artifact-base-url $$url} stateless-validator --execution-client reth --input-folder $(abspath $(ERE_INPUT_FOLDER))
	python3 $(CURDIR)/tools/ere_compare.py --table 'zilkworm-*' --table 'reth-*' "$(ERE_WORKLOAD_DIR)/zkevm-metrics"
	python3 $(CURDIR)/tools/ere_compare.py "$(ERE_WORKLOAD_DIR)/zkevm-metrics"

