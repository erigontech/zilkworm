TESTS_DIR := third_party/eest-fixtures/blockchain_tests/prague

SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c
.PHONY: z6m_guest z6m_prover selftest tests eest-prover-test

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

selftest: z6m_prover
	prover/target/release/z6m_prover execute --is-test --file-name third_party/eest-fixtures/blockchain_tests/static/state_tests/stExample/add11.json

execute-block: z6m_prover
	prover/target/release/z6m_prover execute --file-name prover/temp/blocks/23519000/unifiedBlockAndStateRlp23519000.bin

TESTFILES := $(shell find $(TESTS_DIR)/${TESTS_SUBDIR} -type f -name '*.json')
RELTESTS := $(patsubst $(TESTS_DIR)/%,%,$(TESTFILES))
LOGFILES := $(addprefix target/logs/,$(RELTESTS:.json=.log))

tests: $(LOGFILES)

.DELETE_ON_ERROR:

target/logs/%.log: $(TESTS_DIR)/%.json
	@mkdir -p $(dir $@)
	prover/target/release/z6m_prover execute --is-test --file-name $< 2>&1 | tee $@ || (echo "CRASHED! $@" && rm $@)

eest-blockchain-tests: 
	cmake -B build/eest -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DTESTS_DIR=third_party/eest-fixtures/blockchain_tests
	cmake --build build/eest
	ctest --test-dir build/eest --parallel

eest-prover-test: z6m_prover
	prover/target/release/z6m_prover --test-service --test-dir third_party/eest-fixtures/blockchain_tests
