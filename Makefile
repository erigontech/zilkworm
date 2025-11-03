TESTS_DIR := ../silkworm/third_party/ethereum-tests/BlockchainTests

.PHONY: z6m_guest z6m_prover selftest tests

z6m_guest:
	rm -r target/elf-compilation/riscv32im-succinct-zkvm-elf/release/build/z6m_guest-*
	(cd guest_program && cargo prove build)

z6m_prover: z6m_guest
	cargo build --release --manifest-path prover/Cargo.toml

selftest: z6m_prover
	target/release/z6m_prover --execute --n=1 --file-name $(TESTS_DIR)/GeneralStateTests/stExample/add11_yml.json

TESTFILES := $(shell find $(TESTS_DIR) -type f -name '*.json')
RELTESTS := $(patsubst $(TESTS_DIR)/%,%,$(TESTFILES))
LOGFILES := $(addprefix target/logs/,$(RELTESTS:.json=.log))

tests: $(LOGFILES)

target/logs/%.log: $(TESTS_DIR)/%.json
	@mkdir -p $(dir $@)
	target/release/z6m_prover --execute --n=1 --file-name $< 2>&1 | tee $@
