SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

# EEST blockchain tests from the pinned fixture tarball (test-fixtures.json), fetched by
# `tools/test-fixtures.sh test-fixtures.json test-fixtures-cache eest_stable` from the repo root.
EEST_DIR  ?= ../../test-fixtures-cache/eest_stable/fixtures/blockchain_tests
PROVER    := target/release/z6m_prover_airbender
GUEST_BIN := ../guest_airbender/build/z6m_guest.bin
LOGDIR    := target/eest-logs

# TESTS_SUBDIR can be overridden from the command line:
TESTS_SUBDIR ?=

TESTFILES := $(shell find $(EEST_DIR)/$(TESTS_SUBDIR) -type f -name '*.json')
RELTESTS  := $(patsubst $(EEST_DIR)/%,%,$(TESTFILES))
LOGFILES  := $(addprefix $(LOGDIR)/,$(RELTESTS:.json=.log))

.PHONY: build selftest eest clean-logs

.DELETE_ON_ERROR:

build:
	cargo build --release

selftest: build
	$(PROVER) --guest-bin $(GUEST_BIN) execute --is-test --file-name $(EEST_DIR)/for_osaka/istanbul/eip152_blake2/blake2_delegatecall/blake2_precompile_delegatecall.json

eest: $(LOGFILES)

# A rebuilt prover or guest makes every log stale, so they are prerequisites too (when present).
$(LOGDIR)/%.log: $(EEST_DIR)/%.json $(wildcard $(PROVER) $(GUEST_BIN))
	@mkdir -p $(dir $@)
	$(PROVER) --guest-bin $(GUEST_BIN) execute --is-test --file-name $< 2>&1 | tee $@ || echo "CRASHED! $@" | tee -a $@

clean-logs:
	rm -rf $(LOGDIR)
