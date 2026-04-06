SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

EEST_DIR  := ../../third_party/eest-fixtures/state_tests
PROVER    := target/release/z6m_prover_airbender
GUEST_BIN := ../guest_airbender/build/z6m_guest.bin
LOGDIR    := target/eest-logs

# TESTS_SUBDIR can be overridden from the command line:
TESTS_SUBDIR ?=

TESTFILES := $(shell find $(EEST_DIR)/$(TESTS_SUBDIR) -type f -name '*.json')
RELTESTS  := $(patsubst $(EEST_DIR)/%,%,$(TESTFILES))
LOGFILES  := $(addprefix $(LOGDIR)/,$(RELTESTS:.json=.log))

.PHONY: build selftest eest eest-istanbul eest-blake2 clean-logs

.DELETE_ON_ERROR:

build:
	cargo build --release

selftest: build
	$(PROVER) --guest-bin $(GUEST_BIN) execute --is-test --file-name $(EEST_DIR)/istanbul/eip152_blake2/test_blake2b.json

eest: $(LOGFILES)

$(LOGDIR)/%.log: $(EEST_DIR)/%.json
	@mkdir -p $(dir $@)
	$(PROVER) --guest-bin $(GUEST_BIN) execute --is-test --file-name $< 2>&1 | tee $@ || (echo "CRASHED! $@" && rm $@)

clean-logs:
	rm -rf $(LOGDIR)
