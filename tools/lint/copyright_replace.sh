#!/bin/bash

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

set -e
set -o pipefail

script_dir=$(dirname "${BASH_SOURCE[0]}")
project_dir="$script_dir/../.."

banner1='\/\/ Copyright 2025 The Silkworm Authors\n\/\/ SPDX-License-Identifier: Apache-2.0\n'
banner2='# Copyright 2025 The Silkworm Authors\n# SPDX-License-Identifier: Apache-2.0\n'

for dir in cmd examples silkworm
do
	find "$project_dir/$dir" \( -name '*.cpp' -or -name '*.hpp' \) \
		-not -path '*/zilk_core/core/chain/genesis_*.cpp' \
		-not -path '*/zilk_core/core/common/lru_cache*' \
		-not -path '*/zilk_core/core/crypto/kzg.cpp' \
		-not -path '*/silkworm/interfaces/*' \
		-not -path '*/silkworm/db/datastore/snapshots/config/chains/*' \
		-not -path '*/silkworm/rpc/json_rpc/specification.cpp' \
		-not -path '*/silkworm/sync/internals/preverified_hashes/preverified_hashes_*' \
	    | \
	    xargs -L1 sed -e "1,15d; 16s/^/$banner1/" -i ''
done

for dir in cmake cmd examples silkworm third_party
do
	find "$project_dir/$dir" \( -name '*.cmake' -or -name 'CMakeLists.txt' \) \
		-not -path '*/third_party/*/*/*' \
		-not -path '*/third_party/cmake-conan/conan_provider.cmake' \
		-not -path '*/cmake/conan_quiet.cmake' \
	    | \
	    xargs -L1 sed -e "1,15d; 16s/^/$banner2/" -i ''
done
