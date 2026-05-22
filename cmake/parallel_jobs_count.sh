#!/bin/bash

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

set -e
set -o pipefail

case $(uname -s) in
	Linux)
		nproc
		;;
	Darwin)
		perf_cores=$(sysctl -n hw.perflevel0.physicalcpu)
		effi_cores=$(sysctl -n hw.perflevel1.physicalcpu)
	    echo $(( $perf_cores + $effi_cores / 2 ))
		;;
	*)
		echo "unsupported OS"
		exit 1
		;;
esac
