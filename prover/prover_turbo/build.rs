// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use sp1_build::build_program_with_args;

fn main() {
    build_program_with_args("../guest_program", Default::default() )
}

