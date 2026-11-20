// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#define SILKWORM_ASSERT(expr) \
    if ((expr)) [[likely]]    \
        static_cast<void>(0);

