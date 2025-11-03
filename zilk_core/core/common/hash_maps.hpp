// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <unordered_map>
#include <unordered_set>


namespace silkworm {

/*
Alias templates to fast hash maps and sets, such as Abseil "Swiss tables"

The following aliases are defined:

FlatHashMap – a hash map that might not have pointer stability.
FlatHashSet – a hash set that might not have pointer stability.

See https://abseil.io/docs/cpp/guides/container#hash-tables
and https://abseil.io/docs/cpp/guides/container#fn:pointer-stability
*/


// Abseil is not compatible with Wasm due to its multi-threading features,
// at least not under CMake, but see
// https://github.com/abseil/abseil-cpp/pull/721

template <class K, class V>
using FlatHashMap = std::unordered_map<K, V>;

template <class T>
using FlatHashSet = std::unordered_set<T>;


}  // namespace silkworm
