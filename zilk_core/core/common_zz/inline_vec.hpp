// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

namespace zilkworm {

// A size-aligned vector<> replacement that can use the stack- and/or heap-allocated
// memory for an array of objects. `N` should reasonably fit within stack budget
template <class T, std::size_t N>
class InlineVec {
    static_assert(std::is_trivially_destructible_v<T>,
                  "InlineVec<T,N> assumes T is trivially destructible");
    static_assert(std::is_trivially_copyable_v<T>,
                  "InlineVec<T,N> assumes T is trivially copyable");

    alignas(T) std::byte inline_[N * sizeof(T)];
    T* data_;
    std::size_t size_{0};

  public:
    InlineVec(std::size_t need, std::vector<T>& spill) noexcept {
        if (need <= N) {
            data_ = reinterpret_cast<T*>(inline_);
        } else {
            spill.clear();
            spill.reserve(need);
            data_ = spill.data();
        }
    }

    InlineVec(const InlineVec&) = delete;
    InlineVec& operator=(const InlineVec&) = delete;

    template <class... Args>
    [[gnu::always_inline]] T& emplace_back(Args&&... args) {
        T* slot = data_ + size_++;
        ::new (static_cast<void*>(slot)) T(std::forward<Args>(args)...);
        return *slot;
    }

    T* data() noexcept { return data_; }
    const T* data() const noexcept { return data_; }
    T* begin() noexcept { return data_; }
    T* end() noexcept { return data_ + size_; }
    const T* begin() const noexcept { return data_; }
    const T* end() const noexcept { return data_ + size_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    T& back() noexcept { return data_[size_ - 1]; }
    T& operator[](std::size_t i) noexcept { return data_[i]; }
    const T& operator[](std::size_t i) const noexcept { return data_[i]; }
};

}  // namespace zilkworm
