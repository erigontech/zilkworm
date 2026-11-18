// Integer growth check for unordered containers: with max_load_factor 1.0f every double in libstdc++'s _M_need_rehash is an exact integer, so these formulas give identical bucket counts and rehash points (they differ only at n_elt + n_ins == SIZE_MAX).
// Wrapped via -Wl,--wrap (CMakeLists.txt); other load factors and bucket counts from 14 up go to the real functions.

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <unordered_map>
#include <utility>

#if !(defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32)
#error "hashtable_policy.cpp is the target of the rv32 guest's --wrap of _M_need_rehash"
#endif

// Restates libstdc++ 15's hashtable_c++0x.cc: re-derive when the toolchain changes.
static_assert(_GLIBCXX_RELEASE == 15);
// The wrapped symbol is the size_t == unsigned int overload (the jjj in its mangled name).
static_assert(std::is_same_v<std::size_t, unsigned int>);

namespace
{
using std::__detail::_Prime_rehash_policy;

// The ilp32 psABI returns std::pair<bool, size_t> in a0/a1; a uint64_t with the same two words is returned straight from registers.
using RehashPair = std::pair<bool, std::size_t>;
using RehashResult = std::uint64_t;
static_assert(sizeof(RehashPair) == sizeof(RehashResult) && offsetof(RehashPair, second) == 4);

constexpr RehashResult no_rehash = 0;

constexpr RehashResult rehash_to(std::size_t n_bkt) noexcept
{
    return RehashResult{n_bkt} << 32 | 1;
}

constexpr unsigned char fast_bkt[] = {2, 2, 2, 3, 5, 5, 7, 7, 11, 11, 11, 11, 13, 13};
}

extern "C" RehashResult __real__ZNKSt8__detail20_Prime_rehash_policy14_M_need_rehashEjjj(
    const _Prime_rehash_policy* policy, std::size_t n_bkt, std::size_t n_elt, std::size_t n_ins);

extern "C" RehashResult __wrap__ZNKSt8__detail20_Prime_rehash_policy14_M_need_rehashEjjj(
    const _Prime_rehash_policy* policy, std::size_t n_bkt, std::size_t n_elt, std::size_t n_ins)
{
    const std::size_t n = n_elt + n_ins;
    if (n <= policy->_M_next_resize)
        return no_rehash;

    // A bit test: comparing the floats would be another soft-float call.
    const std::uint32_t load_factor = std::bit_cast<std::uint32_t>(policy->_M_max_load_factor);
    if (load_factor != std::bit_cast<std::uint32_t>(1.0f))
        return __real__ZNKSt8__detail20_Prime_rehash_policy14_M_need_rehashEjjj(
            policy, n_bkt, n_elt, n_ins);

    // _M_next_resize == 0: nothing allocated yet, so size for at least 11 elements.
    const std::size_t min_bkts = std::max<std::size_t>(n, policy->_M_next_resize != 0 ? 0 : 11);
    if (min_bkts < n_bkt)
    {
        policy->_M_next_resize = n_bkt;
        return no_rehash;
    }

    const std::size_t want =
        std::max(min_bkts + 1, n_bkt * _Prime_rehash_policy::_S_growth_factor);
    if (want < std::size(fast_bkt))
    {
        policy->_M_next_resize = fast_bkt[want];
        return rehash_to(fast_bkt[want]);
    }
    return rehash_to(policy->_M_next_bkt(want));
}
