// Integer growth check for the guest's unordered containers.
//
// Every insert into a std::unordered_map or std::unordered_set calls libstdc++'s
// _Prime_rehash_policy::_M_need_rehash (out of line in libstdc++.a) to ask whether the bucket
// array must grow. Once the element count passes the cached threshold _M_next_resize, it works out
// the new bucket count and the next threshold in double, which rv64im runs as soft-float calls
// (__floatundisf, __fixunssfdi, __adddf3, __muldf3, __divdf3, conversions): about 950 instructions
// each time a container takes its first element or grows, 231K times per 200 blocks.
//
// With the default max_load_factor of 1.0f every double in that computation is an exact integer:
// n / 1.0, floor(x) + 1, n_bkt * 1.0, bucket count * 1.0 (all values below 2^53; the guest's
// 512 MiB RAM keeps bucket counts far below it). So the integer formulas below give the same
// result and set the same _M_next_resize: bucket counts, rehash points and iteration order stay
// those of libstdc++. The two differ only above 2^53, where the double conversion of n_bkt or of
// the element count rounds (n_bkt == SIZE_MAX additionally converts the out-of-range double 2^64
// to size_t).
//
// The link wraps the symbol (-Wl,--wrap in CMakeLists.txt). Any other load factor goes to the real
// function, and a bucket count from 14 up comes from the real _M_next_bkt, which owns the prime
// table.
//
// Ported from prover/guest_airbender/src/hashtable_policy.cpp (rv32); on rv64 the
// std::pair<bool, size_t> result already returns in a0/a1, so no word-packed stand-in is needed.

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <unordered_map>
#include <utility>

#if !(defined(ZISK) && defined(__riscv) && __riscv_xlen == 64)
#error "hashtable_policy.cpp is the target of the rv64 ZisK guest's --wrap of _M_need_rehash"
#endif

// The formulas restate libstdc++ 15's src/c++11/hashtable_c++0x.cc: re-derive them when the
// toolchain changes.
static_assert(_GLIBCXX_RELEASE == 15);
// The wrapped symbol is the size_t == unsigned long overload (the Emmm in its mangled name).
static_assert(std::is_same_v<std::size_t, unsigned long>);

namespace
{
using std::__detail::_Prime_rehash_policy;

using RehashResult = std::pair<bool, std::size_t>;
static_assert(sizeof(RehashResult) == 16 && offsetof(RehashResult, second) == 8);

constexpr RehashResult no_rehash{false, 0};

constexpr RehashResult rehash_to(std::size_t n_bkt) noexcept
{
    return {true, n_bkt};
}

// _M_next_bkt's table for bucket counts below 14.
constexpr unsigned char fast_bkt[] = {2, 2, 2, 3, 5, 5, 7, 7, 11, 11, 11, 11, 13, 13};
}  // namespace

extern "C" RehashResult __real__ZNKSt8__detail20_Prime_rehash_policy14_M_need_rehashEmmm(
    const _Prime_rehash_policy* policy, std::size_t n_bkt, std::size_t n_elt, std::size_t n_ins);

extern "C" RehashResult __wrap__ZNKSt8__detail20_Prime_rehash_policy14_M_need_rehashEmmm(
    const _Prime_rehash_policy* policy, std::size_t n_bkt, std::size_t n_elt, std::size_t n_ins)
{
    const std::size_t n = n_elt + n_ins;
    if (n <= policy->_M_next_resize)
        return no_rehash;

    // A bit test: comparing the floats would be another soft-float call.
    const std::uint32_t load_factor = std::bit_cast<std::uint32_t>(policy->_M_max_load_factor);
    if (load_factor != std::bit_cast<std::uint32_t>(1.0f))
        return __real__ZNKSt8__detail20_Prime_rehash_policy14_M_need_rehashEmmm(
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
