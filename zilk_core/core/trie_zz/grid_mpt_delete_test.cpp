// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
// GridMPT<true, DirectState> regression test.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <map>
#include <random>
#include <span>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

namespace {

struct Bytes32Less {
    bool operator()(const bytes32& a, const bytes32& b) const noexcept {
        return std::memcmp(a.bytes, b.bytes, 32) < 0;
    }
};
using Bytes32Map = std::map<bytes32, Bytes, Bytes32Less>;

// Storage-leaf value RLP for a 32-byte big-endian value (as check_root builds).
Bytes slot_value_rlp(uint64_t v) {
    bytes32 val{};
    for (int i = 0; i < 8; ++i) val.bytes[31 - i] = static_cast<uint8_t>(v >> (8 * i));
    Bytes out;
    silkworm::rlp::encode(out, silkworm::zeroless_view(ByteView{val.bytes, 32}));
    return out;
}

// Canonical root over (hashed key -> value rlp) leaves; optionally captures every node RLP into `sink`.
bytes32 hashbuilder_root(const Bytes32Map& leaves, Bytes32Map* sink) {
    if (leaves.empty()) return silkworm::kEmptyRoot;
    silkworm::trie::HashBuilder hb;
    if (sink != nullptr) {
        hb.rlp_collector = [sink](ByteView node_rlp) {
            sink->emplace(keccak_bytes(node_rlp), Bytes{node_rlp});
        };
    }
    for (const auto& [k, v] : leaves) {
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{k.bytes, 32}), v);
    }
    return hb.root_hash();
}

std::vector<uint8_t> build_node_store(const Bytes32Map& nodes) {
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    for (const auto& [h, rlp] : nodes) {
        std::vector<uint8_t> body;
        FlatKv::encode(body, h, rlp);
        nb.add(hash_key8(h), ByteView{body.data(), body.size()});
    }
    return std::move(nb).finalize();
}

// Brute-force a hashed trie key starting with the given nibbles.
bytes32 key_with_prefix(std::initializer_list<uint8_t> nibs) {
    for (uint64_t i = 0;; ++i) {
        bytes32 raw{};
        for (int b = 0; b < 8; ++b) raw.bytes[31 - b] = static_cast<uint8_t>(i >> (8 * b));
        const bytes32 h = keccak_bytes(ByteView{raw.bytes, 32});
        bool match = true;
        size_t j = 0;
        for (uint8_t want : nibs) {
            const uint8_t got = (j % 2 == 0) ? (h.bytes[j / 2] >> 4) : (h.bytes[j / 2] & 0x0F);
            if (got != want) {
                match = false;
                break;
            }
            ++j;
        }
        if (match) return h;
    }
}

// Runs pre -> post through GridMPT<true.
void check_delete_all_then_insert(const Bytes32Map& pre, const Bytes32Map& post) {
    Bytes32Map nodes;
    const bytes32 pre_root = hashbuilder_root(pre, &nodes);
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};

    std::vector<TrieNodeFlat> updates;
    updates.reserve(pre.size() + post.size());
    for (const auto& [k, v] : pre) {
        auto& node = updates.emplace_back(k);
        node.self_initial_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf, v.data(), v.size());
        node.buf[40] = 0x80;
        node.current_off = 40;
        node.current_len = 1;
    }
    for (const auto& [k, v] : post) {
        auto& node = updates.emplace_back(k);
        node.current_off = 40;
        node.current_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf + 40, v.data(), v.size());
    }
    std::ranges::sort(updates, [](const TrieNodeFlat& a, const TrieNodeFlat& b) {
        return std::memcmp(a.key.bytes, b.key.bytes, 32) < 0;
    });

    GridMPT<true, DirectState> trie{direct, pre_root};
    const bytes32 got = trie.calc_root_from_updates({updates.data(), updates.size()});
    const bytes32 expected = hashbuilder_root(post, nullptr);

    CAPTURE(silkworm::to_hex(got), silkworm::to_hex(expected));
    CHECK(trie.missing_count() == 0);
    CHECK_FALSE(trie.failed());
    REQUIRE(got == expected);
}

// Same, for a batch that deletes only part of the pre trie: every pre leaf is in the batch.
void check_partial_delete(const Bytes32Map& pre, const std::vector<bytes32>& deleted) {
    const auto is_deleted = [&deleted](const bytes32& k) {
        return std::ranges::any_of(deleted, [&k](const bytes32& d) {
            return std::memcmp(d.bytes, k.bytes, 32) == 0;
        });
    };

    Bytes32Map nodes;
    const bytes32 pre_root = hashbuilder_root(pre, &nodes);
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};

    Bytes32Map post;
    std::vector<TrieNodeFlat> updates;
    updates.reserve(pre.size());
    for (const auto& [k, v] : pre) {
        auto& node = updates.emplace_back(k);
        node.self_initial_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf, v.data(), v.size());
        if (is_deleted(k)) {
            node.buf[40] = 0x80;
            node.current_off = 40;
            node.current_len = 1;
        } else {
            post[k] = v;
        }
    }

    GridMPT<true, DirectState> trie{direct, pre_root};
    const bytes32 got = trie.calc_root_from_updates({updates.data(), updates.size()});
    const bytes32 expected = hashbuilder_root(post, nullptr);

    CAPTURE(silkworm::to_hex(got), silkworm::to_hex(expected));
    CHECK(trie.missing_count() == 0);
    CHECK_FALSE(trie.failed());
    REQUIRE(got == expected);
}

// Runs a read-only/delete/upsert batch through GridMPT<true, DirectState> and REQUIREs the canonical post root.
void check_mixed_updates(const Bytes32Map& pre, const std::vector<bytes32>& ro,
                         const std::vector<bytes32>& del, const Bytes32Map& post) {
    Bytes32Map nodes;
    const bytes32 pre_root = hashbuilder_root(pre, &nodes);
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};

    Bytes32Map expected_leaves = pre;
    std::vector<TrieNodeFlat> updates;
    updates.reserve(ro.size() + del.size() + post.size());
    for (const auto& k : ro) {
        auto& node = updates.emplace_back(k);
        const auto& v = pre.at(k);
        node.self_initial_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf, v.data(), v.size());
    }
    for (const auto& k : del) {
        auto& node = updates.emplace_back(k);
        const auto& v = pre.at(k);
        node.self_initial_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf, v.data(), v.size());
        node.buf[40] = 0x80;
        node.current_off = 40;
        node.current_len = 1;
        expected_leaves.erase(k);
    }
    for (const auto& [k, v] : post) {
        auto& node = updates.emplace_back(k);
        node.current_off = 40;
        node.current_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf + 40, v.data(), v.size());
        expected_leaves[k] = v;
    }
    std::ranges::sort(updates, [](const TrieNodeFlat& a, const TrieNodeFlat& b) {
        return std::memcmp(a.key.bytes, b.key.bytes, 32) < 0;
    });

    GridMPT<true, DirectState> trie{direct, pre_root};
    const bytes32 got = trie.calc_root_from_updates({updates.data(), updates.size()});
    const bytes32 expected = hashbuilder_root(expected_leaves, nullptr);

    CAPTURE(silkworm::to_hex(got), silkworm::to_hex(expected));
    CHECK(trie.missing_count() == 0);
    CHECK_FALSE(trie.failed());
    REQUIRE(got == expected);
}

// A key that shares exactly `share` leading nibbles with `base` (all 64 when share is 64), random after.
template <typename Rng>
bytes32 key_sharing(const bytes32& base, unsigned share, Rng& rng) {
    bytes32 k = base;
    for (unsigned n = share; n < 64; ++n) {
        uint8_t nib = static_cast<uint8_t>(rng() & 0x0F);
        if (n == share) nib = static_cast<uint8_t>((((n % 2 == 0) ? base.bytes[n / 2] >> 4 : base.bytes[n / 2]) + 1 +
                                                    rng() % 15) & 0x0F);
        uint8_t& b = k.bytes[n / 2];
        b = (n % 2 == 0) ? static_cast<uint8_t>((b & 0x0F) | (nib << 4)) : static_cast<uint8_t>((b & 0xF0) | nib);
    }
    return k;
}

// Keys sharing more nibbles than this are left out of the trie tests.
constexpr unsigned kMaxTrieShare = 37;

// One batch over a pre trie: `ro` keys are visited read-only, `del` keys deleted, `post` keys inserted.
struct Scenario {
    Bytes32Map pre;
    Bytes32Map post;
    Bytes32Map expected;
    std::vector<bytes32> ro;
    std::vector<bytes32> del;
};

// Keys in a cluster around `base`.
template <typename Rng>
Scenario make_scenario(Rng& rng, const bytes32& base, unsigned min_share, bool touch_all) {
    std::vector<bytes32> keys{base};
    const unsigned n = 4 + rng() % 40;
    while (keys.size() < n) {
        const bytes32& from = keys[rng() % keys.size()];
        const bytes32 k = key_sharing(from, min_share + rng() % (kMaxTrieShare + 1 - min_share), rng);
        if (std::ranges::find(keys, k) == keys.end()) keys.push_back(k);
    }
    Scenario sc;
    uint64_t value = 1;
    for (const auto& k : keys) {
        switch (rng() % (touch_all ? 4 : 5)) {
            case 0: sc.post[k] = slot_value_rlp(value++); break;
            case 1: sc.pre[k] = slot_value_rlp(value++); sc.ro.push_back(k); break;
            case 2: sc.pre[k] = slot_value_rlp(value++); sc.del.push_back(k); break;
            case 3: sc.pre[k] = slot_value_rlp(value++); sc.ro.push_back(k); break;
            default: sc.pre[k] = slot_value_rlp(value++); break;
        }
    }
    bytes32 low{};
    bytes32 high{};
    std::memset(high.bytes, 0xFF, 32);
    for (const bytes32* k : {&low, &high}) {
        if (sc.pre.contains(*k) || sc.post.contains(*k)) continue;
        sc.pre[*k] = slot_value_rlp(value++);
        if (touch_all) sc.ro.push_back(*k);
    }
    sc.expected = sc.pre;
    for (const auto& k : sc.del) sc.expected.erase(k);
    for (const auto& [k, v] : sc.post) sc.expected[k] = v;
    return sc;
}

// Changes to the witness (the update claims and the node store) that a verifier must not accept.
struct Forgery {
    const bytes32* ro_value = nullptr;
    const bytes32* del_value = nullptr;
    const bytes32* node = nullptr;
};

// The sorted updates of a scenario (must never reallocate: GridMPT keeps ByteViews into TrieNodeFlat::buf).
std::vector<TrieNodeFlat> build_updates(const Scenario& sc, const Forgery& forgery) {
    std::vector<TrieNodeFlat> updates;
    updates.reserve(sc.ro.size() + sc.del.size() + sc.post.size());
    for (const auto& k : sc.ro) {
        auto& node = updates.emplace_back(k);
        const Bytes v = (forgery.ro_value != nullptr && *forgery.ro_value == k) ? slot_value_rlp(0xbad) : sc.pre.at(k);
        node.self_initial_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf, v.data(), v.size());
    }
    for (const auto& k : sc.del) {
        auto& node = updates.emplace_back(k);
        const Bytes v = (forgery.del_value != nullptr && *forgery.del_value == k) ? slot_value_rlp(0xbad) : sc.pre.at(k);
        node.self_initial_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf, v.data(), v.size());
        node.buf[40] = 0x80;
        node.current_off = 40;
        node.current_len = 1;
    }
    for (const auto& [k, v] : sc.post) {
        auto& node = updates.emplace_back(k);
        node.current_off = 40;
        node.current_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf + 40, v.data(), v.size());
    }
    std::ranges::sort(updates, [](const TrieNodeFlat& a, const TrieNodeFlat& b) {
        return std::memcmp(a.key.bytes, b.key.bytes, 32) < 0;
    });
    return updates;
}

// The root a scenario's batch gives through GridMPT<true, DirectState>, over a complete witness of its pre trie.
bytes32 scenario_root(const Scenario& sc, const Forgery& forgery) {
    Bytes32Map nodes;
    const bytes32 pre_root = hashbuilder_root(sc.pre, &nodes);
    if (forgery.node != nullptr) nodes.at(*forgery.node)[nodes.at(*forgery.node).size() / 2] ^= 0x01;
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
    const std::vector<TrieNodeFlat> updates = build_updates(sc, forgery);

    GridMPT<true, DirectState> trie{direct, pre_root};
    const bytes32 got = trie.calc_root_from_updates({updates.data(), updates.size()});
    if (forgery.node == nullptr && forgery.ro_value == nullptr && forgery.del_value == nullptr)
        CHECK(trie.missing_count() == 0);
    return got;
}

enum class NodeOutcome { kRejected, kCrashed, kAccepted };

// scenario_root with node `h` of the witness altered, in a child process.
NodeOutcome forged_node_outcome(const Scenario& sc, const bytes32& h, const bytes32& honest) {
    std::fflush(nullptr);
    const pid_t pid = fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        for (const int sig : {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT, SIGALRM}) std::signal(sig, SIG_DFL);
        alarm(5);
        const bytes32 got = scenario_root(sc, Forgery{.node = &h});
        _exit(got == honest ? 1 : 0);
    }
    int status = 0;
    REQUIRE(waitpid(pid, &status, 0) == pid);
    if (WIFSIGNALED(status)) return NodeOutcome::kCrashed;
    return WEXITSTATUS(status) == 0 ? NodeOutcome::kRejected : NodeOutcome::kAccepted;
}

}  // namespace

// The seek before each update finds where the new key leaves the previous one from the two keys' common prefix.
TEST_CASE("GridMPT<true, DirectState> seeks between keys sharing long prefixes", "[trie][gridmpt]") {
    std::mt19937 rng{20261008};
    for (int round = 0; round < 120; ++round) {
        bytes32 base{};
        for (auto& b : base.bytes) b = static_cast<uint8_t>(rng());
        const Scenario sc = make_scenario(rng, base, round % 3 == 0 ? 24 : 0, /*touch_all=*/false);
        CAPTURE(round);
        REQUIRE(scenario_root(sc, {}) == hashbuilder_root(sc.expected, nullptr));
    }
}

// check_root hoists one GridMPT<true, DirectState> out of its per-account loop and reset()s it.
TEST_CASE("GridMPT<true, DirectState> after reset seeks from the batch's own keys", "[trie][gridmpt]") {
    std::mt19937 rng{20261009};
    for (int round = 0; round < 30; ++round) {
        bytes32 base{};
        for (auto& b : base.bytes) b = static_cast<uint8_t>(rng());
        std::vector<Scenario> scs;
        Bytes32Map nodes;
        std::vector<bytes32> pre_roots;
        const unsigned batches = 2 + rng() % 5;
        for (unsigned i = 0; i < batches; ++i) {
            base = key_sharing(base, rng() % (kMaxTrieShare + 1), rng);
            scs.push_back(make_scenario(rng, base, 0, /*touch_all=*/false));
            pre_roots.push_back(hashbuilder_root(scs.back().pre, &nodes));
        }
        std::vector<uint8_t> prestate =
            DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
        std::vector<uint8_t> nodestore = build_node_store(nodes);
        DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
        std::vector<std::vector<TrieNodeFlat>> updates;
        for (const auto& sc : scs) updates.push_back(build_updates(sc, {}));

        GridMPT<true, DirectState> trie{direct, pre_roots[0]};
        for (unsigned i = 0; i < batches; ++i) {
            if (i > 0) trie.reset(pre_roots[i]);
            CAPTURE(round, i);
            REQUIRE(trie.calc_root_from_updates({updates[i].data(), updates[i].size()}) ==
                    hashbuilder_root(scs[i].expected, nullptr));
            CHECK(trie.missing_count() == 0);
        }
    }
}

// Forged witnesses: every claim the update batch makes about the pre trie, and every node of the witness.
TEST_CASE("GridMPT<true, DirectState> rejects forged witnesses between keys sharing long prefixes", "[trie][gridmpt]") {
    std::mt19937 rng{20261010};
    size_t forged_claims = 0;
    size_t forged_nodes = 0;
    size_t rejected_nodes = 0;
    size_t crashed_nodes = 0;
    for (int round = 0; round < 12; ++round) {
        bytes32 base{};
        for (auto& b : base.bytes) b = static_cast<uint8_t>(rng());
        const Scenario sc = make_scenario(rng, base, round % 3 == 0 ? 24 : 0, /*touch_all=*/true);
        const bytes32 honest = hashbuilder_root(sc.expected, nullptr);
        CAPTURE(round);
        REQUIRE(scenario_root(sc, {}) == honest);

        for (const auto& k : sc.ro) {
            CAPTURE(silkworm::to_hex(ByteView{k.bytes, 32}));
            REQUIRE(scenario_root(sc, Forgery{.ro_value = &k}) == bytes32{});
            ++forged_claims;
        }
        for (const auto& k : sc.del) {
            CAPTURE(silkworm::to_hex(ByteView{k.bytes, 32}));
            REQUIRE(scenario_root(sc, Forgery{.del_value = &k}) == bytes32{});
            ++forged_claims;
        }
        Bytes32Map nodes;
        hashbuilder_root(sc.pre, &nodes);
        for (const auto& [h, rlp] : nodes) {
            CAPTURE(silkworm::to_hex(ByteView{h.bytes, 32}));
            switch (forged_node_outcome(sc, h, honest)) {
                case NodeOutcome::kRejected: ++rejected_nodes; break;
                case NodeOutcome::kCrashed: ++crashed_nodes; break;
                case NodeOutcome::kAccepted: FAIL("a forged node gave the honest post root"); break;
            }
            ++forged_nodes;
        }
    }
    CHECK(forged_claims > 100);
    CHECK(forged_nodes > 100);
    CHECK(rejected_nodes + crashed_nodes == forged_nodes);
    WARN("forged nodes: " << rejected_nodes << " rejected, " << crashed_nodes << " aborted the walker");
    CHECK(rejected_nodes > 0);
}

// The keys' own comparison the seek uses (key_lcp_nibbles) and the in-place expansion.
namespace {

size_t base_lcp_nibbles(const uint8_t* a, const uint8_t* b, size_t max) noexcept {
    size_t i = 0;
    while (i + 8 <= max) {
        uint64_t wa, wb;
        std::memcpy(&wa, a + i, sizeof(wa));
        std::memcpy(&wb, b + i, sizeof(wb));
        const uint64_t diff = wa ^ wb;
        if (diff != 0) {
            return i + static_cast<size_t>(__builtin_ctzll(diff)) / 8u;
        }
        i += 8;
    }
    while (i < max && a[i] == b[i]) ++i;
    return i;
}

void check_key_pair(const TrieNodeFlat& a, const TrieNodeFlat& b) {
    const nibbles64 na = nibbles64::from_bytes32(a.key);
    const nibbles64 nb = nibbles64::from_bytes32(b.key);
    size_t naive = 0;
    while (naive < 64 && na.nib[naive] == nb.nib[naive]) ++naive;
    REQUIRE(key_lcp_nibbles(a, b) == naive);
    REQUIRE(key_lcp_nibbles(b, a) == naive);
    for (size_t consumed = 1; consumed <= 64; ++consumed) {
        const size_t expected = base_lcp_nibbles(na.nib.data(), nb.nib.data(), consumed);
        REQUIRE(std::min<size_t>(key_lcp_nibbles(a, b), consumed) == expected);
    }
}

}  // namespace

TEST_CASE("key_lcp_nibbles equals the lcp of the expanded keys", "[trie][gridmpt]") {
    std::mt19937 rng{20261011};
    std::vector<TrieNodeFlat> keys(2);
    for (auto& b : keys[0].key.bytes) b = static_cast<uint8_t>(rng());

    SECTION("equal keys") {
        keys[1].key = keys[0].key;
        check_key_pair(keys[0], keys[1]);
    }
    SECTION("first difference at each nibble, each value, with random tails") {
        for (unsigned pos = 0; pos < 64; ++pos) {
            for (unsigned delta = 1; delta < 16; ++delta) {
                keys[1].key = keys[0].key;
                uint8_t& byte = keys[1].key.bytes[pos / 2];
                byte ^= static_cast<uint8_t>(pos % 2 == 0 ? delta << 4 : delta);
                for (unsigned n = pos + 1; n < 64; ++n) {
                    if (rng() % 2 == 0) keys[1].key.bytes[n / 2] ^= static_cast<uint8_t>(n % 2 == 0 ? 0x10 : 0x01);
                }
                CAPTURE(pos, delta);
                check_key_pair(keys[0], keys[1]);
                REQUIRE(key_lcp_nibbles(keys[0], keys[1]) == pos);
            }
        }
    }
    SECTION("random pairs with a shared prefix of random length") {
        for (int i = 0; i < 20000; ++i) {
            for (auto& b : keys[0].key.bytes) b = static_cast<uint8_t>(rng());
            keys[1].key = (rng() % 8 == 0) ? keys[0].key : key_sharing(keys[0].key, rng() % 64, rng);
            check_key_pair(keys[0], keys[1]);
        }
    }
    SECTION("bytes of 0x00 and 0xFF, whose words differ in sign bits") {
        for (unsigned pos = 0; pos < 32; ++pos) {
            std::memset(keys[0].key.bytes, 0x00, 32);
            std::memset(keys[1].key.bytes, 0x00, 32);
            keys[1].key.bytes[pos] = 0xFF;
            check_key_pair(keys[0], keys[1]);
            keys[1].key.bytes[pos] = 0x0F;
            check_key_pair(keys[0], keys[1]);
            keys[1].key.bytes[pos] = 0xF0;
            check_key_pair(keys[0], keys[1]);
        }
    }
}

TEST_CASE("nibbles64::assign_bytes32 equals from_bytes32 over any previous content", "[trie][gridmpt]") {
    std::mt19937 rng{20261012};
    for (int i = 0; i < 2000; ++i) {
        bytes32 k{};
        for (auto& b : k.bytes) b = static_cast<uint8_t>(rng());
        nibbles64 dirty;
        dirty.len = static_cast<uint8_t>(rng());
        for (auto& n : dirty.nib) n = static_cast<uint8_t>(rng());
        dirty.assign_bytes32(k);
        const nibbles64 fresh = nibbles64::from_bytes32(k);
        REQUIRE(dirty.len == 64);
        REQUIRE(dirty.nib == fresh.nib);
    }
}

TEST_CASE("GridMPT<true, DirectState> survives a batch that empties the trie", "[trie][gridmpt]") {
    const Bytes32Map pre{{key_with_prefix({0xa}), slot_value_rlp(1)},
                         {key_with_prefix({0xd}), slot_value_rlp(2)}};

    SECTION("deletes then insert (the grid must re-seed)") {
        check_delete_all_then_insert(pre, {{key_with_prefix({0xf}), slot_value_rlp(3)}});
    }
    SECTION("deletes only (empty post root)") {
        check_delete_all_then_insert(pre, {});
    }
}

// Deletes empty an extension's whole subtree (collapse is deferred, so the empty ext stays on the active path).
TEST_CASE("GridMPT<true, DirectState> insert descending a delete-emptied extension", "[trie][gridmpt]") {
    const Bytes32Map pre{{key_with_prefix({8, 0xe, 1}), slot_value_rlp(1)},
                         {key_with_prefix({8, 0xe, 7}), slot_value_rlp(2)}};
    check_delete_all_then_insert(pre, {{key_with_prefix({8, 0xf}), slot_value_rlp(3)}});
}

// After the eager fold of a delete-emptied line moves the seek's landing depth up.
TEST_CASE("GridMPT<true, DirectState> seek cursor after folding a delete-emptied line", "[trie][gridmpt]") {
    const Bytes32Map pre{{key_with_prefix({0xc, 0xf, 1}), slot_value_rlp(1)},
                         {key_with_prefix({0xc, 0xf, 7}), slot_value_rlp(2)}};
    check_delete_all_then_insert(pre, {{key_with_prefix({0xc, 7}), slot_value_rlp(3)},
                                       {key_with_prefix({0xc, 0xf, 0xf}), slot_value_rlp(4)}});
}

// A delete leaves its parent branch with a single child.
TEST_CASE("GridMPT<true, DirectState> single-child branch folds over an unmodified child", "[trie][gridmpt]") {
    const Bytes32Map pre{{key_with_prefix({1, 0, 0}), slot_value_rlp(1)},
                         {key_with_prefix({1, 0, 1}), slot_value_rlp(2)},
                         {key_with_prefix({1, 1, 1}), slot_value_rlp(3)}};
    check_partial_delete(pre, {key_with_prefix({1, 1, 1})});
}

// A read-only visit into one child of a branch, followed by deleting the branch's only other child.
TEST_CASE("GridMPT<true, DirectState> read-only sibling visit then delete of the branch's other child",
          "[trie][gridmpt]") {
    const bytes32 ro_key = key_with_prefix({6, 1, 0, 6, 0xa});
    const bytes32 sib_key = key_with_prefix({6, 1, 0, 6, 0xe});
    const bytes32 del_key = key_with_prefix({6, 1, 0, 0xc});
    const Bytes32Map pre{{ro_key, slot_value_rlp(1)},
                         {sib_key, slot_value_rlp(2)},
                         {del_key, slot_value_rlp(3)},
                         {key_with_prefix({6, 4}), slot_value_rlp(4)},
                         {key_with_prefix({7}), slot_value_rlp(5)}};
    check_mixed_updates(pre, /*ro=*/{ro_key}, /*del=*/{del_key}, /*post=*/{});
}

namespace {

// A hashed trie key: the given nibbles, then `fill` repeated (prefixes too long to grind with key_with_prefix).
bytes32 key_with_nibbles(std::initializer_list<uint8_t> nibs, uint8_t fill) {
    bytes32 k{};
    size_t i = 0;
    for (uint8_t n : nibs) {
        k.bytes[i / 2] |= static_cast<uint8_t>(i % 2 == 0 ? n << 4 : n);
        ++i;
    }
    for (; i < 64; ++i) k.bytes[i / 2] |= static_cast<uint8_t>(i % 2 == 0 ? fill << 4 : fill);
    return k;
}

}  // namespace

// A delete leaves the branch below an extension with a single child, which is a branch.
TEST_CASE("GridMPT<true, DirectState> single-child branch below an extension the same batch splits", "[trie][gridmpt]") {
    const bytes32 d = key_with_nibbles({2, 5, 7, 3}, 1);
    const bytes32 e = key_with_nibbles({2, 5, 7, 0xa, 5}, 2);
    const bytes32 f = key_with_nibbles({2, 5, 7, 0xa, 6}, 3);
    const bytes32 x = key_with_nibbles({2, 9}, 4);
    const bytes32 y = key_with_nibbles({0xf}, 5);
    const Bytes32Map pre{{d, slot_value_rlp(1)}, {e, slot_value_rlp(2)}, {f, slot_value_rlp(3)}};
    const Bytes32Map post{{x, slot_value_rlp(4)}, {y, slot_value_rlp(5)}};
    SECTION("the extension at the root") {
        check_mixed_updates(pre, /*ro=*/{}, /*del=*/{d}, post);
    }
    SECTION("the extension below a branch") {
        Bytes32Map below = pre;
        below.emplace(key_with_nibbles({0xc}, 6), slot_value_rlp(6));
        check_mixed_updates(below, /*ro=*/{}, /*del=*/{d}, post);
    }
}
