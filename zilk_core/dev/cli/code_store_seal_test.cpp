// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// sanitize() pads the code store's payloads where they lie for the EVM (code_store_seal.hpp): it
// zeroes the bytes after the payload of every entry but the last, once every payload is hashed and
// every account bound, and only for the dense layout MphfBuilder writes, every entry the map refers
// to being one of the entries that tile the data section. The cases here check that it zeroes
// nothing else, nothing on a failed sanitize, nothing for a forged layout (no keys, an entry the
// map refers to inside another's payload or across another's tail), that the code it pads is the
// code evmone then runs in place, that the dead index is not used afterwards, and that a pre-state
// whose code store overlaps another section is rejected. A block creates code equal to a witness
// code with CREATE2 and runs and reads it, through the shadow run and the guest entry point. Built
// with -DEVMONE_RV32_DISPATCH_TEST (the native test build), sanitize() seals as on the guest;
// without it, it must leave the code store as it was. Three more cases compare against references:
// DenseLayout and zero_tails() against an independent walk on random and mutated sections; blocks
// of random contracts, run in place and with every code copied (status, gas, receipts, logs,
// storage, post-state root equal); and forged witnesses, random and crafted mutations of the code
// store, its map, the account records and the header, each in a child process, where an accepted
// pre-state must give every contract its genuine code, with the JUMPDESTs of the copy.

#include <algorithm>
#include <array>
#include <csignal>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <map>
#include <random>
#include <span>
#include <cstdlib>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>
#include <evmone/baseline.hpp>

#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/state_zz/account_read_test_util.hpp>
#include <zilk_core/core/state_zz/code_store_seal.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

using namespace zilkworm;
using namespace zilkworm::test_util;
using silkworm::ByteView;
using silkworm::Bytes;
using silkworm::cmd::state_transition::StateTransition;

namespace {

uint32_t round4(uint32_t v) { return (v + 3) & ~uint32_t{3}; }
uint32_t round8(uint32_t v) { return (v + 7) & ~uint32_t{7}; }

uint64_t load_u64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}
void store_u64(uint8_t* p, uint64_t v) { std::memcpy(p, &v, 8); }

// The hook exists only where evmone runs code in place (EVMONE_IN_PLACE_CODE); without it there is
// no region to reset and sanitize() must seal nothing.
void reset_in_place_region() {
#if EVMONE_IN_PLACE_CODE
    evmone::baseline::set_in_place_code_region(nullptr, nullptr);
#endif
}

bool analyzed_in_place(ByteView code) {
    return evmone::baseline::analyze({code.data(), code.size()}).code().data() == code.data();
}

// ---------------------------------------------------------------------------
// DenseLayout and zero_tails on hand-made data sections
// ---------------------------------------------------------------------------

/// A data section: the 8-byte sentinel, then [len:u64][key:32][payload][zeros to 8] per entry.
struct Section {
    std::vector<uint64_t> words;  // 8-aligned storage
    uint32_t size{8};
    std::vector<uint32_t> offsets;
    std::vector<uint32_t> ends;  // of the payloads, as built: zero_tails() zeroes the lengths

    uint8_t* data() { return reinterpret_cast<uint8_t*>(words.data()); }

    explicit Section(const std::vector<uint32_t>& payload_sizes, uint32_t extra = 0) {
        uint32_t total = 8;
        for (const auto n : payload_sizes) total += round8(40 + n);
        words.assign((total + extra) / 8 + 8, 0);
        for (size_t i = 0; i < payload_sizes.size(); ++i) {
            const uint32_t n = payload_sizes[i];
            offsets.push_back(size);
            store_u64(data() + size, 32 + n);
            std::memset(data() + size + 8, static_cast<int>(0xc0 + i % 32), 32);  // key
            for (uint32_t k = 0; k < n; ++k)
                data()[size + 40 + k] = static_cast<uint8_t>(0x11 + k + i);
            ends.push_back(size + 40 + n);
            size += round8(40 + n);
        }
        size += extra;
    }
};

bool dense(Section& s) { return code_store_seal::DenseLayout{s.data(), s.size}.dense(); }

/// zero_tails() changes only [end, round4(end) + 36) after every payload but the last's, to
/// zero, leaving at least 33 zero bytes after each of those payloads.
void check_zero_tails(Section s) {
    const std::vector<uint64_t> before = s.words;
    const code_store_seal::DenseLayout layout{s.data(), s.size};
    REQUIRE(layout.dense());
    REQUIRE(layout.last() == s.offsets.back());
    code_store_seal::zero_tails(s.data(), layout.last());
    std::vector<bool> zeroed(s.size, false);
    for (size_t i = 0; i + 1 < s.offsets.size(); ++i) {
        const uint32_t end = s.ends[i];
        // In the next entry's 40-byte header, before its payload.
        REQUIRE(round4(end) + 36 <= s.offsets[i + 1] + 40);
        for (uint32_t b = end; b < round4(end) + 36; ++b) zeroed[b] = true;
        for (uint32_t b = end; b < end + 33; ++b) CHECK(s.data()[b] == 0);
    }
    const auto* old = reinterpret_cast<const uint8_t*>(before.data());
    size_t changed_elsewhere = 0;
    for (uint32_t b = 0; b < s.size; ++b) {
        if (zeroed[b])
            CHECK(s.data()[b] == 0);
        else
            changed_elsewhere += s.data()[b] != old[b];
    }
    CHECK(changed_elsewhere == 0);
}

// ---------------------------------------------------------------------------
// Witnesses built by MphfBuilder
// ---------------------------------------------------------------------------

Bytes code_of(size_t n, uint8_t seed) {
    Bytes c(n, 0);
    for (size_t i = 0; i < n; ++i) c[i] = static_cast<uint8_t>(seed + i * 7 + 1);
    return c;
}

struct Witness {
    std::vector<uint8_t> blob;
    std::vector<uint8_t> nodestore;
    std::vector<Bytes> codes;
    /// The entries' offsets in the data section and their lengths (32 + the payload's size), as
    /// built: sealing zeroes the lengths in the section.
    std::map<uint32_t, uint32_t> entries;

    PreStateMeta* meta() { return reinterpret_cast<PreStateMeta*>(blob.data()); }
    MphfMapHeader* header() {
        return reinterpret_cast<MphfMapHeader*>(blob.data() + meta()->code_store_offset);
    }
    uint8_t* data() { return reinterpret_cast<uint8_t*>(header()) + header()->data_offset; }
    uint32_t data_size() { return header()->data_size; }
    uint32_t* slots() {
        return reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(header()) +
                                           header()->slot_offsets_offset);
    }
    /// Entry offsets in the data section, ascending.
    std::vector<uint32_t> offsets() const {
        std::vector<uint32_t> out;
        for (const auto& [off, len] : entries) out.push_back(off);
        return out;
    }
    uint32_t payload_end(uint32_t off) const { return off + 8 + entries.at(off); }
    ByteView payload(uint32_t off) { return {data() + off + 40, entries.at(off) - 32u}; }
    /// Repoints the map's reference to entry `from` at `to`.
    void repoint(uint32_t from, uint32_t to) {
        for (uint32_t i = 0; i < header()->n_keys; ++i)
            if (slots()[i] == from) slots()[i] = to;
    }
};

Witness make_witness(const std::vector<Bytes>& codes) {
    std::vector<std::pair<bytes32, Bytes>> store;
    for (const auto& c : codes) store.emplace_back(keccak_bytes(ByteView{c.data(), c.size()}), c);
    std::vector<DirectState::AccountInfo> accounts{make_eoa(make_addr(0, 0x11), 1, intx::uint256{0})};
    Witness w;
    w.blob = DirectState::build_blob_from_accounts(accounts, {}, build_code_store(store));
    w.codes = codes;
    REQUIRE(w.meta()->code_store_size > 0);
    REQUIRE(w.header()->collisions_size == 0);
    for (uint32_t i = 0; i < w.header()->n_keys; ++i) {
        const uint32_t off = w.slots()[i];
        if (off != 0) w.entries[off] = static_cast<uint32_t>(load_u64(w.data() + off));
    }
    REQUIRE(w.entries.size() == codes.size());
    return w;
}

/// The blob outside the account map, which sanitize() writes through (Account scratch).
std::vector<uint8_t> outside_account_map(Witness& w) {
    std::vector<uint8_t> out = w.blob;
    std::fill(out.begin() + w.meta()->prestate_offset, out.begin() + w.meta()->addr_hashes_offset, 0);
    return out;
}

/// After a sanitize() that sealed: the bytes outside the account map are as before except
/// [end, round4(end) + 36) after each payload but the last's, now zero, and every payload but the
/// last is analyzed in place. Without sealing, nothing changed and nothing is in place.
void check_after_sanitize(Witness& w, const std::vector<uint8_t>& before, bool sealed) {
    const auto offsets = w.offsets();
    std::vector<bool> zeroed(w.blob.size(), false);
    const auto data_at = static_cast<size_t>(w.data() - w.blob.data());
    if (sealed) {
        for (size_t i = 0; i + 1 < offsets.size(); ++i) {
            const uint32_t end = w.payload_end(offsets[i]);
            for (uint32_t b = end; b < round4(end) + 36; ++b) zeroed[data_at + b] = true;
        }
    }
    const auto now = outside_account_map(w);
    size_t changed_elsewhere = 0, nonzero_zeroed = 0;
    for (size_t b = 0; b < now.size(); ++b) {
        if (zeroed[b])
            nonzero_zeroed += now[b] != 0;
        else
            changed_elsewhere += now[b] != before[b];
    }
    CHECK(changed_elsewhere == 0);
    CHECK(nonzero_zeroed == 0);
    for (size_t i = 0; i < offsets.size(); ++i) {
        INFO("entry " << i << " of " << offsets.size());
        CHECK(analyzed_in_place(w.payload(offsets[i])) == (sealed && i + 1 < offsets.size()));
    }
}

constexpr bool kSeals = ZILK_SEAL_CODE_STORE != 0;

/// Fails the test if the pre-state is accepted; true if the constructor aborted after printing
/// `message`. The constructor aborts on a malformed layout, so it runs in a child process.
bool rejected_with(std::vector<uint8_t> blob, const std::string& message) {
    int fds[2];
    REQUIRE(pipe(fds) == 0);
    const pid_t pid = fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        { DirectState ds{std::span<uint8_t>{blob}}; }
        _exit(0);
    }
    close(fds[1]);
    std::string out;
    char buf[256];
    for (ssize_t n; (n = read(fds[0], buf, sizeof(buf))) > 0;) out.append(buf, static_cast<size_t>(n));
    close(fds[0]);
    int status = 0;
    REQUIRE(waitpid(pid, &status, 0) == pid);
    INFO(out);
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT && out.find(message) != std::string::npos;
}

}  // namespace

TEST_CASE("code store seal: dense layouts", "[state_zz][code_store_seal]") {
    std::vector<uint32_t> all_residues;
    for (uint32_t n = 1; n <= 17; ++n) all_residues.push_back(n);
    for (const auto& sizes : std::vector<std::vector<uint32_t>>{
             {1}, {24576}, {1, 1}, {33, 32}, {7, 300, 1}, all_residues, std::vector<uint32_t>(100, 9)}) {
        Section s{sizes};
        INFO("entries " << sizes.size());
        const code_store_seal::DenseLayout layout{s.data(), s.size};
        REQUIRE(layout.dense());
        CHECK(layout.last() == s.offsets.back());
        for (const auto off : s.offsets) {
            CHECK(layout.is_entry(off));
            CHECK_FALSE(layout.is_entry(off + 8));  // in the key
            CHECK_FALSE(layout.is_entry(off + 4));
            CHECK_FALSE(layout.is_entry(off + 1));
        }
        CHECK_FALSE(layout.is_entry(0));  // the sentinel
        CHECK_FALSE(layout.is_entry(s.size));
        CHECK_FALSE(layout.is_entry(uint64_t{1} << 35));
        check_zero_tails(s);
    }
}

TEST_CASE("code store seal: anything but a dense layout is left alone", "[state_zz][code_store_seal]") {
    SECTION("trailing bytes after the last entry") {
        Section s{{40, 50}, 8};
        CHECK_FALSE(dense(s));
        Section t{{40, 50}, 48};  // room for a header, but zero: len 0
        CHECK_FALSE(dense(t));
    }
    SECTION("a section cut inside its last entry") {
        Section s{{40, 50}};
        s.size -= 8;
        CHECK_FALSE(dense(s));
    }
    SECTION("a length whose high word is set") {
        Section s{{40, 50, 60}};
        s.data()[s.offsets[1] + 4] = 1;
        CHECK_FALSE(dense(s));
    }
    SECTION("a length below the key's 32 bytes") {
        Section s{{40, 50, 60}};
        store_u64(s.data() + s.offsets[1], 31);
        CHECK_FALSE(dense(s));
    }
    SECTION("a length past the section") {
        Section s{{40, 50, 60}};
        store_u64(s.data() + s.offsets[2], 32 + 72);
        CHECK_FALSE(dense(s));
        store_u64(s.data() + s.offsets[2], 0xffffffffu);
        CHECK_FALSE(dense(s));
    }
    SECTION("a length that skips an entry") {
        Section s{{40, 50, 60}};
        // Entry 0 then takes the 80 bytes of its own and the 96 of entry 1.
        store_u64(s.data() + s.offsets[0], 80 + 96 - 8);
        // Dense again, over fewer entries: the skipped one is no entry.
        const code_store_seal::DenseLayout layout{s.data(), s.size};
        REQUIRE(layout.dense());
        CHECK_FALSE(layout.is_entry(s.offsets[1]));
        CHECK(layout.is_entry(s.offsets[2]));
    }
    SECTION("a length that wraps the offset arithmetic") {
        // The largest section that rounds: a length of 2^32 - 15 would take the next offset, 8 + 8 +
        // len + 7, around to this very entry. Not read past the 80 bytes there are.
        Section s{{40}};
        store_u64(s.data() + s.offsets[0], 0xfffffff1u);
        CHECK_FALSE(code_store_seal::DenseLayout(s.data(), UINT32_MAX - 8).dense());
    }
    SECTION("sections of the sentinel or less, or too large to round") {
        Section s{{40}};
        CHECK_FALSE(code_store_seal::DenseLayout(s.data(), 8).dense());
        CHECK_FALSE(code_store_seal::DenseLayout(s.data(), 0).dense());
        CHECK_FALSE(code_store_seal::DenseLayout(s.data(), UINT32_MAX - 7).dense());
    }
}

TEST_CASE("code store seal: sanitize pads every payload but the last", "[state_zz][code_store_seal]") {
    reset_in_place_region();
    std::vector<std::vector<Bytes>> stores;
    {
        std::vector<Bytes> residues;
        for (size_t n = 1; n <= 17; ++n) residues.push_back(code_of(n, static_cast<uint8_t>(n)));
        stores.push_back(residues);
    }
    stores.push_back({code_of(1, 1), code_of(24576, 2), code_of(31, 3), code_of(32, 4), code_of(33, 5)});
    stores.push_back({code_of(200, 1), code_of(300, 2)});
    {
        std::vector<Bytes> many;
        for (size_t n = 0; n < 120; ++n) many.push_back(code_of(20 + n * 3, static_cast<uint8_t>(n)));
        stores.push_back(many);
    }
    for (const auto& codes : stores) {
        INFO("codes " << codes.size());
        Witness w = make_witness(codes);
        // The code store ends the blob. 64 zero bytes lie after it, outside the span the state is
        // given: were the last entry run in place, they would pad it, so that only the region's end
        // keeps it a copy.
        const size_t blob_size = w.blob.size();
        w.blob.resize(blob_size + 64, 0);
        const auto before = outside_account_map(w);
        {
            DirectState ds{std::span<uint8_t>{w.blob.data(), blob_size}, std::span<uint8_t>{w.nodestore}};
            REQUIRE(ds.sanitize());
            check_after_sanitize(w, before, kSeals);
            // Every payload is still the code it was hashed as.
            for (const auto off : w.offsets()) {
                const ByteView p = w.payload(off);
                CHECK(std::find(codes.begin(), codes.end(), Bytes{p.data(), p.size()}) != codes.end());
            }
            if (kSeals) CHECK_FALSE(ds.sanitize());  // once only
        }
        // The region goes with the DirectState.
        for (const auto off : w.offsets()) CHECK_FALSE(analyzed_in_place(w.payload(off)));
    }
}

TEST_CASE("code store seal: a single entry, or none, is not padded", "[state_zz][code_store_seal]") {
    Witness w = make_witness({code_of(100, 1)});
    const auto before = outside_account_map(w);
    DirectState ds{std::span<uint8_t>{w.blob}, std::span<uint8_t>{w.nodestore}};
    REQUIRE(ds.sanitize());
    check_after_sanitize(w, before, kSeals);

    std::vector<DirectState::AccountInfo> accounts{make_eoa(make_addr(0, 0x11), 1, intx::uint256{0})};
    std::vector<uint8_t> empty = DirectState::build_blob_from_accounts(accounts, {}, {});
    DirectState none{std::span<uint8_t>{empty}};
    CHECK(none.sanitize());
}

TEST_CASE("code store seal: forged layouts are not padded", "[state_zz][code_store_seal]") {
    reset_in_place_region();
    Witness w = make_witness({code_of(200, 1), code_of(300, 2), code_of(120, 3)});
    const auto offs = w.offsets();
    REQUIRE(offs.size() == 3);
    const uint32_t a = offs[0];
    const uint32_t a_end = w.payload_end(a);

    SECTION("no keys: the data section is not checked, and not walked") {
        // validate_mphf() returns before the data section when n_keys is 0, so its offset and size
        // could put it anywhere, over bytes no hash binds. Here it is a dense chain of entries.
        w.header()->n_keys = 0;
        const auto before = outside_account_map(w);
        DirectState ds{std::span<uint8_t>{w.blob}, std::span<uint8_t>{w.nodestore}};
        REQUIRE(ds.sanitize());
        CHECK(outside_account_map(w) == before);
        for (const auto off : offs) CHECK_FALSE(analyzed_in_place(w.payload(off)));
    }
    SECTION("the map refers to an entry inside another's payload") {
        // A whole entry in the first payload, at an 8-aligned offset, with its own hash.
        const uint32_t f = a + 48;
        const Bytes inner = code_of(20, 9);
        store_u64(w.data() + f, 32 + inner.size());
        const bytes32 h = keccak_bytes(ByteView{inner.data(), inner.size()});
        std::memcpy(w.data() + f + 8, h.bytes, 32);
        std::memcpy(w.data() + f + 40, inner.data(), inner.size());
        REQUIRE(f + 40 + inner.size() < a_end);
        w.repoint(a, f);
        const auto before = outside_account_map(w);
        DirectState ds{std::span<uint8_t>{w.blob}, std::span<uint8_t>{w.nodestore}};
        REQUIRE(ds.sanitize());
        CHECK(outside_account_map(w) == before);
        CHECK_FALSE(analyzed_in_place(ByteView{w.data() + f + 40, inner.size()}));
        for (const auto off : offs) CHECK_FALSE(analyzed_in_place(w.payload(off)));
    }
    SECTION("the map refers to an entry across another's tail") {
        // An entry from inside the first payload over its tail into the second payload: its
        // payload holds the bytes sealing would zero, and its hash binds them.
        const uint32_t f = (a_end - 48) & ~uint32_t{7};
        REQUIRE(f >= a + 40);
        const uint32_t plen = offs[1] + 40 + 16 - (f + 40);
        store_u64(w.data() + f, 32 + plen);
        const bytes32 h = keccak_bytes(ByteView{w.data() + f + 40, plen});
        std::memcpy(w.data() + f + 8, h.bytes, 32);
        REQUIRE(f + 40 < a_end);
        REQUIRE(f + 40 + plen > a_end + 36);
        w.repoint(a, f);
        const auto before = outside_account_map(w);
        DirectState ds{std::span<uint8_t>{w.blob}, std::span<uint8_t>{w.nodestore}};
        REQUIRE(ds.sanitize());
        CHECK(outside_account_map(w) == before);
        CHECK(keccak_bytes(ByteView{w.data() + f + 40, plen}) == h);
        for (const auto off : offs) CHECK_FALSE(analyzed_in_place(w.payload(off)));
    }
}

TEST_CASE("code store seal: a failed sanitize zeroes nothing", "[state_zz][code_store_seal]") {
    reset_in_place_region();
    Witness w = make_witness({code_of(200, 1), code_of(300, 2), code_of(120, 3)});
    const auto offs = w.offsets();
    SECTION("a payload that does not hash to its key") {
        w.data()[offs[1] + 40 + 7] ^= 1;
    }
    SECTION("an addr_hashes entry that is not the account's") {
        // Fails after the code hashing and the account walk, the last check before sealing.
        w.blob[w.meta()->addr_hashes_offset + 3] ^= 1;
    }
    const auto before = outside_account_map(w);
    DirectState ds{std::span<uint8_t>{w.blob}, std::span<uint8_t>{w.nodestore}};
    CHECK_FALSE(ds.sanitize());
    CHECK(outside_account_map(w) == before);
    for (const auto off : offs) CHECK_FALSE(analyzed_in_place(w.payload(off)));
}

TEST_CASE("code store seal: an account no addr_hashes entry names zeroes nothing",
          "[state_zz][code_store_seal]") {
    reset_in_place_region();
    // Accounts with code and without, and a third code so that a seal would have tails to zero.
    const Prestate ps = build_prestate({
        AcctSpec{.addr = make_addr(0x11, 1), .nonce = 1, .balance = 1000},
        AcctSpec{.addr = make_addr(0x12, 2), .nonce = 1, .balance = 0, .code = code_of(100, 1)},
        AcctSpec{.addr = make_addr(0x13, 3), .nonce = 1, .balance = 0, .code = code_of(150, 2)},
        AcctSpec{.addr = make_addr(0x14, 4), .nonce = 1, .balance = 0, .code = code_of(70, 3)},
    });
    Witness w;
    w.blob = ps.blob;
    w.nodestore = ps.nodestore;
    REQUIRE(w.meta()->n_accounts == 4);
    {
        // The honest pre-state seals.
        Witness h = w;
        DirectState ds{std::span<uint8_t>{h.blob}, std::span<uint8_t>{h.nodestore}};
        REQUIRE(ds.sanitize());
    }
    // One entry fewer in addr_hashes than the account map has records: the walk of addr_hashes
    // leaves a record unnamed, the last check of sanitize(), and nothing may have been zeroed.
    w.meta()->n_accounts -= 1;
    const auto before = w.blob;
    int status = -1;
    {
        const pid_t pid = fork();
        REQUIRE(pid >= 0);
        if (pid == 0) {
            const int null = open("/dev/null", O_WRONLY);
            if (null >= 0) dup2(null, STDOUT_FILENO);
            DirectState ds{std::span<uint8_t>{w.blob}, std::span<uint8_t>{w.nodestore}};
            const bool ok = ds.sanitize();
            // 20: refused; 21: refused, and the code store bytes are as they were.
            _exit(ok ? 22 : (std::equal(w.blob.begin() + w.meta()->code_store_offset, w.blob.end(),
                                        before.begin() + w.meta()->code_store_offset) ? 21 : 20));
        }
        REQUIRE(waitpid(pid, &status, 0) == pid);
    }
    INFO("child status " << status);
    // Refused at construction (abort) or by sanitize() with the blob untouched; never accepted.
    CHECK((WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) == 21)));
}

TEST_CASE("code store seal: one region, of the last sanitized state", "[state_zz][code_store_seal]") {
    reset_in_place_region();
    Witness w1 = make_witness({code_of(200, 1), code_of(300, 2)});
    Witness w2 = make_witness({code_of(210, 3), code_of(310, 4)});
    const auto o1 = w1.offsets();
    const auto o2 = w2.offsets();
    auto first = std::make_unique<DirectState>(std::span<uint8_t>{w1.blob}, std::span<uint8_t>{w1.nodestore});
    REQUIRE(first->sanitize());
    CHECK(analyzed_in_place(w1.payload(o1[0])) == kSeals);

    // A move keeps the seal; the moved-from state leaves the region alone.
    {
        DirectState moved{std::move(*first)};
        first.reset();
        CHECK(analyzed_in_place(w1.payload(o1[0])) == kSeals);
    }
    CHECK_FALSE(analyzed_in_place(w1.payload(o1[0])));

    // The next bundle's state replaces the region.
    DirectState second{std::span<uint8_t>{w2.blob}, std::span<uint8_t>{w2.nodestore}};
    REQUIRE(second.sanitize());
    CHECK(analyzed_in_place(w2.payload(o2[0])) == kSeals);
    CHECK_FALSE(analyzed_in_place(w1.payload(o1[0])));
}

TEST_CASE("code store seal: created code equal to witness code goes to created_code_",
          "[state_zz][code_store_seal]") {
    const Bytes c0 = code_of(200, 1), c1 = code_of(300, 2);
    Witness w = make_witness({c0, c1});
    DirectState ds{std::span<uint8_t>{w.blob}, std::span<uint8_t>{w.nodestore}};
    REQUIRE(ds.sanitize());
    for (const auto& c : {c0, c1}) {
        Account pa{};
        ds.apply_code_diff(make_addr(0x33, 0x01), pa, evmc::bytes{c.data(), c.size()});
        // Sealed, the index of the code store is dead: no lookup by hash.
        CHECK((pa.code_store_offset == kCreatedCodeOffset) == kSeals);
        CHECK(pa.code_store_len == c.size());
        const ByteView code = ds.read_code(pa);
        CHECK(Bytes{code.data(), code.size()} == c);
        CHECK(keccak_bytes(code) == keccak_bytes(ByteView{c.data(), c.size()}));
    }
}

TEST_CASE("code store seal: a code store overlapping another pre-state section is rejected",
          "[state_zz][code_store_seal]") {
    Witness w = make_witness({code_of(200, 1), code_of(300, 2)});
    const PreStateMeta m = *w.meta();
    REQUIRE(m.n_accounts > 0);
    REQUIRE(m.code_store_offset >= m.block_hashes_offset);
    const std::string kOverlap = "prestate sections overlap";
    {
        DirectState ds{std::span<uint8_t>{w.blob}};  // the honest layout passes
    }
    SECTION("addr_hashes inside the code store") {
        // The account map, which runs up to them, then takes in the block hashes and the head of
        // the code store too.
        std::vector<uint8_t> b = w.blob;
        auto* meta = reinterpret_cast<PreStateMeta*>(b.data());
        meta->addr_hashes_offset = m.code_store_offset + 8;
        CHECK(rejected_with(b, kOverlap));
    }
    SECTION("the code store inside the account map") {
        // addr_hashes moved behind the code store: the account map, which runs up to them, then
        // takes in the code store, whose bytes are written through as account data.
        std::vector<uint8_t> b = w.blob;
        const auto at = static_cast<uint32_t>(b.size());
        b.insert(b.end(), w.blob.begin() + m.addr_hashes_offset,
                 w.blob.begin() + m.addr_hashes_offset + m.n_accounts * sizeof(AddrHashEntry));
        b.resize(round8(static_cast<uint32_t>(b.size())));
        reinterpret_cast<PreStateMeta*>(b.data())->addr_hashes_offset = at;
        CHECK(rejected_with(b, kOverlap));
    }
    SECTION("block hashes inside the code store") {
        std::vector<uint8_t> b = w.blob;
        auto* meta = reinterpret_cast<PreStateMeta*>(b.data());
        meta->n_block_hashes = 1;
        meta->block_hashes_offset = m.code_store_offset + 16;
        CHECK(rejected_with(b, kOverlap));
    }
    SECTION("block hashes over the pre-state header") {
        std::vector<uint8_t> b = w.blob;
        auto* meta = reinterpret_cast<PreStateMeta*>(b.data());
        meta->n_block_hashes = 1;
        meta->block_hashes_offset = 8;
        CHECK(rejected_with(b, kOverlap));
    }
}

// ---------------------------------------------------------------------------
// A block that creates code equal to a witness code
// ---------------------------------------------------------------------------

namespace {

evmc::bytes32 word(uint64_t v) {
    evmc::bytes32 out{};
    intx::be::store(out.bytes, intx::uint256{v});
    return out;
}

void store_at(Bytes& code, uint8_t slot) {
    push1(code, slot);
    code.push_back(0x55);  // SSTORE
}

void push2(Bytes& code, uint16_t v) {
    code.push_back(0x61);
    code.push_back(static_cast<uint8_t>(v >> 8));
    code.push_back(static_cast<uint8_t>(v));
}

/// CALL `a` with no input -> storage[base] (success) and storage[base + 1] (the first returned
/// word); EXTCODEHASH, EXTCODESIZE and the first 32 code bytes of `a` -> storage[base + 2..4].
void probe(Bytes& k, const evmc::address& a, uint8_t base) {
    push1(k, 0x20);  // retSize
    push1(k, 0x00);  // retOffset
    push1(k, 0x00);  // argsSize
    push1(k, 0x00);  // argsOffset
    push1(k, 0x00);  // value
    push20(k, a);
    k.push_back(0x5a);  // GAS
    k.push_back(0xf1);  // CALL
    store_at(k, base);
    push1(k, 0x00);
    k.push_back(0x51);  // MLOAD
    store_at(k, base + 1);
    push20(k, a);
    k.push_back(0x3f);  // EXTCODEHASH
    store_at(k, base + 2);
    push20(k, a);
    k.push_back(0x3b);  // EXTCODESIZE
    store_at(k, base + 3);
    push1(k, 0x20);  // size
    push1(k, 0x00);  // code offset
    push1(k, 0x20);  // memory offset
    push20(k, a);
    k.push_back(0x3c);  // EXTCODECOPY
    push1(k, 0x20);
    k.push_back(0x51);  // MLOAD
    store_at(k, base + 4);
}

}  // namespace

TEST_CASE("code store seal: CREATE2 of a witness code, then run and read it in two transactions",
          "[state_zz][code_store_seal][exec]") {
    const evmc::address W = make_addr(0x44, 0x04);  // a witness contract
    const evmc::address D = make_addr(0x22, 0x02);  // CREATE2s W's code, then probes the copy
    const evmc::address E = make_addr(0x23, 0x03);  // probes the copy in the next transaction
    constexpr uint8_t kSalt = 0x2a;

    // W returns 0x2a. It ends in a PUSH2 cut off by the end of the code, which the copy
    // repeats: in place, the padding is the zeroed bytes after W's payload.
    Bytes w_code;
    push1(w_code, 0x2a);
    push1(w_code, 0x00);
    w_code.push_back(0x52);  // MSTORE
    push1(w_code, 0x20);
    push1(w_code, 0x00);
    w_code.push_back(0xf3);  // RETURN
    w_code.insert(w_code.end(), {0x5b, 0x61, 0x01});
    const auto w_len = static_cast<uint16_t>(w_code.size());

    // The initcode copies W's code and returns it.
    Bytes init;
    push2(init, w_len);
    push1(init, 0x00);
    push1(init, 0x00);
    push20(init, W);
    init.push_back(0x3c);  // EXTCODECOPY
    push2(init, w_len);
    push1(init, 0x00);
    init.push_back(0xf3);  // RETURN

    // D: CODECOPY the initcode from its own tail, CREATE2 it -> storage[0], probe the result.
    Bytes d_code;
    const auto init_len = static_cast<uint8_t>(init.size());
    const size_t init_at_pos = 4;  // the PUSH2 immediate holding the initcode's offset
    push1(d_code, init_len);
    push2(d_code, 0);
    push1(d_code, 0x00);
    d_code.push_back(0x39);  // CODECOPY
    push1(d_code, kSalt);
    push1(d_code, init_len);
    push1(d_code, 0x00);
    push1(d_code, 0x00);
    d_code.push_back(0xf5);  // CREATE2
    store_at(d_code, 0x00);
    Bytes salt_bytes(32, 0);
    salt_bytes[31] = kSalt;
    const evmc::address CA = [&] {
        Bytes buf{0xff};
        buf.insert(buf.end(), D.bytes, D.bytes + 20);
        buf.insert(buf.end(), salt_bytes.begin(), salt_bytes.end());
        const bytes32 ih = keccak_bytes(ByteView{init.data(), init.size()});
        buf.insert(buf.end(), ih.bytes, ih.bytes + 32);
        const bytes32 h = keccak_bytes(ByteView{buf.data(), buf.size()});
        evmc::address out{};
        std::memcpy(out.bytes, h.bytes + 12, 20);
        return out;
    }();
    probe(d_code, CA, 0x01);
    probe(d_code, W, 0x06);
    d_code.push_back(0x00);  // STOP
    const auto init_at = static_cast<uint16_t>(d_code.size());
    d_code[init_at_pos - 1] = static_cast<uint8_t>(init_at >> 8);
    d_code[init_at_pos] = static_cast<uint8_t>(init_at);
    d_code.insert(d_code.end(), init.begin(), init.end());

    Bytes e_code;
    probe(e_code, CA, 0x01);
    e_code.push_back(0x00);

    const silkworm::Transaction tx1 = make_legacy_txn(D, 1'000'000);
    const silkworm::Transaction tx2 = make_legacy_txn(E, 1'000'000);
    const evmc::address S1 = recover_sender(tx1);
    const evmc::address S2 = recover_sender(tx2);
    REQUIRE(S1 != evmc::address{});
    REQUIRE(S2 != evmc::address{});
    REQUIRE(S1 != S2);

    // A filler code, so that none of the codes above need be the last entry.
    const Prestate ps = build_prestate({
        AcctSpec{.addr = S1, .nonce = 0, .balance = intx::uint256{1} << 64},
        AcctSpec{.addr = S2, .nonce = 0, .balance = intx::uint256{1} << 64},
        AcctSpec{.addr = W, .nonce = 1, .balance = 0, .code = w_code},
        AcctSpec{.addr = D, .nonce = 1, .balance = 0, .code = d_code},
        AcctSpec{.addr = E, .nonce = 1, .balance = 0, .code = e_code},
        AcctSpec{.addr = make_addr(0x55, 0x05), .nonce = 1, .balance = 0, .code = code_of(64, 9)},
    });
    const std::array<silkworm::Transaction, 2> txs{tx1, tx2};
    const ChainSetup chain = make_chain(ps.prev_root, std::span<const silkworm::Transaction>{txs}, S1);
    const ShadowRun sr = shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header,
                                        std::span<const silkworm::Transaction>{txs});
    REQUIRE(sr.sanitize_ok);
    REQUIRE(sr.all_succeeded());
    CHECK(sr.post.missing == 0);

    // W's witness code ran in place, and the copy from created_code_.
    const ByteView w_witness = sr.ds->read_code(W);
    CHECK(analyzed_in_place(w_witness) == kSeals);
    const Account* created = sr.ds->find_created_account(CA);
    REQUIRE(created != nullptr);
    CHECK((created->code_store_offset == kCreatedCodeOffset) == kSeals);
    const ByteView copy = sr.ds->read_code(CA);
    CHECK(Bytes{copy.data(), copy.size()} == w_code);

    REQUIRE(w_code.size() <= 32);
    evmc::bytes32 first32{};
    std::memcpy(first32.bytes, w_code.data(), w_code.size());
    const auto expect_probe = [&](const evmc::address& at, uint8_t base) {
        CHECK(sr.storage(at, base) == word(1));
        CHECK(sr.storage(at, base + 1) == word(0x2a));
        CHECK(sr.storage(at, base + 2) == keccak_bytes(ByteView{w_code.data(), w_code.size()}));
        CHECK(sr.storage(at, base + 3) == word(w_code.size()));
        CHECK(sr.storage(at, base + 4) == first32);
    };
    evmc::bytes32 ca_word{};
    std::memcpy(ca_word.bytes + 12, CA.bytes, 20);
    CHECK(sr.storage(D, 0) == ca_word);
    expect_probe(D, 0x01);
    expect_probe(D, 0x06);
    expect_probe(E, 0x01);

    // The guest entry point accepts the block the shadow run derived, on its own copy.
    std::vector<uint8_t> env = make_envelope(chain, sr, ps.blob, ps.nodestore);
    REQUIRE_FALSE(env.empty());
    StateTransition st{std::span<uint8_t>{env}};
    std::string log;
    uint64_t gas = 0;
    {
        StdoutCapture cap;
        gas = st.run().gas_used;
        log = cap.str();
    }
    CHECK_FALSE(st.failed());
    CHECK(gas == sr.gas_used);
    CHECK(log.find("New Root: " + silkworm::to_hex(sr.post.root)) != std::string::npos);
    CHECK(log.find("ERROR") == std::string::npos);
}

// ---------------------------------------------------------------------------
// DenseLayout and zero_tails() against an independent walk
// ---------------------------------------------------------------------------

namespace {

/// The walk written out again, with 64-bit lengths and wide arithmetic.
struct RefWalk {
    bool dense{false};
    uint64_t last{0};
    std::vector<uint64_t> starts;
};

RefWalk ref_walk(const uint8_t* d, uint64_t size) {
    RefWalk r;
    if (size <= 8 || size > uint64_t{UINT32_MAX} - 8) return r;
    uint64_t off = 8;
    while (off < size) {
        if (size - off < 40) return r;
        const uint64_t len = load_u64(d + off);
        if (len < 32 || len > size - off - 8) return r;
        r.starts.push_back(off);
        off = (off + 8 + len + 7) / 8 * 8;
    }
    if (off != size) return r;
    r.dense = true;
    r.last = r.starts.back();
    return r;
}

/// A section as the reference would have it after zero_tails(): [end, round4(end) + 36) after the
/// payload of every entry but the last, to zero.
std::vector<uint8_t> ref_zero_tails(const std::vector<uint8_t>& in, const RefWalk& w) {
    std::vector<uint8_t> out = in;
    for (size_t i = 0; i + 1 < w.starts.size(); ++i) {
        const uint64_t end = w.starts[i] + 8 + load_u64(in.data() + w.starts[i]);
        const uint64_t stop = (end + 3) / 4 * 4 + 36;
        for (uint64_t b = end; b < stop; ++b) out[b] = 0;
    }
    return out;
}

}  // namespace

TEST_CASE("code store seal: DenseLayout and zero_tails against a reference walk",
          "[state_zz][code_store_seal][fuzz]") {
    std::mt19937_64 rng{0x5ea1};
    size_t n_dense = 0, n_not_dense = 0, n_mutated_dense = 0;
    for (int iter = 0; iter < 4000; ++iter) {
        std::vector<uint32_t> sizes;
        const size_t n = 1 + rng() % 6;
        for (size_t i = 0; i < n; ++i) sizes.push_back(static_cast<uint32_t>(rng() % 3 == 0 ? rng() % 8 : rng() % 90));
        Section s{sizes, rng() % 8 == 0 ? static_cast<uint32_t>(rng() % 24) : 0};
        // Mutations of the header words and the section size, in most iterations.
        const unsigned n_mut = iter % 4 == 0 ? 0 : 1 + rng() % 3;
        for (unsigned m = 0; m < n_mut; ++m) {
            switch (rng() % 7) {
            case 0:  // a length, near or far from the right one
                if (const auto off = s.offsets[rng() % s.offsets.size()]; true) {
                    const uint64_t len = load_u64(s.data() + off);
                    const uint64_t pick[] = {len + 1 + rng() % 9, len - 1 - rng() % 9, rng() % 200,
                                             rng(), len + 8 * (1 + rng() % 4), 31, 32};
                    store_u64(s.data() + off, pick[rng() % 7]);
                }
                break;
            case 1:  // a high word
                {
                    const auto off = s.offsets[rng() % s.offsets.size()];
                    const auto at = off + 4 + rng() % 4;
                    s.data()[at] = static_cast<uint8_t>(rng());
                }
                break;
            case 2:
                if (s.size > 0) s.size -= static_cast<uint32_t>(rng() % std::min<uint32_t>(s.size, 20));
                break;
            case 3:
                s.size += static_cast<uint32_t>(rng() % 17);
                break;
            case 4:  // the section size: nothing but the sentinel, or too large to round
                s.size = std::array<uint32_t, 5>{0, 8, 9, UINT32_MAX - 7, UINT32_MAX}[rng() % 5];
                break;
            case 5:  // a byte anywhere
                {
                    const auto at = rng() % (s.words.size() * 8);
                    s.data()[at] ^= static_cast<uint8_t>(1u << (rng() % 8));
                }
                break;
            default:  // a length skipping one entry
                if (s.offsets.size() > 1) {
                    const size_t i = rng() % (s.offsets.size() - 1);
                    store_u64(s.data() + s.offsets[i],
                              load_u64(s.data() + s.offsets[i]) + round8(40 + sizes[i + 1]));
                }
                break;
            }
        }
        const bool huge = s.size > s.words.size() * 8;
        const uint32_t size = s.size;
        if (huge) {
            // A size beyond the buffer is walked by no one: only the rounding limit is exercised.
            if (size > UINT32_MAX - 8) CHECK_FALSE(code_store_seal::DenseLayout(s.data(), size).dense());
            continue;
        }
        const std::vector<uint8_t> before(s.data(), s.data() + s.words.size() * 8);
        const RefWalk ref = ref_walk(before.data(), size);
        const code_store_seal::DenseLayout layout{s.data(), size};
        INFO("iter " << iter << " size " << size);
        REQUIRE(layout.dense() == ref.dense);
        (ref.dense ? n_dense : n_not_dense)++;
        if (ref.dense && n_mut > 0) n_mutated_dense++;
        if (!ref.dense) continue;
        CHECK(layout.last() == ref.last);
        std::vector<bool> is_start(size + 64, false);
        for (const auto off : ref.starts) is_start[off] = true;
        for (uint64_t off = 0; off < size + 64; ++off) CHECK(layout.is_entry(off) == is_start[off]);
        CHECK_FALSE(layout.is_entry(rng()));
        code_store_seal::zero_tails(s.data(), layout.last());
        const auto want = ref_zero_tails(before, ref);
        CHECK(std::equal(want.begin(), want.end(), s.data()));
    }
    // The comparison is not vacuous: both kinds, and mutated sections that still tile.
    CHECK(n_dense > 500);
    CHECK(n_not_dense > 500);
    CHECK(n_mutated_dense > 20);
}

// ---------------------------------------------------------------------------
// Blocks of random contracts: in place and copied
// ---------------------------------------------------------------------------

namespace {

Bytes random_contract_body(std::mt19937_64& rng, size_t size) {
    static constexpr uint8_t kPlain[] = {0x01, 0x02, 0x03, 0x10, 0x11, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1b, 0x1c, 0x35, 0x38, 0x50, 0x58, 0x5a, 0x80, 0x81, 0x82, 0x90, 0x91, 0x5f, 0x30,
        0x32, 0x33, 0x34, 0x36};
    Bytes code;
    auto u = [&](uint64_t n) { return static_cast<size_t>(rng() % n); };
    while (code.size() < size) {
        switch (u(12)) {
        case 0:
        case 1: {
            const auto n = u(32) + 1;
            code.push_back(static_cast<uint8_t>(0x60 + n - 1));
            for (size_t i = 0; i < n; ++i) code.push_back(u(4) == 0 ? uint8_t{0x5b} : static_cast<uint8_t>(rng()));
            break;
        }
        case 2:
            code.push_back(0x5b);
            break;
        case 3: {
            const auto dst = u(size + 40);
            code.insert(code.end(), {0x61, static_cast<uint8_t>(dst >> 8), static_cast<uint8_t>(dst)});
            code.push_back(u(2) == 0 ? 0x56 : 0x57);
            break;
        }
        case 4:
            code.insert(code.end(), {0x60, static_cast<uint8_t>(u(64)), u(2) == 0 ? uint8_t{0x52} : uint8_t{0x51}});
            break;
        case 5:
            code.insert(code.end(), {0x60, static_cast<uint8_t>(u(8)), u(2) == 0 ? uint8_t{0x55} : uint8_t{0x54}});
            break;
        case 6:
            code.insert(code.end(), {0x60, 32, 0x60, 0, 0xa1});  // LOG1 of 32 bytes
            break;
        case 7:
            code.insert(code.end(), {0x60, 64, 0x60, 0, 0x60, 0, 0x39});  // CODECOPY
            break;
        case 8:
            code.push_back(u(6) == 0 ? (u(2) == 0 ? uint8_t{0xf3} : uint8_t{0xfd}) : uint8_t{0x00});
            break;
        default:
            code.push_back(kPlain[u(sizeof(kPlain))]);
            break;
        }
    }
    code.resize(size);  // often inside a PUSH, with no STOP
    return code;
}

/// Calls `a` with a fixed gas, then reads its size, hash and first 32 code bytes: storage[base..+4].
void probe_with_gas(Bytes& k, const evmc::address& a, uint8_t base) {
    push1(k, 0x20);
    push1(k, 0x00);
    push1(k, 0x00);
    push1(k, 0x00);
    push1(k, 0x00);
    push20(k, a);
    push2(k, 40000);
    k.push_back(0xf1);  // CALL
    store_at(k, base);
    push20(k, a);
    k.push_back(0x3f);  // EXTCODEHASH
    store_at(k, base + 1);
    push20(k, a);
    k.push_back(0x3b);  // EXTCODESIZE
    store_at(k, base + 2);
    push1(k, 0x20);
    push1(k, 0x00);
    push1(k, 0x20);
    push20(k, a);
    k.push_back(0x3c);  // EXTCODECOPY
    push1(k, 0x20);
    k.push_back(0x51);
    store_at(k, base + 3);
}

struct BlockRun {
    uint64_t gas_used;
    evmc::bytes32 receipts_root;
    silkworm::Bloom bloom;
    evmc::bytes32 root;
    unsigned missing;
    std::vector<bool> success;
    std::vector<uint64_t> cumulative;
    std::vector<size_t> n_logs;
    std::vector<evmc::bytes32> storage;
    size_t in_place;
};

}  // namespace

TEST_CASE("code store seal: blocks of random contracts, run in place and with every code copied",
          "[state_zz][code_store_seal][fuzz][exec]") {
    size_t blocks_in_place = 0, succeeded = 0, failed = 0, logs = 0;
    for (uint64_t seed = 1; seed <= 24; ++seed) {
        std::mt19937_64 rng{seed * 7919};
        const size_t n = 3 + rng() % 8;
        std::vector<evmc::address> addrs;
        for (size_t i = 0; i < n; ++i) addrs.push_back(make_addr(static_cast<uint8_t>(0x70 + i), static_cast<uint8_t>(seed)));
        std::vector<AcctSpec> specs;
        std::vector<Bytes> codes;
        for (size_t i = 0; i < n; ++i) {
            Bytes code;
            // Probes of two other contracts (their code is read, and run by the CALL), then a body.
            probe_with_gas(code, addrs[(i + 1) % n], 0x10);
            probe_with_gas(code, addrs[(i + 2) % n], 0x20);
            const size_t body = (seed % 4 == 0 && i == 1) ? 24576 - code.size()
                                : rng() % 5 == 0           ? 1 + rng() % 12
                                                           : 1 + rng() % 400;
            const Bytes b = random_contract_body(rng, body);
            code.insert(code.end(), b.begin(), b.end());
            codes.push_back(code);
        }
        std::vector<silkworm::Transaction> txs;
        std::vector<evmc::address> senders;
        for (size_t i = 0; i < n; ++i) {
            txs.push_back(make_legacy_txn(addrs[i], 1'000'000));
            senders.push_back(recover_sender(txs.back()));
            REQUIRE(senders.back() != evmc::address{});
        }
        for (size_t i = 0; i < n; ++i) {
            specs.push_back(AcctSpec{.addr = senders[i], .nonce = 0, .balance = intx::uint256{1} << 64});
            specs.push_back(AcctSpec{.addr = addrs[i], .nonce = 1, .balance = 0, .code = codes[i]});
        }
        const Prestate ps = build_prestate(specs);
        const ChainSetup chain = make_chain(ps.prev_root, std::span<const silkworm::Transaction>{txs}, senders[0]);

        const auto run = [&](bool keep) {
            ShadowRun sr = shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header,
                                          std::span<const silkworm::Transaction>{txs},
                                          silkworm::test::kShanghaiConfig, keep);
            REQUIRE(sr.sanitize_ok);
            BlockRun r{sr.gas_used, sr.receipts_root, sr.logs_bloom, sr.post.root, sr.post.missing, {}, {}, {}, {}, 0};
            for (const auto& rc : sr.receipts) {
                r.success.push_back(rc.success);
                r.cumulative.push_back(rc.cumulative_gas_used);
                r.n_logs.push_back(rc.logs.size());
            }
            for (const auto& a : addrs) {
                for (uint64_t slot = 0; slot < 0x30; ++slot) r.storage.push_back(sr.storage(a, slot));
                const ByteView code = sr.ds->read_code(a);
                r.in_place += analyzed_in_place(code);
            }
            return r;
        };
        const BlockRun in_place = run(true);
        const BlockRun copied = run(false);
        INFO("seed " << seed << " contracts " << n);
        CHECK(in_place.gas_used == copied.gas_used);
        CHECK(in_place.receipts_root == copied.receipts_root);
        CHECK(in_place.bloom == copied.bloom);
        CHECK(in_place.root == copied.root);
        CHECK(in_place.missing == copied.missing);
        CHECK(in_place.success == copied.success);
        CHECK(in_place.cumulative == copied.cumulative);
        CHECK(in_place.n_logs == copied.n_logs);
        CHECK(in_place.storage == copied.storage);
        CHECK(copied.in_place == 0);
        // Every code but the last entry's lies in place; the unit of the test is that they ran so.
        CHECK(in_place.in_place == (kSeals ? n - 1 : 0));
        if (in_place.in_place > 0) ++blocks_in_place;
        for (const bool ok : in_place.success) (ok ? succeeded : failed)++;
        for (const auto l : in_place.n_logs) logs += l;
    }
    // Neither all reverting nor all succeeding.
    CHECK(succeeded > 10);
    CHECK(failed > 10);
    CHECK(logs > 0);
    CHECK(blocks_in_place == (kSeals ? 24u : 0u));
}

// ---------------------------------------------------------------------------
// Forged witnesses: random and crafted mutations, each in a child process
// ---------------------------------------------------------------------------

namespace {

constexpr int kFuzzFailed = 11;      // sanitize() returned false
constexpr int kFuzzAcceptedCopy = 10;  // accepted, no code in place
constexpr int kFuzzInPlace = 13;     // accepted, some code in place
constexpr int kFuzzViolation = 12;   // accepted, and a contract's code is not its own
constexpr int kFuzzException = 14;

/// What the child checks of an accepted pre-state: every contract's code, as the VM would read it,
/// is byte for byte its genuine code (whose hash binds the account) or none, and when it runs in
/// place, its JUMPDESTs are those of the copy.
int fuzz_child(std::vector<uint8_t>& blob, std::vector<uint8_t>& nodestore,
               const std::vector<std::pair<evmc::address, Bytes>>& expect) {
    try {
        DirectState ds{std::span<uint8_t>{blob}, std::span<uint8_t>{nodestore}};
        if (!ds.sanitize()) return kFuzzFailed;
        bool any_in_place = false;
        for (const auto& [addr, code] : expect) {
            const ByteView got = ds.read_code(addr);
            // An account the forged map no longer finds reads as empty: a failure of the account
            // map, which the state root check shows, and not of the code store.
            if (got.empty()) continue;
            if (got.size() != code.size() || std::memcmp(got.data(), code.data(), code.size()) != 0) {
                std::fprintf(stderr, "forged witness: contract %02x.. reads %zu bytes, not its %zu\n",
                             addr.bytes[0], got.size(), code.size());
                return kFuzzViolation;
            }
            if (!analyzed_in_place(got)) continue;
            any_in_place = true;
            const auto in_place = evmone::baseline::analyze({got.data(), got.size()});
            const auto copied = evmone::baseline::analyze({code.data(), code.size()});
            for (size_t pos = code.size() + 40; pos-- > 0;)
                if (in_place.check_jumpdest(pos) != copied.check_jumpdest(pos)) return kFuzzViolation;
        }
        return any_in_place ? kFuzzInPlace : kFuzzAcceptedCopy;
    } catch (...) {
        return kFuzzException;
    }
}

/// A child's exit status, or 128 + the signal that ended it.
int run_in_child(std::vector<uint8_t> blob, std::vector<uint8_t> nodestore,
                 const std::vector<std::pair<evmc::address, Bytes>>& expect) {
    const pid_t pid = fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        const int null = open("/dev/null", O_WRONLY);
        if (null >= 0) dup2(null, STDOUT_FILENO);
        _exit(fuzz_child(blob, nodestore, expect));
    }
    int status = 0;
    REQUIRE(waitpid(pid, &status, 0) == pid);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return WEXITSTATUS(status);
}

}  // namespace

TEST_CASE("code store seal: forged witnesses never change what runs", "[state_zz][code_store_seal][fuzz]") {
    std::vector<AcctSpec> specs{AcctSpec{.addr = make_addr(0x11, 1), .nonce = 1, .balance = 1000}};
    std::vector<std::pair<evmc::address, Bytes>> expect;
    const size_t sizes[] = {70, 131, 200, 33, 300, 56, 410, 95};
    for (size_t i = 0; i < std::size(sizes); ++i) {
        Bytes c = code_of(sizes[i], static_cast<uint8_t>(3 + i));
        const auto a = make_addr(static_cast<uint8_t>(0x20 + i), 2);
        specs.push_back(AcctSpec{.addr = a, .nonce = 1, .balance = 0, .code = c});
        expect.emplace_back(a, c);
    }
    const Prestate ps = build_prestate(specs);
    Witness base;
    base.blob = ps.blob;
    base.nodestore = ps.nodestore;
    for (uint32_t i = 0; i < base.header()->n_keys; ++i)
        if (const uint32_t off = base.slots()[i]; off != 0)
            base.entries[off] = static_cast<uint32_t>(load_u64(base.data() + off));
    REQUIRE(base.entries.size() == expect.size());
    REQUIRE(run_in_child(base.blob, base.nodestore, expect) == (kSeals ? kFuzzInPlace : kFuzzAcceptedCopy));

    const char* env_iters = std::getenv("ZILK_SEAL_FUZZ_ITERS");
    const int iters = env_iters != nullptr ? std::atoi(env_iters) : 1500;
    std::map<int, int> verdicts;
    for (int iter = 0; iter < iters; ++iter) {
        std::mt19937_64 rng{0xf0123 + static_cast<uint64_t>(iter)};
        Witness w = base;
        const auto offs = w.offsets();
        const uint32_t dsize = w.data_size();
        auto pick_off = [&] { return offs[rng() % offs.size()]; };
        std::string what;
        const unsigned n_ops = 1 + rng() % 3;
        for (unsigned op = 0; op < n_ops; ++op) {
            switch (rng() % 9) {
            case 0:  // a byte of the data section
                {
                    const auto at = rng() % dsize;
                    w.data()[at] ^= static_cast<uint8_t>(1u << (rng() % 8));
                }
                what += "byte;";
                break;
            case 1: {  // a length
                const uint32_t off = pick_off();
                const uint64_t len = load_u64(w.data() + off);
                const uint64_t v[] = {len + 1 + rng() % 40, len - 1 - rng() % 40, rng() % 600, 31, 32};
                store_u64(w.data() + off, v[rng() % 5]);
                what += "len;";
                break;
            }
            case 2:  // a slot of the map
            case 3: {
                const uint32_t i = static_cast<uint32_t>(rng() % base.header()->n_keys);
                const uint32_t off = pick_off();
                const uint32_t v[] = {off, off + 4, off + 8, off - 8, off + 40, off + 1,
                                      static_cast<uint32_t>(8 * (rng() % (dsize / 8))), 0, dsize - 8};
                w.slots()[i] = v[rng() % 9];
                what += "slot;";
                break;
            }
            case 4:
            case 5:
            case 6: {  // a genuine code copied to a place of the data section, the map pointed to it
                const uint32_t e = pick_off();
                const uint32_t clen = w.entries.at(e) - 32;
                Bytes c(w.data() + e + 40, w.data() + e + 40 + clen);
                const bytes32 h = keccak_bytes(ByteView{c.data(), c.size()});
                const uint32_t need = round8(40 + clen);
                if (dsize < 8 + need) break;
                uint32_t p;
                if (rng() % 3 == 0) {
                    p = 8 * static_cast<uint32_t>(rng() % ((dsize - need) / 8 + 1));
                } else {
                    // Around the old entry, or the tail of another one.
                    const auto lo = static_cast<int64_t>(e) - 8 * static_cast<int64_t>(rng() % 12);
                    p = static_cast<uint32_t>(std::clamp<int64_t>(lo + 8 * static_cast<int64_t>(rng() % 20), 8, dsize - need));
                    p &= ~7u;
                }
                if (p < 8) p = 8;
                // c was read before the copy overwrote anything.
                store_u64(w.data() + p, 32 + clen);
                std::memcpy(w.data() + p + 8, h.bytes, 32);
                std::memcpy(w.data() + p + 40, c.data(), clen);
                w.repoint(e, p);
                what += "craft;";
                break;
            }
            case 7: {  // a byte of the account records, or of addr_hashes
                const uint32_t lo = w.meta()->prestate_offset;
                const uint32_t hi = w.meta()->addr_hashes_offset + w.meta()->n_accounts * sizeof(AddrHashEntry);
                const auto at = lo + rng() % (hi - lo);
                const auto bit = static_cast<uint8_t>(1u << (rng() % 8));
                w.blob[at] ^= bit;
                what += "account;";
                break;
            }
            default: {  // the header of the code store
                switch (rng() % 4) {
                case 0: w.header()->n_keys = 0; break;
                case 1: w.header()->data_size = dsize + 8 * (1 + rng() % 4); break;
                case 2: w.header()->data_size = dsize - 8 * (1 + rng() % 4); break;
                default: w.header()->data_size = dsize - 1 - static_cast<uint32_t>(rng() % 7); break;
                }
                what += "header;";
                break;
            }
            }
        }
        const int v = run_in_child(w.blob, w.nodestore, expect);
        INFO("iter " << iter << " ops " << what);
        // A refusal to construct aborts (SIGABRT); anything else but a verdict is a crash.
        REQUIRE(v != kFuzzViolation);
        REQUIRE(v != kFuzzException);
        REQUIRE((v == 128 + SIGABRT || v == kFuzzFailed || v == kFuzzAcceptedCopy || v == kFuzzInPlace));
        ++verdicts[v];
    }
    // Not vacuous: forgeries are refused, some mutations leave an accepted pre-state, and some of
    // those still seal.
    WARN("verdicts: aborted " << verdicts[128 + SIGABRT] << ", failed " << verdicts[kFuzzFailed]
         << ", accepted " << verdicts[kFuzzAcceptedCopy] << ", accepted in place " << verdicts[kFuzzInPlace]);
    if (iters >= 1000) {
        CHECK(verdicts[kFuzzFailed] + verdicts[128 + SIGABRT] > 100);
        CHECK(verdicts[kFuzzAcceptedCopy] + verdicts[kFuzzInPlace] > 20);
        CHECK(verdicts[kSeals ? kFuzzInPlace : kFuzzAcceptedCopy] > 5);
    }
}
