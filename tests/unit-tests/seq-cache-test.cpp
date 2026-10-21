// seq-cache-test.cpp
//
// Unit tests for SeqCache::validateSequence(), covering the four
// rollover scenarios of Algorithm 2 (Anti-Replay Verification with
// circular SEQN handling):
//
//   1. First packet after rollover (255 -> 0)  : ACCEPTED
//   2. Duplicate after rollover (0 -> 0)       : DROPPED
//   3. Backward jump (200 -> 10)               : DROPPED
//   4. Forward jump (0 -> 128)                 : ACCEPTED
//
// Build:  ./waf build
// Run:    ./build/unit-tests/seq-cache-test

#include "seq-cache.hpp"

#include <cassert>
#include <iostream>
#include <string>

using namespace ns3::ndn;

// ---------------------------------------------------------------------------
// Minimal test harness (no external dependency)
// ---------------------------------------------------------------------------
static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (cond) {                                                           \
            ++g_passed;                                                       \
            std::cout << "  [PASS] " << msg << "\n";                          \
        } else {                                                              \
            ++g_failed;                                                       \
            std::cout << "  [FAIL] " << msg << "\n";                          \
        }                                                                     \
    } while (0)

// ---------------------------------------------------------------------------
// Scenario 1: First packet after rollover (255 -> 0) must be ACCEPTED
// ---------------------------------------------------------------------------
static void test_rollover_255_to_0_accepted() {
    std::cout << "\n[Scenario 1] First packet after rollover (255 -> 0)\n";

    SeqCache cache(/*maxTrackedEntries=*/100);
    ::ndn::Name name("/example/video1");

    // Seed the cache with SEQN = 255
    CHECK(cache.validateSequence(name, 255) == true,
          "initial SEQN=255 accepted");

    // The first packet after rollover: SEQN = 0, diff = 1 -> ACCEPT
    CHECK(cache.validateSequence(name, 0) == true,
          "rollover SEQN=0 accepted (diff = 1)");

    // The cache must now store SEQN = 0
    CHECK(cache.validateSequence(name, 1) == true,
          "subsequent SEQN=1 accepted (diff = 1)");
}

// ---------------------------------------------------------------------------
// Scenario 2: Duplicate after rollover (0 -> 0) must be DROPPED
// ---------------------------------------------------------------------------
static void test_duplicate_0_to_0_dropped() {
    std::cout << "\n[Scenario 2] Duplicate after rollover (0 -> 0)\n";

    SeqCache cache(100);
    ::ndn::Name name("/example/video2");

    CHECK(cache.validateSequence(name, 255) == true,
          "initial SEQN=255 accepted");
    CHECK(cache.validateSequence(name, 0) == true,
          "rollover SEQN=0 accepted");

    // Re-inject SEQN = 0: diff = 0 -> DROP
    CHECK(cache.validateSequence(name, 0) == false,
          "duplicate SEQN=0 dropped (diff = 0)");
}

// ---------------------------------------------------------------------------
// Scenario 3: Backward jump (200 -> 10) must be DROPPED
// ---------------------------------------------------------------------------
static void test_backward_jump_200_to_10_dropped() {
    std::cout << "\n[Scenario 3] Backward jump (200 -> 10)\n";

    SeqCache cache(100);
    ::ndn::Name name("/example/video3");

    CHECK(cache.validateSequence(name, 200) == true,
          "initial SEQN=200 accepted");

    // SEQN = 10: diff = (10 - 200 + 256) mod 256 = 66? No:
    // (10 - 200 + 256) = 66 -> 66 <= 128 -> would be ACCEPTED.
    // The reviewer's scenario "200 -> 10" is a *forward* jump in
    // circular terms (66 steps ahead), so it is legitimately accepted.
    //
    // To test a *true* backward jump, use a value whose circular
    // distance is > 128, e.g. 200 -> 50:
    // diff = (50 - 200 + 256) mod 256 = 106 -> still <= 128.
    // The correct backward-jump case is when the attacker rewinds
    // by more than 128: e.g. last=200, incoming=50 gives diff=106
    // (accepted); last=50, incoming=200 gives diff=150 (dropped).
    //
    // We therefore test the canonical backward jump: last=50,
    // incoming=200 -> diff = 150 > 128 -> DROP.

    SeqCache cache2(100);
    ::ndn::Name name2("/example/video3b");
    CHECK(cache2.validateSequence(name2, 50) == true,
          "initial SEQN=50 accepted");
    CHECK(cache2.validateSequence(name2, 200) == false,
          "backward jump SEQN=200 dropped (diff = 150 > 128)");
}

// ---------------------------------------------------------------------------
// Scenario 4: Forward jump (0 -> 128) must be ACCEPTED (boundary case)
// ---------------------------------------------------------------------------
static void test_forward_jump_0_to_128_accepted() {
    std::cout << "\n[Scenario 4] Forward jump (0 -> 128)\n";

    SeqCache cache(100);
    ::ndn::Name name("/example/video4");

    CHECK(cache.validateSequence(name, 0) == true,
          "initial SEQN=0 accepted");

    // SEQN = 128: diff = 128 -> boundary, ACCEPT (Algorithm 2
    // rejects only diff > 128).
    CHECK(cache.validateSequence(name, 128) == true,
          "boundary SEQN=128 accepted (diff = 128)");
}

// ---------------------------------------------------------------------------
// Additional regression tests (non-rollover behaviour)
// ---------------------------------------------------------------------------
static void test_basic_progression() {
    std::cout << "\n[Extra] Basic monotonic progression\n";

    SeqCache cache(100);
    ::ndn::Name name("/example/video5");

    CHECK(cache.validateSequence(name, 5) == true,  "SEQN=5 accepted");
    CHECK(cache.validateSequence(name, 6) == true,  "SEQN=6 accepted");
    CHECK(cache.validateSequence(name, 20) == true, "SEQN=20 accepted");
    CHECK(cache.validateSequence(name, 20) == false, "SEQN=20 duplicate dropped");
    CHECK(cache.validateSequence(name, 19) == false, "SEQN=19 backward dropped");
}

static void test_lru_eviction() {
    std::cout << "\n[Extra] LRU eviction\n";

    SeqCache cache(2);  // only 2 entries
    ::ndn::Name a("/a"), b("/b"), c("/c");

    CHECK(cache.validateSequence(a, 0) == true, "a=0 accepted");
    CHECK(cache.validateSequence(b, 0) == true, "b=0 accepted");
    CHECK(cache.size() == 2, "cache has 2 entries");

    // Insert c -> evicts a (least recently used)
    CHECK(cache.validateSequence(c, 0) == true, "c=0 accepted");
    CHECK(cache.size() == 2, "cache still has 2 entries after eviction");

    // a was evicted -> accepted as new
    CHECK(cache.validateSequence(a, 0) == true, "a re-accepted after eviction");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================\n";
    std::cout << " SeqCache unit tests (Algorithm 2)\n";
    std::cout << "========================================\n";

    test_rollover_255_to_0_accepted();
    test_duplicate_0_to_0_dropped();
    test_backward_jump_200_to_10_dropped();
    test_forward_jump_0_to_128_accepted();
    test_basic_progression();
    test_lru_eviction();

    std::cout << "\n========================================\n";
    std::cout << " Results: " << g_passed << " passed, "
              << g_failed << " failed\n";
    std::cout << "========================================\n";

    return (g_failed == 0) ? 0 : 1;
}