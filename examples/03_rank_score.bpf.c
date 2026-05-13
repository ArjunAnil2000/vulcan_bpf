// Example 03 — Rank / score using vulcan_get_* accessors
//
// Shows how to compose multiple listener outputs into a single score used
// to rank objects for eviction (lower = evict first; S64_MAX = protect).
//
// Assumed context: a cache-eviction BPF program that has already set up the
// feature store as in example 02.  This file focuses only on the scoring
// function itself, illustrating the accessor API.
//
// Score design:
//   Base     = per-folio access count (LFU baseline)
//   Penalty  = subtract if global network is busy (protect cache during I/O)
//   Bonus    = protect if the folio's own interval EWMA is short (hot folio)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "vulcan_bpf.h"

// Feature IDs — must match the enum in whichever .bpf.c includes vulcan_feature.h
// (reproduced here only for readability; in practice, share via a common header)
enum {
    GF_BYTES_RECEIVED = 0,
    GF_SEGS_IN        = 1,
    GF_RETRANS_OUT    = 2,
    _GF_COUNT,
};

// Threshold constants — tune for your workload
#define BUSY_BYTES_THRESHOLD   2000000LL   // >2 MB/s average → network busy
#define RETRANS_PENALTY_THRESH 5           // >5 retransmits in window → congested
#define HOT_INTERVAL_NS        5000000LL   // EWMA interval < 5 ms → hot folio

// --------------------------------------------------------------------------
// Helpers: classify current network state from the feature store
// --------------------------------------------------------------------------

static __always_inline bool net_is_busy(void)
{
    return vulcan_get_avg(GF_BYTES_RECEIVED) > BUSY_BYTES_THRESHOLD;
}

static __always_inline bool net_is_congested(void)
{
    // Use the rolling-window average of retransmits-in-flight
    return vulcan_get_window_avg(GF_RETRANS_OUT) > RETRANS_PENALTY_THRESH;
}

// --------------------------------------------------------------------------
// Per-folio state (would normally be in a shared header)
// --------------------------------------------------------------------------

struct my_folio_meta {
    u32 access_count;
    struct vulcan_ewma interval_ewma;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  u64);
    __type(value, struct my_folio_meta);
    __uint(max_entries, 500000);
} folio_meta_map SEC(".maps");

// --------------------------------------------------------------------------
// Scoring function
// --------------------------------------------------------------------------

static s64 bpf_score_fn(struct cache_ext_list_node *node)
{
    struct folio *folio = node->folio;
    if (!folio)
        return S64_MAX;

    // Guard: skip dirty / stale folios
    if (folio_test_dirty(folio) || folio_test_writeback(folio))
        return S64_MAX;
    if (!folio_test_uptodate(folio) || !folio_test_lru(folio))
        return S64_MAX;

    u64 key = (u64)folio;
    struct my_folio_meta *m = bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!m)
        return S64_MAX;

    // --- Base score: LFU (lower count = evict first) -----------------------
    s64 score = (s64)m->access_count;

    // --- Network penalty: if network is busy, protect cached data ----------
    // Rationale: evicting under I/O load causes expensive re-faults.
    if (net_is_busy())
        score += 50000;

    if (net_is_congested())
        score += 20000;   // extra protection during retransmit storms

    // --- Per-folio hotness bonus: short inter-access interval = hot --------
    // vulcan_ewma_get returns 0 if uninitialized (safe default)
    s64 interval_ewma = vulcan_ewma_get(&m->interval_ewma);
    if (interval_ewma > 0 && interval_ewma < HOT_INTERVAL_NS)
        score += 30000;   // protect frequently re-accessed folios

    return score;
}
