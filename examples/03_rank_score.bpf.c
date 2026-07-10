// Example 03 — Rank / score using vulcan_folio_metadata
//
// Composes all available per-folio features into a single eviction score.
// Lower score = evict first.  S64_MAX = protect (skip this folio).
//
// Depends on folio_meta_map populated by example 02.
//
// Score design:
//   Base      = access_count (LFU)
//   Hotness   = protect if interval_ewma is short (frequently re-accessed)
//   Size      = penalize large folios (more expensive to re-fault)
//   Churn     = protect if eviction_count is high (keep churning folios)
//   Sharing   = protect if mapcount is high (many processes use this folio)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "vulcan_bpf.h"

#define HOT_INTERVAL_NS   5000000LL   // EWMA interval < 5 ms → hot folio
#define LARGE_FOLIO_PAGES 4           // folios >= 4 pages → penalize

// --------------------------------------------------------------------------
// Per-folio metadata map  (populated by example 02)
// --------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  u64);
    __type(value, struct vulcan_folio_metadata);
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

    // Guard: skip folios that are not safe to evict right now
    if (folio_test_dirty(folio) || folio_test_writeback(folio))
        return S64_MAX;
    if (!folio_test_uptodate(folio) || !folio_test_lru(folio))
        return S64_MAX;

    u64 key = (u64)folio;
    struct vulcan_folio_metadata *m = bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!m)
        return S64_MAX;

    // --- Base: LFU (lower access count = colder = evict first) -------------
    s64 score = (s64)m->access_count;

    // --- Hotness: short inter-access interval = frequently used = protect --
    s64 ewma = vulcan_ewma_get(&m->interval_ewma);
    if (ewma > 0 && ewma < HOT_INTERVAL_NS)
        score += 30000;

    // --- Size: larger folios are more expensive to re-fault ----------------
    if (m->size_pages >= LARGE_FOLIO_PAGES)
        score += (s64)m->size_pages * 1000;

    // --- Churn: folios evicted many times keep getting re-faulted ----------
    // High eviction_count means this folio is part of the working set;
    // protect it rather than repeatedly paying the re-fault cost.
    if (m->eviction_count > 2)
        score += (s64)m->eviction_count * 5000;

    // --- Sharing: folio mapped by multiple processes is costly to evict ----
    if (m->mapcount_snap > 1)
        score += (s64)m->mapcount_snap * 2000;

    return score;
}
