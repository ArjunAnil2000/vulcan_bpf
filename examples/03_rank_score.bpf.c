// Example 03 — Rank / score using per-folio and class-level features
//
// Composes per-folio metadata and class-level listener aggregates into a
// single eviction score.  Lower score = evict first.  S64_MAX = protect.
//
// Depends on folio_meta_map and vulcan_c* maps populated by example 02.
//
// Score design:
//   Base      = access_count (LFU)
//   Hotness   = protect if folio interval EWMA is short vs. its class average
//   Class     = scan-class folios get no hotness protection (evict first)
//   Size      = penalize large folios (more expensive to re-fault)
//   Churn     = protect if eviction_count is high (persistent working set)
//   Sharing   = protect if mapcount is high (many processes use this folio)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "vulcan_bpf.h"

#define CLASS_GENERAL 0
#define CLASS_SCAN    1

#define CF_ACCESS_INTERVAL 0

#define VULCAN_NUM_CLASS_FEATURES 1
#define VULCAN_MAX_CLASSES        2

#include "vulcan_class.h"

#define HOT_INTERVAL_NS   5000000LL   // EWMA interval < 5 ms → hot folio
#define LARGE_FOLIO_PAGES 4

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

    if (folio_test_dirty(folio) || folio_test_writeback(folio))
        return S64_MAX;
    if (!folio_test_uptodate(folio) || !folio_test_lru(folio))
        return S64_MAX;

    u64 key = (u64)folio;
    struct vulcan_folio_metadata *m = bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!m)
        return S64_MAX;

    // --- Base: LFU ----------------------------------------------------------
    s64 score = (s64)m->access_count;

    // --- Class: scan folios are evicted first, skip hotness protection ------
    if (m->class_id == CLASS_SCAN)
        return score;

    // --- Hotness: protect if this folio is hotter than its class average ----
    // Compare per-folio EWMA against the class-level EWMA so the threshold
    // adapts to the workload rather than being a fixed constant.
    s64 folio_ewma = vulcan_ewma_get(&m->interval_ewma);
    s64 class_ewma = vulcan_get_class_ewma(m->class_id, CF_ACCESS_INTERVAL);
    if (folio_ewma > 0 && class_ewma > 0 && folio_ewma < class_ewma)
        score += 30000;
    else if (folio_ewma > 0 && folio_ewma < HOT_INTERVAL_NS)
        score += 30000;   // fallback if class stats not yet populated

    // --- Size: larger folios more expensive to re-fault ---------------------
    if (m->size_pages >= LARGE_FOLIO_PAGES)
        score += (s64)m->size_pages * 1000;

    // --- Churn: repeatedly evicted folios are part of working set -----------
    if (m->eviction_count > 2)
        score += (s64)m->eviction_count * 5000;

    // --- Sharing: folio mapped by multiple processes ------------------------
    if (m->mapcount_snap > 1)
        score += (s64)m->mapcount_snap * 2000;

    return score;
}
