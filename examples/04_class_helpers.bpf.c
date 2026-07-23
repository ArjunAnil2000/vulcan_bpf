// Example 04 — Class-derivation, population, ranking, and staleness
//
// Examples 02/03 use an explicit, named 2-class scheme (scan vs general)
// driven by a policy-defined `scan_pids` map. This example instead shows
// the generic class.h helpers added for cases where you don't need named
// semantics — just cheap, even bucketing of a raw key (PID here) across N
// classes, plus the bookkeeping primitives that come with it: how many
// folios are currently in each bucket, which bucket is "hottest" right
// now, and how to tell a bucket has gone idle.
//
// Pattern:
//   1. Derive class_id from a raw key with vulcan_class_from_pid (or
//      vulcan_class_from_u64 / vulcan_class_from_size_bucket).
//   2. Track membership with vulcan_class_member_added/_removed.
//   3. Feed the class feature store as usual, touching last-seen time.
//   4. Rank classes with vulcan_class_top_by_ewma / _top_by_count.
//   5. Check vulcan_class_is_stale before trusting a class's stats;
//      vulcan_class_reset to clear one you no longer trust.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "vulcan_bpf.h"

#define CF_ACCESS_INTERVAL 0

#define VULCAN_NUM_CLASS_FEATURES 1
#define VULCAN_MAX_CLASSES        8   // generic PID buckets, not named classes

#include "vulcan_class.h"

char _license[] SEC("license") = "GPL";

#define CLASS_TTL_NS (10ULL * 1000 * 1000 * 1000)   // 10s idle -> stale

static const struct vulcan_feature_config class_cfg[VULCAN_NUM_CLASS_FEATURES] = {
    [CF_ACCESS_INTERVAL] = {
        .listener_mask = VULCAN_LISTENER_EWMA,
        .ewma_alpha    = 150,
    },
};

struct my_folio_state {
    u64 last_access_ts;
    u32 class_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  u64);   // folio pointer
    __type(value, struct my_folio_state);
    __uint(max_entries, 100000);
} folio_state_map SEC(".maps");

// --------------------------------------------------------------------------
// folio_added: derive a class from the inserting PID, track membership
// --------------------------------------------------------------------------

static __always_inline void on_folio_added(struct folio *folio)
{
    u64 key = (u64)folio;
    u64 now = bpf_ktime_get_ns();
    u32 class_id = vulcan_class_from_pid(VULCAN_MAX_CLASSES);

    struct my_folio_state s = { .last_access_ts = now, .class_id = class_id };
    bpf_map_update_elem(&folio_state_map, &key, &s, BPF_ANY);

    vulcan_class_member_added(class_id);
    vulcan_class_touch(class_id, now);
}

// --------------------------------------------------------------------------
// folio_accessed: feed the class-level interval feature
// --------------------------------------------------------------------------

static __always_inline void on_folio_accessed(struct folio *folio)
{
    u64 key = (u64)folio;
    u64 now = bpf_ktime_get_ns();

    struct my_folio_state *s = bpf_map_lookup_elem(&folio_state_map, &key);
    if (!s)
        return;

    s64 interval = (s64)(now - s->last_access_ts);
    vulcan_update_class_feature(s->class_id, CF_ACCESS_INTERVAL, interval,
                                &class_cfg[CF_ACCESS_INTERVAL]);
    vulcan_class_touch(s->class_id, now);
    s->last_access_ts = now;
}

// --------------------------------------------------------------------------
// folio_evicted: release membership
// --------------------------------------------------------------------------

static __always_inline void on_folio_evicted(struct folio *folio)
{
    u64 key = (u64)folio;
    struct my_folio_state *s = bpf_map_lookup_elem(&folio_state_map, &key);
    if (s)
        vulcan_class_member_removed(s->class_id);
    bpf_map_delete_elem(&folio_state_map, &key);
}

// --------------------------------------------------------------------------
// Decision time: which PID-bucket is currently hottest / biggest, and is
// this folio's own bucket still fresh enough to trust?
// --------------------------------------------------------------------------

static __always_inline s64 score(struct folio *folio)
{
    u64 key = (u64)folio;
    struct my_folio_state *s = bpf_map_lookup_elem(&folio_state_map, &key);
    if (!s)
        return S64_MAX;

    u64 now = bpf_ktime_get_ns();
    if (vulcan_class_is_stale(s->class_id, now, CLASS_TTL_NS)) {
        // This bucket hasn't been touched in a while (possible PID reuse
        // since we last saw it) — don't trust its stats, reset and treat
        // this folio as a fresh/unknown case instead of scoring off stale
        // data.
        vulcan_class_reset(s->class_id, CF_ACCESS_INTERVAL);
        return 0;
    }

    s64 hottest_score;
    u32 hottest_class = vulcan_class_top_by_ewma(CF_ACCESS_INTERVAL, &hottest_score);

    u32 biggest_pop;
    u32 biggest_class = vulcan_class_top_by_count(&biggest_pop);

    s64 my_ewma = vulcan_get_class_ewma(s->class_id, CF_ACCESS_INTERVAL);

    // Illustrative combination: protect folios in the currently-hottest
    // class; mildly penalize folios in the single largest class (a bucket
    // that's grown disproportionately large looks scan-like).
    s64 combined = my_ewma;
    if (s->class_id == hottest_class)
        combined -= 500000LL;
    if (s->class_id == biggest_class && biggest_pop > 1000)
        combined += 200000LL;

    return combined;
}
