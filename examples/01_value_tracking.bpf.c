// Example 01 — Direct listener primitives (no feature dispatch)
//
// Shows how to use vulcan_bpf.h listener structs directly inside a BPF
// program, without any feature-store machinery.  Useful when you have a
// single value to track per-object (e.g. per-folio inter-access interval)
// and don't need the generic GF_* dispatch layer.
//
// Pattern:
//   1. Embed listener state in your map value struct.
//   2. On each event, call the update helper.
//   3. In your scoring / decision function, call the get helper.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "vulcan_bpf.h"

char _license[] SEC("license") = "GPL";

// --------------------------------------------------------------------------
// Map: one entry per folio, holds access-interval listeners
// --------------------------------------------------------------------------

struct my_folio_state {
    u64 last_ts;
    struct vulcan_ewma   interval_ewma;   // smoothed inter-access interval
    struct vulcan_minmax interval_mm;     // min / max interval ever seen
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  u64);                    // folio pointer as key
    __type(value, struct my_folio_state);
    __uint(max_entries, 100000);
} folio_state_map SEC(".maps");

// --------------------------------------------------------------------------
// On each folio access: update listeners
// --------------------------------------------------------------------------

static __always_inline void on_folio_access(struct folio *folio)
{
    u64 key = (u64)folio;
    u64 now = bpf_ktime_get_ns();

    struct my_folio_state *s = bpf_map_lookup_elem(&folio_state_map, &key);
    if (!s) {
        struct my_folio_state init = { .last_ts = now };
        bpf_map_update_elem(&folio_state_map, &key, &init, BPF_ANY);
        return;
    }

    if (s->last_ts > 0) {
        s64 interval = (s64)(now - s->last_ts);
        vulcan_ewma_update(&s->interval_ewma, interval, /*alpha=*/200);
        vulcan_minmax_update(&s->interval_mm, interval);
    }
    s->last_ts = now;
}

// --------------------------------------------------------------------------
// Scoring: lower EWMA interval = hotter folio = protect from eviction
// --------------------------------------------------------------------------

static __always_inline s64 score(struct folio *folio)
{
    u64 key = (u64)folio;
    struct my_folio_state *s = bpf_map_lookup_elem(&folio_state_map, &key);
    if (!s)
        return S64_MAX;

    s64 ewma = vulcan_ewma_get(&s->interval_ewma);
    s64 min  = vulcan_minmax_get_min(&s->interval_mm);

    // Combine: base score is EWMA; bonus protection if recent burst (min small)
    s64 combined = ewma;
    if (min > 0 && min < 1000000LL)   // min interval < 1 ms → burst traffic
        combined -= 500000LL;          // bias toward keeping this folio

    return combined;
}
