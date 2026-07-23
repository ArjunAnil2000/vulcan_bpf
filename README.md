# vulcan_bpf

BPF-compatible listener primitives and a lightweight feature-store dispatch
layer for kernel BPF programs.  Designed for use in cache-eviction, prefetch,
and network-aware scheduling policies.

---

## Headers

| Header | Purpose |
|---|---|
| `vulcan_bpf.h` | Listener primitives, config types, per-folio helpers. No map references. Include this standalone when you only need the low-level structs. |
| `vulcan_feature.h` | Global feature-store dispatch (`vulcan_update_feature`) and read-back accessors (`vulcan_get_*`). Defines four global listener maps. Requires `VULCAN_NUM_GLOBAL_FEATURES` to be `#define`d before inclusion. |
| `vulcan_class.h` | Class-level feature store — sits between per-folio and global. Aggregates listener statistics across all folios sharing a policy-assigned `class_id`. Uses hash maps keyed by `(class_id, feature_id)`. Requires `VULCAN_NUM_CLASS_FEATURES` and `VULCAN_MAX_CLASSES` before inclusion. |

---

## Listener types

All state structs live in `vulcan_bpf.h` and can be embedded anywhere (map
values, per-object structs, etc.).

### MinMax — `struct vulcan_minmax`

Tracks the observed minimum and maximum of a stream.

```c
struct vulcan_minmax mm = {};
vulcan_minmax_update(&mm, value);
s64 lo = vulcan_minmax_get_min(&mm);
s64 hi = vulcan_minmax_get_max(&mm);
```

### EWMA — `struct vulcan_ewma`

Exponentially-weighted moving average. Alpha is a fixed-point integer in
`[0, 1000]` where `1000` = α=1.0 (no smoothing) and `100` = α=0.1 (heavy
smoothing).

```c
struct vulcan_ewma e = {};
vulcan_ewma_update(&e, value, /*alpha=*/200);   // α = 0.2
s64 smooth = vulcan_ewma_get(&e);
```

### Running Average — `struct vulcan_avg`

Exact arithmetic mean over all samples seen.

```c
struct vulcan_avg a = {};
vulcan_avg_update(&a, value);
s64 mean = vulcan_avg_get(&a);
```

### Rolling Window — `struct vulcan_rolling_window`

Circular buffer of the last N samples (max `VULCAN_MAX_WINDOW` = 16).

```c
struct vulcan_rolling_window rw = {};
vulcan_rw_update(&rw, value, /*window_size=*/8);
s64 latest  = vulcan_rw_get_latest(&rw);
s64 avg     = vulcan_rw_get_avg(&rw);
s64 second  = vulcan_rw_get_kth_recent(&rw, 1);   // 0 = latest
u32 n       = vulcan_rw_get_count(&rw);
```

---

## Setting up the feature store

The feature store manages one set of listener maps shared across all global
features (e.g. TCP metrics).  Use it when you have N distinct signals that all
need the same listener types.

### Step 1 — Define feature count and IDs

```c
#define VULCAN_NUM_GLOBAL_FEATURES 4

enum my_feature {
    GF_SEGS_IN        = 0,
    GF_BYTES_RECEIVED = 1,
    GF_SRTT_US        = 2,
    GF_RETRANS_OUT    = 3,
};
```

### Step 2 — Include `vulcan_feature.h`

This single `#include` creates the four BPF listener maps
(`vulcan_gminmax`, `vulcan_gewma`, `vulcan_grw`, `vulcan_gavg`), each with
`VULCAN_NUM_GLOBAL_FEATURES` entries.

```c
#include "vulcan_bpf.h"        // must come first
#include "vulcan_feature.h"    // defines maps + dispatch + accessors
```

**Prerequisites** (must be in scope before the include):
- `VULCAN_NUM_GLOBAL_FEATURES` `#define`
- `vmlinux.h` or equivalent kernel types (`u32`, `s64`, ...)
- `<bpf/bpf_helpers.h>` (for `SEC`, `bpf_map_lookup_elem`)

### Step 3 — Configure listeners per feature

```c
static const struct vulcan_feature_config cfg[VULCAN_NUM_GLOBAL_FEATURES] = {
    [GF_SEGS_IN]        = { .listener_mask = VULCAN_LISTENER_RW | VULCAN_LISTENER_EWMA,
                             .ewma_alpha = 200, .rw_size = 8 },
    [GF_BYTES_RECEIVED] = { .listener_mask = VULCAN_LISTENER_MINMAX | VULCAN_LISTENER_AVG },
    [GF_SRTT_US]        = { .listener_mask = VULCAN_LISTENER_EWMA, .ewma_alpha = 100 },
    [GF_RETRANS_OUT]    = { .listener_mask = VULCAN_LISTENER_RW, .rw_size = 4 },
};
```

Listener flags (OR together freely):

| Flag | Listener |
|---|---|
| `VULCAN_LISTENER_MINMAX` | MinMax |
| `VULCAN_LISTENER_EWMA` | EWMA (set `.ewma_alpha`) |
| `VULCAN_LISTENER_AVG` | Running average |
| `VULCAN_LISTENER_RW` | Rolling window (set `.rw_size`) |
| `VULCAN_LISTENER_ALL` | All four at once |

### Step 4 — Feed observations

Call `vulcan_update_feature` once per event (e.g. inside a kprobe):

```c
vulcan_update_feature(GF_SEGS_IN,        (s64)segs_in,        &cfg[GF_SEGS_IN]);
vulcan_update_feature(GF_BYTES_RECEIVED,  (s64)bytes_received, &cfg[GF_BYTES_RECEIVED]);
```

Only listeners enabled in the config are updated; disabled ones are no-ops.

### Step 5 — Read aggregated values

```c
s64 avg_bytes  = vulcan_get_avg(GF_BYTES_RECEIVED);
s64 max_bytes  = vulcan_get_max(GF_BYTES_RECEIVED);
s64 srtt_ewma  = vulcan_get_ewma(GF_SRTT_US);
s64 win_segs   = vulcan_get_window_avg(GF_SEGS_IN);
u32 win_n      = vulcan_get_window_count(GF_SEGS_IN);
s64 latest_seg = vulcan_get_latest(GF_SEGS_IN);
s64 prev_seg   = vulcan_get_kth_recent(GF_SEGS_IN, 1);
```

Calling an accessor for a listener that is disabled in the config safely
returns `0`.

---

## Per-folio tracking

`vulcan_bpf.h` also ships helpers for per-object (per-folio) interval tracking,
designed for use in cache eviction hooks.

```c
// On folio_added / first access:
struct vulcan_folio_metadata meta = vulcan_folio_init(
    bpf_ktime_get_ns(), /*size_pages=*/1, /*is_anonymous=*/0,
    /*class_id=*/0, /*client_tag=*/0);
bpf_map_update_elem(&folio_metadata_map, &key, &meta, BPF_ANY);

// On each subsequent folio_accessed:
static const struct vulcan_folio_config folio_cfg = {
    .listener_mask = VULCAN_LISTENER_MINMAX | VULCAN_LISTENER_EWMA,
    .ewma_alpha    = 200,
};
vulcan_folio_on_access(meta, bpf_ktime_get_ns(), refcount, mapcount, &folio_cfg);

// On folio_evicted, if you keep the metadata entry alive across eviction:
vulcan_folio_on_evict(meta);

// Reading back:
s64 ewma_interval = vulcan_ewma_get(&meta->interval_ewma);
s64 min_interval  = vulcan_minmax_get_min(&meta->interval_minmax);
u32 size_pages    = meta->size_pages;      // set once at insertion
s32 mapcount_snap = meta->mapcount_snap;   // refreshed on every access
u32 eviction_count = meta->eviction_count; // only if vulcan_folio_on_evict is called
```

---

## Class-level tracking

`vulcan_class.h` sits between per-folio and global: it aggregates listener
statistics across every folio sharing a policy-assigned `class_id`, keyed by
`(class_id, feature_id)`.

### Step 1 — Define class/feature bounds and include

```c
#define VULCAN_NUM_CLASS_FEATURES 1
#define VULCAN_MAX_CLASSES        4   // keep small — see header comment

enum my_class_feature {
    CF_ACCESS_INTERVAL = 0,
};

#include "vulcan_bpf.h"        // must come first
#include "vulcan_class.h"      // defines maps + dispatch + accessors
```

### Step 2 — Assign a class_id

Either derive one with a helper, or use your own policy-defined scheme
(e.g. an explicit "is this PID a known scanner" map, as in
`examples/02_feature_store.bpf.c`):

```c
u32 class_id = vulcan_class_from_pid(VULCAN_MAX_CLASSES);           // generic hash bucket
u32 class_id = vulcan_class_from_size_bucket(size_pages, VULCAN_MAX_CLASSES);
u32 class_id = vulcan_class_from_u64(some_key, VULCAN_MAX_CLASSES); // your own key
```

### Step 3 — Feed observations, track membership and freshness

```c
static const struct vulcan_feature_config class_cfg[VULCAN_NUM_CLASS_FEATURES] = {
    [CF_ACCESS_INTERVAL] = { .listener_mask = VULCAN_LISTENER_EWMA, .ewma_alpha = 150 },
};

// On folio_added, once class_id is assigned:
vulcan_class_member_added(class_id);

// On each observation (e.g. folio_accessed):
vulcan_update_class_feature(class_id, CF_ACCESS_INTERVAL, interval, &class_cfg[CF_ACCESS_INTERVAL]);
vulcan_class_touch(class_id, now);   // for staleness tracking, see below

// On folio_evicted:
vulcan_class_member_removed(class_id);
```

### Step 4 — Read back

```c
s64 class_ewma = vulcan_get_class_ewma(class_id, CF_ACCESS_INTERVAL);
u32 population  = vulcan_get_class_count(class_id);

s64 top_score;
u32 hottest_class = vulcan_class_top_by_ewma(CF_ACCESS_INTERVAL, &top_score);

u32 biggest_pop;
u32 largest_class = vulcan_class_top_by_count(&biggest_pop);

if (vulcan_class_is_stale(class_id, now, /*ttl_ns=*/5000000000ULL)) {
    vulcan_class_reset(class_id, CF_ACCESS_INTERVAL);
}
```

`vulcan_class_top_by_*` scan all classes via `#pragma unroll` (a compile-time
technique, not a runtime callback — see the header comment for why a generic
"rank by arbitrary score function" API isn't portably legal in a header-only
BPF library) and only consider classes with `vulcan_get_class_count() > 0`.

---

## Examples

| File | What it shows |
|---|---|
| [`examples/01_value_tracking.bpf.c`](examples/01_value_tracking.bpf.c) | Embed listeners directly in a map value struct; no feature dispatch |
| [`examples/02_feature_store.bpf.c`](examples/02_feature_store.bpf.c) | Populate `vulcan_folio_metadata` and a named 2-class (scan/general) class-level feature via `folio_added`, `folio_accessed`, `folio_evicted` cache_ext hooks |
| [`examples/03_rank_score.bpf.c`](examples/03_rank_score.bpf.c) | Compose an eviction score from access count, interval EWMA (compared against its class average), folio size, eviction churn, and mapcount |
| [`examples/04_class_helpers.bpf.c`](examples/04_class_helpers.bpf.c) | Generic PID-bucket classing via `vulcan_class_from_pid`, population count, `vulcan_class_top_by_ewma` ranking, and staleness/reset |
