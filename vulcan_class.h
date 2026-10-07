// vulcan_class.h -- Class-level listener feature store for kernel BPF programs.
//
// Sits between per-folio (local) and global features.  A "class" is a
// policy-defined grouping of folios sharing a characteristic assigned at
// insertion time — e.g. scan vs non-scan PID, file type, memcg.
//
// Class features aggregate listener statistics across all folios in the same
// class, keyed by (class_id, feature_id).  Unlike the global feature store
// (which uses BPF_MAP_TYPE_ARRAY), class maps use BPF_MAP_TYPE_HASH because
// class IDs are policy-assigned and may be sparse.
//
// Beyond the core (class_id, feature_id) -> listener store, this header adds:
//   - class-derivation helpers   (turn a raw key into a class_id)
//   - live class population count (folios currently assigned to a class)
//   - class ranking               (which class currently scores highest)
//   - class staleness/expiry      (has this class gone idle)
//
// PREREQUISITES (must be defined/included before this header):
//   VULCAN_NUM_CLASS_FEATURES  -- number of distinct per-class features
//   VULCAN_MAX_CLASSES         -- upper bound on distinct class IDs. Keep
//                                 this small (<=64) — it's used both to
//                                 size hash maps AND, for the ranking
//                                 helpers below, as a #pragma unroll trip
//                                 count, which must stay compile-time
//                                 cheap for the BPF verifier.
//   vulcan_bpf.h               -- listener structs and helpers
//   <bpf/bpf_helpers.h>        -- SEC, bpf_map_lookup_elem, etc.

#ifndef _VULCAN_CLASS_H
#define _VULCAN_CLASS_H

// ============================================================================
// Composite map key: (class_id, feature_id)
// ============================================================================

struct vulcan_class_key {
    u32 class_id;
    u32 feature_id;
};

// ============================================================================
// Class listener maps
// ============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VULCAN_MAX_CLASSES * VULCAN_NUM_CLASS_FEATURES);
    __type(key,   struct vulcan_class_key);
    __type(value, struct vulcan_minmax);
} vulcan_cminmax SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VULCAN_MAX_CLASSES * VULCAN_NUM_CLASS_FEATURES);
    __type(key,   struct vulcan_class_key);
    __type(value, struct vulcan_ewma);
} vulcan_cewma SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VULCAN_MAX_CLASSES * VULCAN_NUM_CLASS_FEATURES);
    __type(key,   struct vulcan_class_key);
    __type(value, struct vulcan_avg);
} vulcan_cavg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VULCAN_MAX_CLASSES * VULCAN_NUM_CLASS_FEATURES);
    __type(key,   struct vulcan_class_key);
    __type(value, struct vulcan_rolling_window);
} vulcan_crw SEC(".maps");

// ============================================================================
// Update
//
// Hash maps require an init-or-update pattern: look up the entry, update it
// in place if found, otherwise initialize a zero struct, apply the first
// update, and insert it.
// ============================================================================

static __always_inline void
vulcan_update_class_feature(u32 class_id, u32 feature_id, s64 raw_value,
                            const struct vulcan_feature_config *cfg)
{
    if (!cfg || feature_id >= VULCAN_NUM_CLASS_FEATURES ||
        class_id >= VULCAN_MAX_CLASSES)
        return;

    struct vulcan_class_key key = { .class_id = class_id,
                                    .feature_id = feature_id };

    if (cfg->listener_mask & VULCAN_LISTENER_MINMAX) {
        struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_cminmax, &key);
        if (mm) {
            vulcan_minmax_update(mm, raw_value);
        } else {
            struct vulcan_minmax init = {};
            vulcan_minmax_update(&init, raw_value);
            bpf_map_update_elem(&vulcan_cminmax, &key, &init, BPF_ANY);
        }
    }

    if (cfg->listener_mask & VULCAN_LISTENER_EWMA) {
        struct vulcan_ewma *ew = bpf_map_lookup_elem(&vulcan_cewma, &key);
        if (ew) {
            vulcan_ewma_update(ew, raw_value, cfg->ewma_alpha);
        } else {
            struct vulcan_ewma init = {};
            vulcan_ewma_update(&init, raw_value, cfg->ewma_alpha);
            bpf_map_update_elem(&vulcan_cewma, &key, &init, BPF_ANY);
        }
    }

    if (cfg->listener_mask & VULCAN_LISTENER_AVG) {
        struct vulcan_avg *avg = bpf_map_lookup_elem(&vulcan_cavg, &key);
        if (avg) {
            vulcan_avg_update(avg, raw_value);
        } else {
            struct vulcan_avg init = {};
            vulcan_avg_update(&init, raw_value);
            bpf_map_update_elem(&vulcan_cavg, &key, &init, BPF_ANY);
        }
    }

    if (cfg->listener_mask & VULCAN_LISTENER_RW) {
        struct vulcan_rolling_window *rw =
            bpf_map_lookup_elem(&vulcan_crw, &key);
        if (rw) {
            vulcan_rw_update(rw, raw_value, cfg->rw_size);
        } else {
            struct vulcan_rolling_window init = {};
            vulcan_rw_update(&init, raw_value, cfg->rw_size);
            bpf_map_update_elem(&vulcan_crw, &key, &init, BPF_ANY);
        }
    }
}

// ============================================================================
// Accessors
// ============================================================================

static __always_inline s64 vulcan_get_class_min(u32 class_id, u32 feature_id)
{
    struct vulcan_class_key key = { .class_id = class_id,
                                    .feature_id = feature_id };
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_cminmax, &key);
    return mm ? vulcan_minmax_get_min(mm) : 0;
}

static __always_inline s64 vulcan_get_class_max(u32 class_id, u32 feature_id)
{
    struct vulcan_class_key key = { .class_id = class_id,
                                    .feature_id = feature_id };
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_cminmax, &key);
    return mm ? vulcan_minmax_get_max(mm) : 0;
}

static __always_inline s64 vulcan_get_class_ewma(u32 class_id, u32 feature_id)
{
    struct vulcan_class_key key = { .class_id = class_id,
                                    .feature_id = feature_id };
    struct vulcan_ewma *ew = bpf_map_lookup_elem(&vulcan_cewma, &key);
    return ew ? vulcan_ewma_get(ew) : 0;
}

static __always_inline s64 vulcan_get_class_avg(u32 class_id, u32 feature_id)
{
    struct vulcan_class_key key = { .class_id = class_id,
                                    .feature_id = feature_id };
    struct vulcan_avg *avg = bpf_map_lookup_elem(&vulcan_cavg, &key);
    return avg ? vulcan_avg_get(avg) : 0;
}

static __always_inline s64
vulcan_get_class_latest(u32 class_id, u32 feature_id)
{
    struct vulcan_class_key key = { .class_id = class_id,
                                    .feature_id = feature_id };
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_crw, &key);
    return rw ? vulcan_rw_get_latest(rw) : 0;
}

static __always_inline s64
vulcan_get_class_window_avg(u32 class_id, u32 feature_id)
{
    struct vulcan_class_key key = { .class_id = class_id,
                                    .feature_id = feature_id };
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_crw, &key);
    return rw ? vulcan_rw_get_avg(rw) : 0;
}

static __always_inline u32
vulcan_get_class_window_count(u32 class_id, u32 feature_id)
{
    struct vulcan_class_key key = { .class_id = class_id,
                                    .feature_id = feature_id };
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_crw, &key);
    return rw ? vulcan_rw_get_count(rw) : 0;
}

// ============================================================================
// Class-derivation helpers
//
// The store above only ever reads/writes a class_id you already computed.
// These helpers turn a raw signal into one, so policies don't hand-roll
// their own hashing/bucketing every time. All are pure functions — no maps,
// no side effects — so they're safe to call from anywhere.
// ============================================================================

static __always_inline u32 vulcan_class_from_u64(u64 key, u32 num_classes)
{
    if (num_classes == 0)
        return 0;
    // 64-bit mix (splitmix64 finalizer) for decent bit dispersion on
    // typically-clustered keys (PIDs, inode numbers) before reducing mod N.
    u64 h = key;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return (u32)(h % num_classes);
}

// Buckets the CURRENT task's PID. For explicit named classes (e.g. "is this
// PID a known scanner") use your own policy-defined map + class_id scheme
// instead — this is for cheap unnamed bucketing when you don't need
// semantic class identity, just "spread PIDs across N buckets."
static __always_inline u32 vulcan_class_from_pid(u32 num_classes)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    return vulcan_class_from_u64((u64)pid, num_classes);
}

// log2-buckets a folio size (in pages) into [0, num_classes).
static __always_inline u32
vulcan_class_from_size_bucket(u32 size_pages, u32 num_classes)
{
    if (num_classes == 0)
        return 0;
    u32 bucket = 0;
    u32 v = size_pages;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (v <= 1)
            break;
        v >>= 1;
        bucket++;
    }
    return bucket % num_classes;
}

// ============================================================================
// Live class population count
//
// The listener maps above track a VALUE STREAM per class (min/max/ewma/
// avg/window) — none of them tell you how many folios currently belong to
// a class. This is separate, explicit bookkeeping: call
// vulcan_class_member_added/_removed from folio_added/folio_evicted once
// you've assigned/released a class_id.
// ============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VULCAN_MAX_CLASSES);
    __type(key, u32);
    __type(value, u32);
} vulcan_class_count SEC(".maps");

static __always_inline void vulcan_class_member_added(u32 class_id)
{
    if (class_id >= VULCAN_MAX_CLASSES)
        return;
    u32 *cnt = bpf_map_lookup_elem(&vulcan_class_count, &class_id);
    if (cnt) {
        // Plain, non-atomic increment — deliberate, not an oversight. Two
        // things: (1) clang-14's BPF backend crashes lowering
        // __sync_fetch_and_add/_sub on a u32 pulled from a map value in
        // this context ("Cannot select: ... AtomicLoadSub ...", an LLVM
        // backend limitation, not a verifier rejection); (2) even where
        // it does compile, this counter is diagnostic/threshold-gating,
        // not exact-precision — same cost/precision tradeoff already
        // documented for manual g_* counters elsewhere in this project
        // (small cross-CPU race, acceptable).
        *cnt += 1;
    } else {
        u32 one = 1;
        bpf_map_update_elem(&vulcan_class_count, &class_id, &one, BPF_ANY);
    }
}

static __always_inline void vulcan_class_member_removed(u32 class_id)
{
    if (class_id >= VULCAN_MAX_CLASSES)
        return;
    u32 *cnt = bpf_map_lookup_elem(&vulcan_class_count, &class_id);
    if (cnt && *cnt > 0)
        *cnt -= 1;  // non-atomic — see vulcan_class_member_added comment
}

static __always_inline u32 vulcan_get_class_count(u32 class_id)
{
    if (class_id >= VULCAN_MAX_CLASSES)
        return 0;
    u32 *cnt = bpf_map_lookup_elem(&vulcan_class_count, &class_id);
    return cnt ? *cnt : 0;
}

// ============================================================================
// Class ranking
//
// NOTE ON DESIGN: a generic "rank classes by an arbitrary caller-supplied
// score function" API would need an indirect (function-pointer) call from
// inside a BPF program. That's not portably legal in a plain inline header
// the way it is for cache_ext's own bpf_cache_ext_list_sample (that one
// works because it's a KERNEL kfunc — the kernel itself provides the
// callback ABI). A header-only library can't replicate that.
//
// Instead: since VULCAN_MAX_CLASSES is already a small compile-time bound
// (it sizes the hash maps above), these use #pragma unroll — a real,
// verifier-friendly technique — to scan all classes and pick the best by
// one FIXED, named metric. Only non-empty classes (count > 0) are
// considered. Add more of these if you need to rank by a different metric;
// don't try to generalize this into a callback.
// ============================================================================

static __always_inline u32
vulcan_class_top_by_ewma(u32 feature_id, s64 *out_score)
{
    u32 best_id = 0;
    s64 best = 0;
    bool found = false;

    #pragma unroll
    for (u32 cid = 0; cid < VULCAN_MAX_CLASSES; cid++) {
        if (vulcan_get_class_count(cid) == 0)
            continue;
        s64 v = vulcan_get_class_ewma(cid, feature_id);
        if (!found || v > best) {
            best = v;
            best_id = cid;
            found = true;
        }
    }
    if (out_score)
        *out_score = best;
    return best_id;
}

static __always_inline u32
vulcan_class_top_by_count(u32 *out_count)
{
    u32 best_id = 0;
    u32 best = 0;

    #pragma unroll
    for (u32 cid = 0; cid < VULCAN_MAX_CLASSES; cid++) {
        u32 c = vulcan_get_class_count(cid);
        if (c > best) {
            best = c;
            best_id = cid;
        }
    }
    if (out_count)
        *out_count = best;
    return best_id;
}

// ============================================================================
// Class staleness / expiry
//
// Class stats never expire on their own — relevant for e.g. PID-based
// classing, where a PID can be reused for an unrelated process after the
// original one exits. There's no background sweep/timer here (BPF has none
// available in this context); the policy calls vulcan_class_touch() every
// time it feeds the class (alongside vulcan_update_class_feature), then
// checks vulcan_class_is_stale() at decision time before trusting a class's
// stats, and vulcan_class_reset() to explicitly clear a class it no longer
// trusts.
// ============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VULCAN_MAX_CLASSES);
    __type(key, u32);
    __type(value, u64);
} vulcan_class_last_seen SEC(".maps");

static __always_inline void vulcan_class_touch(u32 class_id, u64 now)
{
    if (class_id >= VULCAN_MAX_CLASSES)
        return;
    bpf_map_update_elem(&vulcan_class_last_seen, &class_id, &now, BPF_ANY);
}

static __always_inline bool
vulcan_class_is_stale(u32 class_id, u64 now, u64 ttl_ns)
{
    if (class_id >= VULCAN_MAX_CLASSES)
        return true;
    u64 *last = bpf_map_lookup_elem(&vulcan_class_last_seen, &class_id);
    if (!last)
        return true;
    return (now - *last) > ttl_ns;
}

// Clears listener state for (class_id, feature_id) across all listener
// kinds. Does NOT touch the population count or last-seen timestamp —
// call vulcan_class_member_removed / let vulcan_class_touch overwrite
// those separately if you're fully retiring a class_id.
static __always_inline void vulcan_class_reset(u32 class_id, u32 feature_id)
{
    if (class_id >= VULCAN_MAX_CLASSES || feature_id >= VULCAN_NUM_CLASS_FEATURES)
        return;
    struct vulcan_class_key key = { .class_id = class_id, .feature_id = feature_id };
    bpf_map_delete_elem(&vulcan_cminmax, &key);
    bpf_map_delete_elem(&vulcan_cewma, &key);
    bpf_map_delete_elem(&vulcan_cavg, &key);
    bpf_map_delete_elem(&vulcan_crw, &key);
}

// ============================================================================
// Class-level mirror of struct vulcan_folio_metadata
//
// vulcan_update_class_feature() above requires the caller to define its own
// feature IDs, a VULCAN_NUM_CLASS_FEATURES count, and a vulcan_feature_config
// array. This section skips all of that for one specific, common case:
// aggregating the SAME raw signals struct vulcan_folio_metadata
// (vulcan_bpf.h) already tracks per folio — insertion_ts, size_pages,
// is_anonymous, last_access_ts, prev_access_ts, access_count, client_tag,
// refcount_snap, mapcount_snap, eviction_count — per class_id instead of
// per folio, with all 4 listeners (MinMax/EWMA/Avg/RollingWindow) running
// automatically on every signal. No per-feature config needed: call the
// three lifecycle functions below from the matching cache_ext hook and pass
// the folio's own (already-updated) vulcan_folio_metadata.
//
// A class's VULCAN_CM_LAST_ACCESS_TS, e.g., is the most recent access
// timestamp across every folio currently classed into that bucket (by
// whatever derivation the caller used — vulcan_class_from_pid,
// vulcan_class_from_u64, vulcan_class_from_size_bucket, or its own scheme).
//
// Independent, fixed-size maps (VULCAN_MAX_CLASSES x 10 signals) — does not
// share storage with vulcan_update_class_feature()'s caller-defined feature
// IDs above, so the two APIs can be used side by side without collision.
//
// Usage:
//   folio_added:    vulcan_class_meta_on_folio_added(class_id, &meta)
//   folio_accessed: vulcan_class_meta_on_folio_accessed(class_id, &meta)
//                   (call AFTER vulcan_folio_on_access, so meta's dynamic
//                   fields are already refreshed for this access)
//   folio_evicted:  vulcan_class_meta_on_folio_evicted(class_id, &meta)
//                   (call AFTER vulcan_folio_on_evict, so eviction_count
//                   already reflects this eviction)
// ============================================================================

#define VULCAN_CLASS_META_NUM_SIGNALS 10

enum vulcan_class_meta_signal {
    VULCAN_CM_INSERTION_TS   = 0,
    VULCAN_CM_SIZE_PAGES     = 1,
    VULCAN_CM_IS_ANONYMOUS   = 2,
    VULCAN_CM_LAST_ACCESS_TS = 3,
    VULCAN_CM_PREV_ACCESS_TS = 4,
    VULCAN_CM_ACCESS_COUNT   = 5,
    VULCAN_CM_CLIENT_TAG     = 6,
    VULCAN_CM_REFCOUNT_SNAP  = 7,
    VULCAN_CM_MAPCOUNT_SNAP  = 8,
    VULCAN_CM_EVICTION_COUNT = 9,
};

// Fixed listener parameters for this mirror — deliberately not
// caller-configurable (that's the point: zero-config). Matches the
// defaults used elsewhere in this library (vulcan_bpf.h's folio_cfg
// convention, VULCAN_MAX_WINDOW headroom).
#define VULCAN_CLASS_META_EWMA_ALPHA 200
#define VULCAN_CLASS_META_RW_SIZE    8

struct vulcan_class_meta_key {
    u32 class_id;
    u32 signal_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VULCAN_MAX_CLASSES * VULCAN_CLASS_META_NUM_SIGNALS);
    __type(key,   struct vulcan_class_meta_key);
    __type(value, struct vulcan_minmax);
} vulcan_cm_minmax SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VULCAN_MAX_CLASSES * VULCAN_CLASS_META_NUM_SIGNALS);
    __type(key,   struct vulcan_class_meta_key);
    __type(value, struct vulcan_ewma);
} vulcan_cm_ewma SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VULCAN_MAX_CLASSES * VULCAN_CLASS_META_NUM_SIGNALS);
    __type(key,   struct vulcan_class_meta_key);
    __type(value, struct vulcan_avg);
} vulcan_cm_avg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, VULCAN_MAX_CLASSES * VULCAN_CLASS_META_NUM_SIGNALS);
    __type(key,   struct vulcan_class_meta_key);
    __type(value, struct vulcan_rolling_window);
} vulcan_cm_rw SEC(".maps");

// Init-or-update against all 4 listener maps at once (see
// vulcan_update_class_feature's own comment for why hash maps need this
// pattern — no bpf_map_type with an implicit-zero-value lookup here).
static __always_inline void
vulcan_class_meta_update(u32 class_id, u32 signal_id, s64 val)
{
    if (class_id >= VULCAN_MAX_CLASSES || signal_id >= VULCAN_CLASS_META_NUM_SIGNALS)
        return;

    struct vulcan_class_meta_key key = { .class_id = class_id, .signal_id = signal_id };

    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_cm_minmax, &key);
    if (mm) {
        vulcan_minmax_update(mm, val);
    } else {
        struct vulcan_minmax init = {};
        vulcan_minmax_update(&init, val);
        bpf_map_update_elem(&vulcan_cm_minmax, &key, &init, BPF_ANY);
    }

    struct vulcan_ewma *ew = bpf_map_lookup_elem(&vulcan_cm_ewma, &key);
    if (ew) {
        vulcan_ewma_update(ew, val, VULCAN_CLASS_META_EWMA_ALPHA);
    } else {
        struct vulcan_ewma init = {};
        vulcan_ewma_update(&init, val, VULCAN_CLASS_META_EWMA_ALPHA);
        bpf_map_update_elem(&vulcan_cm_ewma, &key, &init, BPF_ANY);
    }

    struct vulcan_avg *avg = bpf_map_lookup_elem(&vulcan_cm_avg, &key);
    if (avg) {
        vulcan_avg_update(avg, val);
    } else {
        struct vulcan_avg init = {};
        vulcan_avg_update(&init, val);
        bpf_map_update_elem(&vulcan_cm_avg, &key, &init, BPF_ANY);
    }

    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_cm_rw, &key);
    if (rw) {
        vulcan_rw_update(rw, val, VULCAN_CLASS_META_RW_SIZE);
    } else {
        struct vulcan_rolling_window init = {};
        vulcan_rw_update(&init, val, VULCAN_CLASS_META_RW_SIZE);
        bpf_map_update_elem(&vulcan_cm_rw, &key, &init, BPF_ANY);
    }
}

// --- Lifecycle: call from the matching cache_ext hook ----------------------

static __always_inline void
vulcan_class_meta_on_folio_added(u32 class_id, const struct vulcan_folio_metadata *m)
{
    vulcan_class_meta_update(class_id, VULCAN_CM_INSERTION_TS, (s64)m->insertion_ts);
    vulcan_class_meta_update(class_id, VULCAN_CM_SIZE_PAGES,   (s64)m->size_pages);
    vulcan_class_meta_update(class_id, VULCAN_CM_IS_ANONYMOUS, (s64)m->is_anonymous);
    vulcan_class_meta_update(class_id, VULCAN_CM_CLIENT_TAG,   (s64)m->client_tag);
}

static __always_inline void
vulcan_class_meta_on_folio_accessed(u32 class_id, const struct vulcan_folio_metadata *m)
{
    vulcan_class_meta_update(class_id, VULCAN_CM_LAST_ACCESS_TS, (s64)m->last_access_ts);
    vulcan_class_meta_update(class_id, VULCAN_CM_PREV_ACCESS_TS, (s64)m->prev_access_ts);
    vulcan_class_meta_update(class_id, VULCAN_CM_ACCESS_COUNT,   (s64)m->access_count);
    vulcan_class_meta_update(class_id, VULCAN_CM_REFCOUNT_SNAP,  (s64)m->refcount_snap);
    vulcan_class_meta_update(class_id, VULCAN_CM_MAPCOUNT_SNAP,  (s64)m->mapcount_snap);
}

static __always_inline void
vulcan_class_meta_on_folio_evicted(u32 class_id, const struct vulcan_folio_metadata *m)
{
    vulcan_class_meta_update(class_id, VULCAN_CM_EVICTION_COUNT, (s64)m->eviction_count);
}

// --- Accessors (naming mirrors vulcan_get_class_* above) -------------------

static __always_inline s64 vulcan_class_meta_get_min(u32 class_id, u32 signal_id)
{
    struct vulcan_class_meta_key key = { .class_id = class_id, .signal_id = signal_id };
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_cm_minmax, &key);
    return mm ? vulcan_minmax_get_min(mm) : 0;
}

static __always_inline s64 vulcan_class_meta_get_max(u32 class_id, u32 signal_id)
{
    struct vulcan_class_meta_key key = { .class_id = class_id, .signal_id = signal_id };
    struct vulcan_minmax *mm = bpf_map_lookup_elem(&vulcan_cm_minmax, &key);
    return mm ? vulcan_minmax_get_max(mm) : 0;
}

static __always_inline s64 vulcan_class_meta_get_ewma(u32 class_id, u32 signal_id)
{
    struct vulcan_class_meta_key key = { .class_id = class_id, .signal_id = signal_id };
    struct vulcan_ewma *ew = bpf_map_lookup_elem(&vulcan_cm_ewma, &key);
    return ew ? vulcan_ewma_get(ew) : 0;
}

static __always_inline s64 vulcan_class_meta_get_avg(u32 class_id, u32 signal_id)
{
    struct vulcan_class_meta_key key = { .class_id = class_id, .signal_id = signal_id };
    struct vulcan_avg *avg = bpf_map_lookup_elem(&vulcan_cm_avg, &key);
    return avg ? vulcan_avg_get(avg) : 0;
}

static __always_inline s64 vulcan_class_meta_get_window_avg(u32 class_id, u32 signal_id)
{
    struct vulcan_class_meta_key key = { .class_id = class_id, .signal_id = signal_id };
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_cm_rw, &key);
    return rw ? vulcan_rw_get_avg(rw) : 0;
}

static __always_inline u32 vulcan_class_meta_get_window_count(u32 class_id, u32 signal_id)
{
    struct vulcan_class_meta_key key = { .class_id = class_id, .signal_id = signal_id };
    struct vulcan_rolling_window *rw = bpf_map_lookup_elem(&vulcan_cm_rw, &key);
    return rw ? vulcan_rw_get_count(rw) : 0;
}

// Ranking counterpart to vulcan_class_top_by_ewma() above, but reading this
// mirror's own vulcan_cm_ewma map instead of the caller-fed vulcan_cewma
// map — needed because a policy using ONLY vulcan_class_meta_* (no calls to
// vulcan_update_class_feature) would otherwise find vulcan_cewma empty.
// vulcan_class_top_by_count() needs no counterpart: population tracking
// (vulcan_class_member_added/_removed) is shared, not feature-store-specific.
static __always_inline u32
vulcan_class_meta_top_by_ewma(u32 signal_id, s64 *out_score)
{
    u32 best_id = 0;
    s64 best = 0;
    bool found = false;

    #pragma unroll
    for (u32 cid = 0; cid < VULCAN_MAX_CLASSES; cid++) {
        if (vulcan_get_class_count(cid) == 0)
            continue;
        s64 v = vulcan_class_meta_get_ewma(cid, signal_id);
        if (!found || v > best) {
            best = v;
            best_id = cid;
            found = true;
        }
    }
    if (out_score)
        *out_score = best;
    return best_id;
}

#endif /* _VULCAN_CLASS_H */
