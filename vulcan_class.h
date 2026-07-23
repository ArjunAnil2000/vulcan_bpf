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
        __sync_fetch_and_add(cnt, 1);
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
        __sync_fetch_and_sub(cnt, 1);
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

#endif /* _VULCAN_CLASS_H */
