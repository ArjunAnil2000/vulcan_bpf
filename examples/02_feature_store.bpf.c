// Example 02 — Per-folio and class-level feature tracking via cache_ext hooks
//
// Populates vulcan_folio_metadata and class-level listener aggregates for
// every folio in the page cache by hooking into the cache_ext lifecycle
// callbacks:
//
//   folio_added    → assign class, vulcan_folio_init
//   folio_accessed → vulcan_folio_on_access, vulcan_update_class_feature
//   folio_evicted  → vulcan_folio_on_evict
//
// Classes (mirroring the get_scan policy):
//   CLASS_GENERAL = 0  — folios inserted by non-scan PIDs
//   CLASS_SCAN    = 1  — folios inserted by scan PIDs
//
// Class feature tracked:
//   CF_ACCESS_INTERVAL = 0  — EWMA of inter-access interval per class
//
// The resulting maps are consumed by the scoring function in example 03.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vulcan_bpf.h"

// --------------------------------------------------------------------------
// Class and class feature definitions
// --------------------------------------------------------------------------

#define CLASS_GENERAL 0
#define CLASS_SCAN    1

#define CF_ACCESS_INTERVAL 0

#define VULCAN_NUM_CLASS_FEATURES 1
#define VULCAN_MAX_CLASSES        2

#include "vulcan_class.h"

char _license[] SEC("license") = "GPL";

// --------------------------------------------------------------------------
// scan_pids map — populated by userspace to identify scan PIDs
// --------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  u32);   // pid
    __type(value, u8);   // 1 = is scan pid
    __uint(max_entries, 1024);
} scan_pids SEC(".maps");

// --------------------------------------------------------------------------
// Per-folio metadata map  (shared with example 03)
// --------------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,  u64);
    __type(value, struct vulcan_folio_metadata);
    __uint(max_entries, 500000);
} folio_meta_map SEC(".maps");

// --------------------------------------------------------------------------
// Listener configs
// --------------------------------------------------------------------------

static const struct vulcan_folio_config folio_cfg = {
    .listener_mask = VULCAN_LISTENER_MINMAX | VULCAN_LISTENER_EWMA,
    .ewma_alpha    = 200,
};

static const struct vulcan_feature_config class_cfg[VULCAN_NUM_CLASS_FEATURES] = {
    [CF_ACCESS_INTERVAL] = {
        .listener_mask = VULCAN_LISTENER_EWMA | VULCAN_LISTENER_AVG,
        .ewma_alpha    = 150,
    },
};

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

static __always_inline u8 folio_is_anonymous(struct folio *folio)
{
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    if (!mapping)
        return 1;
    return ((unsigned long)mapping & 1UL) ? 1 : 0;
}

static __always_inline u32 folio_client_tag(struct folio *folio)
{
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    if (!mapping || ((unsigned long)mapping & 1UL))
        return 0;
    struct inode *host = BPF_CORE_READ(mapping, host);
    if (!host)
        return 0;
    return (u32)BPF_CORE_READ(host, i_ino);
}

static __always_inline u32 current_class(void)
{
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u8 *is_scan = bpf_map_lookup_elem(&scan_pids, &pid);
    return (is_scan && *is_scan) ? CLASS_SCAN : CLASS_GENERAL;
}

// --------------------------------------------------------------------------
// folio_added: assign class, initialize metadata
// --------------------------------------------------------------------------

SEC("struct_ops/folio_added")
void BPF_PROG(ce_folio_added, struct folio *folio)
{
    if (!folio)
        return;

    u64 key       = (u64)folio;
    u64 now       = bpf_ktime_get_ns();
    u32 class_id  = current_class();
    u8  is_anon   = folio_is_anonymous(folio);
    u32 client_tag = folio_client_tag(folio);

    struct vulcan_folio_metadata meta =
        vulcan_folio_init(now, /*size_pages=*/1, is_anon, class_id, client_tag);

    bpf_map_update_elem(&folio_meta_map, &key, &meta, BPF_NOEXIST);
}

// --------------------------------------------------------------------------
// folio_accessed: update per-folio listeners and class-level features
// --------------------------------------------------------------------------

SEC("struct_ops/folio_accessed")
void BPF_PROG(ce_folio_accessed, struct folio *folio)
{
    if (!folio)
        return;

    u64 key = (u64)folio;
    struct vulcan_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!meta)
        return;

    u64 now      = bpf_ktime_get_ns();
    s32 refcount = BPF_CORE_READ(folio, _refcount.counter);
    s32 mapcount = BPF_CORE_READ(folio, _mapcount.counter);

    vulcan_folio_on_access(meta, now, refcount, mapcount, &folio_cfg);

    // Feed the inter-access interval into the class-level listener so the
    // scoring function can compare a folio's hotness against its class average.
    if (meta->access_count > 1) {
        s64 interval = (s64)(now - meta->prev_access_ts);
        vulcan_update_class_feature(meta->class_id, CF_ACCESS_INTERVAL,
                                    interval, &class_cfg[CF_ACCESS_INTERVAL]);
    }
}

// --------------------------------------------------------------------------
// folio_evicted: increment eviction counter
// --------------------------------------------------------------------------

SEC("struct_ops/folio_evicted")
void BPF_PROG(ce_folio_evicted, struct folio *folio)
{
    if (!folio)
        return;

    u64 key = (u64)folio;
    struct vulcan_folio_metadata *meta =
        bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!meta)
        return;

    vulcan_folio_on_evict(meta);
}
