// Example 02 — Per-folio feature tracking via cache_ext hooks
//
// Populates vulcan_folio_metadata for every folio in the page cache by
// hooking into the three cache_ext lifecycle callbacks:
//
//   folio_added    → vulcan_folio_init   (static fields + first timestamp)
//   folio_accessed → vulcan_folio_on_access (dynamic fields + listeners)
//   folio_evicted  → vulcan_folio_on_evict  (eviction_count)
//
// The resulting map (folio_meta_map) is consumed by the scoring function
// in example 03.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vulcan_bpf.h"

char _license[] SEC("license") = "GPL";

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
// Listener config
// --------------------------------------------------------------------------

static const struct vulcan_folio_config folio_cfg = {
    .listener_mask = VULCAN_LISTENER_MINMAX | VULCAN_LISTENER_EWMA,
    .ewma_alpha    = 200,   // α = 0.2
};

// --------------------------------------------------------------------------
// Helpers: extract static folio properties
// --------------------------------------------------------------------------

static __always_inline u8 folio_is_anonymous(struct folio *folio)
{
    // Anonymous folios have PAGE_MAPPING_ANON (bit 0) set in mapping,
    // or mapping is NULL.
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    if (!mapping)
        return 1;
    return ((unsigned long)mapping & 1UL) ? 1 : 0;
}

static __always_inline u32 folio_client_tag(struct folio *folio)
{
    // Use inode number as a workload identifier for file-backed folios.
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    if (!mapping || ((unsigned long)mapping & 1UL))
        return 0;
    struct inode *host = BPF_CORE_READ(mapping, host);
    if (!host)
        return 0;
    return (u32)BPF_CORE_READ(host, i_ino);
}

// --------------------------------------------------------------------------
// folio_added: initialize metadata on insertion into page cache
// --------------------------------------------------------------------------

SEC("struct_ops/folio_added")
void BPF_PROG(ce_folio_added, struct folio *folio)
{
    if (!folio)
        return;

    u64 key  = (u64)folio;
    u64 now  = bpf_ktime_get_ns();

    // size_pages: hardcoded to 1; large folio support requires kernel change.
    u32 size_pages  = 1;
    u8  is_anon     = folio_is_anonymous(folio);
    u32 client_tag  = folio_client_tag(folio);

    struct vulcan_folio_metadata meta =
        vulcan_folio_init(now, size_pages, is_anon, client_tag);

    bpf_map_update_elem(&folio_meta_map, &key, &meta, BPF_NOEXIST);
}

// --------------------------------------------------------------------------
// folio_accessed: update dynamic fields and listeners on each access
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

    u64  now      = bpf_ktime_get_ns();
    s32  refcount = BPF_CORE_READ(folio, _refcount.counter);
    s32  mapcount = BPF_CORE_READ(folio, _mapcount.counter);

    vulcan_folio_on_access(meta, now, refcount, mapcount, &folio_cfg);
}

// --------------------------------------------------------------------------
// folio_evicted: increment eviction counter, keep metadata for re-insertion
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
