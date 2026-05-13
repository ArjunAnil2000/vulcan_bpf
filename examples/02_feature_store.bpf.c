// Example 02 — Feature store: full setup, update, and read
//
// Shows the complete pattern for using vulcan_feature.h:
//   1. Define VULCAN_NUM_GLOBAL_FEATURES and a GF_* enum.
//   2. Include vulcan_feature.h  →  listener maps are created automatically.
//   3. Call vulcan_update_feature() on each new observation.
//   4. Read back aggregated values with vulcan_get_*() accessors anywhere.
//
// This example tracks two TCP metrics (segs_in, bytes_received) with different
// listener combinations and reads them back in a decision function.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vulcan_bpf.h"

char _license[] SEC("license") = "GPL";

// --------------------------------------------------------------------------
// Step 1: define the feature count and IDs
// --------------------------------------------------------------------------

#define VULCAN_NUM_GLOBAL_FEATURES 2

enum my_feature {
    GF_SEGS_IN       = 0,
    GF_BYTES_RECEIVED = 1,
};

// --------------------------------------------------------------------------
// Step 2: include the dispatch layer — listener maps are defined here
// --------------------------------------------------------------------------

#include "vulcan_feature.h"

// --------------------------------------------------------------------------
// Step 3: per-feature listener configuration
//   GF_SEGS_IN       → rolling window (last 8 samples) + EWMA
//   GF_BYTES_RECEIVED → minmax + running average
// --------------------------------------------------------------------------

static const struct vulcan_feature_config feat_cfg[VULCAN_NUM_GLOBAL_FEATURES] = {
    [GF_SEGS_IN]        = {
        .listener_mask = VULCAN_LISTENER_RW | VULCAN_LISTENER_EWMA,
        .ewma_alpha    = 150,    // slow-moving smoothing
        .rw_size       = 8,
    },
    [GF_BYTES_RECEIVED] = {
        .listener_mask = VULCAN_LISTENER_MINMAX | VULCAN_LISTENER_AVG,
    },
};

// --------------------------------------------------------------------------
// Step 4: update the feature store on each TCP receive event
// --------------------------------------------------------------------------

SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    s64 segs_in        = (s64)BPF_CORE_READ(tp, segs_in);
    s64 bytes_received = (s64)BPF_CORE_READ(tp, bytes_received);

    vulcan_update_feature(GF_SEGS_IN,        segs_in,        &feat_cfg[GF_SEGS_IN]);
    vulcan_update_feature(GF_BYTES_RECEIVED,  bytes_received, &feat_cfg[GF_BYTES_RECEIVED]);
    return 0;
}

// --------------------------------------------------------------------------
// Step 5: read aggregated values wherever you need them
// --------------------------------------------------------------------------

static __always_inline bool is_high_throughput(void)
{
    s64 avg_bytes = vulcan_get_avg(GF_BYTES_RECEIVED);
    s64 max_bytes = vulcan_get_max(GF_BYTES_RECEIVED);

    // Recent window average of segment count
    s64 win_segs  = vulcan_get_window_avg(GF_SEGS_IN);
    u32 win_n     = vulcan_get_window_count(GF_SEGS_IN);

    // Require at least 4 samples before trusting the window
    if (win_n < 4)
        return false;

    return avg_bytes > 1000000LL   // >1 MB average
        && win_segs  > 100         // >100 segs in recent window
        && max_bytes > 5000000LL;  // ever saw a burst >5 MB
}
