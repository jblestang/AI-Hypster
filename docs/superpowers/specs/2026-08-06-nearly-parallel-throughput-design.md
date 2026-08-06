# Nearly-Parallel Dual-VM Throughput — Design

**Status:** Approved (user 2026-08-06: “go!”)  
**Date:** 2026-08-06  
**Depends on:** Target B Phase 1 VT-x dual partitions + shared IPC

## Goal

Both partitions make progress in an interleaved (nearly parallel) fashion on the BSP. **Success** = guest-driven IPC throughput test reaches `THROUGHPUT_TARGET_PACKETS` round-trips and the host prints `ThroughputStats` + `SUCCESS`.

## Non-goals

- True concurrent BSP+AP VMLAUNCH under nested KVM (blocked; documented separately).
- Reviving host-simulated `VirtualE1000` as the Target B success path.

## Execution model

```text
BSP:
  loop until both guests shut down:
    run_vcpu_once(VM1)   # until HLT or shutdown
    run_vcpu_once(VM2)   # until HLT or shutdown
  measure TSC → ThroughputStats
```

- Guests **must** `hlt` when idle or after a send/recv burst so the host can switch.
- Hot path: no per-packet serial I/O (VMCALL putchar only for start/end banners).

## Constants

| Name | Value | Notes |
|------|-------|-------|
| `THROUGHPUT_TARGET_PACKETS` | `10_000` | QEMU-friendly; same as legacy shape, scaled for nested VT-x |
| Burst per slice | `128` | Match legacy `run_vcpu_step` burst |
| Bytes/packet (stats) | `1514` | Comparable Mbps to `Hypervisor::run` |

## Success serial

```
[HYPSTER] Throughput: <N> pkts, <pps> pps, <mbps> Mbps
[HYPSTER] SUCCESS: Dual partitions ran under hardware VT-x
```

## Guests

- **VM1:** Hello → loop send up to 128/burst → HLT → until TARGET sent → shutdown.
- **VM2:** Hello → if empty HLT; else recv/ack burst → HLT → until TARGET acked → shutdown.
