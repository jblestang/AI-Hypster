# Nearly-Parallel Throughput Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or implement inline). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Alternating VT-x slices for VM1/VM2 until IPC throughput target completes; print `ThroughputStats` and SUCCESS.

**Architecture:** Guests burst-send/recv on shared IPC and `hlt` to yield; `run_dual_partitions` round-robins `run_vcpu_once` and times the run with TSC.

**Tech Stack:** Rust `no_std`, VT-x `run_vcpu_once`, shared IPC GPA `0xFE000000`.

## Global Constraints

- Do not require concurrent AP VMLAUNCH under nested KVM.
- No per-packet serial in the hot loop.
- Target A (`run_single_guest`) must keep working.
- `THROUGHPUT_TARGET_PACKETS = 10_000`.

---

## File map

| File | Change |
|------|--------|
| `crates/hypster-core/src/throughput.rs` | **Create** — target const + `print_stats` |
| `crates/hypster-core/src/dual_run.rs` | Alternating loop + TSC stats |
| `crates/hypster-core/src/lib.rs` | `mod throughput` |
| `crates/vm1-app/src/main.rs` | Burst send + HLT until target |
| `crates/vm2-app/src/main.rs` | HLT when empty; ack until target |

---

### Task 1: Throughput module + dual_run alternating loop

- [x] Add `throughput.rs` with `THROUGHPUT_TARGET_PACKETS`, `PACKET_BYTES`, `print_stats(stats)`
- [x] Rewrite `run_dual_partitions` SMP/seq paths to shared alternating `run_vcpu_once` until both done
- [x] Print stats; return Ok only if both shut down after target

### Task 2: Guest apps

- [x] VM1: silent burst send + `hlt` until target, then shutdown
- [x] VM2: `hlt` if empty; recv/ack burst; shutdown at target

### Task 3: Verify

- [x] `cargo test -p hypster-core`
- [x] `TARGET_MODE=A ./run_qemu.sh` → SUCCESS
- [x] `TARGET_MODE=B ./run_qemu.sh` → Throughput line + SUCCESS
