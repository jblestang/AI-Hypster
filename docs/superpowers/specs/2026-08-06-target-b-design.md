# Target B — Two Static Partitions (Milestone 2) Design Spec

**Status:** Approved (sequential dual-VM first, then per-core AP loops)  
**Date:** 2026-08-06  
**Depends on:** Target A (`run_single_guest`, `guest_run.rs` VT-x path)

## Goal

Run two statically configured guest partitions under hardware VT-x with non-overlapping RAM, optional shared IPC at a fixed HPA, scheduler-driven execution, and a data path that does not rely on host-side `VirtualE1000` polling.

## Success criteria

### Phase 1 — Sequential dual-VM (QEMU nested KVM, boot CPU)

1. UEFI boots `Hypervisor` with two partition buffers; both guests reach `VMLAUNCH`.
2. Each partition has its own EPT; RAM ranges from `hardware_config.yaml` do not overlap; hypervisor region is not guest-mapped.
3. `SHARED_IPC_RING_BASE_HPA` is mapped into both guests at GPA `0xFE000000` (read/write).
4. `scheduler.next_vcpu()` alternates VM1 vCPU0 and VM2 vCPU0 on one physical core; fake hardcoded schedule table retired.
5. Guests exchange at least one message via shared ring (no `Hypervisor::channel_*` BSS in hot path).
6. `VirtualE1000` removed from VM1 ingress hot path; VM2 egress uses EPT MMIO passthrough or MMIO VM-exit emulation.
7. Serial shows both guests alive and IPC success banner.

### Phase 2 — Per-core execution (QEMU 2+ vCPUs, nested KVM)

1. YAML `pcpu_affinity` drives `schedule_table` (VM1→core0, VM2→core1).
2. AP on core 1 runs `vcpu_run_loop` with pinned VMCS and core-local exit stack.
3. INIT-SIPI-SIPI path from `scheduler.rs` used for AP bring-up.
4. Shared IPC ring uses cross-core atomics without data races (existing `channel.rs` fences).
5. Minimum interrupt injection: virtual APIC timer or posted-interrupt doorbell for IPC wake (stretch within Phase 2).

## Non-goals (later milestones)

- Full VT-d I/O page tables and fault handling on bare metal.
- VM2 second vCPU SMP inside guest (YAML defines 1 vCPU per partition for M2).
- Production NIC driver completeness beyond assigned egress passthrough demo.

## Architecture

```text
UEFI (boot CPU)
  └─ Hypervisor::new() / run_dual_partitions()
       ├─ VM1 EPT → VM1_RAM_HPA (YAML)
       ├─ VM2 EPT → VM2_RAM_HPA (YAML)
       ├─ Both EPTs → SHARED_IPC @ GPA 0xFE000000
       ├─ VM2 EPT → PCI BAR MMIO passthrough (egress NIC)
       └─ Run loop:
            Phase 1: scheduler.next_vcpu() → enter_guest(vcpu) round-robin
            Phase 2: BSP loop + AP per pinned core
```

## Memory layout (from `hardware_config.yaml`)

| Region | HPA | Size |
|--------|-----|------|
| Hypervisor | `0x140000000` | 76 KiB |
| VM1 RAM | `0x140013000` | 2 MiB |
| VM2 RAM | `0x140213000` | 2 MiB |
| Shared IPC | `0x140413000` | 20 KiB |
| Egress NIC BAR0 | `0xC1080000` | 128 KiB |

UEFI allocates partition buffers at **actual** HPAs via static aligned buffers or explicit placement; YAML sizes drive EPT `map_region` calls.

## Guest physical addresses (shared contract)

| GPA | Use |
|-----|-----|
| `0x1000` | Entry (`GUEST_ENTRY_GPA`) |
| `0x8000` | Guest CR3 / page tables |
| `0x7000` | Minimal GDT |
| `0x1F_F000` | Stack top |
| `0xFE000000` | Shared IPC region (both guests) |
| `0x20000000` | VM2 MMIO window (NIC BAR mapping) |

## Workstream designs

### 1. Per-partition EPT

- `EptManager::map_region(gpa, hpa, size)` driven by `PARTITION_RAM_SIZE` and partition HPA.
- New `EptManager::map_shared_ipc(gpa, hpa, size)` — 4 KiB leaves, same as Target A unaligned HPA fix.
- `EptManager::guard_hypervisor_region(hpa, size)` — no mapping (validation only at build time via `build.rs`).
- Extend beyond 512×4 KiB when partition RAM > 2 MiB (additional PD entries).

### 2. Execution model

**Phase 1:** Single `ACTIVE_VCPU` table keyed by `(vm_id, vcpu_id)`; generalize `guest_run.rs` exit handler to dispatch on current VMCS. One `enter_guest(vcpu, ept_pml4_pa)` call per scheduler step; only one guest in VMX non-root at a time.

**Phase 2:** Per-vCPU `HOST_EXIT_STACK`, `reload_host_rsp`, VMCS region (`VMCS_REGION_1` / `VMCS_REGION_2` today; add as needed). AP entry at `ap_trampoline` → `vcpu_run_loop`. BSP continues VM1; AP runs VM2.

### 3. Shared IPC at HPA

Layout at `SHARED_IPC_RING_BASE_HPA`:

```text
offset 0:     UnidirectionalChannel  VM1 → VM2  (~24 KiB with 16 slots)
offset 24KiB: UnidirectionalChannel  VM2 → VM1
```

`UnidirectionalChannel` remains `#[repr(C)]` with existing atomics. Hypervisor `init_ipc_at_hpa()` zeroes region and sets `producer_id`/`consumer_id`. Guests access via GPA `0xFE000000` + offset.

Doorbell (Phase 2): `GLOBAL_PIR_MANAGER.post_vector()` or virtual APIC timer tick.

### 4. Scheduler

- Build `schedule_table` from YAML: partition1 `pcpu_affinity: 0`, partition2 `pcpu_affinity: 1`.
- `StaticScheduler::from_config()` replaces hardcoded `add_pin(1,1,2,2)`.
- `next_vcpu()` used by Phase 1 run loop.
- Align `VM1_VCPUS` / `VM2_VCPUS` in `lib.rs` to `1` (match YAML).

### 5. Data path / VirtualE1000 removal

| VM | Before | After |
|----|--------|-------|
| VM1 | Host sets `e1000.icr`, polls in `run_vcpu_step` | Guest reads IPC ring at GPA `0xFE000000`; no `VirtualE1000` in step |
| VM2 | Mixed passthrough + channel | TX via MMIO passthrough to real BAR; RX/forward via IPC ring |

`Hypervisor::run()` packet simulation loop replaced by `run_dual_partitions()` with guest-driven IPC demo (vm1-app sends string, vm2-app receives and acks).

### 6. Interrupts (Phase 2 minimum)

- Enable virtual APIC timer in VMCS or periodic VM-exit for doorbell polling fallback.
- Wire `GLOBAL_PIR_MANAGER.configure_vmcs(vcpu)` during VMCS setup.
- Notification vector `0xF2` from YAML `posted_interrupts.notification_vector`.

### 7. IOMMU (Phase 2 stretch)

- Keep `create_domain()` aligned with partition HPAs from config.
- Software `validate_dma()` until I/O PTs land; document QEMU vs bare-metal divergence.

## Key files

| File | Role |
|------|------|
| `crates/hypster-uefi/src/main.rs` | Dual buffers, `run_dual_partitions` |
| `crates/hypster-core/src/lib.rs` | `Hypervisor`, YAML constants, run loops |
| `crates/hypster-core/src/guest_run.rs` | Multi-vCPU VT-x entry/exit |
| `crates/hypster-core/src/ept.rs` | Partition + IPC mapping |
| `crates/hypster-core/src/channel.rs` | Ring layout (reuse) |
| `crates/hypster-core/src/scheduler.rs` | YAML-driven pins, AP bring-up |
| `crates/hypster-core/src/vm.rs` | Strip VirtualE1000 from hot path |
| `crates/hypster-core/src/vmx.rs` | Extra VMCS regions, per-vCPU stacks |
| `crates/vm1-app`, `crates/vm2-app` | IPC-aware guests |
| `run_qemu.sh` | Build both guests, `-smp 2` for Phase 2 |

## Risks

| Risk | Mitigation |
|------|------------|
| Nested KVM dual-VMCS | Phase 1 single active guest; only one `VMPTRLD` active per step |
| IPC SMP races | Acquire/Release in `channel.rs`; validate with Phase 2 stress |
| QEMU IOMMU ≠ bare metal | Phase 2 IOMMU marked QEMU-first; bare-metal checklist separate |
| UEFI AP bring-up | Use existing INIT-SIPI-SIPI; test with `-smp 2` |

## Approval

- **Approach:** Phase 1 sequential on boot CPU, then Phase 2 per-core AP loops.
- **Approved by user:** 2026-08-06
