# Hypster Static Hypervisor - Architecture & Non-Goals (§1.2 & §22)

## 1. Static Partitioning Contract (§1.1)
Hypster is a Type-1 static partitioning hypervisor written in `#![no_std]` Rust for x86_64 CPUs.
- **vCPU Isolation**: Physical CPU cores are bound 1-to-1 to guest vCPUs via `VcpuCorePin` (`crates/hypster-core/src/scheduler.rs`). Zero CPU overcommit.
- **Memory Isolation**: Physical RAM is split into static 2MB/4KB EPT page tables (`crates/hypster-core/src/ept.rs`). Hypervisor memory is strictly unmapped from guests.
- **IOMMU DMA Isolation**: Devices are bound to dedicated Intel VT-d IOMMU protection domains via Root/Context table entries (`crates/hypster-core/src/iommu.rs`).
- **Static Configuration**: Configuration is validated offline and at cold boot, becoming strictly immutable at steady state (`crates/hypster-core/src/config.rs`).

## 2. Explicit Non-Goals (§1.2)
To preserve safety, low latency, and low TCB complexity, the initial version of Hypster explicitly excludes:
- Live VM migration
- Runtime CPU overcommit
- Dynamic memory ballooning or swapping
- Nested virtualization
- Dynamic partition creation or destruction
- Guest VM suspend/resume
- SR-IOV dynamic virtual functions
- AMD SVM support (Intel VT-x only)
- Real-mode legacy boot (64-bit direct long-mode entry only)
- Legacy 32-bit guest execution

## 3. Host Memory Management (§22)
- **Early Boot**: Statically sized 4KB-aligned buffer tables for VMCS regions, PML4 page tables, and VT-d Context tables.
- **Steady State**: Zero heap allocations (`alloc` crate disabled in steady state). All inter-partition communication uses 64-byte aligned lock-free SPSC ring buffers (`crates/hypster-core/src/channel.rs`).
