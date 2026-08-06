# Complete Functional Specification (ADV_FSP.5)
## Hypster Type-1 Static Partitioning Separation Kernel

**Document Identifier**: `HYPS-ADV-FSP-2026-V1`  
**CC Assurance Component**: **ADV_FSP.5 (Complete Formal Functional Specification)**  
**Evaluation Standard**: ISO/IEC 15408:2022 (Common Criteria Part 3 / EAL5+)  
**CESTI ANSSI Track**: High-Assurance Separation Kernel Certification Track  

---

# 1. TSF Interface (TSFI) Catalog

The Hypster TSF exposes 6 primary formal interfaces to subjects (guest partitions, hardware devices, and system extensions):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ TSF INTERFACE (TSFI) SPECIFICATION CATALOG                                  │
│                                                                             │
│  TSFI Identifier   Interface Name             Privilege Role  Error Model   │
│  ───────────────   ────────────────────────   ──────────────  ───────────   │
│  TSFI_EPT_MAP      EptManager::map_region     TSF Core        EPT Trap 48   │
│  TSFI_MMIO_PASS    map_mmio_passthrough       System Part.    GP Fault      │
│  TSFI_IOMMU_DEV    assign_device_bdf          System Part.    IOMMU Fault   │
│  TSFI_IPC_SEND     UnidirectionalChannel::send Normal / System Ring Full    │
│  TSFI_IPC_RECV     UnidirectionalChannel::recv Normal / System Ring Empty   │
│  TSFI_HEALTH_RST   record_fault_and_recover   TSF Core        Auto Restart  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# 2. Detailed TSFI Interface Specifications

## 2.1 `TSFI_EPT_MAP`: Physical EPT Memory Region Mapping
- **Function Signature**: `pub fn map_region(&mut self, gpa: u64, hpa: u64, size: usize)` ([`ept.rs`](file:///root/hypster/crates/hypster-core/src/ept.rs#L75))
- **Description**: Allocates 4-level Extended Page Table entries ($L_4 \to L_3 \to L_2 \to L_1$) mapping Guest Physical Address `gpa` to Host Physical Address `hpa`.
- **Input Parameters**:
  - `gpa`: 64-bit Guest Physical Base Address (4KB page-aligned).
  - `hpa`: 64-bit Host Physical Base Address (4KB page-aligned).
  - `size`: Allocation size in bytes (multiple of 4096).
- **Security Attribute Checks**: `hpa` must reside strictly within the partition's assigned physical RAM boundary ($[0x140013000, 0x140212FFF]$ for VM1). Allocation targeting $M_{\text{TSF}} = [0x140000000, 0x140012FFF]$ is explicitly rejected.
- **Error Conditions & Traps**: If a guest vCPU issues an unmapped GPA translation, CPU hardware traps `VM_EXIT_REASON_EPT_VIOLATION` (Exit Reason 48).

---

## 2.2 `TSFI_MMIO_PASS`: EPT Uncacheable MMIO Passthrough Mapping
- **Function Signature**: `pub fn map_mmio_passthrough(&mut self, gpa: u64, hpa: u64, size: usize)` ([`ept.rs`](file:///root/hypster/crates/hypster-core/src/ept.rs#L125))
- **Description**: Maps physical PCI BAR MMIO address `hpa` directly into guest partition EPT tables with memory type `UC` (Uncacheable, type 0).
- **Privilege Role**: **System Partition Only** (e.g. `VM2-Beta` egress driver domain).
- **Security Attribute Checks**: `hpa` must match an assigned physical PCI BAR MMIO region discovered by `PciBusScanner::read_bar0_64()`.

---

## 2.3 `TSFI_IOMMU_DEV`: Intel VT-d IOMMU Device BDF Assignment
- **Function Signature**: `pub fn assign_device_bdf(&mut self, bus: u8, dev: u8, func: u8, domain_id: u32)` ([`iommu.rs`](file:///root/hypster/crates/hypster-core/src/iommu.rs#L85))
- **Description**: Programs VT-d context table entry for PCI Bus/Device/Function `(bus, dev, func)`, binding the physical device to Protection Domain `domain_id`.
- **Security Attribute Checks**: BDF must belong to the caller's assigned PCI configuration entry. DMA accesses outside domain RAM bounds trigger hardware IOMMU fault flag (`F` bit 25 in `VTD_REG_GSTS`).

---

## 2.4 `TSFI_IPC_SEND`: Lock-Free SPSC Channel Packet Push
- **Function Signature**: `pub fn send(&mut self, data: &[u8]) -> bool` ([`channel.rs`](file:///root/hypster/crates/hypster-core/src/channel.rs#L79))
- **Description**: Atomically copies packet payload `data` into ring buffer index `tail & CHANNEL_QUEUE_MASK` and updates atomic `tail` with `Ordering::Release`.
- **Error Model**: Returns `false` if queue is full (`tail - head >= CHANNEL_QUEUE_CAPACITY`), preserving buffer bounds without blocking.

---

## 2.5 `TSFI_IPC_RECV`: Lock-Free SPSC Channel Packet Pop
- **Function Signature**: `pub fn recv(&mut self) -> Option<Packet>` ([`channel.rs`](file:///root/hypster/crates/hypster-core/src/channel.rs#L110))
- **Description**: Atomically checks `head` against `tail` with `Ordering::Acquire`, reads packet payload, and updates `head` with `Ordering::Release`.
- **Error Model**: Returns `None` if queue is empty.

---

## 2.6 `TSFI_HEALTH_RST`: Partition Fault Recovery & Reset
- **Function Signature**: `pub fn record_fault_and_recover(&mut self, name: &'static str, regs: &mut VCpuRegisters)` ([`health.rs`](file:///root/hypster/crates/hypster-core/src/health.rs#L40))
- **Description**: Traps guest `TRIPLE_FAULT` events, logs fault counters, resets vCPU registers (`RIP = 0x1000`, `RSP = 0xF000`), and restarts partition execution.
