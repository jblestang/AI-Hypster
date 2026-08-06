# TOE Modular Design & Architectural Internals (ADV_TDS.4 / ADV_INT.3)
## Hypster Type-1 Static Partitioning Separation Kernel

**Document Identifier**: `HYPS-ADV-TDS-2026-V1`  
**CC Assurance Components**: **ADV_TDS.4 (Semiformal Modular Design)** & **ADV_INT.3 (Formal Architectural Internals)**  
**Evaluation Standard**: ISO/IEC 15408:2022 (Common Criteria Part 3 / EAL5+)  
**CESTI ANSSI Track**: High-Assurance Separation Kernel Certification Track  

---

# 1. Subsystem Architecture & Module Boundaries

The Hypster TSF is structured into 9 decoupled, independent Rust modules within [`crates/hypster-core/src/`](file:///root/hypster/crates/hypster-core/src):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ HYPSTER TSF SUBSYSTEM MODULAR ARCHITECTURE                                  │
│                                                                             │
│  ┌─────────────────────────┐               ┌─────────────────────────────┐  │
│  │ vmx.rs                  │               │ ept.rs                      │  │
│  │ VMX Execution Engine    │◄─────────────►│ 4-Level EPT Page Table MMU  │  │
│  └────────────┬────────────┘               └──────────────┬──────────────┘  │
│               │                                           │                 │
│               ▼                                           ▼                 │
│  ┌─────────────────────────┐               ┌─────────────────────────────┐  │
│  │ scheduler.rs            │               │ iommu.rs                    │  │
│  │ 1-to-1 Core Pinning     │               │ Intel VT-d Protection Domain│  │
│  └────────────┬────────────┘               └──────────────┬──────────────┘  │
│               │                                           │                 │
│               ▼                                           ▼                 │
│  ┌─────────────────────────┐               ┌─────────────────────────────┐  │
│  │ channel.rs              │               │ cat.rs                      │  │
│  │ Lock-Free Atomic SPSC   │               │ Intel CAT L3 Cache Manager  │  │
│  └────────────┬────────────┘               └──────────────┬──────────────┘  │
│               │                                           │                 │
│               ▼                                           ▼                 │
│  ┌─────────────────────────┐               ┌─────────────────────────────┐  │
│  │ ras.rs                  │               │ health.rs                   │  │
│  │ Machine Check RAS       │               │ Partition Health Recovery   │  │
│  └─────────────────────────┘               └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# 2. Module Interface & Data Flow Matrix

| Subsystem Module | Responsible File | Exported Primary Types | Dependencies | Security Function Policy |
| :--- | :--- | :--- | :--- | :--- |
| **VMX Core Engine** | [`vmx.rs`](file:///root/hypster/crates/hypster-core/src/vmx.rs) | `VmxManager`, `VCpuRegisters` | Raw x86 Assembly | `FPT_SEP.1/TSF` |
| **EPT MMU Isolation** | [`ept.rs`](file:///root/hypster/crates/hypster-core/src/ept.rs) | `EptManager`, `EptEntry` | `vmx` | `FDP_ACC.2/MA` |
| **IOMMU DMA Protection** | [`iommu.rs`](file:///root/hypster/crates/hypster-core/src/iommu.rs) | `IommuManager`, `VtdContextTable` | `pci` | `FDP_ACC.2/FA` |
| **Static Core Scheduler**| [`scheduler.rs`](file:///root/hypster/crates/hypster-core/src/scheduler.rs) | `StaticScheduler`, `VcpuCorePin` | `vmx` | `FRU_RSA.2/TIME` |
| **Lock-Free SPSC IPC** | [`channel.rs`](file:///root/hypster/crates/hypster-core/src/channel.rs) | `UnidirectionalChannel`, `Packet` | `core::sync::atomic` | `FDP_ACC.2/CPA` |
| **Intel CAT Allocator** | [`cat.rs`](file:///root/hypster/crates/hypster-core/src/cat.rs) | `IntelCatManager`, `CatPolicy` | x86 CPUID Leaf 0x10 | `FRU_RSA.1/CAT` |
| **Posted Interrupt PIR** | [`pir.rs`](file:///root/hypster/crates/hypster-core/src/pir.rs) | `PostedInterruptDescriptor` | Intel APIC | `FDP_ACC.2/IA` |
| **Machine Check RAS** | [`ras.rs`](file:///root/hypster/crates/hypster-core/src/ras.rs) | `MachineCheckHandler` | x86 MCA MSRs | `FPT_FLS.1/TSF` |
| **Partition Recovery** | [`health.rs`](file:///root/hypster/crates/hypster-core/src/health.rs) | `PartitionHealthRecord` | `vmx` | `FPT_RCV.1/TSF` |

---

# 3. Inter-Module Call Dependencies & Layering

1. **Layer 0 (Hardware Abstraction Layer)**: `pci.rs`, `pir.rs`, `ras.rs`, `cat.rs` interact directly with physical CPU MSRs, PCI configuration space, and APIC vectors.
2. **Layer 1 (Virtualization Subsystems)**: `ept.rs` and `iommu.rs` build hardware translation page tables for CPU MMU and IOMMU hardware units.
3. **Layer 2 (Execution & Control Subsystems)**: `scheduler.rs` and `vmx.rs` manage vCPU state transitions and VMX non-root execution.
4. **Layer 3 (Inter-Partition & Health Services)**: `channel.rs` and `health.rs` manage SPSC packet flow and partition recovery.
