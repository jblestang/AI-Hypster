# Security Architecture Description (ADV_ARC.1)
## Hypster Type-1 Static Partitioning Separation Kernel

**Document Identifier**: `HYPS-ADV-ARC-2026-V1`  
**CC Assurance Component**: **ADV_ARC.1 (Architectural Design & Security Architecture Description)**  
**Evaluation Standard**: ISO/IEC 15408:2022 (Common Criteria Part 3 / EAL5+)  
**CESTI ANSSI Track**: High-Assurance Separation Kernel Certification Track  

---

# 1. Architectural Security Principles

The Hypster TSF Security Architecture enforces four core architectural properties mandated by Common Criteria `ADV_ARC.1`:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ HYPSTER SECURITY ARCHITECTURE (ADV_ARC.1)                                   │
│                                                                             │
│  1. TSF Self-Protection     ──► Hypervisor RAM unmapped in all EPTs         │
│  2. Domain Separation       ──► 1-to-1 Core Pinning & VT-d DMA Domains      │
│  3. Non-Bypassability       ──► Hardware VMX Non-Root Traps                 │
│  4. Secure Initialization   ──► Static Schema Validation & Cold-Boot Reset  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# 2. TSF Self-Protection

## 2.1 Memory Space Isolation
The TSF execution domain ($M_{\text{TSF}} = [0x140000000, 0x140012FFF]$) contains the hypervisor executable binary, host GDT/IDT/TSS tables, per-CPU host stacks, VMCS structures, EPT page directory tables, and VT-d context tables.

- **EPT Exclusion**: During system initialization, `EptManager::new(vm_id)` allocates page table entries **only** for the guest partition's assigned physical RAM range ($[0x140013000, 0x140212FFF]$ for VM1 and $[0x140213000, 0x140412FFF]$ for VM2).
- **Hardware Enforcement**: When a vCPU executes in VMX non-root operation (guest mode), the CPU hardware MMU evaluates every guest physical address against the active Extended Page Table Pointer (`EPTP`). Because no page table entry maps $M_{\text{TSF}}$, any guest instruction attempting to read, write, or execute hypervisor memory triggers an instantaneous hardware `EPT Violation` trap (Exit Reason 48), preventing unauthorized access.

## 2.2 Control Register & MSR Protection
- **Guest CR0/CR4 Fixed MSR Enforcement**: `vmx.rs` queries hardware MSRs `IA32_VMX_CR0_FIXED0/FIXED1` (`0x486`/`0x487`) and `IA32_VMX_CR4_FIXED0/FIXED1` (`0x488`/`0x489`). Guest `CR0` and `CR4` writes are dynamically bitmasked (`cr0 = (cr0 | fixed0) & fixed1`) to guarantee that guest vCPUs cannot disable protection mechanisms (e.g. `CR0.PE` or `CR0.PG`).
- **Restricted System MSRs**: Host MSRs (such as `IA32_PAT`, `IA32_EFER`, and VT-d control registers) are intercepted via VMCS MSR bitmap controls. Attempts by guest partitions to write host MSRs trigger a `VM_EXIT_REASON_MSR_WRITE` trap.

---

# 3. Domain Separation

## 3.1 Spatial Domain Separation
Guest partitions $P_1$ and $P_2$ occupy mutually disjoint physical RAM pools:
- **VM1-Alpha**: $HPA \in [0x140013000, 0x140212FFF]$ (1 GB RAM).
- **VM2-Beta**: $HPA \in [0x140213000, 0x140412FFF]$ (1 GB RAM).
- **Shared Memory Channel**: $HPA \in [0x140413000, 0x140417FFF]$ (Lock-free SPSC ring buffer).

EPT page tables strictly restrict each guest vCPU to its own declared physical RAM pool and the designated shared memory window.

## 3.2 Temporal Domain Separation & Core Pinning
- **1-to-1 Physical Core Allocation**: `scheduler.rs` binds vCPUs to physical CPU cores without time-slicing or dynamic rescheduling (`vCPU 0 -> Core 0`, `vCPU 1 -> Core 1`).
- **Intel CAT L3 Cache Isolation**: `cat.rs` programs `IA32_L3_MASK_0` (`0x00FF`) and `IA32_L3_MASK_1` (`0xFF00`) MSRs, reserving distinct L3 cache ways for each partition and eliminating cross-core cache interference (`T.DEPLETION`).

---

# 4. Non-Bypassability

## 4.1 Hardware VMX Non-Root Enforcement
All guest application code and driver payloads execute in **VMX Non-Root Operation**. Hardware Intel VT-x logic enforces that privilege-escalating instructions (`VMLAUNCH`, `VMRESUME`, `VMXON`, `VMXOFF`, `INVD`, `WBINVD`, `MOV CR3`, `HLT`) automatically suspend guest execution and transfer control back to host hypervisor assembly stubs in VMX Root Operation (`vmx_launch_or_resume`).

## 4.2 Intel VT-d IOMMU DMA Non-Bypassability
Direct Memory Access (DMA) transactions bypass the CPU MMU. To prevent DMA bypass attacks, `iommu.rs` programs the physical VT-d IOMMU `RTADDR` register. All PCI Express bus-mastering transactions are intercepted by hardware IOMMU page tables, restricting physical devices to the DMA protection domain of their assigned partition.

---

# 5. Secure Initialization & Boot Sequence

1. **UEFI Hand-off (`hypster-uefi`)**: Cold-boot loader initializes 64-bit long mode, validates static configuration signatures, and jumps to `hypster-core`.
2. **TSF Environment Setup**: `vmx.rs` programs Host GDT, IDT, TSS, CR0/CR3/CR4, and `VMCS_HOST_TR_SELECTOR = 0x0`.
3. **Hardware Table Construction**: `ept.rs` builds 4-level EPT page tables; `iommu.rs` builds VT-d root/context tables; `cat.rs` programs L3 cache masks.
4. **Partition Launch**: `vmx_launch_or_resume` executes `VMLAUNCH` on Physical Cores 0 and 1 concurrently, entering secure steady-state execution.
