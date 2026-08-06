1. Define the hypervisor contract first

1.1 Static-partitioning invariants

* Every logical CPU belongs to exactly one of:
    * the hypervisor,
    * one guest partition,
    * an explicitly unused/offline set.
* Every allocatable physical-memory page has exactly one owner.
* Hypervisor memory is inaccessible to every guest.
* Every MMIO region has an explicit owner or is denied to all guests.
* Every interrupt source has one defined routing policy.
* Every PCI function is assigned to at most one guest.
* Every DMA-capable device is behind a correctly configured IOMMU domain.
* No CPU, RAM region, interrupt, or device can silently fall through to a default guest.
* Shared resources are explicitly declared, never inferred.
* Configuration is validated completely before any guest starts.
* Configuration becomes immutable once the system enters steady state.
* A guest cannot create, resize, destroy, or reconfigure another partition.
* No runtime CPU overcommit exists unless time partitioning is deliberately added.
* No implicit memory ballooning, swapping, deduplication, or overcommit exists.
* A guest failure cannot alter another guest’s ownership metadata.
* A hypervisor failure policy is defined: halt, reset, isolate, or enter a diagnostic state.

1.2 Explicit non-goals

Document whether the first version excludes:

* Live migration.
* CPU overcommit.
* Device emulation.
* Nested virtualization.
* Suspend/resume.
* CPU hot-plug.
* Memory hot-plug.
* PCI hot-plug.
* SMM virtualization.
* Confidential-computing technologies.
* Dynamic partition creation.
* Guest snapshots.
* Cross-vendor guest migration.
* 32-bit guests.
* Real-mode guest boot.
* Legacy PIC/PIT emulation.
* Nested paging with huge pages.
* Interrupt posted delivery.
* SR-IOV.
* NUMA-aware placement.
* Simultaneous Intel VMX and AMD SVM support.

Keeping these out of scope initially is usually the difference between a small static hypervisor and an unfinished general-purpose VMM.

2. Choose the activation model

2.1 Cold-boot model

The hypervisor owns boot from firmware onward.

* Define UEFI, Multiboot2, or custom boot protocol.
* Capture the firmware memory map.
* Reserve hypervisor code, data, stacks, page tables, VMCS/VMCB objects, logs, and configuration.
* Initialize all hardware that guests will not own.
* Load guest images into their assigned memory.
* Construct each guest’s initial architectural state.

2.2 Jailhouse-like late activation

A management OS initializes the machine, then transfers CPUs and devices to the hypervisor.

* Define exactly what state is inherited from the root OS.
* Freeze or offline secondary CPUs safely.
* Prevent the root OS from retaining mappings to reassigned memory.
* Detach device drivers before device reassignment.
* Quiesce DMA before updating IOMMU ownership.
* Capture APIC, IOAPIC, PCI, IOMMU, timer, and power-management state.
* Define rollback behavior if activation fails halfway.
* Prove that partially transferred ownership cannot occur.
* Prevent Linux or another root OS from re-enumerating removed resources.
* Decide whether deactivation is supported; omitting it greatly simplifies correctness.

Jailhouse uses deferred initialization and relies on Linux for complex platform setup before partitioning resources. That approach reduces the hypervisor’s platform-initialization burden but makes the takeover protocol a critical part of the trusted design.  

3. Platform discovery and configuration

3.1 Firmware inputs

* Validate UEFI memory descriptors or Multiboot memory-map entries.
* Parse ACPI safely with bounds and checksum validation.
* Locate and validate:
    * RSDP.
    * XSDT/RSDT.
    * MADT.
    * MCFG.
    * DMAR on Intel.
    * IVRS on AMD.
    * HPET if used.
    * SRAT and SLIT if NUMA is supported.
    * FADT only where needed.
* Reject malformed, overlapping, truncated, or duplicate tables.
* Do not trust firmware-supplied physical addresses without checking them against the physical-address width and memory map.
* Decide whether ACPI tables are exposed, filtered, copied, or replaced for guests.
* Ensure guests do not discover devices or CPUs they do not own.

3.2 Static configuration format

* Give the format a magic value and version.
* Include total size and per-section lengths.
* Use checked integer arithmetic for all offsets and sizes.
* Reject integer overflow and truncation.
* Reject unknown mandatory fields.
* Validate alignment requirements.
* Validate physical-address widths.
* Validate canonical virtual addresses.
* Detect duplicate CPU assignments.
* Detect overlapping RAM regions.
* Detect RAM/MMIO overlaps.
* Detect overlapping PCI assignments.
* Detect interrupt-vector conflicts.
* Detect IOMMU-group conflicts.
* Detect shared-page declarations inconsistent between participants.
* Validate guest entry points and boot structures lie in guest-owned RAM.
* Validate each image fits wholly in its destination region.
* Hash or sign the configuration where secure boot matters.
* Generate the configuration from a typed schema rather than hand-maintained offsets.
* Provide an offline configuration validator independent of the hypervisor.

4. x86 CPU capability discovery

Run capability discovery independently on every CPU package or validate that all participating CPUs are equivalent.

* Check CPUID availability assumptions.
* Enumerate maximum basic and extended CPUID leaves.
* Detect vendor.
* Record family, model, stepping, and microcode revision.
* Check long-mode support.
* Determine physical- and linear-address widths.
* Check NX support.
* Check invariant or constant TSC properties.
* Enumerate XSAVE components.
* Enumerate APIC and x2APIC support.
* Enumerate PCID and INVPCID if used.
* Enumerate SMEP, SMAP, UMIP, CET, PKU, and other host-hardening features.
* Detect virtualization support:
    * Intel VMX.
    * AMD SVM.
* Check whether firmware has disabled or locked virtualization.
* Check EPT or NPT support.
* Check nested-paging access/dirty-bit support.
* Check large-page support for nested paging.
* Check unrestricted guest support on Intel if booting guests below protected long mode.
* Check virtual APIC, APIC-register virtualization, posted interrupts, or AVIC only if planned.
* Check VPID or ASID capacity.
* Check TSC offset/scaling support.
* Check RDTSCP.
* Check VM-entry and VM-exit MSR load/store capacities.
* Check interrupt-window and NMI-window controls.
* Check preemption timer support only if needed.
* Check instruction intercept capabilities needed for your guest model.
* Fail closed if a required feature is absent.
* Build an explicit normalized feature set shared by all CPUs assigned to one guest.

5. Host execution environment

5.1 Per-CPU host state

Each logical CPU needs private, correctly aligned state:

* Bootstrap stack.
* Runtime stack.
* Optional exception/IST stacks.
* Per-CPU data.
* VMCS or VMCB.
* Host GDT.
* Host IDT.
* Host TSS.
* Host page-table root.
* Guest/vCPU state.
* Local interrupt state.
* VM-exit scratch area.
* FPU/SIMD save area if used by the hypervisor.
* Logging buffer or emergency diagnostic slot.
* CPU-local panic state.

Verify:

* Cache-line alignment where false sharing matters.
* Required VMCS/VMCB alignment.
* No per-CPU object spans unowned or unmapped pages.
* CPU-local pointers cannot reference another CPU’s mutable state accidentally.
* Per-CPU state is initialized before enabling interrupts or virtualization.

5.2 Host descriptor tables

* GDT entries have correct type, privilege, present, long-mode, and granularity bits.
* TSS descriptor is valid and references writable hypervisor memory.
* RSP0 is correct if privilege transitions are used.
* IST entries exist for at least catastrophic exceptions where desired:
    * Double fault.
    * NMI.
    * Machine check.
* IDT entries cover all architectural exceptions.
* Gate types and DPLs are intentional.
* Reserved IDT bits are zero.
* Exception stubs distinguish exceptions that push an error code.
* Stack alignment at the Rust boundary follows the ABI.
* swapgs usage, if any, is formally defined and balanced.
* Host FS/GS base handling cannot be corrupted by a guest transition.

5.3 Host control state

* CR0 satisfies architectural and virtualization fixed-bit constraints.
* CR4 satisfies architectural and virtualization fixed-bit constraints.
* CR3 references a valid, aligned root table.
* EFER.LME/LMA/NXE are coherent.
* XCR0 matches the XSAVE state the hypervisor is prepared to preserve.
* Host PAT is intentional.
* Debug registers are initialized or explicitly unsupported.
* CET state is handled if enabled.
* PKU/PKS state is handled if enabled.
* Speculation-control MSRs are initialized according to policy.

6. Multiprocessor startup

* Enumerate APIC IDs from validated firmware data.
* Handle non-contiguous APIC IDs.
* Handle x2APIC IDs wider than 8 bits.
* Do not index arrays directly by unbounded APIC ID.
* Allocate per-CPU state before bringing up APs.
* Follow the correct INIT-SIPI-SIPI startup sequence when applicable.
* Place the AP trampoline below 1 MiB if required by the startup method.
* Identity-map trampoline code and data correctly.
* Keep trampoline data race-free across simultaneous AP startup.
* Use memory barriers around startup flags.
* Time out and fail deterministically if an AP does not start.
* Prevent a late AP from entering an already running guest incorrectly.
* Synchronize all CPUs before enabling guests.
* Define the bootstrap processor’s special responsibilities.
* Ensure a CPU cannot be assigned to two cells during takeover.
* Define behavior for SMT siblings.
* Optionally prohibit splitting SMT siblings across different assurance domains.
* Define CPU offlining and fatal-CPU behavior.

7. Intel VMX path

The current Intel SDM is authoritative for VMX operation, VMCS fields, control dependencies, VM-entry checks, EPT, APIC virtualization, and VM-exit behavior.  

7.1 Entering VMX operation

* Check IA32_FEATURE_CONTROL.
* Verify VMX is enabled outside SMX.
* Handle the lock bit correctly.
* Set CR4.VMXE.
* Read IA32_VMX_BASIC.
* Extract VMCS revision ID.
* Check VMCS region size.
* Check required memory type.
* Allocate 4 KiB-aligned VMXON and VMCS regions.
* Write the revision ID correctly.
* Zero or initialize the remaining VMX region as required.
* Satisfy IA32_VMX_CR0_FIXED0/FIXED1.
* Satisfy IA32_VMX_CR4_FIXED0/FIXED1.
* Execute VMXON and check both carry and zero flags.
* Distinguish VMfailInvalid from VMfailValid.
* Execute VMCLEAR before first use.
* Execute VMPTRLD.
* Record the VM-instruction error field on failures.

7.2 VMX controls

For every control field:

* Read the relevant capability MSR.
* Compute controls as (desired | must_be_1) & allowed_1.
* Prefer true-control MSRs where supported.
* Verify dependencies between primary, secondary, tertiary, entry, and exit controls.
* Reject unsupported desired bits.
* Avoid blindly copying control constants from another CPU model.

Check policies for:

* Pin-based controls.
* Primary processor-based controls.
* Secondary processor-based controls.
* VM-exit controls.
* VM-entry controls.
* Exception bitmap.
* Page-fault error-code mask and match.
* CR0/CR4 guest-host masks.
* CR0/CR4 read shadows.
* MSR bitmap.
* I/O bitmaps A and B.
* TSC offset.
* TSC multiplier if used.
* EPT pointer.
* VPID.
* APIC-access page.
* Virtual-APIC page.
* Posted-interrupt descriptor if used.
* VM-function controls if used.
* EPTP list if used.
* PML address if used.

7.3 VMCS host-state fields

* Host CR0, CR3, and CR4.
* Host RSP and RIP.
* Host selector fields.
* Host FS/GS/TR/GDTR/IDTR bases.
* Host IA32_EFER.
* Host IA32_PAT if loaded on exit.
* Host SYSENTER state if relevant.
* Host selectors satisfy VM-entry/exit validation.
* Host RIP points to an assembly VM-exit entry stub, not directly to arbitrary Rust.
* Host stack has required alignment at the Rust call boundary.

7.4 VMCS guest state

* Guest CR0, CR3, CR4.
* Guest RSP, RIP, and RFLAGS.
* All segment selectors, bases, limits, and access-right fields.
* GDTR and IDTR bases and limits.
* TR and LDTR state.
* IA32_EFER.
* PAT if managed.
* SYSENTER state where relevant.
* DR7.
* Pending debug exceptions.
* Interruptibility state.
* Activity state.
* VMCS link pointer.
* Guest PDPTE fields when required.
* Guest-state consistency checks for the selected execution mode.
* Canonical address checks.
* Correct unusable-segment encoding.
* No accidental use of host physical addresses as guest linear addresses.

7.5 VM entry and launch

* Assembly wrapper preserves all guest-visible registers not managed by hardware.
* VMLAUNCH is used exactly once per cleared VMCS.
* VMRESUME is used after successful launch.
* Launch state is tracked correctly.
* Failure paths retrieve VM-instruction error.
* Guest register state is not overwritten while reporting an entry failure.
* Interrupt state is well-defined around launch.
* No lock or borrowed Rust reference remains live across VM entry.
* The compiler cannot assume a normal function return from guest entry.

8. AMD SVM path

The current AMD64 APM Volume 2 is authoritative for SVM, VMCB layout, intercepts, nested paging, ASIDs, event injection, and VMRUN behavior.  

* Check CPUID.80000001H:ECX.SVM.
* Check VM_CR.SVMDIS.
* Set EFER.SVME.
* Read SVM feature leaf 8000000AH.
* Allocate a correctly aligned VMCB.
* Allocate a host-save area.
* Program VM_HSAVE_PA.
* Define all required intercept vectors.
* Initialize I/O permission map.
* Initialize MSR permission map.
* Configure ASID and validate nonzero requirements.
* Configure TLB-control policy.
* Configure nested paging.
* Initialize guest control and state areas.
* Set clean bits correctly; initially, conservatively mark state dirty.
* Handle VMRUN, VMLOAD, and VMSAVE semantics correctly.
* Decode EXITCODE, EXITINFO1, EXITINFO2, and EXITINTINFO.
* Handle NRIP only if supported and valid for the exit.
* Implement event injection using EVENTINJ.
* Handle virtual interrupt state and interrupt shadow.
* Validate GIF handling and CLGI/STGI policy.
* Validate AVIC only if deliberately supported.
* Never assume Intel VMX behavior maps one-for-one to AMD SVM.

A clean design should expose a vendor-neutral vCPU abstraction while keeping VMX and SVM structures, control synthesis, and exit decoding in separate backend modules.

9. Nested page tables: EPT or NPT

9.1 Ownership model

* Use host physical addresses as the final page-table targets.
* Never let a guest supply an unchecked host physical address.
* Build nested mappings only from validated partition regions.
* Keep hypervisor memory completely unmapped from guests.
* Keep other guests’ memory completely unmapped.
* Map MMIO only for explicitly assigned devices.
* Map shared memory only in declared participants.
* Apply read/write/execute permissions per region.
* Default to execute-disabled for data and MMIO.
* Default to read-only for immutable guest firmware or boot data where practical.
* Prevent page-table construction from wrapping at the end address.
* Reject zero-sized and non-page-aligned mappings unless deliberately normalized.
* Validate that [base, base + size) does not overflow.
* Ensure a region cannot be mapped twice with conflicting cache types.

9.2 Page-table implementation

* Implement all required paging levels for the supported physical-address width.
* Mask reserved address bits.
* Keep software metadata out of hardware-reserved bits unless guaranteed safe.
* Use 4 KiB pages first; add 2 MiB or 1 GiB pages only after split/merge correctness is proven.
* Handle mixed page sizes without aliasing.
* Prevent two writable aliases of sensitive memory.
* Ensure page-table pages themselves are hypervisor-owned.
* Ensure guests cannot DMA into nested page tables.
* Use correct EPT memory types on Intel.
* Handle EPT misconfiguration separately from EPT violation.
* Decode nested-page-fault qualifications accurately.
* Define access/dirty-bit policy.
* Define whether accessed/dirty state is ever consumed.
* Invalidate stale translations after every mapping or permission change.
* Use INVEPT correctly on Intel.
* Use appropriate ASID/TLB invalidation on AMD.
* Use INVVPID when guest linear translations require it.
* Include memory-ordering barriers around publication of new table entries.
* Verify page-table modifications cannot race with a running vCPU.
* Prefer constructing all tables before guest launch and making them immutable.

9.3 Memory types and aliases

* Understand interaction among MTRRs, PAT, EPT memory type, and host mappings.
* Avoid mapping the same physical page with conflicting cacheability.
* Use uncacheable mappings for device MMIO unless platform requirements specify otherwise.
* Do not map normal RAM as device memory.
* Validate framebuffer and persistent-memory cache requirements separately.
* Determine whether guest PAT/MTRR writes are trapped, ignored, virtualized, or prohibited.
* Handle cache flushing before ownership transfer where required.

10. Guest physical-memory layout and boot

For every supported guest type, define a precise ABI.

10.1 Generic requirements

* Entry RIP.
* Initial RSP.
* Initial RFLAGS.
* Initial control-register state.
* Initial segment state.
* Initial GDT and IDT expectations.
* Initial paging mode.
* Boot-parameter address.
* Memory map visible to the guest.
* CPU topology visible to the guest.
* Interrupt-controller model visible to the guest.
* Timer model visible to the guest.
* Device-discovery model.
* Shutdown/reboot mechanism.
* Hypercall ABI, if any.
* Shared-memory notification ABI, if any.

10.2 Linux guests

* Implement the x86 Linux boot protocol version you claim to support.
* Validate setup header fields.
* Place command line, initrd, and boot parameters in allowed ranges.
* Build e820 entries without exposing foreign memory.
* Decide whether to use bzImage boot, EFI stub, PVH, or another protocol.
* Provide ACPI tables consistent with assigned CPUs and devices.
* Ensure APIC IDs in MADT match guest-visible topology.
* Hide unassigned PCI host bridges and functions.
* Ensure Linux cannot access host firmware runtime services unexpectedly.
* Test CPU bring-up for all assigned vCPUs.
* Test guest reboot and shutdown behavior.

10.3 Bare-metal or RTOS guests

* Define whether they enter in 64-bit long mode directly.
* Define identity-mapping assumptions.
* Define initial stack ownership.
* Define per-vCPU entry points.
* Define how secondary CPUs are released.
* Provide a stable interrupt-vector convention.
* Provide explicit MMIO and shared-memory descriptors.
* Avoid making guests parse raw host ACPI unless necessary.

11. CPUID virtualization

Even with static assignment, raw CPUID passthrough is rarely safe.

* Intercept CPUID.
* Expose a stable vendor and feature policy.
* Hide VMX or SVM unless nested virtualization is supported.
* Hide unsupported XSAVE components.
* Keep CPUID topology leaves coherent with assigned vCPUs.
* Keep APIC IDs coherent across all topology leaves.
* Keep physical-address width coherent with guest mappings.
* Keep virtual-address width coherent with guest mode.
* Expose invariant TSC only when the guest’s time source meets that contract.
* Expose x2APIC only when the interrupt design supports it.
* Expose PCID/INVPCID only if guest use is correctly virtualized.
* Hide SGX, TDX, SEV, SNP, MPX, CET, PT, PMU, or other complex facilities unless supported.
* Make XSAVE leaf sizes agree with the exposed XCR0 mask.
* Keep cache and NUMA topology leaves internally consistent.
* Return deterministic values for unsupported leaves.
* Test guests that probe leaves in unusual orders.

12. MSR policy

Build an explicit allow/read/write/trap policy for every relevant MSR class.

* EFER.
* STAR/LSTAR/CSTAR/SFMASK.
* FS base, GS base, kernel GS base.
* TSC and TSC adjustment.
* TSC deadline.
* APIC base.
* x2APIC MSRs.
* PAT.
* MTRRs.
* SYSENTER MSRs.
* DEBUGCTL.
* PERF global and counter MSRs.
* fixed performance counters.
* SPEC_CTRL.
* PRED_CMD.
* ARCH_CAPABILITIES.
* FLUSH_CMD.
* Machine-check MSRs.
* RAPL/power-management MSRs.
* microcode-update MSRs.
* VMX capability MSRs.
* SVM-specific controls.
* SGX/TDX/SEV-related MSRs.
* Intel PT or branch-trace MSRs.
* CET MSRs.
* XFD MSRs.

For each MSR:

* Define read result.
* Define writable bits.
* Mask reserved bits.
* Decide whether writes are guest-local, host-global, ignored, or fatal.
* Ensure a guest cannot change package-wide or platform-wide state.
* Inject #GP for architecturally invalid access where appropriate.
* Do not return host secrets through unvirtualized MSRs.

13. Control-register and instruction interception

* Intercept or mask CR0 changes that violate guest mode assumptions.
* Intercept or mask CR4 changes requiring unsupported features.
* Handle CR3 writes correctly with VPID/ASID translation behavior.
* Virtualize CR8 or APIC task-priority behavior.
* Decide policies for:
    * HLT.
    * PAUSE.
    * INVLPG.
    * INVPCID.
    * WBINVD.
    * INVD.
    * CLTS.
    * LMSW.
    * MOV DR.
    * RDTSC.
    * RDTSCP.
    * RDPMC.
    * XSETBV.
    * MONITOR/MWAIT.
    * UMONITOR/UMWAIT/TPAUSE.
    * RDRAND/RDSEED.
    * CPUID.
    * RDMSR/WRMSR.
    * port I/O.
    * VMCALL or VMMCALL.
    * VMXON, VMRUN, and other nested-virtualization instructions.
* Prevent guests from globally flushing caches unless explicitly accepted.
* Prevent guests from entering unsupported CPU power states.
* Prevent guests from changing global machine-check configuration.

14. VM-exit handling

14.1 Common entry path

* Write the entry/exit veneer in assembly or extremely constrained inline assembly.
* Save every guest register not saved by hardware.
* Preserve guest register values before using them as scratch.
* Establish a valid host stack.
* Re-establish host direction flag assumptions.
* Re-establish required SIMD/FPU state before Rust code uses it.
* Ensure ABI stack alignment.
* Prevent unwinding across the assembly boundary.
* Disable or carefully control interrupts until host state is safe.
* Associate the exit with the correct per-CPU vCPU.
* Read exit fields before they can be overwritten.
* Treat impossible exit reasons as fatal diagnostic events, not unreachable_unchecked.

14.2 Exit dispatch

Handle or reject explicitly:

* External interrupt.
* NMI.
* Exception.
* CPUID.
* MSR read/write.
* Port I/O.
* MMIO via EPT/NPT violation.
* HLT.
* PAUSE.
* CR access.
* DR access.
* XSETBV.
* EPT violation.
* EPT misconfiguration.
* Nested-page fault.
* APIC access.
* APIC write.
* Interrupt window.
* NMI window.
* Triple fault.
* INIT/SIPI if exposed.
* Machine-check-related exit.
* VM-entry failure.
* Hypercall.
* Shutdown or reset request.
* Invalid guest state.

For every emulated or intercepted instruction:

* Determine instruction length safely.
* Advance RIP exactly once when appropriate.
* Do not advance RIP for fault-like semantics.
* Preserve partial-register semantics.
* Preserve architectural flags.
* Handle operand size and address size correctly.
* Handle REP/string I/O if supported.
* Inject the right exception on invalid operands.
* Test boundary cases around page crossings.

15. Exception and event injection

* Distinguish faults, traps, aborts, and interrupts.
* Inject the correct vector.
* Set the valid and type fields correctly.
* Supply an error code only for exceptions that require one.
* Preserve or set instruction length only where architecturally required.
* Handle delivery during interrupt shadow.
* Handle blocked NMIs.
* Queue at most what your model can represent safely.
* Define priority when an exit and pending event coincide.
* Reinject events reported as interrupted during exit.
* Handle double-fault formation rules.
* Handle triple fault as guest termination/reset, not host failure.
* Prevent stale pending events from leaking to another vCPU.

16. Interrupt architecture

16.1 Local APIC

Choose one model:

1. physical APIC direct assignment where feasible;
2. x2APIC MSR interception;
3. APIC-access/virtual-APIC support;
4. software APIC emulation.

Verify:

* APIC mode is fixed and documented.
* Guest-visible APIC ID matches CPUID and ACPI.
* Spurious-vector register behavior is correct.
* Task-priority behavior is correct.
* EOI handling is correct.
* ICR destination decoding is restricted to guest-owned CPUs.
* A guest cannot send IPIs to another partition.
* Broadcast and lowest-priority modes cannot escape the partition.
* INIT and SIPI behavior is safe.
* Local-vector-table entries are virtualized or constrained.
* APIC timer is virtualized or directly assigned coherently.
* x2APIC writes are validated before reaching hardware.
* APIC-base MSR writes cannot relocate or disable host APIC state globally.

16.2 IOAPIC and interrupt remapping

* Discover all IOAPICs and GSI ranges.
* Validate redirection-table indexes.
* Assign each input pin to one partition.
* Prevent guests from programming entries belonging to others.
* Handle edge versus level triggering correctly.
* Handle polarity correctly.
* Mask sources before ownership changes.
* Complete outstanding level interrupts before reassignment.
* Route physical interrupts only to CPUs owned by the target partition.
* Use interrupt remapping when available and required.
* Program source validation for remapped interrupts.
* Prevent forged MSI/MSI-X messages from targeting foreign CPUs.
* Define behavior when interrupt remapping is unavailable.
* Consider refusing unsafe direct device assignment without it.

16.3 MSI and MSI-X

* Parse capability structures with bounds and loop detection.
* Never trust guest-programmed MSI addresses or data.
* Trap or constrain MSI programming.
* Keep vectors within the partition’s assigned vector space.
* Restrict destination APIC IDs.
* Handle per-vector masking.
* Protect MSI-X tables and pending-bit arrays where necessary.
* Ensure BAR remapping does not bypass MSI-X protection.
* Quiesce device interrupts before changing ownership.

17. Time and timers

* Decide whether guests see host TSC directly.
* Define TSC synchronization assumptions across cores and sockets.
* Use TSC offset where guests require independent epochs.
* Use TSC scaling only if required and supported.
* Prevent guest writes to TSC from changing host/global time.
* Handle IA32_TSC_ADJUST.
* Define migration policy; static pinning simplifies this.
* Virtualize or assign:
    * Local APIC timer.
    * TSC-deadline timer.
    * HPET.
    * PIT if legacy guests need it.
    * RTC/CMOS if exposed.
* Ensure a guest cannot reprogram a timer used by the hypervisor.
* Bound timer-delivery latency if claiming real-time properties.
* Measure interrupt latency under cache, memory, and I/O contention.
* Define behavior across S-states and frequency changes.
* Prefer invariant-TSC systems for simple static designs.
* Do not claim temporal isolation merely because CPUs are statically assigned; shared caches, memory controllers, interconnects, and devices remain sources of interference. Static-partitioning research has specifically highlighted residual real-time and safety limitations.  

18. IOMMU and DMA isolation

Direct device assignment without DMA isolation is not memory isolation.

18.1 Intel VT-d / AMD-Vi discovery

* Parse DMAR or IVRS defensively.
* Discover all remapping units.
* Determine which buses/devices are covered.
* Handle scopes and aliases.
* Identify reserved-memory regions.
* Check translation support and address widths.
* Check interrupt-remapping support.
* Check queued-invalidation support if used.
* Check extended interrupt mode if needed.

18.2 DMA domains

* Create a separate domain for every protection boundary.
* Map only guest-owned RAM and intentional shared buffers.
* Do not map hypervisor memory.
* Do not map another guest’s RAM.
* Map MMIO only where DMA translation semantics require it.
* Attach each requester ID to exactly one domain.
* Handle PCI aliases and multifunction devices.
* Treat bridges and non-ACS topologies conservatively.
* Respect IOMMU groups rather than assuming function-level isolation.
* Disable or reject peer-to-peer DMA paths that bypass isolation.
* Handle Address Translation Services, PRI, and PASID explicitly.
* Disable ATS unless fully supported.
* Flush device and IOMMU translation caches after updates.
* Use correct ordering around context-table publication.
* Log and contain IOMMU faults.
* Do not automatically map faulting addresses.
* Ensure fault-record handling cannot overflow or livelock.

18.3 Ownership transfer

* Stop the device.
* Disable bus mastering.
* Mask interrupts.
* Drain outstanding transactions.
* Reset the function where possible.
* Remove old IOMMU mappings.
* Invalidate caches.
* Attach to the new domain.
* Install new mappings.
* Configure interrupt remapping.
* Expose the function to the new guest.
* Re-enable bus mastering only after isolation is active.

19. PCI and device assignment

* Enumerate PCI segments, buses, devices, and functions safely.
* Validate ECAM ranges from MCFG.
* Define ownership of bridges as well as endpoints.
* Detect multifunction devices.
* Detect devices sharing reset domains.
* Detect devices sharing power-management state.
* Check ACS isolation.
* Check ARI implications.
* Check SR-IOV ownership model.
* Check peer-to-peer DMA paths.
* Assign all functions of inseparable devices together.
* Hide unassigned functions from guest enumeration.
* Filter config-space writes that affect global topology.
* Protect BAR sizing and relocation operations.
* Prevent a guest from relocating a BAR over another guest’s RAM.
* Protect bridge windows.
* Filter command-register bus-master enable until IOMMU setup is complete.
* Filter MSI/MSI-X programming.
* Handle FLR, PM reset, secondary-bus reset, and platform reset.
* Define what happens if a device cannot be reset between owners.
* Avoid sharing a physical device unless using a deliberate mediated or SR-IOV model.
* Include watchdogs, GPIO controllers, SPI, I²C, LPC, and chipset devices in the ownership model—not only PCI endpoints.

20. Shared memory and inter-partition communication

* Shared memory must be explicit in configuration.
* Each participant’s permissions must be explicit.
* Shared pages must not overlap private pages.
* Shared-memory cache type must match in all partitions.
* Define the memory-ordering model.
* Use atomics and fences appropriate to x86 and the Rust memory model.
* Never use volatile as a substitute for synchronization.
* Define queue ownership and wraparound behavior.
* Use checked indexes.
* Handle malicious or corrupted producer values.
* Validate lengths before copying.
* Avoid pointers supplied by another guest.
* Bound message sizes and queue depth.
* Define notification mechanism:
    * IPI.
    * MSI doorbell.
    * shared polling flag.
    * hypercall.
* Ensure notifications cannot target foreign partitions.
* Define restart behavior if one endpoint resets.
* Version the shared-memory ABI.
* Include feature-negotiation fields.
* Prevent one guest from permanently blocking the hypervisor via full queues.
* Keep communication code outside the VM-exit path where possible.

21. Resource interference and real-time behavior

Spatial isolation does not automatically provide temporal isolation.

* Pin vCPUs permanently.
* Avoid SMT sharing across criticality boundaries.
* Consider disabling SMT.
* Allocate cache ways with CAT if available and justified.
* Allocate memory bandwidth with MBA only after validating actual hardware behavior.
* Allocate memory regions NUMA-locally.
* Avoid sharing LLC slices where platform topology permits.
* Avoid sharing memory controllers for hard isolation claims.
* Avoid shared I/O queues and interrupt lines.
* Bound VM-exit paths.
* Avoid heap allocation in steady-state paths.
* Avoid unbounded loops.
* Avoid locks shared across partitions.
* Avoid global logging locks.
* Avoid synchronous serial output from critical paths.
* Measure worst-case interrupt latency.
* Measure worst-case VM-exit latency.
* Measure nested-page-fault behavior.
* Measure under LLC thrashing.
* Measure under DRAM bandwidth saturation.
* Measure under PCIe DMA load.
* Measure under interrupt storms.
* Measure under malicious guest behavior.
* State precisely whether your guarantee is best-effort, bounded under assumptions, or formally established.

22. Host memory management

For a static hypervisor, prefer a staged allocator model.

22.1 Early boot

* A simple bump allocator may allocate:
    * page tables,
    * VMCS/VMCB objects,
    * per-CPU structures,
    * guest metadata,
    * IOMMU tables,
    * logs.
* Allocation must be overflow-safe.
* Alignment must be checked.
* Allocation failures must be explicit.
* Reserved regions must be excluded.
* Allocator metadata must be hypervisor-owned.

22.2 Steady state

Prefer:

* no allocator;
* immutable tables;
* fixed-size per-CPU structures;
* bounded queues;
* fixed-capacity vectors;
* static log buffers.

Verify:

* no guest input can trigger allocation;
* no VM exit can trigger unbounded growth;
* no hidden allocation enters through formatting or collections;
* out-of-memory behavior is defined;
* deallocation is unnecessary or deterministic.

23. Rust #![no_std] architecture

23.1 Crate setup

* Use #![no_std].
* Use #![no_main] where appropriate.
* Provide a panic handler.
* Select abort rather than unwinding.
* Avoid dependencies that require std.
* Audit optional crate features that silently enable allocation.
* Use a custom target specification where necessary.
* Define CPU features conservatively.
* Ensure the compiler does not emit instructions unsupported on target CPUs.
* Decide whether alloc is allowed during initialization.
* Keep the global allocator absent or phase-restricted.
* Pin the Rust toolchain for reproducible builds.
* Record the linker version and options.
* Generate a map file.
* Inspect emitted ELF program headers and sections.
* Strip or retain symbols according to diagnostic needs.

23.2 Unsafe-code policy

* Put #![deny(unsafe_op_in_unsafe_fn)] in relevant crates.
* Minimize the number of unsafe modules.
* Require a written safety invariant for every unsafe abstraction.
* Avoid exposing raw pointers beyond low-level modules.
* Wrap physical and virtual addresses in distinct newtypes.
* Use distinct types for:
    * host virtual address,
    * host physical address,
    * guest virtual address,
    * guest physical address,
    * PCI requester ID,
    * APIC ID,
    * interrupt vector,
    * page-frame number.
* Avoid generic integer conversions between address spaces.
* Use checked constructors for address types.
* Ensure Send and Sync are not implemented automatically for MMIO or CPU-local objects without justification.
* Avoid static mut.
* Use UnsafeCell behind a verified synchronization abstraction.
* Keep mutable aliases impossible in safe APIs.
* Do not create Rust references to invalid, uninitialized, misaligned, MMIO, or foreign guest memory.
* Use raw pointers for potentially invalid guest addresses.
* Copy guest data only after range validation.
* Never use slice::from_raw_parts before proving the full range valid and addressable.
* Never use unreachable_unchecked for hardware states merely believed impossible.
* Avoid transmute for register structures.
* Use explicit masks, shifts, and endian conversions.
* Validate enum discriminants read from hardware or configuration.
* Do not map arbitrary integers directly into Rust enums.

23.3 Assembly boundaries

* Specify all input, output, and clobber operands.
* Do not use options(nomem) when touching MMIO or implicit memory.
* Do not use options(preserves_flags) unless true.
* Account for registers implicitly modified by VM instructions.
* Account for condition flags from VMX instructions.
* Keep stack-pointer manipulation in dedicated assembly stubs.
* Verify red-zone assumptions; kernel code generally disables the red zone.
* Maintain 16-byte ABI stack alignment before calling Rust.
* Set or clear the direction flag before entering Rust.
* Do not allow exceptions to unwind through assembly.
* Inspect generated machine code for VM-entry and VM-exit stubs.
* Add compile-time offset assertions for Rust structures accessed by assembly.

23.4 MMIO and volatile access

* Use volatile reads/writes only for device-register accesses.
* Pair volatile access with the required compiler and CPU barriers.
* Do not represent MMIO registers as ordinary Rust references.
* Respect register width and alignment.
* Handle read-to-clear and write-one-to-clear semantics.
* Prevent read-modify-write on registers that forbid it.
* Use typed register wrappers with documented side effects.
* Ensure no optimizer-created duplicate or elided accesses.
* Do not assume volatile provides mutual exclusion or memory ordering.

23.5 Concurrency

* Use atomics for cross-CPU state.
* Select ordering from a written protocol, not habit.
* Remember that Rust compiler ordering and x86 hardware ordering are separate concerns.
* Avoid holding spinlocks across VM entry.
* Avoid holding spinlocks while interrupts are enabled if an interrupt handler may take the same lock.
* Provide IRQ-safe and NMI-safe variants only where required.
* Bound spin duration.
* Use per-CPU data to remove global contention.
* Ensure panic paths do not deadlock on normal locks.
* Ensure logging from NMI or machine-check context is lock-free or omitted.
* Test with Loom or host-side models where synchronization protocols can be abstracted and exercised.

23.6 Layout and FFI

* Use #[repr(C)] only where external layout is required.
* Use transparent wrappers for typed integers where appropriate.
* Avoid packed structs for directly accessed fields.
* If packed data is unavoidable, use unaligned raw-pointer operations.
* Add compile-time size, alignment, and offset assertions.
* Do not rely on Rust enum layout for hardware structures.
* Confirm linker symbols have correct types and alignment.
* Keep boot-protocol structures versioned.
* Validate every structure received from firmware, bootloader, or management OS.

24. Host FPU, SIMD, and extended state

* Decide whether hypervisor Rust code may emit SSE instructions.
* Ensure required control bits are enabled before calling compiled Rust.
* Initialize MXCSR.
* Decide whether the host uses x87, SSE, AVX, or no floating-point state.
* Avoid floating-point in the hypervisor unless necessary.
* Intercept XSETBV as required.
* Expose only supported guest XSTATE components.
* Allocate correctly sized and aligned XSAVE areas.
* Save and restore guest extended state if not handled automatically.
* Prevent one guest’s SIMD/FPU state leaking to another.
* Handle lazy-FPU designs only with extreme care.
* Handle XFD if exposed.
* Zero sensitive extended-state buffers before reassignment.

25. Security hardening

25.1 Hypervisor mappings

* W^X: no page is writable and executable.
* Code is read-only.
* Read-only data is read-only.
* Stacks are NX.
* Page tables are NX.
* VMCS/VMCB regions are NX.
* Guard pages surround stacks where practical.
* Null page remains unmapped.
* Low memory is mapped only where boot requires it.
* Direct physical map, if present, excludes or protects MMIO.
* Remove temporary identity maps after startup.
* Enable supervisor write protection.
* Enable NX.
* Enable SMEP/SMAP where compatible with the design.
* Enable UMIP if relevant.
* Consider CET where toolchain and hardware support are mature.

25.2 Speculative-execution issues

* Determine the trust relationship among guests.
* Apply the current CPU-vendor mitigation guidance for the target CPUs.
* Handle branch-predictor state at partition boundaries if needed.
* Handle L1D state where required.
* Consider MDS/TAA/MMIO stale-data issues for target CPUs.
* Consider L1TF implications for EPT.
* Avoid speculative access to unvalidated guest indexes.
* Insert speculation barriers where threat analysis requires them.
* Do not expose host kernel pointers through logs or guest interfaces.
* Treat microcode version as part of the verified platform baseline.

25.3 SMM and firmware

* Recognize that SMM executes outside normal hypervisor control.
* Include firmware and SMM in the platform trust model.
* Verify SMRAM is locked.
* Prevent guest access to chipset controls that reopen SMRAM.
* Restrict flash and firmware-update interfaces.
* Restrict ACPI SMI command ports where applicable.
* Measure SMI latency if making real-time claims.
* Document that unbounded SMI execution can violate latency guarantees.

26. Failure containment

Define a policy for every class of fault.

* Guest invalid opcode.
* Guest page fault.
* Guest general-protection fault.
* Guest triple fault.
* Guest EPT/NPT violation.
* Guest access to forbidden MMIO.
* Guest invalid MSR access.
* Guest interrupt storm.
* Guest hypercall abuse.
* Device IOMMU fault.
* Device timeout.
* Host page fault.
* Host general-protection fault.
* Host double fault.
* NMI.
* Machine check.
* VM-entry failure.
* VMX/SVM internal inconsistency.
* AP startup failure.
* Configuration error.
* Assertion failure.
* Rust panic.

For containment:

* Guest faults cannot panic the hypervisor by default.
* A guest can be stopped independently.
* Its CPUs stop executing guest code.
* Its interrupt sources are masked.
* Its devices stop DMA.
* Its IOMMU domain remains restrictive.
* Shared-memory peers receive a defined endpoint-down state.
* Logs identify partition and vCPU.
* Host-fatal paths stop other CPUs safely.
* Fatal paths do not rely on heap allocation.
* Fatal paths do not recursively fault while formatting logs.
* Watchdog behavior is deliberate.

27. Logging and diagnostics

* Per-CPU fixed-size ring buffers.
* Bounded record sizes.
* No allocation in logging.
* No global lock in the VM-exit fast path.
* Timestamp source defined.
* CPU, partition, and vCPU identifiers included.
* VM-exit reason and qualifications recorded.
* VM-entry error recorded.
* Faulting RIP/RSP/CR2 recorded where meaningful.
* EPT/NPT fault GPA and access type recorded.
* IOMMU fault requester ID and address recorded.
* Sensitive values redacted where required.
* Rate limiting prevents guest-induced log flooding.
* Serial output is optional and asynchronous.
* Panic dump format is machine-readable.
* Offline symbolization workflow exists.

28. Testing strategy

28.1 Host-side unit tests

Move pure logic into testable normal Rust crates:

* Configuration parser.
* Range-overlap detection.
* Address arithmetic.
* Page-table indexing.
* CPUID filtering.
* MSR-policy lookup.
* Exit decoding.
* Instruction-length handling.
* APIC destination validation.
* PCI capability parsing.
* ACPI table parsing.
* IOMMU table construction.
* Shared-ring protocol.
* Bitmap manipulation.
* VMX-control synthesis.

28.2 Property testing and fuzzing

Fuzz:

* Configuration files.
* ACPI tables.
* PCI capabilities.
* Linux boot parameters.
* Guest hypercalls.
* Port-I/O requests.
* MMIO requests.
* CPUID leaves and subleaves.
* MSR numbers and values.
* Exit-reason decoders.
* Page-table mapping sequences.
* Range arithmetic near u64::MAX.
* Shared-memory descriptors.

Properties:

* No two private regions overlap.
* No guest mapping resolves to hypervisor memory.
* Mapping then walking returns the expected frame and permissions.
* Unmapping removes accessibility after invalidation.
* Control synthesis never sets a disallowed bit.
* Every assigned interrupt destination belongs to the partition.
* Every DMA mapping is a subset of assigned memory.

28.3 Emulator testing

* QEMU with KVM.
* QEMU TCG where useful for deterministic debugging.
* Intel and AMD hosts.
* One CPU and many CPUs.
* xAPIC and x2APIC.
* Small and large physical-address widths.
* EPT/NPT huge pages enabled and disabled.
* IOMMU enabled and disabled.
* Interrupt remapping enabled and disabled.
* Debug and release builds.
* Deliberately malformed guests.

Do not treat nested virtualization under QEMU/KVM as sufficient hardware validation; nested environments may hide or alter edge behavior.

28.4 Bare-metal matrix

Test across:

* Multiple Intel generations.
* Multiple AMD generations.
* Multiple firmware vendors.
* Different APIC topologies.
* NUMA and non-NUMA.
* SMT enabled and disabled.
* Different IOMMUs.
* Different PCIe topologies.
* Different microcode revisions.
* Secure Boot enabled and disabled.
* High interrupt and DMA load.
* Cold boot and warm reboot.
* Repeated boot cycles.

28.5 Negative and adversarial guests

Create a guest specifically to:

* execute every intercepted instruction;
* issue all CPUID leaves;
* read and write random MSRs;
* access every GPA boundary;
* probe hypervisor RAM;
* probe other guest RAM;
* generate malformed MSI writes;
* send IPIs to foreign APIC IDs;
* trigger triple faults;
* toggle CR0/CR4 combinations;
* use unusual segment states;
* generate interrupt storms;
* flood hypercalls;
* corrupt shared queues;
* perform high-rate DMA;
* attempt PCI BAR relocation;
* attempt cache-flush denial of service.

29. Formalizable invariants

Even without full formal verification, encode these as assertions, offline proofs, or model checks:

* owner(cpu) is unique.
* owner(page) is unique except explicitly shared pages.
* Hypervisor pages have no guest mapping.
* A guest EPT/NPT leaf maps only pages in that guest’s allowed set.
* A DMA domain maps only pages in the corresponding guest’s DMA-allowed set.
* An interrupt route targets only CPUs in the owning partition.
* A PCI requester belongs to one IOMMU domain.
* All guest-supplied indexes are bounds-checked.
* All address-range additions are overflow-checked.
* All runtime queues have finite capacity.
* Every VM exit has exactly one defined action:
    * resume,
    * inject,
    * stop guest,
    * fatal host error.
* No lock is held across guest execution.
* No borrowed Rust reference points into mutable guest memory across VM entry.
* Steady-state paths allocate no memory.
* Configuration cannot mutate after guest launch.

30. Suggested implementation sequence

A low-risk order is:

1. Intel-only or AMD-only, single CPU, one 64-bit bare-metal guest.
2. Host IDT, panic path, serial logging, and robust VM-entry failure diagnostics.
3. Identity-mapped EPT/NPT for a tightly bounded guest RAM region.
4. CPUID, MSR, HLT, and hypercall exits.
5. Strict guest physical-memory ownership validation.
6. Multiple isolated single-vCPU guests.
7. SMP guests and APIC/IPI confinement.
8. Static MMIO assignment.
9. IOMMU DMA isolation.
10. PCI passthrough with safe MSI/MSI-X handling.
11. Linux guest boot.
12. Performance and malicious-guest testing.
13. Hardening and removal of temporary bootstrap mechanisms.
14. Only then add huge pages, advanced interrupt virtualization, NUMA, SR-IOV, or a second CPU-vendor backend.

31. Minimum acceptance gate

Do not call the implementation coherent until all of these are demonstrated:

* A guest cannot read, write, execute, or DMA into hypervisor memory.
* A guest cannot read, write, execute, or DMA into another guest’s private memory.
* A guest cannot interrupt a foreign guest CPU.
* A guest cannot program a device to interrupt or DMA into another partition.
* All VMX/SVM controls are derived from hardware capabilities.
* Every VM-entry failure produces actionable diagnostics.
* Every supported VM exit has tested architectural semantics.
* Guest CPUID, MSR, APIC, and ACPI views are mutually coherent.
* All configuration and address arithmetic is overflow-safe.
* No guest-controlled value becomes a Rust reference before validation.
* No unbounded allocation, queue, loop, or lock exists in a steady-state path.
* SMP startup and shutdown remain correct under repeated stress.
* Negative tests consistently stop only the offending guest.
* IOMMU isolation is active before any assigned device can bus-master.
* The binary has been tested on real Intel or AMD hardware, not only under nested virtualization.
* Claims about real-time behavior are supported by worst-case contention measurements.
* The implemented subset and unsupported hardware states are documented precisely.
