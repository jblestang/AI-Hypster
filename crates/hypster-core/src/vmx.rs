//! # Intel VT-x Hardware Virtualization Subsystem (`vmx.rs`)
//!
//! Provides low-level primitives for Intel VT-x (Virtual Machine Extensions) hardware root operation,
//! VMCS (Virtual Machine Control Structure) initialization, guest context switching, and CPU side-channel mitigations.
//!
//! ## Architectural Overview & Intel SDM References
//! - **VMX Root Operation & VMXON**: Enables hypervisor (Ring 0) VMX operation on the CPU.
//!   Reference: Intel 64 and IA-32 Architectures Software Developer's Manual (SDM), Volume 3C, Chapter 19 ("VMX Support").
//! - **VMCS Architecture**: Configures 4KB VMCS regions for each guest vCPU, defining Guest State, Host State,
//!   VM-Execution Controls, VM-Exit Controls, and VM-Entry Controls.
//!   Reference: Intel SDM Vol 3C, Chapter 24 ("Virtual-Machine Control Structures").
//! - **Hardware Context Switch (`VMLAUNCH`/`VMRESUME`)**: Performs low-overhead CPU context switching using RDI-offset register loading.
//!   Reference: Intel SDM Vol 3C, Chapter 30 ("VMX Instruction Reference").
//! - **Speculative Execution Barriers**: Issues `IBPB` (`IA32_PRED_CMD`) barriers and overwrites Return Stack Buffer (RSB) slots on VM exit.
//!   Reference: Intel Speculative Execution Side Channel Mitigations Guide.

use core::arch::asm;
use crate::serial::{serial_print, serial_print_hex};

// ============================================================================
// Intel VT-x MSR Indices (Intel SDM Vol 3C Appendix A)
// ============================================================================
pub const IA32_FEATURE_CONTROL_MSR: u32 = 0x0000003A;
pub const IA32_VMX_BASIC_MSR: u32 = 0x00000480;
pub const IA32_VMX_PINBASED_CTLS_MSR: u32 = 0x00000481;
pub const IA32_VMX_PROCBASED_CTLS_MSR: u32 = 0x00000482;
pub const IA32_VMX_EXIT_CTLS_MSR: u32 = 0x00000483;
pub const IA32_VMX_ENTRY_CTLS_MSR: u32 = 0x00000484;
pub const IA32_VMX_CR0_FIXED0_MSR: u32 = 0x00000486;
pub const IA32_VMX_CR0_FIXED1_MSR: u32 = 0x00000487;
pub const IA32_VMX_CR4_FIXED0_MSR: u32 = 0x00000488;
pub const IA32_VMX_CR4_FIXED1_MSR: u32 = 0x00000489;
pub const IA32_VMX_PROCBASED_CTLS2_MSR: u32 = 0x0000048B;

// ============================================================================
// VMCS Field Encodings (Intel SDM Vol 3C Component Encodings)
// ============================================================================
// 16-Bit Control & Guest State Fields
pub const VMCS_GUEST_ES_SELECTOR: u32 = 0x00000800;
pub const VMCS_GUEST_CS_SELECTOR: u32 = 0x00000802;
pub const VMCS_GUEST_SS_SELECTOR: u32 = 0x00000804;
pub const VMCS_GUEST_DS_SELECTOR: u32 = 0x00000806;
pub const VMCS_GUEST_FS_SELECTOR: u32 = 0x00000808;
pub const VMCS_GUEST_GS_SELECTOR: u32 = 0x0000080A;
pub const VMCS_GUEST_LDTR_SELECTOR: u32 = 0x0000080C;
pub const VMCS_GUEST_TR_SELECTOR: u32 = 0x0000080E;
pub const VMCS_HOST_ES_SELECTOR: u32 = 0x00000C00;
pub const VMCS_HOST_CS_SELECTOR: u32 = 0x00000C02;
pub const VMCS_HOST_SS_SELECTOR: u32 = 0x00000C04;
pub const VMCS_HOST_DS_SELECTOR: u32 = 0x00000C06;
pub const VMCS_HOST_FS_SELECTOR: u32 = 0x00000C08;
pub const VMCS_HOST_GS_SELECTOR: u32 = 0x00000C0A;
pub const VMCS_HOST_TR_SELECTOR: u32 = 0x00000C0C;

// 64-Bit Control & Guest State Fields
pub const VMCS_MSR_BITMAP: u32 = 0x00002004;
pub const VMCS_EPT_POINTER: u32 = 0x0000201A;
pub const VMCS_GUEST_PHYSICAL_ADDRESS: u32 = 0x00002400;
pub const VMCS_VM_INSTRUCTION_ERROR: u32 = 0x00004400;
pub const VMCS_VM_EXIT_REASON: u32 = 0x00004402;
pub const VMCS_VM_EXIT_INSTRUCTION_LEN: u32 = 0x0000440C;
pub const VMCS_EXIT_QUALIFICATION: u32 = 0x00006400;
pub const VMCS_VMX_PREEMPTION_TIMER_VALUE: u32 = 0x0000482E;
pub const IA32_PRED_CMD_MSR: u32 = 0x49;

#[inline(always)]
pub unsafe fn speculation_barrier_ibpb() {
    if cfg!(test) {
        return;
    }
    let cr4: u64;
    asm!("mov {}, cr4", out(reg) cr4);
    if (cr4 & (1 << 13)) != 0 {
        let edx: u32;
        asm!(
            "push rbx",
            "mov eax, 7",
            "mov ecx, 0",
            "cpuid",
            "mov {0:e}, edx",
            "pop rbx",
            out(reg) edx,
            out("eax") _,
            out("ecx") _
        );
        if (edx & (1 << 26)) != 0 {
            write_msr(IA32_PRED_CMD_MSR, 1);
        }
    }
}

#[inline(always)]
pub unsafe fn flush_rsb() {
    if cfg!(test) {
        return;
    }
    asm!(
        "call 2f",
        "2: call 3f",
        "3: add rsp, 16"
    );
}

#[repr(C, align(4096))]
pub struct MsrBitmapRegion {
    pub read_low: [u8; 1024],   // MSR 0x00000000 - 0x00001FFF
    pub read_high: [u8; 1024],  // MSR 0xC0000000 - 0xC0001FFF
    pub write_low: [u8; 1024],  // MSR 0x00000000 - 0x00001FFF
    pub write_high: [u8; 1024], // MSR 0xC0000000 - 0xC0001FFF
}

static mut MSR_BITMAP_1: MsrBitmapRegion = MsrBitmapRegion {
    read_low: [0; 1024], read_high: [0; 1024],
    write_low: [0; 1024], write_high: [0; 1024],
};

static mut MSR_BITMAP_2: MsrBitmapRegion = MsrBitmapRegion {
    read_low: [0; 1024], read_high: [0; 1024],
    write_low: [0; 1024], write_high: [0; 1024],
};

pub const INVEPT_SINGLE_CONTEXT: u64 = 1;
pub const INVEPT_ALL_CONTEXTS: u64 = 2;

pub const INVVPID_INDIVIDUAL_ADDRESS: u64 = 0;
pub const INVVPID_SINGLE_CONTEXT: u64 = 1;
pub const INVVPID_ALL_CONTEXTS: u64 = 2;

// 32-Bit Control Fields
pub const VMCS_PIN_BASED_VM_EXEC_CONTROL: u32 = 0x00004000;
pub const VMCS_CPU_BASED_VM_EXEC_CONTROL: u32 = 0x00004002;
pub const VMCS_VM_EXIT_CONTROLS: u32 = 0x0000400C;
pub const VMCS_VM_ENTRY_CONTROLS: u32 = 0x00004012;
pub const VMCS_SECONDARY_VM_EXEC_CONTROL: u32 = 0x0000401E;

// 32-Bit Guest State Fields
pub const VMCS_GUEST_ES_LIMIT: u32 = 0x00004800;
pub const VMCS_GUEST_CS_LIMIT: u32 = 0x00004802;
pub const VMCS_GUEST_SS_LIMIT: u32 = 0x00004804;
pub const VMCS_GUEST_DS_LIMIT: u32 = 0x00004806;
pub const VMCS_GUEST_FS_LIMIT: u32 = 0x00004808;
pub const VMCS_GUEST_GS_LIMIT: u32 = 0x0000480A;
pub const VMCS_GUEST_LDTR_LIMIT: u32 = 0x0000480C;
pub const VMCS_GUEST_TR_LIMIT: u32 = 0x0000480E;
pub const VMCS_GUEST_GDTR_LIMIT: u32 = 0x00004810;
pub const VMCS_GUEST_IDTR_LIMIT: u32 = 0x00004812;
pub const VMCS_GUEST_ES_AR_BYTES: u32 = 0x00004814;
pub const VMCS_GUEST_CS_AR_BYTES: u32 = 0x00004816;
pub const VMCS_GUEST_SS_AR_BYTES: u32 = 0x00004818;
pub const VMCS_GUEST_DS_AR_BYTES: u32 = 0x0000481A;
pub const VMCS_GUEST_FS_AR_BYTES: u32 = 0x0000481C;
pub const VMCS_GUEST_GS_AR_BYTES: u32 = 0x0000481E;
pub const VMCS_GUEST_LDTR_AR_BYTES: u32 = 0x00004820;
pub const VMCS_GUEST_TR_AR_BYTES: u32 = 0x00004822;

// Natural-Width Control, Guest & Host State Fields
pub const VMCS_GUEST_CR0: u32 = 0x00006004;
pub const VMCS_GUEST_CR3: u32 = 0x00006002;
pub const VMCS_GUEST_CR4: u32 = 0x00006006;
pub const VMCS_GUEST_ES_BASE: u32 = 0x00006800;
pub const VMCS_GUEST_CS_BASE: u32 = 0x00006802;
pub const VMCS_GUEST_SS_BASE: u32 = 0x00006804;
pub const VMCS_GUEST_DS_BASE: u32 = 0x00006806;
pub const VMCS_GUEST_FS_BASE: u32 = 0x00006808;
pub const VMCS_GUEST_GS_BASE: u32 = 0x0000680A;
pub const VMCS_GUEST_LDTR_BASE: u32 = 0x0000680C;
pub const VMCS_GUEST_TR_BASE: u32 = 0x0000680E;
pub const VMCS_GUEST_GDTR_BASE: u32 = 0x00006810;
pub const VMCS_GUEST_IDTR_BASE: u32 = 0x00006812;
pub const VMCS_GUEST_RSP: u32 = 0x0000681C;
pub const VMCS_GUEST_RIP: u32 = 0x0000681E;
pub const VMCS_GUEST_RFLAGS: u32 = 0x00006820;

pub const VMCS_HOST_CR0: u32 = 0x00006C00;
pub const VMCS_HOST_CR3: u32 = 0x00006C02;
pub const VMCS_HOST_CR4: u32 = 0x00006C04;
pub const VMCS_HOST_FS_BASE: u32 = 0x00006C06;
pub const VMCS_HOST_GS_BASE: u32 = 0x00006C08;
pub const VMCS_HOST_TR_BASE: u32 = 0x00006C0A;
pub const VMCS_HOST_GDTR_BASE: u32 = 0x00006C0C;
pub const VMCS_HOST_IDTR_BASE: u32 = 0x00006C0E;
pub const VMCS_HOST_RSP: u32 = 0x00006C14;
pub const VMCS_HOST_RIP: u32 = 0x00006C16;

#[repr(C, align(4096))]
pub struct VmxonRegion {
    pub revision_id: u32,
    pub data: [u8; 4092],
}

#[repr(C, align(4096))]
pub struct VmcsRegion {
    pub revision_id: u32,
    pub abort_indicator: u32,
    pub data: [u8; 4088],
}

static mut VMXON_REGION: VmxonRegion = VmxonRegion {
    revision_id: 0,
    data: [0; 4092],
};

static mut VMCS_REGION_1: VmcsRegion = VmcsRegion {
    revision_id: 0,
    abort_indicator: 0,
    data: [0; 4088],
};

static mut VMCS_REGION_2: VmcsRegion = VmcsRegion {
    revision_id: 0,
    abort_indicator: 0,
    data: [0; 4088],
};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VCpuRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8:  u64,
    pub r9:  u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
}

pub struct VCpu {
    pub id: usize,
    pub registers: VCpuRegisters,
    pub vmcs_ptr: *mut VmcsRegion,
    pub launched: bool,
    pub active: bool,
}

impl VCpu {
    pub fn new(id: usize, entry_point: u64, stack_pointer: u64) -> Self {
        let mut regs = VCpuRegisters::default();
        regs.rip = entry_point;
        regs.rsp = stack_pointer;
        regs.rflags = 0x2; // Reserved bit always 1

        let vmcs_ptr = if id == 0 {
            core::ptr::addr_of_mut!(VMCS_REGION_1)
        } else {
            core::ptr::addr_of_mut!(VMCS_REGION_2)
        };

        Self {
            id,
            registers: regs,
            vmcs_ptr,
            launched: false,
            active: true,
        }
    }
}

// ============================================================================
// Low-level Assembly Hardware Helpers
// ============================================================================

#[inline(always)]
pub unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

#[inline(always)]
pub unsafe fn write_msr(msr: u32, val: u64) {
    let low = val as u32;
    let high = (val >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline(always)]
pub unsafe fn vmread(field: u32) -> u64 {
    let mut val: u64 = 0;
    let cr4: u64;
    asm!("mov {}, cr4", out(reg) cr4);
    if (cr4 & (1 << 13)) != 0 {
        asm!(
            "vmread {0}, {1}",
            out(reg) val,
            in(reg) field as u64,
            options(nomem, nostack)
        );
    }
    val
}

#[inline(always)]
pub unsafe fn vmwrite(field: u32, val: u64) {
    let cr4: u64;
    asm!("mov {}, cr4", out(reg) cr4);
    if (cr4 & (1 << 13)) != 0 {
        asm!(
            "vmwrite {0}, {1}",
            in(reg) field as u64,
            in(reg) val,
            options(nomem, nostack)
        );
    }
}

#[inline(always)]
pub unsafe fn invept(invept_type: u64, eptp: u64) -> bool {
    if cfg!(test) {
        return true;
    }
    // Perform INVEPT only if hardware CPU supports VMX root operation
    let descriptor: [u64; 2] = [eptp, 0];
    let mut rflags: u64 = 0;
    let mut ok = false;
    // Check CR4.VMXE bit (bit 13)
    let cr4: u64;
    asm!("mov {}, cr4", out(reg) cr4);
    if (cr4 & (1 << 13)) != 0 {
        asm!(
            "invept {0}, [{1}]",
            "pushfq",
            "pop {2}",
            in(reg) invept_type,
            in(reg) descriptor.as_ptr(),
            out(reg) rflags,
            options(nostack)
        );
        ok = (rflags & (1 | 0x40)) == 0;
    }
    ok
}

#[inline(always)]
pub unsafe fn invvpid(invvpid_type: u64, vpid: u16, gva: u64) -> bool {
    if cfg!(test) {
        return true;
    }
    let descriptor: [u64; 2] = [vpid as u64, gva];
    let mut rflags: u64 = 0;
    let mut ok = false;
    let cr4: u64;
    asm!("mov {}, cr4", out(reg) cr4);
    if (cr4 & (1 << 13)) != 0 {
        asm!(
            "invvpid {0}, [{1}]",
            "pushfq",
            "pop {2}",
            in(reg) invvpid_type,
            in(reg) descriptor.as_ptr(),
            out(reg) rflags,
            options(nostack)
        );
        ok = (rflags & (1 | 0x40)) == 0;
    }
    ok
}

/// Hardware VMXON Initialization
pub unsafe fn enable_hardware_vmx() -> bool {
    serial_print("[HYPSTER-VTX] Initializing Hardware Intel VT-x (VMX Root Operation)...\n");

    // 1. Enable CR4.VMXE (Bit 13)
    let mut cr4: u64;
    asm!("mov {}, cr4", out(reg) cr4);
    let cr4_fixed0 = read_msr(IA32_VMX_CR4_FIXED0_MSR);
    let cr4_fixed1 = read_msr(IA32_VMX_CR4_FIXED1_MSR);
    cr4 |= 1 << 13; // Set VMXE
    cr4 |= cr4_fixed0;
    cr4 &= cr4_fixed1;
    asm!("mov cr4, {}", in(reg) cr4);

    // Adjust CR0 fixed bits
    let mut cr0: u64;
    asm!("mov {}, cr0", out(reg) cr0);
    let cr0_fixed0 = read_msr(IA32_VMX_CR0_FIXED0_MSR);
    let cr0_fixed1 = read_msr(IA32_VMX_CR0_FIXED1_MSR);
    cr0 |= cr0_fixed0;
    cr0 &= cr0_fixed1;
    asm!("mov cr0, {}", in(reg) cr0);

    // 2. Configure IA32_FEATURE_CONTROL_MSR (0x3A)
    let feat = read_msr(IA32_FEATURE_CONTROL_MSR);
    if (feat & 1) == 0 {
        // Lock bit not set -> enable VMX outside SMX and lock
        write_msr(IA32_FEATURE_CONTROL_MSR, feat | 1 | (1 << 2));
    }

    // 3. Read VMX Revision ID from IA32_VMX_BASIC MSR
    let basic_msr = read_msr(IA32_VMX_BASIC_MSR);
    let rev_id = (basic_msr & 0x7FFFFFFF) as u32;

    serial_print("[HYPSTER-VTX] VMX Revision ID: ");
    serial_print_hex(rev_id as u64);
    serial_print("\n");

    let vmxon_ptr = core::ptr::addr_of_mut!(VMXON_REGION);
    (*vmxon_ptr).revision_id = rev_id;

    let vmxon_pa = vmxon_ptr as u64;

    // Execute VMXON
    let mut rflags: u64;
    asm!(
        "vmxon [{0}]",
        "pushfq",
        "pop {1}",
        in(reg) &vmxon_pa,
        out(reg) rflags,
        options(nostack)
    );

    let cf = (rflags & 1) != 0;
    let zf = (rflags & 0x40) != 0;

    if cf || zf {
        serial_print("[HYPSTER-VTX] ERROR: VMXON execution failed!\n");
        return false;
    }

    serial_print("[HYPSTER-VTX] VMXON Executed Successfully! CPU entered VMX Root Operation.\n");
    true
}

/// Setup VMCS Fields for Hardware Guest Execution
pub unsafe fn setup_hardware_vmcs(vcpu: &mut VCpu, ept_pml4_pa: u64) {
    let basic_msr = read_msr(IA32_VMX_BASIC_MSR);
    let rev_id = (basic_msr & 0x7FFFFFFF) as u32;

    (*vcpu.vmcs_ptr).revision_id = rev_id;
    let vmcs_pa = vcpu.vmcs_ptr as u64;

    // Execute VMCLEAR & VMPTRLD
    asm!("vmclear [{0}]", in(reg) &vmcs_pa, options(readonly));
    asm!("vmptrld [{0}]", in(reg) &vmcs_pa, options(readonly));

    // 1. Write Pin-Based, CPU-Based, Exit & Entry Execution Controls
    let pin_ctls = (read_msr(IA32_VMX_PINBASED_CTLS_MSR) & 0xFFFFFFFF) as u32 | (1 << 6); // Activate VMX Preemption Timer (bit 6)
    let proc_ctls = (read_msr(IA32_VMX_PROCBASED_CTLS_MSR) & 0xFFFFFFFF) as u32 | (1 << 31) | (1 << 28); // Enable Secondary Controls (bit 31) & Use MSR Bitmaps (bit 28)
    let sec_proc_ctls = (read_msr(IA32_VMX_PROCBASED_CTLS2_MSR) & 0xFFFFFFFF) as u32 | (1 << 1) | (1 << 7); // Enable EPT (bit 1) & Unrestricted Guest (bit 7)
    let exit_ctls = (read_msr(IA32_VMX_EXIT_CTLS_MSR) & 0xFFFFFFFF) as u32 | (1 << 9); // 64-bit Host Mode
    let entry_ctls = (read_msr(IA32_VMX_ENTRY_CTLS_MSR) & 0xFFFFFFFF) as u32;

    vmwrite(VMCS_PIN_BASED_VM_EXEC_CONTROL, pin_ctls as u64);
    vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, proc_ctls as u64);
    vmwrite(VMCS_SECONDARY_VM_EXEC_CONTROL, sec_proc_ctls as u64);
    vmwrite(VMCS_VM_EXIT_CONTROLS, exit_ctls as u64);
    vmwrite(VMCS_VM_ENTRY_CONTROLS, entry_ctls as u64);

    // 2. Set EPTP, MSR Bitmaps Pointer & Preemption Timer
    let eptp = (ept_pml4_pa & !0xFFF) | (3 << 3) | 6;
    vmwrite(VMCS_EPT_POINTER, eptp);

    let msr_bitmap_ptr = if vcpu.id == 0 {
        core::ptr::addr_of_mut!(MSR_BITMAP_1)
    } else {
        core::ptr::addr_of_mut!(MSR_BITMAP_2)
    };
    vmwrite(VMCS_MSR_BITMAP, msr_bitmap_ptr as u64);
    vmwrite(VMCS_VMX_PREEMPTION_TIMER_VALUE, 100_000);

    // 3. Write Guest State Fields
    vmwrite(VMCS_GUEST_RIP, vcpu.registers.rip);
    vmwrite(VMCS_GUEST_RSP, vcpu.registers.rsp);
    vmwrite(VMCS_GUEST_RFLAGS, 0x2);

    vmwrite(VMCS_GUEST_CS_SELECTOR, 0x08);
    vmwrite(VMCS_GUEST_CS_BASE, 0x0);
    vmwrite(VMCS_GUEST_CS_LIMIT, 0xFFFFFFFF);
    vmwrite(VMCS_GUEST_CS_AR_BYTES, 0xC09B); // Present, Code, Exec/Read, 64-bit

    vmwrite(VMCS_GUEST_DS_SELECTOR, 0x10);
    vmwrite(VMCS_GUEST_DS_BASE, 0x0);
    vmwrite(VMCS_GUEST_DS_LIMIT, 0xFFFFFFFF);
    vmwrite(VMCS_GUEST_DS_AR_BYTES, 0xC093); // Present, Data, Read/Write

    vmwrite(VMCS_GUEST_ES_SELECTOR, 0x10);
    vmwrite(VMCS_GUEST_SS_SELECTOR, 0x10);
    vmwrite(VMCS_GUEST_FS_SELECTOR, 0x0);
    vmwrite(VMCS_GUEST_GS_SELECTOR, 0x0);
    vmwrite(VMCS_GUEST_LDTR_SELECTOR, 0x0);
    vmwrite(VMCS_GUEST_TR_SELECTOR, 0x0);

    vmwrite(VMCS_GUEST_ES_LIMIT, 0xFFFFFFFF);
    vmwrite(VMCS_GUEST_SS_LIMIT, 0xFFFFFFFF);
    vmwrite(VMCS_GUEST_FS_LIMIT, 0xFFFFFFFF);
    vmwrite(VMCS_GUEST_GS_LIMIT, 0xFFFFFFFF);
    vmwrite(VMCS_GUEST_LDTR_LIMIT, 0);
    vmwrite(VMCS_GUEST_TR_LIMIT, 0xFFFF);

    vmwrite(VMCS_GUEST_ES_AR_BYTES, 0xC093);
    vmwrite(VMCS_GUEST_SS_AR_BYTES, 0xC093);
    vmwrite(VMCS_GUEST_FS_AR_BYTES, 0xC093);
    vmwrite(VMCS_GUEST_GS_AR_BYTES, 0xC093);
    vmwrite(VMCS_GUEST_LDTR_AR_BYTES, 0x10000); // Unusable
    vmwrite(VMCS_GUEST_TR_AR_BYTES, 0x8B);      // Busy 32-bit TSS

    vmwrite(VMCS_GUEST_CR0, 0x80000001); // PE | PG
    vmwrite(VMCS_GUEST_CR3, 0x1000);
    vmwrite(VMCS_GUEST_CR4, 0x20);       // PAE

    // 4. Write Host State Fields
    let mut host_cr0: u64;
    let mut host_cr3: u64;
    let mut host_cr4: u64;
    asm!("mov {}, cr0", out(reg) host_cr0);
    asm!("mov {}, cr3", out(reg) host_cr3);
    asm!("mov {}, cr4", out(reg) host_cr4);

    vmwrite(VMCS_HOST_CR0, host_cr0);
    vmwrite(VMCS_HOST_CR3, host_cr3);
    vmwrite(VMCS_HOST_CR4, host_cr4);

    vmwrite(VMCS_HOST_CS_SELECTOR, 0x38); // UEFI 64-bit CS
    vmwrite(VMCS_HOST_DS_SELECTOR, 0x30);
    vmwrite(VMCS_HOST_SS_SELECTOR, 0x30);
    vmwrite(VMCS_HOST_FS_SELECTOR, 0x0);
    vmwrite(VMCS_HOST_GS_SELECTOR, 0x0);
    vmwrite(VMCS_HOST_TR_SELECTOR, 0x0);   // Matches UEFI active Task Register

    serial_print("[HYPSTER-VTX] Hardware VMCS Region Configured for VM ");
    crate::serial::serial_print_dec(vcpu.id as u64);
    serial_print(" [EPTP: ");
    serial_print_hex(eptp);
    serial_print("]\n");
}

// ============================================================================
// Assembly VT-x Context Switcher Loop (VMLAUNCH / VMRESUME)
// ============================================================================

/// Execute hardware VMLAUNCH / VMRESUME context switch into VMX non-root operation
pub unsafe fn vmx_launch_or_resume(regs: *mut VCpuRegisters, launched: bool) -> u64 {
    let exit_reason: u64;
    let mut launch_rflags: u64;

    if !launched {
        // VMLAUNCH path
        asm!(
            "push rbx",
            "push rbp",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "push rdi",
            "mov rax, [rdi + 0x00]",
            "mov rbx, [rdi + 0x08]",
            "mov rcx, [rdi + 0x10]",
            "mov rdx, [rdi + 0x18]",
            "mov rsi, [rdi + 0x20]",
            "mov rbp, [rdi + 0x30]",
            "mov r8,  [rdi + 0x40]",
            "mov r9,  [rdi + 0x48]",
            "mov r10, [rdi + 0x50]",
            "mov r11, [rdi + 0x58]",
            "mov r12, [rdi + 0x60]",
            "mov r13, [rdi + 0x68]",
            "mov r14, [rdi + 0x70]",
            "mov r15, [rdi + 0x78]",
            "mov rdi, [rdi + 0x28]",
            "vmlaunch",
            "pushfq",
            "pop {0}",
            "pop rdi",
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbp",
            "pop rbx",
            out(reg) launch_rflags,
            in("rdi") regs,
        );
    } else {
        // VMRESUME path
        asm!(
            "push rbx",
            "push rbp",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "push rdi",
            "mov rax, [rdi + 0x00]",
            "mov rbx, [rdi + 0x08]",
            "mov rcx, [rdi + 0x10]",
            "mov rdx, [rdi + 0x18]",
            "mov rsi, [rdi + 0x20]",
            "mov rbp, [rdi + 0x30]",
            "mov r8,  [rdi + 0x40]",
            "mov r9,  [rdi + 0x48]",
            "mov r10, [rdi + 0x50]",
            "mov r11, [rdi + 0x58]",
            "mov r12, [rdi + 0x60]",
            "mov r13, [rdi + 0x68]",
            "mov r14, [rdi + 0x70]",
            "mov r15, [rdi + 0x78]",
            "mov rdi, [rdi + 0x28]",
            "vmresume",
            "pushfq",
            "pop {0}",
            "pop rdi",
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rbp",
            "pop rbx",
            out(reg) launch_rflags,
            in("rdi") regs,
        );
    }

    if (launch_rflags & (1 | 0x40)) != 0 {
        let err_code = vmread(VMCS_VM_INSTRUCTION_ERROR);
        exit_reason = 0x8000_0000 | (err_code & 0xFFFF);
    } else {
        exit_reason = vmread(VMCS_VM_EXIT_REASON);
        // Save updated guest RIP & RSP from VMCS only on successful VM Exit
        (*regs).rip = vmread(VMCS_GUEST_RIP);
        (*regs).rsp = vmread(VMCS_GUEST_RSP);
    }

    exit_reason
}
