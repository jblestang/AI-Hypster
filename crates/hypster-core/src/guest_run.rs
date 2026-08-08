//! Intel VT-x bring-up for Target A: one guest under hardware VMLAUNCH/VM-exit.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::guest_boot::{GUEST_CR3_GPA, GUEST_ENTRY_GPA, GUEST_STACK_TOP_GPA};
use crate::serial::{serial_print, serial_print_hex};
use crate::vmexit::{HYPERCALL_GET_PAYLOAD_LEN, HYPERCALL_GUEST_PUTCHAR, HYPERCALL_GUEST_SHUTDOWN};

pub use crate::vmx::VCpu;
pub use crate::vmx::enable_hardware_vmx;

use crate::vmx::{
    setup_hardware_vmcs, vmptrld_vmcs, vmread, vmwrite, VMCS_GUEST_RIP, VMCS_HOST_RIP,
    VMCS_VM_EXIT_INSTRUCTION_LEN, VMCS_VM_EXIT_REASON, VMCS_VM_INSTRUCTION_ERROR,
    VMCS_EXIT_QUALIFICATION,
};

static mut ACTIVE_VCPU: [*mut VCpu; 2] = [core::ptr::null_mut(); 2];
/// Per-pCPU shutdown flags (index = [`crate::ap_trampoline::current_pcpu`]).
static GUEST_STOP: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];
/// Legacy alias: BSP stop flag (Target A / single-guest paths).
pub static GUEST_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static mut ENTRY_FAILED: [u64; 2] = [0; 2];
static mut SAVED_GUEST_RAX: [u64; 2] = [0; 2];
static mut SAVED_GUEST_RCX: [u64; 2] = [0; 2];
static CPUID_PATCH_PENDING: [AtomicBool; 2] =
    [AtomicBool::new(false), AtomicBool::new(false)];
static mut CPUID_GPR: [[u64; 4]; 2] = [[0; 4]; 2];
static RAX_PATCH_PENDING: [AtomicBool; 2] =
    [AtomicBool::new(false), AtomicBool::new(false)];
static mut RAX_PATCH_VALUE: [u64; 2] = [0; 2];
/// Payload length for the current Target B trial (returned by GET_PAYLOAD_LEN).
static mut TRIAL_PAYLOAD_LEN: u64 = 64;
/// When set, HLT exits VMRESUME immediately (true concurrent BSP+AP; no time slice).
static CONCURRENT_MODE: AtomicBool = AtomicBool::new(false);
/// First BSP VM-exit sets `AP_BSP_WAITING` so the parked AP may VMLAUNCH.
static RELEASE_AP_ON_EXIT: AtomicBool = AtomicBool::new(false);

pub fn set_concurrent_mode(on: bool) {
    CONCURRENT_MODE.store(on, Ordering::SeqCst);
    crate::serial::set_pcpu_line_tags(on);
    if !on {
        RELEASE_AP_ON_EXIT.store(false, Ordering::SeqCst);
    }
}

pub fn arm_concurrent_ap_release() {
    RELEASE_AP_ON_EXIT.store(true, Ordering::SeqCst);
}

pub fn guest_stop_requested(pcpu: usize) -> bool {
    let i = pcpu.min(1);
    GUEST_STOP[i].load(Ordering::SeqCst)
        || (i == 0 && GUEST_STOP_REQUESTED.load(Ordering::SeqCst))
}

fn clear_guest_stop(pcpu: usize) {
    let i = pcpu.min(1);
    GUEST_STOP[i].store(false, Ordering::SeqCst);
    if i == 0 {
        GUEST_STOP_REQUESTED.store(false, Ordering::SeqCst);
    }
}

fn set_guest_stop(pcpu: usize) {
    let i = pcpu.min(1);
    GUEST_STOP[i].store(true, Ordering::SeqCst);
    if i == 0 {
        GUEST_STOP_REQUESTED.store(true, Ordering::SeqCst);
    }
}

pub fn set_trial_payload_len(len: u64) {
    unsafe {
        TRIAL_PAYLOAD_LEN = len.max(1).min(1518);
    }
}

/// Host GPRs/RSP saved before VMLAUNCH/VMRESUME. VM-exit leaves guest values in
/// GPRs and switches to the exit stack; HLT/shutdown yield must restore these
/// before returning to Rust (needed for alternating `run_vcpu_once`).
#[repr(C)]
struct HostYieldSave {
    rsp: u64,
    rbp: u64,
    rbx: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

static mut HOST_YIELD_SAVE: [HostYieldSave; 2] = [
    HostYieldSave {
        rsp: 0,
        rbp: 0,
        rbx: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
    },
    HostYieldSave {
        rsp: 0,
        rbp: 0,
        rbx: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
    },
];

/// 8 KiB exit stack: HOST_RSP at the top. After VM-exit `ret`, RSP lands at
/// `base+8192` and subsequent host frames grow downward through this buffer
/// (avoids clobbering BSS neighbors — see Task 10). AP uses `AP_HOST_STACKS`.
#[repr(C, align(16))]
struct HostExitStack([u8; 8192]);

static mut HOST_EXIT_STACK: HostExitStack = HostExitStack([0; 8192]);

core::arch::global_asm!(
    ".global vmx_exit_handler",
    "vmx_exit_handler:",
    // Stack guest GPRs immediately — no CALL before this (preserves all GPRs).
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push r11",
    "push r10",
    "push r9",
    "push r8",
    "push rdi",
    "push rsi",
    "push rbp",
    "push rbx",
    "push rdx",
    "push rcx",
    "push rax",
    // Handler args from stacked GPRs: rdi=rax, rsi=rcx, rdx=gpr_stack.
    // Also mirror into per-pCPU save for any auxiliary readers.
    "mov rdi, qword ptr [rsp]",
    "mov rsi, qword ptr [rsp + 8]",
    "call save_guest_gprs_for_pcpu",
    "mov rdi, qword ptr [rsp]",
    "mov rsi, qword ptr [rsp + 8]",
    "mov rdx, rsp",
    "mov rcx, rsp",
    "and rsp, -16",
    "sub rsp, 8",
    "push rcx",
    "call vmx_handle_exit",
    "mov r11b, al",
    "pop rsp",
    "mov rdi, rsp",
    "call apply_cpuid_patch",
    "movzx eax, r11b",
    "test al, al",
    "jz 1f",
    "call reload_host_rsp",
    "pop rax",
    "pop rcx",
    "pop rdx",
    "pop rbx",
    "pop rbp",
    "pop rsi",
    "pop rdi",
    "pop r8",
    "pop r9",
    "pop r10",
    "pop r11",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "vmresume",
    "ud2",
    // Yield/shutdown: discard guest GPRs, restore host callee-saved + Rust RSP.
    "1:",
    "add rsp, 15*8",
    "mov r11, qword ptr [rsp]",
    "call host_yield_save_ptr",
    "mov rsp, qword ptr [rax]",
    "mov rbp, qword ptr [rax + 8]",
    "mov rbx, qword ptr [rax + 16]",
    "mov r12, qword ptr [rax + 24]",
    "mov r13, qword ptr [rax + 32]",
    "mov r14, qword ptr [rax + 40]",
    "mov r15, qword ptr [rax + 48]",
    "jmp r11",
    ".global vmx_do_launch",
    "vmx_do_launch:",
    "vmlaunch",
    "ret",
    ".global vmx_do_resume",
    "vmx_do_resume:",
    "vmresume",
    "ret",
);

extern "C" {
    fn vmx_exit_handler();
    fn vmx_do_launch();
    fn vmx_do_resume();
}

#[no_mangle]
extern "C" fn save_guest_gprs_for_pcpu(rax: u64, rcx: u64) {
    let i = crate::ap_trampoline::current_pcpu().min(1);
    unsafe {
        SAVED_GUEST_RAX[i] = rax;
        SAVED_GUEST_RCX[i] = rcx;
    }
}

/// Returns guest rax in RAX and guest rcx in RDX (SysV u128).
#[no_mangle]
extern "C" fn load_guest_rax_rcx_for_pcpu() -> u128 {
    let i = crate::ap_trampoline::current_pcpu().min(1);
    unsafe {
        let a = SAVED_GUEST_RAX[i];
        let c = SAVED_GUEST_RCX[i];
        (c as u128) << 64 | (a as u128)
    }
}

/// Returns pointer to this pCPU's [`HostYieldSave`] in RAX for the exit stub.
#[no_mangle]
extern "C" fn host_yield_save_ptr() -> *mut HostYieldSave {
    let i = crate::ap_trampoline::current_pcpu().min(1);
    unsafe { core::ptr::addr_of_mut!(HOST_YIELD_SAVE[i]) }
}

/// VM-exit loads host RSP from VMCS_HOST_RSP. The exit stub pushes 15 GPRs then
/// `ret`s to the continuation — RSP must equal the slot holding that address.
pub fn host_exit_rsp_anchor(pcpu_id: usize) -> u64 {
    if pcpu_id != 0 {
        let a = crate::ap_trampoline::ap_exit_anchor();
        if a != 0 {
            return a;
        }
    }
    // SAFETY: BSP exit stack; HOST_RSP at top so post-exit frames grow into the 8 KiB.
    unsafe { core::ptr::addr_of_mut!(HOST_EXIT_STACK) as u64 + 8192 - 8 }
}

pub fn set_host_exit_pcpu(pcpu_id: usize) {
    crate::ap_trampoline::set_host_exit_pcpu(pcpu_id);
}

pub fn install_ap_exit_stack(_page_hpa: u64) {}

#[no_mangle]
extern "C" fn vmwrite_host_rsp(rsp: u64) {
    unsafe {
        let mut host_rsp = rsp;
        if crate::ap_trampoline::current_pcpu() != 0 {
            let a = crate::ap_trampoline::ap_exit_anchor();
            if a != 0 {
                let cont = core::ptr::read_volatile(rsp as *const u64);
                core::ptr::write_volatile(a as *mut u64, cont);
                crate::ap_trampoline::set_ap_enter_continuation(cont);
                host_rsp = a;
            }
        }
        vmwrite(crate::vmx::VMCS_HOST_RSP, host_rsp);
    }
}

#[no_mangle]
extern "C" fn apply_cpuid_patch(gpr_stack: *mut u64) {
    let i = crate::ap_trampoline::current_pcpu().min(1);
    if CPUID_PATCH_PENDING[i].load(Ordering::Acquire) {
        CPUID_PATCH_PENDING[i].store(false, Ordering::Release);
        unsafe {
            *gpr_stack.add(0) = CPUID_GPR[i][0];
            *gpr_stack.add(1) = CPUID_GPR[i][2];
            *gpr_stack.add(2) = CPUID_GPR[i][3];
            *gpr_stack.add(3) = CPUID_GPR[i][1];
        }
    }
    if RAX_PATCH_PENDING[i].load(Ordering::Acquire) {
        RAX_PATCH_PENDING[i].store(false, Ordering::Release);
        unsafe {
            *gpr_stack.add(0) = RAX_PATCH_VALUE[i];
        }
    }
}

#[no_mangle]
extern "C" fn reload_host_rsp() {
    unsafe {
        let pcpu = crate::ap_trampoline::current_pcpu();
        let mut host_rsp = host_exit_rsp_anchor(pcpu);
        if pcpu != 0 {
            let a = crate::ap_trampoline::ap_exit_anchor();
            if a != 0 {
                host_rsp = a;
            }
        }
        vmwrite(crate::vmx::VMCS_HOST_RSP, host_rsp);
    }
}

#[no_mangle]
extern "C" fn vmx_handle_exit(guest_rax_arg: u64, guest_rcx_arg: u64, _gpr_stack: u64) -> u8 {
    unsafe {
        let pcpu = crate::ap_trampoline::current_pcpu().min(1);
        let active = ACTIVE_VCPU[pcpu];
        if active.is_null() {
            return 0;
        }

        let vcpu = &mut *active;
        vcpu.launched = true;

        // Release parked AP once BSP has entered guest (first exit on pCPU 0).
        if pcpu == 0
            && RELEASE_AP_ON_EXIT.swap(false, Ordering::SeqCst)
        {
            crate::ap_trampoline::AP_BSP_WAITING.store(true, Ordering::SeqCst);
            serial_print("[HYPSTER] concurrent: AP released on first BSP VM-exit\n");
        }

        // Args from exit stub (stacked GPRs). Also refresh per-pCPU save for
        // any code that still reads SAVED_* after this returns.
        let mut guest_rax = guest_rax_arg;
        let mut guest_rcx = guest_rcx_arg;
        SAVED_GUEST_RAX[pcpu] = guest_rax;
        SAVED_GUEST_RCX[pcpu] = guest_rcx;

        // Nested KVM under dual-VMLAUNCH has shown RAX/RCX swapped on VMCALL;
        // accept either orientation for putchar.
        if guest_rcx == HYPERCALL_GUEST_PUTCHAR
            && guest_rax != HYPERCALL_GUEST_PUTCHAR
            && guest_rax != HYPERCALL_GUEST_SHUTDOWN
            && guest_rax != HYPERCALL_GET_PAYLOAD_LEN
        {
            core::mem::swap(&mut guest_rax, &mut guest_rcx);
        }

        let exit_reason_full = vmread(VMCS_VM_EXIT_REASON);
        let exit_reason = exit_reason_full as u32 & 0xFFFF;
        let inst_len = vmread(VMCS_VM_EXIT_INSTRUCTION_LEN).max(1);
        let guest_rip = vmread(VMCS_GUEST_RIP);

        let resume = if exit_reason == 18 {
            // VMCALL
            match guest_rax {
                HYPERCALL_GUEST_PUTCHAR => {
                    let vm = (*active).vm_id.min(9) as u8;
                    crate::serial::guest_putchar_line(vm, guest_rcx as u8);
                }
                HYPERCALL_GET_PAYLOAD_LEN => {
                    RAX_PATCH_VALUE[pcpu] = TRIAL_PAYLOAD_LEN;
                    RAX_PATCH_PENDING[pcpu].store(true, Ordering::Release);
                }
                HYPERCALL_GUEST_SHUTDOWN => {
                    set_guest_stop(pcpu);
                    ENTRY_FAILED[pcpu] = 0;
                    vmwrite(VMCS_GUEST_RIP, guest_rip + inst_len);
                    serial_print("[HYPSTER] Guest shutdown acknowledged\n");
                    // On AP, bypass exit-stub `ret` (continuation slot is fragile).
                    unsafe {
                        crate::ap_trampoline::ap_maybe_finish_exit();
                    }
                    return 0;
                }
                other => {
                    // Rate-limit: concurrent dual-VMLAUNCH used to flood the UART
                    // with interleaved Unknown lines that were impossible to read.
                    static UNKNOWN_LEFT: [core::sync::atomic::AtomicU32; 2] = [
                        core::sync::atomic::AtomicU32::new(8),
                        core::sync::atomic::AtomicU32::new(8),
                    ];
                    let left = UNKNOWN_LEFT[pcpu].load(Ordering::Relaxed);
                    if left > 0 {
                        UNKNOWN_LEFT[pcpu].store(left - 1, Ordering::Relaxed);
                        crate::serial::serial_with_lock(|| {
                            serial_print("[HYPSTER] Unknown guest hypercall rax=");
                            serial_print_hex(other);
                            serial_print(" rcx=");
                            serial_print_hex(guest_rcx);
                            serial_print(" pcpu=");
                            crate::serial::serial_print_dec(pcpu as u64);
                            serial_print(" rip=");
                            serial_print_hex(guest_rip);
                            serial_print("\n");
                        });
                    }
                }
            }
            vmwrite(VMCS_GUEST_RIP, guest_rip + inst_len);
            true
        } else if exit_reason == 12 {
            // HLT — time-slice yield unless concurrent mode (VMRESUME immediately).
            vmwrite(VMCS_GUEST_RIP, guest_rip + inst_len);
            if CONCURRENT_MODE.load(Ordering::Relaxed) {
                true
            } else {
                ENTRY_FAILED[pcpu] = 0;
                return 0;
            }
        } else if exit_reason == 10 {
            // CPUID — patch guest GPR stack slots before vmresume (see apply_cpuid_patch).
            let (eax, ebx, ecx, edx) = emulate_cpuid(guest_rax, guest_rcx);
            CPUID_GPR[pcpu] = [eax as u64, ebx as u64, ecx as u64, edx as u64];
            CPUID_PATCH_PENDING[pcpu].store(true, Ordering::Release);
            vmwrite(VMCS_GUEST_RIP, guest_rip + inst_len);
            true
        } else if exit_reason == 2 {
            serial_print("[HYPSTER] Guest triple fault\n");
            false
        } else if exit_reason == 48 {
            serial_print("[HYPSTER] EPT violation qual=");
            serial_print_hex(vmread(VMCS_EXIT_QUALIFICATION));
            serial_print(" gpa=");
            serial_print_hex(vmread(0x2400)); // GUEST_PHYSICAL_ADDRESS
            serial_print(" rip=");
            serial_print_hex(guest_rip);
            serial_print("\n");
            false
        } else if exit_reason == 33 {
            serial_print("[HYPSTER] Invalid guest state on VM-entry, qual ");
            serial_print_hex(vmread(VMCS_EXIT_QUALIFICATION));
            serial_print(" rip=");
            serial_print_hex(guest_rip);
            serial_print("\n");
            false
        } else {
            serial_print("[HYPSTER] Unhandled VM exit ");
            serial_print_hex(exit_reason as u64);
            serial_print(" qual=");
            serial_print_hex(vmread(VMCS_EXIT_QUALIFICATION));
            serial_print("\n");
            false
        };

        if !resume {
            ENTRY_FAILED[pcpu] = 0;
        }
        if resume { 1 } else { 0 }
    }
}

unsafe fn emulate_cpuid(leaf: u64, _subleaf: u64) -> (u32, u32, u32, u32) {
    match leaf {
        0x0 => (
            0x1,
            u32::from_le_bytes(*b"Hyps"),
            u32::from_le_bytes(*b"terH"),
            u32::from_le_bytes(*b"V   "),
        ),
        0x1 => (0x0008_06E9, 0, 1 << 9, (1 << 25) | (1 << 26)),
        0x8000_0000 => (0x8000_0001, 0, 0, 0),
        0x8000_0001 => (0, 0, 0, 1 << 29),
        _ => (0, 0, 0, 0),
    }
}

unsafe fn enter_guest_inner(vcpu: &mut VCpu, use_launch: bool) -> Result<(), u64> {
    let pcpu = crate::ap_trampoline::current_pcpu().min(1);
    ACTIVE_VCPU[pcpu] = vcpu as *mut VCpu;
    vmwrite(VMCS_HOST_RIP, vmx_exit_handler as *const () as u64);

    let anchor = host_exit_rsp_anchor(pcpu);
    let ysave = core::ptr::addr_of_mut!(HOST_YIELD_SAVE[pcpu]);
    let fail_slot = core::ptr::addr_of_mut!(ENTRY_FAILED[pcpu]);
    let continuation: u64;
    ENTRY_FAILED[pcpu] = 0xFFFF_FFFF_FFFF_FFFF;

    if use_launch {
        asm!(
            "mov qword ptr [{ysave}], rsp",
            "mov qword ptr [{ysave} + 8], rbp",
            "mov qword ptr [{ysave} + 16], rbx",
            "mov qword ptr [{ysave} + 24], r12",
            "mov qword ptr [{ysave} + 32], r13",
            "mov qword ptr [{ysave} + 40], r14",
            "mov qword ptr [{ysave} + 48], r15",
            "lea {cont}, [rip + 2f]",
            "mov QWORD PTR [{anchor}], {cont}",
            "mov rdi, {anchor}",
            "call vmwrite_host_rsp",
            "call vmx_do_launch",
            "mov QWORD PTR [{fail_slot}], 1",
            "jmp 3f",
            "2:",
            "mov QWORD PTR [{fail_slot}], 0",
            "3:",
            anchor = in(reg) anchor,
            cont = out(reg) continuation,
            fail_slot = in(reg) fail_slot,
            ysave = in(reg) ysave,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("rsi") _,
            out("rdi") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
        );
    } else {
        asm!(
            "mov qword ptr [{ysave}], rsp",
            "mov qword ptr [{ysave} + 8], rbp",
            "mov qword ptr [{ysave} + 16], rbx",
            "mov qword ptr [{ysave} + 24], r12",
            "mov qword ptr [{ysave} + 32], r13",
            "mov qword ptr [{ysave} + 40], r14",
            "mov qword ptr [{ysave} + 48], r15",
            "lea {cont}, [rip + 2f]",
            "mov QWORD PTR [{anchor}], {cont}",
            "mov rdi, {anchor}",
            "call vmwrite_host_rsp",
            "call vmx_do_resume",
            "mov QWORD PTR [{fail_slot}], 1",
            "jmp 3f",
            "2:",
            "mov QWORD PTR [{fail_slot}], 0",
            "3:",
            anchor = in(reg) anchor,
            cont = out(reg) continuation,
            fail_slot = in(reg) fail_slot,
            ysave = in(reg) ysave,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("rsi") _,
            out("rdi") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
        );
    }

    if ENTRY_FAILED[pcpu] != 0 {
        return Err(vmread(VMCS_VM_INSTRUCTION_ERROR));
    }
    Ok(())
}

/// Run one vCPU time slice: enter guest until HLT yield, shutdown VMCALL, or fatal exit.
/// Returns `Ok(true)` if guest is still runnable, `Ok(false)` on shutdown, `Err` on VM-entry fail.
pub unsafe fn run_vcpu_once(vcpu: &mut VCpu, ept_pml4_pa: u64) -> Result<bool, u64> {
    let pcpu = crate::ap_trampoline::current_pcpu().min(1);
    clear_guest_stop(pcpu);

    vmptrld_vmcs(vcpu);

    if !vcpu.launched {
        vcpu.registers.rip = GUEST_ENTRY_GPA;
        vcpu.registers.rsp = GUEST_STACK_TOP_GPA;
        setup_hardware_vmcs(vcpu, ept_pml4_pa, GUEST_CR3_GPA);
    }

    let use_launch = !vcpu.launched;
    enter_guest_inner(vcpu, use_launch)?;

    if guest_stop_requested(pcpu) {
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Configure VMCS and enter guest mode until shutdown or failure.
pub unsafe fn enter_guest(vcpu: &mut VCpu, ept_pml4_pa: u64) -> Result<u64, u64> {
    let pcpu = crate::ap_trampoline::current_pcpu().min(1);
    clear_guest_stop(pcpu);

    vcpu.registers.rip = GUEST_ENTRY_GPA;
    vcpu.registers.rsp = GUEST_STACK_TOP_GPA;
    vcpu.launched = false;

    vmptrld_vmcs(vcpu);
    setup_hardware_vmcs(vcpu, ept_pml4_pa, GUEST_CR3_GPA);
    ACTIVE_VCPU[pcpu] = vcpu as *mut VCpu;
    vmwrite(VMCS_HOST_RIP, vmx_exit_handler as *const () as u64);

    let anchor = host_exit_rsp_anchor(pcpu);
    let ysave = core::ptr::addr_of_mut!(HOST_YIELD_SAVE[pcpu]);
    let fail_slot = core::ptr::addr_of_mut!(ENTRY_FAILED[pcpu]);
    let continuation: u64;
    ENTRY_FAILED[pcpu] = 0xFFFF_FFFF_FFFF_FFFF;

    asm!(
        "mov qword ptr [{ysave}], rsp",
        "mov qword ptr [{ysave} + 8], rbp",
        "mov qword ptr [{ysave} + 16], rbx",
        "mov qword ptr [{ysave} + 24], r12",
        "mov qword ptr [{ysave} + 32], r13",
        "mov qword ptr [{ysave} + 40], r14",
        "mov qword ptr [{ysave} + 48], r15",
        "lea {cont}, [rip + 2f]",
        "mov QWORD PTR [{anchor}], {cont}",
        "mov rdi, {anchor}",
        "call vmwrite_host_rsp",
        "call vmx_do_launch",
        "mov QWORD PTR [{fail_slot}], 1",
        "jmp 3f",
        "2:",
        "mov QWORD PTR [{fail_slot}], 0",
        "3:",
        anchor = in(reg) anchor,
        cont = out(reg) continuation,
        fail_slot = in(reg) fail_slot,
        ysave = in(reg) ysave,
        out("rax") _,
        out("rcx") _,
        out("rdx") _,
        out("rsi") _,
        out("rdi") _,
        out("r8") _,
        out("r9") _,
        out("r10") _,
        out("r11") _,
    );

    let launch_failed = ENTRY_FAILED[pcpu];
    if guest_stop_requested(pcpu) || launch_failed == 0 {
        serial_print("[HYPSTER] enter_guest returned from VM-exit loop\n");
        return Ok(1);
    }
    Err(vmread(VMCS_VM_INSTRUCTION_ERROR))
}

/// Prepare VMX and launch the guest partition once.
pub fn run_single_guest(
    guest_mem: &mut [u8],
    guest_code: &[u8],
) -> Result<(), u64> {
    serial_print("\n========================================================\n");
    serial_print("[HYPSTER] Target A: Single Guest VT-x Bring-up\n");
    serial_print("========================================================\n");

    crate::guest_boot::install_identity_map(guest_mem);

    let mem_base = guest_mem.as_mut_ptr() as u64;
    let guest_size = guest_mem.len() as u64;
    let ipc_size = crate::config::SHARED_IPC_RING_SIZE as usize;

    let mut vm = crate::vm::VirtualMachine::new(0, "VM1-Guest", 1, guest_size, mem_base);

    if guest_mem.len() >= ipc_size {
        let ipc_hpa = mem_base + guest_mem.len() as u64 - crate::config::SHARED_IPC_RING_SIZE;
        vm.map_shared_ipc(ipc_hpa, crate::config::SHARED_IPC_RING_SIZE);
        unsafe {
            crate::ipc_region::init_ipc_at_hpa(ipc_hpa);
        }
    }

    vm.load_code(guest_code, GUEST_ENTRY_GPA);

    let ept_pml4_pa = vm.ept.pml4_ptr as u64;

    let vmx_ok = unsafe { enable_hardware_vmx() };
    if !vmx_ok {
        serial_print("[HYPSTER-VTX] VMXON failed — cannot run hardware guest.\n");
        return Err(u64::MAX);
    }

    let vcpu = vm.vcpus[0].as_mut().expect("vCPU 0 must exist");
    unsafe {
        match enter_guest(vcpu, ept_pml4_pa) {
            Ok(_) => {
                if guest_stop_requested(0) {
                    serial_print("[HYPSTER] Guest exited cleanly.\n");
                    Ok(())
                } else {
                    serial_print("[HYPSTER] Guest stopped without shutdown hypercall\n");
                    Err(0xDEAD)
                }
            }
            Err(err) => {
                serial_print("[HYPSTER-VTX] VMLAUNCH/VM-entry failed, error ");
                serial_print_hex(err);
                serial_print("\n");
                Err(err)
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_exit_rsp_anchor_bsp() {
        assert_ne!(host_exit_rsp_anchor(0), 0);
        // Without AP stack installed, pCPU 1 falls back to BSP slot.
        assert_eq!(host_exit_rsp_anchor(0), host_exit_rsp_anchor(1));
    }
}
