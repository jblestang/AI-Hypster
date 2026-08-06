//! Intel VT-x bring-up for Target A: one guest under hardware VMLAUNCH/VM-exit.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::guest_boot::{GUEST_CR3_GPA, GUEST_ENTRY_GPA, GUEST_STACK_TOP_GPA};
use crate::serial::{serial_print, serial_print_hex, serial_putchar};
use crate::vmexit::{HYPERCALL_GUEST_PUTCHAR, HYPERCALL_GUEST_SHUTDOWN};

pub use crate::vmx::VCpu;
pub use crate::vmx::enable_hardware_vmx;

use crate::vmx::{
    setup_hardware_vmcs, vmptrld_vmcs, vmread, vmwrite, VMCS_GUEST_RIP, VMCS_HOST_RIP,
    VMCS_VM_EXIT_INSTRUCTION_LEN, VMCS_VM_EXIT_REASON, VMCS_VM_INSTRUCTION_ERROR,
    VMCS_EXIT_QUALIFICATION,
};

static mut ACTIVE_VCPU: *mut VCpu = core::ptr::null_mut();
/// Exposed for dual-partition shutdown checks after [`enter_guest`].
pub static GUEST_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static mut ENTRY_FAILED: u64 = 0;
static mut SAVED_GUEST_RAX: u64 = 0;
static mut SAVED_GUEST_RCX: u64 = 0;
static CPUID_PATCH_PENDING: AtomicBool = AtomicBool::new(false);
static mut CPUID_GPR: [u64; 4] = [0; 4]; // rax, rbx, rcx, rdx

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

static mut HOST_YIELD_SAVE: HostYieldSave = HostYieldSave {
    rsp: 0,
    rbp: 0,
    rbx: 0,
    r12: 0,
    r13: 0,
    r14: 0,
    r15: 0,
};

/// 8 KiB exit stack: HOST_RSP at the top. After VM-exit `ret`, RSP lands at
/// `base+8192` and subsequent host frames grow downward through this buffer
/// (avoids clobbering BSS neighbors — see Task 10).
#[repr(C, align(16))]
struct HostExitStack([u8; 8192]);

static mut HOST_EXIT_STACK: HostExitStack = HostExitStack([0; 8192]);

core::arch::global_asm!(
    ".global vmx_exit_handler",
    "vmx_exit_handler:",
    "mov [{rax_slot}], rax",
    "mov [{rcx_slot}], rcx",
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
    "mov rdi, [{rax_slot}]",
    "mov rsi, [{rcx_slot}]",
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
    // Yield/shutdown: discard guest GPRs, restore host callee-saved + Rust RSP,
    // then jump to the enter continuation (do not `ret` on the exit stack).
    "1:",
    "add rsp, 15*8",
    "mov rax, qword ptr [rsp]",
    "mov rsp, qword ptr [{ysave}]",
    "mov rbp, qword ptr [{ysave} + 8]",
    "mov rbx, qword ptr [{ysave} + 16]",
    "mov r12, qword ptr [{ysave} + 24]",
    "mov r13, qword ptr [{ysave} + 32]",
    "mov r14, qword ptr [{ysave} + 40]",
    "mov r15, qword ptr [{ysave} + 48]",
    "jmp rax",
    ".global vmx_do_launch",
    "vmx_do_launch:",
    "vmlaunch",
    "ret",
    ".global vmx_do_resume",
    "vmx_do_resume:",
    "vmresume",
    "ret",
    rax_slot = sym SAVED_GUEST_RAX,
    rcx_slot = sym SAVED_GUEST_RCX,
    ysave = sym HOST_YIELD_SAVE,
);

extern "C" {
    fn vmx_exit_handler();
    fn vmx_do_launch();
    fn vmx_do_resume();
}

/// VM-exit loads host RSP from VMCS_HOST_RSP. The exit stub pushes 15 GPRs then
/// `ret`s to the continuation — RSP must equal the slot holding that address.
pub fn host_exit_rsp_anchor(pcpu_id: usize) -> u64 {
    let _ = pcpu_id;
    // SAFETY: BSP exit stack; HOST_RSP at top so post-exit frames grow into the 8 KiB.
    unsafe { core::ptr::addr_of_mut!(HOST_EXIT_STACK) as u64 + 8192 - 8 }
}

pub fn set_host_exit_pcpu(pcpu_id: usize) {
    let _ = pcpu_id;
}

pub fn install_ap_exit_stack(_page_hpa: u64) {}


#[no_mangle]
extern "C" fn vmwrite_host_rsp(rsp: u64) {
    unsafe {
        let mut host_rsp = rsp;
        if crate::ap_trampoline::host_exit_pcpu() != 0 {
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
    if !CPUID_PATCH_PENDING.load(Ordering::Acquire) {
        return;
    }
    CPUID_PATCH_PENDING.store(false, Ordering::Release);
    unsafe {
        // Stack layout (top first): rax, rcx, rdx, rbx, ...
        *gpr_stack.add(0) = CPUID_GPR[0];
        *gpr_stack.add(1) = CPUID_GPR[2];
        *gpr_stack.add(2) = CPUID_GPR[3];
        *gpr_stack.add(3) = CPUID_GPR[1];
    }
}

#[no_mangle]
extern "C" fn reload_host_rsp() {
    unsafe {
        let mut host_rsp = host_exit_rsp_anchor(0);
        if crate::ap_trampoline::host_exit_pcpu() != 0 {
            let a = crate::ap_trampoline::ap_exit_anchor();
            if a != 0 {
                host_rsp = a;
            }
        }
        vmwrite(crate::vmx::VMCS_HOST_RSP, host_rsp);
    }
}

#[no_mangle]
extern "C" fn vmx_handle_exit(_guest_rax: u64, _guest_rcx: u64, _guest_rdx: u64) -> u8 {
    unsafe {
        if ACTIVE_VCPU.is_null() {
            return 0;
        }

        let vcpu = &mut *ACTIVE_VCPU;
        vcpu.launched = true;

        // Under nested KVM, host RAX at VM-exit may not hold the guest value;
        // the exit stub saves them before any host clobber.
        let guest_rax = SAVED_GUEST_RAX;
        let guest_rcx = SAVED_GUEST_RCX;

        let exit_reason_full = vmread(VMCS_VM_EXIT_REASON);
        let exit_reason = exit_reason_full as u32 & 0xFFFF;
        let inst_len = vmread(VMCS_VM_EXIT_INSTRUCTION_LEN).max(1);
        let guest_rip = vmread(VMCS_GUEST_RIP);

        let resume = if exit_reason == 18 {
            // VMCALL
            match guest_rax {
                HYPERCALL_GUEST_PUTCHAR => serial_putchar(guest_rcx as u8),
                HYPERCALL_GUEST_SHUTDOWN => {
                    GUEST_STOP_REQUESTED.store(true, Ordering::SeqCst);
                    ENTRY_FAILED = 0;
                    vmwrite(VMCS_GUEST_RIP, guest_rip + inst_len);
                    serial_print("[HYPSTER] Guest shutdown acknowledged\n");
                    // On AP, bypass exit-stub `ret` (continuation slot is fragile).
                    unsafe {
                        crate::ap_trampoline::ap_maybe_finish_exit();
                    }
                    return 0;
                }
                other => {
                    serial_print("[HYPSTER] Unknown guest hypercall ");
                    serial_print_hex(other);
                    serial_print("\n");
                }
            }
            vmwrite(VMCS_GUEST_RIP, guest_rip + inst_len);
            true
        } else if exit_reason == 12 {
            // HLT — yield to host scheduler (return 0); shutdown uses VMCALL path.
            ENTRY_FAILED = 0;
            vmwrite(VMCS_GUEST_RIP, guest_rip + inst_len);
            return 0;
        } else if exit_reason == 10 {
            // CPUID — patch guest GPR stack slots before vmresume (see apply_cpuid_patch).
            let (eax, ebx, ecx, edx) = emulate_cpuid(guest_rax, guest_rcx);
            CPUID_GPR = [eax as u64, ebx as u64, ecx as u64, edx as u64];
            CPUID_PATCH_PENDING.store(true, Ordering::Release);
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
            ENTRY_FAILED = 0;
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
    ACTIVE_VCPU = vcpu as *mut VCpu;
    vmwrite(VMCS_HOST_RIP, vmx_exit_handler as *const () as u64);

    let anchor = host_exit_rsp_anchor(0);
    let continuation: u64;
    ENTRY_FAILED = 0xFFFF_FFFF_FFFF_FFFF;

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
            fail_slot = sym ENTRY_FAILED,
            ysave = sym HOST_YIELD_SAVE,
            // VM-exit leaves guest values in caller-saved GPRs; yield restores
            // only callee-saved + RSP. Tell rustc the volatiles are gone.
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
            fail_slot = sym ENTRY_FAILED,
            ysave = sym HOST_YIELD_SAVE,
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

    if ENTRY_FAILED != 0 {
        return Err(vmread(VMCS_VM_INSTRUCTION_ERROR));
    }
    Ok(())
}

/// Run one vCPU time slice: enter guest until HLT yield, shutdown VMCALL, or fatal exit.
/// Returns `Ok(true)` if guest is still runnable, `Ok(false)` on shutdown, `Err` on VM-entry fail.
pub unsafe fn run_vcpu_once(vcpu: &mut VCpu, ept_pml4_pa: u64) -> Result<bool, u64> {
    GUEST_STOP_REQUESTED.store(false, Ordering::SeqCst);

    vmptrld_vmcs(vcpu);

    if !vcpu.launched {
        vcpu.registers.rip = GUEST_ENTRY_GPA;
        vcpu.registers.rsp = GUEST_STACK_TOP_GPA;
        setup_hardware_vmcs(vcpu, ept_pml4_pa, GUEST_CR3_GPA);
    }

    let use_launch = !vcpu.launched;
    enter_guest_inner(vcpu, use_launch)?;

    if GUEST_STOP_REQUESTED.load(Ordering::SeqCst) {
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Configure VMCS and enter guest mode until shutdown or failure.
pub unsafe fn enter_guest(vcpu: &mut VCpu, ept_pml4_pa: u64) -> Result<u64, u64> {
    GUEST_STOP_REQUESTED.store(false, Ordering::SeqCst);

    vcpu.registers.rip = GUEST_ENTRY_GPA;
    vcpu.registers.rsp = GUEST_STACK_TOP_GPA;
    vcpu.launched = false;

    vmptrld_vmcs(vcpu);
    setup_hardware_vmcs(vcpu, ept_pml4_pa, GUEST_CR3_GPA);
    ACTIVE_VCPU = vcpu as *mut VCpu;
    vmwrite(VMCS_HOST_RIP, vmx_exit_handler as *const () as u64);

    let anchor = host_exit_rsp_anchor(0);
    let continuation: u64;
    ENTRY_FAILED = 0xFFFF_FFFF_FFFF_FFFF;

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
        fail_slot = sym ENTRY_FAILED,
        ysave = sym HOST_YIELD_SAVE,
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

    let launch_failed = ENTRY_FAILED;
    if GUEST_STOP_REQUESTED.load(Ordering::SeqCst) || launch_failed == 0 {
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
                if GUEST_STOP_REQUESTED.load(Ordering::SeqCst) {
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
