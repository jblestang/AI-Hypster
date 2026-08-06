//! Intel VT-x bring-up for Target A: one guest under hardware VMLAUNCH/VM-exit.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::guest_boot::{GUEST_CR3_GPA, GUEST_ENTRY_GPA, GUEST_STACK_TOP_GPA};
use crate::serial::{serial_print, serial_print_hex, serial_putchar};
use crate::vmexit::{HYPERCALL_GUEST_PUTCHAR, HYPERCALL_GUEST_SHUTDOWN};

pub use crate::vmx::VCpu;
pub use crate::vmx::enable_hardware_vmx;

use crate::vmx::{
    setup_hardware_vmcs, vmread, vmwrite, VMCS_GUEST_RIP, VMCS_HOST_RIP,
    VMCS_VM_EXIT_INSTRUCTION_LEN, VMCS_VM_EXIT_REASON, VMCS_VM_INSTRUCTION_ERROR,
    VMCS_EXIT_QUALIFICATION,
};

static mut ACTIVE_VCPU: *mut VCpu = core::ptr::null_mut();
static GUEST_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static mut SAVED_GUEST_RAX: u64 = 0;
static mut SAVED_GUEST_RCX: u64 = 0;

#[repr(C, align(16))]
struct HostExitStack([u8; 4096]);

static mut HOST_EXIT_STACK: HostExitStack = HostExitStack([0; 4096]);

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
    "pop rsp",
    "test al, al",
    "jz 1f",
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
    "call reload_host_rsp",
    "vmresume",
    "ud2",
    "1:",
    "add rsp, 15*8",
    "ret",
    ".global vmx_do_launch",
    "vmx_do_launch:",
    "vmlaunch",
    "ret",
    rax_slot = sym SAVED_GUEST_RAX,
    rcx_slot = sym SAVED_GUEST_RCX,
);

extern "C" {
    fn vmx_exit_handler();
    fn vmx_do_launch();
}

/// VM-exit loads host RSP from VMCS_HOST_RSP. The exit stub pushes 15 GPRs then
/// `ret`s to the continuation — RSP must equal the slot holding that address.
fn host_exit_rsp_anchor() -> u64 {
    core::ptr::addr_of_mut!(HOST_EXIT_STACK) as u64 + 4096 - 8
}

#[no_mangle]
extern "C" fn vmwrite_host_rsp(rsp: u64) {
    unsafe {
        vmwrite(crate::vmx::VMCS_HOST_RSP, rsp);
    }
}

#[no_mangle]
extern "C" fn reload_host_rsp() {
    unsafe {
        vmwrite(crate::vmx::VMCS_HOST_RSP, host_exit_rsp_anchor());
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
                    vmwrite(VMCS_GUEST_RIP, guest_rip + inst_len);
                    serial_print("[HYPSTER] Guest shutdown acknowledged\n");
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
            // HLT
            vmwrite(VMCS_GUEST_RIP, guest_rip + inst_len);
            !GUEST_STOP_REQUESTED.load(Ordering::SeqCst)
        } else if exit_reason == 10 {
            // CPUID
            let (eax, ebx, ecx, edx) = emulate_cpuid(guest_rax, guest_rcx);
            core::arch::asm!(
                "mov rax, {0}",
                "mov rbx, {1}",
                "mov rcx, {2}",
                "mov rdx, {3}",
                in(reg) eax as u64,
                in(reg) ebx as u64,
                in(reg) ecx as u64,
                in(reg) edx as u64,
                options(nostack, preserves_flags),
            );
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

/// Configure VMCS and enter guest mode until shutdown or failure.
pub unsafe fn enter_guest(vcpu: &mut VCpu, ept_pml4_pa: u64) -> Result<u64, u64> {
    GUEST_STOP_REQUESTED.store(false, Ordering::SeqCst);

    vcpu.registers.rip = GUEST_ENTRY_GPA;
    vcpu.registers.rsp = GUEST_STACK_TOP_GPA;
    vcpu.launched = false;

    setup_hardware_vmcs(vcpu, ept_pml4_pa, GUEST_CR3_GPA);
    ACTIVE_VCPU = vcpu as *mut VCpu;
    vmwrite(VMCS_HOST_RIP, vmx_exit_handler as *const () as u64);

    // Dedicated host exit stack: continuation at anchor; VM-exit RSP starts there.
    let anchor = host_exit_rsp_anchor();
    let continuation: u64;
    let mut launch_failed: u64;

    asm!(
        "lea {cont}, [rip + 2f]",
        "mov QWORD PTR [{anchor}], {cont}",
        "mov rdi, {anchor}",
        "call vmwrite_host_rsp",
        "call vmx_do_launch",
        "mov {failed}, 1",
        "jmp 3f",
        "2:",
        "xor {failed}, {failed}",
        "3:",
        anchor = in(reg) anchor,
        cont = out(reg) continuation,
        failed = out(reg) launch_failed,
        out("rdi") _,
    );

    if launch_failed != 0 {
        return Err(vmread(VMCS_VM_INSTRUCTION_ERROR));
    }

    serial_print("[HYPSTER] enter_guest returned from VM-exit loop\n");
    Ok(vcpu.launched as u64)
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

    let mut vm = crate::vm::VirtualMachine::new(0, "VM1-Guest", 1, guest_size, mem_base);
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
                serial_print("[HYPSTER] Guest exited cleanly.\n");
                Ok(())
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
