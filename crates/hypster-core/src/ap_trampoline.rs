//! AP bring-up for Phase 2 dual-partition execution.
//!
//! - **UEFI / nested KVM (QEMU+OVMF):** use [`ap_uefi_procedure`] with `MpServices::startup_this_ap`
//!   (non-blocking). Avoids INIT-SIPI and low-memory trampoline writes that corrupt OVMF.
//! - **Bare metal:** [`bringup_ap`] still offers INIT-SIPI-SIPI + trampoline @ 0x8000.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::serial::serial_print;

pub static AP_READY: AtomicBool = AtomicBool::new(false);
pub static AP_RUN_VM2: AtomicBool = AtomicBool::new(false);
/// BSP sets this only after MpServices bring-up prints are done and it is
/// spinning on `AP_VM2_DONE` — avoids nested-KVM races with concurrent UEFI.
pub static AP_BSP_WAITING: AtomicBool = AtomicBool::new(false);
pub static AP_VM2_DONE: AtomicBool = AtomicBool::new(false);
pub static AP_VM2_OK: AtomicBool = AtomicBool::new(false);

static AP_VM2_EPT_PA: AtomicU64 = AtomicU64::new(0);
static HOST_EXIT_PCPU: AtomicUsize = AtomicUsize::new(0);
static AP_EXIT_ANCHOR: AtomicU64 = AtomicU64::new(0);
static AP_EXIT_COUNT: AtomicU64 = AtomicU64::new(0);
/// Continuation address for enter_guest label-2; restored before exit-stub `ret`.
static AP_ENTER_CONTINUATION: AtomicU64 = AtomicU64::new(0);

/// Optional UEFI hook: start an AP running [`ap_uefi_procedure`].
///
/// Nested KVM reboots if an AP is parked during BSP VMLAUNCH, so the loader
/// registers this and dual-run invokes it **after** VM1 exits.
pub static mut UEFI_START_AP: Option<extern "C" fn() -> bool> = None;

/// BSP descriptor tables captured before AP bring-up (MpServices APs often have
/// a transient IDT that cannot handle VM-exit host state).
#[repr(C, packed)]
struct DescReg {
    limit: u16,
    base: u64,
}

/// Aligned storage so `sgdt`/`sidt`/`lgdt`/`lidt` see a stable 10-byte operand.
#[repr(C, align(16))]
struct DescRegSlot {
    reg: DescReg,
}

static mut BSP_IDTR: DescRegSlot = DescRegSlot {
    reg: DescReg { limit: 0, base: 0 },
};
static mut BSP_GDTR: DescRegSlot = DescRegSlot {
    reg: DescReg { limit: 0, base: 0 },
};

const TRAMPOLINE_HPA: u64 = 0x8000;

#[repr(C, align(4096))]
struct ApVmxonPage([u8; 4096]);

/// Dual AP stacks in one buffer:
/// - lower 8 KiB: Rust frames while setting up / returning from VMX
/// - upper 8 KiB: VMCS HOST_RSP exit stack (must not overlap Rust frames)
#[repr(C, align(4096))]
struct ApHostStacks([u8; 16384]);

/// AP-local VMXON region (UEFI identity-maps this HPA).
static mut AP_VMXON_PAGE: ApVmxonPage = ApVmxonPage([0; 4096]);

static mut AP_HOST_STACKS: ApHostStacks = ApHostStacks([0; 16384]);

const AP_RUST_STACK_TOP: u64 = 8192;
const AP_EXIT_STACK_TOP: u64 = 16384;
/// Identify pCPU from RSP only.
///
/// IMPORTANT: never fall back to a global `HOST_EXIT_PCPU` latch while the AP is
/// merely parked. Prior concurrent attempts set that latch at MpServices entry,
/// which made the BSP's `vmwrite_host_rsp` steal the AP exit stack and #PF
/// (RIP/CR2 = -1, GDTR/IDTR.limit = 0xFFFF) on BSP `VMLAUNCH`.
#[inline(always)]
pub fn current_pcpu() -> usize {
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags));
    }
    let base = core::ptr::addr_of!(AP_HOST_STACKS) as u64;
    if rsp >= base && rsp < base + core::mem::size_of::<ApHostStacks>() as u64 {
        1
    } else {
        0
    }
}

pub fn host_exit_pcpu() -> usize {
    current_pcpu()
}

pub fn set_host_exit_pcpu(pcpu_id: usize) {
    // Kept for call-site compatibility; identity is RSP-based. Do not rely on
    // this latch for BSP/AP discrimination while both may run.
    HOST_EXIT_PCPU.store(pcpu_id.min(1), Ordering::SeqCst);
}

pub fn ap_exit_anchor() -> u64 {
    AP_EXIT_ANCHOR.load(Ordering::SeqCst)
}

pub fn set_ap_exit_anchor(anchor: u64) {
    AP_EXIT_ANCHOR.store(anchor, Ordering::SeqCst);
}

pub fn set_ap_enter_continuation(cont: u64) {
    AP_ENTER_CONTINUATION.store(cont, Ordering::SeqCst);
}

pub fn ap_enter_continuation() -> u64 {
    AP_ENTER_CONTINUATION.load(Ordering::SeqCst)
}

/// On the AP, finish VM2 without returning through the exit-stub/`enter_guest`
/// epilogue (that path is unreliable once HOST_RSP is on the AP exit stack).
/// Signals the BSP wait loop and parks the AP. No-op on the BSP.
#[inline(never)]
pub unsafe fn ap_maybe_finish_exit() {
    if current_pcpu() == 0 {
        return;
    }
    AP_VM2_OK.store(true, Ordering::SeqCst);
    serial_print("[HYPSTER-SMP] AP: VM2 exited cleanly\n");
    AP_VM2_DONE.store(true, Ordering::SeqCst);
    loop {
        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

pub fn ap_exit_count_inc() -> u64 {
    AP_EXIT_COUNT.fetch_add(1, Ordering::SeqCst).wrapping_add(1)
}

pub fn set_ap_vm2_ept(ept_pa: u64) {
    AP_VM2_EPT_PA.store(ept_pa, Ordering::SeqCst);
}

/// Capture BSP GDTR/IDTR for AP reuse (call from BSP before starting the AP).
pub fn capture_bsp_descriptors() {
    unsafe {
        core::arch::asm!(
            "sgdt [{}]",
            in(reg) core::ptr::addr_of_mut!(BSP_GDTR.reg),
            options(nostack)
        );
        core::arch::asm!(
            "sidt [{}]",
            in(reg) core::ptr::addr_of_mut!(BSP_IDTR.reg),
            options(nostack)
        );
    }
    serial_print("[HYPSTER-SMP] captured BSP IDTR base=");
    crate::serial::serial_print_hex(unsafe { BSP_IDTR.reg.base });
    serial_print(" limit=");
    crate::serial::serial_print_hex(unsafe { BSP_IDTR.reg.limit as u64 });
    serial_print("\n");
}

unsafe fn load_bsp_idt_on_ap() {
    // Keep BSP IDT for exception delivery; GDT/TSS are installed separately so
    // the AP does not share the BSP task state segment.
    core::arch::asm!(
        "lidt [{}]",
        in(reg) core::ptr::addr_of!(BSP_IDTR.reg),
        options(readonly, nostack)
    );
    serial_print("[HYPSTER-SMP] AP loaded BSP IDTR\n");
}

/// Install AP exit-stack + reset handoff flags. Call from BSP before starting the AP.
pub fn prepare_ap_context() {
    AP_READY.store(false, Ordering::SeqCst);
    AP_RUN_VM2.store(false, Ordering::SeqCst);
    AP_BSP_WAITING.store(false, Ordering::SeqCst);
    AP_VM2_DONE.store(false, Ordering::SeqCst);
    AP_VM2_OK.store(false, Ordering::SeqCst);

    let stack_base = core::ptr::addr_of_mut!(AP_HOST_STACKS) as u64;
    let anchor = stack_base + AP_EXIT_STACK_TOP - 8;
    set_ap_exit_anchor(anchor);
    serial_print("[HYPSTER-SMP] AP exit stack anchor=");
    crate::serial::serial_print_hex(anchor);
    serial_print("\n");
}

/// UEFI `MpServices` AP entry. Expects [`set_ap_vm2_ept`] already called.
///
/// Parks without touching VMX or the host-exit pCPU latch (see [`current_pcpu`]),
/// then runs VM2 once `AP_RUN_VM2` + `AP_BSP_WAITING` are set.
pub extern "efiapi" fn ap_uefi_procedure(_arg: *mut core::ffi::c_void) {
    // Signal ready first with minimal side effects — no set_host_exit_pcpu here.
    AP_READY.store(true, Ordering::SeqCst);

    let timeout_spins = 50_000_000u64;
    let mut spins = 0u64;
    while !AP_RUN_VM2.load(Ordering::SeqCst) {
        spins += 1;
        if spins >= timeout_spins {
            if AP_VM2_EPT_PA.load(Ordering::SeqCst) != 0 {
                break;
            }
            serial_print("[HYPSTER-SMP] AP timed out waiting for AP_RUN_VM2\n");
            AP_VM2_DONE.store(true, Ordering::SeqCst);
            return;
        }
        core::hint::spin_loop();
    }

    // Wait until BSP has finished MpServices chatter and is ready for overlap.
    spins = 0;
    while !AP_BSP_WAITING.load(Ordering::SeqCst) {
        spins += 1;
        if spins >= timeout_spins {
            serial_print("[HYPSTER-SMP] AP timed out waiting for AP_BSP_WAITING\n");
            AP_VM2_DONE.store(true, Ordering::SeqCst);
            return;
        }
        core::hint::spin_loop();
    }

    serial_print("[HYPSTER-SMP] ap_uefi_procedure on AP — running VM2\n");

    // Run VM2 on the dedicated AP stack — MpServices stacks are too small for
    // VT-x setup + exit handling and have triggered host panics mid-guest I/O.
    unsafe {
        run_on_ap_stack();
    }
    AP_VM2_DONE.store(true, Ordering::SeqCst);
}

#[no_mangle]
unsafe extern "C" fn run_vm2_on_ap_cabi() {
    run_vm2_on_ap();
}

/// Switch to the AP Rust stack half, run VM2, then restore the MpServices RSP.
unsafe fn run_on_ap_stack() {
    let new_rsp = core::ptr::addr_of_mut!(AP_HOST_STACKS) as u64 + AP_RUST_STACK_TOP;
    core::arch::asm!(
        "mov rax, rsp",
        "mov rsp, {new}",
        "push rax",
        "call run_vm2_on_ap_cabi",
        "pop rsp",
        new = in(reg) new_rsp,
        out("rax") _,
        clobber_abi("C"),
    );
}

/// Invoke the UEFI-registered AP starter, if any.
pub fn try_uefi_start_ap() -> bool {
    unsafe {
        if let Some(f) = UEFI_START_AP {
            return f();
        }
    }
    false
}

/// Legacy C entry used by the 16-bit trampoline on bare metal.
#[no_mangle]
pub extern "C" fn ap_main() -> ! {
    ap_uefi_procedure(core::ptr::null_mut());
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// INIT-SIPI-SIPI bring-up for bare metal. Returns `false` under a hypervisor
/// (use UEFI MP Services instead).
///
/// # Safety
/// May write low physical memory and issue IPIs when not under a hypervisor.
pub unsafe fn bringup_ap(target_apic_id: u32, entry64: u64) -> bool {
    if cfg!(test) {
        return false;
    }

    prepare_ap_context();

    if hypervisor_present() {
        serial_print(
            "[HYPSTER-SMP] Nested hypervisor — use UEFI MpServices (INIT-SIPI skipped)\n",
        );
        return false;
    }

    let mut cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem, preserves_flags));
    }

    unsafe {
        install_trampoline(entry64, cr3);
    }

    serial_print("[HYPSTER-SMP] INIT-SIPI-SIPI to APIC ID ");
    crate::serial::serial_print_dec(target_apic_id as u64);
    serial_print(" vector=0x08\n");

    let apic = crate::scheduler::LocalApicDriver::new();
    unsafe {
        apic.send_init_sipi_sipi(target_apic_id, 0x08);
    }

    wait_ap_ready(50_000_000)
}

pub fn wait_ap_ready(max_spins: u64) -> bool {
    let mut spins = 0u64;
    while !AP_READY.load(Ordering::SeqCst) {
        spins += 1;
        if spins >= max_spins {
            serial_print("[HYPSTER-SMP] AP_READY timeout\n");
            return false;
        }
        core::hint::spin_loop();
    }
    serial_print("[HYPSTER-SMP] AP_READY signaled\n");
    true
}

unsafe fn run_vm2_on_ap() {
    // enter_guest returns on the VM-exit stack; save our Rust RSP so we can
    // restore it before returning to `run_on_ap_stack`.
    let mut saved_rust_rsp: u64;
    core::arch::asm!("mov {}, rsp", out(reg) saved_rust_rsp, options(nostack));

    // Keep host IRQs masked for the whole AP VT-x window (VM-exit clears IF,
    // but MpServices may have left IF=1 before we get here).
    core::arch::asm!("cli", options(nomem, nostack, preserves_flags));

    load_bsp_idt_on_ap();

    // Private TSS with RSP0 = AP exit-stack top. HOST_RSP uses the same half
    // via ap_exit_anchor() (guest_run must not grow BSS next to HOST_EXIT_STACK).
    let stack_base = core::ptr::addr_of_mut!(AP_HOST_STACKS) as u64;
    let stack_top = stack_base + AP_EXIT_STACK_TOP;
    let anchor = stack_top - 8;
    set_ap_exit_anchor(anchor);
    set_host_exit_pcpu(1);

    let tr = crate::vmx::install_ap_host_tss(stack_top);
    serial_print("[HYPSTER-SMP] AP TSS selector=");
    crate::serial::serial_print_hex(tr as u64);
    serial_print(" RSP0=");
    crate::serial::serial_print_hex(stack_top);
    serial_print("\n");

    let vmxon_hpa = core::ptr::addr_of_mut!(AP_VMXON_PAGE) as u64;
    if !crate::vmx::enable_hardware_vmx_at(vmxon_hpa) {
        serial_print("[HYPSTER-SMP] AP VMXON failed — BSP will fallback VM2\n");
        set_host_exit_pcpu(0);
        core::arch::asm!("mov rsp, {}", in(reg) saved_rust_rsp, options(nostack));
        return;
    }
    let ept_pa = AP_VM2_EPT_PA.load(Ordering::SeqCst);
    let hv = crate::dual_run::dual_hv_mut();
    // Drop any posted-interrupt ON bit before VMLAUNCH — nested KVM cannot
    // emulate the notification self-IPI on this AP.
    unsafe {
        crate::pir::GLOBAL_PIR_MANAGER.descriptors[1] =
            crate::pir::PostedInterruptDescriptor::new();
    }
    match hv.vcpu_mut(crate::VM2_ID, 0) {
        Ok(vcpu) => match crate::guest_run::enter_guest(vcpu, ept_pa) {
            Ok(_) => {
                if crate::guest_run::guest_stop_requested(1) {
                    AP_VM2_OK.store(true, Ordering::SeqCst);
                    serial_print("[HYPSTER-SMP] AP: VM2 exited cleanly\n");
                } else {
                    serial_print("[HYPSTER-SMP] AP: VM2 stopped without shutdown\n");
                }
            }
            Err(_) => serial_print("[HYPSTER-SMP] AP: VM2 enter_guest failed\n"),
        },
        Err(_) => serial_print("[HYPSTER-SMP] AP: missing VM2 vCPU\n"),
    }

    set_host_exit_pcpu(0);
    core::arch::asm!("mov rsp, {}", in(reg) saved_rust_rsp, options(nostack));
}

unsafe fn install_trampoline(entry64: u64, cr3: u64) {
    let base = TRAMPOLINE_HPA as *mut u8;
    unsafe {
        core::ptr::write_bytes(base, 0x90, 0x1000);
        let gdt = 0x8F00u64 as *mut u64;
        core::ptr::write_volatile(gdt, 0);
        core::ptr::write_volatile(gdt.add(1), 0x00CF_9A00_0000_FFFF);
        core::ptr::write_volatile(gdt.add(2), 0x00CF_9200_0000_FFFF);
        core::ptr::write_volatile(gdt.add(3), 0x00AF_9A00_0000_FFFF);
        let gdtr = 0x8EF0u64 as *mut u8;
        core::ptr::write_unaligned(gdtr as *mut u16, 0x1F);
        core::ptr::write_unaligned(gdtr.add(2) as *mut u32, 0x8F00);
        core::ptr::write_volatile(0x8FE0u64 as *mut u64, entry64);
        core::ptr::write_volatile(0x8FE8u64 as *mut u64, cr3);

        let code16: &[u8] = &[
            0xFA, 0xFC, 0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C,
            0x0F, 0x01, 0x16, 0xF0, 0x8E, 0x0F, 0x20, 0xC0, 0x66, 0x83, 0xC8, 0x01, 0x0F,
            0x22, 0xC0, 0x66, 0xEA, 0x20, 0x80, 0x00, 0x00, 0x08, 0x00,
        ];
        core::ptr::copy_nonoverlapping(code16.as_ptr(), base, code16.len());
        let code32: &[u8] = &[
            0x66, 0xB8, 0x10, 0x00, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0x8E, 0xE0, 0x8E,
            0xE8, 0xBC, 0x00, 0x7C, 0x00, 0x00, 0xA1, 0xE8, 0x8F, 0x00, 0x00, 0x0F, 0x22,
            0xD8, 0x0F, 0x20, 0xE0, 0x83, 0xC8, 0x20, 0x0F, 0x22, 0xE0, 0xB9, 0x80, 0x00,
            0x00, 0xC0, 0x0F, 0x32, 0x0D, 0x00, 0x01, 0x00, 0x00, 0x0F, 0x30, 0x0F, 0x20,
            0xC0, 0x0D, 0x00, 0x00, 0x00, 0x80, 0x0F, 0x22, 0xC0, 0xEA, 0x80, 0x80, 0x00,
            0x00, 0x18, 0x00,
        ];
        core::ptr::copy_nonoverlapping(code32.as_ptr(), base.add(0x20), code32.len());
        let code64: &[u8] = &[
            0x48, 0xBC, 0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x04,
            0x25, 0xE0, 0x8F, 0x00, 0x00, 0xFF, 0xE0,
        ];
        core::ptr::copy_nonoverlapping(code64.as_ptr(), base.add(0x80), code64.len());
    }
}

fn hypervisor_present() -> bool {
    if cfg!(test) {
        return true;
    }
    let info = unsafe { core::arch::x86_64::__cpuid(1) };
    (info.ecx & (1 << 31)) != 0
}

/// Public nested-hypervisor probe for dual-run policy.
pub fn is_nested_hypervisor() -> bool {
    hypervisor_present()
}
