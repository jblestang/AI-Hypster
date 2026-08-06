//! AP bring-up for Phase 2 dual-partition execution.
//!
//! - **UEFI / nested KVM (QEMU+OVMF):** use [`ap_uefi_procedure`] with `MpServices::startup_this_ap`
//!   (non-blocking). Avoids INIT-SIPI and low-memory trampoline writes that corrupt OVMF.
//! - **Bare metal:** [`bringup_ap`] still offers INIT-SIPI-SIPI + trampoline @ 0x8000.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::serial::serial_print;

pub static AP_READY: AtomicBool = AtomicBool::new(false);
pub static AP_RUN_VM2: AtomicBool = AtomicBool::new(false);
pub static AP_VM2_DONE: AtomicBool = AtomicBool::new(false);
pub static AP_VM2_OK: AtomicBool = AtomicBool::new(false);

static AP_VM2_EPT_PA: AtomicU64 = AtomicU64::new(0);
static HOST_EXIT_PCPU: AtomicUsize = AtomicUsize::new(0);

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

static mut BSP_IDTR: DescReg = DescReg { limit: 0, base: 0 };
static mut BSP_GDTR: DescReg = DescReg { limit: 0, base: 0 };

const TRAMPOLINE_HPA: u64 = 0x8000;

#[repr(C, align(4096))]
struct ApVmxonPage([u8; 4096]);

#[repr(C, align(16))]
struct ApHostExitStack([u8; 8192]);

/// AP-local VMXON region (UEFI identity-maps this HPA).
static mut AP_VMXON_PAGE: ApVmxonPage = ApVmxonPage([0; 4096]);

/// AP host exit stack — not BSS-adjacent to the BSP stack (separate static).
static mut AP_HOST_EXIT_STACK: ApHostExitStack = ApHostExitStack([0; 8192]);

pub fn host_exit_pcpu() -> usize {
    HOST_EXIT_PCPU.load(Ordering::SeqCst)
}

pub fn set_host_exit_pcpu(pcpu_id: usize) {
    HOST_EXIT_PCPU.store(pcpu_id.min(1), Ordering::SeqCst);
    crate::guest_run::set_host_exit_pcpu(pcpu_id);
}

pub fn set_ap_vm2_ept(ept_pa: u64) {
    AP_VM2_EPT_PA.store(ept_pa, Ordering::SeqCst);
}

/// Capture BSP GDTR/IDTR for AP reuse (call from BSP before starting the AP).
pub fn capture_bsp_descriptors() {
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) core::ptr::addr_of_mut!(BSP_GDTR), options(nostack));
        core::arch::asm!("sidt [{}]", in(reg) core::ptr::addr_of_mut!(BSP_IDTR), options(nostack));
    }
    serial_print("[HYPSTER-SMP] captured BSP IDTR base=");
    crate::serial::serial_print_hex(unsafe { BSP_IDTR.base });
    serial_print("\n");
}

unsafe fn load_bsp_descriptors_on_ap() {
    core::arch::asm!("lgdt [{}]", in(reg) core::ptr::addr_of!(BSP_GDTR), options(readonly, nostack));
    core::arch::asm!("lidt [{}]", in(reg) core::ptr::addr_of!(BSP_IDTR), options(readonly, nostack));
    serial_print("[HYPSTER-SMP] AP loaded BSP GDTR/IDTR\n");
}

/// Install AP exit-stack + reset handoff flags. Call from BSP before starting the AP.
pub fn prepare_ap_context() {
    AP_READY.store(false, Ordering::SeqCst);
    AP_RUN_VM2.store(false, Ordering::SeqCst);
    AP_VM2_DONE.store(false, Ordering::SeqCst);
    AP_VM2_OK.store(false, Ordering::SeqCst);

    let stack_base = core::ptr::addr_of_mut!(AP_HOST_EXIT_STACK) as u64;
    let anchor = stack_base + 8192 - 8;
    crate::guest_run::install_ap_exit_stack(anchor);
    serial_print("[HYPSTER-SMP] AP exit stack anchor=");
    crate::serial::serial_print_hex(anchor);
    serial_print("\n");
}

/// UEFI `MpServices` AP entry. Expects [`set_ap_vm2_ept`] already called; runs VM2
/// immediately (BSP starts the AP only after VM1 has exited).
pub extern "efiapi" fn ap_uefi_procedure(_arg: *mut core::ffi::c_void) {
    set_host_exit_pcpu(1);
    AP_READY.store(true, Ordering::SeqCst);
    serial_print("[HYPSTER-SMP] ap_uefi_procedure on AP — running VM2\n");

    // Optional barrier if BSP wants to set AP_RUN_VM2 after dispatch.
    let timeout_spins = 50_000_000u64;
    let mut spins = 0u64;
    while !AP_RUN_VM2.load(Ordering::SeqCst) {
        spins += 1;
        if spins >= timeout_spins {
            // Proceed anyway if EPT was pre-armed (normal Phase 2 path).
            if AP_VM2_EPT_PA.load(Ordering::SeqCst) != 0 {
                break;
            }
            serial_print("[HYPSTER-SMP] AP timed out waiting for AP_RUN_VM2\n");
            AP_VM2_DONE.store(true, Ordering::SeqCst);
            return;
        }
        core::hint::spin_loop();
    }

    unsafe {
        run_vm2_on_ap();
    }
    AP_VM2_DONE.store(true, Ordering::SeqCst);
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
    load_bsp_descriptors_on_ap();
    let vmxon_hpa = core::ptr::addr_of_mut!(AP_VMXON_PAGE) as u64;
    if !crate::vmx::enable_hardware_vmx_at(vmxon_hpa) {
        serial_print("[HYPSTER-SMP] AP VMXON failed — BSP will fallback VM2\n");
        return;
    }
    let ept_pa = AP_VM2_EPT_PA.load(Ordering::SeqCst);
    let hv = crate::dual_run::dual_hv_mut();
    match hv.vcpu_mut(crate::VM2_ID, 0) {
        Ok(vcpu) => match crate::guest_run::enter_guest(vcpu, ept_pa) {
            Ok(_) => {
                if crate::guest_run::GUEST_STOP_REQUESTED.load(Ordering::SeqCst) {
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
