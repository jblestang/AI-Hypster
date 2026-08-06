//! AP bring-up via INIT-SIPI-SIPI and a low-memory 16-bit trampoline.
//!
//! Under nested KVM + OVMF, INIT/SIPI and writes to HPA 0x8000 are unsafe (hang /
//! #UD). [`bringup_ap`] detects CPUID.hypervisor and returns `false` so callers
//! fall back to sequential VM1→VM2. The trampoline + IPI path remains for bare metal.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::serial::serial_print;

pub static AP_READY: AtomicBool = AtomicBool::new(false);
pub static AP_RUN_VM2: AtomicBool = AtomicBool::new(false);
pub static AP_VM2_DONE: AtomicBool = AtomicBool::new(false);
pub static AP_VM2_OK: AtomicBool = AtomicBool::new(false);

static AP_VM2_EPT_PA: AtomicU64 = AtomicU64::new(0);
static HOST_EXIT_PCPU: AtomicUsize = AtomicUsize::new(0);
static AP_EXIT_STACK_TOP: AtomicU64 = AtomicU64::new(0);

const TRAMPOLINE_HPA: u64 = 0x8000;
const AP_EXIT_STACK_HPA: u64 = 0x9000;
const AP_VMXON_HPA: u64 = 0xC000;

pub fn host_exit_pcpu() -> usize {
    HOST_EXIT_PCPU.load(Ordering::SeqCst)
}

pub fn set_host_exit_pcpu(pcpu_id: usize) {
    HOST_EXIT_PCPU.store(pcpu_id, Ordering::SeqCst);
}

pub fn install_ap_exit_stack(page_hpa: u64) {
    AP_EXIT_STACK_TOP.store(page_hpa + 4096 - 8, Ordering::SeqCst);
}

pub fn ap_exit_stack_top_raw() -> u64 {
    AP_EXIT_STACK_TOP.load(Ordering::SeqCst)
}

pub fn set_ap_vm2_ept(ept_pa: u64) {
    AP_VM2_EPT_PA.store(ept_pa, Ordering::SeqCst);
}

/// Copy trampoline to 0x8000, INIT-SIPI-SIPI, wait briefly for [`AP_READY`].
///
/// # Safety
/// May write low physical memory and issue IPIs when not under a hypervisor.
pub unsafe fn bringup_ap(target_apic_id: u32, entry64: u64) -> bool {
    if cfg!(test) {
        return false;
    }

    AP_READY.store(false, Ordering::SeqCst);
    AP_RUN_VM2.store(false, Ordering::SeqCst);
    AP_VM2_DONE.store(false, Ordering::SeqCst);
    AP_VM2_OK.store(false, Ordering::SeqCst);

    if hypervisor_present() {
        serial_print(
            "[HYPSTER-SMP] Nested hypervisor — AP trampoline/INIT-SIPI skipped (sequential fallback)\n",
        );
        return false;
    }

    let mut cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem, preserves_flags));
    }

    unsafe {
        install_trampoline(entry64, cr3);
        core::ptr::write_bytes(AP_EXIT_STACK_HPA as *mut u8, 0, 0x1000);
        core::ptr::write_bytes(0xA000u64 as *mut u8, 0, 0x1000);
        core::ptr::write_bytes(AP_VMXON_HPA as *mut u8, 0, 0x1000);
    }
    install_ap_exit_stack(AP_EXIT_STACK_HPA);

    serial_print("[HYPSTER-SMP] INIT-SIPI-SIPI to APIC ID ");
    crate::serial::serial_print_dec(target_apic_id as u64);
    serial_print(" vector=0x08 (tramp @ 0x8000)\n");

    let apic = crate::scheduler::LocalApicDriver::new();
    unsafe {
        apic.send_init_sipi_sipi(target_apic_id, 0x08);
    }

    let timeout_cycles = 50_000u64.saturating_mul(3000);
    let start = unsafe { core::arch::x86_64::_rdtsc() };
    let mut spins = 0u64;
    while !AP_READY.load(Ordering::SeqCst) {
        spins += 1;
        if unsafe { core::arch::x86_64::_rdtsc() }.saturating_sub(start) > timeout_cycles
            || spins >= 50_000_000
        {
            serial_print("[HYPSTER-SMP] AP_READY timeout\n");
            return false;
        }
        core::hint::spin_loop();
    }
    serial_print("[HYPSTER-SMP] AP_READY signaled\n");
    true
}

#[no_mangle]
pub extern "C" fn ap_main() -> ! {
    set_host_exit_pcpu(1);
    AP_READY.store(true, Ordering::SeqCst);
    serial_print("[HYPSTER-SMP] ap_main on AP\n");
    loop {
        if AP_RUN_VM2.load(Ordering::SeqCst) {
            unsafe {
                run_vm2_on_ap();
            }
            AP_VM2_DONE.store(true, Ordering::SeqCst);
            break;
        }
        core::hint::spin_loop();
    }
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

unsafe fn run_vm2_on_ap() {
    if !crate::vmx::enable_hardware_vmx_at(AP_VMXON_HPA) {
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
