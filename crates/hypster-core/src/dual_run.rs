//! Dual-partition bring-up: sequential VM1→VM2, with optional AP handoff when
//! `HYPSTER_SMP` / `cfg(hypster_smp)` is enabled at build time.

use crate::ap_trampoline::{
    ap_main, bringup_ap, capture_bsp_descriptors, set_ap_vm2_ept, try_uefi_start_ap, AP_BSP_WAITING,
    AP_READY, AP_RUN_VM2, AP_VM2_DONE, AP_VM2_OK,
};
use crate::guest_boot;
use crate::guest_run::{enter_guest, GUEST_STOP_REQUESTED};
use crate::serial::serial_print;
use crate::{Hypervisor, VM1_ID, VM2_ID};
use core::mem::MaybeUninit;
use core::sync::atomic::Ordering;

static mut DUAL_HV: MaybeUninit<Hypervisor> = MaybeUninit::uninit();

/// # Safety
/// BSP must have initialized `DUAL_HV`; AP must only touch VM2 while BSP waits.
pub unsafe fn dual_hv_mut() -> &'static mut Hypervisor {
    unsafe { DUAL_HV.assume_init_mut() }
}

pub fn run_dual_partitions(
    vm1_mem: &mut [u8],
    vm2_mem: &mut [u8],
    ipc_mem: &mut [u8],
    vm1_code: &[u8],
    vm2_code: &[u8],
) -> Result<(), u64> {
    serial_print("\n========================================================\n");
    serial_print("[HYPSTER] Target B: Dual Partition VT-x Bring-up\n");
    serial_print("========================================================\n");

    let ipc_size = crate::config::SHARED_IPC_RING_SIZE;
    assert!(
        ipc_mem.len() as u64 >= ipc_size,
        "IPC buffer smaller than SHARED_IPC_RING_SIZE"
    );
    let ipc_hpa = ipc_mem.as_mut_ptr() as u64;
    unsafe {
        crate::ipc_region::init_ipc_at_hpa(ipc_hpa);
    }

    guest_boot::install_identity_map(vm1_mem);
    guest_boot::install_identity_map(vm2_mem);

    unsafe {
        DUAL_HV.write(Hypervisor::new(vm1_mem, vm2_mem));
        let hv = DUAL_HV.assume_init_mut();
        hv.map_shared_ipc(ipc_hpa, ipc_size);
        hv.load_vm_payload(VM1_ID, vm1_code, guest_boot::GUEST_ENTRY_GPA);
        hv.load_vm_payload(VM2_ID, vm2_code, guest_boot::GUEST_ENTRY_GPA);

        let smp = cfg!(hypster_smp);
        if smp {
            serial_print(
                "[HYPSTER] Phase 2: BSP runs VM1 first; AP runs VM2 after handoff\n",
            );
        } else {
            serial_print("[HYPSTER] Phase 1: sequential run — VM1 then VM2\n");
        }

        // Always run VM1 on BSP first. Starting an AP before VMLAUNCH reboots
        // nested KVM; after VM1 the AP can take VM2 alone.
        {
            let ept_pa = hv.ept_pa(VM1_ID);
            let vcpu = hv.vcpu_mut(VM1_ID, 0)?;
            enter_guest(vcpu, ept_pa)?;
            if !GUEST_STOP_REQUESTED.load(Ordering::SeqCst) {
                serial_print("[HYPSTER] VM1 did not shutdown cleanly\n");
                return Err(0xDEAD);
            }
            serial_print("[HYPSTER] VM1 exited cleanly.\n");
        }

        {
            // Posted-interrupt doorbell uses a local-APIC self-IPI. Under nested
            // KVM that IPI is emulated on the BSP fine, but on an MpServices AP it
            // triggers "KVM internal error / emulation failure". Skip when the AP
            // will run VM2; sequential BSP VM2 still gets the doorbell below.
            if !(smp && cfg!(hypster_smp)) {
                let vec = crate::config::POSTED_INTERRUPT_NOTIFICATION_VECTOR;
                crate::pir::GLOBAL_PIR_MANAGER.post_vector(1, vec);
                serial_print("[HYPSTER-PIR] Doorbell posted to VM2 (notification vector)\n");
            } else {
                // Ensure no stale ON bit from a prior run.
                unsafe {
                    crate::pir::GLOBAL_PIR_MANAGER.descriptors[1] =
                        crate::pir::PostedInterruptDescriptor::new();
                }
                serial_print("[HYPSTER-PIR] Doorbell skipped for AP VM2 (nested APIC)\n");
            }
        }

        let mut ap_ran_vm2 = false;
        if smp {
            unsafe {
                crate::vmx::disable_hardware_vmx();
            }
            serial_print("[HYPSTER] BSP VMXOFF before AP VM2\n");
            capture_bsp_descriptors();
            set_ap_vm2_ept(hv.ept_pa(VM2_ID));
            AP_RUN_VM2.store(true, Ordering::SeqCst);

            let ap_ready = if try_uefi_start_ap() {
                serial_print("[HYPSTER] Phase 2: AP started via UEFI MpServices (post-VM1)\n");
                AP_READY.load(Ordering::SeqCst)
                    || crate::ap_trampoline::wait_ap_ready(50_000_000)
            } else {
                serial_print("[HYPSTER] Phase 2: attempting INIT-SIPI AP bring-up\n");
                bringup_ap(1, ap_main as *const () as usize as u64)
            };

            if ap_ready {
                // Release AP to VMLAUNCH only once BSP is past MpServices prints.
                AP_BSP_WAITING.store(true, Ordering::SeqCst);
                let timeout_cycles = 2_000_000u64.saturating_mul(5000);
                let start = core::arch::x86_64::_rdtsc();
                let mut spins = 0u64;
                while !AP_VM2_DONE.load(Ordering::SeqCst) {
                    spins += 1;
                    if core::arch::x86_64::_rdtsc().saturating_sub(start) > timeout_cycles
                        || spins > 100_000_000
                    {
                        break;
                    }
                    core::hint::spin_loop();
                }
                if AP_VM2_OK.load(Ordering::SeqCst) {
                    serial_print("[HYPSTER] VM2 exited cleanly (AP).\n");
                    ap_ran_vm2 = true;
                } else {
                    serial_print(
                        "[HYPSTER] AP VM2 incomplete — sequential fallback for VM2 on BSP\n",
                    );
                }
            } else {
                serial_print(
                    "[HYPSTER] Phase 2 fallback: sequential VM2 on BSP (AP did not start)\n",
                );
            }

            if !ap_ran_vm2 {
                let vmx_ok = unsafe { crate::vmx::enable_hardware_vmx() };
                if !vmx_ok {
                    serial_print("[HYPSTER] BSP VMXON restore failed after AP path\n");
                    return Err(0xBEEF);
                }
                let vec = crate::config::POSTED_INTERRUPT_NOTIFICATION_VECTOR;
                crate::pir::GLOBAL_PIR_MANAGER.post_vector(1, vec);
                serial_print("[HYPSTER-PIR] Doorbell posted to VM2 (BSP fallback)\n");
            }
        }

        if !ap_ran_vm2 {
            let ept_pa = hv.ept_pa(VM2_ID);
            let vcpu = hv.vcpu_mut(VM2_ID, 0)?;
            enter_guest(vcpu, ept_pa)?;
            if !GUEST_STOP_REQUESTED.load(Ordering::SeqCst) {
                serial_print("[HYPSTER] VM2 did not shutdown cleanly\n");
                return Err(0xDEAD);
            }
            serial_print("[HYPSTER] VM2 exited cleanly.\n");
        }

        finish(hv);
        Ok(())
    }
}

fn finish(hv: &Hypervisor) {
    let bar = hv.hw_bar0 as u64;
    let ok = hv.iommu.validate_dma(1, bar, 0x1000);
    if ok {
        serial_print("[HYPSTER-IOMMU] VM2 DMA window validated against VT-d domain\n");
    } else {
        serial_print("[HYPSTER-IOMMU] VM2 DMA window validation soft-fail (QEMU stub)\n");
    }
    serial_print("[HYPSTER] Dual partitions exited cleanly.\n");
}
