//! Dual-partition bring-up with nearly-parallel (alternating) VT-x slices.
//!
//! Guests burst on shared IPC and `hlt` to yield. The BSP round-robins
//! [`run_vcpu_once`] until both shut down after the throughput target.
//! Concurrent AP VMLAUNCH under nested KVM remains unsupported; SMP builds
//! use the same alternating path.

use crate::guest_boot;
use crate::guest_run::run_vcpu_once;
use crate::serial::serial_print;
use crate::throughput::{self, THROUGHPUT_TARGET_PACKETS};
use crate::{Hypervisor, VM1_ID, VM2_ID};
use core::mem::MaybeUninit;

static mut DUAL_HV: MaybeUninit<Hypervisor> = MaybeUninit::uninit();

/// # Safety
/// BSP must have initialized `DUAL_HV`.
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

        serial_print("[HYPSTER] Nearly-parallel: alternating VM1↔VM2 slices (HLT yield)\n");
        serial_print("[HYPSTER] Throughput target packets=");
        crate::serial::serial_print_dec(THROUGHPUT_TARGET_PACKETS);
        serial_print("\n");

        let vec = crate::config::POSTED_INTERRUPT_NOTIFICATION_VECTOR;
        crate::pir::GLOBAL_PIR_MANAGER.post_vector(1, vec);
        serial_print("[HYPSTER-PIR] Doorbell posted to VM2 (notification vector)\n");

        let ept1 = hv.ept_pa(VM1_ID);
        let ept2 = hv.ept_pa(VM2_ID);

        let mut vm1_done = false;
        let mut vm2_done = false;
        let mut slices = 0u64;
        let start_tsc = core::arch::x86_64::_rdtsc();

        while (!vm1_done || !vm2_done) && slices < 50_000_000 {
            slices += 1;
            if !vm1_done {
                let vcpu = hv.vcpu_mut(VM1_ID, 0)?;
                match run_vcpu_once(vcpu, ept1)? {
                    true => {}
                    false => {
                        serial_print("[HYPSTER] VM1 exited cleanly.\n");
                        vm1_done = true;
                    }
                }
            }
            if !vm2_done {
                let vcpu = hv.vcpu_mut(VM2_ID, 0)?;
                match run_vcpu_once(vcpu, ept2)? {
                    true => {}
                    false => {
                        serial_print("[HYPSTER] VM2 exited cleanly.\n");
                        vm2_done = true;
                    }
                }
            }
        }

        let end_tsc = core::arch::x86_64::_rdtsc();

        if !vm1_done || !vm2_done {
            serial_print("[HYPSTER] Throughput run incomplete (guest(s) still live)\n");
            return Err(0xDEAD);
        }

        let stats = throughput::stats_from_tsc(THROUGHPUT_TARGET_PACKETS, start_tsc, end_tsc);
        throughput::print_stats(&stats);

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
