//! Dual-partition bring-up: true concurrent BSP=VM1 + AP=VM2 when `HYPSTER_SMP`,
//! otherwise nearly-parallel alternating VT-x slices (HLT yield) on the BSP.
//!
//! Target B runs a payload-size ladder. Guests query length via hypercall
//! `GET_PAYLOAD_LEN`. Stats use calibrated TSC Hz and counted × len bytes.

use core::sync::atomic::Ordering;

use crate::ap_trampoline::{
    bringup_ap, capture_bsp_descriptors, set_ap_vm2_ept, try_uefi_start_ap, AP_BSP_WAITING,
    AP_READY, AP_RUN_VM2, AP_VM2_DONE, AP_VM2_OK,
};
use crate::guest_boot::{self, GUEST_ENTRY_GPA};
use crate::guest_run::{self, enter_guest, guest_stop_requested, run_vcpu_once};
use crate::ipc_region;
use crate::serial::serial_print;
use crate::throughput::{self, PAYLOAD_SIZES, THROUGHPUT_TARGET_PACKETS};
use crate::{Hypervisor, VM1_ID, VM2_ID};
use core::mem::MaybeUninit;

static mut DUAL_HV: MaybeUninit<Hypervisor> = MaybeUninit::uninit();

/// # Safety
/// BSP must have initialized `DUAL_HV`.
pub unsafe fn dual_hv_mut() -> &'static mut Hypervisor {
    unsafe { DUAL_HV.assume_init_mut() }
}

fn run_until_both_shutdown(hv: &mut Hypervisor, ept1: u64, ept2: u64) -> Result<(), u64> {
    let mut vm1_done = false;
    let mut vm2_done = false;
    let mut slices = 0u64;
    while (!vm1_done || !vm2_done) && slices < 50_000_000 {
        slices += 1;
        if !vm1_done {
            unsafe {
                let vcpu = hv.vcpu_mut(VM1_ID, 0)?;
                match run_vcpu_once(vcpu, ept1)? {
                    true => {}
                    false => {
                        serial_print("[HYPSTER] VM1 exited cleanly.\n");
                        vm1_done = true;
                    }
                }
            }
        }
        if !vm2_done {
            unsafe {
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
    }
    if !vm1_done || !vm2_done {
        serial_print("[HYPSTER] Throughput run incomplete (guest(s) still live)\n");
        return Err(0xDEAD);
    }
    Ok(())
}

/// True concurrent: BSP=VM1 + AP=VM2, guests spin forever in non-root (no exits).
fn run_concurrent_both(hv: &mut Hypervisor, ept1: u64, ept2: u64, ipc_hpa: u64) -> Result<(), u64> {
    guest_run::set_concurrent_mode(true);

    capture_bsp_descriptors();
    set_ap_vm2_ept(ept2);
    AP_VM2_DONE.store(false, Ordering::SeqCst);
    AP_VM2_OK.store(false, Ordering::SeqCst);
    AP_BSP_WAITING.store(false, Ordering::SeqCst);
    AP_RUN_VM2.store(true, Ordering::SeqCst);

    unsafe {
        crate::pir::GLOBAL_PIR_MANAGER.descriptors[1] =
            crate::pir::PostedInterruptDescriptor::new();
    }
    serial_print("[HYPSTER-PIR] Doorbell skipped for concurrent AP VM2\n");

    let ap_ready = if try_uefi_start_ap() {
        serial_print("[HYPSTER] Phase 2: AP parked via UEFI MpServices (pre-concurrent)\n");
        AP_READY.load(Ordering::SeqCst) || crate::ap_trampoline::wait_ap_ready(50_000_000)
    } else {
        serial_print("[HYPSTER] Phase 2: attempting INIT-SIPI AP bring-up\n");
        unsafe { bringup_ap(1, crate::ap_trampoline::ap_main as *const () as usize as u64) }
    };

    if !ap_ready {
        serial_print("[HYPSTER] concurrent AP start failed — falling back to alternating\n");
        guest_run::set_concurrent_mode(false);
        return run_until_both_shutdown(hv, ept1, ept2);
    }

    let hb_hpa = ipc_hpa + crate::ipc_region::HEARTBEAT_OFFSET as u64;
    serial_print(
        "[HYPSTER] concurrent: releasing AP; VM1↔VM2 IPC counter exchange (endless)\n",
    );
    serial_print("[HYPSTER] heartbeat HPA=");
    crate::serial::serial_print_hex(hb_hpa);
    serial_print(" (magic, vm1_acked_counter, tsc, vm2_acked_counter, tsc)\n");
    serial_print(
        "[HYPSTER] both counters must rise in lockstep — ./scripts/check_heartbeats.sh\n",
    );

    AP_BSP_WAITING.store(true, Ordering::SeqCst);
    for _ in 0..500_000 {
        core::hint::spin_loop();
    }

    serial_print("[HYPSTER] concurrent: BSP VMLAUNCH VM1 (no return expected)\n");
    let vcpu = hv.vcpu_mut(VM1_ID, 0)?;
    unsafe {
        enter_guest(vcpu, ept1)?;
    }
    serial_print("[HYPSTER] unexpected return from endless VM1\n");
    guest_run::set_concurrent_mode(false);
    Err(0xDEAD)
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

    guest_boot::install_identity_map(vm1_mem);
    guest_boot::install_identity_map(vm2_mem);

    unsafe {
        DUAL_HV.write(Hypervisor::new(vm1_mem, vm2_mem));
        let hv = DUAL_HV.assume_init_mut();
        hv.map_shared_ipc(ipc_hpa, ipc_size);

        let hz = throughput::tsc_hz();
        let smp = cfg!(hypster_smp);
        if smp {
            serial_print("[HYPSTER] Concurrent: BSP=VM1 + AP=VM2 (QEMU -smp, no time slicing)\n");
        } else {
            serial_print("[HYPSTER] Nearly-parallel: alternating VM1↔VM2 slices (HLT yield)\n");
        }
        serial_print("[HYPSTER] TSC calibrated Hz=");
        crate::serial::serial_print_dec(hz);
        serial_print(" target packets/size=");
        crate::serial::serial_print_dec(THROUGHPUT_TARGET_PACKETS);
        serial_print("\n");

        if !smp {
            let vec = crate::config::POSTED_INTERRUPT_NOTIFICATION_VECTOR;
            crate::pir::GLOBAL_PIR_MANAGER.post_vector(1, vec);
            serial_print("[HYPSTER-PIR] Doorbell posted to VM2 (notification vector)\n");
        }

        let ept1 = hv.ept_pa(VM1_ID);
        let ept2 = hv.ept_pa(VM2_ID);

        // Concurrent AP path currently supports one MpServices dispatch; run a
        // single size under SMP, full ladder under alternating BSP.
        let sizes: &[u64] = if smp { &PAYLOAD_SIZES[..1] } else { &PAYLOAD_SIZES };

        for (i, &payload_len) in sizes.iter().enumerate() {
            ipc_region::init_ipc_at_hpa(ipc_hpa);
            hv.load_vm_payload(VM1_ID, vm1_code, GUEST_ENTRY_GPA);
            hv.load_vm_payload(VM2_ID, vm2_code, GUEST_ENTRY_GPA);
            guest_run::set_trial_payload_len(payload_len);

            if let Ok(v) = hv.vcpu_mut(VM1_ID, 0) {
                v.launched = false;
            }
            if let Ok(v) = hv.vcpu_mut(VM2_ID, 0) {
                v.launched = false;
            }

            serial_print("[HYPSTER] Trial payload_len=");
            crate::serial::serial_print_dec(payload_len);
            serial_print(" trial_id=");
            crate::serial::serial_print_dec((i as u64) + 1);
            serial_print("\n");

            let start_tsc = core::arch::x86_64::_rdtsc();
            if smp {
                run_concurrent_both(hv, ept1, ept2, ipc_hpa)?;
            } else {
                run_until_both_shutdown(hv, ept1, ept2)?;
            }
            let end_tsc = core::arch::x86_64::_rdtsc();

            let ch0 = &*ipc_region::vm1_to_vm2(ipc_hpa);
            let sent = ch0.tail.value.load(Ordering::SeqCst) as u64;
            let recv = ch0.head.value.load(Ordering::SeqCst) as u64;
            if sent != THROUGHPUT_TARGET_PACKETS || recv != THROUGHPUT_TARGET_PACKETS {
                serial_print("[HYPSTER] Count mismatch sent=");
                crate::serial::serial_print_dec(sent);
                serial_print(" recv=");
                crate::serial::serial_print_dec(recv);
                serial_print("\n");
                return Err(0xDEAD);
            }

            let bytes = sent.saturating_mul(payload_len);
            let stats =
                throughput::stats_from_measurement(sent, bytes, start_tsc, end_tsc, hz);
            throughput::print_stats(&stats, payload_len);
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
