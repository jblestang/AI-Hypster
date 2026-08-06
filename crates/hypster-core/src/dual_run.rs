//! Phase 1 sequential dual-partition bring-up: round-robin scheduler over two static VMs.

use crate::guest_boot;
use crate::guest_run;
use crate::scheduler::StaticScheduler;
use crate::serial::serial_print;
use crate::{Hypervisor, VM1_ID, VM2_ID};

/// Boot two static partitions under hardware VT-x with a sequential round-robin scheduler.
///
/// Initializes shared IPC at `SHARED_IPC_RING_BASE_HPA`, identity-maps both guest memories,
/// loads payloads, and runs each vCPU via [`guest_run::run_vcpu_once`] until both guests shutdown.
/// Does not use VirtualE1000, `run_vcpu_step`, or host-side channel simulation.
pub fn run_dual_partitions(
    vm1_mem: &mut [u8],
    vm2_mem: &mut [u8],
    ipc_mem: &mut [u8],
    vm1_code: &[u8],
    vm2_code: &[u8],
) -> Result<(), u64> {
    serial_print("\n========================================================\n");
    serial_print("[HYPSTER] Target B: Dual Partition VT-x Bring-up (Phase 1)\n");
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

    let mut hv = Hypervisor::new(vm1_mem, vm2_mem);
    hv.map_shared_ipc(ipc_hpa, ipc_size);
    hv.load_vm_payload(VM1_ID, vm1_code, guest_boot::GUEST_ENTRY_GPA);
    hv.load_vm_payload(VM2_ID, vm2_code, guest_boot::GUEST_ENTRY_GPA);

    let mut sched = StaticScheduler::from_config();
    let mut vm1_done = false;
    let mut vm2_done = false;

    while !vm1_done || !vm2_done {
        let (vm_id, vcpu_id) = sched.next_vcpu();

        if vm_id == VM1_ID && vm1_done {
            continue;
        }
        if vm_id == VM2_ID && vm2_done {
            continue;
        }

        let ept_pa = hv.ept_pa(vm_id);
        let vcpu = hv.vcpu_mut(vm_id, vcpu_id)?;

        match unsafe { guest_run::run_vcpu_once(vcpu, ept_pa) } {
            Ok(false) => {
                if vm_id == VM1_ID {
                    vm1_done = true;
                } else {
                    vm2_done = true;
                }
            }
            Ok(true) => {}
            Err(e) => return Err(e),
        }
    }

    serial_print("[HYPSTER] Dual partitions exited cleanly.\n");
    Ok(())
}
