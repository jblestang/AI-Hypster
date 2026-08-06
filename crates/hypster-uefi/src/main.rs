#![no_std]
#![no_main]

extern crate alloc;

use uefi::prelude::*;
use uefi::proto::pi::mp::MpServices;
use uefi::boot::{self, EventType, Tpl};

use hypster_core::serial::serial_print;
use hypster_core::{run_dual_partitions, run_single_guest};

/// True when `TARGET_MODE=A` at UEFI build time; default is Target B (dual partition).
const TARGET_IS_A: bool = is_target_mode_a();

/// Compile-time SMP gate from `run_qemu.sh` (`HYPSTER_SMP=1` when `SMP>=2`).
const HYPSTER_SMP: bool = option_env!("HYPSTER_SMP").is_some();

const fn is_target_mode_a() -> bool {
    match option_env!("TARGET_MODE") {
        Some(mode) => {
            let b = mode.as_bytes();
            b.len() == 1 && b[0] == b'A'
        }
        None => false,
    }
}

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    serial_print("[UEFI-LOADER] PANIC occurred!\n");
    loop {
        x86_64::instructions::hlt();
    }
}

#[repr(C, align(4096))]
struct AlignedPartitionBuffer([u8; 4 * 1024 * 1024]);

#[repr(C, align(4096))]
struct AlignedIpcBuffer([u8; 0xD000]);

static mut VM1_PARTITION_BUF: AlignedPartitionBuffer = AlignedPartitionBuffer([0; 4 * 1024 * 1024]);
static mut VM2_PARTITION_BUF: AlignedPartitionBuffer = AlignedPartitionBuffer([0; 4 * 1024 * 1024]);
static mut SHARED_IPC_BUF: AlignedIpcBuffer = AlignedIpcBuffer([0; 0xD000]);

/// Park an AP on [`hypster_core::ap_trampoline::ap_uefi_procedure`] via non-blocking
/// `MpServices::startup_this_ap`. Nested KVM/OVMF cannot use INIT-SIPI safely.
///
/// Called from dual-run **after VM1 + VMXOFF** — a live AP during BSP `VMLAUNCH`
/// causes host `#PF` under nested KVM.
extern "C" fn start_ap_via_mp_services() -> bool {
    if !HYPSTER_SMP {
        return false;
    }

    serial_print("[UEFI-LOADER] Phase 2: starting AP via MpServices (post-VM1)\n");
    hypster_core::ap_trampoline::prepare_ap_context();
    // BSP arms AP_RUN_VM2 before invoking this hook; re-assert after prepare.
    hypster_core::ap_trampoline::AP_RUN_VM2.store(true, core::sync::atomic::Ordering::SeqCst);

    let handle = match boot::get_handle_for_protocol::<MpServices>() {
        Ok(h) => h,
        Err(_) => {
            serial_print("[UEFI-LOADER] MpServices protocol not found\n");
            return false;
        }
    };
    let mp = match boot::open_protocol_exclusive::<MpServices>(handle) {
        Ok(p) => p,
        Err(_) => {
            serial_print("[UEFI-LOADER] failed to open MpServices\n");
            return false;
        }
    };

    let count = match mp.get_number_of_processors() {
        Ok(c) => c,
        Err(_) => {
            serial_print("[UEFI-LOADER] get_number_of_processors failed\n");
            return false;
        }
    };
    serial_print("[UEFI-LOADER] processors total=");
    hypster_core::serial::serial_print_dec(count.total as u64);
    serial_print(" enabled=");
    hypster_core::serial::serial_print_dec(count.enabled as u64);
    serial_print("\n");

    if count.enabled < 2 {
        serial_print("[UEFI-LOADER] need >=2 enabled processors for Phase 2\n");
        return false;
    }

    let mut ap_number: Option<usize> = None;
    for i in 0..count.total {
        if let Ok(info) = mp.get_processor_info(i) {
            if info.is_enabled() && !info.is_bsp() {
                ap_number = Some(i);
                break;
            }
        }
    }
    let Some(ap_number) = ap_number else {
        serial_print("[UEFI-LOADER] no enabled AP found\n");
        return false;
    };

    let event = match unsafe {
        boot::create_event(EventType::empty(), Tpl::APPLICATION, None, None)
    } {
        Ok(e) => e,
        Err(_) => {
            serial_print("[UEFI-LOADER] create_event for AP wait failed\n");
            return false;
        }
    };

    match mp.startup_this_ap(
        ap_number,
        hypster_core::ap_trampoline::ap_uefi_procedure,
        core::ptr::null_mut(),
        Some(event),
        None,
    ) {
        Ok(()) => serial_print("[UEFI-LOADER] startup_this_ap dispatched (non-blocking)\n"),
        Err(_) => {
            serial_print("[UEFI-LOADER] startup_this_ap failed\n");
            return false;
        }
    }

    if hypster_core::ap_trampoline::wait_ap_ready(50_000_000) {
        serial_print("[UEFI-LOADER] AP checked in (AP_READY)\n");
        true
    } else {
        serial_print("[UEFI-LOADER] AP_READY timeout after MpServices start\n");
        false
    }
}

#[entry]
fn main() -> Status {
    let _ = uefi::helpers::init();
    hypster_core::serial::init_serial();
    serial_print("\n========================================================\n");
    if TARGET_IS_A {
        serial_print("[UEFI-LOADER] Hypster Target A — Single Guest VT-x\n");
    } else {
        serial_print("[UEFI-LOADER] Hypster Target B — Dual Partition VT-x\n");
    }
    serial_print("========================================================\n");

    unsafe {
        let vm1_ptr = core::ptr::addr_of_mut!(VM1_PARTITION_BUF).cast::<u8>();
        let vm1_slice = core::slice::from_raw_parts_mut(vm1_ptr, 4 * 1024 * 1024);

        serial_print("[UEFI-LOADER] VM1 partition buffer HPA ");
        hypster_core::serial::serial_print_hex(vm1_ptr as u64);
        serial_print("\n");

        static VM1_BINARY: &[u8] =
            include_bytes!("../../../target/x86_64-unknown-none/release/vm1-app.bin");

        if TARGET_IS_A {
            match run_single_guest(vm1_slice, VM1_BINARY) {
                Ok(()) => {
                    serial_print("\n========================================================\n");
                    serial_print("[HYPSTER] SUCCESS: Guest ran under hardware VT-x\n");
                    serial_print("========================================================\n\n");
                }
                Err(err) => {
                    serial_print("\n[HYPSTER] FAILED: Guest VT-x entry error ");
                    hypster_core::serial::serial_print_hex(err);
                    serial_print("\n");
                }
            }
        } else {
            // Register post-VM1 AP starter; do not dispatch APs before BSP VMLAUNCH
            // (nested KVM reboot).
            if HYPSTER_SMP {
                unsafe {
                    hypster_core::ap_trampoline::UEFI_START_AP = Some(start_ap_via_mp_services);
                }
                serial_print("[UEFI-LOADER] Phase 2: MpServices AP hook registered\n");
            }

            let vm2_ptr = core::ptr::addr_of_mut!(VM2_PARTITION_BUF).cast::<u8>();
            let vm2_slice = core::slice::from_raw_parts_mut(vm2_ptr, 4 * 1024 * 1024);
            let ipc_ptr = core::ptr::addr_of_mut!(SHARED_IPC_BUF).cast::<u8>();
            let ipc_slice = core::slice::from_raw_parts_mut(ipc_ptr, 0xD000);

            serial_print("[UEFI-LOADER] VM2 partition buffer HPA ");
            hypster_core::serial::serial_print_hex(vm2_ptr as u64);
            serial_print("\n");
            serial_print("[UEFI-LOADER] Shared IPC buffer HPA ");
            hypster_core::serial::serial_print_hex(ipc_ptr as u64);
            serial_print("\n");

            static VM2_BINARY: &[u8] =
                include_bytes!("../../../target/x86_64-unknown-none/release/vm2-app.bin");

            match run_dual_partitions(vm1_slice, vm2_slice, ipc_slice, VM1_BINARY, VM2_BINARY) {
                Ok(()) => {
                    serial_print("\n========================================================\n");
                    serial_print("[HYPSTER] SUCCESS: Dual partitions ran under hardware VT-x\n");
                    serial_print("========================================================\n\n");
                }
                Err(err) => {
                    serial_print("\n[HYPSTER] FAILED: Dual partition VT-x entry error ");
                    hypster_core::serial::serial_print_hex(err);
                    serial_print("\n");
                }
            }
        }

        let mut debug_exit_port = x86_64::instructions::port::Port::<u8>::new(0xf4);
        debug_exit_port.write(0x00);
        loop {
            x86_64::instructions::hlt();
        }
    }
}
