#![no_std]
#![no_main]

extern crate alloc;

use uefi::prelude::*;
use hypster_core::serial::serial_print;
use hypster_core::{run_dual_partitions, run_single_guest};

/// True when `TARGET_MODE=A` at UEFI build time; default is Target B (dual partition).
const TARGET_IS_A: bool = is_target_mode_a();

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

static mut VM1_PARTITION_BUF: AlignedPartitionBuffer = AlignedPartitionBuffer([0; 4 * 1024 * 1024]);
static mut VM2_PARTITION_BUF: AlignedPartitionBuffer = AlignedPartitionBuffer([0; 4 * 1024 * 1024]);

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

        static VM1_BINARY: &[u8] = include_bytes!("../../../target/x86_64-unknown-none/release/vm1-app.bin");

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
            let vm2_ptr = core::ptr::addr_of_mut!(VM2_PARTITION_BUF).cast::<u8>();
            let vm2_slice = core::slice::from_raw_parts_mut(vm2_ptr, 4 * 1024 * 1024);

            serial_print("[UEFI-LOADER] VM2 partition buffer HPA ");
            hypster_core::serial::serial_print_hex(vm2_ptr as u64);
            serial_print("\n");

            static VM2_BINARY: &[u8] = include_bytes!("../../../target/x86_64-unknown-none/release/vm2-app.bin");

            match run_dual_partitions(vm1_slice, vm2_slice, VM1_BINARY, VM2_BINARY) {
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
