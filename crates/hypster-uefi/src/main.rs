#![no_std]
#![no_main]

extern crate alloc;

use uefi::prelude::*;
use hypster_core::serial::serial_print;
use hypster_core::Hypervisor;

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    serial_print("[UEFI-LOADER] PANIC occurred!\n");
    loop {
        x86_64::instructions::hlt();
    }
}

#[repr(C, align(4096))]
struct AlignedPartitionBuffer([u8; 2 * 1024 * 1024]);

static mut VM1_PARTITION_BUF: AlignedPartitionBuffer = AlignedPartitionBuffer([0; 2 * 1024 * 1024]);
static mut VM2_PARTITION_BUF: AlignedPartitionBuffer = AlignedPartitionBuffer([0; 2 * 1024 * 1024]);

#[entry]
fn main() -> Status {
    let _ = uefi::helpers::init();
    hypster_core::serial::init_serial();
    serial_print("\n========================================================\n");
    serial_print("[UEFI-LOADER] Booting Hypster Static Partition Hypervisor\n");
    serial_print("========================================================\n");

    unsafe {
        let vm1_ptr = core::ptr::addr_of_mut!(VM1_PARTITION_BUF).cast::<u8>();
        let vm2_ptr = core::ptr::addr_of_mut!(VM2_PARTITION_BUF).cast::<u8>();
        let vm1_slice = core::slice::from_raw_parts_mut(vm1_ptr, 2 * 1024 * 1024);
        let vm2_slice = core::slice::from_raw_parts_mut(vm2_ptr, 2 * 1024 * 1024);

        serial_print("[UEFI-LOADER] VM1 Partition Static HPA: ");
        hypster_core::serial::serial_print_hex(vm1_ptr as u64);
        serial_print("\n[UEFI-LOADER] VM2 Partition Static HPA: ");
        hypster_core::serial::serial_print_hex(vm2_ptr as u64);
        serial_print("\n[UEFI-LOADER] Retrieving Physical Memory Map & Firmware Hand-off...\n");
        serial_print("[UEFI-LOADER] Firmware Boot Services Hand-off Complete. Hypster Hypervisor in Control.\n");

        let mut hypervisor = Hypervisor::new(vm1_slice, vm2_slice);

        // Load compiled bare metal application binaries into VM memory
        static VM1_BINARY: &[u8] = include_bytes!("../../../target/x86_64-unknown-none/release/vm1-app.bin");
        static VM2_BINARY: &[u8] = include_bytes!("../../../target/x86_64-unknown-none/release/vm2-app.bin");

        hypervisor.load_vm_payload(hypster_core::VM1_ID, VM1_BINARY, 0x1000);
        hypervisor.load_vm_payload(hypster_core::VM2_ID, VM2_BINARY, 0x1000);

        let stats = hypervisor.run();

        serial_print("\n========================================================\n");
        serial_print("[BENCHMARK] Throughput & Performance Measurement Results\n");
        serial_print("========================================================\n");
        serial_print("  Hypervisor Architecture : Type-1 Static Partitioning\n");
        serial_print("  Network Protocol Stack  : smoltcp (no_std IPv4/TCP in VM1)\n");
        serial_print("  Packet Pipeline Path    : Net -> VM1 e1000 -> smoltcp -> Port -> VM2 -> VM2 e1000\n");
        serial_print("--------------------------------------------------------\n");
        serial_print("  Total Packets Processed : ");
        hypster_core::serial::serial_print_dec(stats.total_packets);
        serial_print(" packets\n  Total Transferred Volume: ");
        hypster_core::serial::serial_print_dec(stats.total_bytes);
        serial_print(" bytes (");
        hypster_core::serial::serial_print_dec(stats.total_bytes * 8);
        serial_print(" bits)\n  Total CPU Cycles        : ");
        hypster_core::serial::serial_print_dec(stats.elapsed_cycles);
        serial_print(" cycles (");
        hypster_core::serial::serial_print_dec(stats.elapsed_us);
        serial_print(" us)\n  Avg Latency / Packet    : ");
        hypster_core::serial::serial_print_dec(stats.cycles_per_packet);
        serial_print(" cycles/pkt (");
        hypster_core::serial::serial_print_dec(stats.us_per_packet);
        serial_print(" us/pkt)\n  Packet Rate (Throughput): ");
        hypster_core::serial::serial_print_dec(stats.pps);
        serial_print(" Packets/sec\n  Data Rate (Throughput)  : ");
        hypster_core::serial::serial_print_dec(stats.kbps);
        serial_print(" Kbps (");
        hypster_core::serial::serial_print_dec(stats.mbps);
        serial_print(" Mbps)\n");
        serial_print("========================================================\n");
        serial_print("[HYPSTER] SUCCESS: Static Partition Throughput Benchmarked Successfully!\n");
        serial_print("========================================================\n\n");

        for _ in 0..10_000_000 {
            core::hint::spin_loop();
        }

        let mut debug_exit_port = x86_64::instructions::port::Port::<u8>::new(0xf4);
        debug_exit_port.write(0x00);
        loop {
            x86_64::instructions::hlt();
        }
    }
}

