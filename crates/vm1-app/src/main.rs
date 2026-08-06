#![no_std]
#![no_main]

use core::panic::PanicInfo;

const HYPERCALL_GUEST_PUTCHAR: u64 = 0x200;
const HYPERCALL_GUEST_SHUTDOWN: u64 = 0x201;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    guest_print("PANIC in guest\n");
    guest_shutdown();
}

#[inline(always)]
fn hypercall(num: u64, arg0: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "vmcall",
            inout("rax") num => ret,
            in("rcx") arg0,
            options(nostack, preserves_flags),
        );
    }
    ret
}

fn guest_putchar(byte: u8) {
    hypercall(HYPERCALL_GUEST_PUTCHAR, byte as u64);
}

fn guest_print(s: &str) {
    for byte in s.bytes() {
        guest_putchar(byte);
    }
}

fn guest_shutdown() -> ! {
    hypercall(HYPERCALL_GUEST_SHUTDOWN, 0);
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    guest_print("Hello from VM1 guest running under Intel VT-x!\n");
    guest_print("Target A: real VMLAUNCH/VM-exit path active.\n");
    guest_shutdown();
}
