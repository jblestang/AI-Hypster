#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering, fence};

const HYPERCALL_GUEST_PUTCHAR: u64 = 0x200;
const HYPERCALL_GUEST_SHUTDOWN: u64 = 0x201;
const SHARED_IPC_GPA: u64 = 0xFE000000;
const MAX_PACKET_LEN: usize = 1518;
const CHANNEL_QUEUE_CAPACITY: usize = 16;
const CHANNEL_QUEUE_MASK: usize = CHANNEL_QUEUE_CAPACITY - 1;
const PACKET_STRIDE: u64 = 1536;
const QUEUE_OFFSET: u64 = 64;
const TAIL_OFFSET: u64 = 0x6040;
const HEAD_OFFSET: u64 = 0x60C0;
/// Must match `size_of::<UnidirectionalChannel>()` on the host (id + fat `&str` + queue + atomics).
const CHANNEL_SLOT_SIZE: u64 = 0x6140;

static mut CONS_CACHED_TAIL: usize = 0;

#[repr(C, align(64))]
struct Packet {
    data: [u8; MAX_PACKET_LEN],
    len: usize,
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    guest_print("PANIC in VM2 guest\n");
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
    guest_print("Hello from VM2 guest running under Intel VT-x!\n");

    let head_ptr = (SHARED_IPC_GPA + HEAD_OFFSET) as *mut AtomicUsize;
    let tail_ptr = (SHARED_IPC_GPA + TAIL_OFFSET) as *mut AtomicUsize;

    let head = unsafe { (*head_ptr).load(Ordering::Relaxed) };
    let mut cached_tail = unsafe { CONS_CACHED_TAIL };
    if head == cached_tail {
        cached_tail = unsafe { (*tail_ptr).load(Ordering::Acquire) };
        unsafe {
            CONS_CACHED_TAIL = cached_tail;
        }
    }

    if head == cached_tail {
        guest_print("VM2 IPC recv empty\n");
        guest_shutdown();
    }

    fence(Ordering::Acquire);
    let slot_idx = (head & CHANNEL_QUEUE_MASK) as u64;
    let pkt = unsafe {
        &*((SHARED_IPC_GPA + QUEUE_OFFSET + slot_idx * PACKET_STRIDE) as *const Packet)
    };
    let len = pkt.len.min(64);
    guest_print("VM2 received: ");
    for i in 0..len {
        guest_putchar(pkt.data[i]);
    }
    guest_print("\n");

    unsafe {
        (*head_ptr).store(head.wrapping_add(1), Ordering::Release);
    }

    let ack_base = SHARED_IPC_GPA + CHANNEL_SLOT_SIZE;
    let ack_tail = (ack_base + TAIL_OFFSET) as *mut AtomicUsize;
    let msg = b"ack from VM2";
    unsafe {
        let pkt = &mut *((ack_base + QUEUE_OFFSET) as *mut Packet);
        let n = msg.len();
        pkt.data[..n].copy_from_slice(msg);
        pkt.len = n;
        let t = (*ack_tail).load(Ordering::Relaxed);
        fence(Ordering::Release);
        (*ack_tail).store(t.wrapping_add(1), Ordering::Release);
    }

    guest_print("VM2 sent IPC ack\n");
    guest_shutdown();
}
