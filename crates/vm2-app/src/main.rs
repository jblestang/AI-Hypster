#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering, fence};

const HYPERCALL_GUEST_PUTCHAR: u64 = 0x200;
const HYPERCALL_GUEST_SHUTDOWN: u64 = 0x201;
const SHARED_IPC_GPA: u64 = 0xFE000000;
const THROUGHPUT_TARGET_PACKETS: u64 = 10_000;
const BURST_PER_SLICE: usize = 16;
const MAX_PACKET_LEN: usize = 1518;
const CHANNEL_QUEUE_CAPACITY: usize = 16;
const CHANNEL_QUEUE_MASK: usize = CHANNEL_QUEUE_CAPACITY - 1;
const PACKET_STRIDE: u64 = 1536;
const QUEUE_OFFSET: u64 = 64;
const TAIL_OFFSET: u64 = 0x6040;
const HEAD_OFFSET: u64 = 0x60C0;
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

fn guest_hlt() {
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

fn guest_shutdown() -> ! {
    hypercall(HYPERCALL_GUEST_SHUTDOWN, 0);
    loop {
        guest_hlt();
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    guest_print("Hello from VM2 guest running under Intel VT-x!\n");

    let head_ptr = (SHARED_IPC_GPA + HEAD_OFFSET) as *mut AtomicUsize;
    let tail_ptr = (SHARED_IPC_GPA + TAIL_OFFSET) as *mut AtomicUsize;
    let ack_base = SHARED_IPC_GPA + CHANNEL_SLOT_SIZE;
    let ack_tail = (ack_base + TAIL_OFFSET) as *mut AtomicUsize;
    let ack_msg = b"ack from VM2";

    let mut received: u64 = 0;
    while received < THROUGHPUT_TARGET_PACKETS {
        let mut burst = 0usize;
        while burst < BURST_PER_SLICE && received < THROUGHPUT_TARGET_PACKETS {
            let head = unsafe { (*head_ptr).load(Ordering::Relaxed) };
            let mut cached_tail = unsafe { CONS_CACHED_TAIL };
            if head == cached_tail {
                cached_tail = unsafe { (*tail_ptr).load(Ordering::Acquire) };
                unsafe {
                    CONS_CACHED_TAIL = cached_tail;
                }
            }
            if head == cached_tail {
                break;
            }

            fence(Ordering::Acquire);
            let slot_idx = (head & CHANNEL_QUEUE_MASK) as u64;
            let _pkt = unsafe {
                &*((SHARED_IPC_GPA + QUEUE_OFFSET + slot_idx * PACKET_STRIDE) as *const Packet)
            };
            unsafe {
                (*head_ptr).store(head.wrapping_add(1), Ordering::Release);
            }

            // Ack on reverse channel (overwrite slot 0; host counts target round-trips).
            unsafe {
                let pkt = &mut *((ack_base + QUEUE_OFFSET) as *mut Packet);
                let n = ack_msg.len();
                pkt.data[..n].copy_from_slice(ack_msg);
                pkt.len = n;
                let t = (*ack_tail).load(Ordering::Relaxed);
                fence(Ordering::Release);
                (*ack_tail).store(t.wrapping_add(1), Ordering::Release);
            }

            received += 1;
            burst += 1;
        }
        guest_hlt();
    }

    guest_print("VM2 throughput recv complete\n");
    guest_shutdown();
}
