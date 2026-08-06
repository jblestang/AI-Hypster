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

/// Target A builds keep the one-shot Hello + ping path (no VM2 consumer).
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

#[repr(C, align(64))]
struct Packet {
    data: [u8; MAX_PACKET_LEN],
    len: usize,
}

#[repr(C, align(64))]
struct CachePadded<T> {
    value: T,
}

#[repr(C, align(64))]
struct UnidirectionalChannel {
    id: usize,
    _name_ptr: usize,
    _name_len: usize,
    queue: [Packet; CHANNEL_QUEUE_CAPACITY],
    tail: CachePadded<AtomicUsize>,
    cached_head: CachePadded<usize>,
    head: CachePadded<AtomicUsize>,
    cached_tail: CachePadded<usize>,
}

static mut PROD_CACHED_HEAD: usize = 0;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    guest_print("PANIC in VM1 guest\n");
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

fn channel_send(ch: &mut UnidirectionalChannel, data: &[u8]) -> bool {
    let tail = ch.tail.value.load(Ordering::Relaxed);
    let cached_head = unsafe { PROD_CACHED_HEAD };

    if tail.wrapping_sub(cached_head) >= CHANNEL_QUEUE_CAPACITY {
        let actual_head = ch.head.value.load(Ordering::Acquire);
        unsafe {
            PROD_CACHED_HEAD = actual_head;
        }
        if tail.wrapping_sub(actual_head) >= CHANNEL_QUEUE_CAPACITY {
            return false;
        }
    }

    let slot_idx = tail & CHANNEL_QUEUE_MASK;
    let copy_len = data.len().min(MAX_PACKET_LEN);
    ch.queue[slot_idx].data[..copy_len].copy_from_slice(&data[..copy_len]);
    ch.queue[slot_idx].len = copy_len;
    fence(Ordering::Release);
    ch.tail.value.store(tail.wrapping_add(1), Ordering::Release);
    true
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    guest_print("Hello from VM1 guest running under Intel VT-x!\n");

    let msg = b"ping from VM1";
    unsafe {
        let ch = &mut *(SHARED_IPC_GPA as *mut UnidirectionalChannel);
        if TARGET_IS_A {
            if channel_send(ch, msg) {
                guest_print("VM1 sent IPC ping\n");
            } else {
                guest_print("VM1 IPC send failed (ring full)\n");
            }
        } else {
            let mut sent: u64 = 0;
            while sent < THROUGHPUT_TARGET_PACKETS {
                let mut burst = 0usize;
                while burst < BURST_PER_SLICE && sent < THROUGHPUT_TARGET_PACKETS {
                    if !channel_send(ch, msg) {
                        break;
                    }
                    sent += 1;
                    burst += 1;
                }
                guest_hlt();
            }
            guest_print("VM1 throughput send complete\n");
        }
    }

    guest_shutdown();
}
