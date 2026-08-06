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

/// Matches `hypster_core::channel::Packet` layout.
#[repr(C, align(64))]
struct Packet {
    data: [u8; MAX_PACKET_LEN],
    len: usize,
}

#[repr(C, align(64))]
struct CachePadded<T> {
    value: T,
}

/// Matches `hypster_core::channel::UnidirectionalChannel` layout.
#[repr(C, align(64))]
struct UnidirectionalChannel {
    id: usize,
    _name: usize,
    queue: [Packet; CHANNEL_QUEUE_CAPACITY],
    tail: CachePadded<AtomicUsize>,
    cached_head: CachePadded<usize>,
    head: CachePadded<AtomicUsize>,
    cached_tail: CachePadded<usize>,
}

const CHANNEL_SLOT_SIZE: usize = core::mem::size_of::<UnidirectionalChannel>();

static mut CONS_CACHED_TAIL: usize = 0;
static mut PROD_CACHED_HEAD: usize = 0;

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

/// SPSC consumer receive — same algorithm as `hypster_core::channel::UnidirectionalChannel::recv`.
fn channel_recv(ch: &mut UnidirectionalChannel) -> Option<(usize, [u8; MAX_PACKET_LEN])> {
    let head = ch.head.value.load(Ordering::Relaxed);
    let cached_tail = unsafe { CONS_CACHED_TAIL };

    if head == cached_tail {
        let actual_tail = ch.tail.value.load(Ordering::Acquire);
        unsafe {
            CONS_CACHED_TAIL = actual_tail;
        }

        if head == actual_tail {
            return None;
        }
    }

    fence(Ordering::Acquire);

    let slot_idx = head & CHANNEL_QUEUE_MASK;
    let len = ch.queue[slot_idx].len.min(MAX_PACKET_LEN);
    let mut data = [0u8; MAX_PACKET_LEN];
    data[..len].copy_from_slice(&ch.queue[slot_idx].data[..len]);

    ch.head.value.store(head.wrapping_add(1), Ordering::Release);
    Some((len, data))
}

/// SPSC producer send on the VM2 -> VM1 ack channel.
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

fn guest_print_bytes(data: &[u8]) {
    for &byte in data {
        guest_putchar(byte);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    guest_print("VM2 waiting for IPC ping...\n");

    loop {
        let got_message = unsafe {
            let ch = &mut *(SHARED_IPC_GPA as *mut UnidirectionalChannel);
            if let Some((len, data)) = channel_recv(ch) {
                guest_print("VM2 received: ");
                guest_print_bytes(&data[..len]);
                guest_print("\n");

                let ack_ch = &mut *((SHARED_IPC_GPA + CHANNEL_SLOT_SIZE as u64) as *mut UnidirectionalChannel);
                let _ = channel_send(ack_ch, b"ack from VM2");
                true
            } else {
                false
            }
        };

        if got_message {
            guest_shutdown();
        }

        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}
