#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering, fence};

const HYPERCALL_GUEST_PUTCHAR: u64 = 0x200;
const HYPERCALL_GUEST_SHUTDOWN: u64 = 0x201;
const HYPERCALL_GET_PAYLOAD_LEN: u64 = 0x202;
const SHARED_IPC_GPA: u64 = 0xFE000000;
const THROUGHPUT_TARGET_PACKETS: u64 = 10_000;
const BURST_PER_SLICE: usize = 16;
const MAX_PACKET_LEN: usize = 1518;
const CHANNEL_QUEUE_CAPACITY: usize = 16;
const CHANNEL_QUEUE_MASK: usize = CHANNEL_QUEUE_CAPACITY - 1;
const PACKET_STRIDE: u64 = 1536;
const QUEUE_OFFSET: u64 = 64;
/// `Packet.len` offset: align_up(MAX_PACKET_LEN, 8) under #[repr(C)].
const PACKET_LEN_OFFSET: u64 = 1520;
const TAIL_OFFSET: u64 = 0x6040;
const HEAD_OFFSET: u64 = 0x60C0;
const CHANNEL_SLOT_SIZE: u64 = 0x6140;
const QUIET_SMP: bool = option_env!("HYPSTER_SMP").is_some();
const HEARTBEAT_OFFSET: u64 = 0xC280;
const HEARTBEAT_MAGIC: u64 = 0x4859_5042_4541_5400;

static mut CONS_CACHED_TAIL: usize = 0;
static mut TOUCH_SINK: u8 = 0;
static mut PAYLOAD_LEN: usize = 64;
static mut RECEIVED: u64 = 0;

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

/// Uses unaligned u64 loads (no memcpy/GOT — flat .bin has no relocator).
fn recv_counter(ch_base: u64, cached_tail: &mut usize) -> Option<u64> {
    let head_ptr = (ch_base + HEAD_OFFSET) as *mut AtomicUsize;
    let tail_ptr = (ch_base + TAIL_OFFSET) as *mut AtomicUsize;
    let head = unsafe { (*head_ptr).load(Ordering::Relaxed) };
    if head == *cached_tail {
        *cached_tail = unsafe { (*tail_ptr).load(Ordering::Acquire) };
    }
    if head == *cached_tail {
        return None;
    }
    fence(Ordering::Acquire);
    let slot_idx = (head & CHANNEL_QUEUE_MASK) as u64;
    let data_ptr = (ch_base + QUEUE_OFFSET + slot_idx * PACKET_STRIDE) as *const u64;
    let val = unsafe { core::ptr::read_unaligned(data_ptr) };
    unsafe {
        (*head_ptr).store(head.wrapping_add(1), Ordering::Release);
    }
    Some(val)
}

fn send_counter(ch_base: u64, cached_head: &mut usize, val: u64) -> bool {
    let head_ptr = (ch_base + HEAD_OFFSET) as *const AtomicUsize;
    let tail_ptr = (ch_base + TAIL_OFFSET) as *mut AtomicUsize;
    let tail = unsafe { (*tail_ptr).load(Ordering::Relaxed) };
    if tail.wrapping_sub(*cached_head) >= CHANNEL_QUEUE_CAPACITY {
        *cached_head = unsafe { (*head_ptr).load(Ordering::Acquire) };
        if tail.wrapping_sub(*cached_head) >= CHANNEL_QUEUE_CAPACITY {
            return false;
        }
    }
    let slot_idx = (tail & CHANNEL_QUEUE_MASK) as u64;
    let slot = ch_base + QUEUE_OFFSET + slot_idx * PACKET_STRIDE;
    unsafe {
        core::ptr::write_unaligned(slot as *mut u64, val);
        core::ptr::write_unaligned((slot + PACKET_LEN_OFFSET) as *mut usize, 8);
    }
    fence(Ordering::Release);
    unsafe {
        (*tail_ptr).store(tail.wrapping_add(1), Ordering::Release);
    }
    true
}

fn run_ipc_counter_exchange() -> ! {
    let hb = (SHARED_IPC_GPA + HEARTBEAT_OFFSET) as *mut u64;
    unsafe {
        core::ptr::write_volatile(hb, HEARTBEAT_MAGIC);
    }
    let mut cached_tail = 0usize;
    let mut ack_cached_head = 0usize;
    let ack_base = SHARED_IPC_GPA + CHANNEL_SLOT_SIZE;
    loop {
        let Some(counter) = recv_counter(SHARED_IPC_GPA, &mut cached_tail) else {
            core::hint::spin_loop();
            continue;
        };
        while !send_counter(ack_base, &mut ack_cached_head, counter) {
            core::hint::spin_loop();
        }
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        unsafe {
            core::ptr::write_volatile(hb.add(3), counter);
            core::ptr::write_volatile(hb.add(4), tsc);
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if QUIET_SMP {
        run_ipc_counter_exchange();
    }

    guest_print("Hello from VM2 guest running under Intel VT-x!\n");

    let mut payload_len = hypercall(HYPERCALL_GET_PAYLOAD_LEN, 0) as usize;
    if payload_len == 0 || payload_len > MAX_PACKET_LEN {
        payload_len = 64;
    }
    unsafe {
        PAYLOAD_LEN = payload_len;
        RECEIVED = 0;
    }

    let head_ptr = (SHARED_IPC_GPA + HEAD_OFFSET) as *mut AtomicUsize;
    let tail_ptr = (SHARED_IPC_GPA + TAIL_OFFSET) as *mut AtomicUsize;
    let ack_base = SHARED_IPC_GPA + CHANNEL_SLOT_SIZE;
    let ack_tail = (ack_base + TAIL_OFFSET) as *mut AtomicUsize;
    let ack_msg = b"ack from VM2";

    while unsafe { RECEIVED < THROUGHPUT_TARGET_PACKETS } {
        let payload_len = unsafe { PAYLOAD_LEN };
        let mut burst = 0usize;
        while burst < BURST_PER_SLICE && unsafe { RECEIVED < THROUGHPUT_TARGET_PACKETS } {
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
            let pkt = unsafe {
                &*((SHARED_IPC_GPA + QUEUE_OFFSET + slot_idx * PACKET_STRIDE) as *const Packet)
            };
            let n = payload_len.min(pkt.len).min(MAX_PACKET_LEN);
            let mut sum = 0u8;
            for i in 0..n {
                sum = sum.wrapping_add(pkt.data[i]);
            }
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TOUCH_SINK), sum);
                (*head_ptr).store(head.wrapping_add(1), Ordering::Release);
            }

            unsafe {
                let pkt = &mut *((ack_base + QUEUE_OFFSET) as *mut Packet);
                let m = ack_msg.len();
                pkt.data[..m].copy_from_slice(ack_msg);
                pkt.len = m;
                let t = (*ack_tail).load(Ordering::Relaxed);
                fence(Ordering::Release);
                (*ack_tail).store(t.wrapping_add(1), Ordering::Release);
                RECEIVED += 1;
            }
            burst += 1;
        }
        guest_hlt();
    }

    guest_print("VM2 throughput recv complete\n");
    guest_shutdown();
}
