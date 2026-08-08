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
/// After two channels (each 0x6140); must match hypster_core::ipc_region::HEARTBEAT_OFFSET.
const HEARTBEAT_OFFSET: u64 = 0xC280;
const HEARTBEAT_MAGIC: u64 = 0x4859_5042_4541_5400;

const MAX_PACKET_LEN: usize = 1518;
const CHANNEL_QUEUE_CAPACITY: usize = 16;
const CHANNEL_QUEUE_MASK: usize = CHANNEL_QUEUE_CAPACITY - 1;

/// Target A builds keep the one-shot Hello + ping path (no VM2 consumer).
const TARGET_IS_A: bool = is_target_mode_a();
/// Concurrent SMP: skip chatty putchar (host serial is not MP-safe under dual VMLAUNCH).
const QUIET_SMP: bool = option_env!("HYPSTER_SMP").is_some();

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
static mut CONS_CACHED_TAIL: usize = 0;
static mut PAYLOAD_LEN: usize = 64;
static mut PAYLOAD: [u8; MAX_PACKET_LEN] = [0; MAX_PACKET_LEN];
/// In memory — guest GPRs are not restored across alternating VMRESUME.
static mut SENT: u64 = 0;

const CHANNEL_SLOT_SIZE: u64 = 0x6140;
const PACKET_STRIDE: u64 = 1536;
const QUEUE_OFFSET: u64 = 64;
/// `Packet.len` offset: align_up(MAX_PACKET_LEN, 8) under #[repr(C)].
const PACKET_LEN_OFFSET: u64 = 1520;
const TAIL_OFFSET: u64 = 0x6040;
const HEAD_OFFSET: u64 = 0x60C0;

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

/// Recv on reverse channel (VM2→VM1) via raw offsets — returns counter or None.
/// Uses unaligned u64 loads (no memcpy/GOT — flat .bin has no relocator).
fn channel_recv_counter(ch_base: u64) -> Option<u64> {
    let head_ptr = (ch_base + HEAD_OFFSET) as *mut AtomicUsize;
    let tail_ptr = (ch_base + TAIL_OFFSET) as *mut AtomicUsize;
    let head = unsafe { (*head_ptr).load(Ordering::Relaxed) };
    let mut cached_tail = unsafe { CONS_CACHED_TAIL };
    if head == cached_tail {
        cached_tail = unsafe { (*tail_ptr).load(Ordering::Acquire) };
        unsafe {
            CONS_CACHED_TAIL = cached_tail;
        }
    }
    if head == cached_tail {
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

fn channel_send_counter(ch_base: u64, cached_head: &mut usize, val: u64) -> bool {
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

/// Concurrent endless: VM1 posts counter on ch0, waits for matching ack on ch1.
fn run_ipc_counter_exchange() -> ! {
    let hb = (SHARED_IPC_GPA + HEARTBEAT_OFFSET) as *mut u64;
    unsafe {
        core::ptr::write_volatile(hb, HEARTBEAT_MAGIC);
    }
    let mut fwd_cached_head = 0usize;
    let mut counter = 0u64;
    let ack_base = SHARED_IPC_GPA + CHANNEL_SLOT_SIZE;
    loop {
        while !channel_send_counter(SHARED_IPC_GPA, &mut fwd_cached_head, counter) {
            core::hint::spin_loop();
        }
        loop {
            if let Some(ack) = channel_recv_counter(ack_base) {
                if ack == counter {
                    break;
                }
            }
            core::hint::spin_loop();
        }
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        unsafe {
            core::ptr::write_volatile(hb.add(1), counter);
            core::ptr::write_volatile(hb.add(2), tsc);
        }
        counter = counter.wrapping_add(1);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if QUIET_SMP {
        run_ipc_counter_exchange();
    }

    guest_print("Hello from VM1 guest running under Intel VT-x!\n");

    unsafe {
        let ch = &mut *(SHARED_IPC_GPA as *mut UnidirectionalChannel);
        if TARGET_IS_A {
            if channel_send(ch, b"ping from VM1") {
                guest_print("VM1 sent IPC ping\n");
            } else {
                guest_print("VM1 IPC send failed (ring full)\n");
            }
        } else {
            let len = hypercall(HYPERCALL_GET_PAYLOAD_LEN, 0) as usize;
            PAYLOAD_LEN = if len == 0 || len > MAX_PACKET_LEN {
                64
            } else {
                len
            };
            for i in 0..PAYLOAD_LEN {
                PAYLOAD[i] = (i & 0xFF) as u8;
            }
            SENT = 0;
            while SENT < THROUGHPUT_TARGET_PACKETS {
                let len = PAYLOAD_LEN;
                let slice = core::slice::from_raw_parts(PAYLOAD.as_ptr(), len);
                let mut burst = 0usize;
                while burst < BURST_PER_SLICE && SENT < THROUGHPUT_TARGET_PACKETS {
                    if !channel_send(ch, slice) {
                        break;
                    }
                    SENT += 1;
                    burst += 1;
                }
                guest_hlt();
            }
            guest_print("VM1 throughput send complete\n");
        }
    }

    guest_shutdown();
}
