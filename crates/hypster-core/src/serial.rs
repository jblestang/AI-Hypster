//! IBM PC 16550 UART serial diagnostic driver (`serial.rs`).
//!
//! Under SMP / concurrent BSP+AP:
//! - **Line-scoped lock**: a core keeps the UART until it emits `\\n`, so
//!   `serial_print` + `serial_print_hex` + `\\n` cannot be split mid-message.
//! - **`[Cn]` tags** (optional): each new host line is prefixed with the pCPU id.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use x86_64::instructions::port::Port;

use crate::config::{
    UART16550_BAUD_115200_DLL, UART16550_BAUD_115200_DLM, UART16550_COM1_PORT,
    UART16550_FCR_ENABLE_FIFO, UART16550_LCR_8N1,
};

static SERIAL_LOCK: AtomicBool = AtomicBool::new(false);
static SERIAL_OWNER: AtomicUsize = AtomicUsize::new(usize::MAX);
/// When set, host lines are prefixed `[C0]` / `[C1]`.
static TAG_PCPU: AtomicBool = AtomicBool::new(false);
static AT_LINE_START: AtomicBool = AtomicBool::new(true);
/// Guest putchar line buffers (one per pCPU).
static mut GUEST_LINE: [[u8; 160]; 2] = [[0; 160]; 2];
static GUEST_LINE_LEN: [AtomicU8; 2] = [AtomicU8::new(0), AtomicU8::new(0)];

fn pcpu_id() -> usize {
    crate::ap_trampoline::current_pcpu().min(1)
}

/// Acquire UART ownership for this pCPU (no-op if already owned by us).
fn acquire_line() {
    if cfg!(test) {
        return;
    }
    let me = pcpu_id();
    if SERIAL_OWNER.load(Ordering::Relaxed) == me {
        return;
    }
    while SERIAL_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    SERIAL_OWNER.store(me, Ordering::Relaxed);
}

/// Release UART ownership (end of line).
fn release_line() {
    if cfg!(test) {
        return;
    }
    SERIAL_OWNER.store(usize::MAX, Ordering::Relaxed);
    SERIAL_LOCK.store(false, Ordering::Release);
    AT_LINE_START.store(true, Ordering::Relaxed);
}

fn putchar_raw(c: u8) {
    if cfg!(test) {
        return;
    }
    unsafe {
        let mut data = Port::<u8>::new(UART16550_COM1_PORT);
        data.write(c);
    }
}

fn write_host_byte(b: u8) {
    acquire_line();
    let tag = TAG_PCPU.load(Ordering::Relaxed);
    if tag && AT_LINE_START.load(Ordering::Relaxed) && b != b'\n' && b != b'\r' {
        putchar_raw(b'[');
        putchar_raw(b'C');
        putchar_raw(b'0' + pcpu_id() as u8);
        putchar_raw(b']');
        putchar_raw(b' ');
        AT_LINE_START.store(false, Ordering::Relaxed);
    }
    if b == b'\n' {
        putchar_raw(b'\r');
        putchar_raw(b'\n');
        release_line();
    } else if b == b'\r' {
        // ignore; newline emits CRLF
    } else {
        putchar_raw(b);
        AT_LINE_START.store(false, Ordering::Relaxed);
    }
}

/// Hold the line lock across a closure (still releases on embedded newlines).
pub fn serial_with_lock(f: impl FnOnce()) {
    acquire_line();
    f();
    // If caller forgot a trailing newline, flush ownership so we cannot deadlock.
    if SERIAL_OWNER.load(Ordering::Relaxed) == pcpu_id() {
        release_line();
    }
}

pub fn set_pcpu_line_tags(on: bool) {
    TAG_PCPU.store(on, Ordering::SeqCst);
}

pub fn init_serial() {
    if cfg!(test) {
        return;
    }
    unsafe {
        let mut ier = Port::<u8>::new(UART16550_COM1_PORT + 1);
        let mut fcr = Port::<u8>::new(UART16550_COM1_PORT + 2);
        let mut lcr = Port::<u8>::new(UART16550_COM1_PORT + 3);
        let mut dll = Port::<u8>::new(UART16550_COM1_PORT);
        let mut dlm = Port::<u8>::new(UART16550_COM1_PORT + 1);

        ier.write(0x00);
        lcr.write(0x80);
        dll.write(UART16550_BAUD_115200_DLL);
        dlm.write(UART16550_BAUD_115200_DLM);
        lcr.write(UART16550_LCR_8N1);
        fcr.write(UART16550_FCR_ENABLE_FIFO);
    }
}

pub fn poll_com2_host_packet(_buffer: &mut [u8]) -> usize {
    0
}

pub fn serial_putchar(c: u8) {
    write_host_byte(c);
}

pub fn serial_print(s: &str) {
    for b in s.bytes() {
        write_host_byte(b);
    }
}

pub fn serial_print_hex(val: u64) {
    write_host_byte(b'0');
    write_host_byte(b'x');
    for shift in (0..16).rev() {
        let nibble = ((val >> (shift * 4)) & 0xF) as u8;
        let char_byte = if nibble < 10 {
            b'0' + nibble
        } else {
            b'A' + (nibble - 10)
        };
        write_host_byte(char_byte);
    }
}

pub fn serial_print_dec(mut val: u64) {
    if val == 0 {
        write_host_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        write_host_byte(buf[i]);
    }
}

/// Buffer a guest putchar; on newline emit one locked line tagged `[VMn/Cn]`.
pub fn guest_putchar_line(vm_id: u8, c: u8) {
    let cpu = pcpu_id();
    let len = GUEST_LINE_LEN[cpu].load(Ordering::Relaxed) as usize;
    if c == b'\n' || len + 1 >= 160 {
        acquire_line();
        putchar_raw(b'[');
        putchar_raw(b'V');
        putchar_raw(b'M');
        putchar_raw(b'0' + vm_id.min(9));
        putchar_raw(b'/');
        putchar_raw(b'C');
        putchar_raw(b'0' + cpu as u8);
        putchar_raw(b']');
        putchar_raw(b' ');
        unsafe {
            for &b in &GUEST_LINE[cpu][..len] {
                if b == b'\n' {
                    putchar_raw(b'\r');
                }
                putchar_raw(b);
            }
        }
        putchar_raw(b'\r');
        putchar_raw(b'\n');
        release_line();
        GUEST_LINE_LEN[cpu].store(0, Ordering::Relaxed);
        if c != b'\n' && c != b'\r' {
            unsafe {
                GUEST_LINE[cpu][0] = c;
            }
            GUEST_LINE_LEN[cpu].store(1, Ordering::Relaxed);
        }
        return;
    }
    if c == b'\r' {
        return;
    }
    unsafe {
        GUEST_LINE[cpu][len] = c;
    }
    GUEST_LINE_LEN[cpu].store((len + 1) as u8, Ordering::Relaxed);
}
