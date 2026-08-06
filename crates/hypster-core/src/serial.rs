use x86_64::instructions::port::Port;

const COM1: u16 = 0x3F8;

pub fn init_serial() {
    if cfg!(test) {
        return;
    }
    unsafe {
        let mut ier = Port::<u8>::new(COM1 + 1);
        let mut fcr = Port::<u8>::new(COM1 + 2);
        let mut lcr = Port::<u8>::new(COM1 + 3);
        let mut dll = Port::<u8>::new(COM1);
        let mut dlm = Port::<u8>::new(COM1 + 1);

        ier.write(0x00); // Disable UART interrupts
        lcr.write(0x80); // Enable DLAB (Divisor Latch Access Bit)
        dll.write(0x01); // Set Baud Rate Divisor LSB = 1 (115200 Baud)
        dlm.write(0x00); // Set Baud Rate Divisor MSB = 0
        lcr.write(0x03); // 8 bits, no parity, 1 stop bit (8N1)
        fcr.write(0xC7); // Enable FIFO, clear 14-byte threshold queues
    }
}

pub fn poll_com2_host_packet(_buffer: &mut [u8]) -> usize {
    0
}

pub fn serial_putchar(c: u8) {
    if cfg!(test) {
        return;
    }
    unsafe {
        let mut data = Port::<u8>::new(COM1);
        data.write(c);
    }
}

pub fn serial_print(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            serial_putchar(b'\r');
        }
        serial_putchar(b);
    }
}

pub fn serial_print_hex(val: u64) {
    serial_print("0x");
    for shift in (0..16).rev() {
        let nibble = ((val >> (shift * 4)) & 0xF) as u8;
        let char_byte = if nibble < 10 { b'0' + nibble } else { b'A' + (nibble - 10) };
        serial_putchar(char_byte);
    }
}

pub fn serial_print_dec(mut val: u64) {
    if val == 0 {
        serial_putchar(b'0');
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
        serial_putchar(buf[i]);
    }
}
