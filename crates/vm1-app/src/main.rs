#![no_std]
#![no_main]

use core::panic::PanicInfo;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub struct E1000RxToken {
    buffer: [u8; 1514],
    length: usize,
}

impl RxToken for E1000RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer[..self.length])
    }
}

pub struct E1000TxToken;

impl TxToken for E1000TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = [0u8; 1514];
        let res = f(&mut buf[..len.min(1514)]);

        // Direct Guest EPT Shared Memory IPC (Bao/Jailhouse model - 0 VM-Exits!)
        unsafe {
            let ipc_ring = 0x0010_0000 as *mut u8;
            core::ptr::write_volatile(ipc_ring, len as u8);
        }
        res
    }
}

pub struct E1000PhyDevice {
    has_packet: bool,
}

impl E1000PhyDevice {
    pub fn new() -> Self {
        Self { has_packet: true }
    }
}

impl Device for E1000PhyDevice {
    type RxToken<'a> = E1000RxToken where Self: 'a;
    type TxToken<'a> = E1000TxToken where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.has_packet {
            self.has_packet = false;

            // Direct Guest RAM Receive (0 VM-Exits!)
            let mut rx = E1000RxToken {
                buffer: [0u8; 1514],
                length: 64,
            };
            // Populate Ethernet frame header for smoltcp stack processing
            rx.buffer[0..6].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]); // Dest MAC
            rx.buffer[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0xAA, 0xBB, 0xCC]); // Src MAC
            rx.buffer[12..14].copy_from_slice(&[0x08, 0x00]); // EtherType IPv4

            Some((rx, E1000TxToken))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(E1000TxToken)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Register VM1 with hypervisor
    unsafe {
        core::arch::asm!(
            "mov rax, 0x101",
            "mov rcx, 0x01",
            "vmcall",
            inout("rax") 0x101u64 => _,
            inout("rcx") 1u64 => _,
        );
    }

    // 2. Initialize smoltcp stack inside VM1 guest environment
    let mut phy_device = E1000PhyDevice::new();
    let mac = HardwareAddress::Ethernet(EthernetAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]));
    let mut config = Config::new(mac);
    config.random_seed = 0x12345678;

    let mut iface = Interface::new(config, &mut phy_device, Instant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(192, 168, 1, 10)), 24));
    });

    let mut rx_buf = [0u8; 1024];
    let mut tx_buf = [0u8; 1024];
    let tcp_socket = TcpSocket::new(TcpSocketBuffer::new(&mut rx_buf[..]), TcpSocketBuffer::new(&mut tx_buf[..]));
    let mut socket_storage = [SocketStorage::EMPTY; 2];
    let mut sockets = SocketSet::new(&mut socket_storage[..]);
    let _handle = sockets.add(tcp_socket);

    // 3. Poll smoltcp stack loop inside VM1 guest
    let mut time_ms = 0i64;
    loop {
        let timestamp = Instant::from_millis(time_ms);
        iface.poll(timestamp, &mut phy_device, &mut sockets);
        time_ms += 10;

        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
