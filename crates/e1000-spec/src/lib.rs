#![no_std]

/// MMIO Base address for virtual e1000 PCI device in Guest Physical Address Space
pub const E1000_MMIO_BASE: u64 = 0x2000_0000;
pub const E1000_MMIO_SIZE: u64 = 0x4000; // 16 KB

// e1000 Register Offsets
pub const REG_CTRL: u32 = 0x00000;    // Device Control
pub const REG_STATUS: u32 = 0x00008;  // Device Status
pub const REG_EERD: u32 = 0x00014;    // EEPROM Read Register
pub const REG_ICR: u32 = 0x000C0;     // Interrupt Cause Read
pub const REG_IMS: u32 = 0x000D0;     // Interrupt Mask Set/Read
pub const REG_IMC: u32 = 0x000D8;     // Interrupt Mask Clear
pub const REG_RCTL: u32 = 0x00100;    // Receive Control
pub const REG_TCTL: u32 = 0x00400;    // Transmit Control
pub const REG_RDBAL: u32 = 0x02800;   // Receive Descriptor Base Low
pub const REG_RDBAH: u32 = 0x02804;   // Receive Descriptor Base High
pub const REG_RDLEN: u32 = 0x02808;   // Receive Descriptor Length
pub const REG_RDH: u32 = 0x02810;     // Receive Descriptor Head
pub const REG_RDT: u32 = 0x02818;     // Receive Descriptor Tail
pub const REG_TDBAL: u32 = 0x03800;   // Transmit Descriptor Base Low
pub const REG_TDBAH: u32 = 0x03804;   // Transmit Descriptor Base High
pub const REG_TDLEN: u32 = 0x03808;   // Transmit Descriptor Length
pub const REG_TDH: u32 = 0x03810;     // Transmit Descriptor Head
pub const REG_TDT: u32 = 0x03818;     // Transmit Descriptor Tail

// Control bits
pub const CTRL_SLU: u32 = 1 << 6;     // Set Link Up
pub const CTRL_RST: u32 = 1 << 26;    // Device Reset

// Status bits
pub const STATUS_LU: u32 = 1 << 1;    // Link Up
pub const STATUS_SPEED_1000: u32 = 2 << 6; // 1000Mbps speed

// Interrupt bits
pub const INT_RXT0: u32 = 1 << 7;    // Receiver Timer Interrupt
pub const INT_TXDW: u32 = 1 << 0;    // Transmit Descriptor Written Back

// e1000 Transmit Descriptor Structure (Legacy Format)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct E1000TxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub cso: u8,
    pub cmd: u8,
    pub status: u8,
    pub css: u8,
    pub special: u16,
}

pub const TX_CMD_EOP: u8 = 1 << 0;  // End of Packet
pub const TX_CMD_IFCS: u8 = 1 << 1; // Insert FCS
pub const TX_CMD_RS: u8 = 1 << 3;   // Report Status
pub const TX_STATUS_DD: u8 = 1 << 0; // Descriptor Done

// e1000 Receive Descriptor Structure (Legacy Format)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct E1000RxDesc {
    pub buffer_addr: u64,
    pub length: u16,
    pub checksum: u16,
    pub status: u8,
    pub errors: u8,
    pub special: u16,
}

pub const RX_STATUS_DD: u8 = 1 << 0;  // Descriptor Done
pub const RX_STATUS_EOP: u8 = 1 << 1; // End of Packet

pub const MAX_PACKET_LEN: usize = 1518;
pub const RING_SIZE: usize = 16;
