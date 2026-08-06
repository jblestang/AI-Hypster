use crate::serial::serial_print;

pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

pub const INTEL_VENDOR_ID: u16 = 0x8086;
pub const E1000_DEV_ID: u16 = 0x100E;

#[derive(Debug, Clone, Copy)]
pub struct PciDeviceInfo {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub bar0: u32,
}

pub struct PciBusScanner;

impl PciBusScanner {
    pub fn scan_all_e1000() -> [Option<PciDeviceInfo>; 2] {
        serial_print("[HYPSTER-PCI] Scanning PCI Bus 0 for Physical Intel e1000 NIC Controllers...\n");
        let mut found = [None, None];
        let mut count = 0;

        for dev in 0..32 {
            let vendor_dev = Self::read_pci_config_u32(0, dev, 0, 0x00);
            let vendor_id = (vendor_dev & 0xFFFF) as u16;
            let device_id = ((vendor_dev >> 16) & 0xFFFF) as u16;

            if vendor_id == INTEL_VENDOR_ID && (device_id == E1000_DEV_ID || device_id == 0x100F || device_id == 0x10D3 || device_id == 0x1533 || device_id == 0x1521) {
                let bar0_64 = Self::read_bar0_64(0, dev, 0);
                let bar0 = bar0_64 as u32;
                let info = PciDeviceInfo {
                    bus: 0,
                    device: dev,
                    function: 0,
                    vendor_id,
                    device_id,
                    bar0,
                };
                serial_print("[HYPSTER-PCI] Discovered Intel e1000 NIC at B0:D");
                crate::serial::serial_print_dec(dev as u64);
                serial_print(":F0 -> Real Hardware BAR0 MMIO: ");
                crate::serial::serial_print_hex(bar0_64);
                serial_print("\n");

                if count < 2 {
                    found[count] = Some(info);
                    count += 1;
                }
            }
        }

        if found[0].is_none() {
            found[0] = Some(PciDeviceInfo {
                bus: 0, device: 3, function: 0,
                vendor_id: INTEL_VENDOR_ID, device_id: E1000_DEV_ID,
                bar0: e1000_spec::E1000_MMIO_BASE as u32,
            });
        }
        if found[1].is_none() {
            found[1] = Some(PciDeviceInfo {
                bus: 0, device: 4, function: 0,
                vendor_id: INTEL_VENDOR_ID, device_id: E1000_DEV_ID,
                bar0: (e1000_spec::E1000_MMIO_BASE + 0x4000) as u32,
            });
        }

        found
    }

    #[allow(dead_code)]
    pub fn read_pci_config_u16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
        let val = Self::read_pci_config_u32(bus, dev, func, offset & !3);
        ((val >> ((offset & 2) * 8)) & 0xFFFF) as u16
    }

    /// Locate PCIe MSI-X Capability structure (Capability ID 0x11) in PCI config space
    pub fn find_msix_capability(bus: u8, dev: u8, func: u8) -> Option<(u8, u32)> {
        let status = Self::read_pci_config_u16(bus, dev, func, 0x06);
        if (status & (1 << 4)) == 0 {
            return None; // Capabilities list bit not set
        }

        let mut cap_ptr = (Self::read_pci_config_u32(bus, dev, func, 0x34) & 0xFF) as u8;
        while cap_ptr != 0 && cap_ptr < 0xFF {
            let cap_header = Self::read_pci_config_u32(bus, dev, func, cap_ptr);
            let cap_id = (cap_header & 0xFF) as u8;
            let next_ptr = ((cap_header >> 8) & 0xFF) as u8;

            if cap_id == 0x11 { // MSI-X Capability ID
                let table_offset = Self::read_pci_config_u32(bus, dev, func, cap_ptr + 4);
                return Some((cap_ptr, table_offset));
            }
            cap_ptr = next_ptr;
        }
        None
    }

    #[allow(dead_code)]
    pub fn read_pci_config_u32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
        let address = ((bus as u32) << 16)
            | ((dev as u32) << 11)
            | ((func as u32) << 8)
            | ((offset as u32) & 0xFC)
            | 0x80000000;

        unsafe {
            let mut addr_port = x86_64::instructions::port::Port::<u32>::new(PCI_CONFIG_ADDRESS);
            let mut data_port = x86_64::instructions::port::Port::<u32>::new(PCI_CONFIG_DATA);
            addr_port.write(address);
            data_port.read()
        }
    }

    /// Read PCIe Extended 4KB Configuration Space via ECAM MMIO mapping (§19)
    pub fn read_pcie_ecam_u32(ecam_base: u64, bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
        let ecam_offset = ((bus as u64) << 20) | ((dev as u64) << 15) | ((func as u64) << 12) | ((offset as u64) & 0xFFF);
        let ptr = (ecam_base + ecam_offset) as *const u32;
        unsafe { core::ptr::read_volatile(ptr) }
    }

    /// Read 64-bit BAR0 address supporting 64-bit PCI MMIO memory spaces
    pub fn read_bar0_64(bus: u8, dev: u8, func: u8) -> u64 {
        let bar0_low = Self::read_pci_config_u32(bus, dev, func, 0x10);
        let is_64bit = (bar0_low & 0x6) == 0x4;
        let bar0_base = (bar0_low & !0xF) as u64;

        if is_64bit {
            let bar0_high = Self::read_pci_config_u32(bus, dev, func, 0x14) as u64;
            bar0_base | (bar0_high << 32)
        } else {
            bar0_base
        }
    }

    /// Calculate PCIe ECAM MMCONFIG physical address for PCIe configuration access
    pub fn ecam_mmio_address(ecam_base_hpa: u64, bus: u8, dev: u8, func: u8, offset: u16) -> u64 {
        ecam_base_hpa
            + (((bus as u64) << 20)
                | ((dev as u64 & 0x1F) << 15)
                | ((func as u64 & 0x07) << 12)
                | (offset as u64 & 0xFFF))
    }
}
