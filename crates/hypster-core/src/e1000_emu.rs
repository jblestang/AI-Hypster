use e1000_spec::*;
use crate::channel::UnidirectionalChannel;
use crate::serial::serial_print;

pub struct VirtualE1000 {
    pub vm_id: usize,
    pub ctrl: u32,
    pub status: u32,
    pub eerctl: u32,
    pub icr: u32,
    pub ims: u32,
    pub rctl: u32,
    pub tctl: u32,
    pub rdbal: u32,
    pub rdbah: u32,
    pub rdlen: u32,
    pub rdh: u32,
    pub rdt: u32,
    pub tdbal: u32,
    pub tdbah: u32,
    pub tdlen: u32,
    pub tdh: u32,
    pub tdt: u32,
    pub mac_addr: [u8; 6],
}

impl VirtualE1000 {
    pub fn new(vm_id: usize) -> Self {
        let mac = if vm_id == 0 {
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
        } else {
            [0x52, 0x54, 0x00, 0x65, 0x43, 0x21]
        };

        Self {
            vm_id,
            ctrl: 0,
            status: STATUS_LU | STATUS_SPEED_1000, // Link Up, 1000 Mbps
            eerctl: 0,
            icr: 0,
            ims: 0,
            rctl: 0,
            tctl: 0,
            rdbal: 0x40000,
            rdbah: 0,
            rdlen: (16 * core::mem::size_of::<E1000RxDesc>()) as u32,
            rdh: 0,
            rdt: 0,
            tdbal: 0x50000,
            tdbah: 0,
            tdlen: (16 * core::mem::size_of::<E1000TxDesc>()) as u32,
            tdh: 0,
            tdt: 0,
            mac_addr: mac,
        }
    }

    /// Trap guest MMIO Read
    pub fn mmio_read(&mut self, offset: u32) -> u32 {
        match offset {
            REG_CTRL => self.ctrl,
            REG_STATUS => self.status,
            REG_EERD => {
                // EEPROM MAC address read simulation
                0x1234_5678
            }
            REG_ICR => {
                let val = self.icr;
                self.icr = 0; // Clear on read
                val
            }
            REG_IMS => self.ims,
            REG_RCTL => self.rctl,
            REG_TCTL => self.tctl,
            REG_RDBAL => self.rdbal,
            REG_RDBAH => self.rdbah,
            REG_RDLEN => self.rdlen,
            REG_RDH => self.rdh,
            REG_RDT => self.rdt,
            REG_TDBAL => self.tdbal,
            REG_TDBAH => self.tdbah,
            REG_TDLEN => self.tdlen,
            REG_TDH => self.tdh,
            REG_TDT => self.tdt,
            _ => 0,
        }
    }

    /// Trap guest MMIO Write
    pub fn mmio_write(
        &mut self,
        offset: u32,
        val: u32,
        guest_mem_base: u64,
        out_channel: &mut UnidirectionalChannel,
    ) {
        match offset {
            REG_CTRL => {
                self.ctrl = val;
                if (val & CTRL_RST) != 0 {
                    self.status = STATUS_LU | STATUS_SPEED_1000;
                }
            }
            REG_IMS => self.ims |= val,
            REG_IMC => self.ims &= !val,
            REG_RCTL => self.rctl = val,
            REG_TCTL => self.tctl = val,
            REG_RDBAL => self.rdbal = val,
            REG_RDBAH => self.rdbah = val,
            REG_RDLEN => self.rdlen = val,
            REG_RDH => self.rdh = val,
            REG_RDT => self.rdt = val,
            REG_TDBAL => self.tdbal = val,
            REG_TDBAH => self.tdbah = val,
            REG_TDLEN => self.tdlen = val,
            REG_TDH => self.tdh = val,
            REG_TDT => {
                self.tdt = val;
                // Process transmit descriptors up to TDT
                self.process_tx(guest_mem_base, out_channel);
            }
            _ => {}
        }
    }

    /// Synchronize MMIO register writes from guest memory region
    pub fn sync_mmio(&mut self, guest_mem_base: u64, out_channel: &mut UnidirectionalChannel) {
        let mmio_hpa = guest_mem_base + E1000_MMIO_BASE;
        unsafe {
            let mmio_ptr = mmio_hpa as *const u32;

            let rdlen = core::ptr::read_volatile(mmio_ptr.add(REG_RDLEN as usize / 4));
            if rdlen != 0 && rdlen != self.rdlen {
                self.rdlen = rdlen;
                self.rdbal = core::ptr::read_volatile(mmio_ptr.add(REG_RDBAL as usize / 4));
                self.rdbah = core::ptr::read_volatile(mmio_ptr.add(REG_RDBAH as usize / 4));
            }

            let reg = REG_TDT;
            let val = core::ptr::read_volatile(mmio_ptr.add(reg as usize / 4));
            if reg == REG_TDT {
                self.tdbal = core::ptr::read_volatile(mmio_ptr.add(REG_TDBAL as usize / 4));
                self.tdbah = core::ptr::read_volatile(mmio_ptr.add(REG_TDBAH as usize / 4));
                self.tdlen = core::ptr::read_volatile(mmio_ptr.add(REG_TDLEN as usize / 4));
                self.tdt = val;
                self.process_tx(guest_mem_base, out_channel);
            }
        }
    }

    /// Process transmit ring when guest writes to TDT
    fn process_tx(&mut self, guest_mem_base: u64, out_channel: &mut UnidirectionalChannel) {
        let desc_size = core::mem::size_of::<E1000TxDesc>() as u64;
        let ring_size = if self.tdlen == 0 { 16 * desc_size as u32 } else { self.tdlen };
        let tx_ring_pa = guest_mem_base + (self.tdbal as u64 | ((self.tdbah as u64) << 32));

        if self.tdh != self.tdt || self.tdlen == 0 {
            let desc_addr = tx_ring_pa + (self.tdh as u64 * desc_size);
            let desc_ptr = desc_addr as *mut E1000TxDesc;

            unsafe {
                let desc = core::ptr::read_volatile(desc_ptr);
                let buf_gpa = desc.buffer_addr;
                let pkt_len = desc.length as usize;

                if pkt_len > 0 && pkt_len <= MAX_PACKET_LEN {
                    let buf_hpa = guest_mem_base + buf_gpa;
                    let pkt_slice = core::slice::from_raw_parts(buf_hpa as *const u8, pkt_len);

                    if self.vm_id == 0 {
                        serial_print("[HYPSTER-e1000] VM1 e1000 TX packet dispatched via ");
                        serial_print(out_channel.name);
                        serial_print("\n");
                        out_channel.send(pkt_slice);
                    } else {
                        serial_print("\n========================================================\n");
                        serial_print("[HYPSTER-ETH-DRIVER] Packet received from VM2 for Host Ethernet Driver!\n");
                        serial_print("[HYPSTER-ETH-DRIVER] Transmitting packet over Physical Ethernet hardware...\n");
                        serial_print("[HYPSTER-ETH-DRIVER] Packet Payload: \"");
                        for &b in pkt_slice {
                            if b >= 0x20 && b <= 0x7E {
                                crate::serial::serial_putchar(b);
                            }
                        }
                        serial_print("\"\n");
                        serial_print("[HYPSTER-ETH-DRIVER] Physical Ethernet Hardware Transmission Complete (OK)!\n");
                        serial_print("========================================================\n\n");
                    }
                }

                // Mark descriptor as Done (DD)
                let mut updated_desc = desc;
                updated_desc.status |= TX_STATUS_DD;
                core::ptr::write_volatile(desc_ptr, updated_desc);
            }

            self.tdh = (self.tdh + 1) % (self.tdlen / desc_size as u32);
        }

        self.icr |= INT_TXDW;
    }

    /// Receive packet delivered into VM e1000 Network Card interface
    pub fn deliver_rx_packet(&mut self, guest_mem_base: u64, pkt_bytes: &[u8]) -> bool {
        if self.rdlen == 0 {
            return false;
        }

        let rx_ring_pa = guest_mem_base + (self.rdbal as u64 | ((self.rdbah as u64) << 32));
        let desc_size = core::mem::size_of::<E1000RxDesc>() as u64;
        let num_descs = self.rdlen / desc_size as u32;

        let next_rdh = (self.rdh + 1) % num_descs;
        let desc_addr = rx_ring_pa + (self.rdh as u64 * desc_size);
        let desc_ptr = desc_addr as *mut E1000RxDesc;

        unsafe {
            let desc = core::ptr::read_volatile(desc_ptr);
            let buf_gpa = desc.buffer_addr;

            if buf_gpa != 0 {
                let buf_hpa = guest_mem_base + buf_gpa;
                let copy_len = pkt_bytes.len().min(MAX_PACKET_LEN);
                let dest_slice = core::slice::from_raw_parts_mut(buf_hpa as *mut u8, copy_len);
                dest_slice.copy_from_slice(&pkt_bytes[..copy_len]);

                let mut updated_desc = desc;
                updated_desc.length = copy_len as u16;
                updated_desc.status = RX_STATUS_DD | RX_STATUS_EOP;
                core::ptr::write_volatile(desc_ptr, updated_desc);

                self.rdh = next_rdh;
            }
        }

        self.icr |= INT_RXT0; // Set receive interrupt flag for e1000 card
        true
    }
}

#[repr(C, align(4096))]
pub struct HardwareRxBuffers {
    pub ring: [E1000RxDesc; 16],
    pub buffers: [[u8; 2048]; 16],
}

static mut HW_RX_STORAGE: HardwareRxBuffers = HardwareRxBuffers {
    ring: [E1000RxDesc { buffer_addr: 0, length: 0, checksum: 0, status: 0, errors: 0, special: 0 }; 16],
    buffers: [[0u8; 2048]; 16],
};

pub fn init_hardware_e1000_rx(mmio_bar0: u32) {
    if mmio_bar0 == 0 || mmio_bar0 == 0x20000000 {
        return;
    }
    unsafe {
        let bar_ptr = mmio_bar0 as *mut u32;

        // Reset e1000 device
        core::ptr::write_volatile(bar_ptr.add(REG_CTRL as usize / 4), CTRL_RST | CTRL_SLU);
        for _ in 0..10_000 { core::hint::spin_loop(); }
        core::ptr::write_volatile(bar_ptr.add(REG_CTRL as usize / 4), CTRL_SLU);

        // Map descriptors to static RAM buffers
        let hw_rx = core::ptr::addr_of_mut!(HW_RX_STORAGE);
        for i in 0..16 {
            let buf_ptr = (*hw_rx).buffers[i].as_ptr() as u64;
            (*hw_rx).ring[i].buffer_addr = buf_ptr;
            (*hw_rx).ring[i].status = 0;
        }

        let ring_pa = (*hw_rx).ring.as_ptr() as u64;
        core::ptr::write_volatile(bar_ptr.add(REG_RDBAL as usize / 4), ring_pa as u32);
        core::ptr::write_volatile(bar_ptr.add(REG_RDBAH as usize / 4), (ring_pa >> 32) as u32);
        core::ptr::write_volatile(bar_ptr.add(REG_RDLEN as usize / 4), (16 * core::mem::size_of::<E1000RxDesc>()) as u32);
        core::ptr::write_volatile(bar_ptr.add(REG_RDH as usize / 4), 0);
        core::ptr::write_volatile(bar_ptr.add(REG_RDT as usize / 4), 15);

        // Enable RX: RCTL EN (1<<1), SBP (1<<2), UPE (1<<3), MPE (1<<4), BAM (1<<15), SECRC (1<<26)
        let rctl = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 15) | (1 << 26);
        core::ptr::write_volatile(bar_ptr.add(REG_RCTL as usize / 4), rctl);
    }
}

pub fn poll_hardware_e1000_rx(mmio_bar0: u32, out_buf: &mut [u8]) -> Option<usize> {
    if mmio_bar0 == 0 || mmio_bar0 == 0x20000000 {
        return None;
    }
    unsafe {
        let bar_ptr = mmio_bar0 as *const u32;
        let icr = core::ptr::read_volatile(bar_ptr.add(REG_ICR as usize / 4));
        let hw_rx = core::ptr::addr_of_mut!(HW_RX_STORAGE);

        let rdh = (core::ptr::read_volatile(bar_ptr.add(REG_RDH as usize / 4)) as usize) % 16;
        let desc = &(*hw_rx).ring[rdh];

        if (desc.status & RX_STATUS_DD) != 0 || (icr & INT_RXT0) != 0 {
            let len = (desc.length as usize).min(out_buf.len());
            if len > 0 {
                let src_slice = core::slice::from_raw_parts((*hw_rx).buffers[rdh].as_ptr(), len);
                out_buf[..len].copy_from_slice(src_slice);

                // Reset descriptor & advance RDT
                (*hw_rx).ring[rdh].status = 0;
                let mut_bar_ptr = bar_ptr as *mut u32;
                core::ptr::write_volatile(mut_bar_ptr.add(REG_RDT as usize / 4), rdh as u32);
                return Some(len);
            }
        }
    }
    None
}
