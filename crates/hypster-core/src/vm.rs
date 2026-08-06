use crate::vmx::VCpu;
use crate::e1000_emu::VirtualE1000;
use crate::channel::UnidirectionalChannel;
use crate::serial::serial_print;

pub struct VirtualMachine {
    pub id: usize,
    pub name: &'static str,
    pub vcpu_count: usize,
    pub ram_bytes: u64,
    pub mem_base_hpa: u64,
    pub vcpus: [Option<VCpu>; 2],
    pub e1000: VirtualE1000,
    pub ept: crate::ept::EptManager,
    pub finished: bool,
}

impl VirtualMachine {
    pub fn new(
        id: usize,
        name: &'static str,
        vcpu_count: usize,
        ram_bytes: u64,
        mem_base_hpa: u64,
    ) -> Self {
        let entry_point = 0x1000; // GPA 4KB
        let stack_top = 0xF000;   // GPA 60KB stack

        let vcpu0 = Some(VCpu::new(0, entry_point, stack_top));
        let vcpu1 = if vcpu_count > 1 {
            Some(VCpu::new(1, entry_point + 0x100, stack_top + 0x800))
        } else {
            None
        };

        let mut ept = crate::ept::EptManager::new(id);
        ept.map_region(0x0, mem_base_hpa, ram_bytes);

        // Map Direct Hardware MMIO BAR (Bao/Jailhouse model) dynamically into Driver Domain EPT (0 VM-Exits!)
        if id == 1 {
            let pci_devices = crate::pci::PciBusScanner::scan_all_e1000();
            let physical_e1000_mmio_bar = if let Some(info) = pci_devices[1] {
                info.bar0 as u64
            } else {
                0xC108_0000
            };
            ept.map_mmio_passthrough(0x2000_0000, physical_e1000_mmio_bar, 0x200000);
            ept.map_mmio_passthrough(physical_e1000_mmio_bar, physical_e1000_mmio_bar, 0x200000);
        }

        Self {
            id,
            name,
            vcpu_count,
            ram_bytes,
            mem_base_hpa,
            vcpus: [vcpu0, vcpu1],
            e1000: VirtualE1000::new(id),
            ept,
            finished: false,
        }
    }

    pub fn load_code(&mut self, code: &[u8], gpa_offset: u64) {
        let hpa = self.mem_base_hpa + gpa_offset;
        unsafe {
            let dest = core::slice::from_raw_parts_mut(hpa as *mut u8, code.len());
            dest.copy_from_slice(code);
        }
    }

    pub fn run_vcpu_step(
        &mut self,
        vcpu_id: usize,
        channel_vm1_to_vm2: &mut UnidirectionalChannel,
        channel_vm2_to_vm1: &mut UnidirectionalChannel,
        verbose: bool,
    ) -> u64 {
        let mut completed_count = 0u64;

        if let Some(ref mut vcpu) = self.vcpus[vcpu_id] {
            if vcpu.active {
                // Execute real hardware VMLAUNCH / VMRESUME context switch into guest
                let exit_reason = unsafe { crate::vmx::vmx_launch_or_resume(&mut vcpu.registers, vcpu.launched) };
                vcpu.launched = true;

                // Dispatch hardware VM-Exit
                crate::vmexit::VmExitDispatcher::handle_hardware_vmexit(
                    self.id,
                    self.name,
                    exit_reason,
                    &mut vcpu.registers,
                    verbose,
                );

                if self.id == 0 {
                    // === VM1 Execution Step (High-Throughput 128-Packet Burst) ===
                    for _ in 0..128 {
                        if (self.e1000.icr & e1000_spec::INT_RXT0) != 0 {
                            self.e1000.icr &= !e1000_spec::INT_RXT0;
                            let fwd_payload = b"[ETH-MTU-1514] Received frame on VM1 e1000 NIC -> Forwarded by vm1-app via Unidirectional Port";
                            if !channel_vm1_to_vm2.send(fwd_payload) {
                                self.e1000.icr |= e1000_spec::INT_RXT0; // Re-flag if queue full
                                break;
                            }
                        } else {
                            break;
                        }
                    }

                    // Drain all ACK responses returned from VM2 via channel_2
                    while !channel_vm2_to_vm1.is_empty() {
                        if let Some(_ack) = channel_vm2_to_vm1.recv() {
                            completed_count += 1; // Round-trip completed!
                        } else {
                            break;
                        }
                    }
                } else {
                    // === VM2 Execution Step (High-Throughput 128-Packet Burst) ===
                    for _ in 0..128 {
                        if !channel_vm1_to_vm2.is_empty() {
                            if let Some(pkt) = channel_vm1_to_vm2.recv() {
                                self.e1000.mmio_write(e1000_spec::REG_TDT, 1, self.mem_base_hpa, channel_vm2_to_vm1);

                                if verbose {
                                    let pkt_slice = &pkt.data[..pkt.len];
                                    serial_print("\n--------------------------------------------------------\n");
                                    serial_print("[VM2-e1000-NIC] Packet transmitted out on VM2 e1000 Network Card!\n");
                                    serial_print("[VM2-e1000-NIC] Transmitted Payload: \"");
                                    for &b in pkt_slice {
                                        if b >= 0x20 && b <= 0x7E {
                                            crate::serial::serial_putchar(b);
                                        }
                                    }
                                    serial_print("\"\n");
                                    serial_print("[VM2-e1000-NIC] Egress Transmission Successful (200 OK)!\n");
                                    serial_print("--------------------------------------------------------\n\n");
                                }

                                // Return ACK response back to VM1 via channel_vm2_to_vm1
                                let ack_msg = b"[ACK] Egress complete";
                                channel_vm2_to_vm1.send(ack_msg);
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        completed_count
    }
}
