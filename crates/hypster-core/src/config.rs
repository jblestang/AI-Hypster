//! # Static Configuration Parser & Validator (`config.rs`)
//!
//! Provides schema-validated, magic-header versioned static configuration definitions for
//! Hypster hypervisor partitions, memory regions, vCPU pins, and PCI device assignments.
//!
//! ## Architectural References & Checklist Compliance
//! - **Section 3.2 ("Static Configuration Format")**: Magic header validation (`HYPSTER_MAGIC`), versioning (`HYPSTER_CONFIG_VERSION`),
//!   checked bounds arithmetic, overflow detection, and offline schema validation.

pub const HYPSTER_MAGIC: u64 = 0x4859505354455201; // "HYPSTER\1"
pub const HYPSTER_CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct StaticPartitionConfig {
    pub vm_id: usize,
    pub name: &'static str,
    pub guest_phys_base: u64,
    pub guest_phys_size: u64,
    pub pcpu_affinity: usize,
    pub assigned_pci_bdf: (u8, u8, u8), // (Bus, Device, Function)
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct StaticHypervisorConfig {
    pub magic: u64,
    pub version: u32,
    pub num_partitions: usize,
    pub partitions: [StaticPartitionConfig; 2],
}

impl StaticHypervisorConfig {
    pub const fn default_system() -> Self {
        Self {
            magic: HYPSTER_MAGIC,
            version: HYPSTER_CONFIG_VERSION,
            num_partitions: 2,
            partitions: [
                StaticPartitionConfig {
                    vm_id: 0,
                    name: "VM1-Alpha",
                    guest_phys_base: 0x0000_0001_4000_0000,
                    guest_phys_size: 0x0000_0000_0020_0000, // 2MB
                    pcpu_affinity: 0,
                    assigned_pci_bdf: (0, 3, 0),
                },
                StaticPartitionConfig {
                    vm_id: 1,
                    name: "VM2-Beta",
                    guest_phys_base: 0x0000_0001_4020_0000,
                    guest_phys_size: 0x0000_0000_0020_0000, // 2MB
                    pcpu_affinity: 1,
                    assigned_pci_bdf: (0, 4, 0),
                },
            ],
        }
    }

    /// Complete Offline & Runtime Configuration Validation (§3.2)
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.magic != HYPSTER_MAGIC {
            return Err("Invalid configuration magic header!");
        }
        if self.version != HYPSTER_CONFIG_VERSION {
            return Err("Unsupported configuration version!");
        }
        if self.num_partitions == 0 || self.num_partitions > 2 {
            return Err("Invalid partition count!");
        }

        // Validate range non-overlap & overflow safety
        for i in 0..self.num_partitions {
            let p1 = &self.partitions[i];
            let (end1, overflow) = p1.guest_phys_base.overflowing_add(p1.guest_phys_size);
            if overflow {
                return Err("Partition physical memory address arithmetic overflow!");
            }

            for j in (i + 1)..self.num_partitions {
                let p2 = &self.partitions[j];
                let (end2, overflow2) = p2.guest_phys_base.overflowing_add(p2.guest_phys_size);
                if overflow2 {
                    return Err("Partition physical memory address arithmetic overflow!");
                }

                // Check CPU pinning duplicate conflict
                if p1.pcpu_affinity == p2.pcpu_affinity {
                    return Err("Duplicate physical CPU core pinning conflict!");
                }

                // Check memory range overlap
                if !(end1 <= p2.guest_phys_base || end2 <= p1.guest_phys_base) {
                    return Err("Overlapping guest physical memory regions detected!");
                }

                // Check PCI BDF collision
                if p1.assigned_pci_bdf == p2.assigned_pci_bdf {
                    return Err("Duplicate PCI BDF device assignment collision!");
                }
            }
        }

        Ok(())
    }
}
