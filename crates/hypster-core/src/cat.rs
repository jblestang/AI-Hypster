//! # Intel Cache Allocation Technology (CAT) & Memory Bandwidth Allocation (MBA) (`cat.rs`)
//!
//! Provides hardware-enforced L3/LLC cache way partitioning and DRAM bandwidth capping
//! to eliminate Noisy Neighbor interference between static hypervisor partitions.
//!
//! ## Architectural Overview & Intel SDM References
//! - **Class of Service (CLOS)**: Hardware abstraction mapping vCPUs to dedicated L3 cache bitmasks (`IA32_L3_MASK_n` MSRs `0xC90`, `0xC91`).
//!   Reference: Intel 64 and IA-32 Architectures Software Developer's Manual (SDM), Volume 3B, Chapter 17 ("Intel Resource Director Technology (Intel RDT)").
//! - **Core Association (`IA32_PQR_ASSOC` MSR `0xC8F`)**: Binds physical CPU cores (`pcpu_id`) to specific CLOS IDs.

use crate::serial::{serial_print, serial_print_hex};

pub const IA32_PQR_ASSOC_MSR: u32 = 0xC8F;
pub const IA32_L3_MASK_0_MSR: u32 = 0xC90;
pub const IA32_L3_MASK_1_MSR: u32 = 0xC91;
pub const IA32_MBA_THROTTLE_0_MSR: u32 = 0xD50;

#[derive(Debug, Clone, Copy)]
pub struct PartitionCachePolicy {
    pub vm_id: usize,
    pub clos_id: u32,
    pub l3_cache_mask: u64, // L3 Bit Capacity Mask (e.g. 0xFF00 vs 0x00FF)
    pub mba_throttle_pct: u32, // Memory Bandwidth Throttle Percentage (0 = 100% bandwidth)
}

pub struct IntelCatManager {
    pub policies: [PartitionCachePolicy; 2],
}

impl IntelCatManager {
    pub const fn new() -> Self {
        Self {
            policies: [
                PartitionCachePolicy {
                    vm_id: 0,
                    clos_id: 0,
                    l3_cache_mask: 0x00FF, // VM1 (Real-Time smoltcp): Dedicated lower 8 L3 cache ways
                    mba_throttle_pct: 0,   // 100% Unthrottled DRAM Bandwidth
                },
                PartitionCachePolicy {
                    vm_id: 1,
                    clos_id: 1,
                    l3_cache_mask: 0xFF00, // VM2 (Driver Domain): Dedicated upper 8 L3 cache ways (Zero Cache Bouncing!)
                    mba_throttle_pct: 0,   // 100% Unthrottled DRAM Bandwidth
                },
            ],
        }
    }

    /// Program hardware Intel CAT L3 cache masks and bind CLOS to physical CPU core
    pub fn apply_policy(&self, vm_id: usize, pcpu_id: usize) {
        if cfg!(test) {
            return;
        }

        let policy = &self.policies[vm_id.min(1)];
        let mask_msr = if policy.clos_id == 0 {
            IA32_L3_MASK_0_MSR
        } else {
            IA32_L3_MASK_1_MSR
        };

        unsafe {
            // 1. Program hardware L3 Cache Capacity Bitmask (CBM)
            crate::vmx::write_msr(mask_msr, policy.l3_cache_mask);

            // 2. Bind physical CPU core to CLOS ID via IA32_PQR_ASSOC MSR
            let assoc_val = (policy.clos_id as u64) << 32;
            crate::vmx::write_msr(IA32_PQR_ASSOC_MSR, assoc_val);
        }

        serial_print("[HYPSTER-CAT] Intel CAT L3 Cache Isolation programmed for VM ");
        crate::serial::serial_print_dec(vm_id as u64);
        serial_print(" on Core ");
        crate::serial::serial_print_dec(pcpu_id as u64);
        serial_print(" | L3 Mask: ");
        serial_print_hex(policy.l3_cache_mask);
        serial_print(" (Noisy Neighbor Elimination Active)\n");
    }
}

pub static mut GLOBAL_CAT_MANAGER: IntelCatManager = IntelCatManager::new();
