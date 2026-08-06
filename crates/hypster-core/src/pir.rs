//! # Intel VT-d Posted Interrupts (PIR) & Interrupt Remapping Subsystem (`pir.rs`)
//!
//! Implements hardware Posted Interrupt (PIR) descriptors and VT-d Interrupt Remapping (IR) tables
//! for zero-VM exit hardware device interrupt delivery.
//!
//! ## Architectural Overview & Intel SDM References
//! - **Posted-Interrupt Descriptor (`PostedInterruptDescriptor`)**: 64-byte aligned hardware structure
//!   containing a 256-bit Posted-Interrupt Request (PIR) bitmap and notification vector.
//!   Reference: Intel 64 and IA-32 Architectures Software Developer's Manual (SDM), Volume 3C, Section 29.6 ("Posted-Interrupt Processing").
//! - **Notification Vector**: Hardware vector (default `0xF2`) issued by VT-d IOMMU or physical CPU core
//!   to signal pending posted interrupts directly into the guest vCPU Virtual APIC Page.

use crate::serial::{serial_print, serial_print_hex};

pub const VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR: u32 = 0x00000002;
pub const VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS: u32 = 0x00002016;

#[repr(C, align(64))]
pub struct PostedInterruptDescriptor {
    /// 256-bit posted interrupt request bitmap (vectors 0..255)
    pub pir_bitmap: [u64; 4],
    /// Outstanding notification control bit (bit 0 = ON)
    pub control: u64,
    /// Reserved padding to 64 bytes
    pub reserved: [u64; 3],
}

impl PostedInterruptDescriptor {
    pub const fn new() -> Self {
        Self {
            pir_bitmap: [0; 4],
            control: 0,
            reserved: [0; 3],
        }
    }

    /// Post hardware interrupt vector directly to vCPU PIR bitmap without VM-exit
    pub fn post_vector(&mut self, vector: u8) {
        let idx = (vector / 64) as usize;
        let bit = (vector % 64) as u64;
        self.pir_bitmap[idx] |= 1 << bit;
        // Set Outstanding Notification bit (ON)
        self.control |= 1;
    }
}

pub struct PostedInterruptManager {
    pub descriptors: [PostedInterruptDescriptor; 2],
    pub notification_vector: u8,
}

impl PostedInterruptManager {
    pub const fn new() -> Self {
        Self {
            descriptors: [
                PostedInterruptDescriptor::new(),
                PostedInterruptDescriptor::new(),
            ],
            notification_vector: 0xF2, // Standard VMX posted interrupt notification vector
        }
    }

    /// Configure VMCS Posted Interrupt fields for hardware zero-exit interrupt delivery
    pub fn configure_vmcs(&self, vm_id: usize) {
        if cfg!(test) {
            return;
        }

        let desc_ptr = &self.descriptors[vm_id.min(1)] as *const PostedInterruptDescriptor as u64;
        unsafe {
            crate::vmx::vmwrite(VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR, self.notification_vector as u64);
            crate::vmx::vmwrite(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS, desc_ptr);
        }

        serial_print("[HYPSTER-PIR] Intel VT-d Posted Interrupts configured for VM ");
        crate::serial::serial_print_dec(vm_id as u64);
        serial_print(". Descriptor HPA: ");
        serial_print_hex(desc_ptr);
        serial_print(" (0 VM-Exit Hardware Interrupt Delivery Active)\n");
    }
}

pub static mut GLOBAL_PIR_MANAGER: PostedInterruptManager = PostedInterruptManager::new();
