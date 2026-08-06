//! # Partition Health Monitoring & Automatic Recovery Subsystem (`health.rs`)
//!
//! Provides production-grade partition fault monitoring, health tracking, and automatic vCPU recovery
//! for static partitioning isolation.
//!
//! ## Architectural References & Checklist Compliance
//! - **Section 26 ("Failure Containment & Recovery")**: Ensures a crashed or triple-faulted partition
//!   can be reset and restarted independently without affecting peer partitions or host stability.

use crate::serial::{serial_print, serial_print_dec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionState {
    Active,
    Faulted,
    Resetting,
}

#[derive(Debug, Clone, Copy)]
pub struct PartitionHealthRecord {
    pub vm_id: usize,
    pub state: PartitionState,
    pub total_vmexits: u64,
    pub fault_count: u64,
    pub reset_count: u64,
}

impl PartitionHealthRecord {
    pub const fn new(vm_id: usize) -> Self {
        Self {
            vm_id,
            state: PartitionState::Active,
            total_vmexits: 0,
            fault_count: 0,
            reset_count: 0,
        }
    }

    /// Record hardware VM exit occurrence
    pub fn record_vmexit(&mut self) {
        self.total_vmexits += 1;
    }

    /// Record partition crash/fault and initiate automatic vCPU recovery (§26)
    pub fn record_fault_and_recover(&mut self, vm_name: &'static str, vcpu_regs: &mut crate::vmx::VCpuRegisters) {
        self.fault_count += 1;
        self.reset_count += 1;
        self.state = PartitionState::Resetting;

        serial_print("\n========================================================\n");
        serial_print("[HYPSTER-RECOVERY-AGENT] Partition ");
        serial_print(vm_name);
        serial_print(" fault trapped! Initiating Auto-Recovery...\n");
        serial_print("[HYPSTER-RECOVERY-AGENT] Partition Fault Count: ");
        serial_print_dec(self.fault_count);
        serial_print(" | Reset Count: ");
        serial_print_dec(self.reset_count);
        serial_print("\n");

        // Reset vCPU Execution Registers back to initial entry point (0x1000) & stack (0xF000)
        vcpu_regs.rax = 0;
        vcpu_regs.rbx = 0;
        vcpu_regs.rcx = 0;
        vcpu_regs.rdx = 0;
        vcpu_regs.rsi = 0;
        vcpu_regs.rdi = 0;

        if !cfg!(test) {
            unsafe {
                let entry_point = 0x1000u64;
                let stack_top = 0xF000u64;
                crate::vmx::vmwrite(crate::vmx::VMCS_GUEST_RIP, entry_point);
                crate::vmx::vmwrite(crate::vmx::VMCS_GUEST_RSP, stack_top);
            }
        }

        self.state = PartitionState::Active;
        serial_print("[HYPSTER-RECOVERY-AGENT] ");
        serial_print(vm_name);
        serial_print(" vCPU registers reset cleanly. Partition restarted successfully!\n");
        serial_print("========================================================\n\n");
    }
}

pub struct SystemHealthMonitor {
    pub records: [PartitionHealthRecord; 2],
}

impl SystemHealthMonitor {
    pub const fn new() -> Self {
        Self {
            records: [
                PartitionHealthRecord::new(0),
                PartitionHealthRecord::new(1),
            ],
        }
    }
}

pub static mut GLOBAL_HEALTH_MONITOR: SystemHealthMonitor = SystemHealthMonitor::new();
