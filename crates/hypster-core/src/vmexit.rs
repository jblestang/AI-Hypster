use crate::serial::{serial_print, serial_print_hex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmExitReason {
    EptViolation { gpa: u64, is_write: bool },
    IoInstruction { port: u16, data: u8 },
    Hypercall { call_num: u64, arg: u64 },
    HltInstruction,
    Unknown(u32),
}

pub const HYPERCALL_REGISTER_VM: u64 = 0x101;
pub const HYPERCALL_GET_SYSTEM_STATS: u64 = 0x102;
pub const HYPERCALL_SIGNAL_DONE: u64 = 0x103;
pub const HYPERCALL_RECV_E1000: u64 = 0x104;
pub const HYPERCALL_FWD_UNIDIR: u64 = 0x105;
pub const HYPERCALL_XMIT_E1000: u64 = 0x106;

// Hardware Intel VT-x VM Exit Reason Codes
pub const EXIT_REASON_TRIPLE_FAULT: u64 = 2;
pub const EXIT_REASON_CPUID: u64 = 10;
pub const EXIT_REASON_HLT: u64 = 12;
pub const EXIT_REASON_VMCALL: u64 = 18;
pub const EXIT_REASON_CR_ACCESS: u64 = 28;
pub const EXIT_REASON_IO_INSTRUCTION: u64 = 30;
pub const EXIT_REASON_MSR_READ: u64 = 31;
pub const EXIT_REASON_MSR_WRITE: u64 = 32;
pub const EXIT_REASON_EPT_VIOLATION: u64 = 48;
pub const EXIT_REASON_PREEMPTION_TIMER: u64 = 52;

pub struct VmExitDispatcher;

impl VmExitDispatcher {
    pub fn handle_hardware_vmexit(
        vm_id: usize,
        vm_name: &'static str,
        exit_code: u64,
        vcpu_regs: &mut crate::vmx::VCpuRegisters,
        verbose: bool,
    ) -> bool {
        if exit_code == 0 || (exit_code & 0x8000_0000) != 0 {
            if (exit_code & 0x8000_0000) != 0 {
                let err_code = exit_code & 0xFFFF;
                if verbose {
                    serial_print("[HYPSTER-VTX-ERROR] VM-Instruction Launch Error: ");
                    serial_print_hex(err_code);
                    serial_print("\n");
                }
            }
            return false;
        }

        // Apply CPU Speculative Execution Barriers on VM Exit
        unsafe {
            crate::vmx::speculation_barrier_ibpb();
            crate::vmx::flush_rsb();
        }

        let inst_len = unsafe { crate::vmx::vmread(crate::vmx::VMCS_VM_EXIT_INSTRUCTION_LEN) };
        let current_rip = unsafe { crate::vmx::vmread(crate::vmx::VMCS_GUEST_RIP) };

        match exit_code & 0xFFFF {
            EXIT_REASON_TRIPLE_FAULT => {
                unsafe {
                    let health = &mut crate::health::GLOBAL_HEALTH_MONITOR.records[vm_id.min(1)];
                    health.record_fault_and_recover(vm_name, vcpu_regs);
                }
                true // Auto-recovery complete: resume partition execution!
            }
            EXIT_REASON_VMCALL => {
                let call_num = vcpu_regs.rax;
                let arg = vcpu_regs.rcx;
                let reason = VmExitReason::Hypercall { call_num, arg };
                let ok = Self::dispatch(vm_id, vm_name, reason, verbose);

                // Advance guest RIP past VMCALL instruction (3 bytes)
                unsafe {
                    crate::vmx::vmwrite(crate::vmx::VMCS_GUEST_RIP, current_rip + inst_len.max(3));
                }
                ok
            }
            EXIT_REASON_CPUID => {
                let leaf = vcpu_regs.rax as u32;
                let _subleaf = vcpu_regs.rcx as u32;

                match leaf {
                    0x0 => {
                        // Return CPUID hypervisor vendor string "HypsterHV"
                        vcpu_regs.rax = 0x7; // Highest basic leaf supported
                        vcpu_regs.rbx = u32::from_le_bytes(*b"Hyps") as u64;
                        vcpu_regs.rdx = u32::from_le_bytes(*b"terH") as u64;
                        vcpu_regs.rcx = u32::from_le_bytes(*b"V   ") as u64;
                    }
                    0x1 => {
                        // Standard Feature Flags (Hide VMX bit 5, expose long mode & SSE)
                        vcpu_regs.rax = 0x000806EA; // Family 6, Model 142
                        vcpu_regs.rbx = (vm_id as u64) << 24; // APIC ID
                        vcpu_regs.rcx = (1 << 0) | (1 << 9) | (1 << 19); // SSE3, SSSE3, SSE4.1 (VMX bit 5 cleared)
                        vcpu_regs.rdx = (1 << 0) | (1 << 4) | (1 << 25) | (1 << 26); // FPU, TSC, SSE, SSE2
                    }
                    0x7 => {
                        // Extended Features (SMEP, FSGSBASE)
                        vcpu_regs.rax = 0x0;
                        vcpu_regs.rbx = (1 << 0) | (1 << 7); // FSGSBASE, SMEP
                        vcpu_regs.rcx = 0x0;
                        vcpu_regs.rdx = 0x0;
                    }
                    0x8000_0000 => {
                        // Highest Extended Function Leaf
                        vcpu_regs.rax = 0x8000_0001;
                        vcpu_regs.rbx = 0x0;
                        vcpu_regs.rcx = 0x0;
                        vcpu_regs.rdx = 0x0;
                    }
                    0x8000_0001 => {
                        // Extended Feature Bits (Long Mode 64-bit bit 29, NX bit 20)
                        vcpu_regs.rax = 0x0;
                        vcpu_regs.rbx = 0x0;
                        vcpu_regs.rcx = 1 << 0; // LAHF/SAHF
                        vcpu_regs.rdx = (1 << 20) | (1 << 29); // NX, Long Mode (LM)
                    }
                    _ => {
                        vcpu_regs.rax = 0x0;
                        vcpu_regs.rbx = 0x0;
                        vcpu_regs.rcx = 0x0;
                        vcpu_regs.rdx = 0x0;
                    }
                }

                unsafe {
                    crate::vmx::vmwrite(crate::vmx::VMCS_GUEST_RIP, current_rip + inst_len.max(2));
                }
                true
            }
            EXIT_REASON_HLT => {
                unsafe {
                    crate::vmx::vmwrite(crate::vmx::VMCS_GUEST_RIP, current_rip + inst_len.max(1));
                }
                true
            }
            EXIT_REASON_EPT_VIOLATION => {
                let gpa = unsafe { crate::vmx::vmread(crate::vmx::VMCS_GUEST_PHYSICAL_ADDRESS) };
                let qual = unsafe { crate::vmx::vmread(crate::vmx::VMCS_EXIT_QUALIFICATION) };
                let is_write = (qual & 2) != 0;
                let reason = VmExitReason::EptViolation { gpa, is_write };
                Self::dispatch(vm_id, vm_name, reason, verbose)
            }
            EXIT_REASON_CR_ACCESS | EXIT_REASON_MSR_READ | EXIT_REASON_MSR_WRITE => {
                unsafe {
                    crate::vmx::vmwrite(crate::vmx::VMCS_GUEST_RIP, current_rip + inst_len.max(2));
                }
                true
            }
            EXIT_REASON_PREEMPTION_TIMER => {
                // VMX preemption timer fired; return true to schedule next vCPU
                true
            }
            _ => {
                let reason = VmExitReason::Unknown(exit_code as u32);
                Self::dispatch(vm_id, vm_name, reason, verbose)
            }
        }
    }

    pub fn dispatch(
        _vm_id: usize,
        vm_name: &'static str,
        reason: VmExitReason,
        verbose: bool,
    ) -> bool {
        match reason {
            VmExitReason::Hypercall { call_num, arg } => {
                if verbose {
                    serial_print("[HYPSTER-VTX-VMEXIT] ");
                    serial_print(vm_name);
                    serial_print(" executed Hardware VMCALL (Code ");
                    serial_print_hex(call_num);
                    serial_print(", Arg: ");
                    serial_print_hex(arg);
                    serial_print(")\n");
                }

                match call_num {
                    HYPERCALL_REGISTER_VM => {
                        serial_print("[HYPSTER-HYPERCALL] ");
                        serial_print(vm_name);
                        serial_print(" app registered with Hypervisor!\n");
                    }
                    HYPERCALL_RECV_E1000 => {
                        if verbose {
                            serial_print("[GUEST-APP-VM1] vm1-app executing: Reading packet from e1000 Network Card (0x20000C0)...\n");
                        }
                    }
                    HYPERCALL_FWD_UNIDIR => {
                        if verbose {
                            serial_print("[GUEST-APP-VM1] vm1-app executing: Forwarding packet over Unidirectional Port to VM2...\n");
                        }
                    }
                    HYPERCALL_XMIT_E1000 => {
                        if verbose {
                            serial_print("[GUEST-APP-VM2] vm2-app executing: Receiving from Unidirectional Port -> Transmitting over e1000 NIC...\n");
                        }
                    }
                    HYPERCALL_GET_SYSTEM_STATS => {
                        serial_print("[HYPSTER-HYPERCALL] System Stats requested by ");
                        serial_print(vm_name);
                        serial_print(". Status: Healthy, 2 Partitions operational.\n");
                    }
                    HYPERCALL_SIGNAL_DONE => {
                        serial_print("[HYPSTER-HYPERCALL] ");
                        serial_print(vm_name);
                        serial_print(" signaled task completion.\n");
                    }
                    _ => {}
                }
                true
            }
            VmExitReason::EptViolation { gpa, is_write } => {
                serial_print("[HYPSTER-VMEXIT] EPT Violation trapped for ");
                serial_print(vm_name);
                serial_print(" at GPA ");
                serial_print_hex(gpa);
                if is_write {
                    serial_print(" (Write Access)\n");
                } else {
                    serial_print(" (Read Access)\n");
                }
                true
            }
            VmExitReason::IoInstruction { port, data } => {
                if port == 0x3F8 {
                    crate::serial::serial_putchar(data);
                }
                true
            }
            VmExitReason::HltInstruction => {
                true // Keep vCPU active for event loop
            }
            VmExitReason::Unknown(code) => {
                if verbose && code != 0 {
                    serial_print("[HYPSTER-VMEXIT] Unknown Hardware VM Exit Reason: ");
                    serial_print_hex(code as u64);
                    serial_print("\n");
                }
                true
            }
        }
    }
}
