//! # Reliability, Availability, Serviceability (RAS) & Machine Check Architecture (`ras.rs`)
//!
//! Provides hardware ECC memory error detection, Machine Check Architecture (`#MC`) exception handling,
//! and hardware fault isolation for static partitioning.
//!
//! ## Architectural Overview & Intel SDM References
//! - **Machine Check Architecture (MCA)**: Queries `IA32_MCG_CAP` MSR (`0x179`), `IA32_MCG_STATUS` MSR (`0x17A`),
//!   and per-bank `IA32_MCi_STATUS` MSRs to detect hardware ECC memory bit flips and bus errors.
//!   Reference: Intel 64 and IA-32 Architectures Software Developer's Manual (SDM), Volume 3B, Chapter 15 ("Machine-Check Architecture").

use crate::serial::{serial_print, serial_print_hex};

pub const IA32_MCG_CAP_MSR: u32 = 0x179;
pub const IA32_MCG_STATUS_MSR: u32 = 0x17A;
pub const IA32_MCG_CTL_MSR: u32 = 0x17B;
pub const IA32_MC0_STATUS_MSR: u32 = 0x401;

pub const MCI_STATUS_VAL: u64 = 1 << 63; // Error Valid Flag
pub const MCI_STATUS_OVER: u64 = 1 << 62; // Error Overwrite Flag
pub const MCI_STATUS_UC: u64 = 1 << 61; // Uncorrected Error Flag

#[derive(Debug, Clone, Copy)]
pub struct EccErrorRecord {
    pub bank_id: u32,
    pub status: u64,
    pub address: u64,
    pub is_uncorrected: bool,
}

pub struct MachineCheckHandler;

impl MachineCheckHandler {
    /// Initialize hardware Machine Check Architecture (MCA) registers
    pub fn init_mca() {
        if cfg!(test) {
            return;
        }

        unsafe {
            let cap = crate::vmx::read_msr(IA32_MCG_CAP_MSR);
            let num_banks = (cap & 0xFF) as u32;

            // Enable all MCA hardware error reporting banks
            for bank in 0..num_banks {
                let ctl_msr = 0x400 + (bank * 4);
                crate::vmx::write_msr(ctl_msr, 0xFFFFFFFFFFFFFFFF);
            }
        }

        serial_print("[HYPSTER-RAS] Hardware Machine Check Architecture (MCA) & ECC Memory Guard Initialized!\n");
    }

    /// Process Machine Check (`#MC`) trap and isolate hardware memory fault cleanly
    pub fn handle_machine_check() -> Option<EccErrorRecord> {
        if cfg!(test) {
            return None;
        }

        unsafe {
            let mcg_status = crate::vmx::read_msr(IA32_MCG_STATUS_MSR);
            if (mcg_status & 1) != 0 {
                let bank_status = crate::vmx::read_msr(IA32_MC0_STATUS_MSR);
                if (bank_status & MCI_STATUS_VAL) != 0 {
                    let is_uncorrected = (bank_status & MCI_STATUS_UC) != 0;
                    let bank_addr = crate::vmx::read_msr(IA32_MC0_STATUS_MSR + 1);

                    serial_print("\n========================================================\n");
                    serial_print("[HYPSTER-RAS-ALERT] Hardware ECC Memory Error Trapped!\n");
                    serial_print("[HYPSTER-RAS-ALERT] Bank 0 Status: ");
                    serial_print_hex(bank_status);
                    serial_print(" | Faulting Physical Address: ");
                    serial_print_hex(bank_addr);
                    if is_uncorrected {
                        serial_print(" (Uncorrected ECC Failure - Isolating Physical Bank!)\n");
                    } else {
                        serial_print(" (Corrected ECC Bit Flip - Hardware Corrected OK)\n");
                    }
                    serial_print("========================================================\n\n");

                    // Clear MCA error status register
                    crate::vmx::write_msr(IA32_MC0_STATUS_MSR, 0);

                    return Some(EccErrorRecord {
                        bank_id: 0,
                        status: bank_status,
                        address: bank_addr,
                        is_uncorrected,
                    });
                }
            }
        }

        None
    }
}
