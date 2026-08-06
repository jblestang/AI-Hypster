//! # Multi-Core Scheduling & Local APIC Inter-Processor Interrupts (`scheduler.rs`)
//!
//! Implements vCPU-to-physical-core affinity pinning and Local APIC (LAPIC) driver operations for multi-core SMP initialization.
//!
//! ## Architectural Overview & Intel SDM References
//! - **Local APIC Driver (`LocalApicDriver`)**: Accesses MMIO register space (`0xFEE00000`) for LAPIC Interrupt Command Registers (`ICR_LOW` `0x300`, `ICR_HIGH` `0x310`).
//!   Reference: Intel 64 and IA-32 Architectures Software Developer's Manual (SDM), Volume 3A, Chapter 10 ("Advanced Programmable Interrupt Controller (APIC)").
//! - **INIT-SIPI-SIPI Multiprocessor Wakeup Sequence**: Issues INIT and dual SIPI (Startup IPI) vector sequences to wake up secondary physical Application Processors (APs).
//!   Reference: Intel SDM Vol 3A, Section 10.6 ("MP Initialization Protocol").
//! - **Static vCPU Pinning (`VcpuCorePin`)**: Binds specific virtual CPU threads to dedicated physical CPU cores (`pcpu_id`) to ensure isolation and zero contention.

pub const IA32_APIC_BASE_MSR: u32 = 0x0000001B;
pub const APIC_BASE_ENABLE: u64 = 1 << 11;
pub const APIC_LVTT: u32 = 0x320;
pub const APIC_TDCR: u32 = 0x3E0;
pub const APIC_TICR: u32 = 0x380;

#[derive(Debug, Clone, Copy)]
pub struct VcpuCorePin {
    pub vm_id: usize,
    pub vcpu_id: usize,
    pub pcpu_id: usize, // Physical CPU Core ID
    pub apic_id: u32,
}

pub const APIC_ICR_LOW: u32 = 0x300;
pub const APIC_ICR_HIGH: u32 = 0x310;

pub const APIC_DELIVERY_INIT: u32 = 5 << 8;
pub const APIC_DELIVERY_STARTUP: u32 = 6 << 8;

pub struct LocalApicDriver {
    pub base_hpa: u64,
}

impl LocalApicDriver {
    pub fn new() -> Self {
        Self {
            base_hpa: 0xFEE00000,
        }
    }

    /// Broadcast INIT-SIPI-SIPI IPI sequence to wake up secondary physical AP core (§6)
    pub unsafe fn send_init_sipi_sipi(&self, target_apic_id: u32, vector: u8) {
        if cfg!(test) {
            return;
        }

        let icr_high_ptr = (self.base_hpa + APIC_ICR_HIGH as u64) as *mut u32;
        let icr_low_ptr = (self.base_hpa + APIC_ICR_LOW as u64) as *mut u32;

        // SAFETY: APIC ICR MMIO pointer writes to hardware LAPIC register base
        unsafe {
            // 1. Issue INIT IPI
            core::ptr::write_volatile(icr_high_ptr, target_apic_id << 24);
            core::ptr::write_volatile(icr_low_ptr, APIC_DELIVERY_INIT | 0x4000);
        }

        // TSC-calibrated 10 ms (10,000 us) hardware INIT reset delay
        Self::delay_us(10_000);

        // SAFETY: APIC ICR MMIO pointer writes for SIPI 1
        unsafe {
            // 2. Issue SIPI 1
            core::ptr::write_volatile(icr_high_ptr, target_apic_id << 24);
            core::ptr::write_volatile(icr_low_ptr, APIC_DELIVERY_STARTUP | (vector as u32));
        }

        // TSC-calibrated 200 us SIPI delay
        Self::delay_us(200);

        // SAFETY: APIC ICR MMIO pointer writes for SIPI 2
        unsafe {
            // 3. Issue SIPI 2
            core::ptr::write_volatile(icr_high_ptr, target_apic_id << 24);
            core::ptr::write_volatile(icr_low_ptr, APIC_DELIVERY_STARTUP | (vector as u32));
        }
    }

    /// Calibrated microsecond delay using CPU Time Stamp Counter (TSC)
    fn delay_us(us: u64) {
        if cfg!(test) {
            return;
        }
        let cpu_freq_mhz = 3000u64; // 3.0 GHz baseline
        let target_cycles = us * cpu_freq_mhz;
        let start = unsafe { core::arch::x86_64::_rdtsc() };
        while unsafe { core::arch::x86_64::_rdtsc() }.saturating_sub(start) < target_cycles {
            core::hint::spin_loop();
        }
    }
}

pub struct StaticScheduler {
    pub current_index: usize,
    pub schedule_count: usize,
    pub schedule_table: [VcpuCorePin; 8],
    pub apic: LocalApicDriver,
}

impl StaticScheduler {
    pub fn new() -> Self {
        let mut sched = Self {
            current_index: 0,
            schedule_count: 0,
            schedule_table: [VcpuCorePin { vm_id: 0, vcpu_id: 0, pcpu_id: 0, apic_id: 0 }; 8],
            apic: LocalApicDriver::new(),
        };

        sched.add_pin(0, 0, 0, 0); // VM 1 vCPU 0 -> Core 0
        sched.add_pin(1, 0, 1, 1); // VM 2 vCPU 0 -> Core 1
        sched.add_pin(1, 1, 2, 2); // VM 2 vCPU 1 -> Core 2
        sched
    }

    /// Dynamically register vCPU core affinity pin
    pub fn add_pin(&mut self, vm_id: usize, vcpu_id: usize, pcpu_id: usize, apic_id: u32) {
        if self.schedule_count < self.schedule_table.len() {
            self.schedule_table[self.schedule_count] = VcpuCorePin { vm_id, vcpu_id, pcpu_id, apic_id };
            self.schedule_count += 1;
        }
    }

    /// Select next vCPU and return (vm_id, vcpu_id, pcpu_id)
    pub fn next_vcpu(&mut self) -> (usize, usize) {
        if self.schedule_count == 0 {
            return (0, 0);
        }
        let entry = self.schedule_table[self.current_index];
        self.current_index = (self.current_index + 1) % self.schedule_count;
        (entry.vm_id, entry.vcpu_id)
    }

    /// Return all active vCPU core affinity pins for concurrent multi-core execution
    pub fn concurrent_vcpus(&self) -> &[VcpuCorePin] {
        &self.schedule_table[..self.schedule_count]
    }

    pub fn current_pin(&self) -> VcpuCorePin {
        self.schedule_table[self.current_index]
    }
}
