//! # Hypster Hardware Constants Code Generator (`build.rs`)
//!
//! Parses `hardware_config.yaml` at build time and generates `$OUT_DIR/hardware_constants.rs`
//! containing typed, documented system constants for EAL5+ compliance.

use std::env;
use std::fs;
use std::path::Path;
use std::collections::HashMap;

fn main() {
    println!("cargo:rerun-if-changed=hardware_config.yaml");

    let yaml_content = fs::read_to_string("hardware_config.yaml")
        .expect("Failed to read hardware_config.yaml file!");

    let kv = parse_simple_yaml(&yaml_content);

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable not set!");
    let dest_path = Path::new(&out_dir).join("hardware_constants.rs");

    let generated_code = format!(
        r#"// Auto-generated from hardware_config.yaml by build.rs. DO NOT EDIT.

/// Global Hypervisor Magic Header ("HYPSTER\1" ASCII Representation)
pub const HYPSTER_MAGIC: u64 = {magic};

/// Supported Configuration Schema Version
pub const HYPSTER_CONFIG_VERSION: u32 = {version};

/// Base Host Physical Address of Hypervisor Private Execution Domain (1.0 GB boundary)
pub const HYPERVISOR_BASE_HPA: u64 = {hyp_base_hpa};

/// Physical RAM allocation size for Hypervisor Text, Data, VMCS, and Host Stacks (76 KB)
pub const HYPERVISOR_RAM_SIZE: u64 = {hyp_ram_size};

/// Base Host Physical Address of Partition Cell 1 (VM1-Alpha) RAM
pub const VM1_RAM_BASE_HPA: u64 = {vm1_ram_base_hpa};

/// Base Host Physical Address of Partition Cell 2 (VM2-Beta) RAM
pub const VM2_RAM_BASE_HPA: u64 = {vm2_ram_base_hpa};

/// Default Private RAM Allocation Size per Partition Cell (2 MB)
pub const PARTITION_RAM_SIZE: u64 = {partition_ram_size};

/// Base Host Physical Address of Shared SPSC Inter-Partition IPC Ring Buffer (20 KB)
pub const SHARED_IPC_RING_BASE_HPA: u64 = {shared_ipc_base_hpa};

/// Allocation Size of Shared SPSC Inter-Partition IPC Ring Buffer
pub const SHARED_IPC_RING_SIZE: u64 = {shared_ipc_size};

/// Fallback Physical PCIe BAR0 MMIO Address for Egress e1000 Hardware NIC (128 KB)
pub const DEFAULT_PCI_BAR0_MMIO_HPA: u64 = {pci_bar0_base_hpa};

/// Allocation Size of PCIe BAR0 MMIO Mapping
pub const DEFAULT_PCI_BAR0_MMIO_SIZE: u64 = {pci_bar0_size};

/// Fallback Physical Base Address of Intel VT-d IOMMU Hardware Unit (DMAR Table)
pub const DEFAULT_ACPI_DMAR_BASE_HPA: u64 = {iommu_dmar_base_hpa};

/// Standard IBM PC Compatible COM1 16550 UART I/O Port Address
pub const UART16550_COM1_PORT: u16 = {uart_com1_port};

/// Baud Rate Divisor Latch Low Byte for 115200 Baud (1.8432 MHz Clock / (16 * 1))
pub const UART16550_BAUD_115200_DLL: u8 = {uart_baud_dll};

/// Baud Rate Divisor Latch High Byte for 115200 Baud
pub const UART16550_BAUD_115200_DLM: u8 = {uart_baud_dlm};

/// Standard Line Control Register Configuration (8 Data Bits, 1 Stop Bit, No Parity)
pub const UART16550_LCR_8N1: u8 = {uart_lcr_8n1};

/// FIFO Control Register Configuration (14-Byte Threshold, Clear TX/RX FIFOs)
pub const UART16550_FCR_ENABLE_FIFO: u8 = {uart_fcr_enable_fifo};

/// Microsecond Delay for Hardware APIC INIT IPI Calibration (10 ms = 10,000 µs)
pub const APIC_INIT_DELAY_US: u64 = {apic_init_delay_us};

/// Microsecond Delay for Hardware APIC SIPI IPI Calibration (200 µs)
pub const APIC_SIPI_DELAY_US: u64 = {apic_sipi_delay_us};

/// Intel VT-d Posted Interrupt Notification Vector
pub const POSTED_INTERRUPT_NOTIFICATION_VECTOR: u8 = {pir_notification_vector};

/// Intel CAT Class of Service 0 (CLOS0) L3 Cache Capacity Bitmask (Lower 8 Ways)
pub const CAT_L3_CLOS0_MASK: u64 = {cat_clos0_mask};

/// Intel CAT Class of Service 1 (CLOS1) L3 Cache Capacity Bitmask (Upper 8 Ways)
pub const CAT_L3_CLOS1_MASK: u64 = {cat_clos1_mask};
"#,
        magic = kv.get("hypervisor.magic").unwrap_or(&"0x4859505354455201".to_string()),
        version = kv.get("hypervisor.version").unwrap_or(&"1".to_string()),
        hyp_base_hpa = kv.get("hypervisor.base_hpa").unwrap_or(&"0x0000_0001_4000_0000".to_string()),
        hyp_ram_size = kv.get("hypervisor.ram_size").unwrap_or(&"0x0000_0000_0001_3000".to_string()),
        vm1_ram_base_hpa = kv.get("partitions.partition1.ram_base_hpa").unwrap_or(&"0x0000_0001_4001_3000".to_string()),
        vm2_ram_base_hpa = kv.get("partitions.partition2.ram_base_hpa").unwrap_or(&"0x0000_0001_4021_3000".to_string()),
        partition_ram_size = kv.get("partitions.partition1.ram_size").unwrap_or(&"0x0000_0000_0020_0000".to_string()),
        shared_ipc_base_hpa = kv.get("shared_ipc.base_hpa").unwrap_or(&"0x0000_0001_4041_3000".to_string()),
        shared_ipc_size = kv.get("shared_ipc.size").unwrap_or(&"0x0000_0000_0000_5000".to_string()),
        pci_bar0_base_hpa = kv.get("pci_bar0.base_hpa").unwrap_or(&"0x0000_0000_C108_0000".to_string()),
        pci_bar0_size = kv.get("pci_bar0.size").unwrap_or(&"0x0000_0000_0002_0000".to_string()),
        iommu_dmar_base_hpa = kv.get("iommu.dmar_base_hpa").unwrap_or(&"0x0000_0000_FED9_0000".to_string()),
        uart_com1_port = kv.get("uart16550.com1_port").unwrap_or(&"0x03F8".to_string()),
        uart_baud_dll = kv.get("uart16550.baud_dll").unwrap_or(&"0x01".to_string()),
        uart_baud_dlm = kv.get("uart16550.baud_dlm").unwrap_or(&"0x00".to_string()),
        uart_lcr_8n1 = kv.get("uart16550.lcr_8n1").unwrap_or(&"0x03".to_string()),
        uart_fcr_enable_fifo = kv.get("uart16550.fcr_enable_fifo").unwrap_or(&"0xC7".to_string()),
        apic_init_delay_us = kv.get("apic.init_delay_us").unwrap_or(&"10000".to_string()),
        apic_sipi_delay_us = kv.get("apic.sipi_delay_us").unwrap_or(&"200".to_string()),
        pir_notification_vector = kv.get("posted_interrupts.notification_vector").unwrap_or(&"0xF2".to_string()),
        cat_clos0_mask = kv.get("cat_l3.clos0_mask").unwrap_or(&"0x00FF".to_string()),
        cat_clos1_mask = kv.get("cat_l3.clos1_mask").unwrap_or(&"0xFF00".to_string()),
    );

    fs::write(dest_path, generated_code).expect("Failed to write generated hardware_constants.rs!");
}

fn parse_simple_yaml(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut current_prefix: Vec<(usize, String)> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() || trimmed.trim_start().starts_with('#') {
            continue;
        }

        let indent = line.len() - line.trim_start().len();
        let stripped = line.trim();

        while let Some((last_indent, _)) = current_prefix.last() {
            if indent <= *last_indent {
                current_prefix.pop();
            } else {
                break;
            }
        }

        if let Some(pos) = stripped.find(':') {
            let key = stripped[..pos].trim().to_string();
            let value = stripped[pos + 1..].trim();

            if value.is_empty() {
                current_prefix.push((indent, key));
            } else {
                let full_key = if current_prefix.is_empty() {
                    key
                } else {
                    let prefix_str: Vec<String> = current_prefix.iter().map(|(_, k)| k.clone()).collect();
                    format!("{}.{}", prefix_str.join("."), key)
                };
                map.insert(full_key, value.to_string());
            }
        }
    }
    map
}
