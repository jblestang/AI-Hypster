//! Guest long-mode page table setup before VMLAUNCH.

pub const GUEST_CR3_GPA: u64 = 0x8000;
pub const GUEST_ENTRY_GPA: u64 = 0x1000;
pub const GUEST_STACK_TOP_GPA: u64 = 0x1F_F000;

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITE: u64 = 1 << 1;
const PTE_PS: u64 = 1 << 7;

/// Install a 2 MiB identity map at the start of guest physical memory using 2 MiB pages.
pub fn install_identity_map(guest_mem: &mut [u8]) {
    assert!(guest_mem.len() >= 0xB000, "guest memory too small for page tables");

    let pml4 = GUEST_CR3_GPA as usize;
    let pdpt = 0x9000usize;
    let pd = 0xA000usize;

    write_u64(guest_mem, pml4, (pdpt as u64) | PTE_PRESENT | PTE_WRITE);
    write_u64(guest_mem, pdpt, (pd as u64) | PTE_PRESENT | PTE_WRITE);
    write_u64(guest_mem, pd, PTE_PRESENT | PTE_WRITE | PTE_PS);
}

fn write_u64(guest_mem: &mut [u8], offset: usize, value: u64) {
    guest_mem[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
