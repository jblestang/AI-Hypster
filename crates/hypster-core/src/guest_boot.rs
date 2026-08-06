//! Guest long-mode page table setup before VMLAUNCH.

pub const GUEST_CR3_GPA: u64 = 0x8000;
pub const GUEST_ENTRY_GPA: u64 = 0x1000;
pub const GUEST_STACK_TOP_GPA: u64 = 0x1F_F000;

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITE: u64 = 1 << 1;
const PTE_PS: u64 = 1 << 7;

/// Install a 2 MiB identity map at the start of guest physical memory using 2 MiB pages,
/// plus a minimal GDT (null/CS64/DS/TSS) at GPA 0x7000 for guest GDTR.
pub fn install_identity_map(guest_mem: &mut [u8]) {
    assert!(guest_mem.len() >= 0xB000, "guest memory too small for page tables");

    let pml4 = GUEST_CR3_GPA as usize;
    let pdpt = 0x9000usize;
    let pd = 0xA000usize;

    write_u64(guest_mem, pml4, (pdpt as u64) | PTE_PRESENT | PTE_WRITE);
    write_u64(guest_mem, pdpt, (pd as u64) | PTE_PRESENT | PTE_WRITE);
    write_u64(guest_mem, pd, PTE_PRESENT | PTE_WRITE | PTE_PS);

    // GDT at 0x7000: idx0 null, idx1 CS64 (0x08), idx2 DS (0x10), idx3 TSS (0x18)
    for i in 0..5 {
        write_u64(guest_mem, 0x7000 + i * 8, 0);
    }
    // 64-bit code: P=1 DPL=0 S=1 type=0xB L=1 D=0 G=1 limit=0xFFFFF
    write_u64(guest_mem, 0x7008, 0x00AF_9B00_0000_FFFF);
    // Data: P=1 DPL=0 S=1 type=0x3 G=1 D=1 limit=0xFFFFF
    write_u64(guest_mem, 0x7010, 0x00CF_9300_0000_FFFF);
    // 64-bit busy TSS descriptor (16 bytes) — base/limit unused by CPU when AR
    // comes from VMCS, but keep type consistent.
    write_u64(guest_mem, 0x7018, 0x0000_8900_0000_0067);
    write_u64(guest_mem, 0x7020, 0);
}

fn write_u64(guest_mem: &mut [u8], offset: usize, value: u64) {
    guest_mem[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
