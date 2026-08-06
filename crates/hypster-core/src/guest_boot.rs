//! Guest long-mode page table setup before VMLAUNCH.

pub const GUEST_CR3_GPA: u64 = 0x8000;
pub const GUEST_ENTRY_GPA: u64 = 0x1000;
pub const GUEST_STACK_TOP_GPA: u64 = 0x1F_F000;

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITE: u64 = 1 << 1;
const PTE_PS: u64 = 1 << 7;

/// Install a 2 MiB identity map at the start of guest physical memory using 2 MiB pages,
/// plus a 2 MiB identity map covering shared IPC GPA `0xFE000000`, and a minimal GDT
/// (null/CS64/DS/TSS) at GPA 0x7000 for guest GDTR.
pub fn install_identity_map(guest_mem: &mut [u8]) {
    assert!(guest_mem.len() >= 0xC000, "guest memory too small for page tables");

    let pml4 = GUEST_CR3_GPA as usize;
    let pdpt = 0x9000usize;
    let pd_low = 0xA000usize;
    let pd_ipc = 0xB000usize;

    write_u64(guest_mem, pml4, (pdpt as u64) | PTE_PRESENT | PTE_WRITE);
    write_u64(guest_mem, pdpt, (pd_low as u64) | PTE_PRESENT | PTE_WRITE);
    write_u64(guest_mem, pd_low, PTE_PRESENT | PTE_WRITE | PTE_PS);

    // Shared IPC at GPA 0xFE000000 → PDPT index 3, PD index 496 (2 MiB leaf).
    let ipc_gpa = crate::ipc_region::SHARED_IPC_GPA;
    let pdpt_idx = ((ipc_gpa >> 30) & 0x1FF) as usize;
    let pd_idx = ((ipc_gpa >> 21) & 0x1FF) as usize;
    write_u64(
        guest_mem,
        pdpt + pdpt_idx * 8,
        (pd_ipc as u64) | PTE_PRESENT | PTE_WRITE,
    );
    write_u64(
        guest_mem,
        pd_ipc + pd_idx * 8,
        (ipc_gpa & !0x1F_FFFF) | PTE_PRESENT | PTE_WRITE | PTE_PS,
    );

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_map_covers_shared_ipc_gpa() {
        let mut mem = [0u8; 0xC000];
        install_identity_map(&mut mem);
        let ipc = crate::ipc_region::SHARED_IPC_GPA;
        let pdpt = 0x9000usize;
        let pd_ipc = 0xB000usize;
        let pdpt_idx = ((ipc >> 30) & 0x1FF) as usize;
        let pd_idx = ((ipc >> 21) & 0x1FF) as usize;
        let pdpt_e = u64::from_le_bytes(mem[pdpt + pdpt_idx * 8..][..8].try_into().unwrap());
        let pd_e = u64::from_le_bytes(mem[pd_ipc + pd_idx * 8..][..8].try_into().unwrap());
        assert_ne!(pdpt_e & PTE_PRESENT, 0);
        assert_ne!(pd_e & PTE_PRESENT, 0);
        assert_ne!(pd_e & PTE_PS, 0);
        assert_eq!(pd_e & !0x1F_FFFF & !0xFFF, ipc & !0x1F_FFFF);
    }
}
