//! Shared IPC layout at SHARED_IPC_RING_BASE_HPA.

use crate::channel::UnidirectionalChannel;

pub const SHARED_IPC_GPA: u64 = 0xFE000000;
/// Size of one UnidirectionalChannel in bytes (repr C, align 64).
pub const CHANNEL_SLOT_SIZE: usize = core::mem::size_of::<UnidirectionalChannel>();

pub unsafe fn init_ipc_at_hpa(hpa: u64) {
    let base = hpa as *mut u8;
    core::ptr::write_bytes(base, 0, CHANNEL_SLOT_SIZE * 2);
    let ch0 = base as *mut UnidirectionalChannel;
    let ch1 = base.add(CHANNEL_SLOT_SIZE) as *mut UnidirectionalChannel;
    core::ptr::write(ch0, UnidirectionalChannel::new(0, "VM1->VM2"));
    core::ptr::write(ch1, UnidirectionalChannel::new(1, "VM2->VM1"));
}

pub unsafe fn vm1_to_vm2(hpa: u64) -> *mut UnidirectionalChannel {
    hpa as *mut UnidirectionalChannel
}

pub unsafe fn vm2_to_vm1(hpa: u64) -> *mut UnidirectionalChannel {
    (hpa as usize + CHANNEL_SLOT_SIZE) as *mut UnidirectionalChannel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_region_fits_in_yaml_size() {
        let need = CHANNEL_SLOT_SIZE * 2;
        assert!(need <= crate::config::SHARED_IPC_RING_SIZE as usize);
    }

    #[test]
    fn channel_slot_size_matches_guest_constant() {
        // Keep in sync with vm1-app / vm2-app CHANNEL_SLOT_SIZE / field offsets.
        assert_eq!(CHANNEL_SLOT_SIZE, 0x6140);
    }
}
