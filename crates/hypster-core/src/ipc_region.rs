//! Shared IPC layout at SHARED_IPC_RING_BASE_HPA.

use crate::channel::UnidirectionalChannel;

pub const SHARED_IPC_GPA: u64 = 0xFE000000;
/// Size of one UnidirectionalChannel in bytes (repr C, align 64).
pub const CHANNEL_SLOT_SIZE: usize = core::mem::size_of::<UnidirectionalChannel>();

/// After both channels: concurrent endless-run heartbeats (no VM-exit needed).
pub const HEARTBEAT_OFFSET: usize = CHANNEL_SLOT_SIZE * 2;
pub const HEARTBEAT_MAGIC: u64 = 0x4859_5042_4541_5400; // "HYPBEAT\0"

/// Guest-published IPC counter progress (concurrent endless run).
/// VM1 posts incrementing counters on ch0; VM2 acks the same value on ch1.
#[repr(C)]
pub struct GuestHeartbeat {
    pub magic: u64,
    /// Last counter VM1 sent and got acked.
    pub vm1_count: u64,
    pub vm1_tsc: u64,
    /// Last counter VM2 received and acked.
    pub vm2_count: u64,
    pub vm2_tsc: u64,
}

pub unsafe fn init_ipc_at_hpa(hpa: u64) {
    let base = hpa as *mut u8;
    core::ptr::write_bytes(
        base,
        0,
        CHANNEL_SLOT_SIZE * 2 + core::mem::size_of::<GuestHeartbeat>(),
    );
    let ch0 = base as *mut UnidirectionalChannel;
    let ch1 = base.add(CHANNEL_SLOT_SIZE) as *mut UnidirectionalChannel;
    core::ptr::write(ch0, UnidirectionalChannel::new(0, "VM1->VM2"));
    core::ptr::write(ch1, UnidirectionalChannel::new(1, "VM2->VM1"));
    let hb = heartbeat_at(hpa);
    (*hb).magic = HEARTBEAT_MAGIC;
}

pub fn heartbeat_at(hpa: u64) -> *mut GuestHeartbeat {
    (hpa as usize + HEARTBEAT_OFFSET) as *mut GuestHeartbeat
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
        let need = CHANNEL_SLOT_SIZE * 2 + core::mem::size_of::<GuestHeartbeat>();
        assert!(need <= crate::config::SHARED_IPC_RING_SIZE as usize);
    }

    #[test]
    fn channel_slot_size_matches_guest_constant() {
        // Keep in sync with vm1-app / vm2-app CHANNEL_SLOT_SIZE / field offsets.
        assert_eq!(CHANNEL_SLOT_SIZE, 0x6140);
    }
}
