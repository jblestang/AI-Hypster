//! Trustworthy guest-driven IPC throughput: calibrated TSC, counted bytes, size ladder.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::serial::{serial_print, serial_print_dec};
use crate::ThroughputStats;
use crate::ipc_region::CHANNEL_SLOT_SIZE;

/// Round-trips required per payload-size trial.
pub const THROUGHPUT_TARGET_PACKETS: u64 = 10_000;

/// Payload lengths exercised in one Target B boot (≤ MAX_PACKET_LEN 1518).
pub const PAYLOAD_SIZES: [u64; 5] = [64, 256, 512, 1024, 1514];

/// Control block sits after two unidirectional channels in the IPC buffer.
pub const CONTROL_OFFSET: usize = CHANNEL_SLOT_SIZE * 2;

pub const CONTROL_MAGIC: u64 = 0x4859_5054_4354_4C00; // "HYPTCTL\0" marker

pub const CMD_IDLE: u64 = 0;
pub const CMD_RUN: u64 = 1;
pub const CMD_SHUTDOWN: u64 = 2;

/// Shared host↔guest trial control (GPA = SHARED_IPC_GPA + CONTROL_OFFSET).
#[repr(C)]
pub struct ThroughputControl {
    pub magic: u64,
    pub payload_len: u64,
    pub target_packets: u64,
    pub trial_id: AtomicU64,
    pub command: AtomicU64,
    pub vm1_done_trial: AtomicU64,
    pub vm2_done_trial: AtomicU64,
}

impl ThroughputControl {
    pub fn init(ctrl: &mut Self) {
        ctrl.magic = CONTROL_MAGIC;
        ctrl.payload_len = 0;
        ctrl.target_packets = THROUGHPUT_TARGET_PACKETS;
        ctrl.trial_id.store(0, Ordering::SeqCst);
        ctrl.command.store(CMD_IDLE, Ordering::SeqCst);
        ctrl.vm1_done_trial.store(0, Ordering::SeqCst);
        ctrl.vm2_done_trial.store(0, Ordering::SeqCst);
    }
}

static mut TSC_HZ: u64 = 0;

pub fn set_tsc_hz(hz: u64) {
    unsafe {
        TSC_HZ = hz.max(1);
    }
}

pub fn tsc_hz() -> u64 {
    unsafe {
        let hz = TSC_HZ;
        if hz == 0 {
            // Fallback only if UEFI forgot to calibrate — still not the old 3 GHz lie:
            // treat TSC as 1 GHz so numbers stay conservative/obviously uncalibrated.
            1_000_000_000
        } else {
            hz
        }
    }
}

pub fn control_at(ipc_hpa: u64) -> *mut ThroughputControl {
    (ipc_hpa as usize + CONTROL_OFFSET) as *mut ThroughputControl
}

/// Build stats from measured packet count, payload bytes, and calibrated TSC.
pub fn stats_from_measurement(
    packets: u64,
    payload_bytes_total: u64,
    start_tsc: u64,
    end_tsc: u64,
    hz: u64,
) -> ThroughputStats {
    let pkts = packets.max(1);
    let elapsed = end_tsc.saturating_sub(start_tsc).max(1);
    let hz = hz.max(1);
    let bytes = payload_bytes_total;
    let bits = bytes.saturating_mul(8);
    let cycles_per_pkt = elapsed / pkts;
    // us = cycles * 1e6 / hz
    let elapsed_us = elapsed.saturating_mul(1_000_000) / hz;
    let us_per_pkt = elapsed_us.max(1) / pkts;
    let pps = (pkts.saturating_mul(hz)) / elapsed;
    let kbps = (bits.saturating_mul(hz)) / (elapsed.saturating_mul(1000));
    let mbps = kbps / 1000;
    ThroughputStats {
        total_packets: pkts,
        total_bytes: bytes,
        elapsed_cycles: elapsed,
        elapsed_us,
        cycles_per_packet: cycles_per_pkt,
        us_per_packet: us_per_pkt,
        pps,
        kbps,
        mbps,
    }
}

pub fn print_stats(stats: &ThroughputStats, payload_len: u64) {
    serial_print("[HYPSTER] Throughput: pkts=");
    serial_print_dec(stats.total_packets);
    serial_print(" len=");
    serial_print_dec(payload_len);
    serial_print(" cycles/pkt=");
    serial_print_dec(stats.cycles_per_packet);
    serial_print(" us/pkt=");
    serial_print_dec(stats.us_per_packet);
    serial_print(" pps=");
    serial_print_dec(stats.pps);
    serial_print(" Mbps=");
    serial_print_dec(stats.mbps);
    serial_print("\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_use_calibrated_hz_and_real_bytes() {
        // 2 GHz TSC, 100 ms elapsed, 10_000 packets × 64 bytes.
        let hz = 2_000_000_000u64;
        let elapsed = hz / 10; // 100 ms
        let pkts = 10_000u64;
        let len = 64u64;
        let stats = stats_from_measurement(pkts, pkts * len, 1000, 1000 + elapsed, hz);
        assert_eq!(stats.elapsed_us, 100_000);
        assert_eq!(stats.us_per_packet, 10); // 100ms / 10k
        assert_eq!(stats.pps, 100_000);
        // 10k * 64 * 8 bits / 0.1 s = 51.2 Mbps → 51
        assert_eq!(stats.mbps, 51);
        assert_eq!(stats.total_bytes, pkts * len);
    }

    #[test]
    fn control_offset_fits_in_ipc_buffer() {
        let need = CONTROL_OFFSET + core::mem::size_of::<ThroughputControl>();
        assert!(need <= crate::config::SHARED_IPC_RING_SIZE as usize);
        assert_eq!(CONTROL_OFFSET, 0xC280);
    }
}
