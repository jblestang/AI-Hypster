//! Guest-driven IPC throughput constants and serial reporting.

use crate::serial::{serial_print, serial_print_dec};
use crate::ThroughputStats;

/// Round-trips (VM1 send + VM2 ack) required for Target B SUCCESS.
pub const THROUGHPUT_TARGET_PACKETS: u64 = 10_000;

/// Ethernet MTU-sized frame used for Mbps accounting (matches legacy `Hypervisor::run`).
pub const PACKET_BYTES: u64 = 1514;

/// Packets processed per guest slice before `hlt` yield.
pub const BURST_PER_SLICE: usize = 128;

pub fn stats_from_tsc(packets: u64, start_tsc: u64, end_tsc: u64) -> ThroughputStats {
    let pkts = packets.max(1);
    let elapsed = end_tsc.saturating_sub(start_tsc).max(1);
    let bytes = pkts.saturating_mul(PACKET_BYTES);
    let bits = bytes.saturating_mul(8);
    let cycles_per_pkt = elapsed / pkts;
    let cpu_hz = 3_000_000_000u64;
    let elapsed_us = elapsed / 3000;
    let us_per_pkt = elapsed_us.max(1) / pkts;
    let pps = (pkts.saturating_mul(cpu_hz)) / elapsed;
    let kbps = (bits.saturating_mul(cpu_hz)) / (elapsed.saturating_mul(1000));
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

pub fn print_stats(stats: &ThroughputStats) {
    serial_print("[HYPSTER] Throughput: ");
    serial_print_dec(stats.total_packets);
    serial_print(" pkts, ");
    serial_print_dec(stats.pps);
    serial_print(" pps, ");
    serial_print_dec(stats.mbps);
    serial_print(" Mbps\n");
}
