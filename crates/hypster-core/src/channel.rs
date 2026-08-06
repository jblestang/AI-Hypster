//! # Lock-Free Cache-Optimized Inter-Partition SPSC Ring Buffer (`channel.rs`)
//!
//! Provides a state-of-the-art Single-Producer Single-Consumer (SPSC) lock-free ring buffer
//! optimized for low latency and high packet throughput between isolated VM partitions.
//!
//! ## Key Concurrency Optimizations
//! 1. **Zero RMW Locks / No Shared Count Variable**: Eliminates atomic `fetch_add`/`fetch_sub` operations (`lock xadd`)
//!    that cause L1/L2 cache line invalidations across physical CPU cores.
//! 2. **Cache Line Isolation (`CachePadded`)**: Puts Producer fields (`tail`, `cached_head`) and Consumer fields
//!    (`head`, `cached_tail`) on separate 64-byte cache lines, eliminating false sharing.
//! 3. **Power-of-Two Fast Bitwise Masking**: Queue capacity is a power of 2 (64 items). Ring indexing uses bitwise AND
//!    (`idx & MASK`) instead of costly integer modulo division (`idx % CAP`).
//! 4. **Opposite-Index Caching**: Producers cache the consumer's `head` position locally (`cached_head`), avoiding cross-core
//!    atomic loads until the buffer appears full.

use e1000_spec::MAX_PACKET_LEN;
use core::sync::atomic::{AtomicUsize, Ordering, fence};

pub const CHANNEL_QUEUE_CAPACITY: usize = 16; // Power of 2 (16 slots * 1536B = 24KB, prevents UEFI stack overflow)
pub const CHANNEL_QUEUE_MASK: usize = CHANNEL_QUEUE_CAPACITY - 1;

#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct Packet {
    pub data: [u8; MAX_PACKET_LEN],
    pub len: usize,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            data: [0u8; MAX_PACKET_LEN],
            len: 0,
        }
    }
}

/// 64-byte cache-line padded wrapper to eliminate false sharing
#[repr(C, align(64))]
pub struct CachePadded<T> {
    pub value: T,
}

impl<T> CachePadded<T> {
    pub const fn new(value: T) -> Self {
        Self { value }
    }
}

#[repr(C, align(64))]
pub struct UnidirectionalChannel {
    pub id: usize,
    pub name: &'static str,
    pub queue: [Packet; CHANNEL_QUEUE_CAPACITY],
    
    // Producer Cache Line (64 Bytes)
    pub tail: CachePadded<AtomicUsize>,
    pub cached_head: CachePadded<usize>,

    // Consumer Cache Line (64 Bytes)
    pub head: CachePadded<AtomicUsize>,
    pub cached_tail: CachePadded<usize>,
}

impl UnidirectionalChannel {
    pub fn new(id: usize, name: &'static str) -> Self {
        Self {
            id,
            name,
            queue: [Packet::default(); CHANNEL_QUEUE_CAPACITY],
            tail: CachePadded::new(AtomicUsize::new(0)),
            cached_head: CachePadded::new(0),
            head: CachePadded::new(AtomicUsize::new(0)),
            cached_tail: CachePadded::new(0),
        }
    }

    /// High-performance Lock-Free SPSC Send (Producer)
    pub fn send(&mut self, data: &[u8]) -> bool {
        let tail = self.tail.value.load(Ordering::Relaxed);
        let cached_head = self.cached_head.value;

        // Check if queue is full using cached head
        if tail.wrapping_sub(cached_head) >= CHANNEL_QUEUE_CAPACITY {
            // Refresh cached head from shared atomic
            let actual_head = self.head.value.load(Ordering::Acquire);
            self.cached_head.value = actual_head;

            if tail.wrapping_sub(actual_head) >= CHANNEL_QUEUE_CAPACITY {
                return false; // Queue is full
            }
        }

        // Copy packet payload to ring buffer slot
        let slot_idx = tail & CHANNEL_QUEUE_MASK;
        let copy_len = data.len().min(MAX_PACKET_LEN);
        self.queue[slot_idx].data[..copy_len].copy_from_slice(&data[..copy_len]);
        self.queue[slot_idx].len = copy_len;

        // Memory barrier to guarantee data write completes before tail pointer update
        fence(Ordering::Release);

        // Advance tail index with Release ordering
        self.tail.value.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// High-performance Lock-Free SPSC Receive (Consumer)
    pub fn recv(&mut self) -> Option<Packet> {
        let head = self.head.value.load(Ordering::Relaxed);
        let cached_tail = self.cached_tail.value;

        // Check if queue is empty using cached tail
        if head == cached_tail {
            // Refresh cached tail from shared atomic
            let actual_tail = self.tail.value.load(Ordering::Acquire);
            self.cached_tail.value = actual_tail;

            if head == actual_tail {
                return None; // Queue is empty
            }
        }

        // Memory barrier to guarantee we read valid payload written by producer
        fence(Ordering::Acquire);

        // Read packet from ring buffer slot
        let slot_idx = head & CHANNEL_QUEUE_MASK;
        let pkt = self.queue[slot_idx];

        // Advance head index with Release ordering
        self.head.value.store(head.wrapping_add(1), Ordering::Release);
        Some(pkt)
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        let head = self.head.value.load(Ordering::Relaxed);
        let tail = self.tail.value.load(Ordering::Relaxed);
        head == tail
    }
}
