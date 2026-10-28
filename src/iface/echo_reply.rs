//! IPv4 EchoReply owners waiting for device credit, in arrival order.
use crate::driver::{Driver, PacketBuf};
use crate::stack::Statistics;

// W3 reuses at most eight RX-pool owners for native replies. Keep that entire
// working set without allocating packets or changing the RX/TX queue depths.
// The bound also applies with `alloc`; excess replies drop newest, explicitly.
pub(crate) const CAPACITY: usize = 8;

#[derive(Default)]
pub(crate) struct Replies {
    // Keep the head's slot while lending its owner to the driver. A refusal
    // restores that exact slot without a fallible reinsert or an assertion.
    head: Option<PacketBuf>,
    tail: heapless::Deque<PacketBuf, { CAPACITY - 1 }>,
}

impl Replies {
    pub(crate) fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    pub(crate) fn push(&mut self, packet: PacketBuf, statistics: &mut Statistics) {
        if self.head.is_none() {
            self.head = Some(packet);
        } else if let Err(packet) = self.tail.push_back(packet) {
            drop(packet);
            statistics.icmpv4_echo_dropped = statistics.icmpv4_echo_dropped.saturating_add(1);
        }
    }

    /// At most CAPACITY attempts. No retry timer or allocation: a busy driver
    /// arms its credit-return wake through can_transmit(). RX remains eligible.
    pub(crate) fn flush(&mut self, driver: &mut impl Driver, statistics: &mut Statistics) {
        while self.head.is_some() && driver.can_transmit() {
            let Some(packet) = self.head.take() else {
                break;
            };
            statistics.tx_frames = statistics.tx_frames.saturating_add(1);
            match driver.transmit(packet) {
                Ok(()) => self.head = self.tail.pop_front(),
                Err(packet) => {
                    self.head = Some(packet);
                    statistics.tx_refused = statistics.tx_refused.saturating_add(1);
                    statistics.icmpv4_echo_refused = statistics.icmpv4_echo_refused.saturating_add(1);
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{PacketPool, PacketPoolStorage};

    #[test]
    fn overflow_saturates_and_dropping_retention_returns_every_owner() {
        let storage = Box::leak(Box::new(PacketPoolStorage::<16>::new()));
        let pool = Box::leak(Box::new(PacketPool::new(storage)));
        let mut replies = Replies::default();
        let mut statistics = Statistics {
            icmpv4_echo_dropped: u32::MAX,
            ..Statistics::default()
        };
        for _ in 0..CAPACITY + 2 {
            replies.push(pool.try_alloc().unwrap(), &mut statistics);
        }
        assert_eq!(statistics.icmpv4_echo_dropped, u32::MAX);
        let free: std::vec::Vec<_> = std::iter::from_fn(|| pool.try_alloc()).collect();
        assert_eq!(free.len(), 16 - CAPACITY);
        drop(replies);
        let returned: std::vec::Vec<_> = std::iter::from_fn(|| pool.try_alloc()).collect();
        assert_eq!(returned.len(), CAPACITY);
    }
}
