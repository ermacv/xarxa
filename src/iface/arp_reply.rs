//! Bounded, coalescing ARP response ownership. No pool allocation and no RX gate.
use super::IfaceState;
use crate::driver::{LinkState, PacketBuf};
use crate::wire::Ipv4Address;

// Small control working set, independent of socket backlog. A flood can fill
// this queue; drop the new distinct request rather than evict an admitted reply.
const CAPACITY: usize = 4;

pub(crate) struct Reply {
    peer: Ipv4Address,
    local: Ipv4Address,
    packet: PacketBuf,
}

#[derive(Default)]
pub(crate) struct Replies(heapless::Deque<Reply, CAPACITY>);

impl Replies {
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
}

impl IfaceState<'_> {
    pub(crate) fn queue_arp_reply(&mut self, peer: Ipv4Address, local: Ipv4Address, packet: PacketBuf) {
        // Duplicate requests need one response. Replace in place so a changed
        // sender MAC is reflected without changing FIFO order or adding owners.
        if let Some(reply) = self
            .arp_replies
            .0
            .iter_mut()
            .find(|r| r.peer == peer && r.local == local)
        {
            reply.packet = packet;
        } else if self.arp_replies.0.push_back(Reply { peer, local, packet }).is_err() {
            warn!("iface {}: ARP response queue full", self.handle.index());
        }
        self.flush_arp_replies();
    }

    /// Retry only on stack/driver events. A busy driver adds no immediate timer
    /// deadline and does not wake a sender just to retry the same refusal.
    pub(crate) fn flush_arp_replies(&mut self) -> bool {
        if self.arp_replies.0.is_empty() {
            return true;
        }
        if self.driver.link_state() == LinkState::Down {
            self.arp_replies.clear();
            return true;
        }
        while !self.arp_replies.0.is_empty() && self.driver.can_transmit() {
            let mut reply = self.arp_replies.0.pop_front().unwrap();
            match self.driver.transmit(reply.packet) {
                Ok(()) => {}
                Err(packet) => {
                    reply.packet = packet;
                    // This exact slot was removed above. There is no other
                    // writer while the stack holds the interface exclusively.
                    assert!(self.arp_replies.0.push_front(reply).is_ok());
                    break;
                }
            }
        }
        self.arp_replies.0.is_empty()
    }
}
