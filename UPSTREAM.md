# Upstream tracking

This fork (`oer/main` at `github.com/ermacv/xarxa`) follows
`github.com/embassy-rs/xarxa` `main` by periodic merges into `oer/main`. It
is never rebased: every pinned revision stays reachable, and each merge
records what it took. `main` in this repository mirrors upstream unchanged.

## Last merge

- Upstream: `959ee44f4609d33ada7e4a3dff563b692892460a` (2026-09-28,
  "Merge pull request #38 from quartiq/warn-old-data").
- Previous merge base: `9d32976c3f3349235bab4f91922b81e5b04326b3`.

To prepare the next merge, `git fetch upstream` and review
`git log <last merged upstream>..upstream/main`.

## Why the fork differs

An ESP32-S31 access point with two stations both at ceiling traffic needs
the radio to pull per-destination bursts: A-MPDU aggregates of up to 32
MPDUs are only possible when one destination's frames arrive together.
Upstream's single interleaved egress path and busy retry break that, so the
fork keeps:

- **Explicit packet pools.** `Stack::new(seed, PacketBufAllocator)`; every
  stack-originated packet comes from that allocator, and `PacketPool` /
  `PacketPoolStorage` own placement. There is no process-global pool and no
  `PacketBuf::try_new`.
- **Event-driven pool waits (async).** An allocation failure sets a starved
  edge that `Stack::take_packet_allocator_starved` reports; the executor arms
  the pool's `PacketPoolWaiter`, and the release of a buffer schedules the
  next poll. UDP and raw sockets whose send returned `NoBuffer` are woken by
  a poll that finds a free buffer. Without `async`, the upstream 1 ms
  `POOL_RETRY_DELAY` deadline remains.
- **Bounded cooperative polling.** `Stack::poll_bounded(PollBudget)` returns
  `PollOutcome` and resumes ingress and TCP egress from round-robin cursors.
- **Zero-copy adoption.** `ExternalPacketOrigin::adopt` hands driver-owned
  buffers to the stack without copying; it requires
  `PACKET_BUF_DRIVER_HEADROOM == 0`, so the headroom features other than 0
  are not used by this repository's consumers.
- **ARP reply owners across backpressure.** Replies wait in a bounded
  per-interface queue for driver credit instead of being dropped or retried
  on a timer.
- **Aligned checksum.** `wire::ip::checksum::data` sums aligned 32-bit words
  through `bytemuck`, without `unsafe`.

## Upstream changes not taken

- `452d805` "Remove the tx_starved hack" together with the global pool and
  `PacketBuf::try_new`: replaced by the explicit pools and waiter above.
- `d4c0dc7` custom packet pool placement: explicit pools already give every
  pool its own storage.
- `packet-buf-count-*` features and `PACKET_BUF_COUNT`: the pool size is the
  `PacketPoolStorage<COUNT>` parameter.
- `85784cb` critical-section fallback for targets without atomic CAS: the pool
  bitmap uses `core::sync::atomic` and the driver crate fails to compile
  without 32-bit atomic read-modify-write.
- UDP `poll_send` / `SendWait` from the fork were replaced by upstream's
  `tx_blocked_on` device wait, extended with the pool wait described above.

`xarxa-driver` is a path dependency of `xarxa`, so one revision pins both.
