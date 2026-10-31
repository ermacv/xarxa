# xarxa-driver

The driver interface of the [`xarxa`](https://crates.io/crates/xarxa) network
stack.

Driver implementations should depend on `xarxa-driver` instead of the full `xarxa` crate.

## External payload ownership

`external-origin` enables `ExternalPacketSlots`, which adopts an owner of
stable storage (`ExternalPacketStorage`, such as a detached DMA buffer) as a
`PacketBuf` through a safe API. The owner moves into its slot before it lends
its bytes, a refusal returns it with an `ExternalPacketRefusal`, and the
packet's final drop drops the owner in its slot before the slot takes another.
The feature is off by default: packet ownership then has only the `Pool`
variant. Ordinary `PacketPool`, allocator and `PacketBuf` APIs are always
available.

```sh
cargo test -p xarxa-driver
cargo test -p xarxa-driver --features external-origin,async
```
