# xarxa-driver

The driver interface of the [`xarxa`](https://crates.io/crates/xarxa) network
stack.

Driver implementations should depend on `xarxa-driver` instead of the full `xarxa` crate.

## External payload ownership

`external-origin` enables `ExternalPacketOrigin` and `ExternalPacketRelease`.
It is off by default: without it, packet ownership has only the `Pool` variant
and dropping a packet cannot call an external owner's release function.
Ordinary `PacketPool`, allocator and `PacketBuf` APIs are always available.
With the feature enabled the existing external adoption API is unchanged.

```sh
cargo test -p xarxa-driver
cargo test -p xarxa-driver --features external-origin,async
```
