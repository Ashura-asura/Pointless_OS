//! The loopback network stack (design doc §8: "a userspace network stack (not
//! in the kernel) with capability-scoped socket objects: holding a network
//! capability means holding a specific, revocable right to talk to a specific
//! endpoint or class of endpoint, not ambient 'this process can open any
//! socket' authority").
//!
//! No NIC exists here — this is the loopback slice of that claim, and it is
//! honest about being one: the "interface" is the kernel's own endpoint
//! fabric, and the stack's job is the port namespace on top of it. A socket is
//! a kernel endpoint object; the stack owns the routing table (its
//! registration authority is a Creator cap, its declared role) and mints each
//! channel cap into the subscribing task's own CSpace — capability-scoped,
//! narrowed by derivation, revocable by the stack. Every hop of every packet
//! is an ordinary endpoint operation in the kernel audit log: sends are
//! attributed to the sender task, forwards to the stack, and there is no
//! hidden path to inject into a socket without holding its cap.
//!
//! Honest limits: loopback only, no packet framing beyond message boundaries,
//! a single stack instance, and ports are per-socket addresses rather than
//! per-host numbers.

use std::collections::HashMap;

use capability_core::{CapHandle, Kernel, KernelError, KernelResult, ObjectId, Rights, TaskHandle};

/// One registered socket: the stack's own cap onto the channel. `inject` is
/// the only way packets enter the channel, and it requires one of these.
#[derive(Debug, Clone)]
struct Socket {
    port: u16,
    service_cap: CapHandle,
}

/// The userspace netstack. Owns the port table; its entire kernel authority is
/// a Creator cap (to mint channels) and the channel caps it holds for routing.
pub struct LoopbackStack {
    service: TaskHandle,
    creator: CapHandle,
    next_port: u16,
    sockets: HashMap<ObjectId, Socket>,
}

impl LoopbackStack {
    pub fn new(service: TaskHandle, creator: CapHandle) -> LoopbackStack {
        LoopbackStack {
            service,
            creator,
            next_port: 1,
            sockets: HashMap::new(),
        }
    }

    /// Register `subscriber` as the owner of a fresh channel: the stack mints a
    /// new kernel endpoint, keeps SEND|RECV on it for routing, and mints a
    /// narrowed copy into the subscriber's CSpace. `subscriber_name` is a cap
    /// in the *stack's* CSpace naming the subscriber (its install task cap).
    /// Returns the port and the subscriber's channel slot. The channel is
    /// capability-scoped from birth: only the stack and the subscriber hold
    /// caps to it, and only narrow, derived ones.
    pub fn register(
        &mut self,
        k: &mut Kernel,
        subscriber: TaskHandle,
        subscriber_name: CapHandle,
    ) -> KernelResult<(u16, u32)> {
        let channel = k.create_endpoint(self.service, self.creator)?;
        let info = k.cap_info(self.service, channel)?;
        k.grant(
            self.service,
            channel,
            subscriber_name,
            Rights::SEND.union(Rights::RECV),
            None,
        )?;
        let subscriber_slot = (0..256u32)
            .find(|s| matches!(k.cap_info(subscriber, CapHandle(*s)), Ok(i) if i.obj == info.obj))
            .ok_or(KernelError::InvalidOperation)?;
        let port = self.next_port;
        self.next_port += 1;
        self.sockets.insert(
            info.obj,
            Socket {
                port,
                service_cap: channel,
            },
        );
        Ok((port, subscriber_slot))
    }

    /// Is `port` a live socket?
    pub fn is_listening(&self, port: u16) -> bool {
        self.sockets.values().any(|s| s.port == port)
    }

    /// Deliver one packet to a registered port. Requires *the caller to hold a
    /// cap onto its own channel* — knowing the port number is not enough: the
    /// injection op is an ordinary endpoint send, attributed to the caller in
    /// the audit log, and the kernel refuses it without SEND. The stack then
    /// drains its router cap on the sender's box and forwards the same bytes
    /// into the destination's box — both hops are logged with the stack as the
    /// caller, so a packet's whole path is reconstructible from the log.
    pub fn send(
        &mut self,
        k: &mut Kernel,
        from: TaskHandle,
        channel: CapHandle,
        to_port: u16,
        packet: Vec<u8>,
    ) -> KernelResult<()> {
        let target = self
            .sockets
            .values()
            .find(|s| s.port == to_port)
            .ok_or(KernelError::NoSuchObject)?;
        // The sender must actually hold SEND on a channel the stack knows.
        let from_info = k.cap_info(from, channel)?;
        let source = self
            .sockets
            .get(&from_info.obj)
            .ok_or(KernelError::InvalidOperation)?;
        let target_cap = target.service_cap;
        let source_cap = source.service_cap;
        // Hop 1: the sender injects into its own box — attributed to `from`.
        k.ep_send(from, channel, packet)?;
        // Hop 2: the stack reads its own copy and forwards the same bytes.
        let packet = k.ep_recv(self.service, source_cap)?;
        k.ep_send(self.service, target_cap, packet.unwrap_or_default())
    }

    /// Receive the next packet from a socket, or None (non-blocking, matching
    /// the kernel's userspace-scheduled model).
    pub fn recv(
        &mut self,
        k: &mut Kernel,
        subscriber: TaskHandle,
        channel: CapHandle,
    ) -> KernelResult<Option<Vec<u8>>> {
        k.ep_recv(subscriber, channel)
    }

    /// Tear a socket down: the stack drops its router cap. The subscriber's
    /// task remains — but without the stack forwarding into the channel, and
    /// with the channel revocable at the stack's will, the socket is gone from
    /// the interface. (The subscriber's own channel cap can later be revoked
    /// by ordinary revocation, which closes the channel for good.)
    pub fn unsubscribe(
        &mut self,
        k: &mut Kernel,
        channel: CapHandle,
    ) -> KernelResult<()> {
        let info = k.cap_info(self.service, channel)?;
        k.destroy(self.service, channel)?;
        self.sockets.remove(&info.obj);
        Ok(())
    }
}