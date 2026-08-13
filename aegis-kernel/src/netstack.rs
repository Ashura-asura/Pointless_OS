//! Loopback netstack (design doc §8): a network stack whose sockets are
//! capability-scoped channel objects. Holding the network capability means
//! holding a specific, revocable right to talk to a specific endpoint — there
//! is no ambient "open any socket" authority, and no way to inject into a
//! socket without holding its channel cap. This is the kernel-complete mirror
//! of the model crate's `LoopbackStack` (`aegis/crates/net`), over the real
//! channel capability gates (`channel.rs`) instead of a mock kernel.
//!
//! The stack is a router, not a root: its only authority is the channel caps
//! it mints and holds (one router cap per socket, SEND|RECV), and the
//! capability total that a subscriber ever receives is a narrowed SEND|RECV
//! copy — never GRANT, so a channel cannot be delegated onward (I2).
//!
//! Honest limits: loopback only (the "interface" is the channel fabric, ports
//! are per-socket addresses rather than per-host numbers); single stack
//! instance; bounded message size/depth and a bounded port table; every hop
//! still goes through the ordinary capability gates.

use crate::cap::{Cap, CapSlot};
use crate::channel::CHANNEL_BUF;
use crate::tasks::set_task_cap;

pub const MAX_PORTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Port {
    port: u16,
    channel: u32,
    svc_slot: u64,
}

/// The loopback netstack. `svc` is the stack's service identity: its CSpace
/// holds one router cap (SEND|RECV) per registered socket.
pub struct Netstack {
    svc: usize,
    next_port: u16,
    ports: [Option<Port>; MAX_PORTS],
}

impl Netstack {
    pub fn new(svc: usize) -> Netstack {
        Netstack {
            svc,
            next_port: 1,
            ports: [None; MAX_PORTS],
        }
    }

    /// Register `subscriber` as the owner of a fresh socket: the stack mints a
    /// new channel, keeps a SEND|RECV router cap on it under its own identity,
    /// and installs a *narrowed* SEND|RECV copy into the subscriber's CSpace
    /// (no GRANT — a channel cannot be delegated onward). Returns the port and
    /// the subscriber's channel slot. `None` on exhaustion.
    ///
    /// The caller must run under the stack's identity (the mint is a normal
    /// channel-create, attributed to `svc`).
    pub fn register(&mut self, subscriber: usize) -> Option<(u16, u32)> {
        let slot = unsafe { crate::channel::ch_create() } as u64;
        if slot >= crate::tasks::MAX_CAPS as u64 {
            return None;
        }
        let channel = match crate::tasks::task_cap(self.svc, slot as usize).cap {
            Cap::Channel(id) => id,
            _ => return None,
        };
        let free = (0..crate::tasks::MAX_CAPS)
            .find(|&s| crate::tasks::task_cap(subscriber, s).cap == Cap::None)?;
        set_task_cap(
            subscriber,
            free,
            CapSlot {
                cap: Cap::Channel(channel),
                rights: crate::cap::CHANNEL_RIGHTS,
            },
        );
        let port = self.next_port;
        self.next_port = self.next_port.wrapping_add(1);
        let idx = self.ports.iter().position(|p| p.is_none())?;
        self.ports[idx] = Some(Port {
            port,
            channel,
            svc_slot: slot,
        });
        Some((port, free as u32))
    }

    /// Is `port` a live socket on this stack?
    pub fn is_listening(&self, port: u16) -> bool {
        self.ports.iter().flatten().any(|p| p.port == port)
    }

    /// Deliver one packet from `from`'s socket (channel `from_slot`) to
    /// `to_port`. Two hops, both through the ordinary capability gates:
    /// hop 1 injects into the sender's own channel under the sender's identity
    /// (the sender must hold SEND on a channel this stack routes — knowing the
    /// port number grants nothing); hop 2 drains the stack's router copy and
    /// forwards the same bytes into the destination's channel under the stack
    /// identity. `false` when the sender holds no usable cap, the source is
    /// not a socket of this stack, or the destination port is gone.
    pub fn send(&mut self, from: usize, from_slot: u64, to_port: u16, data: &[u8]) -> bool {
        let source_id = match crate::channel::channel_of(from, from_slot) {
            Some(id) => id,
            None => return false,
        };
        let source = match self.ports.iter().flatten().find(|p| p.channel == source_id) {
            Some(p) => *p,
            None => return false,
        };
        let target = match self.ports.iter().flatten().find(|p| p.port == to_port) {
            Some(p) => *p,
            None => return false,
        };
        // Hop 1: the sender injects into its own box — requires SEND.
        if !unsafe { crate::channel::ch_send_as(from, from_slot, data) } {
            return false;
        }
        // Hop 2: the stack drains its router copy and forwards the bytes.
        let mut scratch = [0u8; CHANNEL_BUF];
        let n = unsafe { crate::channel::ch_recv_as(self.svc, source.svc_slot, &mut scratch) };
        if n < 0 {
            return false;
        }
        unsafe { crate::channel::ch_send_as(self.svc, target.svc_slot, &scratch[..n as usize]) }
    }

    /// Pop the next packet from `subscriber`'s socket (channel `slot`), into
    /// `out`. `None` when the queue is empty or the caller holds no RECV cap;
    /// `Some(n)` otherwise with `out[..n]` holding the bytes.
    pub fn recv(&mut self, subscriber: usize, slot: u64, out: &mut [u8]) -> Option<usize> {
        let n = unsafe { crate::channel::ch_recv_as(subscriber, slot, out) };
        if n <= 0 {
            return None;
        }
        Some(n as usize)
    }

    /// Tear a socket down from the interface: the stack drops its router cap
    /// and destroys the channel object. The subscriber may still hold its
    /// granted cap, but it is now dangling — every gated operation on it fails
    /// (-1/None). Other sockets keep working untouched.
    pub fn unsubscribe(&mut self, svc_slot: u64) -> bool {
        let channel = match crate::channel::channel_of(self.svc, svc_slot) {
            Some(id) => id,
            None => return false,
        };
        for p in self.ports.iter_mut() {
            if let Some(inner) = p {
                if inner.channel == channel {
                    *p = None;
                }
            }
        }
        set_task_cap(self.svc, svc_slot as usize, CapSlot::empty());
        crate::channel::ch_destroy(channel)
    }
}

impl Default for Netstack {
    fn default() -> Netstack {
        Netstack::new(7)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::Rights;
    use crate::channel::reset_channels_for_test;
    use crate::tasks::reset_table_for_test;

    /// A clean world: stack service at task index 7, fresh channel + cap tables.
    fn world(svc: usize) -> (Netstack, usize) {
        reset_channels_for_test();
        reset_table_for_test();
        for i in 0..crate::tasks::MAX_TASKS {
            for s in 0..crate::tasks::MAX_CAPS {
                crate::tasks::set_task_cap(i, s, CapSlot::empty());
            }
        }
        crate::tasks::set_current_for_test(svc);
        (Netstack::new(svc), svc)
    }

    fn svc_slot_of(stack: &Netstack, port: u16) -> Option<u64> {
        stack
            .ports
            .iter()
            .flatten()
            .find(|p| p.port == port)
            .map(|p| p.svc_slot)
    }

    /// §8: sockets are capability-scoped objects — a task holding no channel
    /// cap cannot inject into a socket, even knowing the port number; the
    /// kernel agrees at the SEND ability check.
    #[test]
    fn sockets_are_capability_scoped_and_ports_are_not_ambient_authority() {
        let _g = crate::kernel_state_guard();
        let (mut stack, svc) = world(7);
        let (app_a, app_b, outsider) = (1usize, 2usize, 3usize);

        let (port_a, slot_a) = stack.register(app_a).unwrap();
        let (port_b, slot_b) = stack.register(app_b).unwrap();
        assert_ne!(port_a, port_b, "ports are unique per socket");

        // The outsider knows the port number but holds no channel cap — its
        // fabricated slot resolves to nothing, so the stack refuses.
        assert!(
            !stack.send(outsider, 0, port_a, b"x"),
            "a task without a channel cap cannot speak, even knowing the port"
        );
        // And the kernel agrees at the gate, on any channel it could name.
        assert!(
            !unsafe { crate::channel::ch_send_as(outsider, 0, b"raw") },
            "no cap -> no injection",
        );

        let _ = svc;
        assert!(stack.send(app_a, slot_a as u64, port_b, b"ping"));
        let mut out = [0u8; 64];
        let n = stack.recv(app_b, slot_b as u64, &mut out).unwrap();
        assert_eq!(&out[..n], b"ping");
    }

    /// §8: the stack is a router over real channel objects — FIFO order is the
    /// channel queue's own, and the drain is exact.
    #[test]
    fn packets_arrive_fifo_and_drain_exactly() {
        let _g = crate::kernel_state_guard();
        let (mut stack, _svc) = world(7);
        let (app_a, app_b) = (1usize, 2usize);
        let (_port_a, slot_a) = stack.register(app_a).unwrap();
        let (port_b, slot_b) = stack.register(app_b).unwrap();

        for i in 0..3u8 {
            assert!(stack.send(app_a, slot_a as u64, port_b, &[i]));
        }
        let mut out = [0u8; 64];
        for i in 0..3u8 {
            let n = stack.recv(app_b, slot_b as u64, &mut out).unwrap();
            assert_eq!(out[..n], [i], "packets arrive in the order they were sent");
        }
        assert!(
            stack.recv(app_b, slot_b as u64, &mut out).is_none(),
            "and the queue is drained exactly"
        );
    }

    /// §8: network capabilities are revocable rights. Once the stack drops its
    /// router cap, that socket is gone from the interface while every other
    /// socket keeps working — and a dangling subscriber cap is impotent.
    #[test]
    fn a_socket_can_be_torn_down_without_touching_its_peers() {
        let _g = crate::kernel_state_guard();
        let (mut stack, _svc) = world(7);
        let (app_a, app_b) = (1usize, 2usize);
        let (port_a, slot_a) = stack.register(app_a).unwrap();
        let (port_b, slot_b) = stack.register(app_b).unwrap();

        let svc_slot_a = svc_slot_of(&stack, port_a).unwrap();
        assert!(stack.unsubscribe(svc_slot_a));

        assert!(
            !stack.is_listening(port_a),
            "A's socket is gone from the interface"
        );
        assert!(stack.is_listening(port_b), "B's socket is untouched");
        // B still works; A's held cap is dangling and impotent.
        assert!(stack.send(app_b, slot_b as u64, port_b, b"self"));
        assert!(
            !stack.send(app_a, slot_a as u64, port_b, b"x"),
            "a revoked/destroyed socket cannot be spoken through"
        );
    }

    /// §8: the stack is a router, not a root — after registrations its CSpace
    /// holds exactly its socket router caps and nothing else, and a subscriber
    /// receives a narrowed SEND|RECV copy (no GRANT, no delegation - I2).
    #[test]
    fn the_stack_holds_no_authority_beyond_its_sockets() {
        let _g = crate::kernel_state_guard();
        let (mut stack, svc) = world(7);
        let (app_a, app_b) = (1usize, 2usize);
        let (_port_a, slot_a) = stack.register(app_a).unwrap();
        let (_port_b, slot_b) = stack.register(app_b).unwrap();

        // The stack's CSpace: exactly two channel caps, SEND|RECV, no other
        // object kinds.
        let mut channels = 0;
        for s in 0..crate::tasks::MAX_CAPS {
            let cs = crate::tasks::task_cap(svc, s);
            if cs.cap == Cap::None {
                continue;
            }
            match cs.cap {
                Cap::Channel(_) => {
                    channels += 1;
                    assert!(
                        cs.rights == crate::cap::CHANNEL_RIGHTS
                            && !cs.rights.contains(Rights::GRANT),
                        "router caps are SEND|RECV, never delegable"
                    );
                }
                Cap::None => {}
                _ => panic!("stack CSpace must hold only channel caps"),
            }
        }
        assert_eq!(channels, 2, "exactly the two socket router caps");

        // Subscribers hold narrowed copies: no GRANT anywhere on the granted cap.
        let (a, b) = (
            crate::tasks::task_cap(app_a, slot_a as usize),
            crate::tasks::task_cap(app_b, slot_b as usize),
        );
        assert_eq!(a.rights, crate::cap::CHANNEL_RIGHTS);
        assert_eq!(b.rights, crate::cap::CHANNEL_RIGHTS);
        assert!(!a.rights.contains(Rights::GRANT));
    }
}
