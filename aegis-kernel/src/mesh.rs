//! Mesh — Phase J-3: two-node consensus (split-brain resolution) and remote
//! invocation of a transferred capability, built ON TOP of the do-not-touch
//! `fleet` module's public API (Phase I) — it never edits `fleet.rs` or
//! `netif.rs`; it composes them.
//!
//! Phase I's own Definition of Done explicitly left two things "out of
//! scope": split-brain/consensus resolution, and remote *use* of a
//! transferred capability (fleet.rs module doc, scope note 3). J-3 builds the
//! layer that closes both, honestly scoped:
//!
//! 1. **Consensus = deterministic two-node election.** Both nodes carry a
//!    monotonic `epoch` and a `leader`. When they meet (boot, or a partition
//!    heals), each proposes `(my_id, my_epoch)`. The pure, total function
//!    `elect()` maps the two proposals to a single `(epoch, leader)`: the
//!    higher epoch wins, and on equal epochs the lexicographically-smaller
//!    `NodeId` breaks the tie. Because both nodes run the same function on
//!    the same inputs, they converge to the same answer — that is the
//!    resolution. Honest limits: with two nodes there is no majority quorum
//!    and no Byzantine tolerance; this is a deterministic reconciliation
//!    ("last writer by epoch, then total order on identity"), exactly what a
//!    two-node fleet can claim. It is not Raft/Paxos.
//!
//! 2. **Remote invocation = a transferred capability used to call back.**
//!    Node A mints an object (a stateful counter), delegates it to B
//!    (Phase I `send_to` + recipient binding). B holds a *verified* remote
//!    capability. To invoke, B mints a fresh token naming the same object,
//!    binds it to A (`send_to(A)`), and presents it in an `INVOKE` message.
//!    A verifies it with `Fleet::verify` — issuer must be the trusted peer
//!    B, recipient must be A, the HMAC chain must hold, and B must be
//!    reachable (the same fail-closed gate as Phase I). A then executes the
//!    operation on its own object and replies with a result token minted by
//!    A and bound to B, which B verifies. Both directions are therefore
//!    HMAC-verified capability envelopes: the request proves "B, a trusted
//!    reachable peer, holds a token for object 42 bound to A" and the
//!    response proves "A, the issuer, holds a token for object 42 bound to
//!    B." Honest limits: B's invocation token is B-signed (A authenticates
//!    *who is calling* and *what object*, then enforces A's own policy on
//!    whether the object may be called); A does not re-verify the original
//!    A→B delegation envelope through `Fleet::verify` (it is
//!    recipient-bound to B), so A keeps its own one-bit ledger of "object 42
//!    was delegated to B" as the authorization link.
//!
//! ## What's real here
//!
//! - A real UDP link on its own port (`MESH_PORT`, distinct from
//!   `FLEET_PORT`) over the same Phase E netif, carrying fixed-width
//!   capability envelopes (no heap — the whole kernel is no_std/no-alloc).
//! - The same `Fleet` identity/registration/verification machinery as
//!   Phase I; the demo key is the fixed demo constant used there.
//! - A live two-node demo (feature `fleet-j3`, mutually combined with
//!   `fleet-node-a`/`fleet-node-b`) that performs one real mint + delegate,
//!   one real remote invocation round-trip, one real deterministic election,
//!   and — when node A's process is killed and relaunched — real
//!   fail-closed staleness and a real deterministic re-election that
//!   resolves the split-brain. See the `run_boot_demo` gate and
//!   `PHASE_J3_INTEGRATION.md` note in the module doc of `main.rs`.

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
use crate::cap::Rights;
#[cfg(not(any(feature = "fleet-node-a", feature = "fleet-node-b")))]
use crate::fleet::NodeId;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
use crate::fleet::{
    deserialize, serialize, Fleet, NodeId, RemoteCapability, TokenObjectKind, ENVELOPE_MAX,
};

/// The one fixed port mesh traffic uses, distinct from `FLEET_PORT` so the
/// two-node Phase I demo and this layer could even run in one boot without
/// socket collisions (UDP dispatch matches on `local_port == dst_port`).
pub const MESH_PORT: u16 = 7778;

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const MSG_HEARTBEAT: u8 = 0x01;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const MSG_PROPOSE: u8 = 0x02;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const MSG_PROPOSE_ACK: u8 = 0x03;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const MSG_DELEGATE: u8 = 0x04;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const MSG_INVOKE: u8 = 0x05;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const MSG_RESULT: u8 = 0x06;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const MSG_DENIED: u8 = 0x07;

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const OP_INCR: u8 = 0x01;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const OBJ_COUNTER: u64 = 42;

// ---- Deterministic election (pure, unit-tested) ----------------------------

fn node_id_cmp(a: NodeId, b: NodeId) -> core::cmp::Ordering {
    a.0.cmp(&b.0)
}

/// Deterministic two-node election. Given my identity+epoch and the peer's
/// identity+epoch, returns the single `(epoch, leader)` both nodes compute:
/// the higher epoch wins; on equal epochs the lexicographically-smaller
/// `NodeId` wins. Because it is a pure function of the same two proposals,
/// both sides converge on the same answer — that is the resolution.
pub fn elect(my_id: NodeId, my_epoch: u64, peer_id: NodeId, peer_epoch: u64) -> (u64, NodeId) {
    match my_epoch.cmp(&peer_epoch) {
        core::cmp::Ordering::Greater => (my_epoch, my_id),
        core::cmp::Ordering::Less => (peer_epoch, peer_id),
        core::cmp::Ordering::Equal => {
            if node_id_cmp(my_id, peer_id).is_lt() {
                (my_epoch, my_id)
            } else {
                (peer_epoch, peer_id)
            }
        }
    }
}

// ---- Transport over the Phase E netif (mirrors fleet::open_link) -----------

/// Open a UDP socket to `peer_ip:MESH_PORT`, bound to `MESH_PORT` locally
/// (so the peer's replies, addressed to `MESH_PORT`, match this socket).
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
pub fn open_mesh_link(peer_ip: [u8; 4]) -> Option<u16> {
    unsafe {
        crate::netif::NetIf::with(|net| {
            net.socket_open(
                crate::netif::SockKind::Udp,
                peer_ip,
                MESH_PORT,
                Some(MESH_PORT),
            )
            .map(|(id, _)| id)
        })
    }
}

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
pub fn close_mesh_link(socket: u16) {
    unsafe {
        crate::netif::NetIf::with(|net| {
            net.socket_close(socket);
        });
    }
}

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
fn send_msg(socket: u16, buf: &[u8]) -> bool {
    unsafe { crate::netif::NetIf::with(|net| net.socket_send(socket, buf) > 0) }
}

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
pub fn send_heartbeat(socket: u16) -> bool {
    send_msg(socket, &[MSG_HEARTBEAT])
}

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
fn serialize_env(cap: &RemoteCapability) -> ([u8; ENVELOPE_MAX], usize) {
    let mut env = [0u8; ENVELOPE_MAX];
    let n = serialize(cap, &mut env);
    (env, n)
}

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
fn send_propose(socket: u16, my_id: NodeId, my_epoch: u64) -> bool {
    let mut buf = [0u8; 1 + 32 + 8];
    buf[0] = MSG_PROPOSE;
    buf[1..33].copy_from_slice(&my_id.0);
    buf[33..41].copy_from_slice(&my_epoch.to_le_bytes());
    send_msg(socket, &buf)
}

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
fn send_propose_ack(socket: u16, epoch: u64, leader: NodeId) -> bool {
    let mut buf = [0u8; 1 + 8 + 32];
    buf[0] = MSG_PROPOSE_ACK;
    buf[1..9].copy_from_slice(&epoch.to_le_bytes());
    buf[9..41].copy_from_slice(&leader.0);
    send_msg(socket, &buf)
}

#[cfg(feature = "fleet-node-a")]
fn send_delegate(socket: u16, cap: &RemoteCapability) -> bool {
    let (env, n) = serialize_env(cap);
    let mut buf = [0u8; 1 + ENVELOPE_MAX];
    buf[0] = MSG_DELEGATE;
    buf[1..1 + n].copy_from_slice(&env[..n]);
    send_msg(socket, &buf[..1 + n])
}

#[cfg(feature = "fleet-node-b")]
fn send_invoke(socket: u16, token: &RemoteCapability, op: u8, operand: u64) -> bool {
    let (env, n) = serialize_env(token);
    let mut buf = [0u8; 1 + ENVELOPE_MAX + 1 + 8];
    buf[0] = MSG_INVOKE;
    buf[1..1 + n].copy_from_slice(&env[..n]);
    buf[1 + ENVELOPE_MAX] = op;
    buf[1 + ENVELOPE_MAX + 1..1 + ENVELOPE_MAX + 9].copy_from_slice(&operand.to_le_bytes());
    send_msg(socket, &buf[..1 + ENVELOPE_MAX + 9])
}

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
fn send_result(socket: u16, token: &RemoteCapability, value: u64) -> bool {
    let (env, n) = serialize_env(token);
    let mut buf = [0u8; 1 + ENVELOPE_MAX + 8];
    buf[0] = MSG_RESULT;
    buf[1..1 + n].copy_from_slice(&env[..n]);
    buf[1 + ENVELOPE_MAX..1 + ENVELOPE_MAX + 8].copy_from_slice(&value.to_le_bytes());
    send_msg(socket, &buf[..1 + ENVELOPE_MAX + 8])
}

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
fn send_denied(socket: u16, reason: u8) -> bool {
    send_msg(socket, &[MSG_DENIED, reason])
}

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const DENIED_NOTAUTH: u8 = 0x01;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const DENIED_NOTDELEGATED: u8 = 0x02;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const DENIED_BADOP: u8 = 0x03;

/// One event drained from the mesh link. Fixed-width buffers only (no heap).
#[allow(clippy::large_enum_variant)]
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
pub enum MeshEvent {
    None,
    Heartbeat,
    Propose {
        node: NodeId,
        epoch: u64,
    },
    ProposeAck {
        epoch: u64,
        leader: NodeId,
    },
    Delegate(RemoteCapability),
    Invoke {
        token: RemoteCapability,
        op: u8,
        operand: u64,
    },
    Result {
        token: RemoteCapability,
        value: u64,
    },
    Denied {
        reason: u8,
    },
    Malformed,
}

/// Drain pending bytes from `socket`, if any, and classify the first complete
/// mesh message. Transport only — does not touch `Fleet` or consensus state.
///
/// Framing note: `netif`'s UDP path appends each datagram's payload into one
/// per-socket byte stream, so two mesh messages can arrive coalesced (e.g. a
/// 1-byte heartbeat followed by a 41-byte proposal) inside a single
/// `socket_recv`. Reading one fixed slice per call would then misparse across
/// message boundaries. We instead keep a persistent stream buffer and consume
/// exactly one message's bytes per call, using the message code (and, for
/// the variable-length delegate, its locality byte) to know the exact length.
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const MESH_STREAM_MAX: usize = 2048;

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
static mut MESH_STREAM: [u8; MESH_STREAM_MAX] = [0; MESH_STREAM_MAX];

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
static mut MESH_STREAM_LEN: usize = 0;

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
pub fn poll_mesh(socket: u16) -> MeshEvent {
    unsafe {
        let stream = &mut *core::ptr::addr_of_mut!(MESH_STREAM);
        let len = &mut *core::ptr::addr_of_mut!(MESH_STREAM_LEN);

        // Append whatever the socket has buffered onto the stream.
        if *len < MESH_STREAM_MAX {
            let mut tmp = [0u8; MESH_STREAM_MAX];
            let got = crate::netif::NetIf::with(|net| net.socket_recv(socket, &mut tmp));
            if let Some(got) = got {
                if got > 0 {
                    let room = MESH_STREAM_MAX - *len;
                    let n = got.min(room);
                    stream[*len..*len + n].copy_from_slice(&tmp[..n]);
                    *len += n;
                }
            }
        }

        // Parse the first complete message, if any.
        let buf = &stream[..*len];
        if buf.is_empty() {
            return MeshEvent::None;
        }
        let Some(n) = msg_len(buf) else {
            // Unknown leading code or truncated header — consume one byte and
            // resynchronize rather than dying or spinning.
            stream.copy_within(1..*len, 0);
            *len -= 1;
            return MeshEvent::Malformed;
        };
        if *len < n {
            // Incomplete message — wait for the rest of the datagram.
            return MeshEvent::None;
        }
        let ev = parse_mesh_msg(&stream[..n]);
        stream.copy_within(n..*len, 0);
        *len -= n;
        ev
    }
}

/// Length in bytes of the message whose code is `buf[0]`, or `None` when the
/// code is unknown / the buffer is too short to contain the header the length
/// depends on (the delegate's locality byte at envelope offset 64).
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
fn msg_len(buf: &[u8]) -> Option<usize> {
    match buf[0] {
        MSG_HEARTBEAT => Some(1),
        MSG_PROPOSE if buf.len() >= 41 => Some(41),
        MSG_PROPOSE_ACK if buf.len() >= 41 => Some(41),
        MSG_DELEGATE if buf.len() >= 66 => {
            // envelope starts at buf[1]; locality byte is envelope[64] = buf[65].
            // ENVELOPE_MAX = 32+32+1+32+TOKEN_FIXED_LEN, so a Remote-locality
            // envelope is ENVELOPE_MAX bytes and a Local one is ENVELOPE_MAX-32.
            let ser = if buf[65] == 0 {
                ENVELOPE_MAX - 32
            } else {
                ENVELOPE_MAX
            };
            Some(1 + ser)
        }
        MSG_INVOKE if buf.len() >= 1 + ENVELOPE_MAX + 1 + 8 => Some(1 + ENVELOPE_MAX + 1 + 8),
        MSG_RESULT if buf.len() >= 1 + ENVELOPE_MAX + 8 => Some(1 + ENVELOPE_MAX + 8),
        MSG_DENIED if buf.len() >= 2 => Some(2),
        _ => None,
    }
}

/// Classify one complete message (no coalescing involved).
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
fn parse_mesh_msg(buf: &[u8]) -> MeshEvent {
    let n = buf.len();
    match buf[0] {
        MSG_HEARTBEAT => MeshEvent::Heartbeat,
        MSG_PROPOSE if n >= 1 + 32 + 8 => MeshEvent::Propose {
            node: NodeId(buf[1..33].try_into().unwrap()),
            epoch: u64::from_le_bytes(buf[33..41].try_into().unwrap()),
        },
        MSG_PROPOSE_ACK if n >= 1 + 8 + 32 => MeshEvent::ProposeAck {
            epoch: u64::from_le_bytes(buf[1..9].try_into().unwrap()),
            leader: NodeId(buf[9..41].try_into().unwrap()),
        },
        MSG_DELEGATE => match deserialize(&buf[1..n]) {
            Ok(cap) => MeshEvent::Delegate(cap),
            Err(_) => MeshEvent::Malformed,
        },
        MSG_INVOKE if n >= 1 + ENVELOPE_MAX + 1 + 8 => {
            match deserialize(&buf[1..1 + ENVELOPE_MAX]) {
                Ok(token) => MeshEvent::Invoke {
                    token,
                    op: buf[1 + ENVELOPE_MAX],
                    operand: u64::from_le_bytes(
                        buf[1 + ENVELOPE_MAX + 1..1 + ENVELOPE_MAX + 9]
                            .try_into()
                            .unwrap(),
                    ),
                },
                Err(_) => MeshEvent::Malformed,
            }
        }
        MSG_RESULT if n >= 1 + ENVELOPE_MAX + 8 => match deserialize(&buf[1..1 + ENVELOPE_MAX]) {
            Ok(token) => MeshEvent::Result {
                token,
                value: u64::from_le_bytes(
                    buf[1 + ENVELOPE_MAX..1 + ENVELOPE_MAX + 8]
                        .try_into()
                        .unwrap(),
                ),
            },
            Err(_) => MeshEvent::Malformed,
        },
        MSG_DENIED if n >= 2 => MeshEvent::Denied { reason: buf[1] },
        _ => MeshEvent::Malformed,
    }
}

// ---- Consensus state machine (node-local) ----------------------------------

/// A node's view of the two-node consensus.
pub struct Consensus {
    epoch: u64,
    leader: NodeId,
    converged: bool,
    sole_survivor: bool,
}

impl Consensus {
    pub const fn new(my_id: NodeId) -> Consensus {
        Consensus {
            epoch: 1,
            leader: my_id,
            converged: false,
            sole_survivor: false,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn leader(&self) -> NodeId {
        self.leader
    }

    pub fn converged(&self) -> bool {
        self.converged
    }

    pub fn is_sole_survivor(&self) -> bool {
        self.sole_survivor
    }

    /// Handle our own proposal being sent after a (re)contact. If we already
    /// believed we were the sole survivor, we keep the bumped epoch.
    pub fn propose_epoch(&self) -> u64 {
        self.epoch
    }

    /// The peer is gone (stale/unreachable): we are the only live node. Bump
    /// our epoch so a later re-election prefers us only if that is
    /// deterministic; either way the function `elect` decides.
    pub fn mark_partition(&mut self) {
        self.converged = false;
        if !self.sole_survivor {
            self.epoch = self.epoch.saturating_add(1);
        }
        self.sole_survivor = true;
        // We hold authority while alone; the leader stays as-is.
    }

    /// The peer came back: we are no longer sole survivor; re-election is
    /// needed and `elect` decides the leader deterministically.
    pub fn mark_reunited(&mut self) {
        self.sole_survivor = false;
        self.converged = false;
    }

    /// Apply a received proposal. Returns the `(epoch, leader)` we now hold
    /// after running the deterministic election, plus whether this proposal
    /// changed anything (a re-election happened).
    pub fn on_proposal(
        &mut self,
        my_id: NodeId,
        peer: NodeId,
        peer_epoch: u64,
    ) -> (u64, NodeId, bool) {
        let (new_epoch, new_leader) = elect(my_id, self.epoch, peer, peer_epoch);
        let changed = new_epoch != self.epoch || new_leader != self.leader;
        self.epoch = new_epoch;
        self.leader = new_leader;
        self.sole_survivor = false;
        self.converged = false;
        (new_epoch, new_leader, changed)
    }

    /// A proposal ACK arrived. If it matches what we hold, both sides have
    /// converged on the same deterministic answer.
    pub fn on_ack(&mut self, epoch: u64, leader: NodeId) -> bool {
        if epoch == self.epoch && leader == self.leader {
            self.converged = true;
            true
        } else {
            false
        }
    }
}

// ---- Boot demo --------------------------------------------------------------
//
// Gated by `fleet-j3` combined with `fleet-node-a` / `fleet-node-b`
// (mutually exclusive roles). `main.rs` calls `mesh::run_boot_demo()` instead
// of `fleet::run_boot_demo()` when `fleet-j3` is present. Demo-only key note:
// the shared HMAC key is the same fixed constant Phase I's demo uses — real
// key provisioning is a separate, unscoped bootstrapping problem.

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const DEMO_SHARED_KEY: [u8; 32] = *b"aegis-phase-i-demo-shared-key!!Z";
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const NODE_A_ID: NodeId = NodeId([0xA1; 32]);
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const NODE_B_ID: NodeId = NodeId([0xB2; 32]);

/// Node A's static IP for the private mesh link (same private LAN as the
/// Phase I demo — see `netif.rs`'s `OUR_IP` feature-gate patch).
#[cfg(feature = "fleet-node-a")]
const PEER_IP: [u8; 4] = [10, 0, 3, 2]; // node B
#[cfg(feature = "fleet-node-b")]
const PEER_IP: [u8; 4] = [10, 0, 3, 1]; // node A

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const DEMO_MAX_POLLS: u64 = 500_000_000;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const HEARTBEAT_EVERY: u64 = 2_000;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const STALE_AFTER_TICKS: u64 = 10_000;
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const ELECT_EVERY: u64 = 5_000;
#[cfg(feature = "fleet-node-b")]
const INVOKE_EVERY: u64 = 20_000;

/// Common one-loop body both nodes run: advance the fleet clock, poll the
/// NIC, drain the mesh link, run the consensus state machine, and react to
/// delegation/invocation events. Returns the received delegation capability
/// the invoker needs (node B only).
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
fn run_mesh(
    my_id: NodeId,
    peer_id: NodeId,
    sock: u16,
    fleet: &mut Fleet,
    consensus: &mut Consensus,
    #[cfg_attr(feature = "fleet-node-b", allow(unused_variables))] pending_delegate: Option<
        RemoteCapability,
    >,
) {
    // B records the verified delegation it received (node A, the issuer,
    // never receives one in this demo).
    #[cfg(feature = "fleet-node-b")]
    let mut received_delegation: Option<RemoteCapability> = None;
    let mut counter: u64 = 0;
    let mut i: u64 = 0;
    let mut was_reachable = true;
    // True once the delegation has actually been handed to the peer. The
    // issuer grants the authority to execute invocations only after this.
    #[cfg_attr(feature = "fleet-node-b", allow(unused_mut))]
    let mut delegated_to_peer = false;

    while i < DEMO_MAX_POLLS {
        unsafe { crate::netif::NetIf::with(|net| net.poll()) };
        fleet.advance_time(i);

        let reachable = fleet.peer_reachable(peer_id);
        if reachable != was_reachable {
            if reachable {
                consensus.mark_reunited();
                crate::sprintln!(
                    "Aegis: mesh: peer {:?} reachable again — re-electing",
                    peer_id
                );
            } else {
                consensus.mark_partition();
                crate::sprintln!(
                    "Aegis: mesh: PARTITION — peer {:?} stale, I am sole survivor (epoch {})",
                    peer_id,
                    consensus.epoch()
                );
            }
            was_reachable = reachable;
        }

        if i % HEARTBEAT_EVERY == 0 {
            send_heartbeat(sock);
        }
        if i % ELECT_EVERY == 0 && (!consensus.converged() || !reachable) {
            send_propose(sock, my_id, consensus.propose_epoch());
        }

        // Node A hands the delegated capability to B exactly once, and only
        // after both sides have converged on a leader and the peer is
        // reachable (so B's verify has a live HMAC peer, not PeerStale).
        #[cfg(feature = "fleet-node-a")]
        if !delegated_to_peer && consensus.converged() && reachable {
            if let Some(cap) = &pending_delegate {
                let sent = send_delegate(sock, cap);
                crate::sprintln!(
                    "Aegis: mesh: delegated object {} (Endpoint, RS) to node B: sent={}",
                    OBJ_COUNTER,
                    sent
                );
                if sent {
                    delegated_to_peer = true;
                }
            }
        }

        match poll_mesh(sock) {
            MeshEvent::Heartbeat => {
                let _ = fleet.heartbeat(peer_id);
            }
            MeshEvent::Propose { node, epoch } => {
                let (ne, nl, changed) = consensus.on_proposal(my_id, node, epoch);
                if changed {
                    crate::sprintln!(
                        "Aegis: mesh: proposal {} epoch={} -> adopt epoch={} leader={:?}",
                        node_id_tag(node),
                        epoch,
                        ne,
                        nl
                    );
                }
                let _ = send_propose_ack(sock, ne, nl);
            }
            MeshEvent::ProposeAck { epoch, leader } => {
                if consensus.on_ack(epoch, leader) {
                    crate::sprintln!(
                        "Aegis: mesh: CONSENSUS REACHED — epoch={} leader={:?}",
                        epoch,
                        leader
                    );
                }
            }            MeshEvent::Delegate(cap) => {
                match fleet.verify(&cap) {
                    Ok(()) => {
                        crate::sprintln!(
                            "Aegis: mesh: delegation verified — object {} kind {:?} rights {:#04b} from node A, recipient-bound to us",
                            cap.chain.token.object_id,
                            cap.chain.token.kind,
                            cap.chain.token.rights
                        );
                        #[cfg(feature = "fleet-node-b")]
                        {
                            received_delegation = Some(cap);
                        }
                    }
                    Err(e) => crate::sprintln!(
                        "Aegis: mesh: delegation DENIED (fail-closed): {:?}",
                        e
                    ),
                }
            }
            MeshEvent::Invoke { token, op, operand } => {
                let ok = fleet.verify(&token).is_ok();
                let object_ok = token.chain.token.object_id == OBJ_COUNTER;
                let auth_ok = delegated_to_peer;
                if !ok {
                    crate::sprintln!(
                        "Aegis: mesh: invoke DENIED (fail-closed): {:?}",
                        fleet.verify(&token).err().unwrap()
                    );
                    let _ = send_denied(sock, DENIED_NOTAUTH);
                } else if !auth_ok {
                    crate::sprintln!(
                        "Aegis: mesh: invoke DENIED — object {} was never delegated to this node",
                        token.chain.token.object_id
                    );
                    let _ = send_denied(sock, DENIED_NOTDELEGATED);
                } else if !object_ok {
                    crate::sprintln!(
                        "Aegis: mesh: invoke DENIED — token names object {} not {}",
                        token.chain.token.object_id,
                        OBJ_COUNTER
                    );
                    let _ = send_denied(sock, DENIED_NOTDELEGATED);
                } else if op != OP_INCR {
                    crate::sprintln!("Aegis: mesh: invoke DENIED — op {} not permitted", op);
                    let _ = send_denied(sock, DENIED_BADOP);
                } else {
                    counter = counter.wrapping_add(operand);
                    crate::sprintln!(
                        "Aegis: mesh: invoke EXECUTED — object {} op INCR += {} -> counter={}",
                        OBJ_COUNTER,
                        operand,
                        counter
                    );
                    let chain = fleet.issue(
                        OBJ_COUNTER,
                        TokenObjectKind::Endpoint,
                        Rights::READ,
                        None,
                    );
                    match fleet.send_to(chain, peer_id) {
                        Ok(result) => {
                            let _ = send_result(sock, &result, counter);
                        }
                        Err(e) => crate::sprintln!(
                            "Aegis: mesh: could not mint result token: {:?}",
                            e
                        ),
                    }
                }
            }
            MeshEvent::Result { token, value } => {
                match fleet.verify(&token) {
                    Ok(()) => crate::sprintln!(
                        "Aegis: mesh: result verified — object {} value={} (remote invocation round-trip OK)",
                        token.chain.token.object_id,
                        value
                    ),
                    Err(e) => crate::sprintln!(
                        "Aegis: mesh: result DENIED (fail-closed): {:?}",
                        e
                    ),
                }
            }
            MeshEvent::Denied { reason } => {
                crate::sprintln!(
                    "Aegis: mesh: invocation DENIED by peer (reason {:#04b})",
                    reason
                );
            }
            MeshEvent::Malformed => {
                crate::sprintln!("Aegis: mesh: malformed datagram on mesh link (ignored)");
            }
            MeshEvent::None => {}
        }

        // Node B: once we hold a verified delegation and the issuer is
        // reachable, periodically invoke the remote counter.
        #[cfg(feature = "fleet-node-b")]
        if i % INVOKE_EVERY == 0 && received_delegation.is_some() {
            if fleet.peer_reachable(peer_id) {
                let chain = fleet.issue(
                    OBJ_COUNTER,
                    TokenObjectKind::Endpoint,
                    Rights::READ.union(Rights::SEND),
                    None,
                );
                match fleet.send_to(chain, peer_id) {
                    Ok(token) => {
                        let sent = send_invoke(sock, &token, OP_INCR, 1);
                        crate::sprintln!(
                            "Aegis: mesh: invoke sent (object {}, INCR 1, sent={})",
                            OBJ_COUNTER,
                            sent
                        );
                    }
                    Err(e) => {
                        crate::sprintln!("Aegis: mesh: could not mint invocation token: {:?}", e)
                    }
                }
            } else {
                crate::sprintln!(
                    "Aegis: mesh: invoke withheld — issuer {:?} unreachable (fail-closed)",
                    peer_id
                );
            }
        }

        i += 1;
        core::hint::spin_loop();
    }
}

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
fn node_id_tag(id: NodeId) -> &'static str {
    if id.0[0] == 0xA1 {
        "A"
    } else if id.0[0] == 0xB2 {
        "B"
    } else {
        "?"
    }
}

/// Node A (the service / issuer) entry point.
#[cfg(feature = "fleet-node-a")]
pub fn run_boot_demo() {
    crate::sprintln!(
        "Aegis: mesh: node A (service/issuer) starting — J-3 consensus + remote invocation"
    );
    let mut fleet = Fleet::new(NODE_A_ID, DEMO_SHARED_KEY);
    fleet.set_stale_after(STALE_AFTER_TICKS);
    if fleet.register_peer(NODE_B_ID, DEMO_SHARED_KEY).is_err() {
        crate::sprintln!("Aegis: mesh: register_peer failed — aborting demo");
        return;
    }
    let peer_ip = PEER_IP;
    let Some(sock) = open_mesh_link(peer_ip) else {
        crate::sprintln!("Aegis: mesh: could not open mesh link — aborting demo");
        return;
    };
    crate::sprintln!(
        "Aegis: mesh: mesh link to node B at {:?}:{} opened (socket {})",
        peer_ip,
        MESH_PORT,
        sock
    );

    // Mint the object and delegate it to B exactly once — but only *send* it
    // after consensus has converged and B is reachable (done in run_mesh).
    let chain = fleet.issue(
        OBJ_COUNTER,
        TokenObjectKind::Endpoint,
        Rights::READ.union(Rights::SEND),
        None,
    );
    let pending_delegate = match fleet.send_to(chain, NODE_B_ID) {
        Ok(cap) => Some(cap),
        Err(e) => {
            crate::sprintln!("Aegis: mesh: delegate bind failed: {:?}", e);
            None
        }
    };

    let mut consensus = Consensus::new(NODE_A_ID);
    run_mesh(
        NODE_A_ID,
        NODE_B_ID,
        sock,
        &mut fleet,
        &mut consensus,
        pending_delegate,
    );
    close_mesh_link(sock);
    crate::sprintln!("Aegis: mesh: node A demo loop finished");
}

/// Node B (the invoker / holder) entry point.
#[cfg(feature = "fleet-node-b")]
pub fn run_boot_demo() {
    crate::sprintln!(
        "Aegis: mesh: node B (invoker/holder) starting — J-3 consensus + remote invocation"
    );
    let mut fleet = Fleet::new(NODE_B_ID, DEMO_SHARED_KEY);
    fleet.set_stale_after(STALE_AFTER_TICKS);
    if fleet.register_peer(NODE_A_ID, DEMO_SHARED_KEY).is_err() {
        crate::sprintln!("Aegis: mesh: register_peer failed — aborting demo");
        return;
    }
    let peer_ip = PEER_IP;
    let Some(sock) = open_mesh_link(peer_ip) else {
        crate::sprintln!("Aegis: mesh: could not open mesh link — aborting demo");
        return;
    };
    crate::sprintln!(
        "Aegis: mesh: mesh link to node A at {:?}:{} opened (socket {})",
        peer_ip,
        MESH_PORT,
        sock
    );

    let mut consensus = Consensus::new(NODE_B_ID);
    run_mesh(
        NODE_B_ID,
        NODE_A_ID,
        sock,
        &mut fleet,
        &mut consensus,
        None, // B did not delegate; it holds the delegation
    );
    close_mesh_link(sock);
    crate::sprintln!("Aegis: mesh: node B demo loop finished");
}

// ---- Tests (pure protocol logic — no netif/NIC required) ------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn node_a() -> NodeId {
        NodeId([0xA1; 32])
    }
    fn node_b() -> NodeId {
        NodeId([0xB2; 32])
    }

    #[test]
    fn elect_higher_epoch_wins_either_side() {
        // A has epoch 2, B has epoch 1 → A wins, seen from both sides.
        let (a, b) = (node_a(), node_b());
        assert_eq!(elect(a, 2, b, 1), (2, a));
        assert_eq!(elect(b, 1, a, 2), (2, a)); // symmetric
    }

    #[test]
    fn elect_equal_epoch_ties_break_by_smaller_node_id() {
        let (a, b) = (node_a(), node_b());
        // A (0xA1…) < B (0xB2…), equal epoch → A wins on both sides.
        assert_eq!(elect(a, 1, b, 1), (1, a));
        assert_eq!(elect(b, 1, a, 1), (1, a));
    }

    #[test]
    fn elect_is_total_and_deterministic() {
        let ids = [node_a(), node_b()];
        for &my in &ids {
            for &peer in &ids {
                for my_epoch in 0..4u64 {
                    for peer_epoch in 0..4u64 {
                        let (epoch, leader) = elect(my, my_epoch, peer, peer_epoch);
                        assert!(epoch == my_epoch.max(peer_epoch));
                        assert!(leader == my || leader == peer);
                        // The reverse call must produce the same winner.
                        let (e2, l2) = elect(peer, peer_epoch, my, my_epoch);
                        assert_eq!((epoch, leader), (e2, l2));
                    }
                }
            }
        }
    }

    #[test]
    fn consensus_partition_bumps_epoch_and_reunite_reelects() {
        let a = node_a();
        let b = node_b();
        let mut c = Consensus::new(b);

        // Fresh contact: both propose epoch 1 → A wins (smaller id), B converges.
        let (_, _, _) = c.on_proposal(b, a, 1);
        assert_eq!((c.epoch(), c.leader()), (1, a));
        assert!(c.on_ack(1, a));

        // Partition: B is sole survivor → epoch bumps to 2.
        c.mark_partition();
        assert_eq!(c.epoch(), 2);
        assert!(c.is_sole_survivor());

        // Reunion: peer A returns with epoch 1 → B's bumped epoch wins.
        c.mark_reunited();
        let (ne, nl, changed) = c.on_proposal(b, a, 1);
        assert_eq!((ne, nl), (2, b));
        assert!(changed);
        assert!(c.on_ack(2, b));

        // And A's side computes the same: A sees B's epoch 2, loses.
        let mut ca = Consensus::new(a);
        let (na, nla, _) = ca.on_proposal(a, b, 2);
        assert_eq!((na, nla), (2, b));
    }

    #[test]
    fn sole_survivor_does_not_bump_twice_on_repeated_partition_signals() {
        let b = node_b();
        let mut c = Consensus::new(b);
        c.mark_partition();
        c.mark_partition();
        assert_eq!(c.epoch(), 2); // bumped once
    }
}
