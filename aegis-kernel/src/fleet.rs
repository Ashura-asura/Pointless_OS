//! Fleet — cross-machine capability transport (Phase 11 / roadmap Phase I).
//!
//! Design doc §7 Phase 11, master roadmap Phase I: a capability minted on one
//! kernel instance, sent to a second real kernel instance over the real
//! network stack, verified there with cryptographic recipient binding, and
//! denied by default (fail-closed) when the issuing node goes stale or
//! partitioned. This is a from-scratch kernel port of `aegis/crates/fleet`
//! and `aegis/crates/macaroon` (the model crates), narrowed to what a
//! no-heap, `no_std` kernel can carry natively — see "Honest scope notes"
//! below for exactly what was narrowed and why. It is NOT a rewrite of the
//! model's algorithm: `compute_root`/`compute_bound` below produce the same
//! HMAC-chain construction as `macaroon::mint`/`macaroon::bind_caveat`, just
//! against fixed-width buffers instead of `Vec`.
//!
//! ## Honest scope notes (Ground Rule 6 — say which, every time)
//!
//! 1. **Transport is UDP, not TCP.** The master roadmap's Phase I text says
//!    "over a real TCP connection." This kernel's TCP
//!    (`netif.rs`, module docs) is documented as **client-side only — no
//!    passive-open / listen path**. Two peer kernels are symmetric (either
//!    may be the one to (re)connect first), so a TCP rendezvous would need a
//!    real `listen`/`accept` implementation, which does not exist and is a
//!    separate, unscoped undertaking (it is not in this kernel's client-only
//!    TCP today, and building it is not what Phase I is about). UDP is
//!    real, already verified in Phase E (`netif::SockKind::Udp`,
//!    `udp_send_recv_roundtrip` in `netif.rs`), connectionless, and
//!    symmetric — either node can send first. The envelope carries its own
//!    integrity check (the HMAC chain below), so this substitution does not
//!    weaken what is actually being proven (authenticated, recipient-bound,
//!    fail-closed capability transfer); it only swaps which already-real
//!    Phase E primitive carries the bytes. Named here explicitly, not left
//!    implicit — this is a **reduced** substitution of transport, not a
//!    **closed** claim of "TCP" that isn't true.
//!
//! 2. **General caveats are not ported.** The model crate's `Caveat` is a
//!    `Vec`-backed list (`RightsNarrow` / `ExpiryClamp` / `Custom`) so it can
//!    grow attenuation chains of arbitrary length. Phase I only needs ONE
//!    caveat — the HMAC-bound recipient — so this port carries exactly that
//!    one optional caveat as a fixed field (`CapabilityToken::recipient`)
//!    instead of a general list. This keeps the whole module allocation-free
//!    (this kernel has zero `alloc`/`Vec` usage anywhere — see `lib.rs`),
//!    at the cost of not supporting `narrow()`-style re-attenuation in the
//!    kernel yet. The model crate remains the place general attenuation is
//!    proven; if a later phase needs it in the kernel, that is new scope,
//!    named as such then, not silently assumed here.
//!
//! 3. **Remote *use* of a transferred capability is out of scope, and stays
//!    out of scope.** Per §10, distributed transparency cannot be solved,
//!    only made fail-safe under partition. What this phase proves is that
//!    node B can cryptographically verify a capability really came from node
//!    A, is really meant for B, and is really still valid (issuer reachable,
//!    not stale) — not that B can then invoke the object the capability
//!    names on A's kernel. There is no remote-invocation channel here and
//!    building one is a materially different, larger problem than capability
//!    *transport*. The boot demo below proves transport + verification only,
//!    and says so in its own output.
//!
//! ## What's real here
//!
//! - `Fleet`: node identity, per-peer trust registration (symmetric HMAC
//!   key), reachability/staleness tracking, `issue`/`send_to`/`hold_local`/
//!   `verify` — same shape and same fail-closed semantics as
//!   `aegis/crates/fleet::Fleet`, checked line-by-line against that crate
//!   while porting.
//! - `open_link` / `send_capability` / `send_heartbeat` / `poll_link`: a real
//!   UDP-backed transport built directly on `netif::NetIf::with` (the same
//!   entry point `netif`'s own internal helpers use), not a simulation.
//! - `run_boot_demo`: a real two-node boot-time demo, gated by the
//!   `fleet-node-a` / `fleet-node-b` Cargo features (see
//!   `PHASE_I_INTEGRATION.md`), that performs one real mint, one real
//!   cross-machine send, one real verify, and demonstrates fail-closed
//!   behavior for real — by going stale for real when node A's process is
//!   actually killed, not by a simulated flag.

use crate::cap::{Cap, Rights};

// ---- Identity, locality, errors -------------------------------------------

/// A node in the fleet: 32 bytes of identity (kernel-instance id). Mirrors
/// `aegis::fleet::NodeId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub const fn zero() -> NodeId {
        NodeId([0u8; 32])
    }
}

/// Explicit locality of a held capability — never hidden from the holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locality {
    Local,
    Remote(NodeId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FleetError {
    UnknownIssuer,
    UntrustedPeer,
    RegistryFull,
    AlreadyRegistered,
    ChainIntegrity,
    Expired,
    BadEnvelope,
    NotRecipient,
    /// The issuing peer is explicitly marked unreachable (simulated or real
    /// partition) — capabilities from it are denied by default.
    PeerUnreachable,
    /// The issuing peer's last heartbeat is older than the staleness window
    /// — capabilities from it are denied by default.
    PeerStale,
    UnknownPeer,
    /// Transport-level: the socket table is full or the UDP send failed.
    LinkUnavailable,
}

// ---- Object kind (maps the kernel's own `Cap` enum onto the wire) ---------

/// The kernel object kinds a Phase I token can name. Mirrors the subset of
/// `crate::cap::Cap` that it is *meaningful* to mint a cross-machine
/// reference to. `Cap::None` and `Cap::NetRoot` are deliberately excluded:
/// `None` names nothing, and `NetRoot` is the kernel/boot-time-only "may
/// open sockets at all" authority (see `cap.rs`'s own doc comment on
/// `Cap::NetRoot`) — it is exactly the kind of ambient-authority-by-another-
/// name that must never be mintable as a token, cross-machine or otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenObjectKind {
    Endpoint,
    Task,
    MemRegion,
    Channel,
    NetEndpoint,
}

impl TokenObjectKind {
    const fn tag(self) -> u8 {
        match self {
            TokenObjectKind::Endpoint => 0,
            TokenObjectKind::Task => 1,
            TokenObjectKind::MemRegion => 2,
            TokenObjectKind::Channel => 3,
            TokenObjectKind::NetEndpoint => 4,
        }
    }

    const fn from_tag(t: u8) -> Option<TokenObjectKind> {
        match t {
            0 => Some(TokenObjectKind::Endpoint),
            1 => Some(TokenObjectKind::Task),
            2 => Some(TokenObjectKind::MemRegion),
            3 => Some(TokenObjectKind::Channel),
            4 => Some(TokenObjectKind::NetEndpoint),
            _ => None,
        }
    }
}

/// Decompose a local `Cap` into the `(kind, object_id)` pair a token names,
/// or `None` for `Cap::None`/`Cap::NetRoot` (see `TokenObjectKind` doc).
pub fn kind_and_id(cap: Cap) -> Option<(TokenObjectKind, u32)> {
    match cap {
        Cap::None | Cap::NetRoot => None,
        Cap::Endpoint(id) => Some((TokenObjectKind::Endpoint, id)),
        Cap::Task(id) => Some((TokenObjectKind::Task, id)),
        Cap::MemRegion(id) => Some((TokenObjectKind::MemRegion, id)),
        Cap::Channel(id) => Some((TokenObjectKind::Channel, id)),
        Cap::NetEndpoint(id) => Some((TokenObjectKind::NetEndpoint, id)),
    }
}

// ---- HMAC-chain token (fixed-width port of `macaroon`) --------------------

const HMAC_BLOCK: usize = 64;
/// ipad/msg or opad/hash scratch never exceeds this; both call sites below
/// are well under it (largest is ipad(64) + identifier(51) = 115).
const HMAC_SCRATCH_MAX: usize = 160;

/// HMAC-SHA256 using the kernel's existing `sha256` (see `store.rs`). The
/// model crate's `hmac_sha256` handles arbitrary-length keys (hashing down
/// oversized ones); this port's key is always exactly 32 bytes (the fleet
/// signing key), so that branch is dropped — always fits in one block,
/// zero-padded.
fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut kp = [0u8; HMAC_BLOCK];
    kp[..32].copy_from_slice(key);
    let mut ipad = [0u8; HMAC_BLOCK];
    let mut opad = [0u8; HMAC_BLOCK];
    for i in 0..HMAC_BLOCK {
        ipad[i] = 0x36 ^ kp[i];
        opad[i] = 0x5c ^ kp[i];
    }
    debug_assert!(
        msg.len() <= HMAC_SCRATCH_MAX - HMAC_BLOCK,
        "fleet: hmac message exceeds fixed scratch bound"
    );
    let mut inner = [0u8; HMAC_SCRATCH_MAX];
    inner[..HMAC_BLOCK].copy_from_slice(&ipad);
    let n = msg.len().min(HMAC_SCRATCH_MAX - HMAC_BLOCK);
    inner[HMAC_BLOCK..HMAC_BLOCK + n].copy_from_slice(&msg[..n]);
    let ih = crate::store::sha256(&inner[..HMAC_BLOCK + n]);
    let mut outer = [0u8; HMAC_BLOCK + 32];
    outer[..HMAC_BLOCK].copy_from_slice(&opad);
    outer[HMAC_BLOCK..].copy_from_slice(&ih);
    crate::store::sha256(&outer)
}

/// Constant-time 32-byte compare (no `subtle` dependency in this kernel —
/// `Cargo.toml`'s `[dependencies]` is intentionally empty).
fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// The token identity: everything except the recipient caveat and the HMAC
/// chain itself. Mirrors `macaroon::CapabilityToken` minus the general
/// caveat list (see module doc, scope note 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityToken {
    pub kernel_id: [u8; 32],
    pub object_id: u64,
    pub kind: TokenObjectKind,
    pub rights: u8,
    pub expiry: Option<u64>,
    /// The one caveat this port carries: the intended recipient, HMAC-bound
    /// at send time. `None` for a locally-issued, never-sent token.
    pub recipient: Option<NodeId>,
}

const TOKEN_ID_MAX: usize = 32 + 8 + 1 + 1 + 1 + 8; // kernel_id, object_id, kind, rights, expiry flag+value

fn serialize_identifier(token: &CapabilityToken) -> ([u8; TOKEN_ID_MAX], usize) {
    let mut out = [0u8; TOKEN_ID_MAX];
    let mut pos = 0;
    out[pos..pos + 32].copy_from_slice(&token.kernel_id);
    pos += 32;
    out[pos..pos + 8].copy_from_slice(&token.object_id.to_le_bytes());
    pos += 8;
    out[pos] = token.kind.tag();
    pos += 1;
    out[pos] = token.rights;
    pos += 1;
    match token.expiry {
        Some(e) => {
            out[pos] = 1;
            pos += 1;
            out[pos..pos + 8].copy_from_slice(&e.to_le_bytes());
            pos += 8;
        }
        None => {
            out[pos] = 0;
            pos += 1;
            pos += 8;
        }
    }
    (out, pos)
}

const RECIPIENT_CAVEAT_LEN: usize = 1 + 32; // tag(0xC0) + node id

fn recipient_caveat_bytes(node: NodeId) -> [u8; RECIPIENT_CAVEAT_LEN] {
    let mut out = [0u8; RECIPIENT_CAVEAT_LEN];
    out[0] = 0xC0; // "recipient caveat" tag, distinct from macaroon crate's Custom(0x02) framing
    out[1..].copy_from_slice(&node.0);
    out
}

/// The HMAC chain over a token: a root hash, and (iff the token carries a
/// recipient caveat) one more hash binding that recipient in. Mirrors
/// `macaroon::compute_chain`, narrowed to at most two entries (see module
/// doc, scope note 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenChain {
    pub token: CapabilityToken,
    root: [u8; 32],
    bound: Option<[u8; 32]>,
}

fn compute_root(signing_key: &[u8; 32], token: &CapabilityToken) -> [u8; 32] {
    let (buf, n) = serialize_identifier(token);
    hmac_sha256(signing_key, &buf[..n])
}

fn compute_bound(signing_key: &[u8; 32], root: [u8; 32], recipient: NodeId) -> [u8; 32] {
    let caveat = recipient_caveat_bytes(recipient);
    let mut msg = [0u8; RECIPIENT_CAVEAT_LEN + 32];
    msg[..RECIPIENT_CAVEAT_LEN].copy_from_slice(&caveat);
    msg[RECIPIENT_CAVEAT_LEN..].copy_from_slice(&root);
    hmac_sha256(signing_key, &msg)
}

/// Mint a fresh, locally-issued token chain (no recipient bound yet).
/// Mirrors `macaroon::mint`.
fn mint(
    signing_key: &[u8; 32],
    kernel_id: [u8; 32],
    object_id: u64,
    kind: TokenObjectKind,
    rights: u8,
    expiry: Option<u64>,
) -> TokenChain {
    let token = CapabilityToken {
        kernel_id,
        object_id,
        kind,
        rights,
        expiry,
        recipient: None,
    };
    let root = compute_root(signing_key, &token);
    TokenChain {
        token,
        root,
        bound: None,
    }
}

/// Bind a recipient into the chain (re-signs with the issuer's key — this
/// port, like the model crate, only ever does this at the issuing node,
/// which is the only place the signing key lives). Mirrors
/// `macaroon::bind_caveat` specialised to the recipient caveat.
fn bind_recipient(signing_key: &[u8; 32], chain: &TokenChain, recipient: NodeId) -> TokenChain {
    let mut token = chain.token;
    token.recipient = Some(recipient);
    let bound = compute_bound(signing_key, chain.root, recipient);
    TokenChain {
        token,
        root: chain.root,
        bound: Some(bound),
    }
}

/// Verify chain integrity under `signing_key`: the root must match, and if
/// the token claims a recipient, the bound hash must match too. Mirrors
/// `macaroon::verify`.
fn verify_chain(signing_key: &[u8; 32], chain: &TokenChain) -> Result<(), FleetError> {
    let expected_root = compute_root(signing_key, &chain.token);
    if !ct_eq32(&expected_root, &chain.root) {
        return Err(FleetError::ChainIntegrity);
    }
    match (chain.token.recipient, chain.bound) {
        (None, None) => Ok(()),
        (Some(r), Some(b)) => {
            let expected_bound = compute_bound(signing_key, chain.root, r);
            if ct_eq32(&expected_bound, &b) {
                Ok(())
            } else {
                Err(FleetError::ChainIntegrity)
            }
        }
        // A chain claiming a recipient with no bound hash (or vice versa) is
        // malformed / tampered — never treat it as valid.
        _ => Err(FleetError::ChainIntegrity),
    }
}

// ---- Transport envelope ----------------------------------------------------

/// A capability with its transport envelope. Mirrors
/// `aegis::fleet::RemoteCapability`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoteCapability {
    pub chain: TokenChain,
    pub issuer: NodeId,
    pub recipient: NodeId,
    pub locality: Locality,
}

// Fixed-width wire format (no length prefixes needed: every field is
// constant-width because the caveat list was narrowed to exactly one
// optional entry — see module doc, scope note 2).
const TOKEN_FIXED_LEN: usize = 32 + 8 + 1 + 1 + (1 + 8) + (1 + 32) + 32 + (1 + 32);
// kernel_id(32) object_id(8) kind(1) rights(1) expiry(1+8) recipient(1+32) root(32) bound(1+32) = 149
pub const ENVELOPE_MAX: usize = 32 + 32 + 1 + 32 + TOKEN_FIXED_LEN; // issuer+recipient+locality+[remote_id]+token = 246

fn serialize_token_chain(chain: &TokenChain, out: &mut [u8]) -> usize {
    let mut pos = 0;
    out[pos..pos + 32].copy_from_slice(&chain.token.kernel_id);
    pos += 32;
    out[pos..pos + 8].copy_from_slice(&chain.token.object_id.to_le_bytes());
    pos += 8;
    out[pos] = chain.token.kind.tag();
    pos += 1;
    out[pos] = chain.token.rights;
    pos += 1;
    match chain.token.expiry {
        Some(e) => {
            out[pos] = 1;
            pos += 1;
            out[pos..pos + 8].copy_from_slice(&e.to_le_bytes());
            pos += 8;
        }
        None => {
            out[pos] = 0;
            pos += 1;
            out[pos..pos + 8].fill(0);
            pos += 8;
        }
    }
    match chain.token.recipient {
        Some(r) => {
            out[pos] = 1;
            pos += 1;
            out[pos..pos + 32].copy_from_slice(&r.0);
            pos += 32;
        }
        None => {
            out[pos] = 0;
            pos += 1;
            out[pos..pos + 32].fill(0);
            pos += 32;
        }
    }
    out[pos..pos + 32].copy_from_slice(&chain.root);
    pos += 32;
    match chain.bound {
        Some(b) => {
            out[pos] = 1;
            pos += 1;
            out[pos..pos + 32].copy_from_slice(&b);
            pos += 32;
        }
        None => {
            out[pos] = 0;
            pos += 1;
            out[pos..pos + 32].fill(0);
            pos += 32;
        }
    }
    pos
}

fn deserialize_token_chain(data: &[u8]) -> Result<TokenChain, FleetError> {
    if data.len() < TOKEN_FIXED_LEN {
        return Err(FleetError::BadEnvelope);
    }
    let mut pos = 0;
    let mut kernel_id = [0u8; 32];
    kernel_id.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;
    let object_id = u64::from_le_bytes(
        data[pos..pos + 8]
            .try_into()
            .map_err(|_| FleetError::BadEnvelope)?,
    );
    pos += 8;
    let kind = TokenObjectKind::from_tag(data[pos]).ok_or(FleetError::BadEnvelope)?;
    pos += 1;
    let rights = data[pos];
    pos += 1;
    let expiry = if data[pos] == 1 {
        pos += 1;
        let e = u64::from_le_bytes(
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| FleetError::BadEnvelope)?,
        );
        pos += 8;
        Some(e)
    } else {
        pos += 1;
        pos += 8;
        None
    };
    let recipient = if data[pos] == 1 {
        pos += 1;
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        Some(NodeId(id))
    } else {
        pos += 1;
        pos += 32;
        None
    };
    let mut root = [0u8; 32];
    root.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;
    let bound = if data[pos] == 1 {
        pos += 1;
        let mut b = [0u8; 32];
        b.copy_from_slice(&data[pos..pos + 32]);
        Some(b)
    } else {
        None
    };
    Ok(TokenChain {
        token: CapabilityToken {
            kernel_id,
            object_id,
            kind,
            rights,
            expiry,
            recipient,
        },
        root,
        bound,
    })
}

/// Serialize a `RemoteCapability` into a fixed-size buffer, returning the
/// number of bytes written (always <= `ENVELOPE_MAX`). Mirrors
/// `aegis::fleet::Fleet::serialize`.
pub fn serialize(cap: &RemoteCapability, out: &mut [u8; ENVELOPE_MAX]) -> usize {
    let mut pos = 0;
    out[pos..pos + 32].copy_from_slice(&cap.issuer.0);
    pos += 32;
    out[pos..pos + 32].copy_from_slice(&cap.recipient.0);
    pos += 32;
    match cap.locality {
        Locality::Local => {
            out[pos] = 0;
            pos += 1;
        }
        Locality::Remote(id) => {
            out[pos] = 1;
            pos += 1;
            out[pos..pos + 32].copy_from_slice(&id.0);
            pos += 32;
        }
    }
    let n = serialize_token_chain(&cap.chain, &mut out[pos..]);
    pos + n
}

/// Deserialize a `RemoteCapability` from wire bytes. Mirrors
/// `aegis::fleet::Fleet::deserialize`.
pub fn deserialize(data: &[u8]) -> Result<RemoteCapability, FleetError> {
    if data.len() < 65 {
        return Err(FleetError::BadEnvelope);
    }
    let mut issuer = [0u8; 32];
    issuer.copy_from_slice(&data[0..32]);
    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(&data[32..64]);
    let (locality, off) = match data[64] {
        0 => (Locality::Local, 65),
        1 => {
            if data.len() < 97 {
                return Err(FleetError::BadEnvelope);
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&data[65..97]);
            (Locality::Remote(NodeId(id)), 97)
        }
        _ => return Err(FleetError::BadEnvelope),
    };
    if data.len() < off + TOKEN_FIXED_LEN {
        return Err(FleetError::BadEnvelope);
    }
    let chain = deserialize_token_chain(&data[off..off + TOKEN_FIXED_LEN])?;
    Ok(RemoteCapability {
        chain,
        issuer: NodeId(issuer),
        recipient: NodeId(recipient),
        locality,
    })
}

// ---- Fleet: one node's view of trust + reachability ------------------------

pub const MAX_PEERS: usize = 4;

#[derive(Clone, Copy)]
struct PeerEntry {
    id: NodeId,
    key: [u8; 32],
    last_seen: Option<u64>,
    unreachable: bool,
}

/// One node's view of the fleet. Mirrors `aegis::fleet::Fleet` field for
/// field, with a fixed `MAX_PEERS`-slot table instead of a `Vec`.
pub struct Fleet {
    pub node_id: NodeId,
    signing_key: [u8; 32],
    peers: [Option<PeerEntry>; MAX_PEERS],
    now: u64,
    stale_after: u64,
}

impl Fleet {
    pub const fn new(node_id: NodeId, signing_key: [u8; 32]) -> Fleet {
        Fleet {
            node_id,
            signing_key,
            peers: [None; MAX_PEERS],
            now: 0,
            stale_after: 100,
        }
    }

    pub fn advance_time(&mut self, now: u64) {
        self.now = now;
    }

    pub fn now(&self) -> u64 {
        self.now
    }

    pub fn set_stale_after(&mut self, ticks: u64) {
        self.stale_after = ticks;
    }

    pub fn stale_after(&self) -> u64 {
        self.stale_after
    }

    fn peer_index(&self, id: NodeId) -> Option<usize> {
        self.peers
            .iter()
            .position(|slot| slot.is_some_and(|p| p.id == id))
    }

    pub fn has_peer(&self, id: NodeId) -> bool {
        self.peer_index(id).is_some()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.iter().filter(|p| p.is_some()).count()
    }

    /// Register a peer we will verify tokens from (symmetric secret). The
    /// peer starts reachable (last-seen = now). Mirrors
    /// `Fleet::register_peer`.
    pub fn register_peer(&mut self, id: NodeId, key: [u8; 32]) -> Result<(), FleetError> {
        if self.has_peer(id) {
            return Err(FleetError::AlreadyRegistered);
        }
        for slot in self.peers.iter_mut() {
            if slot.is_none() {
                *slot = Some(PeerEntry {
                    id,
                    key,
                    last_seen: Some(self.now),
                    unreachable: false,
                });
                return Ok(());
            }
        }
        Err(FleetError::RegistryFull)
    }

    /// Record a heartbeat from `peer`: makes it reachable again and refreshes
    /// last-seen. This is the ONLY thing that clears staleness or a marked
    /// partition — verification never does it implicitly.
    pub fn heartbeat(&mut self, peer: NodeId) -> Result<(), FleetError> {
        let idx = self.peer_index(peer).ok_or(FleetError::UnknownPeer)?;
        let now = self.now;
        let p = self.peers[idx].as_mut().unwrap();
        p.last_seen = Some(now);
        p.unreachable = false;
        Ok(())
    }

    /// Explicitly mark `peer` unreachable (simulated or operator-declared
    /// partition, independent of the heartbeat clock).
    pub fn mark_unreachable(&mut self, peer: NodeId) -> Result<(), FleetError> {
        let idx = self.peer_index(peer).ok_or(FleetError::UnknownPeer)?;
        self.peers[idx].as_mut().unwrap().unreachable = true;
        Ok(())
    }

    pub fn is_unreachable(&self, peer: NodeId) -> bool {
        self.peer_index(peer)
            .is_some_and(|i| self.peers[i].unwrap().unreachable)
    }

    pub fn is_stale(&self, peer: NodeId) -> bool {
        match self.peer_index(peer) {
            Some(i) => self.peers[i]
                .unwrap()
                .last_seen
                .is_none_or(|seen| self.now.saturating_sub(seen) > self.stale_after),
            None => false,
        }
    }

    pub fn peer_reachable(&self, peer: NodeId) -> bool {
        match self.peer_index(peer) {
            Some(i) => {
                let p = self.peers[i].unwrap();
                !p.unreachable
                    && p.last_seen
                        .is_some_and(|seen| self.now.saturating_sub(seen) <= self.stale_after)
            }
            None => false,
        }
    }

    fn require_peer_reachable(&self, issuer: NodeId) -> Result<(), FleetError> {
        if self.is_unreachable(issuer) {
            return Err(FleetError::PeerUnreachable);
        }
        if self.is_stale(issuer) {
            return Err(FleetError::PeerStale);
        }
        Ok(())
    }

    /// Mint a local capability token signed by this node.
    pub fn issue(
        &self,
        object_id: u64,
        kind: TokenObjectKind,
        rights: Rights,
        expiry: Option<u64>,
    ) -> TokenChain {
        mint(
            &self.signing_key,
            self.node_id.0,
            object_id,
            kind,
            rights.bits(),
            expiry,
        )
    }

    /// Wrap a chain for sending to a trusted peer. Binds the recipient into
    /// the HMAC chain at this point — the peer named here is the only node
    /// that can ever verify it.
    pub fn send_to(&self, chain: TokenChain, peer: NodeId) -> Result<RemoteCapability, FleetError> {
        if !self.has_peer(peer) {
            return Err(FleetError::UntrustedPeer);
        }
        let chain = bind_recipient(&self.signing_key, &chain, peer);
        Ok(RemoteCapability {
            chain,
            issuer: self.node_id,
            recipient: peer,
            locality: Locality::Remote(self.node_id),
        })
    }

    /// A chain minted and held by this node. Locality is `Local`.
    pub fn hold_local(&self, chain: TokenChain) -> RemoteCapability {
        RemoteCapability {
            chain,
            issuer: self.node_id,
            recipient: self.node_id,
            locality: Locality::Local,
        }
    }

    fn issuer_key(&self, issuer: NodeId, locality: Locality) -> Result<[u8; 32], FleetError> {
        if issuer == self.node_id {
            return Ok(self.signing_key);
        }
        match locality {
            Locality::Local => Err(FleetError::UnknownIssuer),
            Locality::Remote(remote) => {
                if remote != issuer {
                    return Err(FleetError::UnknownIssuer);
                }
                self.peer_index(issuer)
                    .map(|i| self.peers[i].unwrap().key)
                    .ok_or(FleetError::UntrustedPeer)
            }
        }
    }

    /// Verify a capability the holder received: chain integrity under the
    /// issuer's key, envelope-level + HMAC-bound recipient checks, expiry,
    /// then the fail-closed partition gate. Mirrors `Fleet::verify`
    /// end-to-end, including check ordering.
    pub fn verify(&self, cap: &RemoteCapability) -> Result<(), FleetError> {
        let key = self.issuer_key(cap.issuer, cap.locality)?;
        verify_chain(&key, &cap.chain)?;
        if cap.recipient != self.node_id {
            return Err(FleetError::NotRecipient);
        }
        match cap.chain.token.recipient {
            Some(r) if r == self.node_id => {}
            Some(_) => return Err(FleetError::NotRecipient),
            None => {
                if cap.issuer != self.node_id {
                    return Err(FleetError::NotRecipient);
                }
            }
        }
        if let Some(exp) = cap.chain.token.expiry {
            if self.now > exp {
                return Err(FleetError::Expired);
            }
        }
        if let Locality::Remote(issuer) = cap.locality {
            self.require_peer_reachable(issuer)?;
        }
        Ok(())
    }
}

// ---- Real UDP transport over the existing Phase E netif -------------------

/// The one fixed port fleet traffic uses. Each side binds a UDP socket to
/// its peer's IP on this port — a real destination-scoped `NetEndpoint`,
/// same discipline as every other socket in this kernel (see `cap.rs`'s
/// `NET_RIGHTS` doc: bound to exactly one destination at creation).
pub const FLEET_PORT: u16 = 7777;

const MSG_HEARTBEAT: u8 = 0x01;
const MSG_CAPABILITY: u8 = 0x02;

/// Open a UDP link to `peer_ip:FLEET_PORT` on the shared kernel `NetIf`.
/// This is kernel-internal infrastructure traffic (peer trust, not a task's
/// job) — same access pattern `netif::open_advisor_endpoint` uses
/// internally, via the `pub unsafe fn NetIf::with` accessor that exists
/// specifically so other kernel modules can drive the shared netif safely.
pub fn open_link(peer_ip: [u8; 4]) -> Option<u16> {
    unsafe {
        crate::netif::NetIf::with(|net| {
            // Fail closed with no NIC: `socket_send` (UDP) would transmit
            // over `nic_mut()` and panic. A fleet image booted NIC-less simply
            // aborts the demo loop cleanly instead.
            if !net.is_online() {
                return None;
            }
            // Bind the well-known FLEET_PORT as our local port so the peer's
            // datagrams (addressed to FLEET_PORT, per socket_send's use of
            // remote_port as dst_port) match our socket: netif's UDP receive
            // path requires `sock.local_port == d.dst_port`.
            net.socket_open(
                crate::netif::SockKind::Udp,
                peer_ip,
                FLEET_PORT,
                Some(FLEET_PORT),
            )
            .map(|(id, _local_port)| id)
        })
    }
}

pub fn close_link(socket: u16) {
    unsafe {
        crate::netif::NetIf::with(|net| {
            net.socket_close(socket);
        });
    }
}

/// Send a one-byte heartbeat datagram to the peer this socket is bound to.
pub fn send_heartbeat(socket: u16) -> bool {
    let msg = [MSG_HEARTBEAT];
    unsafe { crate::netif::NetIf::with(|net| net.socket_send(socket, &msg) > 0) }
}

/// Serialize and send a `RemoteCapability` over `socket`.
pub fn send_capability(socket: u16, cap: &RemoteCapability) -> bool {
    let mut env = [0u8; ENVELOPE_MAX];
    let n = serialize(cap, &mut env);
    let mut buf = [0u8; 1 + ENVELOPE_MAX];
    buf[0] = MSG_CAPABILITY;
    buf[1..1 + n].copy_from_slice(&env[..n]);
    unsafe { crate::netif::NetIf::with(|net| net.socket_send(socket, &buf[..1 + n]) > 0) }
}

/// One event drained from the link.
///
/// `Capability` carries the full fixed-width envelope (246 bytes). Box isn't
/// available — this kernel is no-heap — and the event is drained one at a
/// time on the boot-demo stack, so the large-variant size is deliberate.
#[allow(clippy::large_enum_variant)]
pub enum LinkEvent {
    None,
    Heartbeat,
    Capability(RemoteCapability),
    /// Bytes arrived but didn't parse as a known message — logged, not
    /// fatal (a malformed/foreign datagram must never take the kernel
    /// down).
    Malformed,
}

/// Drain one pending datagram from `socket`, if any, and classify it.
/// Does NOT touch `Fleet` state itself (heartbeat bookkeeping is the
/// caller's job — see `run_boot_demo` below) so this function stays a pure
/// transport primitive, independent of any particular `Fleet` instance.
pub fn poll_link(socket: u16) -> LinkEvent {
    let mut buf = [0u8; 1 + ENVELOPE_MAX];
    let n = unsafe { crate::netif::NetIf::with(|net| net.socket_recv(socket, &mut buf)) };
    let Some(n) = n else {
        return LinkEvent::None;
    };
    if n == 0 {
        return LinkEvent::None;
    }
    match buf[0] {
        MSG_HEARTBEAT => LinkEvent::Heartbeat,
        MSG_CAPABILITY => match deserialize(&buf[1..n]) {
            Ok(cap) => LinkEvent::Capability(cap),
            Err(_) => LinkEvent::Malformed,
        },
        _ => LinkEvent::Malformed,
    }
}

// ---- Boot demo --------------------------------------------------------------
//
// Gated by the `fleet-node-a` / `fleet-node-b` Cargo features (mutually
// exclusive — see PHASE_I_INTEGRATION.md). `main.rs` calls
// `fleet::run_boot_demo(&pci)` once, after the NIC is up, near the end of
// the existing boot-demo sequence (after the other demos have closed their
// sockets — see integration notes).
//
// DEMO-ONLY KEY NOTE: the shared HMAC key between the two nodes is a fixed
// constant below. Real key provisioning (how two kernel instances agree on
// a shared secret before they trust each other at all) is a separate,
// unscoped bootstrapping problem — same category as "how does a fresh node
// get its first TLS root of trust" — and is intentionally not addressed
// here. This demo proves the verification MECHANISM once trust already
// exists, which is exactly what Phase I's own Definition of Done asks for.

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const DEMO_SHARED_KEY: [u8; 32] = *b"aegis-phase-i-demo-shared-key!!Z";

#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const NODE_A_ID: NodeId = NodeId([0xA1; 32]);
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const NODE_B_ID: NodeId = NodeId([0xB2; 32]);

/// Node A's static IP for the private fleet link — see `netif.rs`'s
/// `OUR_IP` feature-gate patch in PHASE_I_INTEGRATION.md.
#[cfg(feature = "fleet-node-a")]
const PEER_IP: [u8; 4] = [10, 0, 3, 2]; // node B
#[cfg(feature = "fleet-node-b")]
const PEER_IP: [u8; 4] = [10, 0, 3, 1]; // node A

/// Bound demo loop length in poll iterations, so the kernel still falls
/// through to the interactive shell afterward (this kernel's default boot
/// state — see repo header). Tune based on observed QEMU poll rate; this is
/// deliberately generous so a human operator has time to kill node A's
/// process mid-run and watch node B's log flip to `PeerStale`.
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const DEMO_MAX_POLLS: u64 = 500_000_000;
/// Send a heartbeat every this many demo-loop iterations.
#[cfg(feature = "fleet-node-a")]
const HEARTBEAT_EVERY: u64 = 2_000;
/// Re-run `verify()` and print the result every this many iterations.
#[cfg(feature = "fleet-node-b")]
const VERIFY_EVERY: u64 = 20_000;
/// A peer is stale after this many ticks without a heartbeat. Must be larger
/// than `HEARTBEAT_EVERY` (heartbeats arrive every 2000 ticks), and small
/// enough that the demo still flips to `PeerStale` promptly if the link is
/// cut mid-run.
#[cfg(any(feature = "fleet-node-a", feature = "fleet-node-b"))]
const STALE_AFTER_TICKS: u64 = 10_000;

#[cfg(feature = "fleet-node-a")]
pub fn run_boot_demo() {
    crate::sprintln!(
        "Aegis: fleet: node A starting (id A1.., peer B at {:?})",
        PEER_IP
    );
    let mut fleet = Fleet::new(NODE_A_ID, DEMO_SHARED_KEY);
    fleet.set_stale_after(STALE_AFTER_TICKS);
    if fleet.register_peer(NODE_B_ID, DEMO_SHARED_KEY).is_err() {
        crate::sprintln!("Aegis: fleet: register_peer failed — aborting demo");
        return;
    }
    let Some(sock) = open_link(PEER_IP) else {
        crate::sprintln!("Aegis: fleet: could not open UDP link to node B — aborting demo");
        return;
    };
    crate::sprintln!("Aegis: fleet: UDP link to node B opened (socket {})", sock);

    // The one real cross-machine capability: mint a token for a demo
    // Endpoint object (id 42, READ|SEND rights), bind it to node B, and
    // send it exactly once. Everything after this is heartbeats — proving
    // the link stays live, and (per §10) that it fails closed, for real,
    // the moment it stops.
    let chain = fleet.issue(
        42,
        TokenObjectKind::Endpoint,
        Rights::READ.union(Rights::SEND),
        None,
    );
    match fleet.send_to(chain, NODE_B_ID) {
        Ok(cap) => {
            let sent = send_capability(sock, &cap);
            crate::sprintln!(
                "Aegis: fleet: capability (object 42, Endpoint, RS) sent to node B: {}",
                sent
            );
        }
        Err(e) => {
            crate::sprintln!("Aegis: fleet: send_to failed: {:?}", e);
        }
    }

    let mut i: u64 = 0;
    while i < DEMO_MAX_POLLS {
        unsafe {
            crate::netif::NetIf::with(|net| {
                if net.is_online() {
                    net.poll();
                }
            })
        };
        fleet.advance_time(i);
        if i % HEARTBEAT_EVERY == 0 {
            send_heartbeat(sock);
        }
        i += 1;
        core::hint::spin_loop();
    }
    close_link(sock);
    crate::sprintln!(
        "Aegis: fleet: node A demo loop finished ({} polls)",
        DEMO_MAX_POLLS
    );
}

#[cfg(feature = "fleet-node-b")]
pub fn run_boot_demo() {
    crate::sprintln!(
        "Aegis: fleet: node B starting (id B2.., peer A at {:?})",
        PEER_IP
    );
    let mut fleet = Fleet::new(NODE_B_ID, DEMO_SHARED_KEY);
    fleet.set_stale_after(STALE_AFTER_TICKS);
    if fleet.register_peer(NODE_A_ID, DEMO_SHARED_KEY).is_err() {
        crate::sprintln!("Aegis: fleet: register_peer failed — aborting demo");
        return;
    }
    let Some(sock) = open_link(PEER_IP) else {
        crate::sprintln!("Aegis: fleet: could not open UDP link to node A — aborting demo");
        return;
    };
    crate::sprintln!("Aegis: fleet: UDP link to node A opened (socket {})", sock);
    // Node B does not know it's talking to node A cryptographically until
    // `verify()` succeeds below — the IP is just where packets are coming
    // from, not a security property. Trust is proven by the HMAC chain.

    let mut received: Option<RemoteCapability> = None;
    let mut i: u64 = 0;
    while i < DEMO_MAX_POLLS {
        unsafe {
            crate::netif::NetIf::with(|net| {
                if net.is_online() {
                    net.poll();
                }
            })
        };
        fleet.advance_time(i);

        match poll_link(sock) {
            LinkEvent::Heartbeat => {
                let _ = fleet.heartbeat(NODE_A_ID);
            }
            LinkEvent::Capability(cap) => {
                crate::sprintln!("Aegis: fleet: capability envelope received from node A");
                received = Some(cap);
            }
            LinkEvent::Malformed => {
                crate::sprintln!("Aegis: fleet: malformed datagram on fleet link (ignored)");
            }
            LinkEvent::None => {}
        }

        if i % VERIFY_EVERY == 0 {
            if let Some(cap) = &received {
                match fleet.verify(cap) {
                    Ok(()) => crate::sprintln!(
                        "Aegis: fleet: verify OK — object {} kind {:?} rights {:#04b} from node A, recipient-bound to us, issuer reachable",
                        cap.chain.token.object_id,
                        cap.chain.token.kind,
                        cap.chain.token.rights
                    ),
                    Err(e) => crate::sprintln!(
                        "Aegis: fleet: verify DENIED (fail-closed): {:?} — issuer reachable={} stale={}",
                        e,
                        fleet.peer_reachable(NODE_A_ID),
                        fleet.is_stale(NODE_A_ID)
                    ),
                }
            } else {
                crate::sprintln!(
                    "Aegis: fleet: no capability received yet (reachable={}, stale={})",
                    fleet.peer_reachable(NODE_A_ID),
                    fleet.is_stale(NODE_A_ID)
                );
            }
        }
        i += 1;
        core::hint::spin_loop();
    }
    close_link(sock);
    crate::sprintln!(
        "Aegis: fleet: node B demo loop finished ({} polls)",
        DEMO_MAX_POLLS
    );
}

// ---- Tests (pure protocol logic — no netif/NIC required) ------------------
//
// Ported directly from `aegis/crates/fleet`'s own test module (same names,
// same scenarios), adapted to this port's fixed-width types. These prove
// the mechanism in isolation; the boot demo above is what proves it live
// over a real link between two real kernel instances.

#[cfg(test)]
mod tests {
    use super::*;

    fn node_a() -> (NodeId, [u8; 32]) {
        (NodeId([1u8; 32]), [0xAA; 32])
    }
    fn node_b() -> (NodeId, [u8; 32]) {
        (NodeId([2u8; 32]), [0xBB; 32])
    }
    fn node_c() -> (NodeId, [u8; 32]) {
        (NodeId([3u8; 32]), [0xCC; 32])
    }

    #[test]
    fn issue_send_verify_roundtrip() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let mut fleet_a = Fleet::new(id_a, key_a);
        let mut fleet_b = Fleet::new(id_b, key_b);
        fleet_a.register_peer(id_b, key_b).unwrap();
        fleet_b.register_peer(id_a, key_a).unwrap();

        let chain = fleet_a.issue(7, TokenObjectKind::Endpoint, Rights::READ, None);
        let cap = fleet_a.send_to(chain, id_b).unwrap();
        assert_eq!(fleet_b.verify(&cap), Ok(()));
    }

    #[test]
    fn wire_roundtrip_preserves_verification() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let fleet_a = Fleet::new(id_a, key_a);
        let mut fleet_a = fleet_a;
        let mut fleet_b = Fleet::new(id_b, key_b);
        fleet_a.register_peer(id_b, key_b).unwrap();
        fleet_b.register_peer(id_a, key_a).unwrap();

        let chain = fleet_a.issue(
            9,
            TokenObjectKind::MemRegion,
            Rights::READ.union(Rights::WRITE),
            None,
        );
        let cap = fleet_a.send_to(chain, id_b).unwrap();
        let mut buf = [0u8; ENVELOPE_MAX];
        let n = serialize(&cap, &mut buf);
        let back = deserialize(&buf[..n]).unwrap();
        assert_eq!(fleet_b.verify(&back), Ok(()));
    }

    #[test]
    fn relayed_token_is_rejected_recipient_binding() {
        // A sends to B; B relays the identical bytes to C, who trusts A too.
        // Before recipient binding this would wrongly verify at C.
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let (id_c, key_c) = node_c();
        let mut fleet_a = Fleet::new(id_a, key_a);
        let mut fleet_b = Fleet::new(id_b, key_b);
        let mut fleet_c = Fleet::new(id_c, key_c);
        fleet_a.register_peer(id_b, key_b).unwrap();
        fleet_b.register_peer(id_a, key_a).unwrap();
        fleet_c.register_peer(id_a, key_a).unwrap();

        let chain = fleet_a.issue(7, TokenObjectKind::Task, Rights::READ, None);
        let cap = fleet_a.send_to(chain, id_b).unwrap();
        assert_eq!(fleet_b.verify(&cap), Ok(()));

        let mut buf = [0u8; ENVELOPE_MAX];
        let n = serialize(&cap, &mut buf);
        let relayed = deserialize(&buf[..n]).unwrap();
        assert_eq!(fleet_c.verify(&relayed), Err(FleetError::NotRecipient));
    }

    #[test]
    fn forged_recipient_field_still_rejected() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let (id_c, key_c) = node_c();
        let mut fleet_a = Fleet::new(id_a, key_a);
        let mut fleet_b = Fleet::new(id_b, key_b);
        let mut fleet_c = Fleet::new(id_c, key_c);
        fleet_a.register_peer(id_b, key_b).unwrap();
        fleet_b.register_peer(id_a, key_a).unwrap();
        fleet_c.register_peer(id_a, key_a).unwrap();

        let chain = fleet_a.issue(7, TokenObjectKind::Task, Rights::READ, None);
        let mut forged = fleet_a.send_to(chain, id_b).unwrap();
        forged.recipient = id_c; // tamper with the envelope only, not the HMAC chain
        assert_eq!(fleet_c.verify(&forged), Err(FleetError::NotRecipient));
    }

    fn set_up_ab() -> (Fleet, Fleet, NodeId, NodeId) {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let mut fleet_a = Fleet::new(id_a, key_a);
        let mut fleet_b = Fleet::new(id_b, key_b);
        fleet_a.register_peer(id_b, key_b).unwrap();
        fleet_b.register_peer(id_a, key_a).unwrap();
        (fleet_a, fleet_b, id_a, id_b)
    }

    #[test]
    fn remote_capability_denied_while_issuer_partitioned() {
        let (fleet_a, mut fleet_b, id_a, id_b) = set_up_ab();
        let chain = fleet_a.issue(7, TokenObjectKind::Task, Rights::READ, None);
        let cap = fleet_a.send_to(chain, id_b).unwrap();
        assert_eq!(fleet_b.verify(&cap), Ok(()));
        fleet_b.mark_unreachable(id_a).unwrap();
        assert_eq!(fleet_b.verify(&cap), Err(FleetError::PeerUnreachable));
        fleet_b.heartbeat(id_a).unwrap();
        assert_eq!(fleet_b.verify(&cap), Ok(()));
    }

    #[test]
    fn remote_capability_denied_when_issuer_state_stale() {
        let (fleet_a, mut fleet_b, id_a, id_b) = set_up_ab();
        let chain = fleet_a.issue(7, TokenObjectKind::Task, Rights::READ, None);
        let cap = fleet_a.send_to(chain, id_b).unwrap();
        fleet_b.advance_time(101);
        assert_eq!(fleet_b.verify(&cap), Err(FleetError::PeerStale));
        fleet_b.heartbeat(id_a).unwrap();
        assert_eq!(fleet_b.verify(&cap), Ok(()));
        fleet_b.advance_time(101 + 101);
        assert_eq!(fleet_b.verify(&cap), Err(FleetError::PeerStale));
    }

    #[test]
    fn local_capability_unaffected_by_partition_of_peers() {
        let (mut fleet_a, _fleet_b, _id_a, id_b) = set_up_ab();
        let chain = fleet_a.issue(42, TokenObjectKind::MemRegion, Rights::READ, None);
        let cap = fleet_a.hold_local(chain);
        fleet_a.mark_unreachable(id_b).unwrap();
        fleet_a.advance_time(500);
        assert_eq!(fleet_a.verify(&cap), Ok(()));
    }

    #[test]
    fn unknown_issuer_fails_verification() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let (id_c, key_c) = node_c();
        let fleet_a = Fleet::new(id_a, key_a);
        let mut fleet_b = Fleet::new(id_b, key_b);
        fleet_b.register_peer(id_c, key_c).unwrap();
        let chain = fleet_a.issue(1, TokenObjectKind::Task, Rights::READ, None);
        let cap = RemoteCapability {
            chain,
            issuer: id_a,
            recipient: id_b,
            locality: Locality::Remote(id_a),
        };
        assert_eq!(fleet_b.verify(&cap), Err(FleetError::UntrustedPeer));
    }

    #[test]
    fn send_to_requires_trusted_peer() {
        let (id_a, key_a) = node_a();
        let (id_b, _) = node_b();
        let fleet = Fleet::new(id_a, key_a);
        let chain = fleet.issue(1, TokenObjectKind::Task, Rights::READ, None);
        assert_eq!(fleet.send_to(chain, id_b), Err(FleetError::UntrustedPeer));
    }

    #[test]
    fn register_peer_duplicate_and_full() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let (id_c, key_c) = node_c();
        let mut fleet = Fleet::new(id_a, key_a);
        fleet.register_peer(id_b, key_b).unwrap();
        assert_eq!(
            fleet.register_peer(id_b, key_b),
            Err(FleetError::AlreadyRegistered)
        );

        let mut fleet = Fleet::new(id_a, key_a);
        for i in 0..MAX_PEERS {
            fleet
                .register_peer(NodeId([0xE0 + i as u8; 32]), [0xE0 + i as u8; 32])
                .unwrap();
        }
        assert_eq!(
            fleet.register_peer(id_c, key_c),
            Err(FleetError::RegistryFull)
        );
    }

    #[test]
    fn unknown_peer_operations_fail_closed() {
        let (mut fleet_a, _fleet_b, _id_a, _id_b) = set_up_ab();
        let (id_c, _) = node_c();
        assert_eq!(fleet_a.heartbeat(id_c), Err(FleetError::UnknownPeer));
        assert_eq!(fleet_a.mark_unreachable(id_c), Err(FleetError::UnknownPeer));
    }

    #[test]
    fn expired_token_is_denied() {
        let (fleet_a, mut fleet_b, id_a, id_b) = set_up_ab();
        let chain = fleet_a.issue(7, TokenObjectKind::Task, Rights::READ, Some(10));
        let cap = fleet_a.send_to(chain, id_b).unwrap();
        fleet_b.advance_time(5);
        assert_eq!(fleet_b.verify(&cap), Ok(()));
        fleet_b.advance_time(11);
        // Stale window default is 100 and last heartbeat was at t=0 at
        // register time, so at t=11 it's still "reachable" — the failure
        // here must be Expired, not PeerStale, proving check ordering.
        assert_eq!(fleet_b.verify(&cap), Err(FleetError::Expired));
        let _ = id_a;
    }

    #[test]
    fn envelope_wire_format_round_trips_all_fields() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let mut fleet_a = Fleet::new(id_a, key_a);
        fleet_a.register_peer(id_b, key_b).unwrap();
        let chain = fleet_a.issue(
            u64::MAX / 3,
            TokenObjectKind::NetEndpoint,
            Rights::SEND.union(Rights::RECV),
            Some(999_999),
        );
        let cap = fleet_a.send_to(chain, id_b).unwrap();
        let mut buf = [0u8; ENVELOPE_MAX];
        let n = serialize(&cap, &mut buf);
        let back = deserialize(&buf[..n]).unwrap();
        assert_eq!(back.issuer, cap.issuer);
        assert_eq!(back.recipient, cap.recipient);
        assert_eq!(back.locality, cap.locality);
        assert_eq!(back.chain.token.object_id, cap.chain.token.object_id);
        assert_eq!(back.chain.token.kind, cap.chain.token.kind);
        assert_eq!(back.chain.token.rights, cap.chain.token.rights);
        assert_eq!(back.chain.token.expiry, cap.chain.token.expiry);
        assert_eq!(back.chain.token.recipient, cap.chain.token.recipient);
    }
}
