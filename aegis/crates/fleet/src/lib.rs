//! Fleet orchestration — cross-machine capability transport (Phase 11).
//!
//! Design doc §3(D)/§5/§7 Phase 11: "Distributed extension (fleet orchestration,
//! cross-machine capabilities) — explicitly *after* single-machine correctness,
//! not concurrently." Cross-machine capabilities are an explicit, opt-in
//! extension using cryptographically-verifiable capability tokens
//! (macaroon/biscuit-style) rather than assuming a trusted LAN. **Locality is
//! never hidden**: a capability always knows whether it is local or remote,
//! even though the invocation shape is the same either way.
//!
//! This crate is the transport/envelope layer over the `macaroon` token
//! format: node identity, an explicit locality flag, a wire-format envelope
//! for `RemoteCapability`, peer trust registration, and verification that
//! checks chain integrity, issuer trust, and expiry.
//!
//! Honest limits: this is a two-node in-process model of a fleet (no sockets,
//! no real network, no consensus/split-brain handling — the design doc's
//! "transparency lies under partition" warning applies, and partition
//! behavior is deliberately NOT modeled here). `macaroon::bind_caveat`
//! requires the signing key, so attenuation in this model is done by a node
//! that holds the issuer key; real macaroons allow keyless attenuation, which
//! is a documented difference, not a security claim.

use capability_core::{ObjectKind, Rights};
use macaroon::{Caveat, TokenChain, TokenError};

/// A node in the fleet. 32 bytes of identity (kernel-instance id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn from_slice(s: &[u8]) -> Option<Self> {
        if s.len() != 32 {
            return None;
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(s);
        Some(NodeId(id))
    }
}

/// Explicit locality of a held capability. Never hidden from the holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locality {
    Local,
    Remote(NodeId),
}

/// A capability with its transport envelope: the token chain, the issuing
/// node, and the locality from the *holding* node's point of view.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteCapability {
    pub chain: TokenChain,
    pub issuer: NodeId,
    pub locality: Locality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetError {
    UnknownIssuer,
    UntrustedPeer,
    RegistryFull,
    AlreadyRegistered,
    ChainIntegrity,
    Expired,
    Serialization,
    BadEnvelope,
}

impl From<TokenError> for FleetError {
    fn from(e: TokenError) -> Self {
        match e {
            TokenError::ChainIntegrityError => FleetError::ChainIntegrity,
            TokenError::SerializationError | TokenError::DeserializationError => {
                FleetError::Serialization
            }
            TokenError::CaveatViolation(_) => FleetError::ChainIntegrity,
        }
    }
}

const MAX_PEERS: usize = 16;

/// One node's view of the fleet: its identity, its signing key, the set of
/// peers it trusts (peer id -> shared secret for HMAC verification), and a
/// monotonic clock for expiry checks.
pub struct Fleet {
    pub node_id: NodeId,
    signing_key: [u8; 32],
    peers: [Option<(NodeId, [u8; 32])>; MAX_PEERS],
    peer_count: usize,
    now: u64,
}

impl Fleet {
    pub fn new(node_id: NodeId, signing_key: [u8; 32]) -> Self {
        const NONE: Option<(NodeId, [u8; 32])> = None;
        Self {
            node_id,
            signing_key,
            peers: [NONE; MAX_PEERS],
            peer_count: 0,
            now: 0,
        }
    }

    /// Register a peer we will verify tokens from. Symmetric secret per peer.
    pub fn register_peer(&mut self, id: NodeId, key: [u8; 32]) -> Result<(), FleetError> {
        if self
            .peers
            .iter()
            .flatten()
            .any(|(peer_id, _)| *peer_id == id)
        {
            return Err(FleetError::AlreadyRegistered);
        }
        if self.peer_count >= MAX_PEERS {
            return Err(FleetError::RegistryFull);
        }
        for slot in self.peers.iter_mut() {
            if slot.is_none() {
                *slot = Some((id, key));
                self.peer_count += 1;
                return Ok(());
            }
        }
        Err(FleetError::RegistryFull)
    }

    pub fn has_peer(&self, id: NodeId) -> bool {
        self.peers
            .iter()
            .flatten()
            .any(|(peer_id, _)| *peer_id == id)
    }

    pub fn peer_count(&self) -> usize {
        self.peer_count
    }

    /// Advance the local clock (used for expiry verification).
    pub fn advance_time(&mut self, now: u64) {
        self.now = now;
    }

    /// Mint a local capability token signed by this node.
    pub fn issue(
        &self,
        object_id: u64,
        kind: ObjectKind,
        rights: Rights,
        expiry: Option<u64>,
    ) -> TokenChain {
        macaroon::mint(
            &self.signing_key,
            self.node_id.0,
            object_id,
            kind,
            rights,
            expiry,
        )
    }

    /// Wrap a chain for presentation to a trusted peer. The envelope's
    /// locality is Remote(issuer): from the *holding* node's point of view the
    /// capability is remote and originated at this (issuing) node.
    pub fn send_to(&self, chain: TokenChain, peer: NodeId) -> Result<RemoteCapability, FleetError> {
        if !self.has_peer(peer) {
            return Err(FleetError::UntrustedPeer);
        }
        Ok(RemoteCapability {
            chain,
            issuer: self.node_id,
            locality: Locality::Remote(self.node_id),
        })
    }

    /// A chain minted by this node and held locally.
    pub fn hold_local(&self, chain: TokenChain) -> RemoteCapability {
        RemoteCapability {
            chain,
            issuer: self.node_id,
            locality: Locality::Local,
        }
    }

    /// Verify a capability the holder received: chain integrity under the
    /// issuer's key, issuer trust, and expiry.
    pub fn verify(&self, cap: &RemoteCapability) -> Result<(), FleetError> {
        let key = self.issuer_key(cap.issuer, cap.locality)?;
        macaroon::verify(&key, &cap.chain)?;
        if let Some(exp) = cap.chain.token.expiry {
            if self.now > exp {
                return Err(FleetError::Expired);
            }
        }
        Ok(())
    }

    /// Narrow (attenuate) a held capability. Uses the issuer key to re-sign
    /// (documented model limitation; real macaroons allow keyless caveats).
    pub fn narrow(
        &self,
        cap: &RemoteCapability,
        caveat: Caveat,
    ) -> Result<RemoteCapability, FleetError> {
        let key = self.issuer_key(cap.issuer, cap.locality)?;
        let chain = macaroon::bind_caveat(&key, &cap.chain, caveat);
        Ok(RemoteCapability {
            chain,
            issuer: cap.issuer,
            locality: cap.locality,
        })
    }

    /// Key used to check a chain from `issuer`: own key for self-issued
    /// tokens (local or remotely presented back), peer key for trusted peers.
    fn issuer_key(&self, issuer: NodeId, locality: Locality) -> Result<[u8; 32], FleetError> {
        if issuer == self.node_id {
            return Ok(self.signing_key);
        }
        match locality {
            Locality::Local => Err(FleetError::UnknownIssuer),
            Locality::Remote(remote) => {
                if remote == issuer {
                    self.peers
                        .iter()
                        .flatten()
                        .find(|(peer_id, _)| *peer_id == issuer)
                        .map(|(_, k)| *k)
                        .ok_or(FleetError::UntrustedPeer)
                } else {
                    Err(FleetError::UnknownIssuer)
                }
            }
        }
    }

    /// Wire format for a RemoteCapability:
    /// issuer(32) | locality_flag(1) | remote_id(32, only if Remote) | chain bytes.
    pub fn serialize(cap: &RemoteCapability) -> Result<Vec<u8>, FleetError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&cap.issuer.0);
        match cap.locality {
            Locality::Local => buf.push(0),
            Locality::Remote(id) => {
                buf.push(1);
                buf.extend_from_slice(&id.0);
            }
        }
        buf.extend_from_slice(&macaroon::serialize_chain(&cap.chain));
        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> Result<RemoteCapability, FleetError> {
        if data.len() < 33 {
            return Err(FleetError::BadEnvelope);
        }
        let mut issuer = [0u8; 32];
        issuer.copy_from_slice(&data[0..32]);
        let locality = match data[32] {
            0 => Locality::Local,
            1 => {
                if data.len() < 65 {
                    return Err(FleetError::BadEnvelope);
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&data[33..65]);
                Locality::Remote(NodeId(id))
            }
            _ => return Err(FleetError::BadEnvelope),
        };
        let chain_off = if matches!(locality, Locality::Local) {
            33
        } else {
            65
        };
        let chain = macaroon::deserialize_chain(&data[chain_off..])?;
        Ok(RemoteCapability {
            chain,
            issuer: NodeId(issuer),
            locality,
        })
    }
}

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

    fn read_write() -> Rights {
        Rights::READ.union(Rights::WRITE)
    }

    #[test]
    fn issue_mints_verifiable_local_capability() {
        let (id_a, key) = node_a();
        let fleet = Fleet::new(id_a, key);
        let chain = fleet.issue(42, ObjectKind::MemRegion, read_write(), None);
        let cap = fleet.hold_local(chain);
        assert_eq!(fleet.verify(&cap), Ok(()));
    }

    #[test]
    fn remote_verification_with_peer_key() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let mut fleet_a = Fleet::new(id_a, key_a);
        let mut fleet_b = Fleet::new(id_b, key_b);
        fleet_a.register_peer(id_b, key_b).unwrap();
        fleet_b.register_peer(id_a, key_a).unwrap();

        let chain = fleet_a.issue(7, ObjectKind::Task, Rights::READ, None);
        let cap = fleet_a.send_to(chain, id_b).unwrap();
        assert_eq!(cap.locality, Locality::Remote(id_a));
        assert_eq!(fleet_b.verify(&cap), Ok(()));
    }

    #[test]
    fn unregistered_peer_cannot_verify() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let mut fleet_a = Fleet::new(id_a, key_a);
        fleet_a.register_peer(id_b, key_b).unwrap();
        let fleet_b = Fleet::new(id_b, key_b); // B never registers A

        let chain = fleet_a.issue(7, ObjectKind::Task, Rights::READ, None);
        let cap = fleet_a.send_to(chain, id_b).unwrap();
        assert_eq!(fleet_b.verify(&cap), Err(FleetError::UntrustedPeer));
    }

    #[test]
    fn tampered_chain_fails_integrity_check() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let mut fleet_a = Fleet::new(id_a, key_a);
        let mut fleet_b = Fleet::new(id_b, key_b);
        fleet_a.register_peer(id_b, key_b).unwrap();
        fleet_b.register_peer(id_a, key_a).unwrap();

        let chain = fleet_a.issue(7, ObjectKind::Task, Rights::READ, None);
        let mut cap = fleet_a.send_to(chain, id_b).unwrap();
        // Flip one byte of the root chain entry
        cap.chain.chain[0][0] ^= 0xFF;
        assert_eq!(fleet_b.verify(&cap), Err(FleetError::ChainIntegrity));
    }

    #[test]
    fn expired_token_rejected() {
        let (id_a, key_a) = node_a();
        let fleet_a = Fleet::new(id_a, key_a);
        let chain = fleet_a.issue(1, ObjectKind::MemRegion, read_write(), Some(100));
        let mut fleet_holder = Fleet::new(node_b().0, node_b().1);
        fleet_holder.register_peer(id_a, key_a).unwrap();
        let cap = RemoteCapability {
            chain,
            issuer: id_a,
            locality: Locality::Remote(id_a),
        };
        fleet_holder.advance_time(50);
        assert_eq!(fleet_holder.verify(&cap), Ok(()));
        fleet_holder.advance_time(101);
        assert_eq!(fleet_holder.verify(&cap), Err(FleetError::Expired));
    }

    #[test]
    fn expiry_clamp_caveat_binds_before_expiry_check() {
        let (id_a, key_a) = node_a();
        let fleet_a = Fleet::new(id_a, key_a);
        let chain = fleet_a.issue(1, ObjectKind::MemRegion, read_write(), Some(1000));
        let mut holder = Fleet::new(node_b().0, node_b().1);
        holder.register_peer(id_a, key_a).unwrap();

        let cap = RemoteCapability {
            chain,
            issuer: id_a,
            locality: Locality::Remote(id_a),
        };
        // Narrow expiry to 10, then check at t=11
        let narrowed = holder.narrow(&cap, Caveat::ExpiryClamp(10)).unwrap();
        holder.advance_time(11);
        assert_eq!(holder.verify(&narrowed), Err(FleetError::Expired));
    }

    #[test]
    fn rights_narrowing_reduces_authority() {
        let (id_a, key_a) = node_a();
        let fleet_a = Fleet::new(id_a, key_a);
        let chain = fleet_a.issue(1, ObjectKind::MemRegion, read_write(), None);
        let cap = RemoteCapability {
            chain,
            issuer: id_a,
            locality: Locality::Remote(id_a),
        };
        // Note: narrowing requires the issuer key (documented model limit),
        // so use fleet_a itself as the attenuating holder.
        let mask = Rights::READ.bits();
        let narrowed = fleet_a.narrow(&cap, Caveat::RightsNarrow(mask)).unwrap();
        assert_eq!(narrowed.chain.token.rights, Rights::READ.bits());
        assert_eq!(narrowed.chain.token.rights & Rights::WRITE.bits(), 0);
    }

    #[test]
    fn envelope_round_trip_local() {
        let (id_a, key_a) = node_a();
        let fleet = Fleet::new(id_a, key_a);
        let chain = fleet.issue(9, ObjectKind::Endpoint, Rights::SEND, None);
        let cap = fleet.hold_local(chain);
        let bytes = Fleet::serialize(&cap).unwrap();
        let decoded = Fleet::deserialize(&bytes).unwrap();
        assert_eq!(decoded.issuer, id_a);
        assert_eq!(decoded.locality, Locality::Local);
        assert_eq!(decoded.chain.token.object_id, 9);
    }

    #[test]
    fn envelope_round_trip_remote() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let mut fleet_a = Fleet::new(id_a, key_a);
        let mut fleet_b = Fleet::new(id_b, key_b);
        fleet_a.register_peer(id_b, key_b).unwrap();
        fleet_b.register_peer(id_a, key_a).unwrap();

        let chain = fleet_a.issue(3, ObjectKind::Task, Rights::READ, None);
        let cap = fleet_a.send_to(chain, id_b).unwrap();
        let bytes = Fleet::serialize(&cap).unwrap();
        let decoded = Fleet::deserialize(&bytes).unwrap();
        assert_eq!(decoded.locality, Locality::Remote(id_a));
        assert_eq!(fleet_b.verify(&decoded), Ok(()));
    }

    #[test]
    fn envelope_rejects_bad_headers() {
        assert_eq!(Fleet::deserialize(&[0u8; 10]), Err(FleetError::BadEnvelope));
        let mut bad = vec![0u8; 65];
        bad[32] = 2; // invalid locality flag
        assert_eq!(Fleet::deserialize(&bad), Err(FleetError::BadEnvelope));
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
    fn send_to_requires_trusted_peer() {
        let (id_a, key_a) = node_a();
        let (id_b, _) = node_b();
        let fleet = Fleet::new(id_a, key_a);
        let chain = fleet.issue(1, ObjectKind::Task, Rights::READ, None);
        assert_eq!(fleet.send_to(chain, id_b), Err(FleetError::UntrustedPeer));
    }

    #[test]
    fn unknown_issuer_fails_verification() {
        let (id_a, key_a) = node_a();
        let (id_b, key_b) = node_b();
        let (id_c, key_c) = node_c();
        let fleet_a = Fleet::new(id_a, key_a);
        let mut fleet_b = Fleet::new(id_b, key_b);
        // B trusts C, not A
        fleet_b.register_peer(id_c, key_c).unwrap();
        let chain = fleet_a.issue(1, ObjectKind::Task, Rights::READ, None);
        let cap = RemoteCapability {
            chain,
            issuer: id_a,
            locality: Locality::Remote(id_a),
        };
        assert_eq!(fleet_b.verify(&cap), Err(FleetError::UntrustedPeer));
    }
}
