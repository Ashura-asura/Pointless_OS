//! The real kernel network interface + minimal TCP/IP stack (design doc §8
//! "Networking"): ARP resolution over the e1000 driver, ICMP echo reply, UDP,
//! and a client TCP with a real three-way handshake, retransmission, and a
//! slow-start congestion window. The stack is polled — the owner (the boot
//! demo, or a socket user's `recv`/`connect`/`send` call) drains the NIC and
//! drives the state machines — and every socket is a capability-scoped
//! `NetEndpoint` object: it is minted bound to exactly one destination, and
//! the kernel refuses any operation outside that scope. No ambient network
//! access.
//!
//! Honest limits (kept, not removed): polled (no interrupts); TCP is
//! client-side only with in-order, non-fragmented, no-option segments; a
//! bounded socket table (MAX_SOCKETS) and bounded send/recv buffers; the
//! retransmission clock is the poll counter (a monotonic software clock, not
//! wall time); a slow-start congestion window that grows per ACK. The stack is
//! exercised by the live QEMU demo exactly as a socket user drives it — the
//! cap-gated syscalls and the kernel-level boot demo share the same socket
//! functions.

use crate::arp::{ArpPacket, ArpTable, ARP_REPLY, ARP_REQUEST, HW_TYPE_ETHERNET, PROTO_TYPE_IPV4};
use crate::ethernet::{ETHERTYPE_ARP, ETHERTYPE_IPV4};
use crate::ipv4::{IPv4Address, IPv4Packet, DEFAULT_TTL, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::net::MacAddress;
use crate::tcp::{TcpFlags, TcpSegment};
use crate::udp::UdpDatagram;

#[cfg(feature = "fleet-node-a")]
pub const OUR_IP: [u8; 4] = [10, 0, 3, 1];
#[cfg(feature = "fleet-node-b")]
pub const OUR_IP: [u8; 4] = [10, 0, 3, 2];
#[cfg(not(any(feature = "fleet-node-a", feature = "fleet-node-b")))]
pub const OUR_IP: [u8; 4] = [10, 0, 2, 15];
pub const GW_IP: [u8; 4] = [10, 0, 2, 2];
pub const GW_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x02];

/// Phase F (`query-advisor`): the ONE host a `query-advisor`-role agent may
/// ever reach. Declared here, by the kernel, not by whoever calls
/// `role::role_grant` — the grantor names a *service* to grant advisory
/// authority in the context of, never a destination. QEMU user-mode
/// networking routes the guest's default gateway (`GW_IP`) to the host, so
/// this reaches a real external network path the same way the Phase E TLS
/// demo does. A production deployment would point this at a real advisor
/// endpoint; the identity of the constant is not the security property — the
/// property is that it is fixed by the kernel and the granted capability
/// cannot be rebound to anything else.
pub const ADVISOR_HOST_IP: [u8; 4] = GW_IP;
pub const ADVISOR_HOST_PORT: u16 = 443;

pub const MAX_SOCKETS: usize = 4;
pub const SEND_BUFLEN: usize = 4096;
pub const RECV_BUFLEN: usize = 8192;
pub const FRAME_MAX: usize = 2048;

/// How often `poll()` emits the aggregate RX diagnostics line (in poll
/// ticks). Aggregate only — never per packet, so it can't perturb timing.
pub const DIAG_EVERY: u64 = 200_000;

/// Retransmission timeout, in poll-count units: if a segment goes unacked for
/// this many `poll()`/`advance()` calls we retransmit. The live host peer
/// answers in a tiny fraction of this; the contract tests advance the poll
/// clock directly.
pub const RTO_POLLS: u64 = 1_000_000;
pub const MAX_RETRANSMIT: u32 = 3;

pub const TCP_MSS: usize = 1460;
const CWND_INIT: u32 = TCP_MSS as u32;
const WINDOW: u16 = 8192;

/// The socket table and stack live in one kernel global so both the boot demo
/// and the cap-gated syscalls drive the same instance.
static mut NETIF: NetIf = NetIf::new();
/// One heap-free contiguous TX scratch buffer (Ethernet + IPv4 assembly).
static mut TX_SCRATCH: [u8; 4096] = [0u8; 4096];
/// TCP/UDP segment assembly scratch (transport header + payload, local to the
/// send paths).
static mut SEG_SCRATCH: [u8; 2000] = [0u8; 2000];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockKind {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
}

/// One socket. The TCP send buffer holds bytes from `snd_una` (the oldest
/// unacked byte) onward; `snd_next` is the sequence number of the next byte to
/// transmit, so bytes `[snd_una, snd_next)` are in flight and the in-flight
/// count is bounded by the congestion window.
pub struct Socket {
    pub id: u16,
    pub kind: SockKind,
    pub state: TcpState,
    /// The capability-scoped destination this socket was minted for.
    pub bound_ip: [u8; 4],
    pub bound_port: u16,
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    pub remote_mac: [u8; 6],
    pub snd_una: u32,
    pub snd_next: u32,
    pub snd_seq: u32,
    pub rcv_seq: u32,
    pub snd_buf: [u8; SEND_BUFLEN],
    pub snd_len: usize,
    pub rcv_buf: [u8; RECV_BUFLEN],
    pub rcv_len: usize,
    pub last_sent_poll: u64,
    pub retrans: u32,
    pub cwnd: u32,
    pub connected: bool,
    pub peer_fin: bool,
}

pub struct NetIf {
    pub nic: Option<crate::e1000::E1000>,
    pub our_mac: [u8; 6],
    pub our_ip: [u8; 4],
    pub gw_ip: [u8; 4],
    pub arp: ArpTable,
    sockets: [Option<Socket>; MAX_SOCKETS],
    next_socket: u16,
    next_local_port: u16,
    /// The stack's monotonic software clock (poll counter).
    pub polls: u64,
}

impl NetIf {
    pub const fn new() -> NetIf {
        NetIf {
            nic: None,
            our_mac: [0; 6],
            our_ip: OUR_IP,
            gw_ip: GW_IP,
            arp: ArpTable::new(),
            sockets: [const { None }; MAX_SOCKETS],
            next_socket: 1,
            next_local_port: 40000,
            polls: 0,
        }
    }

    /// Access the global interface (mutable). The kernel is single-threaded
    /// (the boot demo runs before scheduling; the socket syscalls run with the
    /// scheduler cooperative) — the same global-mut discipline as the rest of
    /// the kernel.
    ///
    /// # Safety
    ///
    /// Callers must not hold another borrow of the interface.
    pub unsafe fn with<R>(f: impl FnOnce(&mut NetIf) -> R) -> R {
        f(&mut *core::ptr::addr_of_mut!(NETIF))
    }

    /// Probe, reset and enable the NIC; record our MAC and bring the link up.
    pub fn init(pci: &crate::pci::PciDeviceList) -> bool {
        unsafe {
            NETIF = NetIf::new();
            let mut nic = match crate::e1000::E1000::probe(pci) {
                Some(n) => n,
                None => return false,
            };
            let ok = nic.reset();
            let mac = nic.mac;
            nic.tx_enable();
            nic.rx_enable();
            let link = nic.link_up();
            NETIF.nic = Some(nic);
            NETIF.our_mac = mac;
            crate::sprintln!(
                "Aegis: e1000: reset: {} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                ok,
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
            crate::sprintln!("Aegis: e1000: link up: {}", link);
            link
        }
    }

    /// Resolve `ip` to a MAC: ARP table first, else broadcast an ARP request
    /// and poll until the reply lands (bounded). Returns the MAC.
    pub fn arp_resolve(&mut self, ip: [u8; 4]) -> Option<[u8; 6]> {
        if let Some(mac) = self.arp.lookup(&ip) {
            return Some(mac.octets);
        }
        let mut frame = [0u8; 42];
        frame[0..6].copy_from_slice(&[0xFF; 6]);
        frame[6..12].copy_from_slice(&self.our_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);
        let arp = ArpPacket {
            hw_type: HW_TYPE_ETHERNET,
            proto_type: PROTO_TYPE_IPV4,
            hw_addr_len: 6,
            proto_addr_len: 4,
            operation: ARP_REQUEST,
            sender_mac: self.our_mac,
            sender_ip: self.our_ip,
            target_mac: [0; 6],
            target_ip: ip,
        };
        frame[14..42].copy_from_slice(&arp.to_bytes());
        self.nic_mut().send(&frame);
        crate::sprintln!(
            "Aegis: netif: ARP request sent ({} bytes) for {}",
            42,
            IPv4Address::from_bytes(&ip)
        );
        let mut polls = 0;
        while polls < 10_000_000 {
            self.poll();
            if let Some(mac) = self.arp.lookup(&ip) {
                return Some(mac.octets);
            }
            polls += 1;
            unsafe { core::arch::asm!("pause", options(nomem, nostack)) };
        }
        None
    }

    fn nic_mut(&mut self) -> &mut crate::e1000::E1000 {
        self.nic.as_mut().expect("netif not initialized")
    }

    /// Transmit one IPv4 packet to `dst_ip`, the transport bytes already
    /// assembled in `payload`. Resolves `dst_ip` via ARP first.
    fn tx_ipv4(&mut self, dst_ip: [u8; 4], protocol: u8, payload: &[u8]) -> bool {
        let dst_mac = match self.arp_resolve(dst_ip) {
            Some(m) => m,
            None => return false,
        };
        let mut payload_buf = [0u8; 2000];
        payload_buf[..payload.len()].copy_from_slice(payload);
        let pkt = IPv4Packet {
            version: 4,
            ihl: 5,
            dscp_ecn: 0,
            total_length: (20 + payload.len()) as u16,
            identification: (self.polls as u16).wrapping_add(1),
            flags: 0,
            fragment_offset: 0,
            ttl: DEFAULT_TTL,
            protocol,
            checksum: 0,
            src_ip: IPv4Address::from_bytes(&self.our_ip),
            dst_ip: IPv4Address::from_bytes(&dst_ip),
            payload: &payload_buf[..payload.len()],
        };
        let scratch = unsafe { &mut *core::ptr::addr_of_mut!(TX_SCRATCH) };
        let total = match pkt.serialize(scratch) {
            Ok(t) => t,
            Err(_) => return false,
        };
        self.tx_eth(dst_mac, ETHERTYPE_IPV4, total)
    }

    /// Assemble the Ethernet header around the frame body already in
    /// `TX_SCRATCH[..total]` and transmit (or, under test, record) it.
    fn tx_eth(&mut self, dst_mac: [u8; 6], ethertype: u16, total: usize) -> bool {
        let scratch = unsafe { &mut *core::ptr::addr_of_mut!(TX_SCRATCH) };
        scratch.copy_within(0..total, 14);
        scratch[0..6].copy_from_slice(&dst_mac);
        scratch[6..12].copy_from_slice(&self.our_mac);
        scratch[12..14].copy_from_slice(&ethertype.to_be_bytes());
        let len = 14 + total;
        #[cfg(not(test))]
        {
            self.nic_mut().send(&scratch[..len])
        }
        #[cfg(test)]
        {
            TEST_TX.lock().unwrap().push(scratch[..len].to_vec());
            true
        }
    }

    /// Drain the NIC, process every received frame, then advance the poll
    /// clock (running retransmission timers).
    pub fn poll(&mut self) {
        let mut buf = [0u8; FRAME_MAX];
        let mut drained = 0u64;
        while let Some(n) = self.nic_mut().receive(&mut buf) {
            if n >= 14 {
                self.handle_frame(&buf[..n]);
            }
            drained += 1;
        }
        if drained > 0 {
            let nic = self.nic.as_mut().unwrap();
            if drained as usize == crate::e1000::RX_RING_LEN {
                nic.rx_saturated = nic.rx_saturated.wrapping_add(1);
            }
            if drained > nic.rx_max_drain {
                nic.rx_max_drain = drained;
            }
        }
        if self.polls % DIAG_EVERY == 0 {
            let (rd_h, rd_t, rx_next, p, pl, e, sat, bad, maxd, bs, bl) =
                self.nic.as_ref().unwrap().rx_stats();
            crate::sprintln!(
                "Aegis: e1000 rx: rd_h={} rd_t={} next={} packets={} polls={} empty={} sat={} bad={} max_drain={} bad_status={:#x} bad_len={}",
                rd_h, rd_t, rx_next, p, pl, e, sat, bad, maxd, bs, bl
            );
        }
        self.advance(1);
    }

    /// Advance the poll clock `polls` steps and run the retransmission timers.
    /// NIC-free: tests use this to simulate time passing.
    pub fn advance(&mut self, polls: u64) {
        for _ in 0..polls {
            self.polls = self.polls.wrapping_add(1);
            for i in 0..MAX_SOCKETS {
                self.tcp_retransmit(i);
            }
        }
    }

    fn handle_frame(&mut self, frame: &[u8]) {
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        match ethertype {
            ETHERTYPE_ARP => self.handle_arp(frame),
            ETHERTYPE_IPV4 => self.handle_ipv4(frame),
            _ => {}
        }
    }

    fn handle_arp(&mut self, frame: &[u8]) {
        let Some(arp) = ArpPacket::parse(&frame[14..]) else {
            return;
        };
        self.arp.insert(
            arp.sender_ip,
            MacAddress::from_bytes(&arp.sender_mac),
            self.polls,
        );
        if arp.operation == ARP_REQUEST && arp.target_ip == self.our_ip {
            let mut out = [0u8; 42];
            out[0..6].copy_from_slice(&arp.sender_mac);
            out[6..12].copy_from_slice(&self.our_mac);
            out[12..14].copy_from_slice(&[0x08, 0x06]);
            let reply = ArpPacket {
                hw_type: HW_TYPE_ETHERNET,
                proto_type: PROTO_TYPE_IPV4,
                hw_addr_len: 6,
                proto_addr_len: 4,
                operation: ARP_REPLY,
                sender_mac: self.our_mac,
                sender_ip: self.our_ip,
                target_mac: arp.sender_mac,
                target_ip: arp.sender_ip,
            };
            out[14..42].copy_from_slice(&reply.to_bytes());
            self.nic_mut().send(&out);
        }
    }

    fn handle_ipv4(&mut self, frame: &[u8]) {
        let Ok(pkt) = IPv4Packet::parse(&frame[14..]) else {
            return;
        };
        if !pkt.dst_ip.is_broadcast() && pkt.dst_ip.octets != self.our_ip {
            return;
        }
        let src = pkt.src_ip.octets;
        match pkt.protocol {
            PROTO_ICMP => self.handle_icmp(&frame[14..], pkt),
            PROTO_UDP => self.handle_udp(src, &frame[14..], pkt),
            PROTO_TCP => self.handle_tcp(src, &frame[14..], pkt),
            _ => {}
        }
    }

    fn handle_icmp(&mut self, _ip_start: &[u8], pkt: IPv4Packet<'_>) {
        let payload = pkt.payload;
        if payload.len() < 8 || payload[0] != 8 {
            return;
        }
        let mut out = [0u8; 512];
        out[0] = 0; // type: echo reply
        out[1] = 0; // code
        out[2..4].copy_from_slice(&[0, 0]); // checksum placeholder
        out[4..8].copy_from_slice(&payload[4..8]); // id + seq
        let body = payload.len().saturating_sub(8).min(504);
        out[8..8 + body].copy_from_slice(&payload[8..8 + body]);
        let total = 8 + body;
        let cksum = ones_complement(&out[..total]);
        out[2..4].copy_from_slice(&cksum.to_be_bytes());
        self.tx_ipv4(pkt.src_ip.octets, PROTO_ICMP, &out[..total]);
    }

    fn handle_udp(&mut self, src: [u8; 4], _ip_start: &[u8], pkt: IPv4Packet<'_>) {
        let Ok(d) = UdpDatagram::parse(pkt.payload, Some(pkt.src_ip), Some(pkt.dst_ip)) else {
            return;
        };
        let slot = self.sockets.iter().position(|s| {
            s.as_ref().is_some_and(|sock| {
                sock.kind == SockKind::Udp
                    && sock.local_port == d.dst_port
                    && (sock.remote_port == 0 || sock.remote_port == d.src_port)
                    && (sock.remote_ip == [0; 4] || sock.remote_ip == src)
            })
        });
        if let Some(i) = slot {
            let sock = self.sockets[i].as_mut().unwrap();
            let n = d.payload.len().min(RECV_BUFLEN - sock.rcv_len);
            sock.rcv_buf[sock.rcv_len..sock.rcv_len + n].copy_from_slice(&d.payload[..n]);
            sock.rcv_len += n;
        }
    }

    fn handle_tcp(&mut self, src: [u8; 4], _ip_start: &[u8], pkt: IPv4Packet<'_>) {
        let Ok(seg) = TcpSegment::parse(pkt.payload, Some(pkt.src_ip), Some(pkt.dst_ip)) else {
            return;
        };
        let slot = self.sockets.iter().position(|s| {
            s.as_ref().is_some_and(|sock| {
                sock.local_port == seg.dst_port
                    && sock.remote_port == seg.src_port
                    && sock.remote_ip == src
            })
        });
        let Some(i) = slot else { return };
        self.tcp_on_seg(i, &seg);
    }

    // ---- TCP state machine ----

    fn tcp_on_seg(&mut self, i: usize, seg: &TcpSegment<'_>) {
        let state = self.sockets[i].as_ref().unwrap().state;
        match state {
            TcpState::SynSent => {
                if seg.flags.rst {
                    self.sockets[i].as_mut().unwrap().state = TcpState::Closed;
                    return;
                }
                if !(seg.flags.syn && seg.flags.ack) {
                    return;
                }
                let iss = self.sockets[i].as_ref().unwrap().snd_seq;
                if seg.ack_num != iss.wrapping_add(1) {
                    return;
                }
                {
                    let s = self.sockets[i].as_mut().unwrap();
                    s.state = TcpState::Established;
                    s.connected = true;
                    s.snd_una = seg.ack_num;
                    s.rcv_seq = seg.seq_num.wrapping_add(1);
                    s.snd_seq = seg.ack_num;
                    s.snd_next = s.snd_seq;
                    s.last_sent_poll = self.polls;
                }
                self.tcp_send_ack(i);
                self.tcp_flush(i);
            }
            TcpState::Established => {
                if seg.flags.rst {
                    self.sockets[i].as_mut().unwrap().state = TcpState::Closed;
                    return;
                }
                if seg.flags.ack {
                    let (snd_una, snd_seq) = {
                        let s = self.sockets[i].as_ref().unwrap();
                        (s.snd_una, s.snd_seq)
                    };
                    if seq_ge(seg.ack_num, snd_una) && seg.ack_num <= snd_seq {
                        let adv = (seg.ack_num - snd_una) as usize;
                        let s = self.sockets[i].as_mut().unwrap();
                        if adv > 0 && adv <= s.snd_len {
                            s.snd_buf.copy_within(adv..s.snd_len, 0);
                            s.snd_len -= adv;
                        }
                        s.snd_una = seg.ack_num;
                        // Slow start: grow the window per ACK.
                        s.cwnd = s.cwnd.saturating_add(TCP_MSS as u32);
                        s.last_sent_poll = self.polls;
                    }
                }
                let mut needs_ack = false;
                {
                    let s = self.sockets[i].as_mut().unwrap();
                    if !seg.payload.is_empty() && seg.seq_num == s.rcv_seq {
                        let n = seg.payload.len().min(RECV_BUFLEN - s.rcv_len);
                        s.rcv_buf[s.rcv_len..s.rcv_len + n].copy_from_slice(&seg.payload[..n]);
                        s.rcv_len += n;
                        s.rcv_seq = s.rcv_seq.wrapping_add(n as u32);
                        needs_ack = true;
                    }
                    if seg.flags.fin {
                        s.peer_fin = true;
                        s.rcv_seq = s.rcv_seq.wrapping_add(1);
                        needs_ack = true;
                    }
                }
                if needs_ack {
                    self.tcp_send_ack(i);
                }
                self.tcp_flush(i);
            }
            TcpState::FinWait1 | TcpState::FinWait2 if seg.flags.fin => {
                self.tcp_send_ack(i);
                self.sockets[i].as_mut().unwrap().state = TcpState::TimeWait;
            }
            TcpState::FinWait1 => {
                if seg.flags.ack && seq_ge(seg.ack_num, self.sockets[i].as_ref().unwrap().snd_una) {
                    self.sockets[i].as_mut().unwrap().state = TcpState::FinWait2;
                }
            }
            TcpState::FinWait2 => {}
            _ => {}
        }
    }

    /// Send a pure ACK for the current receive state.
    fn tcp_send_ack(&mut self, i: usize) {
        let (local_port, remote_port, snd_seq, rcv_seq, remote_ip) = {
            let s = self.sockets[i].as_ref().unwrap();
            (
                s.local_port,
                s.remote_port,
                s.snd_seq,
                s.rcv_seq,
                s.remote_ip,
            )
        };
        let seg_buf = unsafe { &mut *core::ptr::addr_of_mut!(SEG_SCRATCH) };
        let seg = TcpSegment {
            src_port: local_port,
            dst_port: remote_port,
            seq_num: snd_seq,
            ack_num: rcv_seq,
            data_offset: 5,
            flags: TcpFlags {
                ack: true,
                ..Default::default()
            },
            window: WINDOW,
            checksum: 0,
            urgent_pointer: 0,
            options: &[],
            payload: &[],
        };
        let src_ip = IPv4Address::from_bytes(&self.our_ip);
        let dst_ip = IPv4Address::from_bytes(&remote_ip);
        let n = match seg.serialize(seg_buf, src_ip, dst_ip) {
            Ok(n) => n,
            Err(_) => return,
        };
        let _ = self.tx_ipv4(remote_ip, PROTO_TCP, &seg_buf[..n]);
    }

    /// Send queued bytes up to the congestion window.
    fn tcp_flush(&mut self, i: usize) {
        let (in_flight, window) = {
            let s = self.sockets[i].as_ref().unwrap();
            (s.snd_next.wrapping_sub(s.snd_una), s.cwnd)
        };
        if in_flight >= window {
            return;
        }
        let (unsent, offset, snd_seq, rcv_seq, remote_ip, local_port, remote_port) = {
            let s = self.sockets[i].as_ref().unwrap();
            let unsent = (s.snd_len as u32).saturating_sub(in_flight);
            (
                unsent,
                in_flight as usize,
                s.snd_seq,
                s.rcv_seq,
                s.remote_ip,
                s.local_port,
                s.remote_port,
            )
        };
        if unsent == 0 {
            return;
        }
        let n = core::cmp::min(unsent as usize, TCP_MSS);
        let mut data = [0u8; TCP_MSS];
        data[..n].copy_from_slice(&self.sockets[i].as_ref().unwrap().snd_buf[offset..offset + n]);
        let seg_buf = unsafe { &mut *core::ptr::addr_of_mut!(SEG_SCRATCH) };
        let seg = TcpSegment {
            src_port: local_port,
            dst_port: remote_port,
            seq_num: snd_seq,
            ack_num: rcv_seq,
            data_offset: 5,
            flags: TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            window: WINDOW,
            checksum: 0,
            urgent_pointer: 0,
            options: &[],
            payload: &data[..n],
        };
        let src_ip = IPv4Address::from_bytes(&self.our_ip);
        let dst_ip = IPv4Address::from_bytes(&remote_ip);
        let m = match seg.serialize(seg_buf, src_ip, dst_ip) {
            Ok(m) => m,
            Err(_) => return,
        };
        let ok = self.tx_ipv4(remote_ip, PROTO_TCP, &seg_buf[..m]);
        if ok {
            let s = self.sockets[i].as_mut().unwrap();
            s.snd_next = s.snd_next.wrapping_add(n as u32);
            s.snd_seq = s.snd_next;
            s.last_sent_poll = self.polls;
        }
    }

    /// Retransmit an unacked segment (SYN, or in-flight data) after RTO with
    /// no ACK. Bounded by MAX_RETRANSMIT.
    fn tcp_retransmit(&mut self, i: usize) {
        let Some(s) = self.sockets[i].as_ref() else {
            return;
        };
        let (kind, state, retrans, elapsed) = (
            s.kind,
            s.state,
            s.retrans,
            self.polls.wrapping_sub(s.last_sent_poll),
        );
        if kind != SockKind::Tcp || retrans >= MAX_RETRANSMIT || elapsed < RTO_POLLS {
            return;
        }
        match state {
            TcpState::SynSent => {
                let (local_port, remote_port, remote_ip, snd_seq) = {
                    let s = self.sockets[i].as_ref().unwrap();
                    (s.local_port, s.remote_port, s.remote_ip, s.snd_seq)
                };
                let seg_buf = unsafe { &mut *core::ptr::addr_of_mut!(SEG_SCRATCH) };
                let seg = TcpSegment {
                    src_port: local_port,
                    dst_port: remote_port,
                    seq_num: snd_seq,
                    ack_num: 0,
                    data_offset: 5,
                    flags: TcpFlags {
                        syn: true,
                        ..Default::default()
                    },
                    window: WINDOW,
                    checksum: 0,
                    urgent_pointer: 0,
                    options: &[],
                    payload: &[],
                };
                let src_ip = IPv4Address::from_bytes(&self.our_ip);
                let dst_ip = IPv4Address::from_bytes(&remote_ip);
                let n = match seg.serialize(seg_buf, src_ip, dst_ip) {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let _ = self.tx_ipv4(remote_ip, PROTO_TCP, &seg_buf[..n]);
                let s = self.sockets[i].as_mut().unwrap();
                s.retrans += 1;
                s.last_sent_poll = self.polls;
            }
            TcpState::Established | TcpState::FinWait1 => {
                let (remote_ip, local_port, remote_port, snd_una, rcv_seq, snd_next, snd_len) = {
                    let s = self.sockets[i].as_ref().unwrap();
                    (
                        s.remote_ip,
                        s.local_port,
                        s.remote_port,
                        s.snd_una,
                        s.rcv_seq,
                        s.snd_next,
                        s.snd_len,
                    )
                };
                let in_flight = snd_next.wrapping_sub(snd_una) as usize;
                if in_flight == 0 {
                    return;
                }
                let n = in_flight.min(snd_len);
                let mut data = [0u8; TCP_MSS];
                data[..n].copy_from_slice(&self.sockets[i].as_ref().unwrap().snd_buf[..n]);
                let seg_buf = unsafe { &mut *core::ptr::addr_of_mut!(SEG_SCRATCH) };
                let seg = TcpSegment {
                    src_port: local_port,
                    dst_port: remote_port,
                    seq_num: snd_una,
                    ack_num: rcv_seq,
                    data_offset: 5,
                    flags: TcpFlags {
                        ack: true,
                        psh: true,
                        ..Default::default()
                    },
                    window: WINDOW,
                    checksum: 0,
                    urgent_pointer: 0,
                    options: &[],
                    payload: &data[..n],
                };
                let src_ip = IPv4Address::from_bytes(&self.our_ip);
                let dst_ip = IPv4Address::from_bytes(&remote_ip);
                let m = match seg.serialize(seg_buf, src_ip, dst_ip) {
                    Ok(m) => m,
                    Err(_) => return,
                };
                let _ = self.tx_ipv4(remote_ip, PROTO_TCP, &seg_buf[..m]);
                let s = self.sockets[i].as_mut().unwrap();
                s.retrans += 1;
                s.last_sent_poll = self.polls;
            }
            _ => {}
        }
    }

    fn socket_index(&self, id: u16) -> Option<usize> {
        self.sockets
            .iter()
            .position(|s| s.as_ref().is_some_and(|sock| sock.id == id))
    }

    /// The destination a socket is bound to — its capability scope — if the
    /// socket still exists. There is no corresponding setter: a socket's
    /// binding is fixed at `socket_open` and nothing in this module ever
    /// changes it. Exposed for tests and audit tooling to verify a
    /// `NetEndpoint` capability's binding without touching the socket's live
    /// transport state.
    pub fn socket_remote(&self, id: u16) -> Option<([u8; 4], u16)> {
        self.socket_index(id).map(|i| {
            (
                self.sockets[i].as_ref().unwrap().remote_ip,
                self.sockets[i].as_ref().unwrap().remote_port,
            )
        })
    }

    /// The current TCP state of a socket, or `None` if it does not exist.
    pub fn socket_state(&self, id: u16) -> Option<TcpState> {
        let i = self.socket_index(id)?;
        Some(self.sockets[i].as_ref().unwrap().state)
    }

    /// True once a TCP socket has completed its three-way handshake.
    pub fn socket_connected(&self, id: u16) -> bool {
        self.socket_index(id)
            .is_some_and(|i| self.sockets[i].as_ref().unwrap().connected)
    }

    // ---- socket API (shared by the boot demo and the cap-gated syscalls) ----

    /// Mint a new socket bound to exactly one destination. Returns
    /// `(socket_id, local_port)`.
    /// Open a socket bound to exactly one destination. `local_port` lets the
    /// caller bind a fixed local port (used by the Phase I fleet link, where
    /// two peers rendezvous on a well-known port without a control channel);
    /// `None` auto-assigns the next ephemeral port as before.
    pub fn socket_open(
        &mut self,
        kind: SockKind,
        remote_ip: [u8; 4],
        remote_port: u16,
        local_port: Option<u16>,
    ) -> Option<(u16, u16)> {
        let i = self.sockets.iter().position(|s| s.is_none())?;
        let id = self.next_socket;
        self.next_socket = self.next_socket.wrapping_add(1);
        let local_port = match local_port {
            Some(p) => p,
            None => {
                let p = self.next_local_port;
                self.next_local_port = self.next_local_port.wrapping_add(1);
                p
            }
        };
        self.sockets[i] = Some(Socket {
            id,
            kind,
            state: TcpState::Closed,
            bound_ip: remote_ip,
            bound_port: remote_port,
            local_port,
            remote_ip,
            remote_port,
            remote_mac: [0; 6],
            snd_una: 0,
            snd_next: 0,
            snd_seq: 0,
            rcv_seq: 0,
            snd_buf: [0; SEND_BUFLEN],
            snd_len: 0,
            rcv_buf: [0; RECV_BUFLEN],
            rcv_len: 0,
            last_sent_poll: 0,
            retrans: 0,
            cwnd: CWND_INIT,
            connected: false,
            peer_fin: false,
        });
        Some((id, local_port))
    }

    /// Connect a TCP socket: resolve the peer, send SYN, enter SYN-SENT.
    pub fn tcp_connect(&mut self, id: u16) -> bool {
        let Some(i) = self.socket_index(id) else {
            return false;
        };
        let remote_ip = self.sockets[i].as_ref().unwrap().remote_ip;
        let mac = match self.arp_resolve(remote_ip) {
            Some(m) => m,
            None => return false,
        };
        let iss = (self.polls as u32)
            .wrapping_mul(2654435761)
            .wrapping_add(id as u32 * 7);
        {
            let s = self.sockets[i].as_mut().unwrap();
            s.remote_mac = mac;
            s.snd_seq = iss;
            s.snd_una = iss;
            s.snd_next = iss;
            s.state = TcpState::SynSent;
            s.last_sent_poll = self.polls;
            s.retrans = 0;
        }
        let (local_port, remote_port, snd_seq) = {
            let s = self.sockets[i].as_ref().unwrap();
            (s.local_port, s.remote_port, s.snd_seq)
        };
        let seg_buf = unsafe { &mut *core::ptr::addr_of_mut!(SEG_SCRATCH) };
        let seg = TcpSegment {
            src_port: local_port,
            dst_port: remote_port,
            seq_num: snd_seq,
            ack_num: 0,
            data_offset: 5,
            flags: TcpFlags {
                syn: true,
                ..Default::default()
            },
            window: WINDOW,
            checksum: 0,
            urgent_pointer: 0,
            options: &[],
            payload: &[],
        };
        let src_ip = IPv4Address::from_bytes(&self.our_ip);
        let dst_ip = IPv4Address::from_bytes(&remote_ip);
        let n = match seg.serialize(seg_buf, src_ip, dst_ip) {
            Ok(n) => n,
            Err(_) => return false,
        };
        self.tx_ipv4(remote_ip, PROTO_TCP, &seg_buf[..n])
    }

    /// Queue bytes on a TCP (or UDP) socket and transmit what the window
    /// allows. Returns the number of bytes queued.
    pub fn socket_send(&mut self, id: u16, data: &[u8]) -> usize {
        let Some(i) = self.socket_index(id) else {
            return 0;
        };
        let (kind, established) = {
            let s = self.sockets[i].as_ref().unwrap();
            (s.kind, s.state == TcpState::Established)
        };
        match kind {
            SockKind::Tcp => {
                let base = self.sockets[i].as_ref().unwrap().snd_len;
                let n = data.len().min(SEND_BUFLEN - base);
                {
                    let s = self.sockets[i].as_mut().unwrap();
                    s.snd_buf[base..base + n].copy_from_slice(&data[..n]);
                    s.snd_len += n;
                }
                if established {
                    self.tcp_flush(i);
                }
                n
            }
            SockKind::Udp => {
                let (local_port, remote_port, remote_ip) = {
                    let s = self.sockets[i].as_ref().unwrap();
                    (s.local_port, s.remote_port, s.remote_ip)
                };
                let n = data.len().min(1200);
                let seg_buf = unsafe { &mut *core::ptr::addr_of_mut!(SEG_SCRATCH) };
                let d = UdpDatagram {
                    src_port: local_port,
                    dst_port: remote_port,
                    length: (8 + n) as u16,
                    checksum: 0,
                    payload: &data[..n],
                };
                let src_ip = IPv4Address::from_bytes(&self.our_ip);
                let dst_ip = IPv4Address::from_bytes(&remote_ip);
                let m = match d.serialize(seg_buf, src_ip, dst_ip) {
                    Ok(m) => m,
                    Err(_) => return 0,
                };
                let _ = self.tx_ipv4(remote_ip, PROTO_UDP, &seg_buf[..m]);
                n
            }
        }
    }

    /// Pop received bytes. `None` when nothing is buffered.
    pub fn socket_recv(&mut self, id: u16, out: &mut [u8]) -> Option<usize> {
        let i = self.socket_index(id)?;
        let rcv_len = self.sockets[i].as_ref().unwrap().rcv_len;
        if rcv_len == 0 {
            return None;
        }
        let n = rcv_len.min(out.len());
        {
            let s = self.sockets[i].as_mut().unwrap();
            out[..n].copy_from_slice(&s.rcv_buf[..n]);
            s.rcv_buf.copy_within(n..s.rcv_len, 0);
            s.rcv_len -= n;
        }
        Some(n)
    }

    /// Close a socket: TCP sends FIN; the slot is freed.
    pub fn socket_close(&mut self, id: u16) -> bool {
        let Some(i) = self.socket_index(id) else {
            return false;
        };
        let (kind, state) = {
            let s = self.sockets[i].as_ref().unwrap();
            (s.kind, s.state)
        };
        if kind == SockKind::Tcp && state == TcpState::Established {
            let (local_port, remote_port, snd_seq, rcv_seq, remote_ip) = {
                let s = self.sockets[i].as_ref().unwrap();
                (
                    s.local_port,
                    s.remote_port,
                    s.snd_seq,
                    s.rcv_seq,
                    s.remote_ip,
                )
            };
            let seg_buf = unsafe { &mut *core::ptr::addr_of_mut!(SEG_SCRATCH) };
            let fin = TcpSegment {
                src_port: local_port,
                dst_port: remote_port,
                seq_num: snd_seq,
                ack_num: rcv_seq,
                data_offset: 5,
                flags: TcpFlags {
                    ack: true,
                    fin: true,
                    ..Default::default()
                },
                window: WINDOW,
                checksum: 0,
                urgent_pointer: 0,
                options: &[],
                payload: &[],
            };
            let src_ip = IPv4Address::from_bytes(&self.our_ip);
            let dst_ip = IPv4Address::from_bytes(&remote_ip);
            let n = match fin.serialize(seg_buf, src_ip, dst_ip) {
                Ok(n) => n,
                Err(_) => return false,
            };
            let _ = self.tx_ipv4(remote_ip, PROTO_TCP, &seg_buf[..n]);
            let s = self.sockets[i].as_mut().unwrap();
            s.state = TcpState::FinWait1;
            s.snd_seq = s.snd_seq.wrapping_add(1);
            s.snd_next = s.snd_seq;
            s.last_sent_poll = self.polls;
        }
        self.sockets[i] = None;
        true
    }
}

impl Default for NetIf {
    fn default() -> Self {
        Self::new()
    }
}

/// Ones'-complement checksum (RFC 1071), as used by ICMP.
pub fn ones_complement(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn seq_ge(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) < 0x8000_0000
}

/// Phase F: mint a TCP socket bound to the one kernel-declared advisor host
/// (`ADVISOR_HOST_IP`/`ADVISOR_HOST_PORT`), never to a caller-chosen
/// destination. This is the mint path `role::role_grant` uses for the
/// `query-advisor` role — the agent never calls `sys_net_socket` itself for
/// this capability, so it never gets to name the destination. Returns the new
/// socket id, or `None` if the socket table is full.
pub fn open_advisor_endpoint() -> Option<u16> {
    unsafe { &mut *core::ptr::addr_of_mut!(NETIF) }
        .socket_open(SockKind::Tcp, ADVISOR_HOST_IP, ADVISOR_HOST_PORT, None)
        .map(|(id, _local_port)| id)
}

/// The live destination bound to socket `id` on the shared kernel netif, if
/// it still exists. Read-only; there is no way to change a socket's binding
/// through this or any other entry point.
pub fn socket_remote(id: u16) -> Option<([u8; 4], u16)> {
    unsafe { &*core::ptr::addr_of!(NETIF) }.socket_remote(id)
}

// ---- capability-gated socket syscalls ----

/// Phase F closure (master roadmap Phase E item 2, the gap this project's
/// own honest-status notes flagged: "`sys_net_socket` has zero capability
/// gating — any task can mint a socket to any host directly"). Grant the
/// `NetRoot` capability that authorizes calling `sys_net_socket` at all.
///
/// This is deliberately **not** a syscall — there is no `dispatch` case
/// that reaches it, and no task can call it on its own. It exists purely
/// as kernel/boot-time policy: whoever wires up the boot sequence decides,
/// once, which task (if any) is the trusted netstack owner allowed to open
/// sockets to caller-chosen destinations, and installs `NetRoot` into that
/// one task's CSpace before it starts running untrusted code. Every other
/// task starts, and stays, with no way to reach `sys_net_socket`
/// successfully — the only network capability an ordinary task can ever
/// hold is one the kernel pre-binds for it, the way `role_grant`'s
/// `query-advisor` path already works.
///
/// Returns `false` (no cap installed) if `task` or `slot` is out of range,
/// or the slot is already occupied — the same "never silently overwrite a
/// live capability" discipline every other mint path in this kernel
/// follows.
pub fn grant_net_root(task: usize, slot: usize) -> bool {
    use crate::cap::{Cap, CapSlot, NET_ROOT_RIGHTS};
    if task >= crate::tasks::MAX_TASKS || slot >= crate::tasks::MAX_CAPS {
        return false;
    }
    if crate::tasks::task_cap(task, slot).cap != Cap::None {
        return false;
    }
    crate::tasks::set_task_cap(
        task,
        slot,
        CapSlot {
            cap: Cap::NetRoot,
            rights: NET_ROOT_RIGHTS,
        },
    );
    true
}

/// `net_socket(kind, ip_packed, port) -> cap slot` — mint a NetEndpoint cap
/// bound to one destination and install it in the caller's CSpace.
/// `kind` 1 = TCP, 2 = UDP.
///
/// Gated on `Cap::NetRoot` with `NET_ROOT_RIGHTS` (CONTROL): the caller
/// must hold that capability, in any slot, before it is allowed to name a
/// destination at all. A task with none — the default for everything
/// except whatever boot-time policy installed it via `grant_net_root` — is
/// refused here, at the kernel gate, not by any convention the caller is
/// trusted to follow. This is what closes the "ambient network access"
/// gap: "no capability, no socket" is now enforced the same way "no
/// capability, no IPC" and "no capability, no memory" already were.
///
/// Every attempt — granted or refused — is attributed in the kernel audit
/// log (`OpKind::NetOpen`), target = the packed destination the caller
/// asked for, so a denied mint is still traceable to what it tried to
/// reach.
///
/// # Safety
///
/// Called from the syscall dispatcher with caller-controlled raw arguments.
pub unsafe fn sys_net_socket(kind: u64, ip_packed: u64, port: u64) -> i64 {
    use crate::cap::{Cap, CapSlot, NET_RIGHTS, NET_ROOT_RIGHTS};
    let cur = crate::tasks::current_idx();
    // Target attributed in the audit log: the destination the caller
    // asked for, packed the same way `role::role_grant`'s network-scoped
    // path attributes its own target — traceable even on denial.
    let dest_target = (ip_packed as u32) ^ ((port as u32) << 16);
    let record =
        |ok: bool| crate::audit::record(cur, crate::audit::OpKind::NetOpen, Some(dest_target), ok);

    let kind = match kind {
        1 => SockKind::Tcp,
        2 => SockKind::Udp,
        _ => {
            record(false);
            return -1;
        }
    };
    // The capability gate: the caller must hold Cap::NetRoot with CONTROL
    // in *some* slot. Search, don't assume a fixed slot — the same pattern
    // every other "does the caller hold X" check in this kernel uses.
    let has_net_root = (0..crate::tasks::MAX_CAPS).any(|s| {
        let cs = crate::tasks::task_cap(cur, s);
        cs.cap == Cap::NetRoot && cs.rights.contains(NET_ROOT_RIGHTS)
    });
    if !has_net_root {
        record(false);
        return -1;
    }
    let ip = [
        (ip_packed >> 24) as u8,
        (ip_packed >> 16) as u8,
        (ip_packed >> 8) as u8,
        ip_packed as u8,
    ];
    let slot =
        (0..crate::tasks::MAX_CAPS).find(|&s| crate::tasks::task_cap(cur, s).cap == Cap::None);
    let Some(slot) = slot else {
        record(false);
        return -1;
    };
    let Some((id, _lp)) =
        unsafe { &mut *core::ptr::addr_of_mut!(NETIF) }.socket_open(kind, ip, port as u16, None)
    else {
        record(false);
        return -1;
    };
    crate::tasks::set_task_cap(
        cur,
        slot,
        CapSlot {
            cap: Cap::NetEndpoint(id as u32),
            rights: NET_RIGHTS,
        },
    );
    record(true);
    slot as i64
}

/// `net_connect(slot) -> 0/-1` — SEND-gated; connects to the cap's bound
/// destination.
///
/// # Safety
///
/// Called from the syscall dispatcher with caller-controlled raw arguments.
pub unsafe fn sys_net_connect(slot: u64) -> i64 {
    use crate::cap::{Cap, Rights};
    let cur = crate::tasks::current_idx();
    let cap = crate::tasks::task_cap(cur, slot as usize);
    let Cap::NetEndpoint(id) = cap.cap else {
        crate::audit::record(cur, crate::audit::OpKind::NetIo, None, false);
        return -1;
    };
    if !cap.rights.contains(Rights::SEND) {
        crate::audit::record(cur, crate::audit::OpKind::NetIo, Some(id), false);
        return -1;
    }
    let netif = unsafe { &mut *core::ptr::addr_of_mut!(NETIF) };
    let ok = netif.tcp_connect(id as u16);
    crate::audit::record(cur, crate::audit::OpKind::NetIo, Some(id), ok);
    if ok {
        0
    } else {
        -1
    }
}

/// `net_send(slot, va, len) -> n/-1` — SEND-gated; queues bytes on the socket.
///
/// # Safety
///
/// Called from the syscall dispatcher with caller-controlled raw arguments.
pub unsafe fn sys_net_send(slot: u64, va: u64, len: u64) -> i64 {
    use crate::cap::{Cap, Rights};
    let cur = crate::tasks::current_idx();
    let cap = crate::tasks::task_cap(cur, slot as usize);
    let Cap::NetEndpoint(id) = cap.cap else {
        crate::audit::record(cur, crate::audit::OpKind::NetIo, None, false);
        return -1;
    };
    if !cap.rights.contains(Rights::SEND) {
        crate::audit::record(cur, crate::audit::OpKind::NetIo, Some(id), false);
        return -1;
    }
    let len = core::cmp::min(len as usize, 2048);
    let data = core::slice::from_raw_parts(va as *const u8, len);
    let n = unsafe { &mut *core::ptr::addr_of_mut!(NETIF) }.socket_send(id as u16, data);
    crate::audit::record(cur, crate::audit::OpKind::NetIo, Some(id), n > 0);
    n as i64
}

/// `net_recv(slot, va, len) -> n/0/-1` — RECV-gated; drains the socket buffer.
///
/// # Safety
///
/// Called from the syscall dispatcher with caller-controlled raw arguments.
pub unsafe fn sys_net_recv(slot: u64, va: u64, len: u64) -> i64 {
    use crate::cap::{Cap, Rights};
    let cur = crate::tasks::current_idx();
    let cap = crate::tasks::task_cap(cur, slot as usize);
    let Cap::NetEndpoint(id) = cap.cap else {
        crate::audit::record(cur, crate::audit::OpKind::NetIo, None, false);
        return -1;
    };
    if !cap.rights.contains(Rights::RECV) {
        crate::audit::record(cur, crate::audit::OpKind::NetIo, Some(id), false);
        return -1;
    }
    let len = core::cmp::min(len as usize, 2048);
    let out = core::slice::from_raw_parts_mut(va as *mut u8, len);
    let result = unsafe { &mut *core::ptr::addr_of_mut!(NETIF) }.socket_recv(id as u16, out);
    // Both `Some(n)` and `None` (no bytes currently buffered) are an
    // authorized, successful poll of a cap the caller legitimately holds —
    // the syscall itself never returns an error code here, so the audit
    // record agrees: `ok=true` whenever the capability gate above passed.
    crate::audit::record(cur, crate::audit::OpKind::NetIo, Some(id), true);
    match result {
        Some(n) => n as i64,
        None => 0,
    }
}

/// `net_close(slot) -> 0/-1` — closes the socket and clears the cap slot.
///
/// # Safety
///
/// Called from the syscall dispatcher with caller-controlled raw arguments.
pub unsafe fn sys_net_close(slot: u64) -> i64 {
    use crate::cap::{Cap, CapSlot};
    let cur = crate::tasks::current_idx();
    let cap = crate::tasks::task_cap(cur, slot as usize);
    let Cap::NetEndpoint(id) = cap.cap else {
        crate::audit::record(cur, crate::audit::OpKind::NetIo, None, false);
        return -1;
    };
    let ok = unsafe { &mut *core::ptr::addr_of_mut!(NETIF) }.socket_close(id as u16);
    crate::tasks::set_task_cap(cur, slot as usize, CapSlot::empty());
    crate::audit::record(cur, crate::audit::OpKind::NetIo, Some(id), ok);
    if ok {
        0
    } else {
        -1
    }
}

/// Test-only: every frame the stack transmits is recorded here. Protected by a
/// mutex and serialized with the crate-wide kernel-state guard, so a test can
/// clear and then assert on its own transmissions.
#[cfg(test)]
static TEST_TX: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::Cap;

    /// Feed a crafted IPv4 packet to the stack as if it arrived on the wire.
    fn deliver_ipv4(net: &mut NetIf, src_ip: [u8; 4], protocol: u8, payload: &[u8]) {
        let mut buf = [0u8; FRAME_MAX];
        let pkt = IPv4Packet {
            version: 4,
            ihl: 5,
            dscp_ecn: 0,
            total_length: (20 + payload.len()) as u16,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol,
            checksum: 0,
            src_ip: IPv4Address::from_bytes(&src_ip),
            dst_ip: IPv4Address::from_bytes(&net.our_ip),
            payload,
        };
        let n = pkt.serialize(&mut buf[14..]).unwrap_or(0);
        buf[0..6].copy_from_slice(&GW_MAC);
        buf[6..12].copy_from_slice(&net.our_mac);
        buf[12..14].copy_from_slice(&[0x08, 0x00]);
        net.handle_frame(&buf[..14 + n]);
    }

    /// Feed a crafted TCP segment to the stack.
    #[allow(clippy::too_many_arguments)]
    fn deliver_tcp(
        net: &mut NetIf,
        src_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) {
        let mut buf = [0u8; FRAME_MAX];
        let seg = TcpSegment {
            src_port,
            dst_port,
            seq_num: seq,
            ack_num: ack,
            data_offset: 5,
            flags,
            window: WINDOW,
            checksum: 0,
            urgent_pointer: 0,
            options: &[],
            payload,
        };
        let n = seg
            .serialize(
                &mut buf[34..],
                IPv4Address::from_bytes(&src_ip),
                IPv4Address::from_bytes(&net.our_ip),
            )
            .unwrap_or(0);
        let mut ipv4 = [0u8; FRAME_MAX];
        let pkt = IPv4Packet {
            version: 4,
            ihl: 5,
            dscp_ecn: 0,
            total_length: (20 + n) as u16,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: PROTO_TCP,
            checksum: 0,
            src_ip: IPv4Address::from_bytes(&src_ip),
            dst_ip: IPv4Address::from_bytes(&net.our_ip),
            payload: &buf[34..34 + n],
        };
        let m = pkt.serialize(&mut ipv4).unwrap_or(0);
        buf[14..14 + m].copy_from_slice(&ipv4[..m]);
        buf[0..6].copy_from_slice(&GW_MAC);
        buf[6..12].copy_from_slice(&net.our_mac);
        buf[12..14].copy_from_slice(&[0x08, 0x00]);
        net.handle_frame(&buf[..14 + m]);
    }

    /// Feed a crafted UDP datagram to the stack.
    fn deliver_udp(net: &mut NetIf, src_ip: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) {
        let mut buf = [0u8; FRAME_MAX];
        let d = UdpDatagram {
            src_port,
            dst_port,
            length: (8 + payload.len()) as u16,
            checksum: 0,
            payload,
        };
        let n = d
            .serialize(
                &mut buf[34..],
                IPv4Address::from_bytes(&src_ip),
                IPv4Address::from_bytes(&net.our_ip),
            )
            .unwrap_or(0);
        let mut ipv4 = [0u8; FRAME_MAX];
        let pkt = IPv4Packet {
            version: 4,
            ihl: 5,
            dscp_ecn: 0,
            total_length: (20 + n) as u16,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: PROTO_UDP,
            checksum: 0,
            src_ip: IPv4Address::from_bytes(&src_ip),
            dst_ip: IPv4Address::from_bytes(&net.our_ip),
            payload: &buf[34..34 + n],
        };
        let m = pkt.serialize(&mut ipv4).unwrap_or(0);
        buf[14..14 + m].copy_from_slice(&ipv4[..m]);
        buf[0..6].copy_from_slice(&GW_MAC);
        buf[6..12].copy_from_slice(&net.our_mac);
        buf[12..14].copy_from_slice(&[0x08, 0x00]);
        net.handle_frame(&buf[..14 + m]);
    }

    fn setup() -> NetIf {
        let mut net = NetIf::new();
        net.our_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        net.our_ip = OUR_IP;
        net.gw_ip = GW_IP;
        net.arp.insert(GW_IP, MacAddress::from_bytes(&GW_MAC), 0);
        net
    }

    fn clear_tx() {
        TEST_TX.lock().unwrap().clear();
    }

    fn tx_log() -> Vec<Vec<u8>> {
        TEST_TX.lock().unwrap().clone()
    }

    #[test]
    fn arp_resolve_from_table() {
        let _g = crate::kernel_state_guard();
        let mut net = setup();
        assert_eq!(
            net.arp_resolve(GW_IP),
            Some(GW_MAC),
            "resolves the gateway from the ARP table without sending"
        );
        assert_eq!(
            net.arp.lookup(&GW_IP),
            Some(MacAddress::from_bytes(&GW_MAC))
        );
    }

    #[test]
    fn tcp_handshake_syn_ack_establishes() {
        let _g = crate::kernel_state_guard();
        clear_tx();
        let mut net = setup();
        let (id, _lp) = net.socket_open(SockKind::Tcp, GW_IP, 8080, None).unwrap();
        assert!(net.tcp_connect(id));
        assert_eq!(net.sockets[0].as_ref().unwrap().state, TcpState::SynSent);
        // The SYN went out: eth + ipv4 + tcp, SYN set, ACK clear.
        let frames = tx_log();
        assert_eq!(frames.len(), 1);
        let seg = TcpSegment::parse(&frames[0][34..], None, None).unwrap();
        assert!(seg.flags.syn && !seg.flags.ack);
        let iss = seg.seq_num;
        // Peer SYN-ACK: ack = iss+1, seq = peer ISN. Its dst port is our local
        // port (the SYN's source port).
        deliver_tcp(
            &mut net,
            GW_IP,
            8080,
            seg.src_port,
            9000,
            iss.wrapping_add(1),
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            &[],
        );
        let sock = net.sockets[0].as_ref().unwrap();
        assert_eq!(sock.state, TcpState::Established);
        assert!(sock.connected);
        assert_eq!(sock.rcv_seq, 9001);
        assert_eq!(sock.snd_una, iss.wrapping_add(1));
        assert_eq!(tx_log().len(), 2, "SYN + post-handshake ACK");
    }

    #[test]
    fn tcp_retransmits_syn_after_rto() {
        let _g = crate::kernel_state_guard();
        clear_tx();
        let mut net = setup();
        let (id, _lp) = net.socket_open(SockKind::Tcp, GW_IP, 8080, None).unwrap();
        assert!(net.tcp_connect(id));
        assert_eq!(tx_log().len(), 1);
        net.advance(RTO_POLLS - 1);
        assert_eq!(tx_log().len(), 1, "no retransmit before RTO");
        net.advance(1);
        assert_eq!(tx_log().len(), 2, "SYN retransmitted after RTO");
        assert_eq!(net.sockets[0].as_ref().unwrap().retrans, 1);
    }

    #[test]
    fn tcp_data_retransmitted_when_unacked() {
        let _g = crate::kernel_state_guard();
        clear_tx();
        let mut net = setup();
        let (id, _lp) = net.socket_open(SockKind::Tcp, GW_IP, 8080, None).unwrap();
        assert!(net.tcp_connect(id));
        let frames = tx_log();
        let seg = TcpSegment::parse(&frames[0][34..], None, None).unwrap();
        let iss = seg.seq_num;
        let local_port = seg.src_port;
        deliver_tcp(
            &mut net,
            GW_IP,
            8080,
            local_port,
            9000,
            iss.wrapping_add(1),
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            &[],
        );
        assert_eq!(net.socket_send(id, b"data"), 4);
        assert_eq!(tx_log().len(), 3, "SYN, handshake ACK, data");
        let before = tx_log().len();
        // ACK the data: ack = iss+5.
        deliver_tcp(
            &mut net,
            GW_IP,
            8080,
            local_port,
            9001,
            iss.wrapping_add(5),
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            &[],
        );
        assert_eq!(
            net.sockets[0].as_ref().unwrap().snd_len,
            0,
            "acked data freed"
        );
        net.advance(RTO_POLLS);
        assert_eq!(tx_log().len(), before, "no retransmit once acked");
    }

    #[test]
    fn tcp_receives_data_and_acks() {
        let _g = crate::kernel_state_guard();
        clear_tx();
        let mut net = setup();
        let (id, _lp) = net.socket_open(SockKind::Tcp, GW_IP, 8080, None).unwrap();
        assert!(net.tcp_connect(id));
        let frames = tx_log();
        let seg = TcpSegment::parse(&frames[0][34..], None, None).unwrap();
        let iss = seg.seq_num;
        let local_port = seg.src_port;
        deliver_tcp(
            &mut net,
            GW_IP,
            8080,
            local_port,
            9000,
            iss.wrapping_add(1),
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            &[],
        );
        // Peer sends 11 bytes at its sequence.
        deliver_tcp(
            &mut net,
            GW_IP,
            8080,
            local_port,
            9001,
            iss.wrapping_add(1),
            TcpFlags {
                ack: true,
                psh: true,
                ..Default::default()
            },
            b"hello world",
        );
        let mut out = [0u8; 64];
        let n = net.socket_recv(id, &mut out).unwrap();
        assert_eq!(&out[..n], b"hello world");
        assert_eq!(net.sockets[0].as_ref().unwrap().rcv_seq, 9012);
        assert_eq!(tx_log().len(), 3, "SYN, handshake ACK, data ACK");
    }

    #[test]
    fn udp_send_recv_roundtrip() {
        let _g = crate::kernel_state_guard();
        clear_tx();
        let mut net = setup();
        let (id, _lp) = net.socket_open(SockKind::Udp, GW_IP, 9999, None).unwrap();
        assert_eq!(net.socket_send(id, b"ping"), 4);
        let frames = tx_log();
        let d = UdpDatagram::parse(&frames[0][34..], None, None).unwrap();
        assert_eq!(d.dst_port, 9999);
        assert_eq!(d.payload, b"ping");
        let local_port = net.sockets[0].as_ref().unwrap().local_port;
        deliver_udp(&mut net, GW_IP, 9999, local_port, b"pong");
        let mut out = [0u8; 64];
        let n = net.socket_recv(id, &mut out).unwrap();
        assert_eq!(&out[..n], b"pong");
    }

    #[test]
    fn icmp_echo_reply_is_built() {
        let _g = crate::kernel_state_guard();
        clear_tx();
        let mut net = setup();
        let mut icmp = [0u8; 12];
        icmp[0] = 8; // echo request
        icmp[4..6].copy_from_slice(&[0xAB, 0xCD]); // id
        icmp[6..8].copy_from_slice(&[0x00, 0x01]); // seq
        let cksum = ones_complement(&icmp);
        icmp[2..4].copy_from_slice(&cksum.to_be_bytes());
        deliver_ipv4(&mut net, GW_IP, PROTO_ICMP, &icmp);
        let frames = tx_log();
        assert_eq!(frames.len(), 1);
        let pkt = IPv4Packet::parse(&frames[0][14..]).unwrap();
        assert_eq!(pkt.protocol, PROTO_ICMP);
        assert_eq!(pkt.payload[0], 0, "echo reply type");
        assert_eq!(pkt.payload[4..8], [0xAB, 0xCD, 0x00, 0x01], "id+seq echoed");
    }

    #[test]
    fn cwnd_grows_on_acks() {
        let _g = crate::kernel_state_guard();
        clear_tx();
        let mut net = setup();
        let (id, _lp) = net.socket_open(SockKind::Tcp, GW_IP, 8080, None).unwrap();
        assert!(net.tcp_connect(id));
        let frames = tx_log();
        let seg = TcpSegment::parse(&frames[0][34..], None, None).unwrap();
        let iss = seg.seq_num;
        deliver_tcp(
            &mut net,
            GW_IP,
            8080,
            seg.src_port,
            9000,
            iss.wrapping_add(1),
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            },
            &[],
        );
        let before = net.sockets[0].as_ref().unwrap().cwnd;
        deliver_tcp(
            &mut net,
            GW_IP,
            8080,
            seg.src_port,
            9001,
            iss.wrapping_add(1),
            TcpFlags {
                ack: true,
                ..Default::default()
            },
            &[],
        );
        assert!(net.sockets[0].as_ref().unwrap().cwnd > before);
    }

    #[test]
    fn capability_gating_denies_capless_task() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        for s in 0..crate::tasks::MAX_CAPS {
            crate::tasks::set_task_cap(3, s, crate::cap::CapSlot::empty());
        }
        crate::tasks::set_current_for_test(3);
        let denied = unsafe {
            (
                sys_net_connect(0),
                sys_net_send(0, 0, 4),
                sys_net_recv(0, 0, 4),
                sys_net_close(0),
            )
        };
        assert_eq!(denied, (-1, -1, -1, -1), "no cap -> every op denied");
    }

    /// Phase F / Phase E item 2 closure: a task holding zero capabilities —
    /// the default for everything except whatever boot policy explicitly
    /// calls `grant_net_root` — cannot mint a socket to ANY destination.
    /// This is the actual headline result for this fix: "no ambient network
    /// access" was previously false (any task could call `sys_net_socket`
    /// directly); this test is what makes it true.
    #[test]
    fn net_socket_denies_task_without_net_root() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        for s in 0..crate::tasks::MAX_CAPS {
            crate::tasks::set_task_cap(4, s, crate::cap::CapSlot::empty());
        }
        crate::tasks::set_current_for_test(4);
        let ip_packed: u64 = u32::from_be_bytes(GW_IP) as u64;
        let slot = unsafe { sys_net_socket(1, ip_packed, 8080) };
        assert_eq!(slot, -1, "no NetRoot cap -> sys_net_socket is refused");
        // Nothing landed in the caller's CSpace: the refusal is total, not
        // partial.
        assert!(
            (0..crate::tasks::MAX_CAPS).all(|s| crate::tasks::task_cap(4, s).cap == Cap::None),
            "a denied mint must leave no trace of a capability in the caller's CSpace"
        );
        // The audit log attributes the attempt as a denial, not a silent
        // no-op — this is the NetOpen record the honest-status note said
        // did not exist.
        assert_eq!(
            crate::audit::op_counts(4)[crate::audit::OpKind::NetOpen.index()],
            1,
            "the refused mint is still an attributed audit record"
        );
        assert!(!crate::audit::ever_succeeded(
            4,
            crate::audit::OpKind::NetOpen,
            (ip_packed as u32) ^ (8080u32 << 16)
        ));
    }

    /// A task holding `Cap::NetRoot` with `NET_ROOT_RIGHTS` (the boot-time
    /// "this task is the trusted netstack owner" grant) may open a socket to
    /// a destination of its own choosing — the gate is about *authority to
    /// choose a destination at all*, not about narrowing that choice the
    /// way `query-advisor`'s kernel-only-bound mint does. This is the
    /// positive case proving the gate isn't just a blanket denial.
    #[test]
    fn net_socket_allows_task_with_net_root() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        for s in 0..crate::tasks::MAX_CAPS {
            crate::tasks::set_task_cap(5, s, crate::cap::CapSlot::empty());
        }
        assert!(
            grant_net_root(5, 0),
            "boot-time policy installs NetRoot into slot 0"
        );
        crate::tasks::set_current_for_test(5);
        let ip_packed: u64 = u32::from_be_bytes(GW_IP) as u64;
        let slot = unsafe { sys_net_socket(1, ip_packed, 9090) };
        assert!(slot >= 0, "a NetRoot holder may mint a socket");
        // The new NetEndpoint landed in a *different* slot than NetRoot —
        // NetRoot itself is never overwritten or consumed by a mint.
        assert_ne!(slot, 0, "NetRoot's own slot is untouched by the mint");
        let got = crate::tasks::task_cap(5, slot as usize);
        assert!(matches!(got.cap, Cap::NetEndpoint(_)));
        assert_eq!(got.rights.bits(), crate::cap::NET_RIGHTS.bits());
        assert_eq!(
            crate::tasks::task_cap(5, 0).cap,
            Cap::NetRoot,
            "NetRoot survives the mint it authorized"
        );
        assert!(crate::audit::ever_succeeded(
            5,
            crate::audit::OpKind::NetOpen,
            (ip_packed as u32) ^ (9090u32 << 16)
        ));
    }

    /// Holding `Cap::NetRoot` in a slot is not enough on its own — the
    /// rights on that slot must actually contain `NET_ROOT_RIGHTS`
    /// (CONTROL). A `NetRoot` cap installed with `Rights::NONE` (e.g. a
    /// narrowed/miscopied reference, if some future path ever produces one)
    /// must not authorize a mint. This is the same "cap kind is not enough,
    /// rights matter too" discipline every other gate in this kernel
    /// already follows (see `sys_net_connect`'s SEND check, etc.).
    #[test]
    fn net_socket_denies_net_root_without_control_right() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        for s in 0..crate::tasks::MAX_CAPS {
            crate::tasks::set_task_cap(6, s, crate::cap::CapSlot::empty());
        }
        crate::tasks::set_task_cap(
            6,
            0,
            crate::cap::CapSlot {
                cap: Cap::NetRoot,
                rights: crate::cap::Rights::NONE,
            },
        );
        crate::tasks::set_current_for_test(6);
        let ip_packed: u64 = u32::from_be_bytes(GW_IP) as u64;
        let slot = unsafe { sys_net_socket(1, ip_packed, 8080) };
        assert_eq!(
            slot, -1,
            "NetRoot without CONTROL is not authority to open a socket"
        );
    }

    /// `grant_net_root` itself follows the same "never silently overwrite a
    /// live capability" discipline as every other mint path: bounds-checked
    /// and refuses an occupied slot.
    #[test]
    fn grant_net_root_is_bounds_checked_and_never_clobbers() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        for s in 0..crate::tasks::MAX_CAPS {
            crate::tasks::set_task_cap(7, s, crate::cap::CapSlot::empty());
        }
        assert!(!grant_net_root(crate::tasks::MAX_TASKS + 1, 0));
        assert!(!grant_net_root(7, crate::tasks::MAX_CAPS + 1));
        assert!(grant_net_root(7, 0));
        assert!(
            !grant_net_root(7, 0),
            "an occupied slot is refused, not silently overwritten"
        );
    }

    /// End-to-end audit trail for the socket lifecycle (Phase F's other
    /// named gap: "net syscalls 19-23 still don't write to the audit
    /// log"). A NetRoot holder mints a socket, connects, sends, receives,
    /// and closes it; every step lands exactly one attributed record.
    #[test]
    fn net_io_syscalls_are_all_attributed_in_the_audit_log() {
        let _g = crate::kernel_state_guard();
        crate::tasks::reset_table_for_test();
        for s in 0..crate::tasks::MAX_CAPS {
            crate::tasks::set_task_cap(8, s, crate::cap::CapSlot::empty());
        }
        assert!(grant_net_root(8, 0));
        crate::tasks::set_current_for_test(8);
        // Pre-seed the shared static NETIF's ARP table for the destination,
        // the same way `setup()` does for the local-`NetIf` tests above —
        // otherwise `tcp_connect`'s `arp_resolve` falls through to
        // `nic_mut()`, which panics in this host-test build (no real e1000
        // device attached). Idempotent: harmless if another test already
        // inserted it.
        unsafe {
            (&mut *core::ptr::addr_of_mut!(NETIF)).arp.insert(
                GW_IP,
                MacAddress::from_bytes(&GW_MAC),
                0,
            );
        }
        let ip_packed: u64 = u32::from_be_bytes(GW_IP) as u64;
        let slot = unsafe { sys_net_socket(1, ip_packed, 8080) };
        assert!(slot >= 0);
        let ok = unsafe { sys_net_connect(slot as u64) };
        assert_eq!(ok, 0);
        let mut buf = [0u8; 4];
        let _ = unsafe { sys_net_send(slot as u64, buf.as_ptr() as u64, 4) };
        let _ = unsafe { sys_net_recv(slot as u64, buf.as_mut_ptr() as u64, 4) };
        let _ = unsafe { sys_net_close(slot as u64) };
        let counts = crate::audit::op_counts(8);
        assert_eq!(
            counts[crate::audit::OpKind::NetOpen.index()],
            1,
            "one attributed record for the mint"
        );
        assert_eq!(
            counts[crate::audit::OpKind::NetIo.index()],
            4,
            "one attributed record each for connect/send/recv/close"
        );
    }
}
