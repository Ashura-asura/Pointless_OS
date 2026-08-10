/// ARP protocol implementation.

use crate::ethernet::{EthernetFrame, ETHERTYPE_ARP};
use crate::net::MacAddress;

pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

pub const HW_TYPE_ETHERNET: u16 = 1;
pub const PROTO_TYPE_IPV4: u16 = 0x0800;
pub const ARP_HEADER_SIZE: usize = 28;

pub const ARP_STATE_INCOMPLETE: u8 = 0;
pub const ARP_STATE_RESOLVED: u8 = 1;
pub const ARP_STATE_EXPIRED: u8 = 2;

#[derive(Clone, Copy)]
pub struct ArpEntry {
    pub ip_addr: [u8; 4],
    pub mac_addr: MacAddress,
    pub state: u8,
    pub timestamp: u64,
}

pub struct ArpTable {
    pub entries: [Option<ArpEntry>; 64],
    pub count: usize,
    pub expiry_ticks: u64,
}

impl ArpTable {
    pub fn new() -> Self {
        const NONE: Option<ArpEntry> = None;
        ArpTable {
            entries: [NONE; 64],
            count: 0,
            expiry_ticks: 300_000, // default 5 minutes in ticks
        }
    }

    pub fn lookup(&self, ip: &[u8; 4]) -> Option<MacAddress> {
        for i in 0..64 {
            if let Some(entry) = &self.entries[i] {
                if entry.ip_addr == *ip && entry.state == ARP_STATE_RESOLVED {
                    return Some(entry.mac_addr);
                }
            }
        }
        None
    }

    pub fn insert(&mut self, ip: [u8; 4], mac: MacAddress, timestamp: u64) {
        // Update existing
        for i in 0..64 {
            if let Some(entry) = &mut self.entries[i] {
                if entry.ip_addr == ip {
                    entry.mac_addr = mac;
                    entry.state = ARP_STATE_RESOLVED;
                    entry.timestamp = timestamp;
                    return;
                }
            }
        }
        // Insert new
        if self.count < 64 {
            self.entries[self.count] = Some(ArpEntry {
                ip_addr: ip,
                mac_addr: mac,
                state: ARP_STATE_RESOLVED,
                timestamp,
            });
            self.count += 1;
        }
    }

    pub fn remove(&mut self, ip: &[u8; 4]) {
        for i in 0..64 {
            if let Some(entry) = &self.entries[i] {
                if entry.ip_addr == *ip {
                    self.entries[i] = None;
                    self.count = self.count.saturating_sub(1);
                    return;
                }
            }
        }
    }

    pub fn is_complete(&self, ip: &[u8; 4]) -> bool {
        for i in 0..64 {
            if let Some(entry) = &self.entries[i] {
                if entry.ip_addr == *ip && entry.state == ARP_STATE_RESOLVED {
                    return true;
                }
            }
        }
        false
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct ArpPacket {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    pub fn new() -> Self {
        ArpPacket {
            hw_type: HW_TYPE_ETHERNET,
            proto_type: PROTO_TYPE_IPV4,
            hw_addr_len: 6,
            proto_addr_len: 4,
            operation: ARP_REQUEST,
            sender_mac: [0; 6],
            sender_ip: [0; 4],
            target_mac: [0; 6],
            target_ip: [0; 4],
        }
    }

    pub fn to_bytes(&self) -> [u8; 28] {
        let mut buf = [0u8; 28];
        buf[0..2].copy_from_slice(&self.hw_type.to_be_bytes());
        buf[2..4].copy_from_slice(&self.proto_type.to_be_bytes());
        buf[4] = self.hw_addr_len;
        buf[5] = self.proto_addr_len;
        buf[6..8].copy_from_slice(&self.operation.to_be_bytes());
        buf[8..14].copy_from_slice(&self.sender_mac);
        buf[14..18].copy_from_slice(&self.sender_ip);
        buf[18..24].copy_from_slice(&self.target_mac);
        buf[24..28].copy_from_slice(&self.target_ip);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<ArpPacket> {
        if data.len() < 28 {
            return None;
        }

        let hw_type = u16::from_be_bytes([data[0], data[1]]);
        let proto_type = u16::from_be_bytes([data[2], data[3]]);
        let hw_addr_len = data[4];
        let proto_addr_len = data[5];
        let operation = u16::from_be_bytes([data[6], data[7]]);

        if hw_type != HW_TYPE_ETHERNET || proto_type != PROTO_TYPE_IPV4 {
            return None;
        }
        if hw_addr_len != 6 || proto_addr_len != 4 {
            return None;
        }

        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&data[8..14]);
        let mut sender_ip = [0u8; 4];
        sender_ip.copy_from_slice(&data[14..18]);
        let mut target_mac = [0u8; 6];
        target_mac.copy_from_slice(&data[18..24]);
        let mut target_ip = [0u8; 4];
        target_ip.copy_from_slice(&data[24..28]);

        Some(ArpPacket {
            hw_type,
            proto_type,
            hw_addr_len,
            proto_addr_len,
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }
}

pub struct ArpRequest;
impl ArpRequest {
    pub fn build_request(sender_mac: MacAddress, sender_ip: [u8; 4], target_ip: [u8; 4]) -> EthernetFrame<'static> {
        let arp = ArpPacket {
            hw_type: HW_TYPE_ETHERNET,
            proto_type: PROTO_TYPE_IPV4,
            hw_addr_len: 6,
            proto_addr_len: 4,
            operation: ARP_REQUEST,
            sender_mac: sender_mac.to_bytes(),
            sender_ip,
            target_mac: [0; 6],
            target_ip,
        };
        let arp_bytes = arp.to_bytes();

        // We need a static buffer for the Ethernet payload. Use a static array.
        // In production this would use a heap or DMA buffer.
        static mut ARP_PAYLOAD_BUF: [u8; 64] = [0u8; 64];
        let payload_len = arp_bytes.len();
        unsafe {
            ARP_PAYLOAD_BUF[..payload_len].copy_from_slice(&arp_bytes);
        }

        EthernetFrame {
            dst_mac: MacAddress::BROADCAST,
            src_mac: sender_mac,
            ethertype: ETHERTYPE_ARP,
            payload: unsafe { &ARP_PAYLOAD_BUF[..payload_len] },
        }
    }
}

pub struct ArpReply;
impl ArpReply {
    pub fn build_reply(
        sender_mac: MacAddress,
        sender_ip: [u8; 4],
        target_mac: MacAddress,
        target_ip: [u8; 4],
    ) -> EthernetFrame<'static> {
        let arp = ArpPacket {
            hw_type: HW_TYPE_ETHERNET,
            proto_type: PROTO_TYPE_IPV4,
            hw_addr_len: 6,
            proto_addr_len: 4,
            operation: ARP_REPLY,
            sender_mac: sender_mac.to_bytes(),
            sender_ip,
            target_mac: target_mac.to_bytes(),
            target_ip,
        };
        let arp_bytes = arp.to_bytes();

        static mut ARP_REPLY_BUF: [u8; 64] = [0u8; 64];
        let payload_len = arp_bytes.len();
        unsafe {
            ARP_REPLY_BUF[..payload_len].copy_from_slice(&arp_bytes);
        }

        EthernetFrame {
            dst_mac: target_mac,
            src_mac: sender_mac,
            ethertype: ETHERTYPE_ARP,
            payload: unsafe { &ARP_REPLY_BUF[..payload_len] },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_returns_resolved_entry() {
        let mut table = ArpTable::new();
        let mac = MacAddress::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        table.insert([192, 168, 1, 1], mac, 100);
        assert_eq!(table.lookup(&[192, 168, 1, 1]), Some(mac));
    }

    #[test]
    fn lookup_returns_none_for_unknown() {
        let table = ArpTable::new();
        assert_eq!(table.lookup(&[10, 0, 0, 1]), None);
    }

    #[test]
    fn insert_and_lookup_roundtrip() {
        let mut table = ArpTable::new();
        let mac = MacAddress::new(1, 2, 3, 4, 5, 6);
        table.insert([10, 0, 0, 42], mac, 200);
        assert!(table.is_complete(&[10, 0, 0, 42]));
        assert_eq!(table.lookup(&[10, 0, 0, 42]), Some(mac));
    }

    #[test]
    fn remove_deletes_entry() {
        let mut table = ArpTable::new();
        let mac = MacAddress::new(1, 2, 3, 4, 5, 6);
        table.insert([10, 0, 0, 42], mac, 200);
        assert!(table.is_complete(&[10, 0, 0, 42]));
        table.remove(&[10, 0, 0, 42]);
        assert!(!table.is_complete(&[10, 0, 0, 42]));
    }

    #[test]
    fn build_request_has_correct_fields() {
        let sender_mac = MacAddress::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let sender_ip = [192, 168, 1, 100];
        let target_ip = [192, 168, 1, 1];

        let frame = ArpRequest::build_request(sender_mac, sender_ip, target_ip);
        assert_eq!(frame.ethertype, ETHERTYPE_ARP);
        assert!(frame.dst_mac.is_broadcast());
        assert_eq!(frame.src_mac, sender_mac);

        let arp = ArpPacket::parse(frame.payload).unwrap();
        let op = arp.operation;
        let smac = arp.sender_mac;
        let sip = arp.sender_ip;
        let tip = arp.target_ip;
        assert_eq!(op, ARP_REQUEST);
        assert_eq!(smac, sender_mac.to_bytes());
        assert_eq!(sip, sender_ip);
        assert_eq!(tip, target_ip);
    }

    #[test]
    fn parse_reply_extracts_fields() {
        let arp = ArpPacket {
            hw_type: HW_TYPE_ETHERNET,
            proto_type: PROTO_TYPE_IPV4,
            hw_addr_len: 6,
            proto_addr_len: 4,
            operation: ARP_REPLY,
            sender_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            sender_ip: [192, 168, 1, 1],
            target_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            target_ip: [192, 168, 1, 100],
        };
        let bytes = arp.to_bytes();
        let parsed = ArpPacket::parse(&bytes).unwrap();
        let op = parsed.operation;
        assert_eq!(op, ARP_REPLY);
        assert_eq!(parsed.sender_ip, [192, 168, 1, 1]);
        assert_eq!(parsed.target_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }
}
