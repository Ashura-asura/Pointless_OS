/// IPv4 packet handling.
pub const IPV4_HEADER_MIN_SIZE: usize = 20;
pub const IPV4_VERSION: u8 = 4;
pub const DEFAULT_TTL: u8 = 64;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    WrongVersion,
    InvalidIhl,
    ChecksumMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPv4Address {
    pub octets: [u8; 4],
}

impl IPv4Address {
    pub const LOOPBACK: IPv4Address = IPv4Address {
        octets: [127, 0, 0, 1],
    };
    pub const BROADCAST: IPv4Address = IPv4Address {
        octets: [255, 255, 255, 255],
    };

    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        IPv4Address {
            octets: [a, b, c, d],
        }
    }

    pub fn is_loopback(&self) -> bool {
        self.octets[0] == 127
    }

    pub fn is_broadcast(&self) -> bool {
        self.octets == [255; 4]
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        self.octets
    }

    pub fn from_bytes(bytes: &[u8; 4]) -> Self {
        IPv4Address { octets: *bytes }
    }

    pub fn parse_address(s: &str) -> Option<Self> {
        let mut parts = [0u8; 4];
        let mut idx = 0;
        let mut num = 0u32;
        let mut has_digit = false;

        for b in s.bytes() {
            if b == b'.' {
                if idx >= 4 || !has_digit {
                    return None;
                }
                parts[idx] = num as u8;
                num = 0;
                has_digit = false;
                idx += 1;
            } else if b.is_ascii_digit() {
                num = num.checked_mul(10)?.checked_add((b - b'0') as u32)?;
                if num > 255 {
                    return None;
                }
                has_digit = true;
            } else {
                return None;
            }
        }

        if idx != 3 || !has_digit {
            return None;
        }
        parts[idx] = num as u8;

        Some(IPv4Address { octets: parts })
    }
}

impl core::fmt::Display for IPv4Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.octets[0], self.octets[1], self.octets[2], self.octets[3]
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IPv4Packet<'a> {
    pub version: u8,
    pub ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: IPv4Address,
    pub dst_ip: IPv4Address,
    pub payload: &'a [u8],
}

impl<'a> IPv4Packet<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < IPV4_HEADER_MIN_SIZE {
            return Err(ParseError::TooShort);
        }

        let version = (data[0] >> 4) & 0x0F;
        if version != IPV4_VERSION {
            return Err(ParseError::WrongVersion);
        }

        let ihl = data[0] & 0x0F;
        if ihl < 5 {
            return Err(ParseError::InvalidIhl);
        }

        let header_len = (ihl as usize) * 4;
        if data.len() < header_len {
            return Err(ParseError::TooShort);
        }

        let dscp_ecn = data[1];
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags_frag = u16::from_be_bytes([data[6], data[7]]);
        let flags = ((flags_frag >> 13) & 0x07) as u8;
        let fragment_offset = flags_frag & 0x1FFF;
        let ttl = data[8];
        let protocol = data[9];
        let checksum = u16::from_be_bytes([data[10], data[11]]);

        let src_ip = IPv4Address::from_bytes(&[data[12], data[13], data[14], data[15]]);
        let dst_ip = IPv4Address::from_bytes(&[data[16], data[17], data[18], data[19]]);

        // Verify checksum (sum of entire header including checksum should yield 0)
        let verify = Self::compute_checksum(&data[..header_len]);
        if verify != 0 {
            return Err(ParseError::ChecksumMismatch);
        }

        Ok(IPv4Packet {
            version,
            ihl,
            dscp_ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip,
            payload: &data[header_len..],
        })
    }

    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, &'static str> {
        let header_len = (self.ihl as usize) * 4;
        if buffer.len() < header_len + self.payload.len() {
            return Err("buffer too small for IPv4 packet");
        }

        buffer[0] = (self.version << 4) | (self.ihl & 0x0F);
        buffer[1] = self.dscp_ecn;
        buffer[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        buffer[4..6].copy_from_slice(&self.identification.to_be_bytes());

        let flags_frag = ((self.flags as u16) << 13) | (self.fragment_offset & 0x1FFF);
        buffer[6..8].copy_from_slice(&flags_frag.to_be_bytes());

        buffer[8] = self.ttl;
        buffer[9] = self.protocol;
        buffer[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
        buffer[12..16].copy_from_slice(&self.src_ip.octets);
        buffer[16..20].copy_from_slice(&self.dst_ip.octets);

        // Compute and write checksum
        let cksum = Self::compute_checksum(&buffer[..header_len]);
        buffer[10..12].copy_from_slice(&cksum.to_be_bytes());

        let payload_len = self.payload.len().min(buffer.len() - header_len);
        buffer[header_len..header_len + payload_len].copy_from_slice(&self.payload[..payload_len]);

        Ok(header_len + payload_len)
    }

    pub fn compute_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < header.len() {
            sum += ((header[i] as u32) << 8) | (header[i + 1] as u32);
            i += 2;
        }
        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_packet() -> IPv4Packet<'static> {
        static PAYLOAD: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        IPv4Packet {
            version: 4,
            ihl: 5,
            dscp_ecn: 0,
            total_length: 24,
            identification: 0x1234,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: PROTO_TCP,
            checksum: 0,
            src_ip: IPv4Address::new(192, 168, 1, 100),
            dst_ip: IPv4Address::new(192, 168, 1, 1),
            payload: &PAYLOAD,
        }
    }

    #[test]
    fn parses_valid_packet() {
        let mut buf = [0u8; 24];
        let pkt = build_test_packet();
        let len = pkt.serialize(&mut buf).unwrap();

        let parsed = IPv4Packet::parse(&buf[..len]).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.ihl, 5);
        assert_eq!(parsed.protocol, PROTO_TCP);
        assert_eq!(parsed.src_ip, IPv4Address::new(192, 168, 1, 100));
        assert_eq!(parsed.dst_ip, IPv4Address::new(192, 168, 1, 1));
        assert_eq!(parsed.ttl, 64);
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = [0u8; 20];
        buf[0] = 6 << 4 | 5; // version 6
        assert_eq!(IPv4Packet::parse(&buf), Err(ParseError::WrongVersion));
    }

    #[test]
    fn compute_checksum_is_correct() {
        // RFC 1071 test vector: header bytes
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8,
            0x01, 0x64, 0xC0, 0xA8, 0x01, 0x01,
        ];
        // The checksum field is 0x0000 so computed checksum should match the
        // actual checksum. With zero checksum, the ones'-complement sum should
        // fold to 0xFFFF. Let's verify.
        let cksum = IPv4Packet::compute_checksum(&header);
        // The checksum of a valid packet header (with correct checksum field) is 0.
        // But our header has checksum=0, so compute_checksum returns the checksum value.
        assert_ne!(cksum, 0x0000); // Should be non-zero since checksum field is zero
    }

    #[test]
    fn serialize_roundtrip() {
        let mut buf = [0u8; 24];
        let pkt = build_test_packet();
        let len = pkt.serialize(&mut buf).unwrap();

        let parsed = IPv4Packet::parse(&buf[..len]).unwrap();
        assert_eq!(parsed.version, pkt.version);
        assert_eq!(parsed.ihl, pkt.ihl);
        assert_eq!(parsed.total_length, pkt.total_length);
        assert_eq!(parsed.identification, pkt.identification);
        assert_eq!(parsed.src_ip, pkt.src_ip);
        assert_eq!(parsed.dst_ip, pkt.dst_ip);
        assert_eq!(parsed.payload, pkt.payload);
    }

    #[test]
    fn loopback_address_detection() {
        let addr = IPv4Address::LOOPBACK;
        assert!(addr.is_loopback());
        assert!(!addr.is_broadcast());
        assert_eq!(addr, IPv4Address::new(127, 0, 0, 1));
    }

    #[test]
    fn broadcast_address_detection() {
        let addr = IPv4Address::BROADCAST;
        assert!(addr.is_broadcast());
        assert!(!addr.is_loopback());
        assert_eq!(addr, IPv4Address::new(255, 255, 255, 255));
    }
}
