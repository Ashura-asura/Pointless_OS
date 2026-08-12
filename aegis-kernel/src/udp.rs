/// UDP datagram handling.
///
/// Design doc §8 "Networking": userspace transport-layer model over the
/// existing `ipv4`/`ethernet`/`arp` link. This module is pure parse/
/// serialize logic — no socket state, no NIC I/O — matching the honest
/// limit already documented for `ipv4`/`ethernet`/`arp` (model code, not
/// yet wired into the boot path).
use crate::ipv4::IPv4Address;

pub const UDP_HEADER_SIZE: usize = 8;
pub const PROTO_UDP: u8 = crate::ipv4::PROTO_UDP;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    LengthMismatch,
    ChecksumMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpDatagram<'a> {
    /// Parses a UDP datagram. `checksum` is verified against the IPv4
    /// pseudo-header when `src_ip`/`dst_ip` are provided; pass `None` to
    /// skip verification (UDP checksum is optional on IPv4 — a `0x0000`
    /// checksum field means "not computed", per RFC 768).
    pub fn parse(
        data: &'a [u8],
        src_ip: Option<IPv4Address>,
        dst_ip: Option<IPv4Address>,
    ) -> Result<Self, ParseError> {
        if data.len() < UDP_HEADER_SIZE {
            return Err(ParseError::TooShort);
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        let length_usize = length as usize;
        if length_usize < UDP_HEADER_SIZE || length_usize > data.len() {
            return Err(ParseError::LengthMismatch);
        }

        if checksum != 0 {
            if let (Some(src), Some(dst)) = (src_ip, dst_ip) {
                let computed = Self::compute_checksum(src, dst, &data[..length_usize]);
                if computed != 0 {
                    return Err(ParseError::ChecksumMismatch);
                }
            }
        }

        Ok(UdpDatagram {
            src_port,
            dst_port,
            length,
            checksum,
            payload: &data[UDP_HEADER_SIZE..length_usize],
        })
    }

    pub fn serialize(
        &self,
        buffer: &mut [u8],
        src_ip: IPv4Address,
        dst_ip: IPv4Address,
    ) -> Result<usize, &'static str> {
        let total_len = UDP_HEADER_SIZE + self.payload.len();
        if buffer.len() < total_len {
            return Err("buffer too small for UDP datagram");
        }

        buffer[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buffer[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buffer[4..6].copy_from_slice(&(total_len as u16).to_be_bytes());
        buffer[6..8].copy_from_slice(&[0, 0]); // checksum placeholder
        buffer[UDP_HEADER_SIZE..total_len].copy_from_slice(self.payload);

        let cksum = Self::compute_checksum(src_ip, dst_ip, &buffer[..total_len]);
        // RFC 768: a computed checksum of 0x0000 is transmitted as 0xFFFF,
        // since 0x0000 in the field means "no checksum".
        let cksum = if cksum == 0 { 0xFFFF } else { cksum };
        buffer[6..8].copy_from_slice(&cksum.to_be_bytes());

        Ok(total_len)
    }

    /// Ones'-complement checksum over the IPv4 pseudo-header + UDP
    /// header + payload (RFC 768). `segment` is the UDP header+payload
    /// with the checksum field already zeroed.
    pub fn compute_checksum(src_ip: IPv4Address, dst_ip: IPv4Address, segment: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        // Pseudo-header: src (4) + dst (4) + zero (1) + protocol (1) + udp length (2)
        let src = src_ip.to_bytes();
        let dst = dst_ip.to_bytes();
        sum += ((src[0] as u32) << 8) | (src[1] as u32);
        sum += ((src[2] as u32) << 8) | (src[3] as u32);
        sum += ((dst[0] as u32) << 8) | (dst[1] as u32);
        sum += ((dst[2] as u32) << 8) | (dst[3] as u32);
        sum += PROTO_UDP as u32;
        sum += segment.len() as u32;

        // UDP header + payload, padded with a trailing zero byte if odd.
        let mut i = 0;
        while i + 1 < segment.len() {
            sum += ((segment[i] as u32) << 8) | (segment[i + 1] as u32);
            i += 2;
        }
        if i < segment.len() {
            sum += (segment[i] as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_datagram() -> UdpDatagram<'static> {
        static PAYLOAD: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];
        UdpDatagram {
            src_port: 5353,
            dst_port: 53,
            length: (UDP_HEADER_SIZE + PAYLOAD.len()) as u16,
            checksum: 0,
            payload: &PAYLOAD,
        }
    }

    #[test]
    fn serialize_roundtrip_with_checksum_verification() {
        let src = IPv4Address::new(192, 168, 1, 100);
        let dst = IPv4Address::new(192, 168, 1, 1);
        let mut buf = [0u8; 12];
        let dgram = build_test_datagram();
        let len = dgram.serialize(&mut buf, src, dst).unwrap();

        let parsed = UdpDatagram::parse(&buf[..len], Some(src), Some(dst)).unwrap();
        assert_eq!(parsed.src_port, 5353);
        assert_eq!(parsed.dst_port, 53);
        assert_eq!(parsed.payload, dgram.payload);
    }

    #[test]
    fn parse_without_ip_context_skips_checksum_check() {
        let src = IPv4Address::new(10, 0, 0, 1);
        let dst = IPv4Address::new(10, 0, 0, 2);
        let mut buf = [0u8; 12];
        let dgram = build_test_datagram();
        let len = dgram.serialize(&mut buf, src, dst).unwrap();

        // No src/dst supplied -> checksum not verified, still parses.
        let parsed = UdpDatagram::parse(&buf[..len], None, None).unwrap();
        assert_eq!(parsed.dst_port, 53);
    }

    #[test]
    fn zero_checksum_is_accepted_unverified() {
        // RFC 768: checksum 0x0000 means "not computed" and must be
        // accepted without verification even when IP context is given.
        let src = IPv4Address::new(10, 0, 0, 1);
        let dst = IPv4Address::new(10, 0, 0, 2);
        let mut buf = [0u8; 12];
        let dgram = build_test_datagram();
        dgram.serialize(&mut buf, src, dst).unwrap();
        buf[6] = 0;
        buf[7] = 0;

        let parsed = UdpDatagram::parse(&buf, Some(src), Some(dst)).unwrap();
        assert_eq!(parsed.checksum, 0);
    }

    #[test]
    fn rejects_too_short() {
        let buf = [0u8; 7];
        assert_eq!(
            UdpDatagram::parse(&buf, None, None),
            Err(ParseError::TooShort)
        );
    }

    #[test]
    fn rejects_length_field_past_buffer() {
        let mut buf = [0u8; 8];
        buf[4..6].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(
            UdpDatagram::parse(&buf, None, None),
            Err(ParseError::LengthMismatch)
        );
    }

    #[test]
    fn rejects_length_field_below_header_size() {
        let mut buf = [0u8; 8];
        buf[4..6].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            UdpDatagram::parse(&buf, None, None),
            Err(ParseError::LengthMismatch)
        );
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let src = IPv4Address::new(192, 168, 1, 100);
        let dst = IPv4Address::new(192, 168, 1, 1);
        let mut buf = [0u8; 12];
        let dgram = build_test_datagram();
        dgram.serialize(&mut buf, src, dst).unwrap();
        buf[8] ^= 0xFF; // corrupt payload after checksum was computed

        assert_eq!(
            UdpDatagram::parse(&buf, Some(src), Some(dst)),
            Err(ParseError::ChecksumMismatch)
        );
    }

    #[test]
    fn serialize_rejects_undersized_buffer() {
        let dgram = build_test_datagram();
        let mut buf = [0u8; 4];
        assert!(dgram
            .serialize(&mut buf, IPv4Address::LOOPBACK, IPv4Address::LOOPBACK)
            .is_err());
    }
}
