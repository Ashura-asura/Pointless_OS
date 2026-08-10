/// Ethernet frame parsing and serialization.
use crate::net::MacAddress;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

pub const ETH_HEADER_SIZE: usize = 14;
pub const MIN_FRAME_SIZE: usize = 64;
pub const MAX_FRAME_SIZE: usize = 1514;

pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    InvalidEthertype,
    ZeroSourceMac,
}

#[derive(Debug, PartialEq)]
pub struct EthernetFrame<'a> {
    pub dst_mac: MacAddress,
    pub src_mac: MacAddress,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < MIN_FRAME_SIZE {
            return Err(ParseError::TooShort);
        }

        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        match ethertype {
            ETHERTYPE_IPV4 | ETHERTYPE_ARP | ETHERTYPE_IPV6 => {}
            _ => return Err(ParseError::InvalidEthertype),
        }

        let src_mac =
            MacAddress::from_bytes(&[data[6], data[7], data[8], data[9], data[10], data[11]]);
        if src_mac.octets == [0u8; 6] {
            return Err(ParseError::ZeroSourceMac);
        }

        Ok(EthernetFrame {
            dst_mac: MacAddress::from_bytes(&[
                data[0], data[1], data[2], data[3], data[4], data[5],
            ]),
            src_mac,
            ethertype,
            payload: &data[ETH_HEADER_SIZE..],
        })
    }

    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, &'static str> {
        let total = ETH_HEADER_SIZE + self.payload.len();
        if buffer.len() < total {
            return Err("buffer too small for Ethernet frame");
        }

        buffer[0..6].copy_from_slice(&self.dst_mac.octets);
        buffer[6..12].copy_from_slice(&self.src_mac.octets);
        buffer[12..14].copy_from_slice(&self.ethertype.to_be_bytes());

        let payload_len = self.payload.len();
        buffer[14..14 + payload_len].copy_from_slice(&self.payload[..payload_len]);

        let frame_end = total.max(MIN_FRAME_SIZE);
        if buffer.len() < frame_end {
            return Err("buffer too small for padded frame");
        }
        for b in &mut buffer[total..frame_end] {
            *b = 0;
        }

        Ok(frame_end)
    }

    pub fn broadcast() -> Self {
        EthernetFrame {
            dst_mac: MacAddress {
                octets: BROADCAST_MAC,
            },
            src_mac: MacAddress::new(0, 0, 0, 0, 0, 0),
            ethertype: ETHERTYPE_IPV4,
            payload: &[],
        }
    }

    pub fn total_length(&self) -> usize {
        ETH_HEADER_SIZE + self.payload.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_frame_bytes() -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0] = 0xFF;
        buf[1] = 0xFF;
        buf[2] = 0xFF;
        buf[3] = 0xFF;
        buf[4] = 0xFF;
        buf[5] = 0xFF; // dst
        buf[6] = 0xAA;
        buf[7] = 0xBB;
        buf[8] = 0xCC;
        buf[9] = 0xDD;
        buf[10] = 0xEE;
        buf[11] = 0xFF; // src
        buf[12] = 0x08;
        buf[13] = 0x00; // IPv4
        buf
    }

    #[test]
    fn parses_valid_frame() {
        let buf = valid_frame_bytes();
        let frame = EthernetFrame::parse(&buf).unwrap();
        assert_eq!(frame.ethertype, ETHERTYPE_IPV4);
        assert_eq!(
            frame.src_mac,
            MacAddress::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)
        );
        assert_eq!(frame.dst_mac, MacAddress::BROADCAST);
    }

    #[test]
    fn rejects_too_short_frame() {
        let buf = [0u8; 32];
        assert_eq!(EthernetFrame::parse(&buf), Err(ParseError::TooShort));
    }

    #[test]
    fn parses_broadcast_frame() {
        let buf = valid_frame_bytes();
        let frame = EthernetFrame::parse(&buf).unwrap();
        assert!(frame.dst_mac.is_broadcast());
    }

    #[test]
    fn serialize_roundtrip() {
        let mut frame_buf = valid_frame_bytes();
        // Make payload non-empty
        frame_buf[14] = 0xDE;
        frame_buf[15] = 0xAD;

        let frame = EthernetFrame {
            dst_mac: MacAddress::BROADCAST,
            src_mac: MacAddress::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
            ethertype: ETHERTYPE_IPV4,
            payload: &frame_buf[14..28],
        };

        let mut out = [0u8; 64];
        let len = frame.serialize(&mut out).unwrap();
        assert!(len >= MIN_FRAME_SIZE);

        let parsed = EthernetFrame::parse(&out).unwrap();
        assert_eq!(parsed.ethertype, ETHERTYPE_IPV4);
        assert_eq!(parsed.src_mac, frame.src_mac);
        assert_eq!(parsed.dst_mac, frame.dst_mac);
    }

    #[test]
    fn rejects_zero_source_mac() {
        let mut buf = valid_frame_bytes();
        buf[6] = 0;
        buf[7] = 0;
        buf[8] = 0;
        buf[9] = 0;
        buf[10] = 0;
        buf[11] = 0;
        assert_eq!(EthernetFrame::parse(&buf), Err(ParseError::ZeroSourceMac));
    }
}
