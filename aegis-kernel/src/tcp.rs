/// TCP segment header handling.
///
/// Design doc §8 "Networking": userspace transport-layer model. Like
/// `udp.rs`, this is pure parse/serialize logic — no connection state
/// machine, no retransmission, no NIC I/O. Honest limits: TCP options
/// are not parsed (the data offset is used only to locate the payload,
/// option bytes are exposed as a raw slice rather than decoded), and
/// there is no state machine here — that belongs to a future socket
/// layer built on top of this header model.
use crate::ipv4::IPv4Address;

pub const TCP_HEADER_MIN_SIZE: usize = 20;
pub const PROTO_TCP: u8 = crate::ipv4::PROTO_TCP;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShort,
    InvalidDataOffset,
    ChecksumMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TcpFlags {
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TcpFlags {
    fn from_bytes(offset_reserved_ns: u8, flags_byte: u8) -> Self {
        TcpFlags {
            ns: offset_reserved_ns & 0x01 != 0,
            cwr: flags_byte & 0x80 != 0,
            ece: flags_byte & 0x40 != 0,
            urg: flags_byte & 0x20 != 0,
            ack: flags_byte & 0x10 != 0,
            psh: flags_byte & 0x08 != 0,
            rst: flags_byte & 0x04 != 0,
            syn: flags_byte & 0x02 != 0,
            fin: flags_byte & 0x01 != 0,
        }
    }

    fn to_flags_byte(self) -> u8 {
        (self.cwr as u8) << 7
            | (self.ece as u8) << 6
            | (self.urg as u8) << 5
            | (self.ack as u8) << 4
            | (self.psh as u8) << 3
            | (self.rst as u8) << 2
            | (self.syn as u8) << 1
            | (self.fin as u8)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8, // in 32-bit words, per RFC 793 (min 5)
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    /// Parses a TCP segment. Checksum is verified against the IPv4
    /// pseudo-header when `src_ip`/`dst_ip` are provided (unlike UDP,
    /// the TCP checksum is mandatory — but this function still allows
    /// skipping verification for callers without IP context, e.g. tests).
    pub fn parse(
        data: &'a [u8],
        src_ip: Option<IPv4Address>,
        dst_ip: Option<IPv4Address>,
    ) -> Result<Self, ParseError> {
        if data.len() < TCP_HEADER_MIN_SIZE {
            return Err(ParseError::TooShort);
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let data_offset = (data[12] >> 4) & 0x0F;
        if data_offset < 5 {
            return Err(ParseError::InvalidDataOffset);
        }
        let header_len = (data_offset as usize) * 4;
        if data.len() < header_len {
            return Err(ParseError::InvalidDataOffset);
        }

        let flags = TcpFlags::from_bytes(data[12], data[13]);
        let window = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

        if let (Some(src), Some(dst)) = (src_ip, dst_ip) {
            let computed = Self::compute_checksum(src, dst, data);
            if computed != 0 {
                return Err(ParseError::ChecksumMismatch);
            }
        }

        Ok(TcpSegment {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            flags,
            window,
            checksum,
            urgent_pointer,
            options: &data[TCP_HEADER_MIN_SIZE..header_len],
            payload: &data[header_len..],
        })
    }

    pub fn serialize(
        &self,
        buffer: &mut [u8],
        src_ip: IPv4Address,
        dst_ip: IPv4Address,
    ) -> Result<usize, &'static str> {
        let header_len = (self.data_offset as usize) * 4;
        if header_len < TCP_HEADER_MIN_SIZE {
            return Err("data_offset below minimum TCP header size");
        }
        let opts_len = header_len - TCP_HEADER_MIN_SIZE;
        if self.options.len() != opts_len {
            return Err("options length does not match data_offset");
        }
        let total_len = header_len + self.payload.len();
        if buffer.len() < total_len {
            return Err("buffer too small for TCP segment");
        }

        buffer[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buffer[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buffer[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        buffer[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        buffer[12] = (self.data_offset << 4) | (self.flags.ns as u8);
        buffer[13] = self.flags.to_flags_byte();
        buffer[14..16].copy_from_slice(&self.window.to_be_bytes());
        buffer[16..18].copy_from_slice(&[0, 0]); // checksum placeholder
        buffer[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());
        buffer[TCP_HEADER_MIN_SIZE..header_len].copy_from_slice(self.options);
        buffer[header_len..total_len].copy_from_slice(self.payload);

        let cksum = Self::compute_checksum(src_ip, dst_ip, &buffer[..total_len]);
        buffer[16..18].copy_from_slice(&cksum.to_be_bytes());

        Ok(total_len)
    }

    /// Ones'-complement checksum over the IPv4 pseudo-header + TCP
    /// header/options + payload (RFC 793). `segment` is the full TCP
    /// segment (header+options+payload) with the checksum field zeroed.
    pub fn compute_checksum(src_ip: IPv4Address, dst_ip: IPv4Address, segment: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        let src = src_ip.to_bytes();
        let dst = dst_ip.to_bytes();
        sum += ((src[0] as u32) << 8) | (src[1] as u32);
        sum += ((src[2] as u32) << 8) | (src[3] as u32);
        sum += ((dst[0] as u32) << 8) | (dst[1] as u32);
        sum += ((dst[2] as u32) << 8) | (dst[3] as u32);
        sum += PROTO_TCP as u32;
        sum += segment.len() as u32;

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

    fn build_test_segment() -> TcpSegment<'static> {
        static PAYLOAD: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        TcpSegment {
            src_port: 443,
            dst_port: 51234,
            seq_num: 0x0001_0000,
            ack_num: 0,
            data_offset: 5,
            flags: TcpFlags {
                syn: true,
                ..Default::default()
            },
            window: 65535,
            checksum: 0,
            urgent_pointer: 0,
            options: &[],
            payload: &PAYLOAD,
        }
    }

    #[test]
    fn serialize_roundtrip_with_checksum_verification() {
        let src = IPv4Address::new(192, 168, 1, 100);
        let dst = IPv4Address::new(192, 168, 1, 1);
        let mut buf = [0u8; 24];
        let seg = build_test_segment();
        let len = seg.serialize(&mut buf, src, dst).unwrap();

        let parsed = TcpSegment::parse(&buf[..len], Some(src), Some(dst)).unwrap();
        assert_eq!(parsed.src_port, 443);
        assert_eq!(parsed.dst_port, 51234);
        assert_eq!(parsed.seq_num, 0x0001_0000);
        assert!(parsed.flags.syn);
        assert!(!parsed.flags.ack);
        assert_eq!(parsed.payload, seg.payload);
    }

    #[test]
    fn flags_byte_round_trips_all_bits() {
        let flags = TcpFlags {
            ns: true,
            cwr: true,
            ece: true,
            urg: true,
            ack: true,
            psh: true,
            rst: true,
            syn: true,
            fin: true,
        };
        let offset_byte = (5u8 << 4) | (flags.ns as u8);
        let parsed = TcpFlags::from_bytes(offset_byte, flags.to_flags_byte());
        assert_eq!(parsed, flags);
    }

    #[test]
    fn parse_without_ip_context_skips_checksum_check() {
        let mut buf = [0u8; 20];
        buf[12] = 5 << 4; // data_offset = 5, no options
        let parsed = TcpSegment::parse(&buf, None, None).unwrap();
        assert_eq!(parsed.data_offset, 5);
    }

    #[test]
    fn rejects_too_short() {
        let buf = [0u8; 19];
        assert_eq!(
            TcpSegment::parse(&buf, None, None),
            Err(ParseError::TooShort)
        );
    }

    #[test]
    fn rejects_data_offset_below_minimum() {
        let mut buf = [0u8; 20];
        buf[12] = 4 << 4; // data_offset = 4, below the 5-word minimum
        assert_eq!(
            TcpSegment::parse(&buf, None, None),
            Err(ParseError::InvalidDataOffset)
        );
    }

    #[test]
    fn rejects_data_offset_past_buffer() {
        let mut buf = [0u8; 20];
        buf[12] = 15 << 4; // claims 60-byte header, buffer is only 20
        assert_eq!(
            TcpSegment::parse(&buf, None, None),
            Err(ParseError::InvalidDataOffset)
        );
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let src = IPv4Address::new(192, 168, 1, 100);
        let dst = IPv4Address::new(192, 168, 1, 1);
        let mut buf = [0u8; 24];
        let seg = build_test_segment();
        seg.serialize(&mut buf, src, dst).unwrap();
        buf[20] ^= 0xFF; // corrupt payload after checksum was computed

        assert_eq!(
            TcpSegment::parse(&buf, Some(src), Some(dst)),
            Err(ParseError::ChecksumMismatch)
        );
    }

    #[test]
    fn serialize_rejects_options_length_mismatch() {
        let mut seg = build_test_segment();
        seg.data_offset = 6; // claims 4 bytes of options
        seg.options = &[]; // but supplies none
        let mut buf = [0u8; 32];
        assert!(seg
            .serialize(&mut buf, IPv4Address::LOOPBACK, IPv4Address::LOOPBACK)
            .is_err());
    }

    #[test]
    fn serialize_rejects_undersized_buffer() {
        let seg = build_test_segment();
        let mut buf = [0u8; 4];
        assert!(seg
            .serialize(&mut buf, IPv4Address::LOOPBACK, IPv4Address::LOOPBACK)
            .is_err());
    }
}
