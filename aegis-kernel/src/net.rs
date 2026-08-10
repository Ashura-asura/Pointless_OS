/// VirtIO-net NIC driver interface.

// VirtIO register offsets (MMIO)
pub const REG_DEVICE_FEATURES: u64 = 0x00;
pub const REG_QUEUE_ADDRESS: u64 = 0x08;
pub const REG_QUEUE_SIZE: u64 = 0x0C;
pub const REG_QUEUE_NOTIFY: u64 = 0x10;
pub const REG_DEVICE_STATUS: u64 = 0x16;
pub const REG_INTERRUPT_STATUS: u64 = 0x1C;
pub const REG_QUEUE_SELECTOR: u64 = 0x1C;
pub const REG_QUEUE_NOTIFY_OFF: u64 = 0x18;
pub const REG_MAC: u64 = 0x00; // offset within config space

pub const STATUS_ACK: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_DRIVER_OK: u8 = 4;

pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;

pub const MIN_FRAME_SIZE: usize = 64;

#[repr(C, packed)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub header_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VirtioNetHeader {
    pub const SIZE: usize = 10;

    pub fn new() -> Self {
        VirtioNetHeader {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            header_len: VirtioNetHeader::SIZE as u16,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacAddress {
    pub octets: [u8; 6],
}

impl MacAddress {
    pub const BROADCAST: MacAddress = MacAddress { octets: [0xFF; 6] };

    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        MacAddress {
            octets: [a, b, c, d, e, f],
        }
    }

    pub fn is_broadcast(&self) -> bool {
        self.octets == [0xFF; 6]
    }

    pub fn is_multicast(&self) -> bool {
        (self.octets[0] & 0x01) != 0 && !self.is_broadcast()
    }

    pub fn to_bytes(&self) -> [u8; 6] {
        self.octets
    }

    pub fn from_bytes(bytes: &[u8; 6]) -> Self {
        MacAddress { octets: *bytes }
    }
}

impl core::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.octets[0],
            self.octets[1],
            self.octets[2],
            self.octets[3],
            self.octets[4],
            self.octets[5]
        )
    }
}

pub struct NetDevice {
    pub mmio_base: u64,
    pub mac: MacAddress,
    pub irq: u8,
    pub status: u8,
    pub rx_queue_size: u16,
    pub tx_queue_size: u16,
}

impl NetDevice {
    pub fn new(mmio_base: u64, mac: MacAddress) -> Self {
        NetDevice {
            mmio_base,
            mac,
            irq: 0,
            status: 0,
            rx_queue_size: 0,
            tx_queue_size: 0,
        }
    }

    /// Reset device and negotiate features. UNTESTED.
    pub fn init(&mut self) -> Result<(), &'static str> {
        self.write_status(0); // reset
        self.write_status(STATUS_ACK | STATUS_DRIVER);
        // Negotiate features (simplified)
        let _host_features = self.read_device_features();
        self.write_status(self.status | STATUS_FEATURES_OK);
        self.write_status(self.status | STATUS_DRIVER_OK);
        Ok(())
    }

    /// Write a frame to the TX queue and notify. UNTESTED.
    pub fn send(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.is_empty() {
            return Err("empty frame");
        }
        // In a real driver this would DMA into the virtqueue.
        // Stub: write frame bytes to MMIO transmit doorbell.
        self.notify_queue(1);
        Ok(())
    }

    /// Poll the RX queue for a frame. UNTESTED.
    pub fn receive(&mut self, _buffer: &mut [u8]) -> Option<usize> {
        // In a real driver this would check the used ring.
        // Stub: no data available.
        None
    }

    // ---- low-level MMIO helpers (stubbed) ----

    fn read_device_features(&self) -> u32 {
        // Safety: stub for no_std
        0
    }

    fn write_status(&mut self, val: u8) {
        self.status = val;
    }

    fn notify_queue(&self, _queue_index: u16) {
        // stub
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_display() {
        let mac = MacAddress::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let mut buf = [0u8; 24];
        use core::fmt::Write;
        struct BufWriter<'a> {
            buf: &'a mut [u8],
            pos: usize,
        }
        impl<'a> core::fmt::Write for BufWriter<'a> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let end = (self.pos + bytes.len()).min(self.buf.len());
                let len = end - self.pos;
                self.buf[self.pos..end].copy_from_slice(&bytes[..len]);
                self.pos = end;
                Ok(())
            }
        }
        {
            let mut w = BufWriter {
                buf: &mut buf,
                pos: 0,
            };
            write!(w, "{}", mac).unwrap();
        }
        let s = core::str::from_utf8(&buf[..17]).unwrap();
        assert_eq!(s, "AA:BB:CC:DD:EE:FF");
    }

    #[test]
    fn mac_broadcast() {
        let mac = MacAddress::BROADCAST;
        assert!(mac.is_broadcast());
        assert!(!mac.is_multicast());
    }

    #[test]
    fn mac_multicast() {
        let mac = MacAddress::new(0x01, 0x00, 0x5E, 0x00, 0x00, 0x01);
        assert!(!mac.is_broadcast());
        assert!(mac.is_multicast());
    }

    #[test]
    fn mac_roundtrip() {
        let mac = MacAddress::new(1, 2, 3, 4, 5, 6);
        let bytes = mac.to_bytes();
        let mac2 = MacAddress::from_bytes(&bytes);
        assert_eq!(mac, mac2);
    }

    #[test]
    fn virtio_header_size() {
        assert_eq!(VirtioNetHeader::SIZE, 10);
    }

    #[test]
    fn net_device_new() {
        let mac = MacAddress::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        let dev = NetDevice::new(0xFE00_0000, mac);
        assert_eq!(dev.mmio_base, 0xFE00_0000);
        assert_eq!(dev.mac, mac);
        assert_eq!(dev.status, 0);
    }

    #[test]
    fn net_device_init() {
        let mac = MacAddress::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let mut dev = NetDevice::new(0xFE00_0000, mac);
        assert!(dev.init().is_ok());
    }

    #[test]
    fn send_empty_frame_fails() {
        let mac = MacAddress::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let mut dev = NetDevice::new(0xFE00_0000, mac);
        assert_eq!(dev.send(&[]), Err("empty frame"));
    }

    #[test]
    fn receive_returns_none_initially() {
        let mac = MacAddress::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
        let mut dev = NetDevice::new(0xFE00_0000, mac);
        let mut buf = [0u8; 1500];
        assert!(dev.receive(&mut buf).is_none());
    }
}
