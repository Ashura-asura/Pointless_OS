// PCIe device enumeration

// PCI config register offsets
pub const VENDOR_ID: u16 = 0x00;
pub const DEVICE_ID: u16 = 0x02;
pub const COMMAND: u16 = 0x04;
pub const STATUS: u16 = 0x06;
pub const REVISION: u16 = 0x08;
pub const PROG_IF: u16 = 0x09;
pub const SUBCLASS: u16 = 0x0A;
pub const CLASS: u16 = 0x0B;
pub const CACHE_LINE_SIZE: u16 = 0x0C;
pub const HEADER_TYPE: u16 = 0x0E;
pub const BAR0: u16 = 0x10;
pub const BAR1: u16 = 0x14;
pub const BAR2: u16 = 0x18;
pub const BAR3: u16 = 0x1C;
pub const BAR4: u16 = 0x20;
pub const BAR5: u16 = 0x24;
pub const INTERRUPT_LINE: u16 = 0x3C;
pub const INTERRUPT_PIN: u16 = 0x3D;

// PCI class codes
pub const CLASS_MASS_STORAGE: u8 = 0x01;
pub const CLASS_NETWORK: u8 = 0x02;
pub const CLASS_DISPLAY: u8 = 0x03;
pub const CLASS_BRIDGE: u8 = 0x06;
pub const SUBCLASS_NVME: u8 = 0x08;

/// BAR helper functions — pure logic, testable

pub fn bar_is_io(bar: u32) -> bool {
    (bar & 1) == 1
}

pub fn bar_is_mmio(bar: u32) -> bool {
    (bar & 1) == 0
}

pub fn bar_is_64bit(bar: u32) -> bool {
    ((bar >> 1) & 3) == 2
}

/// PCI configuration address (legacy IO port 0xCF8 format)

#[derive(Clone, Copy, Debug)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    pub fn to_config_address(&self, register: u16) -> u32 {
        let enable: u32 = 1 << 31;
        let bus = (self.bus as u32) << 16;
        let device = (self.device as u32) << 11;
        let function = (self.function as u32) << 8;
        let reg = (register as u32) & 0xFC;
        enable | bus | device | function | reg
    }
}

/// PCI device descriptor

#[derive(Clone, Copy, Debug)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub header_type: u8,
    pub bar: [u32; 6],
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

impl PciDevice {
    pub fn is_nvme(&self) -> bool {
        self.class == CLASS_MASS_STORAGE && self.subclass == SUBCLASS_NVME
    }

    pub fn is_network(&self) -> bool {
        self.class == CLASS_NETWORK
    }

    pub fn is_display(&self) -> bool {
        self.class == CLASS_DISPLAY
    }

    pub fn is_bridge(&self) -> bool {
        self.class == CLASS_BRIDGE
    }

    pub fn bar_address(&self, index: usize) -> u64 {
        if index >= 6 {
            return 0;
        }
        let bar = self.bar[index];
        if bar_is_io(bar) {
            return (bar & 0xFFFF_FFF0) as u64;
        }
        if bar_is_64bit(bar) {
            let low = (bar & 0xFFFF_FFF0) as u64;
            let high = self.bar[index + 1] as u64;
            (high << 32) | low
        } else {
            (bar & 0xFFFF_FFF0) as u64
        }
    }
}

/// Fixed-capacity PCI device list

pub struct PciDeviceList {
    devices: [Option<PciDevice>; 32],
    count: usize,
}

impl PciDeviceList {
    pub fn new() -> Self {
        const NONE: Option<PciDevice> = None;
        Self {
            devices: [NONE; 32],
            count: 0,
        }
    }

    pub fn push(&mut self, device: PciDevice) -> bool {
        if self.count >= 32 {
            return false;
        }
        self.devices[self.count] = Some(device);
        self.count += 1;
        true
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &PciDevice> {
        self.devices[..self.count].iter().filter_map(|d| d.as_ref())
    }

    pub fn find_nvme(&self) -> Option<&PciDevice> {
        self.iter().find(|d| d.is_nvme())
    }

    pub fn find_network(&self) -> Option<&PciDevice> {
        self.iter().find(|d| d.is_network())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_config_address_builds_correct_address() {
        let addr = PciAddress::new(1, 2, 3);
        let result = addr.to_config_address(0x10);
        assert_eq!(result, 0x80011310);
    }

    #[test]
    fn bar_address_handles_32bit_mmio_bar() {
        let dev = PciDevice {
            address: PciAddress::new(0, 0, 0),
            vendor_id: 0,
            device_id: 0,
            class: 0,
            subclass: 0,
            prog_if: 0,
            revision: 0,
            header_type: 0,
            bar: [0x1000_0004, 0, 0, 0, 0, 0],
            interrupt_line: 0,
            interrupt_pin: 0,
        };
        assert_eq!(dev.bar_address(0), 0x1000_0000);
    }

    #[test]
    fn bar_address_handles_64bit_bar() {
        let dev = PciDevice {
            address: PciAddress::new(0, 0, 0),
            vendor_id: 0,
            device_id: 0,
            class: 0,
            subclass: 0,
            prog_if: 0,
            revision: 0,
            header_type: 0,
            bar: [0x1000_0004, 0x0000_0000, 0, 0, 0, 0],
            interrupt_line: 0,
            interrupt_pin: 0,
        };
        assert_eq!(dev.bar_address(0), 0x1000_0000);
    }

    #[test]
    fn pci_device_list_push_and_iterate() {
        let mut list = PciDeviceList::new();
        assert!(list.is_empty());
        let dev = PciDevice {
            address: PciAddress::new(0, 0, 0),
            vendor_id: 0x8086,
            device_id: 0x1234,
            class: 0,
            subclass: 0,
            prog_if: 0,
            revision: 0,
            header_type: 0,
            bar: [0; 6],
            interrupt_line: 0,
            interrupt_pin: 0,
        };
        list.push(dev);
        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
        let first = list.iter().next().unwrap();
        assert_eq!(first.vendor_id, 0x8086);
    }

    #[test]
    fn find_nvme_finds_nvme_device() {
        let mut list = PciDeviceList::new();
        let nvme = PciDevice {
            address: PciAddress::new(1, 0, 0),
            vendor_id: 0,
            device_id: 0,
            class: CLASS_MASS_STORAGE,
            subclass: SUBCLASS_NVME,
            prog_if: 0,
            revision: 0,
            header_type: 0,
            bar: [0; 6],
            interrupt_line: 0,
            interrupt_pin: 0,
        };
        let other = PciDevice {
            address: PciAddress::new(0, 1, 0),
            vendor_id: 0,
            device_id: 0,
            class: CLASS_NETWORK,
            subclass: 0,
            prog_if: 0,
            revision: 0,
            header_type: 0,
            bar: [0; 6],
            interrupt_line: 0,
            interrupt_pin: 0,
        };
        list.push(other);
        list.push(nvme);
        assert!(list.find_nvme().is_some());
    }

    #[test]
    fn find_network_finds_network_device() {
        let mut list = PciDeviceList::new();
        let net = PciDevice {
            address: PciAddress::new(2, 0, 0),
            vendor_id: 0,
            device_id: 0,
            class: CLASS_NETWORK,
            subclass: 0,
            prog_if: 0,
            revision: 0,
            header_type: 0,
            bar: [0; 6],
            interrupt_line: 0,
            interrupt_pin: 0,
        };
        list.push(net);
        assert!(list.find_network().is_some());
    }
}
