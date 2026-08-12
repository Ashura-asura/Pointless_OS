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

/// Human-readable class name for scan reports.
pub fn class_name(class: u8, subclass: u8) -> &'static str {
    match (class, subclass) {
        (0x01, 0x01) => "IDE controller",
        (0x01, 0x06) => "SATA controller",
        (0x01, 0x08) => "NVMe controller",
        (0x02, _) => "network controller",
        (0x03, _) => "display controller",
        (0x06, 0x00) => "host bridge",
        (0x06, 0x01) => "ISA bridge",
        (0x06, 0x04) => "PCI-PCI bridge",
        (0x0C, 0x03) => "USB3 xHCI",
        _ => "other",
    }
}

/// ---- live enumeration (legacy 0xCF8/0xCFC config ports) ----
const CONFIG_ADDRESS_PORT: u16 = 0xCF8;
const CONFIG_DATA_PORT: u16 = 0xCFC;

#[inline]
unsafe fn outl_port(port: u16, value: u32) {
    core::arch::asm!(
        "out dx, eax",
        in("dx") port,
        in("eax") value,
        options(nomem, preserves_flags),
    );
}

#[inline]
unsafe fn inl_port(port: u16) -> u32 {
    let mut value: u32;
    core::arch::asm!(
        "in eax, dx",
        out("eax") value,
        in("dx") port,
        options(nomem, preserves_flags),
    );
    value
}

/// Read a 32-bit dword from PCI config space via ports 0xCF8/0xCFC.
///
/// # Safety
/// Direct port I/O; only callable once the kernel owns the I/O space
/// (after boot bring-up).
pub unsafe fn read_config_dword(address: PciAddress, register: u16) -> u32 {
    outl_port(CONFIG_ADDRESS_PORT, address.to_config_address(register));
    inl_port(CONFIG_DATA_PORT)
}

/// Read a 16-bit word from PCI config space.
///
/// # Safety
/// See `read_config_dword`.
pub unsafe fn read_config_word(address: PciAddress, register: u16) -> u16 {
    let shift = ((register & 2) * 8) as u32;
    (read_config_dword(address, register & 0xFC) >> shift) as u16
}

/// Read an 8-bit byte from PCI config space.
///
/// # Safety
/// See `read_config_dword`.
pub unsafe fn read_config_byte(address: PciAddress, register: u16) -> u8 {
    let shift = ((register & 3) * 8) as u32;
    (read_config_dword(address, register & 0xFC) >> shift) as u8
}

/// Write a 32-bit dword to PCI config space via ports 0xCF8/0xCFC.
///
/// # Safety
/// Direct port I/O; only callable once the kernel owns the I/O space.
pub unsafe fn write_config_dword(address: PciAddress, register: u16, value: u32) {
    outl_port(CONFIG_ADDRESS_PORT, address.to_config_address(register));
    outl_port(CONFIG_DATA_PORT, value);
}

/// Write a 16-bit word to PCI config space (read-modify-write of the
/// containing dword so the sibling register is preserved).
///
/// # Safety
/// See `write_config_dword`.
pub unsafe fn write_config_word(address: PciAddress, register: u16, value: u16) {
    let dword_reg = register & 0xFC;
    let shift = ((register & 2) * 8) as u32;
    let mut dword = read_config_dword(address, dword_reg);
    dword = (dword & !(0xFFFFu32 << shift)) | ((value as u32) << shift);
    write_config_dword(address, dword_reg, dword);
}

/// Set the PCI command register's memory-space, IO-space and bus-master
/// bits (device must be the one being initialized).
///
/// # Safety
/// See `write_config_word`.
pub unsafe fn enable_bus_mastering(address: PciAddress) {
    let mut command = read_config_word(address, COMMAND);
    command |= 0x0003 | 0x0004; // IO space | memory space | bus master
    write_config_word(address, COMMAND, command);
}

/// Enumerate PCI devices present on the bus via the legacy config ports.
///
/// Strategy: sweep bus 0, devices 0..=31. A device whose header has the
/// multifunction bit set gets all 8 functions probed; all others get
/// function 0 only. Non-present slots read back vendor 0xFFFF and are
/// skipped.
///
/// Honest limits: bus 0 only — buses behind PCI-PCI bridges found on real
/// hardware are not traversed; the sweep is verified under QEMU.
///
/// # Safety
/// Port I/O; call once after boot bring-up. Fills `list` and stops at
/// capacity (32 devices).
pub unsafe fn scan_live(list: &mut PciDeviceList) {
    for device in 0..32u8 {
        let function0 = PciAddress::new(0, device, 0);
        // Reading the header of a nonexistent slot returns 0xFF (multifunction
        // bit set), so the probe of function 0 catches it via the vendor check.
        let header_type = read_config_byte(function0, HEADER_TYPE);
        let function_count = if header_type & 0x80 != 0 { 8 } else { 1 };
        for function in 0..function_count {
            let address = PciAddress::new(0, device, function);
            let vendor_id = read_config_word(address, VENDOR_ID);
            if vendor_id == 0xFFFF {
                continue;
            }
            let mut bar = [0u32; 6];
            for (i, slot) in bar.iter_mut().enumerate() {
                *slot = read_config_dword(address, BAR0 + (i as u16) * 4);
            }
            let dev = PciDevice {
                address,
                vendor_id,
                device_id: read_config_word(address, DEVICE_ID),
                class: read_config_byte(address, CLASS),
                subclass: read_config_byte(address, SUBCLASS),
                prog_if: read_config_byte(address, PROG_IF),
                revision: read_config_byte(address, REVISION),
                header_type: header_type & 0x7F,
                bar,
                interrupt_line: read_config_byte(address, INTERRUPT_LINE),
                interrupt_pin: read_config_byte(address, INTERRUPT_PIN),
            };
            if !list.push(dev) {
                return; // list full
            }
        }
    }
}

/// Print one line per enumerated device to the serial console.
pub fn print_report(list: &PciDeviceList) {
    for dev in list.iter() {
        crate::sprintln!(
            "Aegis:   PCI {:02X}:{:02X}.{} vid={:04X} did={:04X} class={:02X}{:02X} prog={:02X} rev={:02X} ({})",
            dev.address.bus,
            dev.address.device,
            dev.address.function,
            dev.vendor_id,
            dev.device_id,
            dev.class,
            dev.subclass,
            dev.prog_if,
            dev.revision,
            class_name(dev.class, dev.subclass),
        );
        for (i, bar) in dev.bar.iter().enumerate() {
            if *bar == 0 {
                continue;
            }
            let kind = if bar_is_io(*bar) {
                "IO"
            } else if bar_is_64bit(*bar) {
                "MMIO64"
            } else {
                "MMIO"
            };
            crate::sprintln!(
                "Aegis:     BAR{} = 0x{:08X} ({}) -> 0x{:X}",
                i,
                bar,
                kind,
                dev.bar_address(i),
            );
        }
    }
}

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
        if bar_is_64bit(bar) && index + 1 < self.bar.len() {
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

impl Default for PciDeviceList {
    fn default() -> Self {
        Self::new()
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
    fn bar_address_rejects_64bit_bar_at_last_index() {
        // A device lying about a 64-bit BAR at the final slot (index 5) has
        // no room for the high half. Must not index bar[6] (panic); treat the
        // high half as absent and return the low part only.
        let mut dev = PciDevice {
            address: PciAddress::new(0, 0, 0),
            vendor_id: 0,
            device_id: 0,
            class: 0,
            subclass: 0,
            prog_if: 0,
            revision: 0,
            header_type: 0,
            bar: [0, 0, 0, 0, 0, 0x1000_0004],
            interrupt_line: 0,
            interrupt_pin: 0,
        };
        // index 5 is a 64-bit BAR with no high half: must not panic.
        assert_eq!(dev.bar_address(5), 0x1000_0000);
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
    fn class_name_maps_nvme_and_bridges() {
        assert_eq!(class_name(0x01, 0x08), "NVMe controller");
        assert_eq!(class_name(0x06, 0x00), "host bridge");
        assert_eq!(class_name(0x06, 0x04), "PCI-PCI bridge");
        assert_eq!(class_name(0x03, 0x00), "display controller");
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
