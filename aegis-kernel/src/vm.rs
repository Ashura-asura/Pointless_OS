//! Phase U: the VM object — lifecycle, capability gate, guest boot
//! loading, and port-I/O dispatch.
//!
//! What this is: the pure-logic layer that ties `ept.rs` (guest memory
//! isolation), `vdev.rs` (the minimal-PC device set) and `virtio.rs` (the
//! virtual disk) together into a single object with the same capability
//! discipline as every other privileged kernel resource. Creating a VM is
//! gated on `Cap::VmRoot` + CONTROL (a singleton, like `NetRoot`); a VM's
//! guest RAM is a `MemGrant`; its EPT refuses any mapping outside that
//! grant before hardware ever sees it.
//!
//! Guest boot follows the Linux boot protocol (32-bit protected-mode
//! entry at 0x100000, boot_params in ESI, setup GDT/TSS, e820 map,
//! cmdline, initrd) — the exact handoff a bootloader like GRUB performs
//! for a `bzImage` — so the guest kernel needs no Aegis-specific patches.
//! The guest is built (`guest/build-guest.sh`) with
//! `console=ttyS0,115200 noapic nolapic`, matching exactly the device set
//! `vdev.rs` emulates.
//!
//! Honest scope, per Ground Rule 6: everything here is CPU-independent,
//! contract-testable logic — boot-parameter layout, e820 encoding, the
//! capability gate, I/O dispatch, virtual-time accounting. The
//! hardware-gated half (real VMX entry with this boot state loaded into a
//! VMCS, real exit-reason 30/1 handling) lives in `vmx.rs` + `main.rs`
//! behind the `vmx-demo` feature; this machine has no VT-x
//! (`VirtualizationFirmwareEnabled` is false), so live verification is
//! pending hardware, exactly like Phase K. Timekeeping is honest but
//! coarse: one host tick = one virtual second for the CMOS RTC, and the
//! virtual PIT advances by a fixed host-tick rate (`host_hz`, a run-loop
//! parameter) — no wall-clock drift correction (a later refinement).

use core::ptr;

use crate::cap::{Cap, CapSlot, Rights};
use crate::ept::{Ept, EptError, MemGrant, PageAlloc, EPT_DEFAULT_FLAGS, PAGE_SIZE};
use crate::vdev::DeviceSet;
use crate::virtio::{BlockStore, GuestMem};

// ---------------------------------------------------------------------
// Guest memory layout (Linux boot protocol on our emulated minimal PC)
// ---------------------------------------------------------------------

/// First guest-physical address of the zero page (boot_params).
pub const ZERO_PAGE_GPA: u64 = 0x10000;
/// Setup GDT (code 0x08, data 0x10, TSS 0x18).
pub const GDT_GPA: u64 = 0x2000;
/// Setup TSS (a zeroed page; its limit/type live in the GDT entry).
pub const TSS_GPA: u64 = 0x2100;
/// Kernel command line (null-terminated).
pub const CMDLINE_GPA: u64 = 0x92000;
/// Top of the guest boot stack (grows down; 16 KiB below the EBDA).
pub const GUEST_STACK_TOP: u64 = 0x9F000;
/// End of the first e820 RAM region (the classic 640 KiB hole).
pub const RAM_TOP: u64 = 0x9FC00;
/// 32-bit protected-mode entry point (`code32_start`).
pub const CODE32_GPA: u64 = 0x100000;
/// Initrd load address (16 MiB — safely above the kernel, inside RAM).
pub const INITRD_GPA: u64 = 0x100_0000;

/// The 8254 PIT input clock (1.19318 MHz).
pub const PIT_CLOCK_HZ: u64 = 1_193_180;

// ---------------------------------------------------------------------
// Errors / state
// ---------------------------------------------------------------------

/// Every failure mode of VM lifecycle and boot loading — all checked
/// paths, none panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmError {
    /// The caller lacks `Cap::VmRoot` with CONTROL.
    NoVmRoot,
    /// The EPT ran out of table pages.
    OutOfPages,
    /// An EPT map refused the grant or an address.
    Ept(EptError),
    /// The image is too small to even hold a boot header.
    ImageTooSmall,
    /// The image is not a Linux bzImage (missing "HdrS").
    NotLinuxImage,
    /// The boot protocol is older than 2.02.
    ProtocolTooOld,
    /// Kernel/initrd/cmdline do not fit the layout or the grant.
    ImageTooBig,
    /// Boot structures would overlap (kernel runs into the initrd).
    Overlap,
    /// A guest-memory read/write failed (unmapped or out of grant).
    GuestIo,
}

/// VM lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmState {
    /// Created, nothing loaded.
    Created,
    /// A boot image is loaded and the VM is runnable.
    Loaded,
    /// The guest is executing (host side).
    Running,
    /// Torn down (EPT structures released).
    Destroyed,
}

// ---------------------------------------------------------------------
// bzImage parsing (Linux boot protocol, pure)
// ---------------------------------------------------------------------

/// Parse the bzImage header and return `(setup_len, code_len)` in bytes.
/// `setup_len` is where the protected-mode code begins; `code_len` is its
/// size (header `syssize` in 16-byte paras). Enforces the minimum header,
/// the "HdrS" magic, and boot protocol >= 2.02.
pub fn parse_bzimage(image: &[u8]) -> Result<(u32, u32), VmError> {
    const HDRS_MAGIC: u32 = 0x5372_6448; // "HdrS" little-endian
    if image.len() < 0x202 + 4 {
        return Err(VmError::ImageTooSmall);
    }
    let magic = u32::from_le_bytes([image[0x202], image[0x203], image[0x204], image[0x205]]);
    if magic != HDRS_MAGIC {
        return Err(VmError::NotLinuxImage);
    }
    let version = u16::from_le_bytes([image[0x206], image[0x207]]);
    if version < 0x0202 {
        return Err(VmError::ProtocolTooOld);
    }
    let setup_sects = image[0x1F1] as u32;
    let setup_len = (setup_sects + 1) * 512;
    let syssize = u32::from_le_bytes([image[0x1F4], image[0x1F5], image[0x1F6], image[0x1F7]]);
    let code_len = syssize.checked_mul(16).ok_or(VmError::ImageTooBig)?;
    if setup_len as u64 + code_len as u64 > image.len() as u64 {
        return Err(VmError::ImageTooSmall);
    }
    Ok((setup_len, code_len))
}

// ---------------------------------------------------------------------
// GuestBoot: layout + boot-parameter encoding
// ---------------------------------------------------------------------

/// The resolved boot layout for one guest: where everything went and the
/// register state the VMCS must be loaded with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestBoot {
    pub kernel_gpa: u64,
    pub kernel_len: u32,
    pub initrd_gpa: u64,
    pub initrd_len: u32,
    pub cmdline_gpa: u64,
    pub zero_page_gpa: u64,
    pub gdt_gpa: u64,
    pub tss_gpa: u64,
    pub stack_top: u64,
    /// One past the last byte of guest RAM (end of the grant) — the
    /// second e820 RAM region runs to here.
    pub ram_end_gpa: u64,
}

/// Number of 4 KiB pages a `len`-byte range touches.
fn pages_for(len: u64) -> u64 {
    len.div_ceil(PAGE_SIZE)
}

impl GuestBoot {
    /// Resolve the layout for `image`/`initrd`/`cmdline` inside `grant`.
    /// Pure: no memory touched, so every layout failure is testable
    /// without any guest RAM.
    pub fn build(
        grant: &MemGrant,
        image: &[u8],
        initrd: Option<&[u8]>,
        cmdline: &str,
    ) -> Result<GuestBoot, VmError> {
        let (_, code_len) = parse_bzimage(image)?;
        let kernel_end = CODE32_GPA
            .checked_add(code_len as u64)
            .ok_or(VmError::ImageTooBig)?;
        if kernel_end > INITRD_GPA {
            return Err(VmError::Overlap);
        }
        let initrd_len = initrd.map(|i| i.len() as u64).unwrap_or(0);
        let initrd_end = INITRD_GPA
            .checked_add(initrd_len)
            .ok_or(VmError::ImageTooBig)?;
        if initrd_end > grant.end_gpa() {
            return Err(VmError::ImageTooBig);
        }
        let cmdline_bytes = cmdline.len() as u64 + 1;
        if CMDLINE_GPA + cmdline_bytes > RAM_TOP {
            return Err(VmError::ImageTooBig);
        }
        // Every boot structure must be inside the grant.
        for (gpa, len) in [
            (ZERO_PAGE_GPA, PAGE_SIZE),
            (GDT_GPA, PAGE_SIZE),
            (TSS_GPA, PAGE_SIZE),
            (CMDLINE_GPA, cmdline_bytes),
            (CODE32_GPA, code_len as u64),
            (INITRD_GPA, initrd_len),
        ] {
            let pages = pages_for(len);
            if pages > 0 && !grant.contains(gpa, pages) {
                return Err(VmError::ImageTooBig);
            }
        }
        Ok(GuestBoot {
            kernel_gpa: CODE32_GPA,
            kernel_len: code_len,
            initrd_gpa: INITRD_GPA,
            initrd_len: initrd_len as u32,
            cmdline_gpa: CMDLINE_GPA,
            zero_page_gpa: ZERO_PAGE_GPA,
            gdt_gpa: GDT_GPA,
            tss_gpa: TSS_GPA,
            stack_top: GUEST_STACK_TOP,
            ram_end_gpa: grant.end_gpa(),
        })
    }

    /// Write every boot structure into guest memory: zero page (boot
    /// params + e820), setup GDT/TSS, kernel image, initrd, cmdline.
    /// All writes go through `GuestMem` (the EPT in production, a fake in
    /// the contract tests), so a failure anywhere is `GuestIo`.
    pub fn write_all(
        &self,
        mem: &mut impl GuestMem,
        image: &[u8],
        initrd: Option<&[u8]>,
        cmdline: &str,
    ) -> Result<(), VmError> {
        let (setup_len, code_len) = parse_bzimage(image)?;
        let kernel = &image[setup_len as usize..(setup_len + code_len) as usize];
        // Zero the whole zero page first: unset fields must read 0.
        mem.write(self.zero_page_gpa, &[0u8; 4096])
            .then_some(())
            .ok_or(VmError::GuestIo)?;
        self.write_boot_params(mem, image, initrd, cmdline)?;
        self.write_e820(mem)?;
        self.write_gdt(mem)?;
        mem.write(self.tss_gpa, &[0u8; 4096])
            .then_some(())
            .ok_or(VmError::GuestIo)?;
        mem.write(self.kernel_gpa, kernel)
            .then_some(())
            .ok_or(VmError::GuestIo)?;
        if let Some(ir) = initrd {
            mem.write(self.initrd_gpa, ir)
                .then_some(())
                .ok_or(VmError::GuestIo)?;
        }
        let mut cmd = [0u8; 256];
        let n = cmdline.len().min(cmd.len() - 1);
        cmd[..n].copy_from_slice(&cmdline.as_bytes()[..n]);
        cmd[n] = 0;
        mem.write(self.cmdline_gpa, &cmd[..n + 1])
            .then_some(())
            .ok_or(VmError::GuestIo)?;
        Ok(())
    }

    /// Boot-protocol fields in the zero page (offsets per the Linux boot
    /// protocol; `bzImage` header values are echoed so the kernel sees a
    /// consistent handoff).
    fn write_boot_params(
        &self,
        mem: &mut impl GuestMem,
        image: &[u8],
        initrd: Option<&[u8]>,
        cmdline: &str,
    ) -> Result<(), VmError> {
        let base = self.zero_page_gpa;
        w8(mem, base + 0x1E8, 4)?; // e820_entries
        w8(mem, base + 0x1F1, image[0x1F1])?; // setup_sects
        w32(
            mem,
            base + 0x1F4,
            u32::from_le_bytes([image[0x1F4], image[0x1F5], image[0x1F6], image[0x1F7]]),
        )?; // syssize
        w32(mem, base + 0x202, 0x5372_6448)?; // "HdrS"
        w16(mem, base + 0x206, 0x0202)?; // protocol version
        w8(mem, base + 0x210, 0xFF)?; // type_of_loader: unknown/other
        w8(mem, base + 0x211, 0x01)?; // loadflags: LOADED_HIGH
        w32(mem, base + 0x214, CODE32_GPA as u32)?; // code32_start
        w32(mem, base + 0x218, INITRD_GPA as u32)?; // ramdisk_image
        w32(
            mem,
            base + 0x21C,
            initrd.map(|i| i.len() as u32).unwrap_or(0),
        )?; // ramdisk_size
        w32(mem, base + 0x228, CMDLINE_GPA as u32)?; // cmd_line_ptr
        w32(mem, base + 0x22C, u32::MAX)?; // initrd_addr_max
        let _ = cmdline;
        Ok(())
    }

    /// The classic minimal-PC e820 map: 640 KiB RAM, EBDA reserved,
    /// VGA reserved, then RAM up to the end of the grant.
    fn write_e820(&self, mem: &mut impl GuestMem) -> Result<(), VmError> {
        let grant_end = self.ram_end_gpa;
        let entries: [(u64, u64, u32); 4] = [
            (0x0, 0x9FC00, 1),                   // RAM
            (0x9FC00, 0x400, 2),                 // EBDA reserved
            (0xA0000, 0x60000, 2),               // VGA reserved
            (0x100000, grant_end - 0x100000, 1), // RAM
        ];
        for (i, (base, len, ty)) in entries.iter().enumerate() {
            let off = self.zero_page_gpa + 0x2D0 + (i as u64) * 20;
            w64(mem, off, *base)?;
            w64(mem, off + 8, *len)?;
            w32(mem, off + 16, *ty)?;
        }
        Ok(())
    }

    /// Setup GDT: null, 32-bit code (0x08), 32-bit data (0x10), TSS (0x18).
    /// The access bytes match the VMCS guest-segment AR bytes used at
    /// VM-entry (code 0x9A | D=1 | G=1 -> 0xC09B; data 0xC093; TSS busy
    /// 0x8B), so the CPU's guest-state checks and the guest's own segment
    /// state agree.
    fn write_gdt(&self, mem: &mut impl GuestMem) -> Result<(), VmError> {
        let mut gdt = [0u8; 32];
        gdt[8..16].copy_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xCF, 0x00]); // code
        gdt[16..24].copy_from_slice(&[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00]); // data
                                                                                        // TSS: base TSS_GPA, limit 0x67, busy 32-bit TSS.
        let b = self.tss_gpa;
        gdt[24..32].copy_from_slice(&[
            0x67,
            0x00,
            (b & 0xFF) as u8,
            ((b >> 8) & 0xFF) as u8,
            ((b >> 16) & 0xFF) as u8,
            0x8B,
            ((b >> 24) & 0xFF) as u8,
            0x00,
        ]);
        mem.write(self.gdt_gpa, &gdt)
            .then_some(())
            .ok_or(VmError::GuestIo)
    }

    /// The register state a VMCS must be loaded with for this boot.
    pub fn boot_state(&self) -> BootState {
        BootState {
            eip: CODE32_GPA,
            esi: ZERO_PAGE_GPA,
            rsp: GUEST_STACK_TOP,
            cs: 0x08,
            ds: 0x10,
            es: 0x10,
            fs: 0x10,
            gs: 0x10,
            ss: 0x10,
            gdt_base: GDT_GPA,
            gdt_limit: 31,
            tr: 0x18,
            tss_base: TSS_GPA,
            tss_limit: 0x67,
            cr0: 0x31,   // PE | ET | NE
            cr4: 0x2000, // VMXE mirror (the guest must see VMX enabled)
            rflags: 0x2,
        }
    }
}

/// The CPU state the hypervisor must load for the guest (VMCS fields on
/// the real side; exact same numbers in the contract tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootState {
    pub eip: u64,
    pub esi: u64,
    pub rsp: u64,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
    pub gdt_base: u64,
    pub gdt_limit: u16,
    pub tr: u16,
    pub tss_base: u64,
    pub tss_limit: u16,
    pub cr0: u64,
    pub cr4: u64,
    pub rflags: u64,
}

// ---------------------------------------------------------------------
// Little-endian writes through GuestMem
// ---------------------------------------------------------------------

fn w8(mem: &mut impl GuestMem, gpa: u64, v: u8) -> Result<(), VmError> {
    mem.write(gpa, &[v]).then_some(()).ok_or(VmError::GuestIo)
}

fn w16(mem: &mut impl GuestMem, gpa: u64, v: u16) -> Result<(), VmError> {
    mem.write(gpa, &v.to_le_bytes())
        .then_some(())
        .ok_or(VmError::GuestIo)
}

fn w32(mem: &mut impl GuestMem, gpa: u64, v: u32) -> Result<(), VmError> {
    mem.write(gpa, &v.to_le_bytes())
        .then_some(())
        .ok_or(VmError::GuestIo)
}

fn w64(mem: &mut impl GuestMem, gpa: u64, v: u64) -> Result<(), VmError> {
    mem.write(gpa, &v.to_le_bytes())
        .then_some(())
        .ok_or(VmError::GuestIo)
}

// ---------------------------------------------------------------------
// Virtual time: host ticks -> guest PIT cycles
// ---------------------------------------------------------------------

/// Converts host timer ticks into virtual PIT cycles at a fixed rate.
/// Host tick rate is a run-loop parameter (`host_hz`); the fraction
/// (sub-cycle) accumulates across ticks so no cycles are lost over time.
pub struct PitTicker {
    /// PIT cycles per host tick, scaled x1000 (fixed point).
    cycles_per_tick_milli: u64,
    /// Accumulated fractional cycles (milli-cycles).
    acc: u64,
}

impl PitTicker {
    pub const fn new(host_hz: u32) -> PitTicker {
        PitTicker {
            cycles_per_tick_milli: if host_hz == 0 {
                0
            } else {
                (PIT_CLOCK_HZ * 1000) / host_hz as u64
            },
            acc: 0,
        }
    }

    /// Advance one host tick; returns the virtual PIT cycles to feed the
    /// 8254 this tick.
    pub fn advance(&mut self) -> u32 {
        self.acc += self.cycles_per_tick_milli;
        let cycles = (self.acc / 1000) as u32;
        self.acc %= 1000;
        cycles
    }
}

// ---------------------------------------------------------------------
// GuestMem over the EPT
// ---------------------------------------------------------------------

/// `GuestMem` implementation over a live EPT: translates each touched
/// page and copies through the host-physical mapping. Bounds are the EPT
/// itself — anything unmapped fails `read`/`write` with `false`.
pub struct EptMem<'e> {
    ept: &'e mut Ept,
}

impl<'e> EptMem<'e> {
    pub fn new(ept: &'e mut Ept) -> EptMem<'e> {
        EptMem { ept }
    }
}

impl GuestMem for EptMem<'_> {
    fn read(&mut self, gpa: u64, buf: &mut [u8]) -> bool {
        let ept = &*self.ept;
        let mut off = 0usize;
        let mut g = gpa;
        while off < buf.len() {
            let Some(hpa) = ept.translate(g) else {
                return false;
            };
            let in_page = (PAGE_SIZE - (g & (PAGE_SIZE - 1))) as usize;
            let n = in_page.min(buf.len() - off);
            unsafe {
                ptr::copy_nonoverlapping(
                    (hpa + (g & (PAGE_SIZE - 1))) as *const u8,
                    buf.as_mut_ptr().add(off),
                    n,
                )
            };
            off += n;
            g += n as u64;
        }
        true
    }

    fn write(&mut self, gpa: u64, buf: &[u8]) -> bool {
        let ept = &*self.ept;
        let mut off = 0usize;
        let mut g = gpa;
        while off < buf.len() {
            let Some(hpa) = ept.translate(g) else {
                return false;
            };
            let in_page = (PAGE_SIZE - (g & (PAGE_SIZE - 1))) as usize;
            let n = in_page.min(buf.len() - off);
            unsafe {
                ptr::copy_nonoverlapping(
                    buf.as_ptr().add(off),
                    (hpa + (g & (PAGE_SIZE - 1))) as *mut u8,
                    n,
                )
            };
            off += n;
            g += n as u64;
        }
        true
    }
}

// ---------------------------------------------------------------------
// The VM object
// ---------------------------------------------------------------------

/// One guest VM. Owns its memory grant (capability), EPT (isolation),
/// device set (emulation), and boot state.
pub struct Vm<'a, S: BlockStore> {
    pub id: u32,
    pub state: VmState,
    pub grant: MemGrant,
    pub ept: Ept,
    pub devices: DeviceSet<'a, S>,
    pub boot: Option<GuestBoot>,
    pub ticker: PitTicker,
    /// Host-physical address of the grant's first frame. The kernel's own
    /// RAM convention is identity (guest phys == host phys), so the kernel
    /// passes `grant.start_gpa`; the contract tests pass a contiguous host
    /// buffer's address so `EptMem` writes land in real memory.
    pub host_ram_base: u64,
    /// EPT violations refused since creation (the isolation counter).
    pub ept_violations: u64,
}

impl<'a, S: BlockStore> Vm<'a, S> {
    pub fn new(
        id: u32,
        grant: MemGrant,
        devices: DeviceSet<'a, S>,
        host_ram_base: u64,
        host_hz: u32,
    ) -> Vm<'a, S> {
        Vm {
            id,
            state: VmState::Created,
            grant,
            ept: Ept::new(),
            devices,
            boot: None,
            ticker: PitTicker::new(host_hz),
            host_ram_base,
            ept_violations: 0,
        }
    }

    /// Load a Linux bzImage (with optional initrd and cmdline) into the
    /// guest. Maps the grant to `host_ram_base` (identity in the kernel,
    /// a host buffer in the contract tests) and writes every boot
    /// structure. Only `VmRoot:CONTROL` holders may create a VM;
    /// `Vm::new` itself is the syscall-visible entry point and the gate
    /// is checked by the caller (`sys_vm_create`), mirrored here by
    /// `can_create_vm` for the contract tests.
    pub fn load_linux(
        &mut self,
        alloc: &mut impl PageAlloc,
        image: &[u8],
        initrd: Option<&[u8]>,
        cmdline: &str,
    ) -> Result<(), VmError> {
        let boot = GuestBoot::build(&self.grant, image, initrd, cmdline)?;
        if self.ept.is_empty() {
            self.ept
                .map(
                    alloc,
                    &self.grant,
                    self.grant.start_gpa,
                    self.host_ram_base,
                    self.grant.frames,
                    EPT_DEFAULT_FLAGS,
                )
                .map_err(VmError::Ept)?;
        }
        let mut mem = EptMem::new(&mut self.ept);
        boot.write_all(&mut mem, image, initrd, cmdline)?;
        self.boot = Some(boot);
        self.state = VmState::Loaded;
        Ok(())
    }

    /// Dispatch one port-I/O access (VM-exit reason 30). `size` is the
    /// access width in bytes (1/2/4); `out` selects out vs. in; `val` is
    /// the value for out accesses. Returns the value read (0 for writes).
    pub fn handle_io(&mut self, port: u16, size: u8, out: bool, val: u32) -> u32 {
        match (size, out) {
            (1, false) => self.devices.inb(port) as u32,
            (1, true) => {
                self.devices.outb(port, val as u8);
                0
            }
            (2, false) => self.devices.inw(port) as u32,
            (2, true) => {
                self.devices.outw(port, val as u16);
                0
            }
            (4, false) => self.devices.inl(port),
            (4, true) => {
                self.devices.outl(port, val);
                0
            }
            _ => 0xFFFF_FFFF,
        }
    }

    /// Advance virtual time by `host_ticks` host timer ticks: feeds the
    /// virtual PIT (returning IRQ0 pulses to raise) and the coarse CMOS
    /// clock (one tick = one second, documented approximation).
    pub fn advance_time(&mut self, host_ticks: u32) -> u32 {
        let mut pulses = 0u32;
        for _ in 0..host_ticks {
            let cycles = self.ticker.advance();
            if cycles > 0 {
                pulses += self.devices.pit.advance(cycles);
            }
        }
        self.devices.rtc.advance_seconds(host_ticks as u64);
        pulses
    }

    /// Release every EPT table page (guest frames are the grant and are
    /// freed by the caller). Safe to call twice.
    pub fn teardown(&mut self, alloc: &mut impl PageAlloc) {
        self.ept.unmap_all(alloc);
        self.state = VmState::Destroyed;
    }
}

/// The capability gate for creating a VM: the caller must hold
/// `Cap::VmRoot` with `VM_ROOT_RIGHTS` (CONTROL). Mirrors
/// `netif::sys_net_socket`'s NetRoot gate.
pub fn can_create_vm(table: &[CapSlot]) -> bool {
    table
        .iter()
        .any(|s| s.cap == Cap::VmRoot && s.rights.contains(Rights::CONTROL))
}

// ---------------------------------------------------------------------
// Tests (pure protocol/encoding/state logic — no VMX CPU required)
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake bzImage with a valid 2.02 header and `code_len` bytes of
    /// patterned protected-mode code (byte i of the payload = i % 251).
    fn fake_image(code_len: usize) -> Vec<u8> {
        let setup_len = 1024; // setup_sects = 1
        let mut img = vec![0u8; setup_len + code_len];
        img[0x1F1] = 1;
        img[0x1F4..0x1F8].copy_from_slice(&((code_len / 16) as u32).to_le_bytes());
        img[0x202..0x206].copy_from_slice(b"HdrS");
        img[0x206..0x208].copy_from_slice(&0x0202u16.to_le_bytes());
        for (i, b) in img[setup_len..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        img
    }

    /// Flat guest-memory fake (contract tests for the boot-parameter
    /// layout without any EPT).
    struct FakeMem {
        bytes: Vec<u8>,
    }

    impl FakeMem {
        fn new(size: usize) -> FakeMem {
            FakeMem {
                bytes: vec![0u8; size],
            }
        }
    }

    impl GuestMem for FakeMem {
        fn read(&mut self, gpa: u64, buf: &mut [u8]) -> bool {
            let s = gpa as usize;
            let e = s + buf.len();
            if e > self.bytes.len() {
                return false;
            }
            buf.copy_from_slice(&self.bytes[s..e]);
            true
        }
        fn write(&mut self, gpa: u64, buf: &[u8]) -> bool {
            let s = gpa as usize;
            let e = s + buf.len();
            if e > self.bytes.len() {
                return false;
            }
            self.bytes[s..e].copy_from_slice(buf);
            true
        }
    }

    fn u16_at(mem: &FakeMem, gpa: u64) -> u16 {
        u16::from_le_bytes([mem.bytes[gpa as usize], mem.bytes[gpa as usize + 1]])
    }

    fn u32_at(mem: &FakeMem, gpa: u64) -> u32 {
        u32::from_le_bytes([
            mem.bytes[gpa as usize],
            mem.bytes[gpa as usize + 1],
            mem.bytes[gpa as usize + 2],
            mem.bytes[gpa as usize + 3],
        ])
    }

    fn u64_at(mem: &FakeMem, gpa: u64) -> u64 {
        u64::from_le_bytes([
            mem.bytes[gpa as usize],
            mem.bytes[gpa as usize + 1],
            mem.bytes[gpa as usize + 2],
            mem.bytes[gpa as usize + 3],
            mem.bytes[gpa as usize + 4],
            mem.bytes[gpa as usize + 5],
            mem.bytes[gpa as usize + 6],
            mem.bytes[gpa as usize + 7],
        ])
    }

    /// 32 MiB grant at 0 (the kernel's own RAM convention).
    fn grant() -> MemGrant {
        MemGrant::new(0, 8192)
    }

    /// A heap page that is *really* 4 KiB aligned (see the identical arena
    /// in `ept.rs` tests: `Box<[u64; 512]>` is only 8-byte aligned, so
    /// rounding its address up would push the fake page past the block end).
    #[repr(align(4096))]
    struct Page(#[allow(dead_code)] [u64; 512]);

    /// EPT table-page arena (same pattern as `ept.rs` tests).
    struct TestAlloc {
        pages: Vec<(u64, Box<Page>)>,
    }

    impl TestAlloc {
        fn new() -> TestAlloc {
            TestAlloc { pages: Vec::new() }
        }
        fn outstanding(&self) -> usize {
            self.pages.len()
        }
    }

    impl PageAlloc for TestAlloc {
        fn alloc_page(&mut self) -> Option<u64> {
            let page: Box<Page> = Box::new(Page([0; 512]));
            let phys = page.as_ref() as *const Page as u64;
            self.pages.push((phys, page));
            Some(phys)
        }
        fn free_page(&mut self, phys: u64) -> bool {
            match self.pages.iter().position(|(p, _)| *p == phys) {
                Some(i) => {
                    self.pages.remove(i);
                    true
                }
                None => false,
            }
        }
    }

    struct MemStore {
        bytes: Vec<u8>,
        capacity: u64,
    }

    impl MemStore {
        fn new(sectors: u64) -> MemStore {
            MemStore {
                bytes: vec![0u8; (sectors * 512) as usize],
                capacity: sectors,
            }
        }
    }

    impl BlockStore for MemStore {
        fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> bool {
            let s = (lba * 512) as usize;
            let e = s + 512;
            if e > self.bytes.len() {
                return false;
            }
            out.copy_from_slice(&self.bytes[s..e]);
            true
        }
        fn write_sector(&mut self, lba: u64, data: &[u8]) -> bool {
            let s = (lba * 512) as usize;
            let e = s + 512;
            if e > self.bytes.len() {
                return false;
            }
            self.bytes[s..e].copy_from_slice(data);
            true
        }
        fn capacity_sectors(&self) -> u64 {
            self.capacity
        }
    }

    // ---- bzImage parsing -------------------------------------------------

    #[test]
    fn parse_rejects_truncated_and_non_linux_images() {
        assert_eq!(parse_bzimage(&[0u8; 10]), Err(VmError::ImageTooSmall));
        let mut img = vec![0u8; 0x300];
        assert_eq!(parse_bzimage(&img), Err(VmError::NotLinuxImage));
        img[0x202..0x206].copy_from_slice(b"HdrS");
        img[0x206..0x208].copy_from_slice(&0x0200u16.to_le_bytes());
        assert_eq!(parse_bzimage(&img), Err(VmError::ProtocolTooOld));
    }

    #[test]
    fn parse_accepts_real_header_layout() {
        let img = fake_image(4096);
        let (setup_len, code_len) = parse_bzimage(&img).unwrap();
        assert_eq!(setup_len, 1024);
        assert_eq!(code_len, 4096);
        // Truncated payload is refused even with a valid header.
        assert_eq!(
            parse_bzimage(&img[..1024 + 100]),
            Err(VmError::ImageTooSmall)
        );
    }

    // ---- layout resolution ------------------------------------------------

    #[test]
    fn build_rejects_overlapping_and_oversized_layouts() {
        let g = grant();
        // Kernel that would run into the initrd slot.
        let big = fake_image(0x100_0000);
        assert_eq!(
            GuestBoot::build(&g, &big, Some(&[0u8; 4]), "x"),
            Err(VmError::Overlap)
        );
        // Initrd that does not fit the grant (grant ends at 32 MiB).
        let img = fake_image(4096);
        assert_eq!(
            GuestBoot::build(&g, &img, Some(&[0u8; 0x100_0000 + 1]), "x"),
            Err(VmError::ImageTooBig)
        );
        // Command line that would overlap the EBDA region.
        let long: String = "x".repeat(60_000);
        assert_eq!(
            GuestBoot::build(&g, &img, None, &long),
            Err(VmError::ImageTooBig)
        );
        // A grant that does not cover the low structures is refused.
        let small = MemGrant::new(0x2000, 4);
        assert_eq!(
            GuestBoot::build(&small, &img, None, "x"),
            Err(VmError::ImageTooBig)
        );
    }

    #[test]
    fn build_resolves_the_standard_layout() {
        let img = fake_image(4096);
        let boot = GuestBoot::build(&grant(), &img, Some(&[0xAB; 16]), "console=ttyS0").unwrap();
        assert_eq!(boot.kernel_gpa, CODE32_GPA);
        assert_eq!(boot.kernel_len, 4096);
        assert_eq!(boot.initrd_gpa, INITRD_GPA);
        assert_eq!(boot.initrd_len, 16);
        assert_eq!(boot.cmdline_gpa, CMDLINE_GPA);
        assert_eq!(boot.zero_page_gpa, ZERO_PAGE_GPA);
        assert_eq!(boot.ram_end_gpa, 0x200_0000);
    }

    // ---- boot-parameter encoding ------------------------------------------

    #[test]
    fn write_all_encodes_boot_protocol_fields() {
        let img = fake_image(4096);
        let mut mem = FakeMem::new(0x200_0000);
        let boot = GuestBoot::build(&grant(), &img, Some(&[0xAB; 16]), "console=ttyS0").unwrap();
        boot.write_all(&mut mem, &img, Some(&[0xAB; 16]), "console=ttyS0")
            .unwrap();
        let zp = ZERO_PAGE_GPA;
        assert_eq!(mem.bytes[zp as usize + 0x1E8], 4); // e820 entries
        assert_eq!(mem.bytes[zp as usize + 0x1F1], 1); // setup_sects
        assert_eq!(u32_at(&mem, zp + 0x1F4), 256); // syssize (4096 / 16)
        assert_eq!(u32_at(&mem, zp + 0x202), 0x5372_6448); // "HdrS"
        assert_eq!(u16_at(&mem, zp + 0x206), 0x0202);
        assert_eq!(mem.bytes[zp as usize + 0x210], 0xFF); // type_of_loader
        assert_eq!(mem.bytes[zp as usize + 0x211], 0x01); // LOADED_HIGH
        assert_eq!(u32_at(&mem, zp + 0x214), CODE32_GPA as u32);
        assert_eq!(u32_at(&mem, zp + 0x218), INITRD_GPA as u32);
        assert_eq!(u32_at(&mem, zp + 0x21C), 16);
        assert_eq!(u32_at(&mem, zp + 0x228), CMDLINE_GPA as u32);
        assert_eq!(u32_at(&mem, zp + 0x22C), u32::MAX); // initrd_addr_max
                                                        // Kernel bytes landed at 0x100000 with the payload pattern.
        for i in 0..4096usize {
            assert_eq!(mem.bytes[CODE32_GPA as usize + i], (i % 251) as u8);
        }
        // Initrd, cmdline (null-terminated).
        assert_eq!(
            &mem.bytes[INITRD_GPA as usize..INITRD_GPA as usize + 16],
            &[0xAB; 16]
        );
        assert_eq!(
            &mem.bytes[CMDLINE_GPA as usize..CMDLINE_GPA as usize + 14],
            b"console=ttyS0\0"
        );
    }

    #[test]
    fn write_all_encodes_the_minimal_pc_e820_map() {
        let img = fake_image(4096);
        let mut mem = FakeMem::new(0x200_0000);
        let boot = GuestBoot::build(&grant(), &img, None, "").unwrap();
        boot.write_all(&mut mem, &img, None, "").unwrap();
        let zp = ZERO_PAGE_GPA;
        let e820 = zp + 0x2D0;
        // Entry 0: 0..0x9FC00 RAM.
        assert_eq!(u64_at(&mem, e820), 0);
        assert_eq!(u64_at(&mem, e820 + 8), 0x9FC00);
        assert_eq!(u32_at(&mem, e820 + 16), 1);
        // Entry 1: EBDA reserved.
        assert_eq!(u64_at(&mem, e820 + 20), 0x9FC00);
        assert_eq!(u64_at(&mem, e820 + 28), 0x400);
        assert_eq!(u32_at(&mem, e820 + 36), 2);
        // Entry 2: VGA reserved.
        assert_eq!(u64_at(&mem, e820 + 40), 0xA0000);
        assert_eq!(u64_at(&mem, e820 + 48), 0x60000);
        assert_eq!(u32_at(&mem, e820 + 56), 2);
        // Entry 3: RAM to the end of the grant (32 MiB).
        assert_eq!(u64_at(&mem, e820 + 60), 0x100000);
        assert_eq!(u64_at(&mem, e820 + 68), 0x200_0000 - 0x100000);
        assert_eq!(u32_at(&mem, e820 + 76), 1);
    }

    #[test]
    fn write_all_encodes_gdt_and_tss() {
        let img = fake_image(4096);
        let mut mem = FakeMem::new(0x200_0000);
        let boot = GuestBoot::build(&grant(), &img, None, "").unwrap();
        boot.write_all(&mut mem, &img, None, "").unwrap();
        // Code segment at selector 0x08: base 0, limit 0xFFFFF, D=1, G=1.
        assert_eq!(
            &mem.bytes[GDT_GPA as usize + 8..GDT_GPA as usize + 16],
            &[0xFF, 0xFF, 0, 0, 0, 0x9A, 0xCF, 0]
        );
        // Data segment at 0x10.
        assert_eq!(
            &mem.bytes[GDT_GPA as usize + 16..GDT_GPA as usize + 24],
            &[0xFF, 0xFF, 0, 0, 0, 0x92, 0xCF, 0]
        );
        // TSS at 0x18: base 0x2100, limit 0x67, busy 32-bit TSS (0x8B).
        assert_eq!(
            &mem.bytes[GDT_GPA as usize + 24..GDT_GPA as usize + 32],
            &[0x67, 0x00, 0x00, 0x21, 0x00, 0x8B, 0x00, 0x00]
        );
        // TSS page itself is zeroed.
        assert!(mem.bytes[TSS_GPA as usize..TSS_GPA as usize + 4096]
            .iter()
            .all(|&b| b == 0));
    }

    #[test]
    fn boot_state_matches_the_protocol() {
        let img = fake_image(4096);
        let boot = GuestBoot::build(&grant(), &img, None, "").unwrap();
        let st = boot.boot_state();
        assert_eq!(st.eip, CODE32_GPA);
        assert_eq!(st.esi, ZERO_PAGE_GPA);
        assert_eq!(st.rsp, GUEST_STACK_TOP);
        assert_eq!((st.cs, st.ds, st.ss, st.tr), (0x08, 0x10, 0x10, 0x18));
        assert_eq!((st.gdt_base, st.gdt_limit), (GDT_GPA, 31));
        assert_eq!((st.tss_base, st.tss_limit), (TSS_GPA, 0x67));
        assert_eq!(st.cr0, 0x31); // PE | ET | NE
        assert_eq!(st.cr4, 0x2000); // VMXE mirror
        assert_eq!(st.rflags, 0x2);
    }

    // ---- virtual time -----------------------------------------------------

    #[test]
    fn pit_ticker_accumulates_fractional_cycles() {
        // 100 Hz host tick: 1193180 / 100 = 11931.8 cycles per tick.
        let mut t = PitTicker::new(100);
        assert_eq!(t.advance(), 11931);
        assert_eq!(t.advance(), 11932); // the 0.8 accumulates
                                        // Zero host rate: nothing advances (no divide-by-zero).
        let mut z = PitTicker::new(0);
        assert_eq!(z.advance(), 0);
    }

    /// A heap buffer big enough to stand in for host RAM, page-aligned so it
    /// can anchor an EPT mapping (heap pointers are only 8-byte aligned).
    fn aligned_ram(len: usize) -> (Vec<u8>, u64) {
        let mut backing = vec![0u8; len + 4096];
        let raw = backing.as_mut_ptr() as u64;
        let host_base = (raw + 4095) & !4095u64;
        (backing, host_base)
    }

    // ---- EptMem over a real EPT -------------------------------------------

    #[test]
    fn ept_mem_reads_and_writes_through_translation() {
        let mut alloc = TestAlloc::new();
        let mut ept = Ept::new();
        // The host side of the mapping is a real contiguous buffer (the
        // kernel's RAM; a heap buffer in the contract tests).
        let (backing, host_base) = aligned_ram(64 * 4096);
        let g = MemGrant::new(0x1000_0000, 64);
        ept.map(&mut alloc, &g, 0x1000_0000, host_base, 2, EPT_DEFAULT_FLAGS)
            .unwrap();
        let mut mem = EptMem::new(&mut ept);
        assert!(mem.write(0x1000_0FFC, &[1u8, 2, 3, 4, 5, 6, 7, 8])); // spans pages
        let mut back = [0u8; 8];
        assert!(mem.read(0x1000_0FFC, &mut back));
        assert_eq!(back, [1, 2, 3, 4, 5, 6, 7, 8]);
        // Really in RAM (the host mapping is offset by the alignment
        // padding between the Vec start and the page-aligned base).
        let pad = (host_base - backing.as_ptr() as u64) as usize;
        assert_eq!(
            &backing[pad + 0xFFC..pad + 0x1004],
            &[1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert!(!mem.write(0x2000_0000, &[0u8; 4])); // unmapped
        assert!(!mem.read(0x2000_0000, &mut [0u8; 4]));
        ept.unmap_all(&mut alloc);
        assert_eq!(alloc.outstanding(), 0);
    }

    // ---- the VM object ----------------------------------------------------

    #[test]
    fn vm_load_linux_end_to_end_through_real_ept() {
        let img = fake_image(4096);
        let mut store = MemStore::new(64);
        let devices = DeviceSet::new(&mut store, 1_700_000_000);
        // Host RAM: a 32 MiB buffer standing in for the kernel's RAM.
        let (_backing, host_base) = aligned_ram(0x200_0000);
        let mut vm = Vm::new(0, grant(), devices, host_base, 62);
        assert_eq!(vm.state, VmState::Created);
        let mut alloc = TestAlloc::new();
        vm.load_linux(&mut alloc, &img, Some(&[0xCD; 32]), "console=ttyS0,115200")
            .unwrap();
        assert_eq!(vm.state, VmState::Loaded);
        let boot = vm.boot.unwrap();
        assert_eq!(boot.kernel_len, 4096);
        assert_eq!(boot.initrd_len, 32);
        // Read back through the live EPT.
        let mut mem = EptMem::new(&mut vm.ept);
        let mut zp = [0u8; 4096];
        assert!(mem.read(ZERO_PAGE_GPA, &mut zp));
        assert_eq!(zp[0x1E8], 4);
        let code32 = u32::from_le_bytes([zp[0x214], zp[0x215], zp[0x216], zp[0x217]]);
        assert_eq!(code32 as u64, CODE32_GPA);
        let mut k = [0u8; 16];
        assert!(mem.read(CODE32_GPA, &mut k));
        assert_eq!(k[0], 0); // payload pattern: byte 0 of code
        let mut ir = [0u8; 32];
        assert!(mem.read(INITRD_GPA, &mut ir));
        assert!(ir.iter().all(|&b| b == 0xCD));
        vm.teardown(&mut alloc);
        assert_eq!(vm.state, VmState::Destroyed);
        assert_eq!(alloc.outstanding(), 0);
    }

    #[test]
    fn vm_capability_gate_controls_creation() {
        use crate::cap::{new_cap_table, CapSlot, CapTable, Rights};
        let mut table: CapTable = new_cap_table();
        // No VmRoot anywhere: creation denied.
        assert!(!can_create_vm(&table));
        table[0] = CapSlot {
            cap: Cap::VmRoot,
            rights: Rights::READ,
        };
        assert!(!can_create_vm(&table), "READ on VmRoot is not enough");
        table[0] = CapSlot {
            cap: Cap::VmRoot,
            rights: Rights::CONTROL,
        };
        assert!(can_create_vm(&table));
        // A Vm reference to an existing VM is not a creation authority.
        table[0] = CapSlot {
            cap: Cap::Vm(3),
            rights: Rights::CONTROL,
        };
        assert!(!can_create_vm(&table));
    }

    #[test]
    fn handle_io_dispatches_byte_word_and_dword() {
        let mut store = MemStore::new(64);
        let devices = DeviceSet::new(&mut store, 0);
        let mut vm = Vm::new(0, grant(), devices, 0, 62);
        // UART console byte out.
        vm.handle_io(0x3F8, 1, true, b'A' as u32);
        assert_eq!(vm.devices.take_guest_tx(), Some(b'A'));
        // PIC programming through the VM.
        vm.handle_io(0x20, 1, true, 0x11);
        vm.handle_io(0x21, 1, true, 0x20);
        vm.handle_io(0x21, 1, true, 0x04);
        vm.handle_io(0x21, 1, true, 0x01);
        vm.handle_io(0x21, 1, true, 0x00);
        assert_eq!(vm.devices.pic.master.base, 0x20);
        // Virtio I/O BAR: program BAR0 to 0xC000 via PCI config space.
        vm.handle_io(0xCF8, 4, true, 0x8000_0000 | (6 << 11) | (4 << 2));
        vm.handle_io(0xCFC, 4, true, 0xC001);
        assert_eq!(vm.devices.pci.virtio_bar(), 0xC000);
        // 16-bit read of QUEUE_NUM_MAX through the VM.
        assert_eq!(vm.handle_io(0xC00E, 2, false, 0), 128u32);
        // Dword read of an unhandled port floats high.
        assert_eq!(vm.handle_io(0x4000, 4, false, 0), 0xFFFF_FFFF);
        // Word read of a byte-only device floats high.
        assert_eq!(vm.handle_io(0x3F8, 2, false, 0), 0xFFFFu32);
    }

    #[test]
    fn advance_time_feeds_pit_and_rtc() {
        let mut store = MemStore::new(64);
        let devices = DeviceSet::new(&mut store, 0);
        let mut vm = Vm::new(0, grant(), devices, 0, 62);
        // Program PIT ch0: count 119318 (100 Hz IRQ0).
        vm.handle_io(0x43, 1, true, 0x36);
        vm.handle_io(0x40, 1, true, 0xB6);
        vm.handle_io(0x40, 1, true, 0x01);
        let pulses = vm.advance_time(10);
        // 10 ticks at 62 Hz = 10 * 1193180/62 = 192448 cycles -> 1 pulse
        // (the remaining 79130 cycles carry over into the next tick).
        assert!(pulses >= 1, "10 host ticks must produce at least one IRQ0");
        // The coarse RTC advanced 10 virtual seconds (BCD 0x10).
        vm.devices.rtc.outb(0x70, 0x00);
        assert_eq!(vm.devices.rtc.inb(0x71), 0x10);
    }

    #[test]
    fn teardown_releases_every_ept_page() {
        let img = fake_image(4096);
        let mut store = MemStore::new(64);
        let devices = DeviceSet::new(&mut store, 0);
        let (_backing, host_base) = aligned_ram(0x200_0000);
        let mut vm = Vm::new(0, grant(), devices, host_base, 62);
        let mut alloc = TestAlloc::new();
        vm.load_linux(&mut alloc, &img, None, "").unwrap();
        assert!(alloc.outstanding() > 0);
        vm.teardown(&mut alloc);
        assert_eq!(vm.state, VmState::Destroyed);
        assert_eq!(alloc.outstanding(), 0);
        // Teardown twice is safe.
        vm.teardown(&mut alloc);
        assert_eq!(alloc.outstanding(), 0);
    }
}
