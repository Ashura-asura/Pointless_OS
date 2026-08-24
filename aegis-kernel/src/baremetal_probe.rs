//! Bare-metal boot self-test battery (bare-metal boot procedure, Layer 2).
//!
//! A fixed list of `Result`-returning, non-panicking probe functions — one
//! per subsystem — that run at boot on the *live* hardware and report each
//! result as `ok - name` / `FAIL - name: reason`. The runner never stops on a
//! failure: every probe catches its own error as `Err`, the loop moves on,
//! and a summary is produced. This is the mechanism for "keep going even if
//! some probes fail": each probe is a total function over the live facts it
//! is handed, and none of them can panic.
//!
//! Honest scope, per the project's own Ground Rule 6: a probe can only "fail
//! gracefully" for conditions the code anticipates (device absent, register
//! read returns garbage, value out of range). A probe that causes a genuine
//! CPU exception — a real page fault or #GP against unexpected hardware —
//! still faults like any other unhandled kernel-mode fault. Making
//! faults-during-a-probe themselves recoverable (an exception-table-style
//! fixup) is named future work in `Docs/VMX_LIVE_HOSTING.md`, not assumed.
//!
//! The probes are deliberately decoupled from the live device handles: the
//! caller (the boot path) fills a [`LiveFacts`] struct from the real probes
//! it already performed, and the battery is a pure, testable function over
//! that data.

/// Number of probes in the battery.
pub const PROBE_COUNT: usize = 9;

/// One probe result, in the `battery-contract.py` evidence style.
#[derive(Clone, Copy, Debug)]
pub struct ProbeResult {
    pub name: &'static str,
    pub ok: bool,
    /// Present when `ok` is false.
    pub reason: &'static str,
}

/// The live hardware facts the boot path collects and hands to the battery.
/// Each field is a single, already-decided boolean/size so the probes stay
/// pure and total (no hardware access inside the battery itself).
#[derive(Clone, Copy, Debug)]
pub struct LiveFacts {
    /// Number of devices discovered on the PCI bus (host bridge counts).
    pub pci_device_count: usize,
    /// An NVMe controller was found on PCI.
    pub nvme_found: bool,
    /// The NVMe controller probed and a sector read succeeded.
    pub nvme_read_ok: bool,
    /// A network device (e1000) was found on PCI.
    pub network_found: bool,
    /// A display device was found on PCI.
    pub display_found: bool,
    /// The ACPI RSDP/RSDT parsed cleanly.
    pub acpi_ok: bool,
    /// A usable GOP framebuffer was handed over.
    pub gop_found: bool,
    /// Reported RAM in MiB (from the boot memory map).
    pub ram_mib: u64,
}

fn pci_enumeration(f: &LiveFacts) -> Result<(), &'static str> {
    if f.pci_device_count > 0 {
        Ok(())
    } else {
        Err("no devices discovered on the PCI bus")
    }
}

fn nvme_present(f: &LiveFacts) -> Result<(), &'static str> {
    if f.nvme_found {
        Ok(())
    } else {
        Err("no NVMe controller on PCI")
    }
}

fn nvme_responds(f: &LiveFacts) -> Result<(), &'static str> {
    if f.nvme_read_ok {
        Ok(())
    } else {
        Err("NVMe probe or first sector read failed")
    }
}

fn network_device(f: &LiveFacts) -> Result<(), &'static str> {
    if f.network_found {
        Ok(())
    } else {
        Err("no network device (e1000) on PCI")
    }
}

fn display_device(f: &LiveFacts) -> Result<(), &'static str> {
    if f.display_found {
        Ok(())
    } else {
        Err("no display device on PCI")
    }
}

fn acpi_tables(f: &LiveFacts) -> Result<(), &'static str> {
    if f.acpi_ok {
        Ok(())
    } else {
        Err("ACPI RSDP/tables did not parse")
    }
}

fn memory_map(f: &LiveFacts) -> Result<(), &'static str> {
    if f.ram_mib >= 128 {
        Ok(())
    } else {
        Err("boot memory map reports < 128 MiB of RAM")
    }
}

fn framebuffer(f: &LiveFacts) -> Result<(), &'static str> {
    if f.gop_found {
        Ok(())
    } else {
        Err("no GOP framebuffer handed over by firmware")
    }
}

/// The serial channel is the battery's own output path: if this probe's line
/// printed at all, the channel works. Always `Ok` by construction.
fn serial_out(_f: &LiveFacts) -> Result<(), &'static str> {
    Ok(())
}

fn mk(name: &'static str, r: Result<(), &'static str>) -> ProbeResult {
    match r {
        Ok(()) => ProbeResult {
            name,
            ok: true,
            reason: "",
        },
        Err(reason) => ProbeResult {
            name,
            ok: false,
            reason,
        },
    }
}

/// Run the full battery over the given live facts. Total: no panics, and no
/// probe's failure stops the others from running.
pub fn run(f: &LiveFacts) -> [ProbeResult; PROBE_COUNT] {
    [
        mk("pci_enumeration", pci_enumeration(f)),
        mk("nvme_present", nvme_present(f)),
        mk("nvme_responds", nvme_responds(f)),
        mk("network_device", network_device(f)),
        mk("display_device", display_device(f)),
        mk("acpi_tables", acpi_tables(f)),
        mk("memory_map", memory_map(f)),
        mk("framebuffer", framebuffer(f)),
        mk("serial_out", serial_out(f)),
    ]
}

/// Count how many probes passed.
pub fn passed(results: &[ProbeResult]) -> usize {
    results.iter().filter(|r| r.ok).count()
}

/// Format the battery as the `battery-contract.py` evidence style:
/// one `ok - name` / `FAIL - name: reason` line per probe, then a summary
/// line. Writes into `buf` (no allocation), returning the byte length.
pub fn format_summary(results: &[ProbeResult], buf: &mut [u8]) -> usize {
    let mut n = 0usize;
    for r in results {
        let line: &[u8] = if r.ok { b"ok - " } else { b"FAIL - " };
        for b in line {
            if n < buf.len() {
                buf[n] = *b;
                n += 1;
            }
        }
        for b in r.name.bytes() {
            if n < buf.len() {
                buf[n] = b;
                n += 1;
            }
        }
        if !r.ok {
            for b in b": " {
                if n < buf.len() {
                    buf[n] = *b;
                    n += 1;
                }
            }
            for b in r.reason.bytes() {
                if n < buf.len() {
                    buf[n] = b;
                    n += 1;
                }
            }
        }
        if n < buf.len() {
            buf[n] = b'\n';
            n += 1;
        }
    }
    // "# boot self-test: X/Y passed" (hand-built; core::fmt::format is not
    // available in no_std without alloc).
    let header = b"# boot self-test: ";
    for b in header {
        if n < buf.len() {
            buf[n] = *b;
            n += 1;
        }
    }
    n = write_dec(passed(results), buf, n);
    if n < buf.len() {
        buf[n] = b'/';
        n += 1;
    }
    n = write_dec(results.len(), buf, n);
    let tail = b" passed\n";
    for b in tail {
        if n < buf.len() {
            buf[n] = *b;
            n += 1;
        }
    }
    n
}

/// Write `v` as decimal digits at `buf[n..]`, returning the new length.
fn write_dec(mut v: usize, buf: &mut [u8], mut n: usize) -> usize {
    let mut tmp = [0u8; 20];
    let mut i = 0usize;
    loop {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
        if v == 0 {
            break;
        }
    }
    while i > 0 {
        i -= 1;
        if n < buf.len() {
            buf[n] = tmp[i];
            n += 1;
        }
    }
    n
}

/// Retain the most recent battery run so a later boot stage (e.g. the object
/// store, once it is open) can persist the same summary to disk. Copy-only,
/// no allocation; the results array is `Copy`.
pub fn keep(results: &[ProbeResult; PROBE_COUNT]) {
    unsafe {
        LAST = Some(*results);
    }
}

/// Format the retained summary into `buf`; returns 0 if the battery has not
/// run yet.
pub fn last_summary(buf: &mut [u8]) -> usize {
    match unsafe { LAST } {
        Some(results) => format_summary(&results, buf),
        None => 0,
    }
}

static mut LAST: Option<[ProbeResult; PROBE_COUNT]> = None;

#[cfg(test)]
mod tests {
    use super::*;

    fn good_facts() -> LiveFacts {
        LiveFacts {
            pci_device_count: 4,
            nvme_found: true,
            nvme_read_ok: true,
            network_found: true,
            display_found: true,
            acpi_ok: true,
            gop_found: true,
            ram_mib: 8192,
        }
    }

    #[test]
    fn all_ok_on_a_healthy_system() {
        let results = run(&good_facts());
        assert_eq!(results.len(), PROBE_COUNT);
        assert!(results.iter().all(|r| r.ok));
        assert_eq!(passed(&results), PROBE_COUNT);
    }

    #[test]
    fn failures_do_not_stop_the_battery() {
        let mut f = good_facts();
        f.nvme_found = false;
        f.network_found = false;
        f.gop_found = false;
        f.ram_mib = 32;
        let results = run(&f);
        // The three failing probes report FAIL with a reason; the others
        // still pass — the battery ran to completion regardless.
        assert!(!results[1].ok); // nvme_present
        assert!(!results[3].ok); // network_device
        assert!(!results[6].ok); // memory_map
        assert!(!results[7].ok); // framebuffer
        assert!(results[0].ok); // pci_enumeration
        assert!(results[8].ok); // serial_out
        assert_eq!(passed(&results), PROBE_COUNT - 4);
    }

    #[test]
    fn summary_matches_evidence_style() {
        let results = run(&good_facts());
        let mut buf = [0u8; 512];
        let n = format_summary(&results, &mut buf);
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.starts_with("ok - pci_enumeration\n"));
        assert!(text.contains("ok - nvme_present\n"));
        assert!(text.contains("# boot self-test: 9/9 passed\n"));
    }

    #[test]
    fn failing_reason_is_included() {
        let mut f = good_facts();
        f.acpi_ok = false;
        let results = run(&f);
        let mut buf = [0u8; 512];
        let n = format_summary(&results, &mut buf);
        let text = core::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.contains("FAIL - acpi_tables: ACPI RSDP/tables did not parse\n"));
        assert!(text.contains("# boot self-test: 8/9 passed\n"));
    }
}
