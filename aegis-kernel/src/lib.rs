#![cfg_attr(not(test), no_std)]

pub mod boot_info;
pub mod cap;
pub mod cpu;
pub mod font;
pub mod frame;
pub mod gdt;
pub mod idt;
pub mod ipc;
pub mod mem;
pub mod page_tables;
pub mod process;
pub mod scheduler;
pub mod supervisor;
pub mod syscall;
pub mod tasks;
pub mod trace;
pub mod vga;

pub mod audit;
pub mod monitor;

pub mod fat;
pub mod iommu;
pub mod nvme;
pub mod nvme_store;
pub mod pci;

pub mod arp;
pub mod e1000;
pub mod ethernet;
pub mod fleet;
pub mod ipv4;
pub mod mesh;
pub mod net;
pub mod netif;
pub mod tcp;
pub mod udp;

pub mod adaptive;
pub mod agent;
pub mod policy_engine;
pub mod profiler;

pub mod compositor;
pub mod desktop;
pub mod gpu;
pub mod gpu_compositor;
pub mod input;
pub mod object_graph;
pub mod ps2;
pub mod shell;
pub mod window;

pub mod elf_loader;
pub mod linux_abi;
pub mod linux_compat;
pub mod linux_compat_elf;
pub mod nt_abi;
pub mod pe_loader;
pub mod win_compat;

pub mod ceiling;

pub mod hardening;

pub mod serial;

pub mod store;

pub mod update;

pub mod channel;

pub mod netstack;
pub mod role;

pub mod aes;

pub mod tls;

#[cfg(test)]
mod rfc8448_vec;

/// Test-only: serialize tests that mutate the kernel's single global task /
/// region / supervisor state. The kernel has one `static mut CURRENT` and one
/// capability table per task, so tests that pin `CURRENT` and seed caps must
/// not run concurrently with each other even though they use distinct task
/// indices (the global cursor itself is shared). Poison-tolerant: a test that
/// panics while holding the lock must not cascade into every other guarded
/// test via `PoisonError` -- mutual exclusion (the actual invariant) still
/// holds after a panic, only the "no panic happened" invariant is lost.
#[cfg(test)]
pub(crate) fn kernel_state_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
