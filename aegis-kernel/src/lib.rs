#![cfg_attr(not(test), no_std)]

pub mod gdt;
pub mod idt;
pub mod page_tables;
pub mod process;
pub mod scheduler;
pub mod syscall;

pub mod pci;
pub mod iommu;
pub mod nvme;

pub mod net;
pub mod ethernet;
pub mod arp;
pub mod ipv4;

pub mod agent;
pub mod profiler;
pub mod adaptive;
pub mod policy_engine;
