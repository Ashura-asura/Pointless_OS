#![cfg_attr(not(test), no_std)]

pub mod gdt;
pub mod idt;
pub mod page_tables;
pub mod process;
pub mod scheduler;
pub mod syscall;

pub mod iommu;
pub mod nvme;
pub mod pci;

pub mod arp;
pub mod ethernet;
pub mod ipv4;
pub mod net;

pub mod adaptive;
pub mod agent;
pub mod policy_engine;
pub mod profiler;

pub mod input;
pub mod object_graph;
pub mod shell;
pub mod window;
