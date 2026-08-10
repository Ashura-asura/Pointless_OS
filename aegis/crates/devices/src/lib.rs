//! The device model (design doc §8: "Every device is discovered, IOMMU-fenced,
//! and exposed as a capability-scoped object with a typed interface (block
//! device, network device, GPU command queue, etc.), owned by a userspace
//! driver process. No devices are kernel-resident. A driver crash is contained
//! to that driver's execution context and recovered by the supervision tree
//! (Section 5) without touching the rest of the system").
//!
//! The device registry is a *userspace* service: there is no kernel API to
//! enumerate or touch a device — a device is a table entry plus the kernel
//! objects (region, endpoint) its licence derives from. Every operation on a
//! device resolves through a capability the *caller itself* holds in its own
//! CSpace, so knowing a device id reads nothing and writes nothing: there is
//! no ambient path, which is the model's analogue of the IOMMU fence (a real
//! IOMMU is hardware, out of scope of the model — what we do model is that
//! device memory is reachable only through a granted device capability, and
//! that licence is context-scoped and revocable).
//!
//! Typed interface: each device kind speaks one record format — a block device
//! has no command queue, a net device has no sector interface. The registry
//! gates the interface by kind before the kernel even sees the op; the kernel
//! independently enforces the capability scoping on the underlying objects.
//!
//! Ownership and supervision: the registry records the userspace driver task
//! that licenced the device (`claim`). A device whose owner is not running is
//! *down*: it can licence no new clients until the supervision tree restarts
//! the driver, while capabilities already granted ride through — revocation is
//! explicit in this model, so a crash destroys the owner's own execution
//! context, nothing else.

use std::collections::HashMap;

use capability_core::{CapHandle, Kernel, KernelError, KernelResult, ObjectId, Rights, TaskHandle};

pub mod graphics;

/// The typed interface of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Block,
    Net,
    Gpu,
}

/// Framework-level errors: the registry's own gates, plus kernel errors passed
/// through (a caller whose granted rights are too narrow gets the kernel's
/// answer, not a device-framework one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    UnknownDevice,
    /// The op does not belong to this device kind's interface.
    WrongInterface(&'static str),
    /// The caller holds no cap to this device object — nothing ambient.
    NotHeld,
    /// The owner driver is not running: licence refused until supervision
    /// recovery (design doc §5).
    DeviceDown,
    Kernel(KernelError),
}

impl From<KernelError> for DeviceError {
    fn from(e: KernelError) -> DeviceError {
        DeviceError::Kernel(e)
    }
}

/// Find the caller's own slot naming `obj` — the framework's only way onto an
/// object: through a cap in the caller's table. No slot, no operation.
pub fn cap_for(k: &Kernel, holder: TaskHandle, obj: ObjectId) -> KernelResult<CapHandle> {
    (0..256u32)
        .find_map(|s| {
            k.cap_info(holder, CapHandle(s))
                .ok()
                .filter(|i| i.obj == obj)
                .map(|_| CapHandle(s))
        })
        .ok_or(KernelError::NoCap)
}

/// Every slot of `task` naming `obj` (grants can mint one object several ways).
pub fn slots_of(k: &Kernel, task: TaskHandle, obj: ObjectId) -> Vec<u32> {
    (0..256u32)
        .filter(|s| k.cap_info(task, CapHandle(*s)).is_ok_and(|i| i.obj == obj))
        .collect()
}

pub type DeviceId = u64;

#[derive(Debug, Clone)]
struct DeviceSpec {
    name: String,
    kind: DeviceKind,
    /// The object the command interface lives on (region for block, endpoint
    /// for net and gpu queues).
    command_obj: ObjectId,
    command_cap: CapHandle,
    /// A GPU's framebuffer object (the device's own memory window).
    fb_obj: Option<ObjectId>,
    fb_cap: Option<CapHandle>,
    /// The licenced userspace driver of record, and the cap in *our* CSpace
    /// naming it (the supervision tree's handle for restarting it).
    driver: Option<TaskHandle>,
    driver_name: Option<CapHandle>,
}

/// The userspace device registry. All authority flows through the kernel
/// objects it created; the registry itself decides nothing about capability
/// scoping — it merely records what exists, who owns it, and what interface it
/// speaks.
pub struct Devices {
    service: TaskHandle,
    creator: CapHandle,
    next_id: DeviceId,
    devices: HashMap<DeviceId, DeviceSpec>,
}

impl Devices {
    pub fn new(service: TaskHandle, creator: CapHandle) -> Devices {
        Devices {
            service,
            creator,
            next_id: 1,
            devices: HashMap::new(),
        }
    }

    /// The device directory: what the system believes exists. A userspace
    /// service — there is no kernel-resident enumeration (no devices are
    /// kernel-resident).
    pub fn list(&self) -> Vec<(DeviceId, String, DeviceKind)> {
        let mut out: Vec<_> = self
            .devices
            .iter()
            .map(|(id, d)| (*id, d.name.clone(), d.kind))
            .collect();
        out.sort_by_key(|(id, _, _)| *id);
        out
    }

    fn insert(&mut self, spec: DeviceSpec) -> DeviceId {
        let id = self.next_id;
        self.next_id += 1;
        self.devices.insert(id, spec);
        id
    }

    /// Discover a block device: a region the licenced driver can serve
    /// sectors from. "Discovery" here is registration by the platform layer;
    /// the kernel never offers devices up on its own.
    pub fn register_block(
        &mut self,
        k: &mut Kernel,
        name: &str,
        sectors: Vec<u8>,
    ) -> KernelResult<DeviceId> {
        let cap = k.create_mem(self.service, self.creator, sectors)?;
        let info = k.cap_info(self.service, cap)?;
        Ok(self.insert(DeviceSpec {
            name: name.to_string(),
            kind: DeviceKind::Block,
            command_obj: info.obj,
            command_cap: cap,
            fb_obj: None,
            fb_cap: None,
            driver: None,
            driver_name: None,
        }))
    }

    /// Discover a network device: a channel endpoint.
    pub fn register_net(&mut self, k: &mut Kernel, name: &str) -> KernelResult<DeviceId> {
        let cap = k.create_endpoint(self.service, self.creator)?;
        let info = k.cap_info(self.service, cap)?;
        Ok(self.insert(DeviceSpec {
            name: name.to_string(),
            kind: DeviceKind::Net,
            command_obj: info.obj,
            command_cap: cap,
            fb_obj: None,
            fb_cap: None,
            driver: None,
            driver_name: None,
        }))
    }

    /// Discover a GPU: a command queue endpoint plus a framebuffer window.
    pub fn register_gpu(
        &mut self,
        k: &mut Kernel,
        name: &str,
        fb: Vec<u8>,
    ) -> KernelResult<DeviceId> {
        let queue = k.create_endpoint(self.service, self.creator)?;
        let fbc = k.create_mem(self.service, self.creator, fb)?;
        let qi = k.cap_info(self.service, queue)?;
        let fi = k.cap_info(self.service, fbc)?;
        Ok(self.insert(DeviceSpec {
            name: name.to_string(),
            kind: DeviceKind::Gpu,
            command_obj: qi.obj,
            command_cap: queue,
            fb_obj: Some(fi.obj),
            fb_cap: Some(fbc),
            driver: None,
            driver_name: None,
        }))
    }

    fn spec(&self, id: DeviceId) -> Result<&DeviceSpec, DeviceError> {
        self.devices.get(&id).ok_or(DeviceError::UnknownDevice)
    }

    /// The command-interface object of a registered device.
    pub fn command_obj(&self, id: DeviceId) -> Option<ObjectId> {
        self.devices.get(&id).map(|d| d.command_obj)
    }

    /// The framebuffer object of a registered GPU.
    pub fn fb_obj(&self, id: DeviceId) -> Option<ObjectId> {
        self.devices.get(&id).and_then(|d| d.fb_obj)
    }

    /// `driver` is now the licenced owner of the device: it receives the
    /// device's command cap (and framebuffer, if any) in its own CSpace. From
    /// here on the device is "owned by a userspace driver process".
    pub fn claim(
        &mut self,
        k: &mut Kernel,
        id: DeviceId,
        driver: TaskHandle,
        driver_name: CapHandle,
    ) -> KernelResult<()> {
        let spec = self.devices.get_mut(&id).ok_or(KernelError::NoSuchObject)?;
        let ops = match spec.kind {
            DeviceKind::Block => Rights::READ.union(Rights::WRITE),
            DeviceKind::Net => Rights::SEND.union(Rights::RECV),
            DeviceKind::Gpu => Rights::SEND.union(Rights::RECV),
        };
        k.grant(self.service, spec.command_cap, driver_name, ops, None)?;
        if let Some(fbc) = spec.fb_cap {
            k.grant(
                self.service,
                fbc,
                driver_name,
                Rights::READ.union(Rights::WRITE),
                None,
            )?;
        }
        spec.driver = Some(driver);
        spec.driver_name = Some(driver_name);
        Ok(())
    }

    /// Is the owner driver running as far as the kernel records? A killed
    /// driver is a down device for licensing purposes.
    pub fn is_up(&self, k: &mut Kernel, id: DeviceId) -> bool {
        match self.devices.get(&id).and_then(|d| d.driver_name) {
            Some(name) => k.task_running(self.service, name).unwrap_or(false),
            None => false,
        }
    }

    /// Licence a client: a narrowed cap onto the device object, minted into
    /// the client's own CSpace. Refused while the device is down — the
    /// supervision hook (a dead driver cannot license new clients, design doc
    /// §5).
    pub fn grant_surface(
        &self,
        k: &mut Kernel,
        id: DeviceId,
        client_name: CapHandle,
        rights: Rights,
    ) -> Result<(), DeviceError> {
        let _ = self.spec(id)?;
        if !self.is_up(k, id) {
            return Err(DeviceError::DeviceDown);
        }
        let spec = self.spec(id)?;
        k.grant(self.service, spec.command_cap, client_name, rights, None)
            .map_err(DeviceError::from)
    }

    // ---------------------------------------------------------------- typed ops
    // Every op first passes the kind gate (the typed interface), then resolves
    // through the *caller's own* cap (capability scoping), then hits the kernel.

    pub fn read_sector(
        &self,
        k: &mut Kernel,
        caller: TaskHandle,
        id: DeviceId,
        offset: usize,
        len: usize,
    ) -> Result<Vec<u8>, DeviceError> {
        let spec = self.spec(id)?;
        if spec.kind != DeviceKind::Block {
            return Err(DeviceError::WrongInterface(
                "read_sector is a block-device interface",
            ));
        }
        let cap = cap_for(k, caller, spec.command_obj).map_err(|_| DeviceError::NotHeld)?;
        Ok(k.mem_read(caller, cap, offset, len)?)
    }

    pub fn write_sector(
        &self,
        k: &mut Kernel,
        caller: TaskHandle,
        id: DeviceId,
        offset: usize,
        data: Vec<u8>,
    ) -> Result<(), DeviceError> {
        let spec = self.spec(id)?;
        if spec.kind != DeviceKind::Block {
            return Err(DeviceError::WrongInterface(
                "write_sector is a block-device interface",
            ));
        }
        let cap = cap_for(k, caller, spec.command_obj).map_err(|_| DeviceError::NotHeld)?;
        Ok(k.mem_write(caller, cap, offset, data)?)
    }

    pub fn send_frame(
        &self,
        k: &mut Kernel,
        caller: TaskHandle,
        id: DeviceId,
        frame: Vec<u8>,
    ) -> Result<(), DeviceError> {
        let spec = self.spec(id)?;
        if spec.kind != DeviceKind::Net {
            return Err(DeviceError::WrongInterface(
                "send_frame is a network-device interface",
            ));
        }
        let cap = cap_for(k, caller, spec.command_obj).map_err(|_| DeviceError::NotHeld)?;
        Ok(k.ep_send(caller, cap, frame)?)
    }

    /// GPU command-queue submission (design doc §8 graphics): the caller must
    /// itself hold SEND on the queue object — the kernel attributes the
    /// submission to the caller and refuses it without the cap, exactly as for
    /// any other endpoint send.
    pub fn submit_commands(
        &self,
        k: &mut Kernel,
        caller: TaskHandle,
        id: DeviceId,
        record: Vec<u8>,
    ) -> Result<(), DeviceError> {
        let spec = self.spec(id)?;
        if spec.kind != DeviceKind::Gpu {
            return Err(DeviceError::WrongInterface(
                "submit_commands is a GPU-command-queue interface",
            ));
        }
        let cap = cap_for(k, caller, spec.command_obj).map_err(|_| DeviceError::NotHeld)?;
        Ok(k.ep_send(caller, cap, record)?)
    }
}
