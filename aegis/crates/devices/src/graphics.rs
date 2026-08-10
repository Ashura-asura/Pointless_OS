//! The graphics model (design doc §8: "GPU access is capability-scoped
//! command-queue submission ... The kernel's job is limited to isolating GPU
//! memory and command-queue capabilities between contexts; compositing,
//! window management, and the actual graphics stack are ordinary userspace
//! services, replaceable independently of the kernel").
//!
//! The graphics service (a userspace driver, exactly like any other driver in
//! this crate) owns the GPU's command-queue machinery. Each context gets two
//! *distinct* kernel objects: its own command queue (an endpoint, granted
//! SEND only — user-mode submission with no read-back) and its own
//! framebuffer (a memory region, READ|WRITE). Isolation between contexts is
//! therefore kernel-enforced by construction: a context's CSpace holds caps
//! only to its own queue and its own framebuffer; no slot a neighbouring
//! context reports can name its objects, because capability handles resolve
//! against the *caller's* table alone.
//!
//! The screen never appears without a compositor: the display server holds
//! READ grants on every framebuffer and composites them through its own caps.
//! A dead compositor stops the screen (the service refuses to composite for
//! a context that is not running) while the contexts' capsules are untouched —
//! replace the compositor and the screen returns, with the kernel state
//! identical throughout.

use capability_core::{CapHandle, Kernel, KernelError, KernelResult, ObjectId, Rights, TaskHandle};

use crate::{cap_for, DeviceError};

/// One attached context: the two objects the kernel isolates for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpuContext {
    pub queue_obj: ObjectId,
    pub fb_obj: ObjectId,
}

#[derive(Debug, Clone)]
struct CompositorSession {
    task: TaskHandle,
    /// The cap *we* hold naming the display server (CONTROL from creation),
    /// used to gate compositing on its liveness.
    name: CapHandle,
    fbs: Vec<ObjectId>,
}

/// The userspace graphics driver. Its kernel authority is a Creator cap and
/// the queue/framebuffer objects it mints; it is itself capable of being
/// replaced or restarted like any other service.
pub struct GraphicsService {
    service: TaskHandle,
    creator: CapHandle,
    queues: Vec<ObjectId>,
    fbs: Vec<ObjectId>,
    compositor: Option<CompositorSession>,
}

impl GraphicsService {
    pub fn new(service: TaskHandle, creator: CapHandle) -> GraphicsService {
        GraphicsService {
            service,
            creator,
            queues: Vec::new(),
            fbs: Vec::new(),
            compositor: None,
        }
    }

    /// Attach a context: a fresh command queue (endpoint) and a fresh
    /// framebuffer (region) minted into the context's own CSpace. The context
    /// gets SEND on its queue — capability-scoped command-queue submission —
    /// and READ|WRITE on its own framebuffer slice: GPU memory isolated per
    /// context by the kernel, not by any graphics-stack policy.
    pub fn attach(
        &mut self,
        k: &mut Kernel,
        _context: TaskHandle,
        context_name: CapHandle,
        clear: Vec<u8>,
    ) -> KernelResult<GpuContext> {
        let queue = k.create_endpoint(self.service, self.creator)?;
        let fb = k.create_mem(self.service, self.creator, clear)?;
        k.grant(self.service, queue, context_name, Rights::SEND, None)?;
        k.grant(
            self.service,
            fb,
            context_name,
            Rights::READ.union(Rights::WRITE),
            None,
        )?;
        let qi = k.cap_info(self.service, queue)?;
        let fi = k.cap_info(self.service, fb)?;
        self.queues.push(qi.obj);
        self.fbs.push(fi.obj);
        Ok(GpuContext {
            queue_obj: qi.obj,
            fb_obj: fi.obj,
        })
    }

    /// User-mode submission: the caller's *own* slot onto its own queue. The
    /// kernel attributes the send to the caller and refuses a submission
    /// against any object the caller does not hold.
    pub fn submit(
        &self,
        k: &mut Kernel,
        context: TaskHandle,
        queue_cap: CapHandle,
        record: Vec<u8>,
    ) -> KernelResult<()> {
        k.ep_send(context, queue_cap, record)
    }

    /// Render into the context's own framebuffer, through the caller's own cap.
    pub fn write_fb(
        &self,
        k: &mut Kernel,
        context: TaskHandle,
        ctx: GpuContext,
        offset: usize,
        bytes: Vec<u8>,
    ) -> KernelResult<()> {
        let cap = cap_for(k, context, ctx.fb_obj)?;
        k.mem_write(context, cap, offset, bytes)
    }

    /// Attach the display server: READ grants on a context's framebuffer,
    /// minted from the driver's own cap into the compositor's CSpace.
    pub fn attach_compositor(
        &mut self,
        k: &mut Kernel,
        compositor: TaskHandle,
        compositor_name: CapHandle,
    ) -> KernelResult<()> {
        let mut fbs = Vec::new();
        for fb in &self.fbs {
            let cap = cap_for(k, self.service, *fb)?;
            k.grant(self.service, cap, compositor_name, Rights::READ, None)?;
            fbs.push(*fb);
        }
        self.compositor = Some(CompositorSession {
            task: compositor,
            name: compositor_name,
            fbs,
        });
        Ok(())
    }

    /// Composite the screen: every attached framebuffer, read through the
    /// display server's *own* READ caps. Refused while the display server is
    /// not running (its context is dead), and rebuildable by attaching a
    /// replacement — the graphics stack is an ordinary, replaceable userspace
    /// service; the kernel state (the contexts' queues and framebuffers) is
    /// untouched by the swap.
    pub fn compose(&self, k: &mut Kernel) -> Result<Vec<Vec<u8>>, DeviceError> {
        let session = self
            .compositor
            .as_ref()
            .ok_or(DeviceError::Kernel(KernelError::NoSuchObject))?;
        if !k.task_running(self.service, session.name).unwrap_or(false) {
            return Err(DeviceError::DeviceDown);
        }
        let mut screen = Vec::new();
        for fb in &session.fbs {
            let cap = cap_for(k, session.task, *fb).map_err(DeviceError::from)?;
            let len = k.mem_len(session.task, cap).map_err(DeviceError::from)?;
            screen.push(
                k.mem_read(session.task, cap, 0, len)
                    .map_err(DeviceError::from)?,
            );
        }
        Ok(screen)
    }
}
