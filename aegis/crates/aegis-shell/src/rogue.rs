//! The adversarial payload: escalation attempts run *under the agent's own identity*,
//! with the same kernel, given the same leaked knowledge a curious-but-unprivileged
//! agent would realistically accumulate. Every attempt must fail. Identity forgery is
//! not even expressible (TaskHandle has no public constructor), so it is documented as
//! a type-level fact rather than a runtime attempt.

use capability_core::{CapHandle, Kernel, KernelError, Rights, TaskHandle};

/// Knowledge the agent is assumed to possess: its own slots and a leaked index that
/// happens to be another task's slot number in another task's CSpace.
pub struct RogueContext {
    pub me: TaskHandle,
    /// The agent's own legitimate slots (self cap slot 0, grant slots).
    pub my_slots: Vec<CapHandle>,
    /// A "leaked" slot index: the index of a protected object's cap *as it exists in
    /// the owner's CSpace*. The rogue may use it freely: it resolves against the
    /// rogue's own CSpace, where it names nothing.
    pub leaked_owner_slot: CapHandle,
}

/// One executable escalation attempt. Returns the kernel result; everything here is
/// supposed to be an error (except `kill_self`, the confined-in-self-succeeds case).
/// `explains` documents *why* it must fail.
pub struct Attempt {
    pub name: &'static str,
    pub explains: &'static str,
    pub expected_failure: bool,
    pub run: fn(&mut Kernel, &RogueContext) -> Result<(), KernelError>,
}

pub fn escalation_suite() -> Vec<Attempt> {
    vec![
        Attempt {
            name: "fabricated handle (u32::MAX)",
            explains: "an index into your own CSpace that holds no cap",
            expected_failure: true,
            run: |k, ctx| {
                k.task_kill(ctx.me, CapHandle(u32::MAX))
            },
        },
        Attempt {
            name: "leaked slot from another task's CSpace",
            explains: "handles resolve against the CALLER's CSpace, never anyone else's",
            expected_failure: true,
            run: |k, ctx| {
                k.task_kill(ctx.me, ctx.leaked_owner_slot)
            },
        },
        Attempt {
            name: "copy own grant cap with GRANT rights",
            explains: "copy requires GRANT on the source; the role grants READ+CONTROL only",
            expected_failure: true,
            run: |k, ctx| {
                k.copy(ctx.me, ctx.my_slots[1], Rights::ALL)
                    .map(|_| ())
            },
        },
        Attempt {
            name: "delegate own grant cap onward",
            explains: "delegation requires GRANT on the source; none was granted",
            expected_failure: true,
            run: |k, ctx| {
                k.grant(ctx.me, ctx.my_slots[1], ctx.my_slots[0], Rights::ALL, None)
            },
        },
        Attempt {
            name: "revoke own grant cap",
            explains: "revocation requires GRANT on the source",
            expected_failure: true,
            run: |k, ctx| {
                k.revoke(ctx.me, ctx.my_slots[1])
            },
        },
        Attempt {
            name: "mint a cap under a (nonexistent) grant root",
            explains: "the agent holds no GrantRoot cap; grant_mint fails before anything else",
            expected_failure: true,
            run: |k, ctx| {
                k.grant_mint(ctx.me, ctx.my_slots[0], ctx.my_slots[1], ctx.my_slots[0], Rights::ALL, None)
                    .map(|_| ())
            },
        },
        Attempt {
            name: "create a new task",
            explains: "creation requires a Creator cap; the agent never received one",
            expected_failure: true,
            run: |k, ctx| {
                k.create_task(ctx.me, ctx.my_slots[0], "skunkworks")
                    .map(|_| ())
            },
        },
        Attempt {
            name: "create an endpoint",
            explains: "creation requires a Creator cap",
            expected_failure: true,
            run: |k, ctx| {
                k.create_endpoint(ctx.me, ctx.my_slots[0])
                    .map(|_| ())
            },
        },
        Attempt {
            name: "send on a fabricated endpoint handle",
            explains: "no endpoint cap exists in the agent's CSpace",
            expected_failure: true,
            run: |k, ctx| {
                k.ep_send(ctx.me, ctx.my_slots[0], b"hi".to_vec())
            },
        },
        Attempt {
            name: "touch memory the agent was never given",
            explains: "no MemRegion cap in the agent's CSpace",
            expected_failure: true,
            run: |k, ctx| {
                k.mem_len(ctx.me, ctx.my_slots[0]).map(|_| ())
            },
        },
        Attempt {
            name: "kill itself (confined success)",
            explains: "CONTROL is held on its own task via the self cap — legal, but the only object it can control is itself",
            expected_failure: false,
            run: |k, ctx| k.task_kill(ctx.me, ctx.my_slots[0]),
        },
    ]
}
