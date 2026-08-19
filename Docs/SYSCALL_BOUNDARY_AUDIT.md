# Syscall Boundary Audit — syscall → argument → check-or-justification

*Phase AC of the Aegis master roadmap. Every ring-3 syscall number (0–23) plus
the unknown-number path is listed with its ring-3 arguments, the documented
check-or-justification for each, the audit op (if any) that attributes
refusals, and the adversarial test in
`aegis-kernel/src/hardening_syscalls.rs` that proves the documented check
holds. This is the machine-checked companion to the live-status matrix in
`SECURITY_AUDIT.md`.*

*Scope note: the checks below are the fail-closed, never-panic contract at the
**dispatch boundary**. Pointer *ranges* are additionally proven at the
`user_ptr` gate itself (`user_ptr_gate_never_panics_on_hostile_ranges`,
`hardening_fuzz.rs`); dispatch-level tests pin pointer arguments to live
scratch buffers because host tests run the gate in kernel-context bypass
(`pml4_phys == 0`). Under that bypass only `va == 0` is refused, which is what
the Write test exercises. This is exactly the honest limit the Phase 1 hostile
audit documented — hostile ranges are a gate-level proof, hostile *indices and
lengths* are a dispatch-level proof.*

## Syscall numbers

| # | Name | Ring-3 args | Check / justification | Refusal audited as | Adversarial test |
|---|------|-------------|-----------------------|--------------------|------------------|
| 0 | Exit | — | Unimplemented; returns -1. No ring-3 args to validate. | none (no gate fires) | `syscall_0_exit_returns_minus_one` |
| 1 | Write | `buf`, `len` | `buf` must pass `user_ptr::validate_range` (present, user-accessible); `len` clamped to `WRITE_MAX_LEN` (256). Null buf refused even under kernel-context bypass. | `OpKind::Write` (refusals only) | `syscall_1_write_refuses_null_buffer_and_is_audited` (+ `write_length_is_capped_at_the_maximum`) |
| 2 | Read | — | Unimplemented; returns -1. No ring-3 args. | none | `syscall_2_read_returns_minus_one` |
| 3 | Yield | — | Returns 0. No ring-3 args. | none | `syscall_3_yield_returns_zero` |
| 4 | Fork | — | Unimplemented; returns -1. No ring-3 args. | none | `syscall_4_fork_returns_minus_one` |
| 5 | Call | `ep_slot`, `msg_va`, `len`, `reply_va` | `ep_slot` via `caps_endpoint` (bounds + generation + SEND right); message and reply buffers via `user_ptr`/`copy_user` against the owning task's PML4; `len` clamped to `IPC_BUF`. | `OpKind::Send` | `syscall_5_call_refuses_hostile_ep_slot_and_is_audited` |
| 6 | Serve | `ep_slot`, `recvbuf_va` | `ep_slot` via `caps_endpoint` (RECV right); `recvbuf_va` via `user_ptr`. | `OpKind::Recv` | `syscall_6_serve_refuses_hostile_ep_slot_and_is_audited` |
| 7 | Reply | `ep_slot`, `caller_id`, `reply_va`, `rlen` | `ep_slot` via `caps_endpoint` (RECV right); `caller_id` bounds-checked **and** cross-checked against the task actually blocked on this endpoint (blocks forged returns); `reply_va`/`rlen` via `copy_user` + clamp. | `OpKind::Send` | `syscall_7_reply_refuses_hostile_ep_slot_and_is_audited` (+ `reply_refuses_forged_and_out_of_range_callers`) |
| 8 | EndpointCreate | — | No ring-3 args; mints a new endpoint (generation-bumped) and installs SEND\|RECV\|GRANT. Returns -1 only when the endpoint table is full. | none (no gate fires; a create is not a capability-boundary refusal) | `syscall_8_endpoint_create_ignores_hostile_args` |
| 9 | CapGrant | `dst`, `src_slot`, `dst_slot` | `src_slot` requires GRANT right; `dst` and `dst_slot` bounds-checked before the recipient's table is touched; ledger suspension gates the flow. | `OpKind::Grant` | `syscall_9_cap_grant_refuses_hostile_indices_and_is_audited` (+ `cap_grant_refuses_out_of_range_recipient`) |
| 10 | MemCreate | `frames` | `frames == 0` refused; allocator (`alloc_contiguous_global`) returns `None` when the free list can't satisfy the count → -1. No region installed on failure. | none (resource-count refusal, not a rights-boundary gate) | `syscall_10_mem_create_refuses_zero_and_huge_frame_counts` |
| 11 | MemLen | `slot` | `slot` via `caps_region` (bounds + generation + READ right); region must be active. | `OpKind::MemRead` | `syscall_11_mem_len_refuses_hostile_slot_and_is_audited` |
| 12 | MemRead | `slot`, `offset`, `len`, `dst_va` | `slot` via `caps_region` (READ); `offset+len` via `checked_add` (overflow → refuse); bounds vs region length; `dst_va` via `copy_to_user`. | `OpKind::MemRead` | `syscall_12_mem_read_refuses_hostile_args_and_is_audited` |
| 13 | MemWrite | `slot`, `offset`, `len`, `src_va` | `slot` via `caps_region` (WRITE); `offset+len` via `checked_add`; bounds vs region length; `src_va` via `copy_from_user`. | `OpKind::MemWrite` | `syscall_13_mem_write_refuses_hostile_args_and_is_audited` |
| 14 | TaskState | `slot` | `slot` via `caps_task` (READ). | `OpKind::TaskState` | `syscall_14_task_state_refuses_hostile_slot_and_is_audited` |
| 15 | TaskKill | `slot` | `slot` via `caps_task` (CONTROL). | `OpKind::TaskKill` | `syscall_15_task_kill_refuses_hostile_slot_and_is_audited` |
| 16 | TaskRestart | `slot` | `slot` via `caps_task` (CONTROL). | `OpKind::TaskSpawn` | `syscall_16_task_restart_refuses_hostile_slot_and_is_audited` |
| 17 | CapRevoke | `dst`, `dst_slot`, `src_slot` | `src_slot` requires GRANT; `dst`/`dst_slot` bounds-checked; the recipient's slot must name the **same** object as the grantor's (a foreign/empty slot is refused). | `OpKind::Revoke` | `syscall_17_cap_revoke_refuses_hostile_indices_and_is_audited` |
| 18 | RoleGrant | `role_id`, `grantee`, `target`, `dst_slot` | Unknown `role_id` refused; `grantee`/`target`/`dst_slot` bounds-checked before either table is touched; the grantor must hold the role's exact rights (or watchdog READ for network-scoped roles) over `target`. | `OpKind::RoleGrant` | `syscall_18_role_grant_refuses_garbage_and_is_audited` (+ `role_grant_never_panics_and_denies_garbage`) |
| 19 | NetSocket | `kind`, `ip_packed`, `port` | `kind` must be 1 (TCP) or 2 (UDP); caller must hold a `NetRoot` cap with CONTROL in some slot; the stack must be online (offline → distinct `ERR_NET_OFFLINE`). Every refusal attributed with the destination target. | `OpKind::NetOpen` | `syscall_19_net_socket_refuses_bad_kind_and_is_audited` (+ `net_socket_denies_task_without_net_root`) |
| 20 | NetConnect | `slot` | `slot` bounds-checked, must be a `NetEndpoint` cap with SEND; generation-safe resolve; online gate. | `OpKind::NetIo` | `syscall_20_net_connect_refuses_hostile_slot_and_is_audited` |
| 21 | NetSend | `slot`, `va`, `len` | `slot` bounds-checked + SEND right; `va` via `user_ptr`; `len` clamped to 2048; generation-safe resolve; online gate. | `OpKind::NetIo` | `syscall_21_net_send_refuses_hostile_slot_and_is_audited` |
| 22 | NetRecv | `slot`, `va`, `len` | `slot` bounds-checked + RECV right; `va` via `user_ptr`; `len` clamped; generation-safe resolve; online gate. | `OpKind::NetIo` | `syscall_22_net_recv_refuses_hostile_slot_and_is_audited` |
| 23 | NetClose | `slot` | `slot` bounds-checked, must be a `NetEndpoint` cap (presence only); generation-safe resolve. | `OpKind::NetIo` | `syscall_23_net_close_refuses_hostile_slot_and_is_audited` |
| — | unknown | — | Any number with no documented handler returns -1; nothing is attributed (no gate fires). | none | `unknown_syscall_numbers_are_refused` |

## Why every row is either a check or an explicit justification

Per the Phase AC DoD: *"For every argument with no documented check: either add
one (fail closed, audit the refusal, never panic) or write an explicit code
comment proving why it's safe without one."* Every row above is one of:

- **A check** — a capability gate (`caps_endpoint`/`caps_region`/`caps_task`/
  `NetRoot`), a bounds check on a table index, a `checked_add`, a length clamp,
  or a `user_ptr` range approval. All fail closed and never panic, and the
  refusal is attributed to the audit log where the gate records an op.
- **A justification** — syscalls with **no ring-3 arguments** (Exit, Read,
  Yield, Fork, EndpointCreate) have nothing to validate; MemCreate's `frames`
  is a resource-count refusal by the allocator rather than a rights-boundary
  refusal, so no audit op exists for it by design (nothing is refused at a
  capability boundary).

## Audit-gap closures landed in this phase

Enumerating the surface found three refusals that were **not** attributed, so
"assert the refusal is audited" would have failed for them. All three are now
audited, matching the Phase-1 claim that every gated refusal is traceable:

1. `syscall.rs` Write gate refusal → now records `OpKind::Write` (refusals
   only; a successful debug-print is not a security event and would flood the
   bounded ring, so Write success stays un-attributed by design).
2. `ipc.rs` `ipc_call` `caps_endpoint` failure → now records `OpKind::Send`.
3. `ipc.rs` `ipc_serve` `caps_endpoint` failure → now records `OpKind::Recv`.
4. `ipc.rs` `ipc_reply` `caps_endpoint` failure → now records `OpKind::Send`.

The existing `reply_refuses_forged_and_out_of_range_callers` assertion
(`op_counts[Send] == 2`) is unaffected: it seeds a valid endpoint, so the
caps_endpoint gate succeeds and only the forged-caller refusals are counted.

## Where the counts live

The table above is proven by `aegis-kernel/src/hardening_syscalls.rs` (26 new
adversarial tests, one per syscall number + the unknown path + a
deterministic never-moves-CURRENT sweep). Full-suite totals are maintained in
`SECURITY_AUDIT.md` and re-checked by `scripts/verify-security-audit.sh`.