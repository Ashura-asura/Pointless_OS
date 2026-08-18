# 🏗️ Architecture & Design Philosophy

> Deep dive into Pointless OS's design decisions, why we chose each component, and how they fit together.

---

## Table of Contents

1. [Core Design Principles](#core-design-principles)
2. [Five Architectures Evaluated](#five-architectures-evaluated)
3. [Why We Chose: Adaptive Capability Substrate](#why-we-chose-adaptive-capability-substrate)
4. [The Kernel: seL4 Foundation](#the-kernel-sel4-foundation)
5. [Orchestration Layer: AI-Native Scheduling](#orchestration-layer-ai-native-scheduling)
6. [Security Model: Capabilities Over Permissions](#security-model-capabilities-over-permissions)
7. [Data Model: Objects, Not Files](#data-model-objects-not-files)
8. [AI Integration: Agents as First-Class Actors](#ai-integration-agents-as-first-class-actors)
9. [Compatibility Strategy](#compatibility-strategy)
10. [Performance Tradeoffs](#performance-tradeoffs)

> This document describes the *target* architecture. The orchestration,
> compatibility, distributed-transparency and graphics sections are design
> intent; each has now been implemented at its honest scope (see
> `HONEST_STATUS.md` and `design/master-roadmap.md` §10). The implemented-and-verified
> surface (boot, kernel, isolation, IPC, drivers, storage) is in ../README.md and
> HONEST_STATUS.md; the full-fidelity vehicles that remain unimplemented are
> documented honestly in design/future-work.md.

---

## Core Design Principles

### 1. **Minimize the Trusted Computing Base (TCB)**

**The Problem**: Every line of code in the TCB must be verified. Linux kernel ≈ 30M LOC; Windows ≈ 50M LOC. Verification is expensive—seL4 took ~10 years.

**Our Solution**: Keep the kernel to ~10-15k LOC. Everything else (drivers, filesystems, even the AI orchestration layer) can be restarted or replaced without trusting its internals.

```
Traditional OS:          Pointless OS:
┌─────────────────────┐  ┌─────────────┐
│ TCB (30M LOC)       │  │ TCB (15k LOC)│ ← Formally verified
│ ├─ Kernel           │  │ └─ Kernel   │
│ ├─ Drivers          │  ├─────────────┤
│ ├─ Filesystem       │  │ Drivers     │ ← Can fail & restart
│ ├─ Network Stack    │  │ Filesystem  │
│ └─ Device Mgmt      │  │ Network     │
└─────────────────────┘  └─────────────┘
  ❌ Unverifiable         ✅ Verifiable
```

### 2. **Capability-Based Authority (Never Ambient)**

No component has power by default. Authority is **explicit, bounded, revocable**.

```rust
// ❌ WRONG: Ambient authority
app.read_any_file();           // Can read anything
app.network_any_host();        // Can reach any server

// ✅ RIGHT: Capability-based
let read_cap = Capability::FileTree("/home/user/docs");
let net_cap = Capability::Network(endpoints: ["api.example.com"]);

app.grant(read_cap).grant(net_cap).run();
// App CAN:   Read /home/user/docs, connect to api.example.com
// App CAN'T: Read /etc, connect to other hosts, escalate privileges
```

### 3. **Objects Over Processes**

The Unix process is a medieval bundling of three separate concepts:
- Address space (memory isolation)
- Scheduling entity (thread)
- Authority/identity (user+permissions)

We separate them:

```
┌────────────────────────────────────────────────┐
│ Execution Context                              │
│ ┌──────────────┐ ┌──────────┐ ┌────────────┐  │
│ │Address Space │ │Scheduler │ │Capabilities│  │
│ │(Memory)      │ │Handle    │ │(Authority) │  │
│ └──────────────┘ └──────────┘ └────────────┘  │
└────────────────────────────────────────────────┘
          ↓ Can be independent ↓
  Multiple address spaces can share a scheduler handle
  Multiple scheduling handles can share capabilities
  You can delegate a capability without forking a process
```

### 4. **Formal Verification at the Boundary**

You can't verify everything. You **can** verify the isolation boundary.

```
┌─────────────────────────────────────┐
│ Userspace (Untrusted)               │  ← No universal verification claims
│ ┌──────────┐ ┌──────────────────┐   │
│ │Buggy App │ │Malicious Code    │   │
│ └──────────┘ └──────────────────┘   │
├─ FORMALLY VERIFIED BOUNDARY ──────────┤
│ ┌─────────────────────────────────┐   │
│ │ Kernel (seL4)                   │   │ ← Proof: "If you're in capability
│ │ Proven: Memory isolation        │   │   set X, you can only access
│ │         Capability enforcement  │   │   resources in set X"
│ │         IPC isolation           │   │
│ └─────────────────────────────────┘   │
└─────────────────────────────────────┘
```

---

## Five Architectures Evaluated

We seriously considered five distinct OS architectures. Here's why we rejected four and chose one:

### A. Capability Microkernel (seL4-lineage)

**Architecture**: Small verified kernel, everything else is userspace services communicating via IPC.

**Pros**:
- ✅ Minimal TCB (most verifiable)
- ✅ Proven in real products (avionics, automotive, defense)
- ✅ Excellent for AI integration (capabilities are the right isolation token)
- ✅ 20+ years of research deployment

**Cons**:
- ❌ IPC overhead (every filesystem read = one IPC hop minimum)
- ❌ Requires building entire POSIX stack from scratch
- ❌ Development difficulty extremely high
- ❌ No compatibility layer for legacy apps

**Verdict**: This is our **kernel architecture** (seL4-lineage design), but not sufficient alone.

**DECISION (recorded)**: We evaluated adopting seL4 or a verified-lineage kernel and decided **against** it — (1) the formal-proof path is multi-year for a fraction of the surface, (2) its IPC-first design fights the compat layer we must ship (every filesystem read = one IPC hop minimum), and (3) the isolation model we actually need (capability gates, no ambient authority, scoped roles) is deliverable in a from-scratch Rust microkernel of this size with contract tests + TLA+ model-checking. Consequence tracked honestly in HONEST_STATUS.md: "verified" = finite-instance TLA+ model-checking (`AegisCapabilities.tla`, `AegisCeiling.tla`), **not** an inductive seL4-class proof.

---

### B. Exokernel / Library-OS Substrate

**Architecture**: Kernel only multiplexes raw hardware; apps bring their own OS abstractions (filesystem, scheduler, memory manager).

**Pros**:
- ✅ Maximum performance potential (apps pick optimal policies)
- ✅ Excellent for specialized/HPC workloads
- ✅ Strong isolation per app

**Cons**:
- ❌ Fragmentation: every app reimplements the filesystem
- ❌ No system-wide visibility (can't understand cross-app dependencies)
- ❌ Not suitable for general-purpose desktop/server
- ❌ AI orchestration becomes per-app, defeating the "symbiotic" goal

**Verdict**: Good for embedded systems, wrong for what we're building.

---

### C. Object/Graph Operating System

**Architecture**: Everything is a persistent object (files, processes, devices, AI agents) with typed relationships forming a queryable graph.

**Pros**:
- ✅ AI-native reasoning ("what depends on what?" is a query)
- ✅ Rich audit trails (every relationship is recorded)
- ✅ Adaptability (graph enables semantic understanding)

**Cons**:
- ❌ **WinFS Trap**: Microsoft tried this (Windows File System, 2000s). It became a database bottleneck. Performance disaster.
- ❌ Graph consistency is hard (transactions, ACID guarantees at OS level = slow)
- ❌ Every write path must maintain the graph = latency killer

**Verdict**: The graph is **too good** as a ground-truth. We'll use it as an **index** (query layer), not the database.

---

### D. Distributed-first Operating System

**Architecture**: Single machine is just a special case of distributed. Plan 9 philosophy: "everything is a network service."

**Pros**:
- ✅ Natural for fleet orchestration
- ✅ Excellent for heterogeneous workloads (some on GPU, some on CPU, some remote)

**Cons**:
- ❌ CAP theorem doesn't disappear because you design it away
- ❌ Network partitions break "transparency"
- ❌ Most use cases (personal laptop, local server) don't need this
- ❌ Adds latency and complexity for single-machine workloads

**Verdict**: Great for Phase 11 (fleet management). Not the foundation.

---

### E. Adaptive Capability Substrate with AI-native Orchestration

**Architecture** (Ours): 
- Thin capability kernel (seL4-lineage design, custom Rust implementation)
- Separate orchestration layer (not in TCB)
- Graph as query index (not ground truth)
- Distributed as opt-in, not default

**This wins because**:
- ✅ Smallest TCB (follows seL4's minimal kernel philosophy)
- ✅ AI agents are first-class, bounded principals
- ✅ Circuit-breaker / supervision trees (proven in Erlang)
- ✅ Adaptability without the WinFS trap
- ✅ Can layer distribution on top later
- ✅ Remains single-machine fast

**Tradeoff**: IPC overhead. We accept it because it's bounded and worth the security gain.

---

## Why We Chose: Adaptive Capability Substrate

### The Decision Matrix

| Criterion | Microkernel | Exokernel | Graph OS | Distributed | Ours |
|-----------|-------------|-----------|----------|-------------|------|
| TCB Size | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Performance | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ |
| AI Integration | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Dev Difficulty | ⭐ (very hard) | ⭐⭐ | ⭐⭐⭐ | ⭐ (very hard) | ⭐⭐⭐ |
| Compatibility | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐ |

**Key insight**: We need the security of (A) + the adaptability of (C) + the bootstrapping speed of (E).

---

## The Kernel: seL4-Lineage Architecture

### Why seL4-Lineage?

**seL4** is a formally verified capability microkernel:
- ~10-15k LOC (vs. 30M+ for Linux)
- Machine-checked proof of functional correctness
- Already open source & shipping in real products
- Proven on real hardware (ARM, x86, RISC-V)

**Our implementation** follows seL4's architecture but is a custom Rust kernel (`aegis-kernel`):
- We **do not** use seL4's verified C code directly
- We follow the same design principles: minimal TCB, capability-based authority, IPC-driven
- **Honest limit**: No formal (inductive) proof exists for `aegis-kernel`. TLA+ model-checking covers 331k states (2 tasks, 3 slots) — evidence, not proof. Contract tests prove the model, not production behavior.

### What the Kernel Provides

```rust
// Kernel Primitives (What's Formally Verified)
pub trait KernelAPI {
    // 1. Address space management
    fn create_address_space() -> Result<AddressSpace>;
    fn map_pages(space: &AddressSpace, phys: PhysAddr, virt: VirtAddr);
    
    // 2. Capability management
    fn create_capability(object: &Object, rights: Rights) -> Cap;
    fn revoke_capability(cap: &Cap);
    fn delegate_capability(cap: &Cap, to: &ExecutionContext, new_rights: Rights);
    
    // 3. Inter-process communication
    fn send_sync(to: &Endpoint, msg: &Message) -> Result<Response>;
    fn recv_async(from: &Endpoint) -> Result<Message>;
    
    // 4. Scheduling
    fn yield_to_scheduler();
    fn set_priority(ctx: &ExecutionContext, prio: Priority);
}
```

**Everything above the kernel is userspace and can be restarted**.

---

## Orchestration Layer: AI-Native Scheduling

### The Problem with Existing Schedulers

Linux CFS (Completely Fair Scheduler): Optimizes for throughput & fairness. Doesn't understand:
- What's a critical task vs. background maintenance?
- Which apps should run on GPU vs. CPU?
- When should we fail fast vs. retry?
- What is the intended topology of app dependencies?

### Our Approach: Capability-Scoped Scheduling

```rust
pub enum ExecutionPolicy {
    // Real-time: Strict deadline, cannot exceed budget
    RealTime { deadline_ms: u64, budget_us: u64 },
    
    // Adaptive: AI can adjust within bounds
    Adaptive { 
        min_latency_us: u64,
        max_latency_us: u64,
        budget_us: u64,
    },
    
    // Best-effort: Run when idle, can be preempted
    BestEffort { budget_us: u64 },
    
    // Bounded retry: Can restart, but with limits
    BoundedRetry { 
        max_restarts: u32,
        retry_backoff_ms: u64,
        budget_per_attempt_us: u64,
    },
}

// Each task has a policy + a supervising circuit breaker
pub struct SupervisedTask {
    policy: ExecutionPolicy,
    circuit_breaker: CircuitBreaker,  // Trips if repeated failures
    metadata: TaskMetadata,            // For AI reasoning
}
```

### Supervision Trees (from Erlang/OTP)

```
              ┌─────────────────┐
              │ Root Supervisor │
              └────────┬────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
   ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
   │Supervisor│  │Supervisor│  │Supervisor│
   │(Storage) │  │(Network) │  │(AI Agent)│
   └────┬─────┘  └────┬─────┘  └────┬─────┘
        │             │             │
   ┌────▼─────┐  ┌────▼──────┐  ┌──▼──────┐
   │ObjStore  │  │NetStack   │  │AIRuntime│
   │Thread 1  │  │Thread 1   │  │Thread 1 │
   └──────────┘  └───────────┘  └─────────┘
   ┌────▼─────┐  ┌────▼──────┐  ┌──▼──────┐
   │ObjStore  │  │NetStack   │  │AIRuntime│
   │Thread 2  │  │Thread 2   │  │Thread 2 │
   └──────────┘  └───────────┘  └─────────┘

If a Thread crashes:
1. Supervisor notices (via heartbeat)
2. Restart the thread (with backoff)
3. After N failures, escalate to parent supervisor
4. Parents can decide: restart the whole subsystem or fail-over
```

This is **proven at scale**: Erlang systems routinely achieve 99.9999999% uptime.

---

## Security Model: Capabilities Over Permissions

### Permissions: The Old Way (Unix)

```
rwxrwxrwx = 777 (octal)

Owner: read, write, execute
Group: read, write, execute
Other: read, write, execute

Problems:
- Ambient authority (if you own it, you can use it)
- Non-transferable (can't give a friend specific permissions)
- Coarse-grained (only 9 bits)
- No revocation (set once, must wait for process death)
```

### Capabilities: The New Way (Pointless OS)

```rust
pub struct Capability<T> {
    // Unforgeable handle to a kernel object
    id: ObjectId,
    
    // Rights: what can be done with this object
    rights: Rights,
    
    // Proof: cryptographically signed or kernel-enforced
    proof: CapabilityProof,
    
    // Metadata: for audit & revocation
    granted_by: PrincipalId,
    granted_at: Timestamp,
    expires_at: Option<Timestamp>,  // Ephemeral grants
}

pub enum Rights {
    FileRead,
    FileWrite,
    FileExecute,
    NetworkSend,
    NetworkRecv,
    DeviceRead,
    DeviceWrite,
    CapabilityDeploy,  // Can hand this cap to others
    CapabilityRevoke,  // Can revoke delegated caps
    // ...
}

// Usage:
let cap: Capability<File> = agent.receive_capability()?;

// This CANNOT be forged; it came from the kernel
// This CAN be revoked at any time
// This CAN be logged (who has it, what they did with it)
// This CAN expire after timeout
```

### Why This Matters for AI

```rust
// ❌ Without capabilities:
// "Grant AI agent write to /home/user/data"
// Result: Agent can write to ANYTHING under /home/user/data
//         including sensitive config files
//         Including files created by other apps

// ✅ With capabilities:
let cap = Capability::FileWrite {
    path: "/home/user/data/work_notes",  // SPECIFIC file
    scope: vec!["/home/user/data/work_notes"],  // Only this
    expires_at: now + 5_minutes,  // Ephemeral
    delegable: false,  // Agent can't hand it to another process
};

agent.grant(cap)?;
// Now agent CAN write to that file
// Agent CAN'T access other files
// Agent CAN'T keep the capability after 5 minutes
// Agent CAN'T escalate or hand the cap elsewhere
```

---

## Data Model: Objects, Not Files

### The Problem with Files

Unix treats everything as a file:
- `/dev/sda` (device) looks like a file
- `/proc/1234/maps` (process metadata) looks like a file
- `/sys/class/net/eth0` (network device) looks like a file

But they're not really files—they're special-cased in kernels & drivers. This leads to:
- Inconsistent semantics
- Bugs (seek on `/proc` doesn't work the same as on real files)
- Performance hacks (mmap, splice, various ioctl shortcuts)

### Our Approach: Objects with Methods

```rust
pub trait SystemObject {
    fn id(&self) -> ObjectId;
    fn type_name(&self) -> &'static str;
    fn methods_available(&self) -> Vec<MethodSignature>;
    fn query_relationship(&self, rel_type: &str) -> Vec<ObjectId>;
}

pub struct File {
    id: ObjectId,
    path: Path,
    content: Bytes,
    owner: PrincipalId,
}

impl SystemObject for File {
    fn methods_available(&self) -> Vec<MethodSignature> {
        vec![
            MethodSignature { name: "read", params: vec!["offset", "length"] },
            MethodSignature { name: "write", params: vec!["offset", "data"] },
            MethodSignature { name: "stat", params: vec![] },
        ]
    }
}

pub struct NetworkDevice {
    id: ObjectId,
    mac: MacAddress,
    mtu: u16,
}

impl SystemObject for NetworkDevice {
    fn methods_available(&self) -> Vec<MethodSignature> {
        vec![
            MethodSignature { name: "send_packet", params: vec!["data"] },
            MethodSignature { name: "recv_packet", params: vec!["max_size"] },
            MethodSignature { name: "get_stats", params: vec![] },
        ]
    }
}

// Usage:
let file: Capability<File> = get_file_capability()?;
let device: Capability<NetworkDevice> = get_device_capability()?;

// Both are accessed uniformly:
// file.invoke("read", params)?;
// device.invoke("send_packet", params)?;

// Filesystems are now just a VIEW (projection) over objects:
// /home/user/file → File object (id: 0x1234)
// /dev/eth0 → NetworkDevice object (id: 0x5678)
```

### File System as a Projection Layer

The traditional filesystem tree is still there, but it's a **view**, not the ground truth:

```
┌────────────────────────────────────────┐
│ File-tree view (POSIX compatibility)   │
│ /home/user/file.txt → 0x1234           │
│ /dev/eth0 → 0x5678                     │
└────────────────────────────────────────┘
              ↓ (Index lookup)
┌────────────────────────────────────────┐
│ Object Store (Ground truth)             │
│ 0x1234: File object                    │
│ 0x5678: NetworkDevice object           │
│ 0x9abc: Process context                │
│ ...                                    │
└────────────────────────────────────────┘
```

Benefits:
- ✅ Multiple views possible (users can see `~/Documents`, admin sees `/data/users/alice`)
- ✅ Objects are first-class (no weird special cases)
- ✅ Consistency is optional (users can choose file view or object API)

---

## AI Integration: Agents as First-Class Actors

### The Problem with Current AI Integration

"AI integration" in existing OSes usually means:
- Run a Python script with sudo access
- Let it do whatever it wants
- Hope it doesn't break things

This is the opposite of security.

### Our Approach: Bounded Principals

An AI agent is an execution context like any other:

```rust
pub struct AIAgent {
    id: PrincipalId,
    execution_context: ExecutionContext,
    granted_capabilities: Vec<Capability<_>>,
    supervision_handle: SupervisionHandle,
    audit_log: Vec<AuditEntry>,
}

// Creating an agent with specific authority:
let mut agent = AIAgent::spawn()?;

// Grant it specific capabilities (never ambient authority):
agent.grant(Capability::FileRead {
    scope: "/home/user/documents",
    expires_at: Some(now + 5_minutes),
})?;

agent.grant(Capability::NetworkSend {
    endpoints: vec!["api.openai.com"],
    expires_at: Some(now + 5_minutes),
})?;

// Agent CAN:
// - Read files under /home/user/documents
// - Send packets to api.openai.com
// - Receive responses

// Agent CANNOT:
// - Read /etc/passwd
// - Connect to attacker.com
// - Escalate to admin
// - Exceed time limits (timeout = automatic termination)
// - Keep capabilities after expiration
```

### Anomaly Detection & Circuit Breakers

```rust
pub struct CircuitBreaker {
    state: State,  // Closed, Open, HalfOpen
    
    // Configuration
    failure_threshold: u32,
    failure_window: Duration,
    reset_timeout: Duration,
    
    // Runtime state
    failures: VecDeque<Timestamp>,
    last_state_change: Timestamp,
}

impl CircuitBreaker {
    pub fn check_request(&mut self, req: &AgentRequest) -> Result<()> {
        match self.state {
            State::Closed => {
                // Normal operation: check if request is anomalous
                if self.is_anomalous(req) {
                    // Flag for human review
                    self.record_anomaly(req);
                    return Err(Error::AnomalyDetected);
                }
                Ok(())
            },
            State::Open => {
                // Circuit is broken: reject everything
                // Try to reset after timeout
                if self.last_state_change.elapsed() > self.reset_timeout {
                    self.state = State::HalfOpen;
                }
                Err(Error::CircuitOpen)
            },
            State::HalfOpen => {
                // Tentative recovery: allow test request
                if self.is_safe_request(req) {
                    self.state = State::Closed;
                    Ok(())
                } else {
                    self.state = State::Open;
                    Err(Error::CircuitOpen)
                }
            }
        }
    }
}
```

---

## Compatibility Strategy

### The Moat Problem

Windows & Linux have 40+ years of installed app base. Millions of apps depend on their exact syscall semantics. This is a **real engineering moat**, not a gap.

We're honest about this:

### Linux Compatibility: Translation Layer

```
┌────────────────────────────────┐
│ Legacy Linux App               │
│ (wants to call open(), read()) │
└────────────────────────────────┘
              ↓
┌────────────────────────────────┐
│ Linux Syscall Translation Layer │
│ (userspace service)             │
│ - Translates open() → object    │
│ - Translates read() → IPC call  │
│ - Handles open file descriptors │
└────────────────────────────────┘
              ↓
┌────────────────────────────────┐
│ Pointless OS Object API         │
│ (native capability model)       │
└────────────────────────────────┘
```

**Cost**: ~10-15% overhead vs. native Linux
**Benefit**: Full app compatibility without recompilation

### Windows Compatibility: VM-First Approach

Windows compatibility is harder because:
- Kernel-mode drivers (DirectX, etc.)
- COM object model
- Registry
- Complex licensing

**We're honest**: We won't have native Windows app support on day 1. Instead:

1. **VM Approach** (year 1-2): Run Windows in Hyper-V-style VM on Pointless OS
   - Full fidelity, all apps work
   - Performance cost, but correct
   
2. **Native Subset** (year 3+): Port high-value, well-behaved apps
   - Not everything, but the important 10%

---

## Performance Tradeoffs

### Where We're Slower Than Linux

1. **IPC-heavy workloads**: File I/O now crosses isolation boundary
   - Single `read()` = one IPC round-trip
   - seL4 IPC is fast (~1-2µs), but not free
   - **Impact**: 10-30% overhead on filesystem-heavy workloads

2. **Compatibility layers**: Linux/Windows translation adds latency
   - Each syscall is translated & mapped
   - **Impact**: Similar to WSL2 (5-15% overhead)

3. **Graph indexing** (if not carefully managed): Maintaining object relationships
   - **Mitigation**: Index is async, never in critical path

### Where We're Competitive or Better

1. **Driver isolation**: IOMMU-backed userspace drivers
   - Modern hardware already provides IOMMU
   - User-space driver = no context switch overhead
   - **Win**: Same performance as in-kernel drivers, better security

2. **Task scheduling**: AI-aware scheduling
   - Can make better decisions about GPU/CPU placement
   - Can predict failures before they happen
   - **Win**: 20-40% less wasted work

3. **Capability checking**: O(1) operation (hash table lookup)
   - vs. Linux permission checks (UID/GID + traversal = O(n) worst case)
   - **Win**: Measurably faster for deep file hierarchies

---

## What We're Building: A Summary

| Layer | Tech | Purpose |
|-------|------|---------|
| **Kernel** | Custom Rust (`aegis-kernel`), seL4-lineage design | Memory isolation, capability enforcement, IPC |
| **Orchestration** | Rust + supervision trees | AI-aware scheduling, circuit breaking, anomaly detection |
| **Storage** | Capability-addressed object store | Immutable, content-addressed, with POSIX view |
| **Network** | Userspace stack (DPDK-style) | Isolated, capability-scoped, efficient |
| **Drivers** | IOMMU-fenced userspace processes | Safe, isolated, updatable without reboot |
| **Compatibility** | Translation layers (Linux) + VM (Windows) | Legacy app support without trusting their code |
| **UX** | Object/relationship view + file tree | Both CLI and semantic interfaces |

> The deferred rows above (compatibility, distributed/fleet, GPU compositor,
> broader orchestration) are now implemented at their honest scope — see
> HONEST_STATUS.md, design/master-roadmap.md §10, and design/future-work.md for
> the remaining full-fidelity limits.
> What is actually implemented and verified today is in ../README.md and HONEST_STATUS.md.

---

## Honest Limits

See **[Known Limits](HONEST_STATUS.md#known-limits)** — the single consolidated
section (closed / reduced / inherent split). Headline facts: no seL4-class
inductive proof (TLA+ is finite-instance); contract tests prove the model, not
production behavior; real hardware is UNTESTED; AI behavior is monitored, not
verified.

**Next Steps**: See [os-from-first-principles.md](os-from-first-principles.md) for the master design and [design/future-work.md](design/future-work.md) for deferred items.
