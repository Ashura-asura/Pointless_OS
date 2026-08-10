/// Contract tests for the scheduler module.
/// Contains its own copy of the scheduler/process structs since the kernel crate is no_std.
/// Runs on the host target as a standard Rust test.

// ── Copies of the kernel structs ──────────────────────────────────────────────

pub type Pid = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Ready,
    Running,
    Blocked,
    Zombie,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CpuState {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

pub struct Process {
    pub pid: Pid,
    pub state: ProcessState,
    pub cpu_state: CpuState,
    pub kernel_stack_top: u64,
    pub user_stack_top: u64,
    pub pml4_phys: u64,
}

const MAX_PROCESSES: usize = 64;
const DEFAULT_TIME_SLICE: u32 = 10;

pub struct Scheduler {
    processes: [Option<Process>; MAX_PROCESSES],
    current: Option<Pid>,
    next_pid: Pid,
    time_slice_remaining: u32,
    time_slice_total: u32,
}

impl Scheduler {
    pub fn new() -> Self {
        let mut processes: [Option<Process>; MAX_PROCESSES] = unsafe { core::mem::zeroed() };
        let mut i = 0;
        while i < MAX_PROCESSES {
            processes[i] = None;
            i += 1;
        }
        Scheduler {
            processes,
            current: None,
            next_pid: 1,
            time_slice_remaining: DEFAULT_TIME_SLICE,
            time_slice_total: DEFAULT_TIME_SLICE,
        }
    }

    pub fn spawn(
        &mut self,
        entry_point: u64,
        user_stack: u64,
        kernel_stack: u64,
    ) -> Result<Pid, &'static str> {
        let slot = self.processes.iter().position(|p| p.is_none());
        let slot = match slot {
            Some(s) => s,
            None => return Err("no free process slots"),
        };

        let pid = self.next_pid;
        self.next_pid += 1;

        let mut cpu_state = CpuState::default();
        cpu_state.rip = entry_point;
        cpu_state.rsp = user_stack;
        cpu_state.rflags = 0x200;

        self.processes[slot] = Some(Process {
            pid,
            state: ProcessState::Ready,
            cpu_state,
            kernel_stack_top: kernel_stack,
            user_stack_top: user_stack,
            pml4_phys: 0,
        });

        Ok(pid)
    }

    pub fn schedule_next(&mut self) -> Option<&Process> {
        let current_idx = self.current.and_then(|cur| {
            self.processes
                .iter()
                .position(|p| p.as_ref().map_or(false, |proc| proc.pid == cur))
        });

        let start = current_idx.map_or(0, |i| i + 1);

        for i in start..MAX_PROCESSES {
            if let Some(ref proc) = self.processes[i] {
                if proc.state == ProcessState::Ready {
                    self.current = Some(proc.pid);
                    self.time_slice_remaining = self.time_slice_total;
                    return self.processes[i].as_ref();
                }
            }
        }
        for i in 0..start {
            if let Some(ref proc) = self.processes[i] {
                if proc.state == ProcessState::Ready {
                    self.current = Some(proc.pid);
                    self.time_slice_remaining = self.time_slice_total;
                    return self.processes[i].as_ref();
                }
            }
        }
        None
    }

    pub fn block_current(&mut self) {
        if let Some(cur) = self.current {
            for slot in self.processes.iter_mut() {
                if let Some(ref mut proc) = slot {
                    if proc.pid == cur {
                        proc.state = ProcessState::Blocked;
                        break;
                    }
                }
            }
        }
    }

    pub fn wake(&mut self, pid: Pid) {
        for slot in self.processes.iter_mut() {
            if let Some(ref mut proc) = slot {
                if proc.pid == pid && proc.state == ProcessState::Blocked {
                    proc.state = ProcessState::Ready;
                    break;
                }
            }
        }
    }

    pub fn tick(&mut self) -> bool {
        if self.time_slice_remaining > 0 {
            self.time_slice_remaining -= 1;
        }
        self.time_slice_remaining == 0
    }

    pub fn current(&self) -> Option<&Process> {
        self.current.and_then(|cur| {
            self.processes
                .iter()
                .find(|p| p.as_ref().map_or(false, |proc| proc.pid == cur))
                .and_then(|p| p.as_ref())
        })
    }

    pub fn current_mut(&mut self) -> Option<&mut Process> {
        self.current.and_then(|cur| {
            self.processes
                .iter_mut()
                .find(|p| p.as_ref().map_or(false, |proc| proc.pid == cur))
                .and_then(|p| p.as_mut())
        })
    }

    pub fn process_count(&self) -> usize {
        self.processes.iter().filter(|p| p.is_some()).count()
    }

    pub fn is_ready(&self, pid: Pid) -> bool {
        self.processes
            .iter()
            .any(|p| p.as_ref().map_or(false, |proc| proc.pid == pid && proc.state == ProcessState::Ready))
    }

    pub fn reap_zombies(&mut self) {
        for slot in self.processes.iter_mut() {
            if let Some(ref proc) = slot {
                if proc.state == ProcessState::Zombie {
                    *slot = None;
                }
            }
        }
    }
}

// ── Contract tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_increments_process_count() {
        let mut sched = Scheduler::new();
        assert_eq!(sched.process_count(), 0);
        sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        assert_eq!(sched.process_count(), 1);
        sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        assert_eq!(sched.process_count(), 2);
    }

    #[test]
    fn spawn_beyond_max_fails() {
        let mut sched = Scheduler::new();
        for _ in 0..MAX_PROCESSES {
            sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        }
        assert_eq!(sched.spawn(0x1000, 0x2000, 0x3000), Err("no free process slots"));
    }

    #[test]
    fn schedule_next_returns_first_spawned() {
        let mut sched = Scheduler::new();
        sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        let proc = sched.schedule_next().unwrap();
        assert_eq!(proc.pid, 1);
    }

    #[test]
    fn tick_false_when_time_remaining() {
        let mut sched = Scheduler::new();
        assert!(!sched.tick()); // 10 -> 9
        assert!(!sched.tick()); // 9 -> 8
        // Still 8 ticks remaining
    }

    #[test]
    fn tick_true_when_time_expires() {
        let mut sched = Scheduler::new();
        // time_slice_remaining starts at 10, each tick decrements
        for _ in 0..(DEFAULT_TIME_SLICE - 1) {
            assert!(!sched.tick());
        }
        // Last tick: decrements to 0, returns true
        assert!(sched.tick());
    }

    #[test]
    fn blocking_removes_from_ready_queue() {
        let mut sched = Scheduler::new();
        sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        sched.schedule_next();
        sched.block_current();
        // No ready processes left
        assert!(sched.schedule_next().is_none());
    }

    #[test]
    fn waking_makes_ready() {
        let mut sched = Scheduler::new();
        sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        let pid = sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        sched.schedule_next();  // pid 1
        sched.block_current();  // pid 1 blocked
        // pid 2 is still ready
        let proc = sched.schedule_next().unwrap();
        assert_eq!(proc.pid, pid);
        sched.block_current();  // pid 2 blocked
        assert!(sched.schedule_next().is_none()); // nothing ready
        sched.wake(pid);
        assert!(sched.is_ready(pid));
        let proc = sched.schedule_next().unwrap();
        assert_eq!(proc.pid, pid);
    }

    #[test]
    fn round_robin_cycles_all_ready() {
        let mut sched = Scheduler::new();
        let pid1 = sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        let pid2 = sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        let pid3 = sched.spawn(0x1000, 0x2000, 0x3000).unwrap();

        let p1 = sched.schedule_next().unwrap().pid;
        let p2 = sched.schedule_next().unwrap().pid;
        let p3 = sched.schedule_next().unwrap().pid;
        let p1_again = sched.schedule_next().unwrap().pid;

        assert_eq!(p1, pid1);
        assert_eq!(p2, pid2);
        assert_eq!(p3, pid3);
        assert_eq!(p1_again, pid1);
    }

    #[test]
    fn state_transitions_ready_running_blocked_ready() {
        let mut sched = Scheduler::new();
        let pid = sched.spawn(0x1000, 0x2000, 0x3000).unwrap();

        // Initially Ready
        assert!(sched.is_ready(pid));

        // schedule_next -> Running
        let proc = sched.schedule_next().unwrap();
        assert_eq!(proc.pid, pid);

        // block_current -> Blocked
        sched.block_current();
        assert!(!sched.is_ready(pid));

        // wake -> Ready
        sched.wake(pid);
        assert!(sched.is_ready(pid));
    }

    #[test]
    fn zombie_removed_from_scheduling() {
        let mut sched = Scheduler::new();
        sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        sched.spawn(0x1000, 0x2000, 0x3000).unwrap();
        assert_eq!(sched.process_count(), 2);

        // Schedule and mark as zombie
        sched.schedule_next();
        {
            let proc = sched.current_mut().unwrap();
            proc.state = ProcessState::Zombie;
        }

        sched.reap_zombies();
        assert_eq!(sched.process_count(), 1);
    }
}
