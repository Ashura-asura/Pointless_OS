use crate::process::{Process, ProcessState, Pid, CpuState};

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
        // Find a free slot
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
        cpu_state.rflags = 0x200; // IF flag set

        self.processes[slot] = Some(Process {
            pid,
            state: ProcessState::Ready,
            cpu_state,
            kernel_stack_top: kernel_stack,
            user_stack_top: user_stack,
            pml4_phys: 0, // Will be set by caller
        });

        Ok(pid)
    }

    pub fn schedule_next(&mut self) -> Option<&Process> {
        // Find the next Ready process after the current one
        let current_idx = self.current.and_then(|cur| {
            self.processes
                .iter()
                .position(|p| p.as_ref().map_or(false, |proc| proc.pid == cur))
        });

        let start = current_idx.map_or(0, |i| i + 1);

        // Search from start to end, then wrap around
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

    /// Decrement the time slice. Returns true if context switch is needed.
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

    /// Remove zombie processes from the table
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
