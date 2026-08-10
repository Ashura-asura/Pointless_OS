pub type AgentId = u32;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AgentState {
    Created,
    Running,
    Suspended,
    Terminated,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityScope {
    pub allowed_syscalls: [bool; 32],
    pub max_memory_pages: u32,
    pub max_file_handles: u8,
    pub network_allowed: bool,
    pub time_slice_ms: u32,
}

impl CapabilityScope {
    pub fn restrictive() -> Self {
        let mut scope = Self {
            allowed_syscalls: [false; 32],
            max_memory_pages: 1,
            max_file_handles: 0,
            network_allowed: false,
            time_slice_ms: 10,
        };
        scope.allowed_syscalls[0] = true;
        scope
    }

    pub fn permissive() -> Self {
        Self {
            allowed_syscalls: [true; 32],
            max_memory_pages: 256,
            max_file_handles: 16,
            network_allowed: true,
            time_slice_ms: 100,
        }
    }

    pub fn is_allowed(&self, syscall_num: u32) -> bool {
        (syscall_num as usize) < self.allowed_syscalls.len()
            && self.allowed_syscalls[syscall_num as usize]
    }
}

pub struct Agent {
    pub id: AgentId,
    pub state: AgentState,
    pub scope: CapabilityScope,
    pub created_at: u64,
    pub last_active_at: u64,
    pub syscall_count: u32,
    pub deviation_score: f32,
}

pub struct AgentRegistry {
    agents: [Option<Agent>; 32],
    count: usize,
    next_id: AgentId,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: Default::default(),
            count: 0,
            next_id: 1,
        }
    }

    pub fn spawn(&mut self, scope: CapabilityScope) -> Result<AgentId, &'static str> {
        if self.count >= self.agents.len() {
            return Err("maximum agents reached");
        }
        let id = self.next_id;
        self.next_id += 1;
        let agent = Agent {
            id,
            state: AgentState::Running,
            scope,
            created_at: 0,
            last_active_at: 0,
            syscall_count: 0,
            deviation_score: 0.0,
        };
        for slot in self.agents.iter_mut() {
            if slot.is_none() {
                *slot = Some(agent);
                self.count += 1;
                return Ok(id);
            }
        }
        Err("spawn failed")
    }

    pub fn suspend(&mut self, id: AgentId) -> Result<(), &'static str> {
        for slot in self.agents.iter_mut() {
            if let Some(a) = slot {
                if a.id == id && a.state != AgentState::Terminated {
                    a.state = AgentState::Suspended;
                    return Ok(());
                }
            }
        }
        Err("agent not found")
    }

    pub fn resume(&mut self, id: AgentId) -> Result<(), &'static str> {
        for slot in self.agents.iter_mut() {
            if let Some(a) = slot {
                if a.id == id && a.state == AgentState::Suspended {
                    a.state = AgentState::Running;
                    return Ok(());
                }
            }
        }
        Err("agent not found or not suspended")
    }

    pub fn terminate(&mut self, id: AgentId) -> Result<(), &'static str> {
        for slot in self.agents.iter_mut() {
            if let Some(a) = slot {
                if a.id == id && a.state != AgentState::Terminated {
                    a.state = AgentState::Terminated;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err("agent not found")
    }

    pub fn get(&self, id: AgentId) -> Option<&Agent> {
        for slot in self.agents.iter() {
            if let Some(a) = slot {
                if a.id == id {
                    return Some(a);
                }
            }
        }
        None
    }

    pub fn get_mut(&mut self, id: AgentId) -> Option<&mut Agent> {
        for slot in self.agents.iter_mut() {
            if let Some(a) = slot {
                if a.id == id {
                    return Some(a);
                }
            }
        }
        None
    }

    pub fn active_count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_returns_sequential_ids() {
        let mut reg = AgentRegistry::new();
        let scope = CapabilityScope::permissive();
        let id1 = reg.spawn(scope.clone()).unwrap();
        let id2 = reg.spawn(scope).unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn spawn_beyond_max_fails() {
        let mut reg = AgentRegistry::new();
        let scope = CapabilityScope::permissive();
        for _ in 0..32 {
            reg.spawn(scope.clone()).unwrap();
        }
        assert!(reg.spawn(scope).is_err());
    }

    #[test]
    fn suspend_transitions_state() {
        let mut reg = AgentRegistry::new();
        let id = reg.spawn(CapabilityScope::permissive()).unwrap();
        reg.suspend(id).unwrap();
        assert_eq!(reg.get(id).unwrap().state, AgentState::Suspended);
    }

    #[test]
    fn resume_transitions_back() {
        let mut reg = AgentRegistry::new();
        let id = reg.spawn(CapabilityScope::permissive()).unwrap();
        reg.suspend(id).unwrap();
        reg.resume(id).unwrap();
        assert_eq!(reg.get(id).unwrap().state, AgentState::Running);
    }

    #[test]
    fn terminate_removes_from_active_count() {
        let mut reg = AgentRegistry::new();
        let id = reg.spawn(CapabilityScope::permissive()).unwrap();
        assert_eq!(reg.active_count(), 1);
        reg.terminate(id).unwrap();
        assert_eq!(reg.active_count(), 0);
    }

    #[test]
    fn restrictive_scope_blocks_network() {
        let scope = CapabilityScope::restrictive();
        assert!(!scope.network_allowed);
    }

    #[test]
    fn permissive_scope_allows_all() {
        let scope = CapabilityScope::permissive();
        for i in 0..32 {
            assert!(scope.is_allowed(i));
        }
        assert!(scope.network_allowed);
        assert_eq!(scope.max_memory_pages, 256);
    }

    #[test]
    fn is_allowed_checks_syscall_number() {
        let scope = CapabilityScope::restrictive();
        assert!(scope.is_allowed(0));
        assert!(!scope.is_allowed(1));
    }
}
