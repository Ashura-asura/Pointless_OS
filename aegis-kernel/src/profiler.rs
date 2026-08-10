use crate::agent::AgentId;

#[derive(Debug, Clone)]
pub struct SyscallRecord {
    pub agent_id: AgentId,
    pub syscall_num: u32,
    pub timestamp: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub struct UsageProfile {
    pub agent_id: AgentId,
    pub syscall_histogram: [u32; 32],
    pub total_syscalls: u32,
    pub peak_memory_pages: u32,
    pub file_handles_open: u8,
    pub network_frames_sent: u32,
    pub network_frames_received: u32,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl UsageProfile {
    pub fn new(agent_id: AgentId) -> Self {
        Self {
            agent_id,
            syscall_histogram: [0; 32],
            total_syscalls: 0,
            peak_memory_pages: 0,
            file_handles_open: 0,
            network_frames_sent: 0,
            network_frames_received: 0,
            first_seen: 0,
            last_seen: 0,
        }
    }
}

struct ProfileSlot {
    agent_id: AgentId,
    profile: UsageProfile,
    used: bool,
}

struct RecordSlot {
    record: SyscallRecord,
    used: bool,
}

pub struct Profiler {
    profiles: [ProfileSlot; 32],
    records: [RecordSlot; 256],
    record_count: usize,
    window_size: u32,
}

impl Profiler {
    pub fn new(window_size: u32) -> Self {
        const DEFAULT_PROFILE: ProfileSlot = ProfileSlot {
            agent_id: 0,
            profile: UsageProfile {
                agent_id: 0,
                syscall_histogram: [0; 32],
                total_syscalls: 0,
                peak_memory_pages: 0,
                file_handles_open: 0,
                network_frames_sent: 0,
                network_frames_received: 0,
                first_seen: 0,
                last_seen: 0,
            },
            used: false,
        };
        const DEFAULT_RECORD: RecordSlot = RecordSlot {
            record: SyscallRecord {
                agent_id: 0,
                syscall_num: 0,
                timestamp: 0,
                arg1: 0,
                arg2: 0,
                success: false,
            },
            used: false,
        };
        Self {
            profiles: [DEFAULT_PROFILE; 32],
            records: [DEFAULT_RECORD; 256],
            record_count: 0,
            window_size,
        }
    }

    pub fn record(&mut self, rec: SyscallRecord) {
        let agent_id = rec.agent_id;
        let syscall_num = rec.syscall_num;
        let timestamp = rec.timestamp;

        if self.record_count < self.records.len() {
            self.records[self.record_count] = RecordSlot { record: rec, used: true };
            self.record_count += 1;
        } else {
            self.records[0] = RecordSlot { record: rec, used: true };
        }

        let profile = self.get_or_create_profile(agent_id);
        if (syscall_num as usize) < 32 {
            profile.syscall_histogram[syscall_num as usize] += 1;
        }
        profile.total_syscalls += 1;
        profile.last_seen = timestamp;
        if profile.first_seen == 0 {
            profile.first_seen = timestamp;
        }
    }

    pub fn get_profile(&self, agent_id: AgentId) -> Option<&UsageProfile> {
        for slot in self.profiles.iter() {
            if slot.used && slot.agent_id == agent_id {
                return Some(&slot.profile);
            }
        }
        None
    }

    pub fn compute_deviation(&self, agent_id: AgentId) -> f32 {
        if let Some(profile) = self.get_profile(agent_id) {
            let total = profile.total_syscalls;
            if total == 0 {
                return 0.0;
            }
            let mut diff_sum: f32 = 0.0;
            let mut expected_sum: f32 = 0.0;
            for i in 0..32 {
                let actual = profile.syscall_histogram[i] as f32;
                let expected = (total as f32) / 32.0;
                diff_sum += (actual - expected).abs();
                expected_sum += expected;
            }
            if expected_sum == 0.0 {
                return 0.0;
            }
            (diff_sum / expected_sum).min(1.0)
        } else {
            0.0
        }
    }

    pub fn set_baseline(&mut self, agent_id: AgentId, profile: UsageProfile) {
        for slot in self.profiles.iter_mut() {
            if slot.used && slot.agent_id == agent_id {
                slot.profile = profile;
                return;
            }
        }
        for slot in self.profiles.iter_mut() {
            if !slot.used {
                slot.agent_id = agent_id;
                slot.profile = profile;
                slot.used = true;
                return;
            }
        }
    }

    pub fn clear_records(&mut self, agent_id: AgentId) {
        let mut i = 0;
        while i < self.records.len() {
            if self.records[i].used && self.records[i].record.agent_id == agent_id {
                self.records[i].used = false;
            }
            i += 1;
        }
        self.compact();
    }

    fn compact(&mut self) {
        let mut write = 0;
        for read in 0..self.records.len() {
            if self.records[read].used {
                if write != read {
                    let tmp = RecordSlot { record: SyscallRecord {
                        agent_id: self.records[read].record.agent_id,
                        syscall_num: self.records[read].record.syscall_num,
                        timestamp: self.records[read].record.timestamp,
                        arg1: self.records[read].record.arg1,
                        arg2: self.records[read].record.arg2,
                        success: self.records[read].record.success,
                    }, used: true };
                    self.records[read].used = false;
                    self.records[write] = tmp;
                }
                write += 1;
            }
        }
        self.record_count = write;
    }

    fn get_or_create_profile(&mut self, agent_id: AgentId) -> &mut UsageProfile {
        let mut found = None;
        for slot in self.profiles.iter_mut() {
            if slot.used && slot.agent_id == agent_id {
                found = Some(slot as *mut ProfileSlot);
                break;
            }
        }
        if let Some(ptr) = found {
            return unsafe { &mut (*ptr).profile };
        }
        for slot in self.profiles.iter_mut() {
            if !slot.used {
                slot.agent_id = agent_id;
                slot.used = true;
                return &mut slot.profile;
            }
        }
        panic!("profiler: too many agents");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(agent_id: AgentId, syscall_num: u32) -> SyscallRecord {
        SyscallRecord {
            agent_id,
            syscall_num,
            timestamp: 100,
            arg1: 0,
            arg2: 0,
            success: true,
        }
    }

    #[test]
    fn record_updates_histogram() {
        let mut prof = Profiler::new(1000);
        prof.record(make_record(1, 5));
        prof.record(make_record(1, 5));
        prof.record(make_record(1, 3));
        let p = prof.get_profile(1).unwrap();
        assert_eq!(p.syscall_histogram[5], 2);
        assert_eq!(p.syscall_histogram[3], 1);
        assert_eq!(p.total_syscalls, 3);
    }

    #[test]
    fn compute_deviation_zero_for_identical() {
        let mut prof = Profiler::new(1000);
        for i in 0..32 {
            for _ in 0..10 {
                prof.record(make_record(1, i));
            }
        }
        let dev = prof.compute_deviation(1);
        assert!((dev - 0.0).abs() < 0.001);
    }

    #[test]
    fn compute_deviation_nonzero_for_different() {
        let mut prof = Profiler::new(1000);
        for _ in 0..320 {
            prof.record(make_record(1, 0));
        }
        let dev = prof.compute_deviation(1);
        assert!(dev > 0.0);
    }

    #[test]
    fn set_baseline_affects_deviation() {
        let mut prof = Profiler::new(1000);
        for _ in 0..320 {
            prof.record(make_record(1, 0));
        }
        let dev_before = prof.compute_deviation(1);
        assert!((dev_before - 1.0).abs() < 0.001);
        let mut baseline = UsageProfile::new(1);
        for i in 0..32 {
            baseline.syscall_histogram[i] = 10;
        }
        baseline.total_syscalls = 320;
        prof.set_baseline(1, baseline);
        let dev_after = prof.compute_deviation(1);
        assert!((dev_after - 0.0).abs() < 0.001);
    }

    #[test]
    fn clear_records_removes_old_entries() {
        let mut prof = Profiler::new(1000);
        prof.record(make_record(1, 0));
        prof.record(make_record(2, 0));
        prof.clear_records(1);
        assert_eq!(prof.record_count, 1);
    }
}
