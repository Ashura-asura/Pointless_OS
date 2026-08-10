// NVMe command queue interface

/// NVMe submission queue entry (64 bytes)

#[derive(Clone, Copy, Debug)]
pub struct NvmeSubmissionEntry {
    pub opcode: u8,
    pub flags: u8,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub mptr: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

/// NVMe completion queue entry (16 bytes)

#[derive(Clone, Copy, Debug)]
pub struct NvmeCompletionEntry {
    pub command_specific: u32,
    pub reserved: u32,
    pub sq_head: u16,
    pub sq_identifier: u8,
    pub command_id: u16,
    pub phase_bit: bool,
    pub status: u16,
}

/// Admin opcodes

#[derive(Clone, Copy, Debug)]
pub enum NvmeAdminOp {
    CreateIoQueue = 0x05,
    Identify = 0x06,
    SetFeatures = 0x09,
}

/// IO opcodes

#[derive(Clone, Copy, Debug)]
pub enum NvmeIoOp {
    Write = 0x01,
    Read = 0x02,
}

/// NVMe queue pair

pub struct NvmeQueue {
    submissions: [NvmeSubmissionEntry; 64],
    completions: [NvmeCompletionEntry; 64],
    tail: u16,
    head: u16,
    phase: bool,
    next_id: u16,
}

impl NvmeQueue {
    pub fn new(_depth: u16) -> Self {
        const EMPTY_SUB: NvmeSubmissionEntry = NvmeSubmissionEntry {
            opcode: 0,
            flags: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        const EMPTY_COMP: NvmeCompletionEntry = NvmeCompletionEntry {
            command_specific: 0,
            reserved: 0,
            sq_head: 0,
            sq_identifier: 0,
            command_id: 0,
            phase_bit: false,
            status: 0,
        };
        Self {
            submissions: [EMPTY_SUB; 64],
            completions: [EMPTY_COMP; 64],
            tail: 0,
            head: 0,
            phase: false,
            next_id: 0,
        }
    }

    pub fn submit(&mut self, command: NvmeSubmissionEntry) -> u16 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.submissions[self.tail as usize] = command;
        self.tail = (self.tail + 1) % 64;
        id
    }

    pub fn poll_completion(&mut self) -> Option<NvmeCompletionEntry> {
        let comp = &self.completions[self.head as usize];
        if comp.phase_bit == self.phase {
            return None;
        }
        let entry = *comp;
        self.head = (self.head + 1) % 64;
        if self.head == 0 {
            self.phase = !self.phase;
        }
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_increments_tail_pointer() {
        let mut q = NvmeQueue::new(64);
        assert_eq!(q.tail, 0);
        let cmd = NvmeSubmissionEntry {
            opcode: 0x02,
            flags: 0,
            nsid: 1,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1: 0x1000,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        q.submit(cmd);
        assert_eq!(q.tail, 1);
        q.submit(cmd);
        assert_eq!(q.tail, 2);
    }

    #[test]
    fn submit_returns_sequential_command_ids() {
        let mut q = NvmeQueue::new(64);
        let cmd = NvmeSubmissionEntry {
            opcode: 0,
            flags: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        let id1 = q.submit(cmd);
        let id2 = q.submit(cmd);
        let id3 = q.submit(cmd);
        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
        assert_eq!(id3, 2);
    }

    #[test]
    fn poll_completion_returns_none_when_empty() {
        let mut q = NvmeQueue::new(64);
        assert!(q.poll_completion().is_none());
    }

    #[test]
    fn poll_completion_returns_entry_after_submit() {
        let mut q = NvmeQueue::new(64);
        q.completions[0] = NvmeCompletionEntry {
            command_specific: 42,
            reserved: 0,
            sq_head: 0,
            sq_identifier: 0,
            command_id: 0,
            phase_bit: true,
            status: 0,
        };
        let comp = q.poll_completion().unwrap();
        assert_eq!(comp.command_specific, 42);
    }

    #[test]
    fn phase_bit_toggles_on_completion() {
        let mut q = NvmeQueue::new(64);
        assert!(!q.phase);
        for i in 0..64 {
            q.completions[i] = NvmeCompletionEntry {
                command_specific: 0,
                reserved: 0,
                sq_head: 0,
                sq_identifier: 0,
                command_id: i as u16,
                phase_bit: true,
                status: 0,
            };
        }
        for _ in 0..64 {
            q.poll_completion();
        }
        assert!(q.phase);
    }
}
