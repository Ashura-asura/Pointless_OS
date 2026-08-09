//! Capability rights. A rights set is a monotone quantity over the derivation graph:
//! derived caps always carry a subset of their parent's rights (spec invariants I2/I3).

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Rights(u32);

impl Rights {
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const CONTROL: Rights = Rights(1 << 2);
    pub const SEND: Rights = Rights(1 << 3);
    pub const RECV: Rights = Rights(1 << 4);
    pub const GRANT: Rights = Rights(1 << 5);
    /// Grant-consent (I6): the holder of a RECEIVE cap to a task may target that
    /// task as a grant destination. Without it, a cap is only a *naming reference* —
    /// it proves the task exists, it does not license pushing caps into its CSpace.
    pub const RECEIVE: Rights = Rights(1 << 6);

    pub const NONE: Rights = Rights(0);
    pub const ALL: Rights = Rights((1 << 7) - 1);

    pub const fn new(bits: u32) -> Rights {
        Rights(bits & Self::ALL.0)
    }

    pub const fn contains(self, other: Rights) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns true iff `self` grants everything `other` does.
    pub const fn superset_of(self, other: Rights) -> bool {
        self.contains(other)
    }

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl Default for Rights {
    fn default() -> Self {
        Rights::NONE
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        for (bit, name) in [
            (Self::READ, "R"),
            (Self::WRITE, "W"),
            (Self::CONTROL, "C"),
            (Self::SEND, "S"),
            (Self::RECV, "RCV"),
            (Self::GRANT, "G"),
            (Self::RECEIVE, "RCVE"),
        ] {
            if self.contains(bit) {
                out.push_str(name);
            }
        }
        if out.is_empty() {
            out.push('-');
        }
        write!(f, "{out}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subset_semantics() {
        let full = Rights::ALL;
        assert!(full.superset_of(Rights::READ.union(Rights::GRANT)));
        assert!(!Rights::READ.superset_of(Rights::WRITE));
        assert!(Rights::NONE.superset_of(Rights::NONE));
    }

    #[test]
    fn intersection_narrows() {
        let r = Rights::ALL.intersect(Rights::READ.union(Rights::SEND));
        assert!(!r.contains(Rights::WRITE));
        assert!(r.contains(Rights::SEND));
    }
}