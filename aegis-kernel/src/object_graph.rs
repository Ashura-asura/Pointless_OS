pub type ObjectId = u64;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ObjectType {
    File,
    Process,
    Device,
    Capability,
    Network,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RelType {
    Owns,
    Uses,
    DependsOn,
    CapabilityOf,
}

pub struct ObjectNode {
    pub id: ObjectId,
    pub obj_type: ObjectType,
    pub name: [u8; 32],
    pub attributes: u32,
}

pub struct Relationship {
    pub from_id: ObjectId,
    pub to_id: ObjectId,
    pub rel_type: RelType,
    pub bidirectional: bool,
}

pub struct ObjectGraph {
    nodes: [Option<ObjectNode>; 64],
    node_count: usize,
    relationships: [Option<Relationship>; 128],
    rel_count: usize,
}

impl ObjectGraph {
    pub fn new() -> Self {
        Self {
            nodes: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
            ],
            node_count: 0,
            relationships: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            rel_count: 0,
        }
    }

    pub fn add_node(&mut self, node: ObjectNode) -> Result<ObjectId, &'static str> {
        if self.node_count >= self.nodes.len() {
            return Err("maximum nodes reached");
        }
        let id = node.id;
        for slot in self.nodes.iter_mut() {
            if slot.is_none() {
                *slot = Some(node);
                self.node_count += 1;
                return Ok(id);
            }
        }
        Err("add_node failed")
    }

    pub fn remove_node(&mut self, id: ObjectId) -> Result<(), &'static str> {
        let mut found = false;
        for slot in self.nodes.iter_mut() {
            if let Some(n) = slot {
                if n.id == id {
                    *slot = None;
                    self.node_count -= 1;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err("node not found");
        }
        for slot in self.relationships.iter_mut() {
            if let Some(r) = slot {
                if r.from_id == id || r.to_id == id {
                    *slot = None;
                    self.rel_count -= 1;
                }
            }
        }
        Ok(())
    }

    pub fn add_relationship(
        &mut self,
        from: ObjectId,
        to: ObjectId,
        rel_type: RelType,
        bidirectional: bool,
    ) -> Result<(), &'static str> {
        if self.rel_count >= self.relationships.len() {
            return Err("maximum relationships reached");
        }
        let from_exists = self
            .nodes
            .iter()
            .any(|s| s.as_ref().map_or(false, |n| n.id == from));
        let to_exists = self
            .nodes
            .iter()
            .any(|s| s.as_ref().map_or(false, |n| n.id == to));
        if !from_exists || !to_exists {
            return Err("node not found");
        }
        let rel = Relationship {
            from_id: from,
            to_id: to,
            rel_type,
            bidirectional,
        };
        for slot in self.relationships.iter_mut() {
            if slot.is_none() {
                *slot = Some(rel);
                self.rel_count += 1;
                return Ok(());
            }
        }
        Err("add_relationship failed")
    }

    pub fn remove_relationship(
        &mut self,
        from: ObjectId,
        to: ObjectId,
    ) -> Result<(), &'static str> {
        let mut found = false;
        for slot in self.relationships.iter_mut() {
            if let Some(r) = slot {
                if r.from_id == from && r.to_id == to {
                    *slot = None;
                    self.rel_count -= 1;
                    found = true;
                    break;
                }
            }
        }
        if found {
            Ok(())
        } else {
            Err("relationship not found")
        }
    }

    pub fn neighbors(&self, id: ObjectId) -> [ObjectId; 16] {
        let mut result = [0u64; 16];
        let mut count = 0;
        for slot in self.relationships.iter() {
            if let Some(r) = slot {
                if count >= 16 {
                    break;
                }
                if r.from_id == id {
                    result[count] = r.to_id;
                    count += 1;
                } else if r.bidirectional && r.to_id == id {
                    result[count] = r.from_id;
                    count += 1;
                }
            }
        }
        result
    }

    pub fn find_by_type(&self, obj_type: ObjectType) -> [ObjectId; 16] {
        let mut result = [0u64; 16];
        let mut count = 0;
        for slot in self.nodes.iter() {
            if let Some(n) = slot {
                if count >= 16 {
                    break;
                }
                if n.obj_type == obj_type {
                    result[count] = n.id;
                    count += 1;
                }
            }
        }
        result
    }

    pub fn get_node(&self, id: ObjectId) -> Option<&ObjectNode> {
        for slot in self.nodes.iter() {
            if let Some(n) = slot {
                if n.id == id {
                    return Some(n);
                }
            }
        }
        None
    }

    pub fn node_count(&self) -> usize {
        self.node_count
    }

    pub fn rel_count(&self) -> usize {
        self.rel_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: ObjectId, obj_type: ObjectType) -> ObjectNode {
        ObjectNode {
            id,
            obj_type,
            name: [0u8; 32],
            attributes: 0,
        }
    }

    #[test]
    fn add_node_assigns_id() {
        let mut g = ObjectGraph::new();
        let id = g.add_node(make_node(1, ObjectType::File)).unwrap();
        assert_eq!(id, 1);
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn add_beyond_max_fails() {
        let mut g = ObjectGraph::new();
        for i in 0..64 {
            g.add_node(make_node(i, ObjectType::File)).unwrap();
        }
        assert!(g.add_node(make_node(64, ObjectType::File)).is_err());
    }

    #[test]
    fn add_relationship_and_neighbors() {
        let mut g = ObjectGraph::new();
        g.add_node(make_node(1, ObjectType::Process)).unwrap();
        g.add_node(make_node(2, ObjectType::File)).unwrap();
        g.add_relationship(1, 2, RelType::Uses, false).unwrap();
        let n = g.neighbors(1);
        assert_eq!(n[0], 2);
        assert_eq!(g.rel_count(), 1);
    }

    #[test]
    fn remove_node_clears_relationships() {
        let mut g = ObjectGraph::new();
        g.add_node(make_node(1, ObjectType::Process)).unwrap();
        g.add_node(make_node(2, ObjectType::File)).unwrap();
        g.add_relationship(1, 2, RelType::Uses, false).unwrap();
        g.remove_node(1).unwrap();
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.rel_count(), 0);
    }

    #[test]
    fn find_by_type_returns_matching() {
        let mut g = ObjectGraph::new();
        g.add_node(make_node(1, ObjectType::File)).unwrap();
        g.add_node(make_node(2, ObjectType::Process)).unwrap();
        g.add_node(make_node(3, ObjectType::File)).unwrap();
        let ids = g.find_by_type(ObjectType::File);
        assert_eq!(ids[0], 1);
        assert_eq!(ids[1], 3);
    }

    #[test]
    fn remove_relationship_updates_neighbors() {
        let mut g = ObjectGraph::new();
        g.add_node(make_node(1, ObjectType::Process)).unwrap();
        g.add_node(make_node(2, ObjectType::File)).unwrap();
        g.add_relationship(1, 2, RelType::Uses, false).unwrap();
        g.remove_relationship(1, 2).unwrap();
        let n = g.neighbors(1);
        assert_eq!(n[0], 0);
        assert_eq!(g.rel_count(), 0);
    }
}
