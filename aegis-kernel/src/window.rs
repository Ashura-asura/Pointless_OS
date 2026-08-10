use crate::shell::AppId;

pub type WindowId = u32;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Region {
    pub x: i16,
    pub y: i16,
    pub width: u16,
    pub height: u16,
}

pub struct Window {
    pub id: WindowId,
    pub owner_app: AppId,
    pub region: Region,
    pub z_order: u8,
    pub visible: bool,
    pub title: [u8; 32],
    pub framebuffer_offset: u64,
}

pub struct WindowManager {
    windows: [Option<Window>; 32],
    count: usize,
    next_id: WindowId,
    #[allow(dead_code)] // Screen bounds for clipping in the real compositor
    screen_width: u16,
    #[allow(dead_code)] // Screen bounds for clipping in the real compositor
    screen_height: u16,
    dirty_regions: [Region; 32],
    dirty_count: usize,
}

impl WindowManager {
    pub fn new(width: u16, height: u16) -> Self {
        Self {
            windows: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None,
            ],
            count: 0,
            next_id: 1,
            screen_width: width,
            screen_height: height,
            dirty_regions: [Region {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            }; 32],
            dirty_count: 0,
        }
    }

    pub fn create_window(
        &mut self,
        app_id: AppId,
        title: &[u8],
        region: Region,
    ) -> Result<WindowId, &'static str> {
        if self.count >= self.windows.len() {
            return Err("maximum windows reached");
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut title_buf = [0u8; 32];
        let len = title.len().min(32);
        title_buf[..len].copy_from_slice(&title[..len]);
        let win = Window {
            id,
            owner_app: app_id,
            region,
            z_order: self.count as u8,
            visible: true,
            title: title_buf,
            framebuffer_offset: 0,
        };
        for slot in self.windows.iter_mut() {
            if slot.is_none() {
                *slot = Some(win);
                self.count += 1;
                return Ok(id);
            }
        }
        Err("create_window failed")
    }

    pub fn destroy_window(&mut self, id: WindowId) -> Result<(), &'static str> {
        if let Some(slot) = self
            .windows
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|w| w.id == id))
        {
            *slot = None;
            self.count -= 1;
            return Ok(());
        }
        Err("window not found")
    }

    pub fn move_window(&mut self, id: WindowId, x: i16, y: i16) -> Result<(), &'static str> {
        if let Some(w) = self.windows.iter_mut().flatten().find(|w| w.id == id) {
            w.region.x = x;
            w.region.y = y;
            return Ok(());
        }
        Err("window not found")
    }

    pub fn resize_window(
        &mut self,
        id: WindowId,
        width: u16,
        height: u16,
    ) -> Result<(), &'static str> {
        if let Some(w) = self.windows.iter_mut().flatten().find(|w| w.id == id) {
            w.region.width = width;
            w.region.height = height;
            return Ok(());
        }
        Err("window not found")
    }

    pub fn set_visible(&mut self, id: WindowId, visible: bool) -> Result<(), &'static str> {
        if let Some(w) = self.windows.iter_mut().flatten().find(|w| w.id == id) {
            w.visible = visible;
            return Ok(());
        }
        Err("window not found")
    }

    pub fn set_z_order(&mut self, id: WindowId, z: u8) -> Result<(), &'static str> {
        if let Some(w) = self.windows.iter_mut().flatten().find(|w| w.id == id) {
            w.z_order = z;
            return Ok(());
        }
        Err("window not found")
    }

    pub fn focus_window(&mut self, id: WindowId) -> Result<(), &'static str> {
        let max_z = self
            .windows
            .iter()
            .filter_map(|s| s.as_ref().map(|w| w.z_order))
            .max()
            .unwrap_or(0);
        if let Some(w) = self.windows.iter_mut().flatten().find(|w| w.id == id) {
            w.z_order = max_z + 1;
            return Ok(());
        }
        Err("window not found")
    }

    pub fn hit_test(&self, x: i16, y: i16) -> Option<WindowId> {
        let mut best_z: i16 = -1;
        let mut best_id: Option<WindowId> = None;
        for w in self.windows.iter().flatten() {
            if !w.visible {
                continue;
            }
            if x >= w.region.x
                && x < w.region.x + w.region.width as i16
                && y >= w.region.y
                && y < w.region.y + w.region.height as i16
                && w.z_order as i16 > best_z
            {
                best_z = w.z_order as i16;
                best_id = Some(w.id);
            }
        }
        best_id
    }

    pub fn compositor_order(&self) -> [WindowId; 32] {
        let mut entries: [(WindowId, u8); 32] = [(0, 0); 32];
        let mut entry_count = 0;
        for w in self.windows.iter().flatten() {
            entries[entry_count] = (w.id, w.z_order);
            entry_count += 1;
        }
        for i in 1..entry_count {
            let mut j = i;
            while j > 0 && entries[j - 1].1 > entries[j].1 {
                entries.swap(j - 1, j);
                j -= 1;
            }
        }
        let mut output = [0u32; 32];
        for i in 0..entry_count {
            output[i] = entries[i].0;
        }
        output
    }

    pub fn mark_dirty(&mut self, id: WindowId) -> Result<(), &'static str> {
        if self.dirty_count >= self.dirty_regions.len() {
            return Err("dirty list full");
        }
        if let Some(w) = self.windows.iter().flatten().find(|w| w.id == id) {
            self.dirty_regions[self.dirty_count] = w.region;
            self.dirty_count += 1;
            return Ok(());
        }
        Err("window not found")
    }

    pub fn dirty_regions(&self) -> [Region; 32] {
        self.dirty_regions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_region() -> Region {
        Region {
            x: 10,
            y: 20,
            width: 100,
            height: 200,
        }
    }

    #[test]
    fn create_window_assigns_id() {
        let mut wm = WindowManager::new(800, 600);
        let id1 = wm.create_window(1, b"win1", test_region()).unwrap();
        let id2 = wm.create_window(1, b"win2", test_region()).unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn create_beyond_max_fails() {
        let mut wm = WindowManager::new(800, 600);
        for _ in 0..32 {
            wm.create_window(1, b"w", test_region()).unwrap();
        }
        assert!(wm.create_window(1, b"w", test_region()).is_err());
    }

    #[test]
    fn hit_test_finds_topmost_window() {
        let mut wm = WindowManager::new(800, 600);
        let _id1 = wm
            .create_window(
                1,
                b"bottom",
                Region {
                    x: 0,
                    y: 0,
                    width: 200,
                    height: 200,
                },
            )
            .unwrap();
        let id2 = wm
            .create_window(
                1,
                b"top",
                Region {
                    x: 50,
                    y: 50,
                    width: 200,
                    height: 200,
                },
            )
            .unwrap();
        let hit = wm.hit_test(100, 100).unwrap();
        assert_eq!(hit, id2);
    }

    #[test]
    fn hit_test_returns_none_outside() {
        let mut wm = WindowManager::new(800, 600);
        wm.create_window(
            1,
            b"w",
            Region {
                x: 0,
                y: 0,
                width: 100,
                height: 100,
            },
        )
        .unwrap();
        assert!(wm.hit_test(500, 500).is_none());
    }

    #[test]
    fn set_visible_toggles() {
        let mut wm = WindowManager::new(800, 600);
        let id = wm.create_window(1, b"w", test_region()).unwrap();
        wm.set_visible(id, false).unwrap();
        assert!(wm.hit_test(10, 20).is_none());
        wm.set_visible(id, true).unwrap();
        assert_eq!(wm.hit_test(10, 20), Some(id));
    }

    #[test]
    fn compositor_order_sorts_by_z() {
        let mut wm = WindowManager::new(800, 600);
        let id1 = wm.create_window(1, b"a", test_region()).unwrap();
        let id2 = wm.create_window(1, b"b", test_region()).unwrap();
        let id3 = wm.create_window(1, b"c", test_region()).unwrap();
        wm.set_z_order(id1, 10).unwrap();
        wm.set_z_order(id3, 5).unwrap();
        let order = wm.compositor_order();
        assert_eq!(order[0], id2);
        assert_eq!(order[1], id3);
        assert_eq!(order[2], id1);
    }

    #[test]
    fn mark_dirty_adds_to_list() {
        let mut wm = WindowManager::new(800, 600);
        let id = wm.create_window(1, b"w", test_region()).unwrap();
        wm.mark_dirty(id).unwrap();
        let dirty = wm.dirty_regions();
        assert_eq!(dirty[0], test_region());
    }
}
