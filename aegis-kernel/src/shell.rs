use crate::agent::CapabilityScope;

pub type AppId = u32;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppState {
    Running,
    Stopped,
    Crashed,
}

#[derive(Debug, Clone)]
pub struct AppManifest {
    pub name: [u8; 32],
    pub entry_point: u64,
    pub required_caps: CapabilityScope,
    pub stack_size: u32,
}

impl AppManifest {
    pub fn new(name: &[u8], entry_point: u64) -> Self {
        let mut buf = [0u8; 32];
        let len = name.len().min(32);
        buf[..len].copy_from_slice(&name[..len]);
        Self {
            name: buf,
            entry_point,
            required_caps: CapabilityScope::restrictive(),
            stack_size: 4096,
        }
    }
}

pub struct AppEntry {
    pub id: AppId,
    pub manifest: AppManifest,
    pub state: AppState,
    pub pid: Option<u32>,
    pub window_id: Option<u32>,
}

pub struct ShellRuntime {
    apps: [Option<AppEntry>; 16],
    count: usize,
    focused_app: Option<AppId>,
    next_id: AppId,
}

fn empty_entry() -> AppEntry {
    AppEntry {
        id: 0,
        manifest: AppManifest {
            name: [0u8; 32],
            entry_point: 0,
            required_caps: CapabilityScope::restrictive(),
            stack_size: 0,
        },
        state: AppState::Stopped,
        pid: None,
        window_id: None,
    }
}

impl ShellRuntime {
    pub fn new() -> Self {
        let apps: [Option<AppEntry>; 16] = [
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None,
        ];
        Self {
            apps,
            count: 0,
            focused_app: None,
            next_id: 1,
        }
    }

    pub fn launch(&mut self, manifest: AppManifest) -> Result<AppId, &'static str> {
        if self.count >= self.apps.len() {
            return Err("maximum apps reached");
        }
        let id = self.next_id;
        self.next_id += 1;
        let pid = Some(self.next_id);
        let entry = AppEntry {
            id,
            manifest,
            state: AppState::Running,
            pid,
            window_id: None,
        };
        for slot in self.apps.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(id);
            }
        }
        Err("launch failed")
    }

    pub fn stop(&mut self, app_id: AppId) -> Result<(), &'static str> {
        if let Some(entry) = self.apps.iter_mut().flatten().find(|e| e.id == app_id) {
            entry.state = AppState::Stopped;
            entry.pid = None;
            if self.focused_app == Some(app_id) {
                self.focused_app = None;
            }
            return Ok(());
        }
        Err("app not found")
    }

    pub fn restart(&mut self, app_id: AppId) -> Result<AppId, &'static str> {
        let manifest = self
            .apps
            .iter()
            .find_map(|s| {
                s.as_ref()
                    .filter(|e| e.id == app_id)
                    .map(|e| e.manifest.clone())
            })
            .ok_or("app not found")?;
        if let Some(slot) = self
            .apps
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|e| e.id == app_id))
        {
            *slot = None;
            self.count -= 1;
        }
        self.launch(manifest)
    }

    pub fn focus(&mut self, app_id: AppId) {
        self.focused_app = Some(app_id);
    }

    pub fn focused(&self) -> Option<AppId> {
        self.focused_app
    }

    pub fn list(&self) -> [AppEntry; 16] {
        let mut out = [
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
            empty_entry(),
        ];
        for (i, slot) in self.apps.iter().enumerate() {
            if let Some(e) = slot {
                out[i].id = e.id;
                out[i].manifest = AppManifest {
                    name: e.manifest.name,
                    entry_point: e.manifest.entry_point,
                    required_caps: CapabilityScope::restrictive(),
                    stack_size: e.manifest.stack_size,
                };
                out[i].state = match e.state {
                    AppState::Running => AppState::Running,
                    AppState::Stopped => AppState::Stopped,
                    AppState::Crashed => AppState::Crashed,
                };
                out[i].pid = e.pid;
                out[i].window_id = e.window_id;
            }
        }
        out
    }

    pub fn app_count(&self) -> usize {
        self.count
    }
}

impl Default for ShellRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manifest() -> AppManifest {
        AppManifest::new(b"test_app", 0x1000)
    }

    #[test]
    fn launch_returns_sequential_ids() {
        let mut rt = ShellRuntime::new();
        let id1 = rt.launch(test_manifest()).unwrap();
        let id2 = rt.launch(test_manifest()).unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn launch_beyond_max_fails() {
        let mut rt = ShellRuntime::new();
        for _ in 0..16 {
            rt.launch(test_manifest()).unwrap();
        }
        assert!(rt.launch(test_manifest()).is_err());
    }

    #[test]
    fn stop_transitions_state() {
        let mut rt = ShellRuntime::new();
        let id = rt.launch(test_manifest()).unwrap();
        rt.stop(id).unwrap();
        let apps = rt.list();
        let entry = apps.iter().find(|e| e.id == id).unwrap();
        assert_eq!(entry.state, AppState::Stopped);
        assert!(entry.pid.is_none());
    }

    #[test]
    fn restart_relaunches() {
        let mut rt = ShellRuntime::new();
        let id1 = rt.launch(test_manifest()).unwrap();
        let id2 = rt.restart(id1).unwrap();
        assert_ne!(id1, id2);
        assert_eq!(rt.app_count(), 1);
    }

    #[test]
    fn focus_tracks_last_focused() {
        let mut rt = ShellRuntime::new();
        assert!(rt.focused().is_none());
        let id = rt.launch(test_manifest()).unwrap();
        rt.focus(id);
        assert_eq!(rt.focused(), Some(id));
    }

    #[test]
    fn app_count_increments_on_launch() {
        let mut rt = ShellRuntime::new();
        assert_eq!(rt.app_count(), 0);
        rt.launch(test_manifest()).unwrap();
        assert_eq!(rt.app_count(), 1);
        rt.launch(test_manifest()).unwrap();
        assert_eq!(rt.app_count(), 2);
    }
}
