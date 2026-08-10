use crate::window::WindowId;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Key {
    A, B, C, D, E, F, G, H, I, J, K, L, M,
    N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
    Zero, One, Two, Three, Four, Five,
    Six, Seven, Eight, Nine,
    Enter, Backspace, Space, Tab, Escape,
    ArrowUp, ArrowDown, ArrowLeft, ArrowRight,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeyEvent {
    pub key: Key,
    pub pressed: bool,
    pub modifiers: KeyModifiers,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct KeyModifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MouseEvent {
    pub x: i16,
    pub y: i16,
    pub left_button: bool,
    pub right_button: bool,
    pub scroll: i8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
}

pub struct InputBuffer {
    events: [Option<InputEvent>; 64],
    head: usize,
    tail: usize,
    count: usize,
}

impl InputBuffer {
    pub fn new() -> Self {
        Self {
            events: [
                None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
            ],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn push(&mut self, event: InputEvent) -> Result<(), &'static str> {
        if self.count >= self.events.len() {
            return Err("input buffer full");
        }
        self.events[self.head] = Some(event);
        self.head = (self.head + 1) % self.events.len();
        self.count += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<InputEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.events[self.tail].take();
        self.tail = (self.tail + 1) % self.events.len();
        self.count -= 1;
        event
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn is_full(&self) -> bool {
        self.count >= self.events.len()
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

pub struct InputDispatcher {
    focused_window: Option<WindowId>,
    key_handlers: [Option<WindowId>; 16],
    mouse_handlers: [Option<WindowId>; 16],
}

impl InputDispatcher {
    pub fn new() -> Self {
        Self {
            focused_window: None,
            key_handlers: [
                None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
            ],
            mouse_handlers: [
                None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None,
            ],
        }
    }

    pub fn set_focus(&mut self, window_id: WindowId) {
        self.focused_window = Some(window_id);
    }

    pub fn dispatch(&self, event: &InputEvent) -> Option<WindowId> {
        match event {
            InputEvent::Key(_) => self.focused_window,
            InputEvent::Mouse(_) => self.focused_window,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop_roundtrip() {
        let mut buf = InputBuffer::new();
        let ev = InputEvent::Key(KeyEvent {
            key: Key::A,
            pressed: true,
            modifiers: KeyModifiers::default(),
        });
        buf.push(ev).unwrap();
        let popped = buf.pop().unwrap();
        assert_eq!(popped, ev);
    }

    #[test]
    fn push_to_full_buffer_fails() {
        let mut buf = InputBuffer::new();
        let ev = InputEvent::Key(KeyEvent {
            key: Key::A,
            pressed: true,
            modifiers: KeyModifiers::default(),
        });
        for _ in 0..64 {
            buf.push(ev).unwrap();
        }
        assert!(buf.push(ev).is_err());
    }

    #[test]
    fn pop_from_empty_returns_none() {
        let mut buf = InputBuffer::new();
        assert!(buf.pop().is_none());
    }

    #[test]
    fn ring_buffer_wraps_around() {
        let mut buf = InputBuffer::new();
        let ev = InputEvent::Key(KeyEvent {
            key: Key::A,
            pressed: true,
            modifiers: KeyModifiers::default(),
        });
        // Fill and drain to move head/tail past zero
        for _ in 0..32 {
            buf.push(ev).unwrap();
        }
        for _ in 0..32 {
            buf.pop().unwrap();
        }
        // Now push/pop should work after wrapping
        buf.push(ev).unwrap();
        assert_eq!(buf.pop().unwrap(), ev);
    }

    #[test]
    fn dispatch_routes_to_focused_window() {
        let mut disp = InputDispatcher::new();
        disp.set_focus(42);
        let ev = InputEvent::Key(KeyEvent {
            key: Key::Enter,
            pressed: true,
            modifiers: KeyModifiers::default(),
        });
        assert_eq!(disp.dispatch(&ev), Some(42));
        let mev = InputEvent::Mouse(MouseEvent {
            x: 10,
            y: 20,
            left_button: true,
            right_button: false,
            scroll: 0,
        });
        assert_eq!(disp.dispatch(&mev), Some(42));
    }
}
