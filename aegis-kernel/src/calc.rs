//! Phase AA: the kernel's fourth real application window — a 4-function
//! calculator model. This is the pure arithmetic/logic half of the desktop's
//! `render_calc`/`apply_mouse` calculator window: the desktop owns a [`Calc`],
//! renders `display_text()` into the window's display row, and routes button
//! presses (digits, `C`, `=`, and the four operators) into
//! `press_digit`/`press_clear`/`press_equals`/`press_op`. The result of every
//! press is a new NUL-terminated `display` text the compositor paints — so the
//! live `6*7=` interaction is provable from the serial log, exactly like the
//! editor's F2 save digest.
//!
//! Semantics: a standard immediate-execution 4-function calculator.
//! [`Self::acc`] holds the saved left operand of a pending binary operator;
//! the on-display operand is parsed back from `display` when an operator or
//! `=` evaluates. Operators chain left-to-right (`2 + 3 * 4 =` -> `20`);
//! division by zero or any `i64` overflow latches `error` and shows `ERR`
//! until `C` clears it. Honest limits: integer arithmetic only (no decimal
//! point — `input.rs` has no punctuation keys anyway); a result wider than the
//! 15-text-byte display latches `error` like an overflow, rather than
//! silently truncating.

/// The calculator model. `display` is NUL-terminated ASCII text (the current
/// operand or result); `acc` is the saved left operand; `op` is the pending
/// operator; `pending` is true when the next digit must start a fresh operand;
/// `error` latches on divide-by-zero / overflow and shows `ERR`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Calc {
    pub display: [u8; 16],
    pub acc: i64,
    pub op: Option<u8>,
    pub pending: bool,
    pub error: bool,
}

/// The 4x4 calculator button grid, in window row-major order. The desktop's
/// `render_calc`/`apply_mouse` and this module's tests share it so a click
/// cell maps to exactly the character the model sees.
pub const BUTTONS: [[u8; 4]; 4] = [*b"789/", *b"456*", *b"123-", *b"0C=+"];

/// Longest text that fits the display buffer with room for the NUL
/// terminator (16 bytes). A wider value latches `error` rather than
/// truncating — the display is fixed-size by design.
const DISPLAY_MAX: usize = 15;

/// The text shown after an overflow / divide-by-zero latch.
const ERR: &[u8] = b"ERR";

impl Default for Calc {
    fn default() -> Self {
        Self::new()
    }
}

impl Calc {
    /// A fresh calculator: display `0`, no operator, no error.
    pub fn new() -> Calc {
        let mut display = [0u8; 16];
        display[0] = b'0';
        Calc {
            display,
            acc: 0,
            op: None,
            pending: false,
            error: false,
        }
    }

    /// The current display text (the NUL-terminated slice).
    pub fn display_text(&self) -> &[u8] {
        let n = self
            .display
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.display.len());
        &self.display[..n]
    }

    /// Press a digit `0..=9`. Ignored while latched in error; otherwise the
    /// digit replaces the display after an operator/`=` (pending) or appends
    /// to the current operand. A value that would overflow `i64` or the
    /// 15-byte display latches the error state.
    pub fn press_digit(&mut self, d: u8) {
        if self.error || d > 9 {
            return;
        }
        let current = if self.pending {
            0
        } else {
            let mut v = 0i64;
            for &b in self.display_text() {
                if b.is_ascii_digit() {
                    v = v * 10 + (b - b'0') as i64;
                }
            }
            v
        };
        self.pending = false;
        let Some(next) = current
            .checked_mul(10)
            .and_then(|v| v.checked_add(d as i64))
        else {
            self.set_error();
            return;
        };
        if !self.write_display(next) {
            self.set_error();
        }
    }

    /// Press an operator `+ - * /`. Ignores nothing but a latched error: with
    /// a complete operand on display it first evaluates the previous pending
    /// operation left-to-right, then stores the running result as the new left
    /// operand. Two operators in a row just replace the operator.
    pub fn press_op(&mut self, o: u8) {
        if self.error {
            return;
        }
        match o {
            b'+' | b'-' | b'*' | b'/' => {}
            _ => return,
        }
        if let Some(prev) = self.op {
            if !self.pending {
                // A complete operand sits on the display: fold it into the
                // running result left-to-right, then let the new operator act
                // on that result.
                if !self.eval(prev) {
                    return;
                }
                self.op = None;
                self.pending = true;
            }
        }
        if self.op.is_none() {
            // First operator of a chain: the current display becomes the left
            // operand of the pending operation.
            self.acc = self.parse_display();
        }
        self.op = Some(o);
        self.pending = true;
    }

    /// Press `=`: evaluate the pending operation against the left operand and
    /// the current display, store the result as the new left operand, and show
    /// it. A no-op with no pending operator.
    pub fn press_equals(&mut self) {
        if self.error {
            return;
        }
        if let Some(op) = self.op {
            if self.eval(op) {
                self.op = None;
                self.pending = true;
            }
        }
    }

    /// Press `C`: reset to the fresh state.
    pub fn press_clear(&mut self) {
        *self = Self::new();
    }

    /// Evaluate `acc op <current display value>` into `acc` and the display.
    /// Returns false (and latches `error`) on divide-by-zero or `i64`
    /// overflow. `pending` is left as the caller expects — the callers set it
    /// after a successful eval.
    fn eval(&mut self, op: u8) -> bool {
        let right = self.parse_display();
        let result = match op {
            b'+' => self.acc.checked_add(right),
            b'-' => self.acc.checked_sub(right),
            b'*' => self.acc.checked_mul(right),
            b'/' => {
                if right == 0 {
                    None
                } else {
                    self.acc.checked_div(right)
                }
            }
            _ => None,
        };
        match result {
            Some(v) if self.write_display(v) => {
                self.acc = v;
                true
            }
            _ => {
                self.set_error();
                false
            }
        }
    }

    /// The numeric value of the current display text (0 for a negative sign
    /// handling: a `-` prefix is decoded as a negative number).
    fn parse_display(&self) -> i64 {
        let t = self.display_text();
        let (neg, digits) = match t.split_first() {
            Some((&b'-', rest)) => (true, rest),
            _ => (false, t),
        };
        let mut v = 0i64;
        for &b in digits {
            if b.is_ascii_digit() {
                v = v * 10 + (b - b'0') as i64;
            }
        }
        if neg {
            -v
        } else {
            v
        }
    }

    /// Format `v` as ASCII decimal into `display` (NUL-terminated). Returns
    /// false when the text would not fit [`DISPLAY_MAX`] bytes.
    fn write_display(&mut self, v: i64) -> bool {
        let mut tmp = [0u8; 24];
        let mut i = tmp.len();
        let mut mag = v.unsigned_abs();
        loop {
            i -= 1;
            tmp[i] = b'0' + (mag % 10) as u8;
            mag /= 10;
            if mag == 0 {
                break;
            }
        }
        if v < 0 {
            i -= 1;
            tmp[i] = b'-';
        }
        let text = &tmp[i..];
        if text.len() > DISPLAY_MAX {
            return false;
        }
        self.display = [0u8; 16];
        self.display[..text.len()].copy_from_slice(text);
        true
    }

    /// Latch the error state and show `ERR` on the display.
    fn set_error(&mut self) {
        self.error = true;
        self.display = [0u8; 16];
        let n = ERR.len().min(DISPLAY_MAX);
        self.display[..n].copy_from_slice(&ERR[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disp(c: &Calc) -> String {
        core::str::from_utf8(c.display_text()).unwrap().to_string()
    }

    #[test]
    fn press_2_plus_2_equals_is_4() {
        let mut c = Calc::new();
        c.press_digit(2);
        c.press_op(b'+');
        c.press_digit(2);
        c.press_equals();
        assert_eq!(disp(&c), "4");
        assert_eq!(c.acc, 4);
        assert!(!c.error);
    }

    #[test]
    fn clear_resets() {
        let mut c = Calc::new();
        c.press_digit(9);
        c.press_op(b'/');
        c.press_digit(0);
        c.press_equals();
        assert!(c.error);
        assert_eq!(c.display_text(), b"ERR");
        c.press_clear();
        assert!(!c.error);
        assert_eq!(c.op, None);
        assert!(!c.pending);
        assert_eq!(c.display_text(), b"0");
    }

    #[test]
    fn operator_chaining_evaluates_left_to_right() {
        // 2 + 3 * 4 = 20 (immediate execution, not precedence).
        let mut c = Calc::new();
        c.press_digit(2);
        c.press_op(b'+');
        c.press_digit(3);
        c.press_op(b'*');
        c.press_digit(4);
        c.press_equals();
        assert_eq!(disp(&c), "20");
        assert!(!c.error);
    }

    #[test]
    fn division_by_zero_shows_error() {
        let mut c = Calc::new();
        c.press_digit(7);
        c.press_op(b'/');
        c.press_digit(0);
        c.press_equals();
        assert!(c.error);
        assert_eq!(c.display_text(), b"ERR");
    }

    #[test]
    fn overflow_shows_error() {
        // 99999999999999 * 99999999999999 overflows i64.
        let mut c = Calc::new();
        for &d in b"99999999999999" {
            c.press_digit(d - b'0');
        }
        c.press_op(b'*');
        for &d in b"99999999999999" {
            c.press_digit(d - b'0');
        }
        c.press_equals();
        assert!(c.error);
        assert_eq!(c.display_text(), b"ERR");
    }

    #[test]
    fn display_is_zero_padded_nul_terminated() {
        let mut c = Calc::new();
        c.press_digit(4);
        c.press_op(b'+');
        c.press_digit(2);
        c.press_equals();
        assert_eq!(c.display, {
            let mut d = [0u8; 16];
            d[0] = b'6';
            d
        });
        assert_eq!(c.display_text(), b"6");
        // A NUL always terminates the text even mid-buffer.
        let mut c2 = Calc::new();
        c2.display = [0u8; 16];
        c2.display[0] = b'1';
        c2.display[1] = b'2';
        assert_eq!(c2.display_text(), b"12");
    }

    #[test]
    fn negative_results_display_with_sign() {
        let mut c = Calc::new();
        c.press_digit(5);
        c.press_op(b'-');
        c.press_digit(7);
        c.press_equals();
        assert_eq!(c.display_text(), b"-2");
    }

    #[test]
    fn button_grid_layout_matches_documented_cells() {
        // The QEMU demo clicks the cells this grid places `6 * 7 =` at.
        assert_eq!(BUTTONS[1][2], b'6');
        assert_eq!(BUTTONS[1][3], b'*');
        assert_eq!(BUTTONS[0][0], b'7');
        assert_eq!(BUTTONS[3][2], b'=');
    }
}
