//! SceCtrl button-mask helpers. Pure (no FFI) so they're host-testable;
//! bit values verified against psp2common/ctrl.h `SceCtrlButtons`.

pub const SELECT: u32 = 0x0000_0001;
pub const START: u32 = 0x0000_0008;
pub const UP: u32 = 0x0000_0010;
pub const RIGHT: u32 = 0x0000_0020;
pub const DOWN: u32 = 0x0000_0040;
pub const LEFT: u32 = 0x0000_0080;
pub const LTRIGGER: u32 = 0x0000_0100;
pub const RTRIGGER: u32 = 0x0000_0200;
pub const TRIANGLE: u32 = 0x0000_1000;
pub const CIRCLE: u32 = 0x0000_2000;
pub const CROSS: u32 = 0x0000_4000;
pub const SQUARE: u32 = 0x0000_8000;

const NAMED: [(u32, &str); 12] = [
    (SELECT, "SELECT"),
    (START, "START"),
    (UP, "UP"),
    (RIGHT, "RIGHT"),
    (DOWN, "DOWN"),
    (LEFT, "LEFT"),
    (LTRIGGER, "L"),
    (RTRIGGER, "R"),
    (TRIANGLE, "TRIANGLE"),
    (CIRCLE, "CIRCLE"),
    (CROSS, "CROSS"),
    (SQUARE, "SQUARE"),
];

/// Space-separated names of every held button in `mask`; empty string
/// when nothing is held. Order is fixed (the `NAMED` table order) so
/// output is stable for display + tests.
pub fn names(mask: u32) -> String {
    let mut out = String::new();
    for (bit, name) in NAMED {
        if mask & bit != 0 {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_formats_held_buttons_in_stable_order() {
        assert_eq!(names(0), "");
        assert_eq!(names(CROSS), "CROSS");
        // Mask order doesn't matter; table order does.
        assert_eq!(names(CROSS | UP), "UP CROSS");
        assert_eq!(names(SELECT | START | SQUARE), "SELECT START SQUARE");
        // Unknown bits are ignored.
        assert_eq!(names(0x8000_0000), "");
    }
}
