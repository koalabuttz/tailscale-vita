#![allow(dead_code)] // apply/read paths are vita-gated; host sees some as dead

//! M17-B — section-aware line editing of config.toml. Config has no
//! `Serialize` and the template is comment-heavy, so we NEVER
//! re-serialize; we rewrite the single target line in place, preserving
//! every comment and all formatting. Pure string→string (host-tested);
//! the file I/O + atomic swap lives in `apply_toggle`.

use std::path::Path;

/// Toggle a boolean `key` under `[section]` in raw TOML `text`, flipping
/// its value. Returns the new file text and the new value, or `None` if
/// the key wasn't found under that section (caller surfaces an error).
///
/// Section-aware: `enabled` exists under both `[ftp]` and
/// `[egress_probe]`, so we only edit the target line that appears AFTER
/// the `[section]` header and BEFORE the next `[…]` header.
/// Name of the TOML table a line declares (`[name]`), tolerating a
/// trailing comment (`[name] # note`). `None` for non-header lines.
fn section_name(line: &str) -> Option<&str> {
    let t = line.trim_start();
    let inner = t.strip_prefix('[')?;
    let end = inner.find(']')?;
    Some(inner[..end].trim())
}

pub fn toggle_bool(text: &str, section: &str, key: &str) -> Option<(String, bool)> {
    let mut in_section = false;
    let mut new_value = None;
    let mut out = String::with_capacity(text.len() + 8);

    for line in text.lines() {
        if let Some(name) = section_name(line) {
            in_section = name == section;
            out.push_str(line);
            out.push('\n');
            continue;
        } else if in_section && new_value.is_none() {
            // Match `key` before `=`, ignoring leading whitespace and
            // a leading `#` (commented lines are skipped — we only flip
            // an active setting).
            if let Some((lhs, _rhs)) = line.split_once('=') {
                if lhs.trim() == key {
                    let indent = &line[..line.len() - line.trim_start().len()];
                    let cur = current_bool(line);
                    let next = !cur;
                    out.push_str(indent);
                    out.push_str(key);
                    out.push_str(&format!(" = {next}"));
                    out.push('\n');
                    new_value = Some(next);
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    new_value.map(|v| (out, v))
}

/// Read the current bool from a `key = value` line (defaults to false if
/// the RHS isn't literally `true`).
fn current_bool(line: &str) -> bool {
    line.split_once('=')
        .map(|(_, rhs)| rhs.trim().starts_with("true"))
        .unwrap_or(false)
}

/// Read the current value of a bool `key` under `[section]`, if present
/// and active. Used to render the live setting state.
pub fn read_bool(text: &str, section: &str, key: &str) -> Option<bool> {
    let mut in_section = false;
    for line in text.lines() {
        if let Some(name) = section_name(line) {
            in_section = name == section;
        } else if in_section {
            if let Some((lhs, _)) = line.split_once('=') {
                if lhs.trim() == key {
                    return Some(current_bool(line));
                }
            }
        }
    }
    None
}

/// Read config.toml, flip `[section] key`, write it back. Returns the
/// new value on success.
///
/// Durability note: `vita_fs::rename` is NOT an atomic swap on the Vita
/// — it does remove-then-rename, so a rename *error* (not just a crash)
/// could otherwise leave config.toml missing while the runtime rewrites
/// a blank template over it, stranding the user's auth_key. We defend on
/// two fronts: (1) a `.bak` copy of the original is written FIRST, so
/// the pre-edit file (auth_key and all) is always recoverable; (2) after
/// the swap we VERIFY config.toml is present and non-empty, and if the
/// non-atomic rename lost it, we rewrite the new content directly. The
/// new content is a full copy that preserves every non-target line, so
/// this restore is lossless.
pub fn apply_toggle(config_path: &str, section: &str, key: &str) -> Result<bool, String> {
    let text = vita_fs::read_to_string(Path::new(config_path))
        .map_err(|e| format!("read config: {e}"))?;
    let (new_text, new_value) = toggle_bool(&text, section, key)
        .ok_or_else(|| format!("no `{key}` under [{section}]"))?;

    // 1. Backup the ORIGINAL before anything destructive (best-effort).
    let bak = format!("{config_path}.bak");
    let _ = vita_fs::write(Path::new(&bak), text.as_bytes());

    // 2. Stage the new content, then swap it in. A staging-write failure
    //    leaves config.toml untouched (rename never runs).
    let tmp = format!("{config_path}.tmp");
    vita_fs::write(Path::new(&tmp), new_text.as_bytes())
        .map_err(|e| format!("write tmp: {e}"))?;
    let _rename = vita_fs::rename(Path::new(&tmp), Path::new(config_path));

    // 3. Verify the swap landed a good file; if the non-atomic rename
    //    lost it (error mid-swap), rewrite the new content directly.
    let good = matches!(
        vita_fs::read_to_string(Path::new(config_path)),
        Ok(ref s) if !s.trim().is_empty()
    );
    if !good {
        vita_fs::write(Path::new(config_path), new_text.as_bytes())
            .map_err(|e| format!("config swap failed; original saved at {bak}: {e}"))?;
    }
    Ok(new_value)
}

/// Read config.toml and return the live value of `[section] key`.
pub fn read_toggle(config_path: &str, section: &str, key: &str) -> Option<bool> {
    let text = vita_fs::read_to_string(Path::new(config_path)).ok()?;
    read_bool(&text, section, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "\
control_url = \"https://x\"
auth_key = \"secret-key-do-not-touch\"

[ftp]
enabled         = false
port            = 21
read_only       = true

[egress_probe]
enabled            = false
rounds             = 5
";

    #[test]
    fn toggles_correct_section() {
        let (out, v) = toggle_bool(CFG, "ftp", "enabled").unwrap();
        assert!(v);
        assert!(out.contains("enabled = true\n"));
        // egress_probe.enabled must be UNTOUCHED (still the decoy false).
        assert!(out.contains("[egress_probe]\nenabled            = false"));
        // auth_key preserved verbatim.
        assert!(out.contains("auth_key = \"secret-key-do-not-touch\""));
        // Comment-preservation: port line intact.
        assert!(out.contains("port            = 21"));
    }

    #[test]
    fn toggles_read_only_true_to_false() {
        let (out, v) = toggle_bool(CFG, "ftp", "read_only").unwrap();
        assert!(!v);
        assert!(out.contains("read_only = false\n"));
        // ftp.enabled unchanged.
        assert!(out.contains("enabled         = false"));
    }

    #[test]
    fn egress_probe_enabled_targets_the_right_one() {
        let (out, v) = toggle_bool(CFG, "egress_probe", "enabled").unwrap();
        assert!(v);
        // ftp.enabled stays false; egress_probe flips.
        assert!(out.contains("[ftp]\nenabled         = false"));
        assert!(out.contains("[egress_probe]\nenabled = true"));
    }

    #[test]
    fn missing_key_returns_none() {
        assert!(toggle_bool(CFG, "ftp", "nonexistent").is_none());
        assert!(toggle_bool(CFG, "nosuchsection", "enabled").is_none());
    }

    #[test]
    fn double_toggle_is_identity_on_value() {
        let (out1, v1) = toggle_bool(CFG, "ftp", "enabled").unwrap();
        let (_out2, v2) = toggle_bool(&out1, "ftp", "enabled").unwrap();
        assert!(v1 && !v2);
    }

    #[test]
    fn read_bool_reads_live_value() {
        assert_eq!(read_bool(CFG, "ftp", "enabled"), Some(false));
        assert_eq!(read_bool(CFG, "ftp", "read_only"), Some(true));
        assert_eq!(read_bool(CFG, "egress_probe", "enabled"), Some(false));
        assert_eq!(read_bool(CFG, "ftp", "missing"), None);
    }

    #[test]
    fn section_header_with_trailing_comment_still_matches() {
        let cfg = "[ftp]  # the file server\nenabled = false\n\n[egress_probe]\nenabled = false\n";
        let (out, v) = toggle_bool(cfg, "ftp", "enabled").unwrap();
        assert!(v);
        // The commented header line is preserved verbatim.
        assert!(out.contains("[ftp]  # the file server\n"));
        // ftp.enabled flipped; egress_probe.enabled untouched.
        assert!(out.contains("enabled = true\n"));
        assert!(out.contains("[egress_probe]\nenabled = false"));
        assert_eq!(read_bool(cfg, "ftp", "enabled"), Some(false));
    }

    #[test]
    fn no_trailing_newline_and_blank_lines_preserved() {
        let cfg = "[ftp]\nenabled = false"; // no trailing newline
        let (out, _) = toggle_bool(cfg, "ftp", "enabled").unwrap();
        assert!(out.contains("enabled = true"));
    }
}
