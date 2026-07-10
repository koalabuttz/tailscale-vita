//! Virtual filesystem path mapping — the single place client FTP paths turn
//! into real Vita paths. Two conventions coexist so ts-ftp is a drop-in
//! replacement for both its own historical behaviour and ftpvita/VitaShell:
//!
//! - **Jail-relative** (historical): bare/relative paths and plain absolutes
//!   like `data/...` or `/data/...` resolve *under* the configured `root`
//!   (default `ux0:`), and `..` cannot escape above it.
//! - **Device-absolute** (VitaShell/ftpvita): optional compatibility mode for
//!   a path whose first segment is a device token — `/ux0:/data`,
//!   `/ur0:/tai`. It is disabled by default because it bypasses the jail.
//!
//! The virtual root `/` is the device-list level: `LIST /` shows the known
//! mount points. There is no device-enumeration syscall, so [`DEVICES`] is a
//! hardcoded list. Real paths are handed to `vita_fs`, which normalizes the
//! device-prefix slash (`"ux0:/a" -> "ux0:a"`).

/// A path jail rooted at `root` (e.g. `"ux0:"` or `"ux0:/data"`).
pub(crate) struct Vfs {
    root: String,
    allow_device_paths: bool,
}

impl Vfs {
    pub(crate) fn new(root: &str, allow_device_paths: bool) -> Self {
        // Drop a trailing '/' so joins are clean ("ux0:/" -> "ux0:").
        Self {
            root: root.trim_end_matches('/').to_string(),
            allow_device_paths,
        }
    }

    /// Resolve a client path `arg` against the current virtual `cwd`,
    /// returning a normalized absolute virtual path (`"/a/b"` or `"/"`).
    /// Returns `None` if the path would escape above the virtual root.
    pub(crate) fn resolve(&self, cwd: &str, arg: &str) -> Option<String> {
        let base = if arg.starts_with('/') { "/" } else { cwd };
        let mut segs: Vec<&str> = Vec::new();
        for seg in base.split('/').chain(arg.split('/')) {
            match seg {
                "" | "." => {}
                ".." => {
                    // Pop a segment; popping past the root is an escape.
                    if segs.pop().is_none() {
                        return None;
                    }
                }
                s => segs.push(s),
            }
        }
        if segs.is_empty() {
            Some("/".to_string())
        } else {
            Some(format!("/{}", segs.join("/")))
        }
    }

    /// Map a virtual path (`"/"` or `"/a/b"`) to a real Vita path. A leading
    /// device segment (`/ux0:/...`) routes straight to that device, bypassing
    /// the jail root (VitaShell convention); everything else appends under
    /// `root`. `"/"` is the bare root. `vita_fs` strips the post-colon slash
    /// for the device prefix.
    pub(crate) fn to_real(&self, vpath: &str) -> String {
        if let Some(rest) = vpath.strip_prefix('/') {
            let first = rest.split('/').next().unwrap_or("");
            if self.allow_device_paths && is_device(first) {
                // `/ux0:/a` -> `ux0:/a`; `/ux0:` -> `ux0:`.
                return rest.to_string();
            }
        }
        if vpath == "/" {
            self.root.clone()
        } else {
            format!("{}{}", self.root, vpath)
        }
    }
}

/// True if `seg` is a device token: it ends in a single trailing `:` and has
/// no other `:` (e.g. `ux0:`, `ur0:`, `uma0:`). Vita filenames can't contain
/// `:` (the device separator), so a segment ending in `:` is unambiguously a
/// device — a bogus one like `zz0:` still routes to `zz0:...` and the FS
/// rejects it (`550`).
pub(crate) fn is_device(seg: &str) -> bool {
    seg.len() >= 2 && seg.ends_with(':') && !seg[..seg.len() - 1].contains(':')
}

/// Split a virtual path into `(parent, name)`. `"/a/b" -> ("/a", "b")`,
/// `"/b" -> ("/", "b")`. Used by `SIZE` (look the name up in its parent).
pub(crate) fn split_parent(vpath: &str) -> (String, String) {
    match vpath.rfind('/') {
        Some(0) => ("/".to_string(), vpath[1..].to_string()),
        Some(i) => (vpath[..i].to_string(), vpath[i + 1..].to_string()),
        None => ("/".to_string(), vpath.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_and_absolute() {
        let v = Vfs::new("ux0:", false);
        assert_eq!(v.resolve("/", "data").as_deref(), Some("/data"));
        assert_eq!(
            v.resolve("/data", "tailscale-vita").as_deref(),
            Some("/data/tailscale-vita")
        );
        assert_eq!(v.resolve("/data", "/app").as_deref(), Some("/app"));
        assert_eq!(v.resolve("/data/x", "..").as_deref(), Some("/data"));
        assert_eq!(v.resolve("/data", ".").as_deref(), Some("/data"));
    }

    #[test]
    fn escape_above_root_is_rejected() {
        let v = Vfs::new("ux0:", false);
        assert_eq!(v.resolve("/", ".."), None);
        assert_eq!(v.resolve("/data", "../../etc"), None);
        assert_eq!(v.resolve("/", "/../secret"), None);
    }

    #[test]
    fn to_real_maps_under_root() {
        let v = Vfs::new("ux0:", false);
        assert_eq!(v.to_real("/"), "ux0:");
        assert_eq!(v.to_real("/data/x"), "ux0:/data/x");
        let v2 = Vfs::new("ux0:/data", false);
        assert_eq!(v2.to_real("/"), "ux0:/data");
        assert_eq!(v2.to_real("/foo"), "ux0:/data/foo");
    }

    #[test]
    fn split_parent_cases() {
        assert_eq!(split_parent("/a/b"), ("/a".into(), "b".into()));
        assert_eq!(split_parent("/b"), ("/".into(), "b".into()));
    }

    // --- both path conventions (issue #5) ---

    #[test]
    fn is_device_recognizes_device_tokens() {
        assert!(is_device("ux0:"));
        assert!(is_device("ur0:"));
        assert!(is_device("uma0:"));
        assert!(is_device("zz0:")); // bogus but still device-shaped
        assert!(!is_device("data"));
        assert!(!is_device("foo.txt"));
        assert!(!is_device(":"));
        assert!(!is_device(""));
    }

    #[test]
    fn device_absolute_paths_stay_jailed_by_default() {
        let v = Vfs::new("ux0:", false);
        assert_eq!(v.to_real("/ux0:/data"), "ux0:/ux0:/data");
        assert_eq!(v.to_real("/ur0:/tai"), "ux0:/ur0:/tai");
        let v2 = Vfs::new("ux0:/data", false);
        assert_eq!(v2.to_real("/ur0:/tai"), "ux0:/data/ur0:/tai");
    }

    #[test]
    fn bare_paths_still_map_under_root() {
        // Issue #5(b): the historical bare/relative convention keeps working.
        let v = Vfs::new("ux0:", false);
        assert_eq!(
            v.to_real("/data/tailscale-vita/vita.log"),
            "ux0:/data/tailscale-vita/vita.log"
        );
    }

    #[test]
    fn explicit_compatibility_mode_allows_device_paths() {
        let v = Vfs::new("ux0:", false);
        assert_eq!(v.to_real("/ur0:/tai"), "ux0:/ur0:/tai");
        let compat = Vfs::new("ux0:", true);
        assert_eq!(compat.to_real("/ur0:/tai"), "ur0:/tai");
    }

    #[test]
    fn device_absolute_syntax_does_not_escape_jail() {
        let v = Vfs::new("ux0:", false);
        let vp = v.resolve("/", "ux0:/data").unwrap();
        assert_eq!(vp, "/ux0:/data");
        assert_eq!(v.to_real(&vp), "ux0:/ux0:/data");
        let vp2 = v.resolve("/", "/ur0:/tai").unwrap();
        assert_eq!(vp2, "/ur0:/tai");
        assert_eq!(v.to_real(&vp2), "ux0:/ur0:/tai");
    }
}
