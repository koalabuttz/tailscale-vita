//! Virtual filesystem path mapping — the single place client FTP paths turn
//! into real Vita paths. Two conventions coexist so ts-ftp is a drop-in
//! replacement for both its own historical behaviour and ftpvita/VitaShell:
//!
//! - **Jail-relative** (historical): bare/relative paths and plain absolutes
//!   like `data/...` or `/data/...` resolve *under* the configured `root`
//!   (default `ux0:`), and `..` cannot escape above it.
//! - **Device-absolute** (VitaShell/ftpvita): a path whose first segment is a
//!   device token — `/ux0:/data`, `/ur0:/tai` — routes straight to that
//!   device, bypassing the jail root. On a jailbroken Vita the tailnet ACL is
//!   the real boundary (see the threat-model note in memory), so cross-device
//!   access is intentional and matches what VitaShell exposes.
//!
//! The virtual root `/` is the device-list level: `LIST /` shows the known
//! mount points. There is no device-enumeration syscall, so [`DEVICES`] is a
//! hardcoded list. Real paths are handed to `vita_fs`, which normalizes the
//! device-prefix slash (`"ux0:/a" -> "ux0:a"`).

use vita_fs::DirEntry;

/// Known Vita mount points surfaced at the virtual root `/` (there is no
/// enumeration syscall). A client can still `CWD`/`RETR` into any `xxx:`
/// device that actually exists — this list only drives the `LIST /` view.
pub(crate) const DEVICES: &[&str] = &["ux0:", "ur0:", "uma0:", "imc0:"];

/// A path jail rooted at `root` (e.g. `"ux0:"` or `"ux0:/data"`).
pub(crate) struct Vfs {
    root: String,
}

impl Vfs {
    pub(crate) fn new(root: &str) -> Self {
        // Drop a trailing '/' so joins are clean ("ux0:/" -> "ux0:").
        Self {
            root: root.trim_end_matches('/').to_string(),
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
            if is_device(first) {
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

/// Whether `vpath` is the virtual root (`/`) — the device-list level.
pub(crate) fn is_root(vpath: &str) -> bool {
    vpath == "/"
}

/// The `LIST /` view: the known [`DEVICES`] as directory entries.
pub(crate) fn device_entries() -> Vec<DirEntry> {
    DEVICES
        .iter()
        .map(|d| DirEntry {
            name: (*d).to_string(),
            is_dir: true,
            size: 0,
        })
        .collect()
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
        let v = Vfs::new("ux0:");
        assert_eq!(v.resolve("/", "data").as_deref(), Some("/data"));
        assert_eq!(v.resolve("/data", "tailscale-vita").as_deref(), Some("/data/tailscale-vita"));
        assert_eq!(v.resolve("/data", "/app").as_deref(), Some("/app"));
        assert_eq!(v.resolve("/data/x", "..").as_deref(), Some("/data"));
        assert_eq!(v.resolve("/data", ".").as_deref(), Some("/data"));
    }

    #[test]
    fn escape_above_root_is_rejected() {
        let v = Vfs::new("ux0:");
        assert_eq!(v.resolve("/", ".."), None);
        assert_eq!(v.resolve("/data", "../../etc"), None);
        assert_eq!(v.resolve("/", "/../secret"), None);
    }

    #[test]
    fn to_real_maps_under_root() {
        let v = Vfs::new("ux0:");
        assert_eq!(v.to_real("/"), "ux0:");
        assert_eq!(v.to_real("/data/x"), "ux0:/data/x");
        let v2 = Vfs::new("ux0:/data");
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
    fn device_absolute_paths_route_to_device() {
        // Jail root is ux0:, but a leading device segment bypasses it and
        // routes straight to the named device (VitaShell convention).
        let v = Vfs::new("ux0:");
        assert_eq!(v.to_real("/ux0:/data"), "ux0:/data");
        assert_eq!(v.to_real("/ux0:"), "ux0:");
        assert_eq!(v.to_real("/ur0:/tai"), "ur0:/tai");
        // A subdir jail is still bypassed by an explicit device path.
        let v2 = Vfs::new("ux0:/data");
        assert_eq!(v2.to_real("/ur0:/tai"), "ur0:/tai");
    }

    #[test]
    fn bare_paths_still_map_under_root() {
        // Issue #5(b): the historical bare/relative convention keeps working.
        let v = Vfs::new("ux0:");
        assert_eq!(v.to_real("/data/tailscale-vita/vita.log"), "ux0:/data/tailscale-vita/vita.log");
    }

    #[test]
    fn bogus_device_routes_to_a_nonexistent_device_path() {
        // Issue #5: a bogus device is still routed as a device path, so the
        // FS layer rejects it (`550 no such directory/file`) rather than
        // silently mapping it under the jail root.
        let v = Vfs::new("ux0:");
        assert_eq!(v.to_real("/zz0:/x"), "zz0:/x");
    }

    #[test]
    fn device_absolute_resolves_from_client_arg() {
        // The old bug: `ux0:/data` used to resolve to `/ux0:/data` and then
        // map to `ux0:/ux0:/data` (a `550`). Now the leading `ux0:` segment
        // routes to the real device.
        let v = Vfs::new("ux0:");
        let vp = v.resolve("/", "ux0:/data").unwrap();
        assert_eq!(vp, "/ux0:/data");
        assert_eq!(v.to_real(&vp), "ux0:/data");
        let vp2 = v.resolve("/", "/ur0:/tai").unwrap();
        assert_eq!(vp2, "/ur0:/tai");
        assert_eq!(v.to_real(&vp2), "ur0:/tai");
    }

    #[test]
    fn root_is_the_device_list_level() {
        assert!(is_root("/"));
        assert!(!is_root("/ux0:"));
        let names: Vec<String> = device_entries().into_iter().map(|e| e.name).collect();
        assert!(names.contains(&"ux0:".to_string()));
        assert!(device_entries().iter().all(|e| e.is_dir));
    }
}
