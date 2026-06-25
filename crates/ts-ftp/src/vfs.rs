//! Virtual filesystem jail: maps client FTP paths (virtual, rooted at `/`)
//! to real Vita paths under a configured `root`, refusing `..` escapes above
//! the root. Real paths are handed to `vita_fs`, which normalizes the
//! device-prefix slash (`"ux0:/a" -> "ux0:a"`).

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
    /// Returns `None` if the path would escape above the jail root.
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

    /// Map a virtual path (`"/"` or `"/a/b"`) to a real Vita path under the
    /// root. `"/"` is the bare root; others append the slash-prefixed path
    /// (vita_fs strips the post-colon slash for the device prefix).
    pub(crate) fn to_real(&self, vpath: &str) -> String {
        if vpath == "/" {
            self.root.clone()
        } else {
            format!("{}{}", self.root, vpath)
        }
    }
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
}
