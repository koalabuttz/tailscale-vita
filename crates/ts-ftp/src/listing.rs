//! Directory-listing formatting for `LIST` (Unix `ls -l`-style, which every
//! FTP client parses) and `NLST` (bare names).

use vita_fs::DirEntry;

/// `ls -l`-style lines clients expect: `perms links owner group size date name`.
/// Owner/group/links/date are placeholders — the Vita FS has no real owners
/// and clients only key on perms/size/name.
pub(crate) fn format_list(entries: &[DirEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        let perms = if e.is_dir { "drwxr-xr-x" } else { "-rw-r--r--" };
        out.push_str(&format!(
            "{perms} 1 vita vita {:>12} Jan  1 00:00 {}\r\n",
            e.size, e.name
        ));
    }
    out
}

/// `NLST`: one bare name per line.
pub(crate) fn format_nlst(entries: &[DirEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&e.name);
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ent(name: &str, is_dir: bool, size: u64) -> DirEntry {
        DirEntry {
            name: name.into(),
            is_dir,
            size,
        }
    }

    #[test]
    fn list_has_perms_size_name() {
        let s = format_list(&[ent("a.txt", false, 42), ent("sub", true, 0)]);
        let lines: Vec<&str> = s.lines().collect();
        assert!(lines[0].starts_with("-rw-r--r--"));
        assert!(lines[0].contains("42"));
        assert!(lines[0].ends_with("a.txt"));
        assert!(lines[1].starts_with("drwxr-xr-x"));
        assert!(lines[1].ends_with("sub"));
        assert!(s.ends_with("\r\n"));
    }

    #[test]
    fn nlst_is_bare_names() {
        let s = format_nlst(&[ent("a.txt", false, 1), ent("b", true, 0)]);
        assert_eq!(s, "a.txt\r\nb\r\n");
    }
}
