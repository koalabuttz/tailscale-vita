//! Taildrop filename handling: strict percent-decode + sanitization, and
//! collision-free destination naming. Both are **pure** functions so the
//! security-critical logic is unit-tested without touching the filesystem
//! or the network (the accept path just calls them).
//!
//! Threat model note: Taildrop names arrive from any ACL-permitted peer
//! (the tailnet ACL is the boundary; see the project threat model). A
//! malicious name is the one thing that could escape the drop dir, so the
//! sanitizer is deliberately stricter than ts-ftp's VFS — a Taildrop name
//! is a bare basename, never a path, so ANY separator is a hard reject.

use std::collections::HashSet;

/// Why a name was rejected. Every variant maps to HTTP 400 at the handler.
#[derive(Debug, PartialEq, Eq)]
pub enum NameError {
    /// Decoded to the empty string.
    Empty,
    /// Decoded to `.` or `..` (the current/parent dir).
    DotOrDotDot,
    /// Contains a path separator: `/`, `\\`, or `:` (the Vita device
    /// separator, e.g. `ux0:`).
    Separator,
    /// Contains a control char (`< 0x20` or `0x7F`).
    Control,
    /// Decoded length exceeds [`MAX_NAME_BYTES`].
    TooLong,
    /// Malformed `%XX` escape, or the decoded bytes aren't valid UTF-8.
    BadEncoding,
}

/// Max sanitized name length, in BYTES (not chars). Vita FAT/exFAT
/// tolerates up to 255; we cap there.
const MAX_NAME_BYTES: usize = 255;

/// Cap on collision-rename attempts before we accept an overwrite. 100 is
/// far more `foo (N).ext` siblings than any real drop dir accumulates.
const MAX_COLLISION: u32 = 100;

/// Percent-decode `raw` exactly ONCE, then validate it's a safe bare
/// basename. On success the returned `String` has NO path components —
/// join it directly under the drop dir.
///
/// Single-pass decode is deliberate: decoding twice would let a
/// double-encoded `%252e%252e` collapse to `..` AFTER our checks. We
/// decode once and reject the literal result, so `%2e%2e` → `..` →
/// rejected and `%252e` → `%2e` (a literal, harmless) stays literal.
pub fn sanitize_filename(raw: &str) -> Result<String, NameError> {
    let decoded = percent_decode_once(raw.as_bytes())?;
    let name = String::from_utf8(decoded).map_err(|_| NameError::BadEncoding)?;
    validate(&name)?;
    Ok(name)
}

/// Reject empty / `.` / `..` / separators / control chars / overlong.
fn validate(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name == "." || name == ".." {
        return Err(NameError::DotOrDotDot);
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(NameError::TooLong);
    }
    // All rejected bytes are ASCII, so a byte scan is safe: multibyte
    // UTF-8 continuation bytes are >= 0x80 and never collide with these.
    for &b in name.as_bytes() {
        match b {
            b'/' | b'\\' | b':' => return Err(NameError::Separator),
            0x00..=0x1F | 0x7F => return Err(NameError::Control),
            _ => {}
        }
    }
    Ok(())
}

/// Decode `%XX` escapes once. A `%` not followed by two hex digits is an
/// error (a well-formed peerapi client always encodes). `+` is **not**
/// treated as a space — that's query-string encoding; a path segment's
/// `+` is a literal plus. All other bytes pass through unchanged.
fn percent_decode_once(input: &[u8]) -> Result<Vec<u8>, NameError> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == b'%' {
            // Need two more bytes for the hex pair.
            if i + 2 >= input.len() {
                return Err(NameError::BadEncoding);
            }
            let hi = hex_val(input[i + 1]).ok_or(NameError::BadEncoding)?;
            let lo = hex_val(input[i + 2]).ok_or(NameError::BadEncoding)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Pick a collision-free destination name. If `base` isn't already in
/// `existing`, use it as-is; otherwise insert ` (1)`, ` (2)`, … before the
/// extension (`foo.txt` → `foo (1).txt`, `foo` → `foo (1)`, `.bashrc` →
/// `.bashrc (1)` because a leading dot is not an extension). Caps at
/// [`MAX_COLLISION`]; if every candidate is taken it returns the last one
/// (accepting an overwrite beats rejecting the drop). Pure: `existing` is
/// the current dir contents, so this is testable without vita-fs.
pub fn next_free_name(base: &str, existing: &HashSet<String>) -> String {
    if !existing.contains(base) {
        return base.to_string();
    }
    let (stem, ext) = split_stem_ext(base);
    let mut candidate = String::new();
    for n in 1..=MAX_COLLISION {
        candidate = format!("{stem} ({n}){ext}");
        if !existing.contains(&candidate) {
            return candidate;
        }
    }
    candidate
}

/// Split `name` into `(stem, ext)` where `ext` includes its leading dot,
/// using the LAST `.` that isn't the first byte (so dotfiles like
/// `.bashrc` have an empty ext). `archive.tar.gz` → `("archive.tar",
/// ".gz")`.
fn split_stem_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(idx) if idx > 0 => (&name[..idx], &name[idx..]),
        _ => (name, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_filename_table() {
        // --- accepted ---
        assert_eq!(sanitize_filename("hello.txt").unwrap(), "hello.txt");
        assert_eq!(sanitize_filename("my%20file.txt").unwrap(), "my file.txt");
        assert_eq!(sanitize_filename("a-b_c.1.2.bin").unwrap(), "a-b_c.1.2.bin");
        // unicode check mark, %E2%9C%93 → ✓
        assert_eq!(sanitize_filename("%E2%9C%93.txt").unwrap(), "\u{2713}.txt");
        // exactly 255 bytes is fine.
        assert_eq!(sanitize_filename(&"a".repeat(255)).unwrap().len(), 255);
        // A literal double-encoded token stays literal (single-pass decode).
        assert_eq!(sanitize_filename("%252e%252e").unwrap(), "%2e%2e");

        // --- rejected ---
        let reject: &[(&str, NameError)] = &[
            ("", NameError::Empty),
            (".", NameError::DotOrDotDot),
            ("..", NameError::DotOrDotDot),
            ("%2e%2e", NameError::DotOrDotDot),      // encoded ".."
            ("..%2F", NameError::Separator),          // traversal
            ("..%2f", NameError::Separator),          // traversal (lc hex)
            ("foo%2Fbar", NameError::Separator),      // encoded slash
            ("foo/bar", NameError::Separator),        // literal slash
            ("foo%5Cbar", NameError::Separator),      // encoded backslash
            ("foo\\bar", NameError::Separator),       // literal backslash
            ("ux0:", NameError::Separator),           // device token
            ("ux0%3Adata", NameError::Separator),     // encoded colon
            ("a%00b", NameError::Control),            // NUL
            ("a%09b", NameError::Control),            // TAB (< 0x20)
            ("a%1Fb", NameError::Control),            // unit separator
            ("a%7Fb", NameError::Control),            // DEL
            (&"a".repeat(256), NameError::TooLong),   // overlong
            ("%zz", NameError::BadEncoding),          // non-hex escape
            ("%2", NameError::BadEncoding),           // truncated escape
            ("ab%", NameError::BadEncoding),          // trailing percent
        ];
        for (input, want) in reject {
            assert_eq!(
                sanitize_filename(input).unwrap_err(),
                *want,
                "input {input:?} expected {want:?}"
            );
        }
    }

    #[test]
    fn next_free_name_collision_walk() {
        let mut ex: HashSet<String> = HashSet::new();
        // No collision → identity.
        assert_eq!(next_free_name("foo.txt", &ex), "foo.txt");
        // First collision → " (1)" before the extension.
        ex.insert("foo.txt".into());
        assert_eq!(next_free_name("foo.txt", &ex), "foo (1).txt");
        // Walks to the first gap.
        ex.insert("foo (1).txt".into());
        ex.insert("foo (2).txt".into());
        assert_eq!(next_free_name("foo.txt", &ex), "foo (3).txt");
        // No extension.
        ex.insert("bar".into());
        assert_eq!(next_free_name("bar", &ex), "bar (1)");
        // Dotfile: the leading dot is not an extension.
        ex.insert(".bashrc".into());
        assert_eq!(next_free_name(".bashrc", &ex), ".bashrc (1)");
        // Double extension: only the LAST dot splits.
        ex.insert("a.tar.gz".into());
        assert_eq!(next_free_name("a.tar.gz", &ex), "a.tar (1).gz");
    }

    #[test]
    fn next_free_name_caps_at_max_and_accepts_overwrite() {
        let mut ex: HashSet<String> = HashSet::new();
        ex.insert("x.bin".into());
        for n in 1..=MAX_COLLISION {
            ex.insert(format!("x ({n}).bin"));
        }
        // Every candidate taken → returns the last attempt (overwrite).
        assert_eq!(next_free_name("x.bin", &ex), format!("x ({MAX_COLLISION}).bin"));
    }
}
