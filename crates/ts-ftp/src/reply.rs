//! FTP reply formatting. Single-line `code text\r\n` and multi-line
//! (`code-head … code tail`) responses, flushed immediately so the client
//! sees each reply (netstack transmits on flush/poke).

use std::io::{self, Write};

/// Write a single-line reply: `"{code} {text}\r\n"`, then flush.
pub(crate) fn reply<W: Write>(w: &mut W, code: u16, text: &str) -> io::Result<()> {
    write!(w, "{code} {text}\r\n")?;
    w.flush()
}

/// Write a multi-line reply: `"{code}-{head}\r\n"`, one indented `lines`
/// entry per line, then `"{code} {tail}\r\n"`. Used for `FEAT`.
pub(crate) fn reply_multiline<W: Write>(
    w: &mut W,
    code: u16,
    head: &str,
    lines: &[&str],
    tail: &str,
) -> io::Result<()> {
    write!(w, "{code}-{head}\r\n")?;
    for l in lines {
        write!(w, " {l}\r\n")?;
    }
    write!(w, "{code} {tail}\r\n")?;
    w.flush()
}

/// RFC 959 quoted pathname for `257` replies (PWD/MKD): wrap in double quotes
/// and double any embedded `"` so clients parse the path unambiguously.
pub(crate) fn dir_reply(dir: &str) -> String {
    format!("\"{}\"", dir.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_reply_quotes_and_doubles() {
        assert_eq!(dir_reply("/"), "\"/\"");
        assert_eq!(dir_reply("/a/b"), "\"/a/b\"");
        // Embedded quotes are doubled per RFC 959.
        assert_eq!(dir_reply("/od\"d"), "\"/od\"\"d\"");
    }
}
