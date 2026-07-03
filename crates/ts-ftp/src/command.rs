//! FTP control-command parsing. One CRLF-stripped line → a [`Command`].

/// A parsed FTP command. Argument-bearing variants carry the trimmed arg;
/// `LIST`/`NLST` args are optional (bare `LIST` lists the cwd).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    User(String),
    Pass(String),
    Syst,
    Feat,
    Type(String),
    Pwd,
    Cwd(String),
    Cdup,
    Pasv,
    /// Extended passive mode. Optional arg is a net-protocol number
    /// (`1`/`2`) or `ALL` (lock the client into EPSV).
    Epsv(Option<String>),
    List(Option<String>),
    Nlst(Option<String>),
    Retr(String),
    Stor(String),
    Size(String),
    Dele(String),
    Mkd(String),
    Rmd(String),
    Rnfr(String),
    Rnto(String),
    Quit,
    Noop,
    /// Unrecognized verb — replied to with `502`.
    Unknown(String),
}

/// Parse one command line. The verb is case-insensitive; the argument keeps
/// its original case (paths are case-sensitive on the Vita FS).
pub(crate) fn parse(line: &str) -> Command {
    let line = line.trim();
    let (verb, arg) = match line.split_once(' ') {
        Some((v, a)) => (v, a.trim()),
        None => (line, ""),
    };
    let s = |x: &str| x.to_string();
    let opt = |x: &str| (!x.is_empty()).then(|| x.to_string());

    match verb.to_ascii_uppercase().as_str() {
        "USER" => Command::User(s(arg)),
        "PASS" => Command::Pass(s(arg)),
        "SYST" => Command::Syst,
        "FEAT" => Command::Feat,
        "TYPE" => Command::Type(s(arg)),
        "PWD" | "XPWD" => Command::Pwd,
        "CWD" => Command::Cwd(s(arg)),
        "CDUP" => Command::Cdup,
        "PASV" => Command::Pasv,
        "EPSV" => Command::Epsv(opt(arg)),
        "LIST" => Command::List(opt(arg)),
        "NLST" => Command::Nlst(opt(arg)),
        "RETR" => Command::Retr(s(arg)),
        "STOR" => Command::Stor(s(arg)),
        "SIZE" => Command::Size(s(arg)),
        "DELE" => Command::Dele(s(arg)),
        "MKD" | "XMKD" => Command::Mkd(s(arg)),
        "RMD" | "XRMD" => Command::Rmd(s(arg)),
        "RNFR" => Command::Rnfr(s(arg)),
        "RNTO" => Command::Rnto(s(arg)),
        "QUIT" => Command::Quit,
        "NOOP" => Command::Noop,
        _ => Command::Unknown(s(line)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbs_are_case_insensitive() {
        assert_eq!(parse("user bob"), Command::User("bob".into()));
        assert_eq!(parse("USER bob"), Command::User("bob".into()));
        assert_eq!(parse("PaSs pw"), Command::Pass("pw".into()));
    }

    #[test]
    fn args_keep_case_and_trim() {
        assert_eq!(parse("CWD /App/Foo"), Command::Cwd("/App/Foo".into()));
        assert_eq!(parse("RETR  spaced.txt "), Command::Retr("spaced.txt".into()));
    }

    #[test]
    fn list_arg_optional() {
        assert_eq!(parse("LIST"), Command::List(None));
        assert_eq!(parse("LIST -la"), Command::List(Some("-la".into())));
        assert_eq!(parse("NLST sub"), Command::Nlst(Some("sub".into())));
    }

    #[test]
    fn no_arg_commands() {
        assert_eq!(parse("PASV"), Command::Pasv);
        assert_eq!(parse("pwd"), Command::Pwd);
        assert_eq!(parse("XPWD"), Command::Pwd);
        assert_eq!(parse("QUIT"), Command::Quit);
    }

    #[test]
    fn epsv_with_and_without_arg() {
        assert_eq!(parse("EPSV"), Command::Epsv(None));
        assert_eq!(parse("epsv"), Command::Epsv(None));
        assert_eq!(parse("EPSV 1"), Command::Epsv(Some("1".into())));
        assert_eq!(parse("EPSV ALL"), Command::Epsv(Some("ALL".into())));
    }

    #[test]
    fn unknown_verb() {
        assert_eq!(parse("FROB x"), Command::Unknown("FROB x".into()));
    }
}
