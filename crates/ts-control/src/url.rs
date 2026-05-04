use crate::ControlError;

/// Tiny URL splitter. Avoids pulling the `url` crate just to split scheme,
/// host, port, and path off `http://10.0.237.22:8080/x` -style strings.
#[derive(Debug, Clone)]
pub struct ParsedUrl<'a> {
    pub scheme: &'a str, // "http" or "https"
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str, // includes leading '/'
}

pub fn parse(url: &str) -> Result<ParsedUrl<'_>, ControlError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or(ControlError::Url("missing scheme://"))?;
    let (scheme_lc, default_port) = match scheme {
        "http" => ("http", 80),
        "https" => ("https", 443),
        _ => return Err(ControlError::Url("scheme must be http or https")),
    };
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| ControlError::Url("bad port"))?,
        ),
        None => (authority, default_port),
    };
    Ok(ParsedUrl {
        scheme: scheme_lc,
        host,
        port,
        path,
    })
}

/// Append a path to a URL, normalizing trailing slashes.
pub fn join_path(base: &str, suffix: &str) -> String {
    let base_clean = base.trim_end_matches('/');
    if suffix.starts_with('/') {
        format!("{base_clean}{suffix}")
    } else {
        format!("{base_clean}/{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_port() {
        let p = parse("http://example.com").unwrap();
        assert_eq!(p.scheme, "http");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 80);
        assert_eq!(p.path, "/");
    }

    #[test]
    fn parse_with_port_and_path() {
        let p = parse("http://10.0.237.22:8080/key?v=90").unwrap();
        assert_eq!(p.host, "10.0.237.22");
        assert_eq!(p.port, 8080);
        assert_eq!(p.path, "/key?v=90");
    }

    #[test]
    fn parse_https_default() {
        assert_eq!(parse("https://h").unwrap().port, 443);
    }

    #[test]
    fn rejects_bad_scheme() {
        assert!(parse("ftp://h").is_err());
        assert!(parse("h").is_err());
    }

    #[test]
    fn join_path_normalizes() {
        assert_eq!(join_path("http://h", "/key"), "http://h/key");
        assert_eq!(join_path("http://h/", "/key"), "http://h/key");
        assert_eq!(join_path("http://h/", "key"), "http://h/key");
    }
}
