//! Transport-native peer addressing.

use std::fmt;
use std::str::FromStr;

/// Transport-native address of a tor peer: a v3 `.onion` hostname and port,
/// obtained out of band, opaque to consumers. Shared by every Tor backend
/// (the SOCKS5h daemon backend and the in-process arti backend).
///
/// Construction validates the v3 textual form (`<56 base32 chars>.onion`),
/// so a held `OnionAddr` is always shaped like a real onion address. Only
/// the form is checked; the checksum embedded in the base32 label is not
/// verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionAddr {
    host: String,
    port: u16,
}

/// The v3 textual form: a 56-character base32 label (`a-z2-7`), then `.onion`.
fn is_v3_onion_host(host: &str) -> bool {
    host.strip_suffix(".onion").is_some_and(|label| {
        label.len() == 56
            && label
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    })
}

impl OnionAddr {
    /// An onion address from its hostname (`<56 base32 chars>.onion`) and
    /// port. Rejects a hostname without the v3 textual form.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, ParseOnionAddrError> {
        let host = host.into();
        if !is_v3_onion_host(&host) {
            return Err(ParseOnionAddrError);
        }
        Ok(Self { host, port })
    }

    /// The `.onion` hostname.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The virtual port on the onion service.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for OnionAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Failure to parse an [`OnionAddr`] from its `host:port` text form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOnionAddrError;

impl fmt::Display for ParseOnionAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected an onion address of the form <56 base32 chars>.onion:port")
    }
}

impl std::error::Error for ParseOnionAddrError {}

impl FromStr for OnionAddr {
    type Err = ParseOnionAddrError;

    /// Parse the `host:port` text form (the inverse of [`Display`]): the
    /// split takes the last colon, so the port is whatever follows the final
    /// `:`, and the host must have the v3 onion form. This lets an address
    /// survive a round trip across a text boundary such as capnp `Text`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = s.rsplit_once(':').ok_or(ParseOnionAddrError)?;
        let port: u16 = port.parse().map_err(|_| ParseOnionAddrError)?;
        Self::new(host, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_host() -> String {
        format!("{}.onion", "a".repeat(56))
    }

    #[test]
    fn display_parse_roundtrip() {
        let addr = OnionAddr::new(valid_host(), 9735).unwrap();
        let parsed: OnionAddr = addr.to_string().parse().unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn malformed_input_is_rejected() {
        // No colon at all.
        assert_eq!("noport".parse::<OnionAddr>(), Err(ParseOnionAddrError));
        // Empty host.
        assert_eq!(":9735".parse::<OnionAddr>(), Err(ParseOnionAddrError));
        // Non-numeric port.
        assert_eq!(
            format!("{}:notaport", valid_host()).parse::<OnionAddr>(),
            Err(ParseOnionAddrError)
        );
        // Port out of u16 range.
        assert_eq!(
            format!("{}:70000", valid_host()).parse::<OnionAddr>(),
            Err(ParseOnionAddrError)
        );
    }

    #[test]
    fn hosts_without_the_v3_form_are_rejected() {
        // Too short (a v2-style name).
        assert!(OnionAddr::new("abcdefghij234567.onion", 1).is_err());
        // Right length, wrong suffix.
        assert!(OnionAddr::new(format!("{}.example", "a".repeat(56)), 1).is_err());
        // Right length, characters outside base32 (0, 1, 8, 9, uppercase).
        assert!(OnionAddr::new(format!("{}0.onion", "a".repeat(55)), 1).is_err());
        assert!(OnionAddr::new(format!("{}A.onion", "a".repeat(55)), 1).is_err());
        // The same rejections through the text form.
        assert_eq!(
            "short.onion:9735".parse::<OnionAddr>(),
            Err(ParseOnionAddrError)
        );
    }

    #[test]
    fn the_full_base32_alphabet_is_accepted() {
        let label = "abcdefghijklmnopqrstuvwxyz234567".repeat(2)[..56].to_string();
        let addr = OnionAddr::new(format!("{label}.onion"), 1).unwrap();
        assert_eq!(addr.host(), format!("{label}.onion"));
    }
}
