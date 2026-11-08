//! Which way a service may reach PostgreSQL.

use crate::error::{Error, Result};
use std::net::IpAddr;
use tokio_postgres::config::Host;

/// The route a session uses. Anything else is `Error::Configuration`.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// PostgreSQL's own Unix socket, without TLS.
    Unix,
    /// Loopback TCP in clear text (only if the policy allows it).
    Loopback,
    /// Loopback TCP with verified TLS.
    LoopbackTls,
    /// Any other destination with verified TLS.
    Tls,
    /// RFC1918/ULA address in clear text (only if the policy allows it).
    PlaintextPrivate,
}

impl Transport {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unix => "unix",
            Self::Loopback => "loopback",
            Self::LoopbackTls => "loopback-tls",
            Self::Tls => "tls",
            Self::PlaintextPrivate => "plaintext-private",
        }
    }

    pub fn tls(self) -> bool {
        matches!(self, Self::LoopbackTls | Self::Tls)
    }
}

/// What a consumer accepts besides Unix sockets and verified TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Clear text to 127.0.0.0/8 or ::1.
    pub loopback_plaintext: bool,
    /// Clear text to RFC1918/ULA addresses, for a network protected otherwise.
    pub private_plaintext: bool,
    /// The UID that must own the Unix socket and be its peer.
    pub unix_peer_uid: Option<u32>,
    /// A Unix socket in a directory others can write to (like `/tmp`) without a pinned
    /// `unix_peer_uid`. Anyone there could plant a socket and pose as the server: only a
    /// consumer that accepts that risk explicitly sets this.
    pub shared_socket_dir: bool,
    /// `hostaddr` beside a TCP host (judged by its address). When false, any
    /// `hostaddr` is refused.
    pub hostaddr: bool,
    /// `user` and `dbname` must be named. When false, libpq's defaults apply (the
    /// process user, and a database named like the user).
    pub explicit_names: bool,
}

impl Policy {
    /// Unix socket or verified TLS only, even on loopback.
    pub const STRICT: Self = Self {
        loopback_plaintext: false,
        private_plaintext: false,
        unix_peer_uid: None,
        shared_socket_dir: false,
        hostaddr: true,
        explicit_names: true,
    };
}

fn normalized(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Decides the route for `config`, with `tls` meaning a CA file is configured.
/// One host; `hostaddr` only beside a host (the host stays the TLS identity, the
/// hostaddr is the destination that is judged); a Unix socket never with TLS.
pub fn classify(config: &tokio_postgres::Config, tls: bool, policy: &Policy) -> Result<Transport> {
    let unnamed = config.get_user().is_none() || config.get_dbname().is_none();
    if (policy.explicit_names && unnamed) || config.get_ports().len() > 1 {
        return Err(Error::Configuration);
    }
    let [host] = config.get_hosts() else {
        return Err(Error::Configuration);
    };
    let hostaddr = match config.get_hostaddrs() {
        [] => None,
        [one] if policy.hostaddr => Some(normalized(*one)),
        _ => return Err(Error::Configuration),
    };
    let name = match host {
        Host::Unix(path) => {
            return if tls || hostaddr.is_some() || !path.is_absolute() {
                Err(Error::Configuration)
            } else {
                Ok(Transport::Unix)
            };
        }
        Host::Tcp(name) => name,
    };
    let address = match hostaddr {
        Some(ip) => Some(ip),
        None => name.parse::<IpAddr>().ok().map(normalized),
    };
    let Some(address) = address else {
        // A DNS name: only with TLS, which verifies it.
        return if tls {
            Ok(Transport::Tls)
        } else {
            Err(Error::Configuration)
        };
    };
    if address.is_unspecified() || address.is_multicast() {
        return Err(Error::Configuration);
    }
    let (loopback, private) = match address {
        IpAddr::V4(ip) => (ip.is_loopback(), ip.is_private()),
        IpAddr::V6(ip) => (ip.is_loopback(), ip.is_unique_local()),
    };
    match (tls, loopback, private) {
        (true, true, _) => Ok(Transport::LoopbackTls),
        (true, false, _) => Ok(Transport::Tls),
        (false, true, _) if policy.loopback_plaintext => Ok(Transport::Loopback),
        (false, false, true) if policy.private_plaintext => Ok(Transport::PlaintextPrivate),
        _ => Err(Error::Configuration),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(dsn: &str, tls: bool, policy: &Policy) -> Option<Transport> {
        let config: tokio_postgres::Config = dsn.parse().ok()?;
        classify(&config, tls, policy).ok()
    }

    const PERMISSIVE: Policy = Policy {
        loopback_plaintext: true,
        private_plaintext: true,
        unix_peer_uid: None,
        shared_socket_dir: false,
        hostaddr: true,
        explicit_names: true,
    };

    #[test]
    fn a_policy_can_refuse_every_hostaddr() {
        let no_hostaddr = Policy {
            hostaddr: false,
            ..PERMISSIVE
        };
        for (dsn, tls) in [
            ("host=db.example hostaddr=10.0.0.5 user=u dbname=d", true),
            ("host=127.0.0.1 hostaddr=127.0.0.1 user=u dbname=d", false),
            ("host=10.0.0.5 hostaddr=10.0.0.5 user=u dbname=d", false),
        ] {
            assert_eq!(check(dsn, tls, &no_hostaddr), None, "{dsn}");
            assert!(
                check(dsn, tls, &PERMISSIVE).is_some(),
                "{dsn} with hostaddr allowed"
            );
        }
        assert_eq!(
            check("host=127.0.0.1 user=u dbname=d", false, &no_hostaddr),
            Some(Transport::Loopback)
        );
    }

    #[test]
    fn a_policy_can_accept_libpq_default_names() {
        let defaults = Policy {
            explicit_names: false,
            ..PERMISSIVE
        };
        for dsn in [
            "host=127.0.0.1",
            "host=127.0.0.1 user=u",
            "host=127.0.0.1 dbname=d",
        ] {
            assert_eq!(
                check(dsn, false, &defaults),
                Some(Transport::Loopback),
                "{dsn}"
            );
            assert_eq!(
                check(dsn, false, &PERMISSIVE),
                None,
                "{dsn} with explicit names"
            );
        }
        assert_eq!(
            check("host=127.0.0.1 port=5432,5433", false, &defaults),
            None,
            "one port at most, whatever the names"
        );
    }

    #[test]
    fn strict_policy_table() {
        use Transport::*;
        let strict = Policy::STRICT;
        let cases: [(&str, bool, Option<Transport>); 14] = [
            (
                "host=/var/run/postgresql user=u dbname=d",
                false,
                Some(Unix),
            ),
            ("host=/var/run/postgresql user=u dbname=d", true, None),
            ("host=relative user=u dbname=d", false, None),
            ("host=127.0.0.1 user=u dbname=d", false, None),
            ("host=127.0.0.1 user=u dbname=d", true, Some(LoopbackTls)),
            ("host=10.0.0.5 user=u dbname=d", false, None),
            ("host=10.0.0.5 user=u dbname=d", true, Some(Tls)),
            ("host=db.example user=u dbname=d", true, Some(Tls)),
            ("host=db.example user=u dbname=d", false, None),
            ("hostaddr=10.0.0.5 user=u dbname=d", true, None),
            (
                "host=db.example hostaddr=10.0.0.5 user=u dbname=d",
                true,
                Some(Tls),
            ),
            ("host=0.0.0.0 user=u dbname=d", true, None),
            ("host=224.0.0.1 user=u dbname=d", true, None),
            ("host=127.0.0.1,127.0.0.2 user=u dbname=d", true, None),
        ];
        for (dsn, tls, expected) in cases {
            assert_eq!(check(dsn, tls, &strict), expected, "{dsn} tls={tls}");
        }
    }

    #[test]
    fn a_permissive_policy_allows_explicit_plaintext() {
        use Transport::*;
        let cases: [(&str, bool, Option<Transport>); 7] = [
            ("host=127.0.0.1 user=u dbname=d", false, Some(Loopback)),
            (
                "host=::ffff:127.0.0.1 user=u dbname=d",
                false,
                Some(Loopback),
            ),
            (
                "host=10.89.8.2 user=u dbname=d",
                false,
                Some(PlaintextPrivate),
            ),
            (
                "host=::ffff:10.0.0.5 user=u dbname=d",
                false,
                Some(PlaintextPrivate),
            ),
            ("host=8.8.8.8 user=u dbname=d", false, None),
            (
                "host=localhost hostaddr=8.8.8.8 user=u dbname=d",
                false,
                None,
            ),
            (
                "host=localhost hostaddr=127.0.0.1 user=u dbname=d",
                false,
                Some(Loopback),
            ),
        ];
        for (dsn, tls, expected) in cases {
            assert_eq!(check(dsn, tls, &PERMISSIVE), expected, "{dsn} tls={tls}");
        }
    }

    #[test]
    fn user_and_database_are_required() {
        assert_eq!(check("host=/tmp dbname=d", false, &Policy::STRICT), None);
        assert_eq!(check("host=/tmp user=u", false, &Policy::STRICT), None);
    }
}
