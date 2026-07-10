//! Inbound packet policy distributed by the Tailscale control plane.
//!
//! WireGuard authenticates a peer's key, but it deliberately does not know
//! Tailscale's ACL/grant policy.  That policy must be checked at the
//! destination *after* decryption and before a plaintext packet reaches the
//! local network stack.

use std::net::Ipv4Addr;

use crate::peer::Ipv4Cidr;

/// One destination address/port range in a control-plane filter rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetPortRange {
    pub ip: Ipv4Cidr,
    pub port_first: u16,
    pub port_last: u16,
}

/// A Tailscale packet-filter allow rule, reduced to the IPv4 data plane this
/// client implements. Empty `ip_protocols` means every IP protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterRule {
    pub src_ips: Vec<Ipv4Cidr>,
    pub dst_ports: Vec<NetPortRange>,
    pub ip_protocols: Vec<u8>,
}

/// The effective inbound policy. It is deliberately deny-by-default: until
/// the first MapResponse supplies an explicit policy, no plaintext traffic is
/// delivered to local services.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundPolicy {
    DenyAll,
    AllowAll,
    Rules(Vec<FilterRule>),
}

impl InboundPolicy {
    pub fn allows(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: u8,
        dst_port: Option<u16>,
    ) -> bool {
        match self {
            Self::DenyAll => false,
            Self::AllowAll => true,
            Self::Rules(rules) => rules
                .iter()
                .any(|rule| rule_matches(rule, src, dst, protocol, dst_port)),
        }
    }
}

fn rule_matches(
    rule: &FilterRule,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    dst_port: Option<u16>,
) -> bool {
    if !rule.src_ips.iter().any(|cidr| cidr.contains(src)) {
        return false;
    }
    if !rule.ip_protocols.is_empty() && !rule.ip_protocols.contains(&protocol) {
        return false;
    }
    rule.dst_ports.iter().any(|range| {
        if !range.ip.contains(dst) {
            return false;
        }
        // Tailscale treats a portless protocol (for example ICMP) as port 0
        // and matches it by range containment, so a rule with a `*` port range
        // (0..=65535, the common allow-all case) admits it. Ranges are sorted
        // (first <= last), so `0 ∈ [first, last]` reduces to `first == 0` — a
        // ports-only rule like 22..=22 still (correctly) denies ICMP.
        match dst_port {
            Some(port) => (range.port_first..=range.port_last).contains(&port),
            None => range.port_first == 0,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(addr: [u8; 4], prefix: u8) -> Ipv4Cidr {
        Ipv4Cidr {
            addr: Ipv4Addr::from(addr),
            prefix,
        }
    }

    fn ssh_rule() -> FilterRule {
        FilterRule {
            src_ips: vec![cidr([100, 64, 0, 2], 32)],
            dst_ports: vec![NetPortRange {
                ip: cidr([100, 64, 0, 1], 32),
                port_first: 22,
                port_last: 22,
            }],
            ip_protocols: vec![6],
        }
    }

    #[test]
    fn rule_allows_exact_tcp_destination() {
        let policy = InboundPolicy::Rules(vec![ssh_rule()]);
        assert!(policy.allows(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            6,
            Some(22),
        ));
    }

    #[test]
    fn rule_rejects_wrong_source_protocol_or_port() {
        let policy = InboundPolicy::Rules(vec![ssh_rule()]);
        let dst = Ipv4Addr::new(100, 64, 0, 1);
        assert!(!policy.allows(Ipv4Addr::new(100, 64, 0, 3), dst, 6, Some(22)));
        assert!(!policy.allows(Ipv4Addr::new(100, 64, 0, 2), dst, 17, Some(22)));
        assert!(!policy.allows(Ipv4Addr::new(100, 64, 0, 2), dst, 6, Some(23)));
    }

    #[test]
    fn icmp_rule_uses_zero_port_range() {
        let policy = InboundPolicy::Rules(vec![FilterRule {
            src_ips: vec![cidr([100, 64, 0, 0], 24)],
            dst_ports: vec![NetPortRange {
                ip: cidr([100, 64, 0, 1], 32),
                port_first: 0,
                port_last: 0,
            }],
            ip_protocols: vec![1],
        }]);
        assert!(policy.allows(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            1,
            None,
        ));
    }

    #[test]
    fn wildcard_port_range_admits_icmp() {
        // A `dst:*` ACL compiles to Ports {First:0, Last:65535}. ICMP arrives
        // as port 0 (dst_port=None) and must be admitted by range containment,
        // not rejected for lack of an exact 0-0 range.
        let policy = InboundPolicy::Rules(vec![FilterRule {
            src_ips: vec![cidr([100, 64, 0, 0], 24)],
            dst_ports: vec![NetPortRange {
                ip: cidr([100, 64, 0, 1], 32),
                port_first: 0,
                port_last: 65535,
            }],
            ip_protocols: vec![], // empty = every protocol (a `*:*` rule)
        }]);
        let src = Ipv4Addr::new(100, 64, 0, 2);
        let dst = Ipv4Addr::new(100, 64, 0, 1);
        assert!(policy.allows(src, dst, 1, None)); // ICMP echo
        assert!(policy.allows(src, dst, 6, Some(8080))); // TCP still fine
    }

    #[test]
    fn ports_only_rule_still_denies_icmp() {
        // A rule scoped to a real port must NOT leak ICMP through.
        let policy = InboundPolicy::Rules(vec![ssh_rule()]); // 22..=22
        assert!(!policy.allows(
            Ipv4Addr::new(100, 64, 0, 2),
            Ipv4Addr::new(100, 64, 0, 1),
            1,
            None,
        ));
    }
}
