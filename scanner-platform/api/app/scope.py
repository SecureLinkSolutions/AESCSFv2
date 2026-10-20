"""Scope validation and the hard blocklist.

This module is the single source of truth for "may this target be scanned".
The API uses it when scope items are added; the worker (M3) calls the same
functions before every tool runs and again on every DNS answer.

Everything here is pure: no database, no network. That keeps it easy to test
for every blocked range.
"""

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Named so the UI and audit log can say *why* something was refused.
# Anything not globally routable is refused even if it isn't listed here
# (see is_blocked), so this list is for explanation, not completeness.
BLOCKED_NETWORKS: dict[str, tuple[str, ...]] = {
    "this network": ("0.0.0.0/8",),
    "RFC1918 private": ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
    "CGNAT / Tailscale": ("100.64.0.0/10",),
    "loopback": ("127.0.0.0/8", "::1/128"),
    "link-local (incl. cloud metadata)": ("169.254.0.0/16", "fe80::/10"),
    "IETF protocol assignments": ("192.0.0.0/24",),
    "documentation": ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"),
    "benchmarking": ("198.18.0.0/15", "2001:2::/48"),
    "multicast": ("224.0.0.0/4", "ff00::/8"),
    "reserved / broadcast": ("240.0.0.0/4", "255.255.255.255/32"),
    "unspecified": ("::/128",),
    "unique local (incl. AWS IPv6 metadata)": ("fc00::/7",),
    "IPv4-mapped / translated": ("::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48"),
    "6to4 / Teredo": ("2002::/16", "2001::/32"),
    "discard-only": ("100::/64",),
}

_BLOCKED: list[tuple[IPNetwork, str]] = [
    (ipaddress.ip_network(cidr), reason)
    for reason, cidrs in BLOCKED_NETWORKS.items()
    for cidr in cidrs
]

# Suffixes that never resolve on the public internet (or must not be trusted to).
BLOCKED_DOMAIN_SUFFIXES = (
    "localhost",
    "local",
    "internal",
    "intranet",
    "lan",
    "home",
    "corp",
    "home.arpa",
    "arpa",
    "test",
    "example",
    "invalid",
    "onion",
    "ts.net",
)

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

SCOPE_TYPES = ("domain", "ip", "cidr")


class ScopeError(ValueError):
    """A value can't be used as a scope item or target."""


@dataclass(frozen=True)
class Blocklist:
    """The fixed blocklist plus any extra networks from config (e.g. our own ranges)."""

    extra: tuple[IPNetwork, ...] = ()

    @classmethod
    def from_config(cls, extra_cidrs: str) -> "Blocklist":
        nets = []
        for raw in filter(None, (part.strip() for part in extra_cidrs.split(","))):
            nets.append(ipaddress.ip_network(raw, strict=False))
        return cls(tuple(nets))

    def reason(self, ip: IPAddress) -> str | None:
        """Why this address is blocked, or None if it may be scanned."""
        if isinstance(ip, ipaddress.IPv6Address):
            # Judge embedded IPv4 by the IPv4 rules too, so ::ffff:10.0.0.1 can't slip past.
            for embedded in (ip.ipv4_mapped, ip.sixtofour, (ip.teredo or (None, None))[1]):
                if embedded is not None and (why := self.reason(embedded)):
                    return f"{why} (embedded in {ip})"
        for net, why in _BLOCKED:
            if ip.version == net.version and ip in net:
                return why
        for net in self.extra:
            if ip.version == net.version and ip in net:
                return "configured blocklist"
        if not ip.is_global:
            return "not globally routable"
        return None

    def is_blocked(self, ip: IPAddress) -> bool:
        return self.reason(ip) is not None

    def network_reason(self, net: IPNetwork) -> str | None:
        """Why a CIDR is unusable: it overlaps any blocked range."""
        for blocked, why in _BLOCKED:
            if net.version == blocked.version and net.overlaps(blocked):
                return why
        for blocked in self.extra:
            if net.version == blocked.version and net.overlaps(blocked):
                return "configured blocklist"
        # Catch non-global space not named above by checking the ends of the range.
        for edge in (net.network_address, net.broadcast_address):
            if why := self.reason(edge):
                return why
        return None


def normalise_domain(value: str) -> str:
    """Lower-case, IDNA-encode and validate a domain name. No wildcards, no IPs."""
    name = value.strip().rstrip(".").lower()
    if not name:
        raise ScopeError("Domain is empty")
    if "*" in name:
        raise ScopeError("Wildcards aren't allowed; a domain item already covers its subdomains")
    if _looks_like_ip(name):
        raise ScopeError("That's an IP address; add it as an IP item instead")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError(f"Invalid domain name: {exc}") from exc
    if len(name) > 253:
        raise ScopeError("Domain name is too long")
    labels = name.split(".")
    if len(labels) < 2:
        raise ScopeError("Use a fully qualified domain name, e.g. example.com.au")
    if not all(_LABEL.match(label) for label in labels):
        raise ScopeError("Domain contains invalid characters")
    if labels[-1].isdigit():
        raise ScopeError("Top-level domain can't be numeric")
    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if name == suffix or name.endswith("." + suffix):
            raise ScopeError(f"Domains under .{suffix} can't be scanned")
    return name


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class Limits:
    min_prefix_v4: int = 24
    min_prefix_v6: int = 112


DEFAULT_LIMITS = Limits()


def normalise_scope_value(
    kind: str, value: str, blocklist: Blocklist, limits: Limits = DEFAULT_LIMITS
) -> str:
    """Validate a new scope item and return its canonical form."""
    value = value.strip()
    if kind == "domain":
        return normalise_domain(value)
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ScopeError("Not a valid IP address") from exc
        if why := blocklist.reason(ip):
            raise ScopeError(f"{ip} is blocked: {why}")
        return str(ip)
    if kind == "cidr":
        try:
            net = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ScopeError(f"Not a valid CIDR (host bits must be zero): {exc}") from exc
        min_prefix = limits.min_prefix_v4 if net.version == 4 else limits.min_prefix_v6
        if net.prefixlen < min_prefix:
            raise ScopeError(f"CIDR is too large; the smallest allowed prefix is /{min_prefix}")
        if why := blocklist.network_reason(net):
            raise ScopeError(f"{net} overlaps a blocked range: {why}")
        return str(net)
    raise ScopeError(f"Unknown scope type {kind!r}")


@dataclass(frozen=True)
class ScopeEntry:
    """A verified, authorised scope item, reduced to what the matcher needs."""

    type: str
    value: str


def scope_overlaps(a: ScopeEntry, b: ScopeEntry) -> bool:
    """True if two scope items cover any of the same targets."""
    if a.type == "domain" and b.type == "domain":
        return _domain_covers(a.value, b.value) or _domain_covers(b.value, a.value)
    if a.type != "domain" and b.type != "domain":
        na, nb = ipaddress.ip_network(a.value), ipaddress.ip_network(b.value)
        return na.version == nb.version and na.overlaps(nb)
    return False


def _domain_covers(parent: str, name: str) -> bool:
    return name == parent or name.endswith("." + parent)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def check_host(name: str, scope: Iterable[ScopeEntry]) -> Decision:
    """May this hostname be scanned? It must be a verified domain or one of its subdomains."""
    try:
        host = normalise_domain(name)
    except ScopeError as exc:
        return Decision(False, str(exc))
    for entry in scope:
        if entry.type == "domain" and _domain_covers(entry.value, host):
            return Decision(True, f"covered by domain {entry.value}")
    return Decision(False, "not under any verified domain")


def check_ip(value: str, scope: Iterable[ScopeEntry], blocklist: Blocklist) -> Decision:
    """May this IP be scanned directly? It must be unblocked and inside a verified IP or CIDR."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return Decision(False, "not a valid IP address")
    if why := blocklist.reason(ip):
        return Decision(False, f"blocked: {why}")
    for entry in scope:
        if entry.type in ("ip", "cidr"):
            net = ipaddress.ip_network(entry.value)
            if ip.version == net.version and ip in net:
                return Decision(True, f"covered by {entry.type} {entry.value}")
    return Decision(False, "not inside any verified IP or CIDR")


def check_resolved(
    host: str, addresses: Iterable[str], scope: Iterable[ScopeEntry], blocklist: Blocklist
) -> dict[str, Decision]:
    """Re-check the blocklist after DNS resolution.

    A hostname under a verified domain may resolve anywhere public (CDNs, shared
    hosting), so its addresses only need to pass the blocklist. But if the
    hostname isn't in scope, none of its addresses are either.
    """
    scope = list(scope)
    host_decision = check_host(host, scope)
    results = {}
    for addr in addresses:
        if not host_decision.allowed:
            results[addr] = Decision(False, f"{host}: {host_decision.reason}")
            continue
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            results[addr] = Decision(False, "not a valid IP address")
            continue
        why = blocklist.reason(ip)
        results[addr] = Decision(False, f"blocked: {why}") if why else host_decision
    return results
