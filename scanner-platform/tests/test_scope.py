"""The hard blocklist and scope matching. Every blocked range has a test."""

import pytest

from app.scope import (
    BLOCKED_NETWORKS,
    Blocklist,
    Limits,
    ScopeEntry,
    ScopeError,
    check_host,
    check_ip,
    check_resolved,
    normalise_domain,
    normalise_scope_value,
    scope_overlaps,
)

BL = Blocklist()

# At least one address inside every named range, plus the edges that matter.
BLOCKED = [
    "0.0.0.0",
    "0.255.255.255",
    "10.0.0.0",
    "10.1.2.3",
    "10.255.255.255",
    "172.16.0.0",
    "172.20.1.1",
    "172.31.255.255",
    "192.168.0.1",
    "192.168.255.255",
    "100.64.0.0",
    "100.100.100.100",
    "100.127.255.255",
    "127.0.0.1",
    "127.255.255.254",
    "::1",
    "169.254.0.1",
    "169.254.169.254",
    "169.254.170.2",
    "fe80::1",
    "192.0.0.1",
    "192.0.0.170",
    "192.0.2.1",
    "198.51.100.7",
    "203.0.113.200",
    "2001:db8::1",
    "198.18.0.1",
    "198.19.255.255",
    "2001:2::1",
    "224.0.0.1",
    "239.255.255.250",
    "ff02::1",
    "240.0.0.1",
    "255.255.255.255",
    "::",
    "fc00::1",
    "fd00:ec2::254",
    "fd7a:115c:a1e0::1",
    "::ffff:10.0.0.1",
    "::ffff:169.254.169.254",
    "::ffff:127.0.0.1",
    "64:ff9b::a00:1",
    "64:ff9b:1::1",
    "2002:a00:1::",
    "2002:808:808::",
    "2001::1",
    "100::1",
]

ALLOWED = [
    "8.8.8.8",
    "1.1.1.1",
    "203.2.218.214",
    "172.15.255.255",
    "172.32.0.0",  # either side of 172.16.0.0/12
    "100.63.255.255",
    "100.128.0.0",  # either side of CGNAT
    "192.167.255.255",
    "192.169.0.0",  # either side of 192.168.0.0/16
    "169.253.255.255",
    "169.255.0.0",  # either side of link-local
    "2606:4700:4700::1111",
    "2404:6800:4006:80a::200e",
]


@pytest.mark.parametrize("addr", BLOCKED)
def test_blocked_addresses(addr):
    import ipaddress

    assert BL.is_blocked(ipaddress.ip_address(addr)), addr
    with pytest.raises(ScopeError):
        normalise_scope_value("ip", addr, BL)


@pytest.mark.parametrize("addr", ALLOWED)
def test_public_addresses_allowed(addr):
    assert normalise_scope_value("ip", addr, BL)


def test_every_named_range_is_covered_by_a_test():
    import ipaddress

    for reason, cidrs in BLOCKED_NETWORKS.items():
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr)
            assert any(
                ipaddress.ip_address(a).version == net.version and ipaddress.ip_address(a) in net
                for a in BLOCKED
            ), f"no test address in {cidr} ({reason})"


def test_metadata_reason_is_named():
    import ipaddress

    assert "metadata" in BL.reason(ipaddress.ip_address("169.254.169.254"))


def test_extra_blocklist():
    import ipaddress

    bl = Blocklist.from_config("45.79.0.0/16, 2600:3c00::/32")
    assert bl.reason(ipaddress.ip_address("45.79.1.1")) == "configured blocklist"
    assert bl.is_blocked(ipaddress.ip_address("2600:3c00::5"))
    assert not bl.is_blocked(ipaddress.ip_address("8.8.8.8"))
    assert check_ip("45.79.1.1", [ScopeEntry("cidr", "45.79.1.0/24")], bl).allowed is False


@pytest.mark.parametrize(
    "cidr",
    [
        "10.0.0.0/24",
        "100.64.0.0/24",
        "169.254.169.0/24",
        "192.168.1.0/28",
        "127.0.0.0/30",
        "224.0.0.0/24",
        "fd00::/112",
        "fe80::/112",
        "::ffff:0:0/112",
    ],
)
def test_blocked_cidrs(cidr):
    with pytest.raises(ScopeError):
        normalise_scope_value("cidr", cidr, BL)


def test_cidr_rules():
    assert normalise_scope_value("cidr", "8.8.8.0/24", BL) == "8.8.8.0/24"
    with pytest.raises(ScopeError, match="too large"):
        normalise_scope_value("cidr", "8.8.0.0/16", BL)
    with pytest.raises(ScopeError, match="host bits"):
        normalise_scope_value("cidr", "8.8.8.1/24", BL)
    assert normalise_scope_value("cidr", "8.8.0.0/16", BL, Limits(min_prefix_v4=16))
    # A range that only touches a blocked range at its edge is still refused.
    with pytest.raises(ScopeError):
        normalise_scope_value("cidr", "100.64.0.0/25", BL, Limits(min_prefix_v4=8))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM.au.", "example.com.au"),
        ("  shop.example.com ", "shop.example.com"),
        ("bücher.com.au", "xn--bcher-kva.com.au"),
    ],
)
def test_domain_normalisation(raw, expected):
    assert normalise_domain(raw) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "*.example.com",
        "localhost",
        "intranet",
        "printer.local",
        "db.internal",
        "nas.home.arpa",
        "box.lan",
        "host.tailnet-abc.ts.net",
        "a.test",
        "x.invalid",
        "something.onion",
        "10.0.0.1",
        "::1",
        "exa mple.com",
        "-bad.com",
        "bad-.com",
        "example.123",
        "",
        "a" * 64 + ".com",
    ],
)
def test_bad_domains(bad):
    with pytest.raises(ScopeError):
        normalise_domain(bad)


SCOPE = [
    ScopeEntry("domain", "example.com.au"),
    ScopeEntry("ip", "8.8.8.8"),
    ScopeEntry("cidr", "1.1.1.0/28"),
]


@pytest.mark.parametrize(
    ("host", "allowed"),
    [
        ("example.com.au", True),
        ("www.example.com.au", True),
        ("a.b.example.com.au", True),
        ("WWW.Example.com.au.", True),
        ("notexample.com.au", False),  # suffix match must respect the dot
        ("example.com.au.evil.com", False),
        ("com.au", False),
        ("other.com", False),
    ],
)
def test_check_host(host, allowed):
    assert check_host(host, SCOPE).allowed is allowed


@pytest.mark.parametrize(
    ("addr", "allowed"),
    [
        ("8.8.8.8", True),
        ("8.8.8.9", False),
        ("1.1.1.5", True),
        ("1.1.1.16", False),
        ("10.0.0.1", False),
        ("not-an-ip", False),
    ],
)
def test_check_ip(addr, allowed):
    assert check_ip(addr, SCOPE, BL).allowed is allowed


def test_check_resolved_reapplies_blocklist():
    results = check_resolved(
        "app.example.com.au", ["93.184.216.34", "10.0.0.5", "169.254.169.254", "::1"], SCOPE, BL
    )
    assert results["93.184.216.34"].allowed
    assert not results["10.0.0.5"].allowed
    assert not results["169.254.169.254"].allowed
    assert not results["::1"].allowed


def test_check_resolved_out_of_scope_host_refuses_everything():
    results = check_resolved("evil.com", ["93.184.216.34"], SCOPE, BL)
    assert not results["93.184.216.34"].allowed


def test_scope_overlaps():
    d = ScopeEntry("domain", "example.com")
    assert scope_overlaps(d, ScopeEntry("domain", "www.example.com"))
    assert scope_overlaps(ScopeEntry("domain", "www.example.com"), d)
    assert not scope_overlaps(d, ScopeEntry("domain", "notexample.com"))
    assert scope_overlaps(ScopeEntry("ip", "8.8.8.8"), ScopeEntry("cidr", "8.8.8.0/24"))
    assert not scope_overlaps(ScopeEntry("ip", "8.8.8.8"), ScopeEntry("cidr", "8.8.4.0/24"))
    assert not scope_overlaps(ScopeEntry("ip", "8.8.8.8"), ScopeEntry("ip", "2001:4860::8888"))
    assert not scope_overlaps(d, ScopeEntry("ip", "8.8.8.8"))
