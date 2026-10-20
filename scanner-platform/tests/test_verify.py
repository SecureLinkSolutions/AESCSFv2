"""Domain ownership checks, with DNS and HTTP faked out."""

import dns.resolver
import httpx
import pytest

from app.scope import Blocklist
from app.verify import WELL_KNOWN_PATH, check_dns_txt, check_well_known

TOKEN = "securelink-verify=abc123"
BL = Blocklist()


class FakeRdata:
    def __init__(self, text):
        self.strings = [text.encode()]


class FakeResolver:
    def __init__(self, records=None, error=None):
        self.records, self.error, self.lifetime, self.asked = records or [], error, None, None

    def resolve(self, name, rtype):
        self.asked = (name, rtype)
        if self.error:
            raise self.error
        return [FakeRdata(r) for r in self.records]


def test_dns_txt_match():
    resolver = FakeResolver(["v=spf1 -all", TOKEN])
    result = check_dns_txt("example.com.au", TOKEN, resolver)
    assert result.ok and result.method == "dns_txt"
    assert resolver.asked == ("_securelink-verify.example.com.au", "TXT")


@pytest.mark.parametrize(
    "resolver",
    [
        FakeResolver(["securelink-verify=wrong"]),
        FakeResolver(error=dns.resolver.NXDOMAIN()),
        FakeResolver(error=dns.resolver.NoAnswer()),
        FakeResolver(error=dns.resolver.LifetimeTimeout()),
    ],
)
def test_dns_txt_failures(resolver):
    assert not check_dns_txt("example.com.au", TOKEN, resolver).ok


def well_known(handler, addresses=("93.184.216.34",)):
    seen = []

    def wrapped(request):
        seen.append(request)
        return handler(request)

    result = check_well_known(
        "example.com.au",
        TOKEN,
        BL,
        resolve=lambda _: list(addresses),
        transport=httpx.MockTransport(wrapped),
    )
    return result, seen


def test_well_known_match_connects_to_checked_address():
    result, seen = well_known(lambda r: httpx.Response(200, text=f"{TOKEN}\n"))
    assert result.ok and result.method == "well_known_file"
    request = seen[0]
    assert request.url.host == "93.184.216.34"
    assert request.url.path == WELL_KNOWN_PATH
    assert request.url.scheme == "https"
    assert request.headers["host"] == "example.com.au"
    assert request.extensions["sni_hostname"] == "example.com.au"


@pytest.mark.parametrize(
    "addresses", [("10.0.0.5",), ("93.184.216.34", "169.254.169.254"), ("::1",), ()]
)
def test_well_known_refuses_blocked_resolution_without_connecting(addresses):
    result, seen = well_known(lambda r: httpx.Response(200, text=TOKEN), addresses)
    assert not result.ok
    assert seen == []


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(301, headers={"Location": "http://169.254.169.254/"}),
        httpx.Response(404),
        httpx.Response(200, text="securelink-verify=wrong"),
        httpx.Response(200, text="x" * 5000),
    ],
)
def test_well_known_failures(response):
    result, seen = well_known(lambda r: response)
    assert not result.ok
    assert len(seen) == 1  # redirects are never followed
