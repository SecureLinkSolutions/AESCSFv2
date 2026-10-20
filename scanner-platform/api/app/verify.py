"""Domain ownership verification: a DNS TXT record or a /.well-known file.

Runs in the verifier service, which has outbound access; the api container has none.

DNS TXT: _securelink-verify.<domain>  TXT  "securelink-verify=<token>"
File:    https://<domain>/.well-known/securelink-verify.txt  containing the same line

The file check resolves the domain itself, refuses blocked addresses, then connects
to the checked address (with SNI and Host set to the domain), so a DNS answer that
changes between the check and the connection can't redirect it. Redirects aren't
followed.
"""

import ipaddress
import socket
from dataclasses import dataclass

import dns.exception
import dns.resolver
import httpx

from app.scope import Blocklist

WELL_KNOWN_PATH = "/.well-known/securelink-verify.txt"
MAX_FILE_BYTES = 1024
TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    method: str | None
    detail: str


def check_dns_txt(domain: str, expected: str, resolver: dns.resolver.Resolver | None = None):
    resolver = resolver or dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT_SECONDS
    name = f"_securelink-verify.{domain}"
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return VerifyResult(False, None, f"no TXT record at {name}")
    except dns.exception.DNSException as exc:
        return VerifyResult(False, None, f"DNS lookup for {name} failed: {exc.__class__.__name__}")
    for rdata in answer:
        text = b"".join(rdata.strings).decode("utf-8", "replace").strip()
        if text == expected:
            return VerifyResult(True, "dns_txt", f"TXT record found at {name}")
    return VerifyResult(False, None, f"TXT record at {name} doesn't match the token")


def _resolve(domain: str) -> list[str]:
    infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def check_well_known(
    domain: str,
    expected: str,
    blocklist: Blocklist,
    resolve=_resolve,
    transport: httpx.BaseTransport | None = None,
) -> VerifyResult:
    try:
        addresses = resolve(domain)
    except OSError as exc:
        return VerifyResult(False, None, f"could not resolve {domain}: {exc}")
    if not addresses:
        return VerifyResult(False, None, f"{domain} has no addresses")
    for addr in addresses:
        if why := blocklist.reason(ipaddress.ip_address(addr)):
            return VerifyResult(False, None, f"{domain} resolves to blocked {addr}: {why}")

    addr = addresses[0]
    host = f"[{addr}]" if ":" in addr else addr
    url = f"https://{host}{WELL_KNOWN_PATH}"
    try:
        # trust_env=False: never route through a proxy, which would undo the address pinning.
        with httpx.Client(
            transport=transport, timeout=TIMEOUT_SECONDS, follow_redirects=False, trust_env=False
        ) as client:
            with client.stream(
                "GET",
                url,
                headers={"Host": domain, "User-Agent": "SecureLink-Verifier/1.0"},
                extensions={"sni_hostname": domain},
            ) as resp:
                if resp.status_code != 200:
                    return VerifyResult(
                        False, None, f"{WELL_KNOWN_PATH} returned HTTP {resp.status_code}"
                    )
                body = b""
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) > MAX_FILE_BYTES:
                        return VerifyResult(False, None, f"{WELL_KNOWN_PATH} is too large")
    except httpx.HTTPError as exc:
        return VerifyResult(False, None, f"fetching {WELL_KNOWN_PATH} failed: {exc}")

    lines = {line.strip() for line in body.decode("utf-8", "replace").splitlines()}
    if expected in lines:
        return VerifyResult(
            True, "well_known_file", f"token found at https://{domain}{WELL_KNOWN_PATH}"
        )
    return VerifyResult(False, None, f"{WELL_KNOWN_PATH} doesn't contain the token")


def verify_domain(domain: str, expected: str, blocklist: Blocklist) -> VerifyResult:
    """Try DNS TXT first, then the well-known file. Report both failures if neither works."""
    dns_result = check_dns_txt(domain, expected)
    if dns_result.ok:
        return dns_result
    file_result = check_well_known(domain, expected, blocklist)
    if file_result.ok:
        return file_result
    return VerifyResult(False, None, f"{dns_result.detail}; {file_result.detail}")
