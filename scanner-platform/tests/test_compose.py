"""Guards the "no public ports" rule: only Caddy publishes a port, and only on the Tailscale IP."""

from pathlib import Path

import yaml

COMPOSE = yaml.safe_load((Path(__file__).resolve().parents[1] / "compose.yaml").read_text())
SERVICES = COMPOSE["services"]


def test_only_caddy_publishes_ports():
    published = {name for name, svc in SERVICES.items() if svc.get("ports")}
    assert published == {"caddy"}


def test_caddy_binds_tailscale_ip_only():
    for port in SERVICES["caddy"]["ports"]:
        assert isinstance(port, str)
        assert port.startswith("${TAILSCALE_IP:?"), port
        assert port.endswith(":443:443")


def test_internal_networks_have_no_egress():
    nets = COMPOSE["networks"]
    assert nets["frontend"]["internal"] is True
    assert nets["backend"]["internal"] is True


def test_data_stores_only_on_backend():
    for name in ("postgres", "valkey"):
        assert SERVICES[name]["networks"] == ["backend"]
        assert "ports" not in SERVICES[name]
        assert "expose" not in SERVICES[name]


def test_no_privileged_containers():
    for name, svc in SERVICES.items():
        assert not svc.get("privileged"), name
        assert svc.get("network_mode") != "host", name
