"""Tests for farsight.modules.recon port-scan orchestration.

Covers Recon._port_scan_targets: masscan bulk-discovery + banner-grab
path, fallback to the built-in asyncio scanner when masscan is
unavailable or unprivileged, and IP dedup when multiple domains share
one resolved IP.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from farsight.modules.recon import Recon
from farsight.utils.masscan import MasscanPermissionError


def make_recon():
    recon = Recon(api_manager=MagicMock())
    recon.masscan_scanner = MagicMock()
    recon.port_scanner = MagicMock()
    return recon


@pytest.mark.asyncio
async def test_port_scan_targets_masscan_success_grabs_banners_for_open_ports_only():
    recon = make_recon()
    recon.masscan_scanner.is_available.return_value = True
    recon.masscan_scanner.scan = AsyncMock(return_value={"1.2.3.4": [80, 443]})

    async def fake_scan_port(target, port):
        return {"port": port, "open": True, "banner": f"banner-{port}"}

    recon.port_scanner.scan_port = AsyncMock(side_effect=fake_scan_port)

    domains = ["example.com"]
    ips = {"example.com": ["1.2.3.4"]}

    result = await recon._port_scan_targets(domains, ips, [80, 443, 22], rate=10000)

    assert recon.port_scanner.scan_port.await_count == 2
    called_ports = {c.args[1] for c in recon.port_scanner.scan_port.await_args_list}
    assert called_ports == {80, 443}

    assert result["example.com"]["open_ports"] == 2
    assert result["example.com"]["total_ports"] == 3
    banners = {p["port"]: p["banner"] for p in result["example.com"]["ports"]}
    assert banners == {80: "banner-80", 443: "banner-443"}


@pytest.mark.asyncio
async def test_port_scan_targets_falls_back_when_masscan_unavailable():
    recon = make_recon()
    recon.masscan_scanner.is_available.return_value = False

    recon.port_scanner.scan_ports = AsyncMock(
        return_value={
            "target": "1.2.3.4",
            "timestamp": 0,
            "total_ports": 2,
            "open_ports": 1,
            "ports": [{"port": 80, "open": True, "banner": None}],
        }
    )

    domains = ["example.com"]
    ips = {"example.com": ["1.2.3.4"]}

    result = await recon._port_scan_targets(domains, ips, [80, 443], rate=10000)

    recon.masscan_scanner.scan.assert_not_called()
    recon.port_scanner.scan_ports.assert_awaited_once_with("1.2.3.4", [80, 443])
    assert result["example.com"]["open_ports"] == 1


@pytest.mark.asyncio
async def test_port_scan_targets_falls_back_on_masscan_permission_error():
    recon = make_recon()
    recon.masscan_scanner.is_available.return_value = True
    recon.masscan_scanner.scan = AsyncMock(
        side_effect=MasscanPermissionError("masscan requires elevated privileges")
    )
    recon.port_scanner.scan_ports = AsyncMock(
        return_value={
            "target": "1.2.3.4",
            "timestamp": 0,
            "total_ports": 1,
            "open_ports": 0,
            "ports": [],
        }
    )

    domains = ["example.com"]
    ips = {"example.com": ["1.2.3.4"]}

    result = await recon._port_scan_targets(domains, ips, [80], rate=10000)

    recon.port_scanner.scan_ports.assert_awaited_once_with("1.2.3.4", [80])
    assert result["example.com"]["open_ports"] == 0


@pytest.mark.asyncio
async def test_port_scan_targets_dedupes_shared_ip_across_domains():
    recon = make_recon()
    recon.masscan_scanner.is_available.return_value = True
    recon.masscan_scanner.scan = AsyncMock(return_value={"1.2.3.4": [80]})
    recon.port_scanner.scan_port = AsyncMock(
        return_value={"port": 80, "open": True, "banner": None}
    )

    domains = ["a.example.com", "b.example.com"]
    ips = {
        "a.example.com": ["1.2.3.4"],
        "b.example.com": ["1.2.3.4"],
    }

    result = await recon._port_scan_targets(domains, ips, [80], rate=10000)

    recon.masscan_scanner.scan.assert_awaited_once_with(["1.2.3.4"], [80], 10000)
    assert result["a.example.com"] is result["b.example.com"]
    assert result["a.example.com"]["open_ports"] == 1
