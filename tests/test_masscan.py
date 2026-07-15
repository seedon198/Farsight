"""Tests for farsight.utils.masscan.

Covers MasscanScanner.scan()'s JSON-output parsing, permission-error
detection, and is_available() presence/absence detection via a mocked
`masscan` subprocess -- no real masscan binary or raw sockets involved.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from farsight.utils.masscan import (
    MasscanPermissionError,
    MasscanScanner,
    _find_masscan_binary,
)


def _mock_proc(returncode=0, stderr=b""):
    proc = MagicMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(b"", stderr))
    return proc


@pytest.mark.asyncio
async def test_scan_parses_open_ports_from_masscan_json_output():
    scanner = MasscanScanner()

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        output_path = cmd[cmd.index("-oJ") + 1]
        payload = [
            {"ip": "1.2.3.4", "ports": [{"port": 80, "status": "open"}]},
            {"ip": "1.2.3.4", "ports": [{"port": 443, "status": "open"}]},
            {"ip": "5.6.7.8", "ports": [{"port": 22, "status": "open"}]},
        ]
        with open(output_path, "w") as f:
            json.dump(payload, f)
        return _mock_proc(returncode=0)

    with patch(
        "farsight.utils.masscan.asyncio.create_subprocess_exec",
        side_effect=fake_create_subprocess_exec,
    ):
        result = await scanner.scan(["1.2.3.4", "5.6.7.8"], [22, 80, 443], rate=10000)

    assert result == {"1.2.3.4": [80, 443], "5.6.7.8": [22]}


@pytest.mark.asyncio
async def test_scan_returns_empty_dict_when_no_open_ports_found():
    scanner = MasscanScanner()

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        output_path = cmd[cmd.index("-oJ") + 1]
        with open(output_path, "w") as f:
            json.dump([], f)
        return _mock_proc(returncode=0)

    with patch(
        "farsight.utils.masscan.asyncio.create_subprocess_exec",
        side_effect=fake_create_subprocess_exec,
    ):
        result = await scanner.scan(["1.2.3.4"], [80], rate=10000)

    assert result == {}


@pytest.mark.asyncio
async def test_scan_raises_permission_error_when_masscan_lacks_privileges():
    scanner = MasscanScanner()

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        return _mock_proc(
            returncode=1,
            stderr=b"FAIL: permission denied\n[hint] need to sudo or run as root",
        )

    with patch(
        "farsight.utils.masscan.asyncio.create_subprocess_exec",
        side_effect=fake_create_subprocess_exec,
    ):
        with pytest.raises(MasscanPermissionError):
            await scanner.scan(["1.2.3.4"], [80], rate=10000)


@pytest.mark.asyncio
async def test_scan_raises_runtime_error_on_other_failure():
    scanner = MasscanScanner()

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        return _mock_proc(returncode=1, stderr=b"unknown interface eth9")

    with patch(
        "farsight.utils.masscan.asyncio.create_subprocess_exec",
        side_effect=fake_create_subprocess_exec,
    ):
        with pytest.raises(RuntimeError):
            await scanner.scan(["1.2.3.4"], [80], rate=10000)


@pytest.mark.asyncio
async def test_scan_returns_empty_dict_when_output_file_is_empty():
    """Test that zero-byte output file (not JSON array) returns empty dict."""
    scanner = MasscanScanner()

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        output_path = cmd[cmd.index("-oJ") + 1]
        # Write empty file (zero bytes) to exercise the `if not content: return {}` branch
        with open(output_path, "w") as f:
            pass  # Write nothing
        return _mock_proc(returncode=0)

    with patch(
        "farsight.utils.masscan.asyncio.create_subprocess_exec",
        side_effect=fake_create_subprocess_exec,
    ):
        result = await scanner.scan(["1.2.3.4"], [80], rate=10000)

    assert result == {}


@pytest.mark.asyncio
async def test_scan_raises_runtime_error_on_malformed_json():
    """Test that malformed JSON in output file raises RuntimeError."""
    scanner = MasscanScanner()

    async def fake_create_subprocess_exec(*cmd, **kwargs):
        output_path = cmd[cmd.index("-oJ") + 1]
        # Write genuinely malformed JSON to exercise the JSONDecodeError branch
        with open(output_path, "w") as f:
            f.write("not valid json {{{")
        return _mock_proc(returncode=0)

    with patch(
        "farsight.utils.masscan.asyncio.create_subprocess_exec",
        side_effect=fake_create_subprocess_exec,
    ):
        with pytest.raises(RuntimeError):
            await scanner.scan(["1.2.3.4"], [80], rate=10000)


def test_is_available_true_when_binary_on_path():
    _find_masscan_binary.cache_clear()
    with patch("farsight.utils.masscan.shutil.which", return_value="/usr/bin/masscan"):
        assert MasscanScanner.is_available() is True
    _find_masscan_binary.cache_clear()


def test_is_available_false_when_binary_missing():
    _find_masscan_binary.cache_clear()
    with patch("farsight.utils.masscan.shutil.which", return_value=None):
        assert MasscanScanner.is_available() is False
    _find_masscan_binary.cache_clear()
