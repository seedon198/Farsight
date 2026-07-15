"""masscan integration for FARSIGHT's port scanning.

Wraps the external `masscan` binary for fast bulk port discovery across
many hosts at once. masscan requires raw-socket privileges (root, or
CAP_NET_RAW on Linux) and is not always installed -- callers should
check `MasscanScanner.is_available()` and be ready to fall back to
`farsight.utils.dns.PortScanner` when it isn't usable.
"""

import asyncio
import functools
import json
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

MASSCAN_BINARY = "masscan"


class MasscanPermissionError(RuntimeError):
    """Raised when masscan can't run because it lacks raw-socket privileges."""


@functools.lru_cache(maxsize=1)
def _find_masscan_binary() -> Optional[str]:
    return shutil.which(MASSCAN_BINARY)


def _looks_like_permission_error(stderr_text: str) -> bool:
    lowered = stderr_text.lower()
    return any(
        phrase in lowered
        for phrase in (
            "permission denied",
            "must be root",
            "raw socket",
            "are you root",
        )
    )


def _parse_masscan_output(output_path: Path) -> Dict[str, List[int]]:
    content = output_path.read_text(encoding="utf-8", errors="ignore").strip()
    if not content:
        return {}

    try:
        records = json.loads(content)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"could not parse masscan output: {e}") from e

    results: Dict[str, List[int]] = {}
    for record in records:
        ip = record.get("ip")
        if not ip:
            continue
        for port_entry in record.get("ports", []):
            if port_entry.get("status") == "open":
                results.setdefault(ip, []).append(port_entry["port"])

    return results


class MasscanScanner:
    """Wraps the external `masscan` binary for fast bulk port discovery."""

    @staticmethod
    def is_available() -> bool:
        return _find_masscan_binary() is not None

    async def scan(
        self, targets: List[str], ports: List[int], rate: int
    ) -> Dict[str, List[int]]:
        """
        Run masscan against `targets` for `ports` at `rate` packets/sec.

        Returns:
            Mapping of IP -> list of open ports found on it. IPs with no
            open ports are simply absent from the result.

        Raises:
            MasscanPermissionError: masscan lacks raw-socket privileges.
            RuntimeError: masscan failed for any other reason, or its
                output couldn't be parsed.
        """
        with tempfile.NamedTemporaryFile(
            prefix="farsight_masscan_", suffix=".json", delete=False
        ) as tmp:
            output_path = Path(tmp.name)

        try:
            port_arg = ",".join(str(p) for p in ports)
            cmd = [
                _find_masscan_binary() or MASSCAN_BINARY,
                *targets,
                "-p",
                port_arg,
                "--rate",
                str(rate),
                "-oJ",
                str(output_path),
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()

            if proc.returncode != 0:
                stderr_text = stderr.decode("utf-8", errors="ignore")
                if _looks_like_permission_error(stderr_text):
                    raise MasscanPermissionError(
                        f"masscan requires elevated privileges: {stderr_text.strip()}"
                    )
                raise RuntimeError(
                    f"masscan exited with code {proc.returncode}: {stderr_text.strip()}"
                )

            return _parse_masscan_output(output_path)
        finally:
            output_path.unlink(missing_ok=True)
