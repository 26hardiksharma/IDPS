"""
Snort 3 runner — invokes Snort CLI on a PCAP file and parses its alert output.
Safety: Snort is called with an argument array (no shell interpolation).
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.errors import SnortError
from app.core.logging import get_logger

logger = get_logger(__name__)

# Version string regex: e.g. "Snort++ 3.1.78.0"
_SNORT_VERSION_RE = re.compile(r"Snort\+*\s+([\d.]+)")


def _sync_get_snort_version(snort_bin: str) -> str:
    if not shutil.which(snort_bin):
        return "not_installed"
    try:
        res = subprocess.run(
            [snort_bin, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )
        text = res.stdout.decode(errors="replace")
        m = _SNORT_VERSION_RE.search(text)
        return m.group(1) if m else "unknown"
    except (FileNotFoundError, PermissionError):
        return "not_installed"
    except Exception as exc:
        logger.warning("snort_version_check_failed", error=str(exc))
        return "unknown"


async def get_snort_version(snort_bin: str) -> str:
    """Return the Snort version string or 'not_installed'."""
    return await asyncio.to_thread(_sync_get_snort_version, snort_bin)


def _build_snort_args(
    pcap_path: Path,
    config_path: Path,
    output_dir: Path,
    rules_path: Path | None = None,
) -> list[str]:
    """
    Build the Snort 3 command-line argument list.
    Uses -r (read PCAP), -c (config), --daq-dir, and --lua-script-args
    where appropriate. Alert output goes to output_dir in JSON/CSV mode.
    """
    settings = get_settings()
    args = [
        settings.SNORT_BIN,
        "-c", str(config_path),
        "-r", str(pcap_path),
        "--pcap-no-filter",
        "-l", str(output_dir),  # log directory for alerts
        "-A", "json",           # JSON alert output (Snort 3 supports alert_json)
        "--quiet",
    ]
    if rules_path and rules_path.exists():
        args += ["--rule-path", str(rules_path)]
    return args


async def is_snort_available() -> bool:
    """
    Quick check: is the Snort binary findable and the config present?
    Returns False when Snort is simply not installed (expected on dev laptops).
    """
    settings = get_settings()
    if not shutil.which(settings.SNORT_BIN):
        return False
    version = await get_snort_version(settings.SNORT_BIN)
    return version != "not_installed"


def _sync_run_snort(args: list[str], timeout: int) -> tuple[int, str, str]:
    res = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    return res.returncode, res.stdout.decode(errors="replace"), res.stderr.decode(errors="replace")


async def run_snort(
    pcap_path: Path,
    run_id: str,
    timeout: int | None = None,
) -> list[dict[str, Any]]:
    """
    Execute Snort on *pcap_path* and return a list of normalised alert dicts.
    Raises SnortError on process failure or timeout.
    """
    settings = get_settings()
    timeout = timeout or settings.SNORT_TIMEOUT_SECONDS

    output_dir = settings.SNORT_OUTPUT_DIR / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    # Check binary availability first — clearer error than config-not-found
    snort_available = await is_snort_available()
    if not snort_available:
        raise SnortError(
            "Snort binary not found",
            detail=(
                f"SNORT_BIN='{settings.SNORT_BIN}' is not installed or not in PATH. "
                "Install Snort 3 or set SNORT_BIN to the full path of the binary."
            ),
        )

    config_path = settings.SNORT_CONFIG
    rules_path = settings.SNORT_RULES_DIR / "local.rules"

    if not config_path.exists():
        # Generate a minimal stub config so the pipeline can continue
        logger.warning(
            "snort_config_missing",
            config=str(config_path),
            run_id=run_id,
        )
        raise SnortError(
            f"Snort config not found at {config_path}",
            detail="Ensure SNORT_CONFIG is set correctly in .env",
        )

    args = _build_snort_args(pcap_path, config_path, output_dir, rules_path)

    logger.info("snort_starting", run_id=run_id, args=args)
    try:
        returncode, stdout_text, stderr_text = await asyncio.to_thread(
            _sync_run_snort, args, timeout
        )
    except subprocess.TimeoutExpired:
        raise SnortError(
            "Snort timed out",
            detail=f"Exceeded {timeout}s timeout for run {run_id}",
        )
    except (FileNotFoundError, OSError) as exc:
        raise SnortError(
            "Snort binary could not be executed",
            detail=f"SNORT_BIN={settings.SNORT_BIN}: {exc}",
        )

    if returncode not in (0, 1):  # Snort returns 1 when alerts fired
        raise SnortError(
            f"Snort exited with code {returncode}",
            detail=stderr_text[:2000],
        )

    logger.info(
        "snort_finished",
        run_id=run_id,
        return_code=returncode,
        output_dir=str(output_dir),
    )

    return _parse_snort_output(output_dir, stdout_text)


def _parse_snort_output(output_dir: Path, stdout_text: str) -> list[dict[str, Any]]:
    """
    Parse Snort alert_json output files from output_dir.
    Falls back to line-based stdout parsing if no JSON files are found.
    """
    alerts: list[dict[str, Any]] = []

    # Snort 3 with alert_json creates alert_json.txt or similar files
    for json_file in sorted(output_dir.glob("alert_json*")):
        try:
            content = json_file.read_text(errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    alerts.append(obj)
                except json.JSONDecodeError:
                    pass
        except OSError:
            pass

    # If Snort wrote to stdout (some modes)
    if not alerts and stdout_text:
        for line in stdout_text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    return alerts
