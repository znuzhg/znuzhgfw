from __future__ import annotations

import subprocess
import sys

from znuzhgfw.main import build_scan_config, parse_args


def test_cli_scan_asset_flags(monkeypatch) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "znuzhgfw",
            "--url",
            "https://example.com",
            "--scan-assets",
            "--include-static",
            "--confidence-threshold",
            "medium",
            "--proof-threshold",
            "heuristic",
        ],
    )

    args = parse_args()
    config = build_scan_config(args)

    assert config.scan_assets is True
    assert config.include_static is True
    assert config.confidence_threshold == "MEDIUM"
    assert config.proof_threshold == "heuristic"


def test_cli_help_smoke() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "znuzhgfw.main", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--scan-assets" in result.stdout
    assert "--include-static" in result.stdout
    assert "--proof-threshold" in result.stdout
