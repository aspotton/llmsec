"""Subprocess matrix for ``llmsec authorize``: exit codes 0/2/3 and error paths.

Runs the real CLI (``python3 -m llmsec``, house pattern from
tests/integration/test_guard.py) against JSON fixture files written under
tmp_path. Pins the plan section 9 exit codes: ALLOW=0, DENY=2,
REQUIRE_APPROVAL=3, and that malformed input fails nonzero with a readable
stderr. Plain asserts with messages, no fixtures/mocks (house style).
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from llmsec import ToolCall
from llmsec.actions import proposal_sha256

_SRC = str(Path(__file__).resolve().parents[2] / "src")

REGISTRY_JSON = {
    "tools": [
        {
            "name": "fs.read",
            "effects": ["read"],
            "params": [{"name": "path", "kind": "str", "role": "generic", "required": True}],
        },
        {
            "name": "net.post",
            "effects": ["data_egress"],
            "params": [{"name": "body", "kind": "str", "role": "payload", "required": True}],
        },
        {
            "name": "fs.write",
            "effects": ["external_write"],
            "params": [{"name": "path", "kind": "str", "role": "generic", "required": True}],
        },
    ]
}

# Grants fs.read and fs.write only; net.post stays ungranted (DENY path).
CAPABILITIES_JSON = [
    {"tool": "fs.read", "effects": ["read"]},
    {"tool": "fs.write", "effects": ["external_write"]},
]


def _write(tmp_path: Path, name: str, payload: object) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _run_authorize(
    tmp_path: Path, stdin: str, *extra_args: str, registry: object = REGISTRY_JSON
) -> subprocess.CompletedProcess[str]:
    registry_path = _write(tmp_path, "registry.json", registry)
    argv = [sys.executable, "-m", "llmsec", "authorize", "--registry", registry_path, *extra_args]
    return subprocess.run(
        argv,
        input=stdin,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": _SRC},
        check=False,
    )


def make_args() -> dict[str, Any]:
    return {"path": "/tmp/x"}


def test_allowed_read_exits_zero(tmp_path: Path) -> None:
    """Given: granted READ tool, valid schema. When: authorize. Then: exit 0 + allow verdict."""
    stdin = json.dumps({"tool": "fs.read", "arguments": {"path": "/etc/hosts"}})
    caps = _write(tmp_path, "caps.json", CAPABILITIES_JSON)
    proc = _run_authorize(tmp_path, stdin, "--capabilities", caps)
    assert proc.returncode == 0, f"allowed read must exit 0; stderr={proc.stderr!r}"
    assert "allow" in proc.stdout and "authorized" in proc.stdout, f"stdout was {proc.stdout!r}"


def test_ungranted_egress_exits_two(tmp_path: Path) -> None:
    """Given: egress tool with NO capability grant. When: authorize. Then: exit 2 + deny."""
    stdin = json.dumps({"tool": "net.post", "arguments": {"body": "secrets"}})
    proc = _run_authorize(tmp_path, stdin)
    assert proc.returncode == 2, f"missing capability must exit 2; stdout={proc.stdout!r}"
    assert "deny" in proc.stdout, f"stdout was {proc.stdout!r}"
    assert "missing_capability" in proc.stdout, f"stdout was {proc.stdout!r}"


def test_granted_write_without_approval_exits_three(tmp_path: Path) -> None:
    """Given: granted write, no approval flags. When: authorize. Then: exit 3 + require_approval."""
    stdin = json.dumps({"tool": "fs.write", "arguments": {"path": "/tmp/x"}})
    caps = _write(tmp_path, "caps.json", CAPABILITIES_JSON)
    proc = _run_authorize(tmp_path, stdin, "--capabilities", caps)
    assert proc.returncode == 3, f"write without approval must exit 3; stdout={proc.stdout!r}"
    assert "require_approval" in proc.stdout, f"stdout was {proc.stdout!r}"


def test_granted_write_with_correct_approval_exits_zero(tmp_path: Path) -> None:
    """Given: granted write + approval digest of the EXACT call. When: authorize. Then: exit 0."""
    call = ToolCall(tool="fs.write", arguments=make_args())
    stdin = json.dumps({"tool": call.tool, "arguments": dict(call.arguments)})
    proc = _run_authorize(
        tmp_path,
        stdin,
        "--capabilities",
        _write(tmp_path, "caps.json", CAPABILITIES_JSON),
        "--approval-sha",
        proposal_sha256(call),
        "--approver",
        "ada@example.com",
    )
    assert proc.returncode == 0, f"correct approval must exit 0; stdout={proc.stdout!r}"
    assert "allow" in proc.stdout, f"stdout was {proc.stdout!r}"
    digest = proposal_sha256(call)
    assert f"proposal_sha256={digest}" in proc.stdout, "verdict must carry the digest"


def test_malformed_stdin_json_exits_nonzero_with_readable_error(tmp_path: Path) -> None:
    """Given: stdin that is not JSON. When: authorize. Then: nonzero + readable stderr."""
    proc = _run_authorize(tmp_path, "this is not json")
    assert proc.returncode != 0, "malformed stdin must not exit 0"
    assert "error" in proc.stderr.lower(), f"stderr was {proc.stderr!r}"


def test_registry_with_bad_effect_string_exits_nonzero(tmp_path: Path) -> None:
    """Given: registry JSON with an unknown effect. When: authorize. Then: nonzero + enum named."""
    bad = json.loads(json.dumps(REGISTRY_JSON))
    bad["tools"][0]["effects"] = ["warp_drive"]
    proc = _run_authorize(tmp_path, json.dumps({"tool": "fs.read", "arguments": {}}), registry=bad)
    assert proc.returncode != 0, "an unknown enum string must fail the load"
    assert "EffectClass" in proc.stderr, f"stderr should name the enum, was {proc.stderr!r}"
