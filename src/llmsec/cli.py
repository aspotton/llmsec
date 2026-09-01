import argparse
import json
import sys
from pathlib import Path
from typing import Final

from llmsec import (
    Approval,
    AuthorizationAction,
    Capability,
    EffectClass,
    Guard,
    Profile,
    ReferenceMonitor,
    Stage,
    ToolCall,
    ToolRegistry,
    Trust,
)

#: Exit-code map; a new AuthorizationAction member raises KeyError instead of
#: silently exiting 0 (the repo's exhaustive-lookup tripwire idiom). Note that
#: argparse usage errors also exit 2, colliding with DENY (documented in the
#: authorize --help epilog per plan section 9).
_AUTHORIZE_EXIT: Final[dict[AuthorizationAction, int]] = {
    AuthorizationAction.ALLOW: 0,
    AuthorizationAction.DENY: 2,
    AuthorizationAction.REQUIRE_APPROVAL: 3,
}


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _serialize(result: object) -> str:
    from llmsec.core import Decision

    if not isinstance(result, Decision):
        raise TypeError("expected Decision")
    return json.dumps(
        {
            "action": result.action.value,
            "risk": result.risk,
            "findings": [
                {
                    "detector": finding.detector,
                    "category": finding.category,
                    "confidence": finding.confidence,
                    "severity": finding.severity.value,
                    "message": finding.message,
                    "spans": finding.spans,
                    "properties": dict(finding.properties),
                }
                for finding in result.findings
            ],
            "metrics": dict(result.metrics),
        },
        indent=2,
        sort_keys=True,
    )


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``llmsec`` CLI."""
    parser = argparse.ArgumentParser(prog="llmsec")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="inspect text from a file or stdin")
    scan.add_argument("path", help="file to scan, or - for stdin")
    scan.add_argument(
        "--stage",
        choices=[stage.value for stage in Stage],
        default=Stage.USER_INPUT.value,
    )
    scan.add_argument(
        "--trust",
        choices=[trust.value for trust in Trust],
        default=Trust.UNKNOWN.value,
    )
    scan.add_argument("--json", action="store_true", help="emit structured JSON")
    scan.add_argument("--diagnostics", action="store_true", help="include timing diagnostics")
    scan.add_argument(
        "--profile",
        choices=[profile.value for profile in Profile],
        default=None,
        help="policy preset; omit = chat/defaults",
    )

    authorize = subparsers.add_parser(
        "authorize",
        help="authorize one proposed tool call (JSON object) read from stdin",
        epilog=(
            "exit codes: 0 = allow, 2 = deny, 3 = require_approval. "
            "WARNING: argparse usage errors also exit 2, which collides with deny; "
            "check stderr to tell them apart. "
            "The registry/capabilities JSON files are a demo convenience, "
            "not a production trust path."
        ),
    )
    authorize.add_argument(
        "--registry",
        required=True,
        metavar="PATH.json",
        help="host-declared tool registry JSON (demo convenience, not a production trust path)",
    )
    authorize.add_argument(
        "--capabilities",
        metavar="PATH.json",
        help='granted capabilities JSON, shape [{"tool": ..., "effects": [...]}] '
        "(demo convenience, not a production trust path)",
    )
    authorize.add_argument(
        "--approval-sha",
        metavar="HEX",
        help="proposal_sha256 a human approved (requires --approver)",
    )
    authorize.add_argument(
        "--approver", metavar="NAME", help="who approved (requires --approval-sha)"
    )
    return parser


def _load_capabilities(path: str) -> frozenset[Capability]:
    """Parse the capabilities demo file; enum members checked, never passed through."""
    entries = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("capabilities file must be a JSON list")
    capabilities: list[Capability] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("tool"), str):
            raise ValueError(f"capabilities[{index}] must be an object naming a tool")
        effects_raw = entry.get("effects")
        if not isinstance(effects_raw, list) or not effects_raw:
            raise ValueError(f"capabilities[{index}] effects must be a non-empty list")
        capabilities.append(
            Capability(
                tool=entry["tool"],
                effects=frozenset(EffectClass(raw) for raw in effects_raw),
            )
        )
    return frozenset(capabilities)


def _authorize(args: argparse.Namespace) -> int:
    """Run the authorize subcommand; see _AUTHORIZE_EXIT for the exit-code matrix."""
    try:
        registry = ToolRegistry.from_json(args.registry)
        capabilities = _load_capabilities(args.capabilities) if args.capabilities else frozenset()
        approval = None
        if args.approval_sha is not None or args.approver is not None:
            if args.approval_sha is None or args.approver is None:
                raise ValueError("--approval-sha and --approver must be given together")
            approval = Approval(proposal_sha256=args.approval_sha, approver=args.approver)
        payload = json.loads(sys.stdin.read())
        if not isinstance(payload, dict) or not isinstance(payload.get("tool"), str):
            raise ValueError('stdin must be one JSON object like {"tool": ..., "arguments": {...}}')
        arguments = payload.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ValueError("stdin 'arguments' must be a JSON object")
        call = ToolCall(tool=payload["tool"], arguments=arguments)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    decision = ReferenceMonitor(registry, capabilities).authorize(call, approval=approval)
    print(
        f"{decision.action.value} reason={decision.reason} "
        f"proposal_sha256={decision.proposal_sha256}"
    )
    return _AUTHORIZE_EXIT[decision.action]


def main() -> int:
    """Run the CLI; scan exits 0/2, authorize follows _AUTHORIZE_EXIT (0/2/3)."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        content = _read_input(args.path)
        if args.profile:
            guard = Guard.from_profile(Profile(args.profile), diagnostics=args.diagnostics)
        else:
            guard = Guard.default(diagnostics=args.diagnostics)
        result = guard.inspect(
            content,
            stage=Stage(args.stage),
            trust=Trust(args.trust),
        )
        if args.json:
            print(_serialize(result))
        else:
            print(result.action.value.upper())
            for finding in result.findings:
                print(
                    f"{finding.severity.value.upper():8} "
                    f"{finding.category:28} "
                    f"{finding.confidence:.2f}  {finding.message}"
                )
        return 0 if result.allowed else 2

    if args.command == "authorize":
        return _authorize(args)

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
