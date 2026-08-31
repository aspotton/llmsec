import argparse
import json
import sys
from pathlib import Path

from llmsec import Guard, Stage, Trust


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
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        content = _read_input(args.path)
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

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
