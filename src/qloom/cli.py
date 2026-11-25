"""qloom.cli — Standalone CLI for QLOOM/2.0 & QLOOM/1.0 (.qloom) Format & Verification.

Supports `sample`, `verify`, `project`, `draw`, `waves`, `compile`, `upgrade`,
`downgrade`, `distill`, and `mcp`. Accepts `-` for stdin or a file path within
the current working directory, user home directory, or system temp directory.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from .ast_nodes import QLOOM_V2, QloomDocument, QloomError, Tier
from .codec import dump_qloom, parse_qloom, project_qloom, render_qloom_ascii
from .compat import (
    distill_qloom_handoff,
    downgrade_qloom_to_v1,
    plan_weave_waves,
    upgrade_qloom_to_v2,
)
from .mcp_server import serve_mcp_stdio
from .verifier import sample_qloom, verify_qloom

_QLOOM_CLI_ACTIONS: tuple[str, ...] = (
    "sample",
    "verify",
    "project",
    "draw",
    "waves",
    "compile",
    "upgrade",
    "downgrade",
    "distill",
    "mcp",
)


def _resolve_cli_path(raw_path: str) -> Path:
    candidate = Path(raw_path).expanduser().resolve()
    allowed_roots = [
        Path.cwd().resolve(),
        Path.home().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    ]
    if not any(candidate == root or candidate.is_relative_to(root) for root in allowed_roots):
        raise PermissionError(f"Path '{raw_path}' escapes sanctioned roots (CWE-22 guard)")
    if not candidate.is_file():
        raise FileNotFoundError(f"File not found: {raw_path}")
    return candidate


def _select_input_arg(args: argparse.Namespace) -> str | None:
    file_flag = getattr(args, "file", None)
    pos_target = getattr(args, "target", None)
    return str(file_flag) if file_flag is not None else (str(pos_target) if pos_target else None)


def _read_input_text(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    return _resolve_cli_path(source).read_text(encoding="utf-8")


def _load_wire_or_sample(args: argparse.Namespace, version: str) -> str:
    source = _select_input_arg(args)
    if not source:
        return dump_qloom(sample_qloom(version=version))
    return _read_input_text(source)


def _emit_wire(doc: QloomDocument, as_json: bool) -> None:
    wire = dump_qloom(doc, recompute_seal=False)
    if as_json:
        print(
            json.dumps(
                {"version": doc.version, "knot": doc.seal.knot if doc.seal else None, "wire": wire},
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(wire, end="")


def _action_sample(_args: argparse.Namespace, version: str, as_json: bool) -> int:
    doc = sample_qloom(version=version)
    wire = dump_qloom(doc, recompute_seal=False)
    if as_json:
        print(json.dumps({"wire": wire, "ast": doc.to_dict()}, indent=2, ensure_ascii=False))
    else:
        print(wire, end="")
    return 0


def _action_verify(args: argparse.Namespace, version: str, as_json: bool) -> int:
    raw = _load_wire_or_sample(args, version)
    enforce = not bool(getattr(args, "no_wire_ceiling", False))
    report = verify_qloom(raw, enforce_wire_ceiling=enforce)
    if as_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        status = "OK" if report["valid"] else "FAIL"
        print(
            f"[{status}] QLOOM [{report['verdict']}] ver={report.get('version')} "
            f"id={report.get('doc_id')} tier={report.get('tier')} "
            f"knot={report.get('knot')} findings={report['findings_count']}"
        )
        for finding in report.get("findings", []):
            print(f"  - [{finding['law']} @ {finding['plane']}] {finding['message']}")
    return 0 if report["valid"] else 1


def _action_project(args: argparse.Namespace, version: str, as_json: bool) -> int:
    raw = _load_wire_or_sample(args, version)
    tier = Tier(getattr(args, "tier", "L0"))
    projected = project_qloom(parse_qloom(raw), tier)
    wire = dump_qloom(projected)
    if as_json:
        print(
            json.dumps(
                {"tier": tier.value, "wire": wire, "ast": projected.to_dict()},
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print(wire, end="")
    return 0


def _action_compile(args: argparse.Namespace, _version: str, _as_json: bool) -> int:
    source = _select_input_arg(args)
    if not source:
        print("Error: a file path or '-' (stdin) is required for 'qloom compile'", file=sys.stderr)
        return 1
    content = _read_input_text(source)
    if getattr(args, "from_json", False):
        decoded = json.loads(content)
        if not isinstance(decoded, dict):
            raise ValueError("JSON AST input must be a JSON object")
        print(dump_qloom(QloomDocument.from_dict(decoded)), end="")
        return 0
    doc = parse_qloom(content)
    if getattr(args, "to_json", False):
        print(json.dumps(doc.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(dump_qloom(doc), end="")
    return 0


def _action_draw(args: argparse.Namespace, version: str, as_json: bool) -> int:
    raw = _load_wire_or_sample(args, version)
    max_rows = max(1, int(getattr(args, "max_rows", 5) or 5))
    diagram = render_qloom_ascii(raw, max_rows=max_rows)
    print(json.dumps({"ascii": diagram}, indent=2, ensure_ascii=False) if as_json else diagram)
    return 0


def _action_waves(args: argparse.Namespace, version: str, as_json: bool) -> int:
    raw = _load_wire_or_sample(args, version)
    waves = plan_weave_waves(raw)
    if as_json:
        print(json.dumps({"waves": waves}, indent=2, ensure_ascii=False))
    else:
        for idx, wave in enumerate(waves, 1):
            print(f"Wave {idx}: {', '.join(wave)}")
    return 0


def _action_upgrade(args: argparse.Namespace, version: str, as_json: bool) -> int:
    raw = _load_wire_or_sample(args, version)
    doc = upgrade_qloom_to_v2(
        raw,
        admin=getattr(args, "admin", None),
        tag=getattr(args, "tag", None),
        hub=getattr(args, "hub", None),
    )
    _emit_wire(doc, as_json)
    return 0


def _action_downgrade(args: argparse.Namespace, version: str, as_json: bool) -> int:
    raw = _load_wire_or_sample(args, version)
    _emit_wire(downgrade_qloom_to_v1(raw), as_json)
    return 0


def _action_distill(args: argparse.Namespace, version: str, as_json: bool) -> int:
    raw = _load_wire_or_sample(args, version)
    doc = distill_qloom_handoff(
        raw,
        tier=getattr(args, "tier", "L2"),
        doc_id=getattr(args, "doc_id", None),
    )
    _emit_wire(doc, as_json)
    return 0


_ACTION_HANDLERS: dict[str, Callable[[argparse.Namespace, str, bool], int]] = {
    "sample": _action_sample,
    "verify": _action_verify,
    "project": _action_project,
    "draw": _action_draw,
    "waves": _action_waves,
    "compile": _action_compile,
    "upgrade": _action_upgrade,
    "downgrade": _action_downgrade,
    "distill": _action_distill,
}


def cmd_qloom(args: argparse.Namespace) -> int:
    """Executes a parsed QLOOM CLI command and returns a process exit code."""
    action = getattr(args, "qloom_action", "sample") or "sample"
    if action == "mcp":
        return serve_mcp_stdio()
    as_json = bool(getattr(args, "json", False))
    version = str(getattr(args, "version", QLOOM_V2) or QLOOM_V2)
    handler = _ACTION_HANDLERS.get(action, _action_sample)
    try:
        return handler(args, version, as_json)
    except (
        QloomError,
        PermissionError,
        FileNotFoundError,
        OSError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        err = (
            json.dumps({"valid": False, "error": str(exc)}, indent=2)
            if as_json
            else f"QLOOM Error: {exc}"
        )
        print(err, file=sys.stdout if as_json else sys.stderr)
        return 1


def _add_common_flags(parser: argparse.ArgumentParser, *, default_tier: str = "L0") -> None:
    parser.add_argument("target", nargs="?", default=None, help="Path to .qloom/.json or '-'")
    parser.add_argument("--file", default=None, help="Path to a .qloom/.json file or '-' for stdin")
    parser.add_argument(
        "--version",
        default=QLOOM_V2,
        choices=["1.0", "2.0", "QLOOM/1.0", "QLOOM/2.0"],
        help="Protocol version (default: QLOOM/2.0)",
    )
    parser.add_argument(
        "--tier",
        default=default_tier,
        choices=["L0", "L1", "L2", "L3", "L4"],
        help="Target disclosure tier for 'project' or 'distill'",
    )
    parser.add_argument(
        "--admin", default=None, choices=["working", "summary"], help="Admin window for upgrade"
    )
    parser.add_argument("--tag", default=None, help="Optional domain tag for upgrade")
    parser.add_argument("--hub", default=None, help="Optional federated hub ID for upgrade")
    parser.add_argument("--doc-id", dest="doc_id", default=None, help="Optional doc_id for distill")
    parser.add_argument("--max-rows", dest="max_rows", type=int, default=5, help="Max draw rows")
    parser.add_argument("--to-json", action="store_true", help="Compile .qloom to JSON AST")
    parser.add_argument("--from-json", action="store_true", help="Compile JSON AST to .qloom")
    parser.add_argument(
        "--no-wire-ceiling",
        dest="no_wire_ceiling",
        action="store_true",
        help="Disable 8,000-char wire ceiling check during verify",
    )
    parser.add_argument("--json", action="store_true", help="Emit structured JSON output")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the standalone `qloom` CLI."""
    parser = argparse.ArgumentParser(
        prog="qloom",
        description="QLOOM/2.0 & QLOOM/1.0 Standalone Algebraic State Codec, Verifier & MCP Server",
    )
    sub = parser.add_subparsers(dest="qloom_action")
    for act in _QLOOM_CLI_ACTIONS:
        subparser = sub.add_parser(act)
        if act != "mcp":
            _add_common_flags(subparser, default_tier="L2" if act == "distill" else "L0")
    args = parser.parse_args(argv)
    if not getattr(args, "qloom_action", None):
        args.qloom_action = "sample"
        args.version = QLOOM_V2
        args.json = False
    return cmd_qloom(args)


if __name__ == "__main__":
    raise SystemExit(main())
