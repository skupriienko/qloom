"""qloom.mcp_server — Zero-Dependency Stdio JSON-RPC 2.0 MCP Server.

Exposes five QLOOM tools over newline-delimited JSON-RPC 2.0 on stdio:
- `qloom_verify`
- `qloom_project`
- `qloom_draw`
- `qloom_plan_waves`
- `qloom_compat`

Supports `initialize`, `ping`, `tools/list`, and `tools/call`.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import IO, Any

from .ast_nodes import QLOOM_V2, QloomDocument, QloomError
from .codec import dump_qloom, parse_qloom, project_qloom, render_qloom_ascii
from .compat import (
    distill_qloom_handoff,
    downgrade_qloom_to_v1,
    link_qlooms,
    plan_weave_waves,
    upgrade_qloom_to_v2,
)
from .verifier import sample_qloom, verify_qloom

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "qloom-mcp"
SERVER_VERSION = "2.0.0"

QLOOM_COMPAT_ACTIONS: tuple[str, ...] = (
    "sample",
    "upgrade",
    "downgrade",
    "distill",
    "link",
    "to_json",
    "from_json",
)

QLOOM_TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "qloom_verify",
        "description": (
            "Verify a QLOOM/2.0 (10-law) or QLOOM/1.0 (8-law) wire packet for Merkle seal, "
            "safety, safe argv, taint lattice, Bernstein R/W concurrency, DAG closure, and budgets."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "qloom_text": {"type": "string", "description": "Input .qloom wire text."},
                "enforce_wire_ceiling": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enforce the 8,000-char wire ceiling check.",
                },
            },
            "required": ["qloom_text"],
        },
    },
    {
        "name": "qloom_project",
        "description": (
            "Project a QLOOM packet onto a progressive disclosure tier (L0..L4) "
            "while preserving parent knot lineage."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "qloom_text": {"type": "string", "description": "Input .qloom wire text."},
                "tier": {
                    "type": "string",
                    "enum": ["L0", "L1", "L2", "L3", "L4"],
                    "default": "L2",
                    "description": "Target disclosure tier.",
                },
            },
            "required": ["qloom_text"],
        },
    },
    {
        "name": "qloom_draw",
        "description": "Render a compact 6-plane ASCII state and execution DAG diagram.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "qloom_text": {"type": "string", "description": "Input .qloom wire text."},
                "max_rows": {
                    "type": "integer",
                    "default": 5,
                    "description": "Maximum rows per relation table to display.",
                },
                "max_chars": {
                    "type": "integer",
                    "default": 8000,
                    "description": "Maximum ASCII output character length.",
                },
            },
            "required": ["qloom_text"],
        },
    },
    {
        "name": "qloom_plan_waves",
        "description": (
            "Schedule @weave DAG nodes into dependency-ordered and Bernstein-safe parallel waves."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "qloom_text": {"type": "string", "description": "Input .qloom wire text."}
            },
            "required": ["qloom_text"],
        },
    },
    {
        "name": "qloom_compat",
        "description": (
            "Run QLOOM compatibility and conversion actions: sample, upgrade, downgrade, "
            "distill, link, to_json, or from_json."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": list(QLOOM_COMPAT_ACTIONS),
                    "description": "Compatibility or conversion action to run.",
                },
                "qloom_text": {"type": "string", "description": "Input .qloom wire text."},
                "json_text": {"type": "string", "description": "Input JSON AST for from_json."},
                "version": {
                    "type": "string",
                    "enum": ["1.0", "2.0", "QLOOM/1.0", "QLOOM/2.0"],
                    "default": "2.0",
                    "description": "Protocol version for sample.",
                },
                "tier": {
                    "type": "string",
                    "enum": ["L0", "L1", "L2", "L3", "L4"],
                    "default": "L2",
                    "description": "Target disclosure tier for distill.",
                },
                "admin": {
                    "type": "string",
                    "enum": ["working", "summary"],
                    "description": "Admin window for upgrade.",
                },
                "tag": {"type": "string", "description": "Optional tag for upgrade."},
                "hub": {"type": "string", "description": "Optional hub ID for upgrade."},
                "doc_id": {"type": "string", "description": "Optional doc_id for distill or link."},
                "hub_id": {"type": "string", "description": "Hub ID for link."},
                "packets": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Map of slot -> .qloom wire text for link.",
                },
            },
            "required": ["action"],
        },
    },
]


def _require_str(args: dict[str, Any], key: str, tool: str) -> str:
    val = args.get(key)
    if not isinstance(val, str):
        raise ValueError(f"Parameter '{key}' (str) is required for '{tool}'")
    return val


def _opt_str(args: dict[str, Any], key: str) -> str | None:
    val = args.get(key)
    if val is None:
        return None
    if not isinstance(val, str):
        raise ValueError(f"Parameter '{key}' must be a string")
    return val


def _opt_int(args: dict[str, Any], key: str, default: int) -> int:
    val = args.get(key)
    if val is None:
        return default
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"Parameter '{key}' must be an integer")
    return val


def _opt_bool(args: dict[str, Any], key: str, default: bool) -> bool:
    val = args.get(key)
    if val is None:
        return default
    if not isinstance(val, bool):
        raise ValueError(f"Parameter '{key}' must be a boolean")
    return val


def _jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


class QloomMCPServer:
    """Zero-dependency JSON-RPC 2.0 MCP server exposing QLOOM verification & tooling."""

    def __init__(self) -> None:
        self._tool_handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "qloom_verify": self._tool_verify,
            "qloom_project": self._tool_project,
            "qloom_draw": self._tool_draw,
            "qloom_plan_waves": self._tool_plan_waves,
            "qloom_compat": self._tool_compat,
        }
        self._compat_handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "sample": self._compat_sample,
            "upgrade": self._compat_upgrade,
            "downgrade": self._compat_downgrade,
            "distill": self._compat_distill,
            "link": self._compat_link,
            "to_json": self._compat_to_json,
            "from_json": self._compat_from_json,
        }

    def _tool_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        wire = _require_str(args, "qloom_text", "qloom_verify")
        enforce = _opt_bool(args, "enforce_wire_ceiling", True)
        return verify_qloom(wire, enforce_wire_ceiling=enforce)

    def _tool_project(self, args: dict[str, Any]) -> dict[str, Any]:
        wire = _require_str(args, "qloom_text", "qloom_project")
        tier = _opt_str(args, "tier") or "L2"
        doc = project_qloom(parse_qloom(wire), tier)
        return {
            "tier": doc.tier.value,
            "knot": doc.seal.knot if doc.seal else None,
            "qloom_text": dump_qloom(doc, recompute_seal=False),
            "ast": doc.to_dict(),
        }

    def _tool_draw(self, args: dict[str, Any]) -> dict[str, Any]:
        wire = _require_str(args, "qloom_text", "qloom_draw")
        max_rows = max(1, _opt_int(args, "max_rows", 5))
        max_chars = max(64, _opt_int(args, "max_chars", 8000))
        return {"ascii": render_qloom_ascii(wire, max_rows=max_rows, max_chars=max_chars)}

    def _tool_plan_waves(self, args: dict[str, Any]) -> dict[str, Any]:
        wire = _require_str(args, "qloom_text", "qloom_plan_waves")
        waves = plan_weave_waves(wire)
        return {"waves": waves, "wave_count": len(waves)}

    def _doc_response(self, action: str, doc: QloomDocument) -> dict[str, Any]:
        return {
            "action": action,
            "version": doc.version,
            "knot": doc.seal.knot if doc.seal else None,
            "qloom_text": dump_qloom(doc, recompute_seal=False),
        }

    def _compat_sample(self, args: dict[str, Any]) -> dict[str, Any]:
        version = _opt_str(args, "version") or QLOOM_V2
        doc = sample_qloom(version=version)
        return {**self._doc_response("sample", doc), "ast": doc.to_dict()}

    def _compat_upgrade(self, args: dict[str, Any]) -> dict[str, Any]:
        wire = _require_str(args, "qloom_text", "qloom_compat:upgrade")
        doc = upgrade_qloom_to_v2(
            wire,
            admin=_opt_str(args, "admin"),
            tag=_opt_str(args, "tag"),
            hub=_opt_str(args, "hub"),
        )
        return self._doc_response("upgrade", doc)

    def _compat_downgrade(self, args: dict[str, Any]) -> dict[str, Any]:
        wire = _require_str(args, "qloom_text", "qloom_compat:downgrade")
        return self._doc_response("downgrade", downgrade_qloom_to_v1(wire))

    def _compat_distill(self, args: dict[str, Any]) -> dict[str, Any]:
        wire = _require_str(args, "qloom_text", "qloom_compat:distill")
        doc = distill_qloom_handoff(
            wire,
            tier=_opt_str(args, "tier") or "L2",
            doc_id=_opt_str(args, "doc_id"),
        )
        return self._doc_response("distill", doc)

    def _compat_link(self, args: dict[str, Any]) -> dict[str, Any]:
        raw_packets = args.get("packets")
        if not isinstance(raw_packets, dict) or not raw_packets:
            raise ValueError("Parameter 'packets' (non-empty dict) is required for 'link'")
        packets: dict[str, QloomDocument | str] = {str(k): str(v) for k, v in raw_packets.items()}
        doc = link_qlooms(
            packets,
            hub_id=_opt_str(args, "hub_id") or "HubA",
            doc_id=_opt_str(args, "doc_id") or "qloom.swarm.hub",
        )
        return self._doc_response("link", doc)

    def _compat_to_json(self, args: dict[str, Any]) -> dict[str, Any]:
        wire = _require_str(args, "qloom_text", "qloom_compat:to_json")
        ast = parse_qloom(wire).to_dict()
        return {"action": "to_json", "ast": ast, "json_text": json.dumps(ast, indent=2)}

    def _compat_from_json(self, args: dict[str, Any]) -> dict[str, Any]:
        raw_json = _require_str(args, "json_text", "qloom_compat:from_json")
        decoded = json.loads(raw_json)
        if not isinstance(decoded, dict):
            raise ValueError("Parameter 'json_text' must decode to a JSON object")
        doc = QloomDocument.from_dict(decoded)
        doc_wire = dump_qloom(doc, recompute_seal=True)
        return {
            "action": "from_json",
            "version": doc.version,
            "knot": doc.seal.knot if doc.seal else None,
            "qloom_text": doc_wire,
        }

    def _tool_compat(self, args: dict[str, Any]) -> dict[str, Any]:
        action = args.get("action")
        if not isinstance(action, str) or action not in self._compat_handlers:
            allowed = ", ".join(QLOOM_COMPAT_ACTIONS)
            raise ValueError(f"Unsupported action {action!r}; expected one of: {allowed}")
        return self._compat_handlers[action](args)

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Executes a named QLOOM MCP tool and returns its structured result dict."""
        handler = self._tool_handlers.get(name)
        if handler is None:
            raise ValueError(f"Unknown tool: {name!r}")
        return handler(arguments)

    def _handle_tools_call(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        tool_name = params.get("name")
        if not isinstance(tool_name, str) or tool_name not in self._tool_handlers:
            return _jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name!r}")
        raw_args = params.get("arguments")
        if raw_args is None:
            raw_args = {}
        if not isinstance(raw_args, dict):
            return _jsonrpc_error(req_id, -32602, "Tool arguments must be an object")
        try:
            payload = self.call_tool(tool_name, raw_args)
            text = json.dumps(payload, indent=2, ensure_ascii=False)
            return _jsonrpc_result(
                req_id,
                {
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": payload,
                    "isError": False,
                },
            )
        except (QloomError, ValueError, TypeError, json.JSONDecodeError) as exc:
            err_payload = {"error": str(exc)}
            return _jsonrpc_result(
                req_id,
                {
                    "content": [
                        {"type": "text", "text": json.dumps(err_payload, ensure_ascii=False)}
                    ],
                    "structuredContent": err_payload,
                    "isError": True,
                },
            )

    def _dispatch_rpc_method(
        self, method: str, req_id: Any, request: dict[str, Any]
    ) -> dict[str, Any]:
        static_results: dict[str, dict[str, Any]] = {
            "initialize": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
            "ping": {},
            "tools/list": {"tools": QLOOM_TOOL_SPECS},
        }
        if method in static_results:
            return _jsonrpc_result(req_id, static_results[method])
        if method == "tools/call":
            params = request.get("params")
            if not isinstance(params, dict):
                return _jsonrpc_error(req_id, -32602, "Invalid params for tools/call")
            return self._handle_tools_call(req_id, params)
        return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Handles a single decoded JSON-RPC 2.0 message; returns None for notifications."""
        method = request.get("method")
        if not isinstance(method, str):
            return _jsonrpc_error(request.get("id"), -32600, "Invalid Request: missing method")
        if "id" not in request:
            return None
        return self._dispatch_rpc_method(method, request["id"], request)


def serve_mcp_stdio(
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
) -> int:
    """Runs the newline-delimited JSON-RPC 2.0 MCP server loop over stdio."""
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout
    server = QloomMCPServer()
    for raw_line in in_stream:
        line = raw_line.strip()
        if not line:
            continue
        response: dict[str, Any] | None
        try:
            decoded = json.loads(line)
            if not isinstance(decoded, dict):
                response = _jsonrpc_error(None, -32600, "Invalid Request: expected JSON object")
            else:
                response = server.handle_request(decoded)
        except json.JSONDecodeError as exc:
            response = _jsonrpc_error(None, -32700, f"Parse error: {exc}")
        if response is not None:
            out_stream.write(json.dumps(response, ensure_ascii=False) + "\n")
            out_stream.flush()
    return 0
