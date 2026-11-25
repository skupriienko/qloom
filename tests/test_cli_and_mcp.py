"""CLI and Stdio JSON-RPC 2.0 MCP server tests for `qloom`."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
import qloom
from qloom.cli import main
from qloom.mcp_server import QLOOM_COMPAT_ACTIONS, QloomMCPServer, serve_mcp_stdio


def test_cli_all_subcommands_and_json_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["sample", "--version", "QLOOM/2.0"]) == 0
    v2_wire = capsys.readouterr().out
    assert "~= QLOOM/2.0" in v2_wire

    assert main(["sample", "--version", "1.0", "--json"]) == 0
    v1_sample = json.loads(capsys.readouterr().out)
    assert v1_sample["ast"]["version"] == "QLOOM/1.0"

    v2_file = tmp_path / "handoff.qloom"
    v2_file.write_text(v2_wire, encoding="utf-8")

    assert main(["verify", "--file", str(v2_file), "--json"]) == 0
    ver_out = json.loads(capsys.readouterr().out)
    assert ver_out["valid"] is True
    assert ver_out["verdict"] == "VERIFIED"

    bad_file = tmp_path / "tampered.qloom"
    bad_file.write_text(v2_wire.replace("Migrate", "Break"), encoding="utf-8")
    assert main(["verify", "--file", str(bad_file), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False

    assert main(["project", "--file", str(v2_file), "--tier", "L0", "--json"]) == 0
    proj_out = json.loads(capsys.readouterr().out)
    assert proj_out["tier"] == "L0"
    assert "tier=L0" in proj_out["wire"]

    assert main(["compile", "--file", str(v2_file), "--to-json"]) == 0
    ast_json_text = capsys.readouterr().out
    ast_file = tmp_path / "ast.json"
    ast_file.write_text(ast_json_text, encoding="utf-8")

    assert main(["compile", "--file", str(ast_file), "--from-json"]) == 0
    recompiled_wire = capsys.readouterr().out
    assert qloom.verify(recompiled_wire)["valid"] is True

    assert main(["draw", "--file", str(v2_file), "--json"]) == 0
    draw_out = json.loads(capsys.readouterr().out)
    assert "epic.auth.v2" in draw_out["ascii"]

    assert main(["waves", "--file", str(v2_file), "--json"]) == 0
    waves_out = json.loads(capsys.readouterr().out)
    assert waves_out["waves"] == [["t_audit"], ["t_patch"], ["t_tests"]]

    v1_file = tmp_path / "legacy.qloom"
    v1_file.write_text(qloom.dump(qloom.sample_qloom_v1()), encoding="utf-8")
    assert (
        main(
            [
                "upgrade",
                "--file",
                str(v1_file),
                "--admin",
                "working",
                "--tag",
                "rel",
                "--hub",
                "HubA",
                "--json",
            ]
        )
        == 0
    )
    up_out = json.loads(capsys.readouterr().out)
    assert up_out["version"] == "QLOOM/2.0"

    assert main(["downgrade", "--file", str(v2_file), "--json"]) == 0
    down_out = json.loads(capsys.readouterr().out)
    assert down_out["version"] == "QLOOM/1.0"

    assert (
        main(
            ["distill", "--file", str(v2_file), "--tier", "L2", "--doc-id", "sum.doc", "--json"]
        )
        == 0
    )
    dist_out = json.loads(capsys.readouterr().out)
    assert "admin=summary" in dist_out["wire"]
    assert 'id="sum.doc"' in dist_out["wire"]


def test_cli_cwe22_containment_and_error_cases(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["verify", "--file", "/etc/passwd"]) == 1
    assert "CWE-22 guard" in capsys.readouterr().err

    assert main(["verify", "--file", "/etc/passwd", "--json"]) == 1
    err_json = json.loads(capsys.readouterr().out)
    assert err_json["valid"] is False
    assert "CWE-22 guard" in err_json["error"]

    missing = tmp_path / "missing.qloom"
    assert main(["verify", "--file", str(missing)]) == 1
    assert "File not found" in capsys.readouterr().err

    assert main(["compile"]) == 1
    assert "required" in capsys.readouterr().err


def test_mcp_server_protocol_and_all_tools() -> None:
    server = QloomMCPServer()

    init_resp = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init_resp is not None
    assert init_resp["result"]["serverInfo"]["name"] == "qloom-mcp"

    assert server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "ping"}) == {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {},
    }

    list_resp = server.handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert list_resp is not None
    tools = {t["name"]: t for t in list_resp["result"]["tools"]}
    assert set(tools) == {
        "qloom_verify",
        "qloom_project",
        "qloom_draw",
        "qloom_plan_waves",
        "qloom_compat",
    }
    assert set(
        tools["qloom_compat"]["inputSchema"]["properties"]["action"]["enum"]
    ) == set(QLOOM_COMPAT_ACTIONS)

    assert server.handle_request({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    def call(req_id: int, tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
        resp = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            }
        )
        assert resp is not None
        assert resp["result"]["isError"] is False
        structured = resp["result"]["structuredContent"]
        assert isinstance(structured, dict)
        return structured

    samp = call(10, "qloom_compat", {"action": "sample", "version": "QLOOM/2.0"})
    v2_wire = str(samp["qloom_text"])

    ver = call(11, "qloom_verify", {"qloom_text": v2_wire})
    assert ver["valid"] is True

    proj = call(12, "qloom_project", {"qloom_text": v2_wire, "tier": "L0"})
    assert proj["tier"] == "L0"

    drawn = call(13, "qloom_draw", {"qloom_text": v2_wire})
    assert "epic.auth.v2" in str(drawn["ascii"])

    waves = call(14, "qloom_plan_waves", {"qloom_text": v2_wire})
    assert waves["wave_count"] == 3

    v1_samp = call(15, "qloom_compat", {"action": "sample", "version": "QLOOM/1.0"})
    v1_wire = str(v1_samp["qloom_text"])

    up = call(16, "qloom_compat", {"action": "upgrade", "qloom_text": v1_wire, "admin": "working"})
    assert up["version"] == "QLOOM/2.0"

    down = call(17, "qloom_compat", {"action": "downgrade", "qloom_text": v2_wire})
    assert down["version"] == "QLOOM/1.0"

    dist = call(18, "qloom_compat", {"action": "distill", "qloom_text": v2_wire, "tier": "L2"})
    assert "admin=summary" in str(dist["qloom_text"])

    linked = call(
        19,
        "qloom_compat",
        {"action": "link", "packets": {"a": v1_wire, "b": v2_wire}, "hub_id": "SwarmHub"},
    )
    assert "hub=\"SwarmHub\"" in str(linked["qloom_text"])

    to_j = call(20, "qloom_compat", {"action": "to_json", "qloom_text": v2_wire})
    from_j = call(21, "qloom_compat", {"action": "from_json", "json_text": str(to_j["json_text"])})
    assert from_j["knot"] == samp["knot"]

    err_call = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {"name": "qloom_verify", "arguments": {}},
        }
    )
    assert err_call is not None
    assert err_call["result"]["isError"] is True

    unknown_tool = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 23,
            "method": "tools/call",
            "params": {"name": "missing_tool", "arguments": {}},
        }
    )
    assert unknown_tool is not None
    assert unknown_tool["error"]["code"] == -32602

    unknown_method = server.handle_request({"jsonrpc": "2.0", "id": 24, "method": "nope"})
    assert unknown_method is not None
    assert unknown_method["error"]["code"] == -32601


def test_serve_mcp_stdio_roundtrip() -> None:
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
    ]
    stdin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
    stdout = io.StringIO()
    assert serve_mcp_stdio(stdin=stdin, stdout=stdout) == 0

    lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    assert [line["id"] for line in lines] == [1, 2]
