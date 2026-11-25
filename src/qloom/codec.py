"""qloom.codec — Deterministic Parser, Canonical Serializer, Projector & ASCII Renderer.

Implements:
- Bounded, ReDoS-free lexical scanning and parsing (`parse_qloom` / `parse`)
- Canonical body formatting and SHA-256 knot sealing (`dump_qloom` / `dumps_qloom`)
- File-object and Path I/O helpers (`load` / `dump_file`)
- Progressive disclosure projection (`project_qloom` / `project`)
- Visual CLI State & DAG renderer (`render_qloom_ascii` / `draw_qloom` / `draw`)
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from .ast_nodes import (
    QLOOM_V1,
    QLOOM_V2,
    V1_GENESIS_PARENT,
    V2_GENESIS_PARENT,
    VALID_COLUMN_TYPES,
    AdminWindow,
    AgentState,
    AttachFace,
    CharterLock,
    CharterMandate,
    CharterPlane,
    ColumnSpec,
    ContractClause,
    ContractsPlane,
    EpistemicModality,
    LatticePlane,
    NodeLifecycle,
    NodeWeight,
    PulsePlane,
    QloomDocument,
    QloomSyntaxError,
    ReconciliationSeal,
    RelationCheck,
    RelationTable,
    Spin,
    Tier,
    VaultBlob,
    VaultPlane,
    WeaveNode,
    WeavePlane,
    WorkspaceMode,
    normalize_qloom_version,
)

MAX_QLOOM_BYTES = 500_000
MAX_RELATIONS = 64
MAX_ROWS_PER_RELATION = 5_000
MAX_WEAVE_NODES = 512
MAX_ASCII_CHARS = 8_000

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-:/]*$")
_REL_HEADER_RE = re.compile(r"^relation\s+([A-Za-z_][A-Za-z0-9_\-]*)\(([^)]*)\)(.*?)\{$")
_VALID_TIERS = frozenset({"T0", "T1", "T2", "T3"})
_VALID_LIFECYCLES = frozenset(item.value for item in NodeLifecycle)
_VALID_MODALITIES = frozenset(item.value for item in EpistemicModality)


def _check_ident(value: str, line: int = 1, col: int = 1) -> str:
    if not _IDENT_RE.match(value):
        raise QloomSyntaxError(f"Invalid identifier {value!r}", line, col)
    return value


def _strip_comment(line: str) -> str:
    in_str = False
    escape = False
    for idx, ch in enumerate(line):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_str:
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if ch == "#" and not in_str:
            return line[:idx]
    return line


def _handle_quoted_char(ch: str, state: list[bool], buf: list[str]) -> bool:
    if state[1]:
        buf.append(ch)
        state[1] = False
        return True
    if ch == "\\" and state[0]:
        buf.append(ch)
        state[1] = True
        return True
    if ch == '"':
        state[0] = not state[0]
        buf.append(ch)
        return True
    if state[0]:
        buf.append(ch)
        return True
    return False


def _update_delim_depths(ch: str, depths: list[int]) -> None:
    if ch in ("[", "{", "("):
        idx = 0 if ch == "[" else (1 if ch == "{" else 2)
        depths[idx] += 1
    elif ch in ("]", "}", ")"):
        idx = 0 if ch == "]" else (1 if ch == "}" else 2)
        depths[idx] = max(0, depths[idx] - 1)


def _split_top_level(text: str, sep: str | None = None) -> list[str]:
    """Splits text on separator (or whitespace when sep is None) outside quotes and braces."""
    tokens: list[str] = []
    buf: list[str] = []
    str_state = [False, False]
    depths = [0, 0, 0]

    for ch in text:
        if _handle_quoted_char(ch, str_state, buf):
            continue
        _update_delim_depths(ch, depths)
        at_sep = (ch.isspace() if sep is None else ch == sep) and sum(depths) == 0
        if at_sep:
            item = "".join(buf).strip()
            if item or sep is not None:
                tokens.append(item)
            buf.clear()
        else:
            buf.append(ch)

    tail = "".join(buf).strip()
    if tail:
        tokens.append(tail)
    return tokens


def _parse_string(raw: str, line: int = 1) -> str:
    raw = raw.strip()
    if len(raw) < 2 or not (raw.startswith('"') and raw.endswith('"')):
        raise QloomSyntaxError(f"Expected quoted string, got {raw!r}", line)
    try:
        val = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise QloomSyntaxError(f"Invalid string literal: {exc}", line) from exc
    if not isinstance(val, str):
        raise QloomSyntaxError(f"Expected string literal, got {type(val).__name__}", line)
    return val


def _parse_ref(raw: str, *, allow_null: bool = False, line: int = 1) -> str | None:
    raw = raw.strip()
    if allow_null and raw == "_":
        return None
    if not raw.startswith("->"):
        raise QloomSyntaxError(f"Expected reference starting with '->', got {raw!r}", line)
    return _check_ident(raw[2:], line)


def _parse_collection_item(part: str, *, expect_refs: bool, line: int) -> str | None:
    if expect_refs:
        return _parse_ref(part, allow_null=False, line=line)
    if part.startswith('"'):
        return _parse_string(part, line)
    return _check_ident(part, line)


def _parse_collection(
    raw: str, *, brace_delim: str, expect_refs: bool = False, line: int = 1
) -> list[str]:
    open_ch, close_ch = brace_delim[0], brace_delim[1]
    s = raw.strip()
    if not (s.startswith(open_ch) and s.endswith(close_ch)):
        raise QloomSyntaxError(f"Expected {open_ch}...{close_ch} collection, got {raw!r}", line)
    inner = s[1:-1].strip()
    if not inner:
        return []
    out: list[str] = []
    for part in _split_top_level(inner, sep=","):
        p = part.strip()
        if not p:
            raise QloomSyntaxError("Empty element inside collection literal", line)
        item = _parse_collection_item(p, expect_refs=expect_refs, line=line)
        if item is not None:
            out.append(item)
    return out


def _parse_kv_pairs(tokens: list[str], line: int = 1) -> dict[str, str]:
    kv: dict[str, str] = {}
    for tok in tokens:
        if "=" not in tok:
            raise QloomSyntaxError(f"Expected key=value token, got {tok!r}", line)
        k, v = tok.split("=", 1)
        kv[_check_ident(k.strip(), line)] = v.strip()
    return kv


def _parse_num(raw: str, line: int) -> int | float:
    s = raw.strip()
    try:
        return int(s, 10)
    except ValueError:
        try:
            return float(s)
        except ValueError as exc:
            raise QloomSyntaxError(f"Expected numeric literal, got {raw!r}", line) from exc


def _parse_enum_cell(raw: str, valid: frozenset[str], label: str, line: int) -> str:
    if raw not in valid:
        raise QloomSyntaxError(f"Invalid {label} {raw!r}", line)
    return raw


def _parse_int_cell(s: str, line: int) -> int:
    try:
        return int(s, 10)
    except ValueError as exc:
        raise QloomSyntaxError(f"Invalid integer cell {s!r}", line) from exc


def _parse_float_cell(s: str, line: int) -> float:
    try:
        return float(s)
    except ValueError as exc:
        raise QloomSyntaxError(f"Invalid float cell {s!r}", line) from exc


def _parse_bool_cell(s: str, line: int) -> bool:
    if s == "true":
        return True
    if s == "false":
        return False
    raise QloomSyntaxError(f"Invalid bool cell {s!r} (use true/false)", line)


_CELL_PARSERS: dict[str, Callable[[str, int], Any]] = {
    "id": lambda s, ln: _check_ident(s, ln),
    "mod": lambda s, ln: _parse_enum_cell(s, _VALID_MODALITIES, "epistemic modality", ln),
    "tier": lambda s, ln: _parse_enum_cell(s, _VALID_TIERS, "trust tier", ln),
    "str": _parse_string,
    "int": _parse_int_cell,
    "float": _parse_float_cell,
    "bool": _parse_bool_cell,
    "ref": lambda s, ln: _parse_ref(s, allow_null=False, line=ln),
    "ref?": lambda s, ln: _parse_ref(s, allow_null=True, line=ln),
}


def _parse_cell(raw: str, col_type: str, line: int = 1) -> Any:
    parser = _CELL_PARSERS.get(col_type)
    if parser is None:
        raise QloomSyntaxError(f"Unsupported column type {col_type!r}", line)
    return parser(raw.strip(), line)


def _format_cell(val: Any, col_type: str) -> str:
    if col_type == "str":
        return json.dumps(str(val), ensure_ascii=False)
    if col_type == "bool":
        return "true" if bool(val) else "false"
    if col_type == "ref":
        return f"->{val}"
    if col_type == "ref?":
        return "_" if val is None else f"->{val}"
    if col_type == "float":
        return repr(float(val))
    return str(val)


def _parse_opt_enum(raw: str | None, enum_cls: type[Any], label: str, line_no: int) -> Any:
    if raw is None:
        return None
    try:
        return enum_cls(raw)
    except ValueError as exc:
        raise QloomSyntaxError(f"Invalid {label} {raw!r}", line_no) from exc


def _parse_header_metadata(kv: dict[str, str], version: str, line_no: int) -> dict[str, Any]:
    try:
        tier = Tier(kv.get("tier", "L2"))
        epoch = int(kv.get("epoch", "1"), 10)
    except ValueError as exc:
        raise QloomSyntaxError("Invalid tier or epoch in header", line_no) from exc
    default_par = V1_GENESIS_PARENT if version == QLOOM_V1 else V2_GENESIS_PARENT
    return {
        "tier": tier,
        "state": kv.get("state", AgentState.REASONING.value),
        "parent": _parse_string(kv["parent"], line_no) if "parent" in kv else default_par,
        "epoch": epoch,
        "admin": _parse_opt_enum(kv.get("admin"), AdminWindow, "admin", line_no),
        "tag": _parse_string(kv["tag"], line_no) if "tag" in kv else None,
        "hub": _parse_string(kv["hub"], line_no) if "hub" in kv else None,
    }


def _parse_header_line(line_str: str, line_no: int) -> dict[str, Any]:
    tokens = _split_top_level(line_str)
    if len(tokens) < 2 or tokens[0] != "~=":
        raise QloomSyntaxError("Document must begin with '~= QLOOM/2.0' or '~= QLOOM/1.0'", line_no)
    version = normalize_qloom_version(tokens[1])
    kv = _parse_kv_pairs(tokens[2:], line_no)
    doc_id = _parse_string(kv["id"], line_no) if "id" in kv else ""
    if not doc_id:
        raise QloomSyntaxError('Header missing non-empty id="..."', line_no)
    return {"version": version, "doc_id": doc_id, **(_parse_header_metadata(kv, version, line_no))}


_BUDGET_FIELD_SPECS: tuple[tuple[str, str, Callable[[str], int | float]], ...] = (
    ("tokens<=", "max_tokens", lambda v: int(v, 10)),
    ("chars<=", "max_chars", lambda v: int(v, 10)),
    ("cost_usd<=", "max_cost_usd", float),
    ("retries<=", "max_retries", lambda v: int(v, 10)),
    ("tol_pct<=", "tol_pct", float),
)


def _parse_budget_lock(lock_id: str, spec: str, line_no: int) -> CharterLock:
    parsed: dict[str, int | float] = {}
    for tok in _split_top_level(spec):
        matched = False
        for prefix, attr, converter in _BUDGET_FIELD_SPECS:
            if tok.startswith(prefix):
                try:
                    parsed[attr] = converter(tok[len(prefix) :])
                except ValueError as exc:
                    raise QloomSyntaxError(f"Invalid budget value in {tok!r}", line_no) from exc
                matched = True
                break
        if not matched:
            raise QloomSyntaxError(f"Unknown budget predicate {tok!r}", line_no)
    return CharterLock(
        lock_id=lock_id,
        kind="budget",
        max_tokens=int(parsed["max_tokens"]) if "max_tokens" in parsed else None,
        max_chars=int(parsed["max_chars"]) if "max_chars" in parsed else None,
        max_cost_usd=float(parsed["max_cost_usd"]) if "max_cost_usd" in parsed else None,
        max_retries=int(parsed["max_retries"]) if "max_retries" in parsed else None,
        tol_pct=float(parsed["tol_pct"]) if "tol_pct" in parsed else None,
    )


def _parse_lock_directive(rest: str, line_no: int) -> CharterLock:
    if ":" not in rest:
        raise QloomSyntaxError("Malformed lock directive (missing ':')", line_no)
    lock_id_raw, spec = rest.split(":", 1)
    lock_id = _check_ident(lock_id_raw.strip(), line_no)
    spec = spec.strip()
    if spec.startswith("forbid "):
        code = _parse_string(spec[7:].strip(), line_no)
        return CharterLock(lock_id=lock_id, kind="forbid", forbid_code=code)
    if spec.startswith("budget "):
        return _parse_budget_lock(lock_id, spec[7:].strip(), line_no)
    raise QloomSyntaxError(f"Unsupported lock clause {spec!r}", line_no)


def _parse_mandate_directive(rest: str, line_no: int) -> CharterMandate:
    if ":" not in rest:
        raise QloomSyntaxError("Malformed mandate directive (missing ':')", line_no)
    mandate_id_raw, stmt = rest.split(":", 1)
    stmt = stmt.strip()
    if not stmt.startswith("must "):
        raise QloomSyntaxError("Mandate clause must begin with 'must \"...\"'", line_no)
    return CharterMandate(
        mandate_id=_check_ident(mandate_id_raw.strip(), line_no),
        statement=_parse_string(stmt[5:].strip(), line_no),
    )


def _parse_charter_lines(lines: list[tuple[int, str]]) -> CharterPlane:
    plane = CharterPlane()
    for line_no, text in lines:
        if text.startswith("goal:"):
            plane.goal = _parse_string(text[5:].strip(), line_no)
        elif text.startswith("lock "):
            plane.locks.append(_parse_lock_directive(text[5:].strip(), line_no))
        elif text.startswith("mandate "):
            plane.mandates.append(_parse_mandate_directive(text[8:].strip(), line_no))
        else:
            raise QloomSyntaxError(f"Unknown @charter statement {text!r}", line_no)
    return plane


def _parse_slice_arg(arg: str, line_no: int) -> tuple[int, int]:
    if ".." not in arg:
        raise QloomSyntaxError(f"Expected start..end slice in relation check, got {arg!r}", line_no)
    s_raw, e_raw = arg.split("..", 1)
    try:
        return int(s_raw.strip(), 10), int(e_raw.strip(), 10)
    except ValueError as exc:
        raise QloomSyntaxError(f"Invalid slice bounds {arg!r}", line_no) from exc


def _parse_single_relation_check(tok: str, line_no: int) -> RelationCheck:
    m_cnt = re.match(r"^\^count=(\d+)$", tok)
    if m_cnt:
        return RelationCheck(kind="count", expected=int(m_cnt.group(1), 10))
    m_sum = re.match(r"^\^sum\(([^)]+)\)=(.+)$", tok)
    if m_sum:
        args = [a.strip() for a in m_sum.group(1).split(",") if a.strip()]
        start_r, end_r = _parse_slice_arg(args[1], line_no) if len(args) > 1 else (None, None)
        return RelationCheck(
            kind="sum",
            column=_check_ident(args[0], line_no),
            start_row=start_r,
            end_row=end_r,
            expected=_parse_num(m_sum.group(2), line_no),
        )
    m_net = re.match(r"^\^net\(([^,]+),\s*([^)]+)\)=(.+)$", tok)
    if m_net:
        return RelationCheck(
            kind="net",
            column=_check_ident(m_net.group(1).strip(), line_no),
            extra_column=_check_ident(m_net.group(2).strip(), line_no),
            expected=_parse_num(m_net.group(3), line_no),
        )
    m_pct = re.match(r"^\^(tol|quota)\(([^,]+),\s*pct=([^)]+)\)=(.+)$", tok)
    if m_pct:
        return RelationCheck(
            kind=m_pct.group(1),
            column=_check_ident(m_pct.group(2).strip(), line_no),
            pct=float(m_pct.group(3).strip()),
            expected=_parse_num(m_pct.group(4), line_no),
        )
    raise QloomSyntaxError(f"Invalid relation check syntax {tok!r}", line_no)


def _parse_relation_columns(cols_raw: str, line_no: int) -> list[ColumnSpec]:
    columns: list[ColumnSpec] = []
    for rc in [c.strip() for c in cols_raw.split(",") if c.strip()]:
        if ":" not in rc:
            raise QloomSyntaxError(f"Column spec missing ':' in {rc!r}", line_no)
        cname, ctype = (part.strip() for part in rc.split(":", 1))
        if ctype not in VALID_COLUMN_TYPES:
            raise QloomSyntaxError(f"Unknown column type {ctype!r}", line_no)
        columns.append(ColumnSpec(name=_check_ident(cname, line_no), col_type=ctype))
    return columns


def _consume_relation_rows(
    lines: list[tuple[int, str]],
    idx: int,
    rel_name: str,
    columns: list[ColumnSpec],
    rows: list[list[Any]],
    spacers: list[int],
) -> tuple[int, bool]:
    while idx < len(lines):
        r_line_no, r_text = lines[idx]
        if r_text == "}":
            return idx + 1, True
        if r_text == "---":
            spacers.append(len(rows))
            idx += 1
            continue
        if len(rows) >= MAX_ROWS_PER_RELATION:
            raise QloomSyntaxError("Exceeded MAX_ROWS_PER_RELATION", r_line_no)
        cells_raw = _split_top_level(r_text, sep="|")
        if len(cells_raw) != len(columns):
            raise QloomSyntaxError(
                f"Row in relation {rel_name!r} has {len(cells_raw)} cells, expected {len(columns)}",
                r_line_no,
            )
        rows.append(
            [
                _parse_cell(c_raw, col.col_type, r_line_no)
                for c_raw, col in zip(cells_raw, columns, strict=True)
            ]
        )
        idx += 1
    return idx, False


def _parse_lattice_lines(lines: list[tuple[int, str]]) -> LatticePlane:
    plane = LatticePlane()
    idx = 0
    while idx < len(lines):
        line_no, text = lines[idx]
        m = _REL_HEADER_RE.match(text)
        if not m:
            raise QloomSyntaxError(f"Expected 'relation name(cols...) {{', got {text!r}", line_no)
        if len(plane.relations) >= MAX_RELATIONS:
            raise QloomSyntaxError(f"Exceeded MAX_RELATIONS ({MAX_RELATIONS})", line_no)
        rel_name = m.group(1)
        columns = _parse_relation_columns(m.group(2), line_no)
        checks = [_parse_single_relation_check(t, line_no) for t in _split_top_level(m.group(3))]
        rows: list[list[Any]] = []
        spacers: list[int] = []
        idx, closed = _consume_relation_rows(lines, idx + 1, rel_name, columns, rows, spacers)
        if not closed:
            raise QloomSyntaxError(f"Unclosed relation block {rel_name!r}", line_no)
        plane.relations.append(
            RelationTable(
                name=rel_name,
                columns=columns,
                rows=rows,
                checks=checks,
                spacer_indices=spacers,
            )
        )
    return plane


def _parse_weave_node(line_no: int, text: str) -> WeaveNode:
    tokens = _split_top_level(text)
    if len(tokens) < 4 or tokens[0] != "node":
        raise QloomSyntaxError(f"Expected 'node <id> ... -> <status>', got {text!r}", line_no)
    node_id = _check_ident(tokens[1], line_no)
    if tokens[-2] != "->" or tokens[-1] not in _VALID_LIFECYCLES:
        raise QloomSyntaxError(
            "Node line must end with '-> <pending|active|done|blocked|skipped>'",
            line_no,
        )
    lifecycle = NodeLifecycle(tokens[-1])
    kv = _parse_kv_pairs(tokens[2:-2], line_no)
    try:
        spin = Spin(kv.get("spin", ""))
    except ValueError as exc:
        raise QloomSyntaxError(
            f"Invalid spin {kv.get('spin')!r} (expected Z or S)", line_no
        ) from exc
    return WeaveNode(
        node_id=node_id,
        spin=spin,
        state=_check_ident(kv.get("state", AgentState.SANDBOX_COMPUTE.value), line_no),
        deps=_parse_collection(kv["deps"], brace_delim="[]", line=line_no) if "deps" in kv else [],
        reads=_parse_collection(kv["R"], brace_delim="{}", line=line_no) if "R" in kv else [],
        writes=_parse_collection(kv["W"], brace_delim="{}", line=line_no) if "W" in kv else [],
        lifecycle=lifecycle,
        face=_parse_opt_enum(kv.get("face"), AttachFace, "face", line_no),
        weight=_parse_opt_enum(kv.get("weight"), NodeWeight, "weight", line_no),
    )


def _parse_weave_lines(mode_str: str, lines: list[tuple[int, str]], header_line: int) -> WeavePlane:
    try:
        mode = WorkspaceMode(mode_str)
    except ValueError as exc:
        raise QloomSyntaxError(f"Invalid @weave mode {mode_str!r}", header_line) from exc
    nodes: list[WeaveNode] = []
    for line_no, text in lines:
        if len(nodes) >= MAX_WEAVE_NODES:
            raise QloomSyntaxError(f"Exceeded MAX_WEAVE_NODES ({MAX_WEAVE_NODES})", line_no)
        nodes.append(_parse_weave_node(line_no, text))
    return WeavePlane(mode=mode, nodes=nodes)


def _parse_clause_attr(clause: ContractClause, line_no: int, text: str) -> None:
    if text.startswith("requires:"):
        raw_reqs = text[9:].strip()
        clause.requires = _parse_collection(
            raw_reqs, brace_delim="[]", expect_refs=True, line=line_no
        )
    elif text.startswith("ensures:"):
        clause.ensures = _parse_string(text[8:].strip(), line_no)
    elif text.startswith("witness_argv:"):
        clause.witness_argv = _parse_collection(text[13:].strip(), brace_delim="[]", line=line_no)
    elif text.startswith("timeout_s:"):
        try:
            clause.timeout_s = int(text[10:].strip(), 10)
        except ValueError as exc:
            raise QloomSyntaxError("Invalid integer timeout_s", line_no) from exc
    elif text.startswith("rollback_argv:"):
        clause.rollback_argv = _parse_collection(text[14:].strip(), brace_delim="[]", line=line_no)
    else:
        raise QloomSyntaxError(f"Unknown clause attribute {text!r}", line_no)


def _parse_contracts_lines(lines: list[tuple[int, str]]) -> ContractsPlane:
    plane = ContractsPlane()
    idx = 0
    while idx < len(lines):
        line_no, text = lines[idx]
        m = re.match(r"^clause\s+([A-Za-z_][A-Za-z0-9_.\-]*)\s*\{$", text)
        if not m:
            raise QloomSyntaxError(f"Expected 'clause <ID> {{', got {text!r}", line_no)
        clause = ContractClause(clause_id=_check_ident(m.group(1), line_no))
        idx += 1
        closed = False
        while idx < len(lines):
            c_line_no, c_text = lines[idx]
            if c_text == "}":
                closed = True
                idx += 1
                break
            _parse_clause_attr(clause, c_line_no, c_text)
            idx += 1
        if not closed:
            raise QloomSyntaxError(f"Unclosed clause {clause.clause_id!r}", line_no)
        plane.clauses.append(clause)
    return plane


def _parse_vault_lines(lines: list[tuple[int, str]]) -> VaultPlane:
    blobs: list[VaultBlob] = []
    for line_no, text in lines:
        tokens = _split_top_level(text)
        if len(tokens) < 4 or tokens[0] != "blob":
            raise QloomSyntaxError(f"Expected 'blob <id> tier=T2|T3 ...', got {text!r}", line_no)
        blob_id = _check_ident(tokens[1], line_no)
        kv = _parse_kv_pairs(tokens[2:], line_no)
        tier = kv.get("tier", "T2")
        if tier not in ("T2", "T3"):
            raise QloomSyntaxError(f"@vault blob tier must be T2 or T3, got {tier!r}", line_no)
        try:
            size_bytes = int(kv.get("bytes", "0"), 10)
        except ValueError as exc:
            raise QloomSyntaxError("Invalid integer 'bytes' in @vault blob", line_no) from exc
        blobs.append(
            VaultBlob(
                blob_id=blob_id,
                tier=tier,
                sha256=_parse_string(kv["sha256"], line_no),
                size_bytes=size_bytes,
                origin=_parse_string(kv["origin"], line_no),
                uri=_parse_string(kv["uri"], line_no),
                wrap=_parse_string(kv["wrap"], line_no) if "wrap" in kv else None,
            )
        )
    return VaultPlane(blobs=blobs)


def _parse_pulse_lines(lines: list[tuple[int, str]]) -> PulsePlane:
    plane = PulsePlane()
    for line_no, text in lines:
        if text.startswith("focus:"):
            plane.focus = _parse_ref(text[6:].strip(), allow_null=True, line=line_no)
        elif text.startswith("filament:"):
            plane.filament = _parse_string(text[9:].strip(), line_no)
        elif text.startswith("signals:"):
            plane.signals = _parse_collection(text[8:].strip(), brace_delim="[]", line=line_no)
        elif text.startswith("next:"):
            plane.next_actions = _parse_collection(text[5:].strip(), brace_delim="[]", line=line_no)
        elif text.startswith("blockers:"):
            plane.blockers = _parse_collection(text[9:].strip(), brace_delim="[]", line=line_no)
        else:
            raise QloomSyntaxError(f"Unknown @pulse attribute {text!r}", line_no)
    return plane


def _brace_delta(line_text: str) -> int:
    in_str = False
    esc = False
    delta = 0
    for ch in line_text:
        if esc:
            esc = False
        elif ch == "\\" and in_str:
            esc = True
        elif ch == '"':
            in_str = not in_str
        elif not in_str:
            delta += 1 if ch == "{" else -1 if ch == "}" else 0
    return delta


def _extract_plane_body(
    cleaned_lines: list[tuple[int, str]], start_idx: int, plane_name: str, open_line: int
) -> tuple[list[tuple[int, str]], int]:
    brace_depth = 1
    idx = start_idx
    body_lines: list[tuple[int, str]] = []
    while idx < len(cleaned_lines) and brace_depth > 0:
        b_line_no, b_text = cleaned_lines[idx]
        brace_depth += _brace_delta(b_text)
        if brace_depth == 0:
            if b_text != "}":
                raise QloomSyntaxError(
                    "Closing plane brace '}' must sit on its own line", b_line_no
                )
            return body_lines, idx + 1
        body_lines.append((b_line_no, b_text))
        idx += 1
    raise QloomSyntaxError(f"Unclosed @{plane_name} plane", open_line)


def _parse_seal_line(text_line: str, line_no: int) -> ReconciliationSeal:
    kv = _parse_kv_pairs(_split_top_level(text_line)[1:], line_no)
    rec_str = kv.get("reconciled", "true")
    if rec_str not in ("true", "false"):
        raise QloomSyntaxError(f"Invalid reconciled boolean {rec_str!r}", line_no)
    return ReconciliationSeal(
        knot=_parse_string(kv["knot"], line_no),
        sha256=_parse_string(kv["sha256"], line_no),
        reconciled=(rec_str == "true"),
    )


def _assign_plane(
    doc: QloomDocument, plane_name: str, plane_args: str, body: list[tuple[int, str]], line_no: int
) -> None:
    if plane_name == "weave":
        kv = _parse_kv_pairs(_split_top_level(plane_args), line_no) if plane_args else {}
        doc.weave = _parse_weave_lines(kv.get("mode", "inherit"), body, line_no)
        return
    assigners: dict[str, tuple[str, Callable[[list[tuple[int, str]]], Any]]] = {
        "charter": ("charter", _parse_charter_lines),
        "lattice": ("lattice", _parse_lattice_lines),
        "contracts": ("contracts", _parse_contracts_lines),
        "vault": ("vault", _parse_vault_lines),
        "pulse": ("pulse", _parse_pulse_lines),
    }
    entry = assigners.get(plane_name)
    if entry is None:
        raise QloomSyntaxError(f"Unknown QLOOM plane '@{plane_name}'", line_no)
    setattr(doc, entry[0], entry[1](body))


def _parse_plane_statement(
    doc: QloomDocument,
    cleaned: list[tuple[int, str]],
    idx: int,
    line_no: int,
    text_line: str,
) -> int:
    if not text_line.startswith("@"):
        raise QloomSyntaxError(
            f"Expected plane block '@...' or seal '=~', got {text_line!r}", line_no
        )
    m_plane = re.match(r"^@([a-z]+)(?:\s+(.+?))?\s*\{$", text_line)
    if not m_plane:
        raise QloomSyntaxError(f"Malformed plane header {text_line!r}", line_no)
    plane_name = m_plane.group(1)
    plane_args = (m_plane.group(2) or "").strip()
    body, next_idx = _extract_plane_body(cleaned, idx + 1, plane_name, line_no)
    _assign_plane(doc, plane_name, plane_args, body, line_no)
    return next_idx


def _tokenize_qloom_lines(text: str) -> list[tuple[int, str]]:
    if not isinstance(text, str):
        raise QloomSyntaxError("QLOOM input must be str")
    if "\x00" in text:
        raise QloomSyntaxError("Null byte rejected in QLOOM payload")
    raw_bytes = len(text.encode("utf-8"))
    if raw_bytes > MAX_QLOOM_BYTES:
        raise QloomSyntaxError(f"QLOOM payload exceeds MAX_QLOOM_BYTES ({raw_bytes})")
    cleaned = [(i, _strip_comment(r).strip()) for i, r in enumerate(text.splitlines(), 1)]
    non_empty = [(i, s) for i, s in cleaned if s]
    if not non_empty:
        raise QloomSyntaxError("Empty QLOOM document")
    return non_empty


def parse_qloom(text: str) -> QloomDocument:
    """Parses QLOOM/2.0 or QLOOM/1.0 wire text into a typed QloomDocument AST."""
    cleaned = _tokenize_qloom_lines(text)
    hdr = _parse_header_line(cleaned[0][1], cleaned[0][0])
    doc = QloomDocument(**hdr)
    idx = 1
    while idx < len(cleaned):
        line_no, text_line = cleaned[idx]
        if text_line.startswith("=~ "):
            if idx != len(cleaned) - 1:
                raise QloomSyntaxError("Reconciliation seal '=~' must be the final line", line_no)
            doc.seal = _parse_seal_line(text_line, line_no)
            idx += 1
            continue
        idx = _parse_plane_statement(doc, cleaned, idx, line_no, text_line)
    return doc


def _format_relation_check(chk: RelationCheck) -> str:
    if chk.kind == "count":
        return f"^count={chk.expected}"
    if chk.kind == "sum":
        slc = f", {chk.start_row}..{chk.end_row}" if chk.start_row is not None else ""
        return f"^sum({chk.column}{slc})={chk.expected}"
    if chk.kind == "net":
        return f"^net({chk.column}, {chk.extra_column})={chk.expected}"
    return f"^{chk.kind}({chk.column}, pct={chk.pct})={chk.expected}"


def _serialize_header(doc: QloomDocument) -> str:
    parts = [
        f"~= {doc.version}",
        f"id={json.dumps(doc.doc_id, ensure_ascii=False)}",
        f"tier={doc.tier.value}",
        f"state={doc.state}",
        f"parent={json.dumps(doc.parent, ensure_ascii=False)}",
        f"epoch={doc.epoch}",
    ]
    if doc.version == QLOOM_V2:
        if doc.admin is not None:
            parts.append(f"admin={doc.admin.value}")
        if doc.tag is not None:
            parts.append(f"tag={json.dumps(doc.tag, ensure_ascii=False)}")
        if doc.hub is not None:
            parts.append(f"hub={json.dumps(doc.hub, ensure_ascii=False)}")
    return " ".join(parts)


def _format_budget_lock(lock: CharterLock, is_v2: bool) -> str:
    pairs: list[tuple[str, Any]] = [("tokens<=", lock.max_tokens), ("chars<=", lock.max_chars)]
    if is_v2:
        pairs.extend(
            [
                ("cost_usd<=", lock.max_cost_usd),
                ("retries<=", lock.max_retries),
                ("tol_pct<=", lock.tol_pct),
            ]
        )
    parts = [f"{prefix}{val}" for prefix, val in pairs if val is not None]
    return f"  lock {lock.lock_id}: budget {' '.join(parts)}"


def _serialize_charter(doc: QloomDocument, lines: list[str]) -> None:
    lines.append("@charter {")
    if doc.charter.goal:
        lines.append(f"  goal: {json.dumps(doc.charter.goal, ensure_ascii=False)}")
    for lock in doc.charter.locks:
        if lock.kind == "forbid":
            code = json.dumps(lock.forbid_code, ensure_ascii=False)
            lines.append(f"  lock {lock.lock_id}: forbid {code}")
        else:
            lines.append(_format_budget_lock(lock, doc.version == QLOOM_V2))
    for m in doc.charter.mandates:
        stmt_json = json.dumps(m.statement, ensure_ascii=False)
        lines.append(f"  mandate {m.mandate_id}: must {stmt_json}")
    lines.append("}")


def _serialize_relation_block(rel: RelationTable, is_v2: bool, lines: list[str]) -> None:
    cols_str = ", ".join(f"{c.name}:{c.col_type}" for c in rel.columns)
    chk_str = (
        " " + " ".join(_format_relation_check(c) for c in rel.checks)
        if (is_v2 and rel.checks)
        else ""
    )
    lines.append(f"  relation {rel.name}({cols_str}){chk_str} {{")
    spacer_set = set(rel.spacer_indices) if is_v2 else set()
    for r_idx, row in enumerate(rel.rows):
        if r_idx in spacer_set:
            lines.append("    ---")
        formatted = " | ".join(
            _format_cell(val, col.col_type) for val, col in zip(row, rel.columns, strict=True)
        )
        lines.append(f"    {formatted}")
    lines.append("  }")


def _serialize_lattice(doc: QloomDocument, lines: list[str]) -> None:
    if not doc.lattice.relations:
        return
    lines.extend(["", "@lattice {"])
    is_v2 = doc.version == QLOOM_V2
    for rel in doc.lattice.relations:
        _serialize_relation_block(rel, is_v2, lines)
    lines.append("}")


def _serialize_weave_node(node: WeaveNode, is_v2: bool) -> str:
    deps_s = ", ".join(node.deps)
    reads_s = ", ".join(json.dumps(r, ensure_ascii=False) for r in node.reads)
    writes_s = ", ".join(json.dumps(w, ensure_ascii=False) for w in node.writes)
    v2_bits: list[str] = []
    if is_v2:
        if node.face is not None:
            v2_bits.append(f"face={node.face.value}")
        if node.weight is not None:
            v2_bits.append(f"weight={node.weight.value}")
    extra = (" " + " ".join(v2_bits)) if v2_bits else ""
    return (
        f"  node {node.node_id} spin={node.spin.value}{extra} state={node.state} "
        f"deps=[{deps_s}] R={{{reads_s}}} W={{{writes_s}}} -> {node.lifecycle.value}"
    )


def _serialize_weave(doc: QloomDocument, lines: list[str]) -> None:
    if not (doc.weave.nodes or doc.weave.mode != WorkspaceMode.INHERIT):
        return
    lines.extend(["", f"@weave mode={doc.weave.mode.value} {{"])
    is_v2 = doc.version == QLOOM_V2
    for node in doc.weave.nodes:
        lines.append(_serialize_weave_node(node, is_v2))
    lines.append("}")


def _serialize_contracts(doc: QloomDocument, lines: list[str]) -> None:
    if not doc.contracts.clauses:
        return
    lines.extend(["", "@contracts {"])
    is_v2 = doc.version == QLOOM_V2
    for clause in doc.contracts.clauses:
        req_s = ", ".join(f"->{r}" for r in clause.requires)
        argv_s = ", ".join(json.dumps(a, ensure_ascii=False) for a in clause.witness_argv)
        lines.append(f"  clause {clause.clause_id} {{")
        lines.append(f"    requires: [{req_s}]")
        lines.append(f"    ensures: {json.dumps(clause.ensures, ensure_ascii=False)}")
        lines.append(f"    witness_argv: [{argv_s}]")
        if is_v2 and clause.timeout_s is not None:
            lines.append(f"    timeout_s: {clause.timeout_s}")
        if is_v2 and clause.rollback_argv:
            rb_s = ", ".join(json.dumps(a, ensure_ascii=False) for a in clause.rollback_argv)
            lines.append(f"    rollback_argv: [{rb_s}]")
        lines.append("  }")
    lines.append("}")


def _serialize_vault(doc: QloomDocument, lines: list[str]) -> None:
    if not doc.vault.blobs:
        return
    lines.extend(["", "@vault {"])
    for blob in doc.vault.blobs:
        wrap_s = (
            f" wrap={json.dumps(blob.wrap, ensure_ascii=False)}"
            if (doc.version == QLOOM_V2 and blob.wrap is not None)
            else ""
        )
        lines.append(
            f"  blob {blob.blob_id} tier={blob.tier} "
            f"sha256={json.dumps(blob.sha256, ensure_ascii=False)} bytes={blob.size_bytes} "
            f"origin={json.dumps(blob.origin, ensure_ascii=False)} "
            f"uri={json.dumps(blob.uri, ensure_ascii=False)}{wrap_s}"
        )
    lines.append("}")


def _serialize_pulse(doc: QloomDocument, lines: list[str]) -> None:
    lines.extend(["", "@pulse {"])
    lines.append(f"  focus: {'_' if doc.pulse.focus is None else '->' + doc.pulse.focus}")
    if doc.pulse.filament:
        lines.append(f"  filament: {json.dumps(doc.pulse.filament, ensure_ascii=False)}")
    if doc.pulse.signals:
        sig_s = ", ".join(json.dumps(s, ensure_ascii=False) for s in doc.pulse.signals)
        lines.append(f"  signals: [{sig_s}]")
    next_s = ", ".join(json.dumps(n, ensure_ascii=False) for n in doc.pulse.next_actions)
    blk_s = ", ".join(json.dumps(b, ensure_ascii=False) for b in doc.pulse.blockers)
    lines.append(f"  next: [{next_s}]")
    lines.append(f"  blockers: [{blk_s}]")
    lines.append("}")


def serialize_body(doc: QloomDocument) -> str:
    """Renders canonical QLOOM planes without the trailing reconciliation seal line."""
    lines: list[str] = [_serialize_header(doc), ""]
    _serialize_charter(doc, lines)
    _serialize_lattice(doc, lines)
    _serialize_weave(doc, lines)
    _serialize_contracts(doc, lines)
    _serialize_vault(doc, lines)
    _serialize_pulse(doc, lines)
    return "\n".join(lines)


def compute_seal(doc: QloomDocument) -> ReconciliationSeal:
    """Computes the deterministic SHA-256 knot seal over the canonical body."""
    body = serialize_body(doc)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    prefix = "quipu" if doc.version == QLOOM_V1 else "qloom"
    return ReconciliationSeal(knot=f"{prefix}-{digest[:12]}", sha256=digest, reconciled=True)


def dump_qloom(doc: QloomDocument, *, recompute_seal: bool = True) -> str:
    """Serializes a QloomDocument AST into canonical QLOOM wire format."""
    body = serialize_body(doc)
    seal = compute_seal(doc) if recompute_seal or doc.seal is None else doc.seal
    if recompute_seal:
        doc.seal = seal
    rec_str = "true" if seal.reconciled else "false"
    seal_line = (
        f"=~ knot={json.dumps(seal.knot, ensure_ascii=False)} "
        f"sha256={json.dumps(seal.sha256, ensure_ascii=False)} reconciled={rec_str}"
    )
    return f"{body}\n\n{seal_line}\n"


def loads_qloom(text: str) -> dict[str, Any]:
    """Parses QLOOM wire text into a structured AST dictionary."""
    return parse_qloom(text).to_dict()


def dumps_qloom(doc_or_dict: QloomDocument | dict[str, Any], *, recompute_seal: bool = True) -> str:
    """Serializes a QloomDocument or AST dictionary into canonical QLOOM wire text."""
    doc = QloomDocument.from_dict(doc_or_dict) if isinstance(doc_or_dict, dict) else doc_or_dict
    return dump_qloom(doc, recompute_seal=recompute_seal)


def load(fp_or_path: IO[str] | str | Path) -> QloomDocument:
    """Loads and parses a QloomDocument from a file path or readable text stream."""
    if isinstance(fp_or_path, (str, Path)):
        text = Path(fp_or_path).read_text(encoding="utf-8")
    else:
        text = fp_or_path.read()
    return parse_qloom(text)


def dump_file(
    doc: QloomDocument, fp_or_path: IO[str] | str | Path, *, recompute_seal: bool = True
) -> int:
    """Serializes a QloomDocument to a file path or writable text stream."""
    wire = dump_qloom(doc, recompute_seal=recompute_seal)
    if isinstance(fp_or_path, (str, Path)):
        return Path(fp_or_path).write_text(wire, encoding="utf-8")
    return fp_or_path.write(wire)


def _should_drop_row(row_mod: str, row_tier: str, tier: Tier) -> bool:
    if tier in (Tier.L1, Tier.L2, Tier.L3) and row_mod == EpistemicModality.SUPERSEDED.value:
        return True
    return tier in (Tier.L1, Tier.L2) and row_tier in ("T2", "T3")


def _prune_relation(rel: RelationTable, tier: Tier, dropped_ids: set[str]) -> RelationTable:
    id_idx = next((i for i, c in enumerate(rel.columns) if c.col_type == "id"), 0)
    mod_idx = rel.column_index("mod")
    tier_idx = rel.column_index("tier")
    spacer_set = set(rel.spacer_indices)
    filtered_rows: list[list[Any]] = []
    kept_spacers: list[int] = []
    for r_idx, row in enumerate(rel.rows):
        row_mod = str(row[mod_idx]) if mod_idx is not None else "verified"
        row_tier = str(row[tier_idx]) if tier_idx is not None else "T0"
        if _should_drop_row(row_mod, row_tier, tier):
            dropped_ids.add(str(row[id_idx]))
            continue
        if r_idx in spacer_set and filtered_rows:
            kept_spacers.append(len(filtered_rows))
        filtered_rows.append(list(row))
    kept_checks = [] if len(filtered_rows) != len(rel.rows) else list(rel.checks)
    return RelationTable(
        name=rel.name,
        columns=list(rel.columns),
        rows=filtered_rows,
        checks=kept_checks,
        spacer_indices=kept_spacers,
    )


def _prune_lattice_for_tier(lattice: LatticePlane, tier: Tier) -> LatticePlane:
    dropped_ids: set[str] = set()
    kept_relations = [_prune_relation(rel, tier, dropped_ids) for rel in lattice.relations]
    if dropped_ids:
        for rel in kept_relations:
            ref_opt = [i for i, col in enumerate(rel.columns) if col.col_type == "ref?"]
            for row in rel.rows:
                for col_i in ref_opt:
                    if row[col_i] in dropped_ids:
                        row[col_i] = None
    return LatticePlane(relations=[r for r in kept_relations if r.rows])


def project_qloom(doc: QloomDocument, target_tier: Tier | str) -> QloomDocument:
    """Projects a QloomDocument onto a target disclosure tier (L0..L4) with parent chaining."""
    tier = target_tier if isinstance(target_tier, Tier) else Tier(str(target_tier))
    parent_knot = (
        doc.seal.knot if doc.seal is not None and doc.seal.knot else compute_seal(doc).knot
    )
    projected = QloomDocument(
        doc_id=doc.doc_id,
        tier=tier,
        state=doc.state,
        parent=parent_knot,
        epoch=doc.epoch,
        version=doc.version,
        admin=doc.admin,
        tag=doc.tag,
        hub=doc.hub,
        charter=copy.deepcopy(doc.charter),
        pulse=copy.deepcopy(doc.pulse),
    )
    if tier in (Tier.L1, Tier.L2, Tier.L3):
        projected.lattice = _prune_lattice_for_tier(doc.lattice, tier)
    elif tier == Tier.L4:
        projected.lattice = copy.deepcopy(doc.lattice)
    if tier in (Tier.L2, Tier.L3, Tier.L4):
        projected.weave = copy.deepcopy(doc.weave)
        projected.contracts = copy.deepcopy(doc.contracts)
    if tier in (Tier.L3, Tier.L4):
        projected.vault = copy.deepcopy(doc.vault)
    projected.seal = compute_seal(projected)
    return projected


def _ascii_loom_header(doc: QloomDocument) -> str:
    knot = doc.seal.knot if doc.seal else "unsealed"
    meta = [f"tier={doc.tier.value}", f"state={doc.state}", f"epoch={doc.epoch}"]
    if doc.admin:
        meta.append(f"admin={doc.admin.value}")
    if doc.tag:
        meta.append(f"tag={doc.tag}")
    if doc.hub:
        meta.append(f"hub={doc.hub}")
    return f"=== {doc.version}: {doc.doc_id} [{' '.join(meta)} | knot={knot}] ==="


def _ascii_charter_lines(doc: QloomDocument, lines: list[str]) -> None:
    goal = doc.charter.goal or "(no goal)"
    lines.append(f"  ├─ @charter  goal: {goal}")
    if doc.charter.locks:
        lock_tags = ", ".join(lk.lock_id for lk in doc.charter.locks)
        lines.append(f"  │            locks=[{lock_tags}] mandates={len(doc.charter.mandates)}")


def _ascii_lattice_lines(doc: QloomDocument, lines: list[str], max_rows: int) -> None:
    if not doc.lattice.relations:
        return
    lines.append("  ├─ @lattice")
    for rel in doc.lattice.relations:
        chk = f" {' '.join(_format_relation_check(c) for c in rel.checks)}" if rel.checks else ""
        lines.append(f"  │   ├── relation {rel.name} ({len(rel.rows)} rows){chk}")
        for idx, row in enumerate(rel.rows[:max_rows]):
            cells = " | ".join(
                _format_cell(v, c.col_type) for v, c in zip(row, rel.columns, strict=True)
            )
            lines.append(f"  │   │   [{idx}] {cells}")
        if len(rel.rows) > max_rows:
            lines.append(f"  │   │   ... (+{len(rel.rows) - max_rows} more rows)")


def _ascii_weave_lines(doc: QloomDocument, lines: list[str]) -> None:
    if not doc.weave.nodes:
        return
    lines.append(f"  ├─ @weave (mode={doc.weave.mode.value})")
    for idx, n in enumerate(doc.weave.nodes):
        branch = "└──" if idx == len(doc.weave.nodes) - 1 else "├──"
        face_s = f" {n.face.value}" if n.face else ""
        wt_s = f" {n.weight.value}" if n.weight else ""
        deps_s = f" deps=[{','.join(n.deps)}]" if n.deps else ""
        lines.append(
            f"  │   {branch} [{n.lifecycle.value}] {n.node_id} (spin={n.spin.value}{face_s}{wt_s})"
            f"{deps_s} R={len(n.reads)} W={len(n.writes)}"
        )


def _ascii_tail_lines(doc: QloomDocument, lines: list[str]) -> None:
    if doc.contracts.clauses:
        c_ids = ", ".join(c.clause_id for c in doc.contracts.clauses)
        lines.append(f"  ├─ @contracts clauses=[{c_ids}]")
    if doc.vault.blobs:
        v_ids = ", ".join(f"{b.blob_id}({b.tier})" for b in doc.vault.blobs)
        lines.append(f"  ├─ @vault    quarantined=[{v_ids}]")
    focus = f"->{doc.pulse.focus}" if doc.pulse.focus else "_"
    lines.append(
        f"  └─ @pulse    focus={focus} "
        f"next={len(doc.pulse.next_actions)} blockers={len(doc.pulse.blockers)}"
    )


def render_qloom_ascii(
    doc_or_text: QloomDocument | str,
    *,
    max_rows: int = 5,
    max_chars: int = MAX_ASCII_CHARS,
) -> str:
    """Renders a compact 6-plane ASCII state & execution DAG diagram for terminal output."""
    doc = parse_qloom(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    lines = [_ascii_loom_header(doc), "═" * 84]
    _ascii_charter_lines(doc, lines)
    _ascii_lattice_lines(doc, lines, max_rows)
    _ascii_weave_lines(doc, lines)
    _ascii_tail_lines(doc, lines)
    lines.append("═" * 84)
    out = "\n".join(lines)
    if len(out) > max_chars:
        return out[: max(64, max_chars - 32)] + "\n... [TRUNCATED_TO_MAX_ASCII_CHARS]"
    return out


draw_qloom = render_qloom_ascii
parse = parse_qloom
dump = dump_qloom
loads = loads_qloom
dumps = dumps_qloom
project = project_qloom
draw = render_qloom_ascii
