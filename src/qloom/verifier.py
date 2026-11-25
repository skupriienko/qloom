"""qloom.verifier — Pure-Stdlib 8-Law (QLOOM/1.0) & 10-Law (QLOOM/2.0) Verification Engine.

Verifies:
1. LAW_01_KNOT_SEAL: SHA-256 Merkle knot seal integrity (`quipu-*` for v1, `qloom-*` for v2)
2. LAW_02_CONTENT_SAFETY: Zero NUL/bidi trojans, private keys, tokens, or destructive shell cmds
3. LAW_03_SAFE_ARGV: CWE-78 safe subprocess witness & rollback argv guarantees
4. LAW_04_TAINT_LATTICE: T0-T3 non-interference taint isolation
5. LAW_05_SPIN_AND_BERNSTEIN: Spin S/Z dualism, R/V face isolation, AgentState & Bernstein R/W sets
6. LAW_06_DAG_AND_REFS: Causal DAG / supersession acyclicity & reference closure
7. LAW_07_CLARITY_AND_CEILING: Concise English clarity lint, 8,000-char ceiling & Charter budgets
8. LAW_08_WIRE_EFFICIENCY: Wire compactness vs equivalent JSON representation
9. LAW_09_RELATION_ARITHMETIC (QLOOM/2.0): Row bounds, band spacers, ^count/^sum/^tol/^net/^quota
10. LAW_10_LINEAGE_AND_SAGA_BOUNDS (QLOOM/2.0): Parent knot format, tags, timeouts, working cap
"""

from __future__ import annotations

import json
import math
import re
from collections import deque
from typing import Any

from .ast_nodes import (
    MAX_WORKING_ROWS,
    QLOOM_V2,
    AdminWindow,
    AgentState,
    AttachFace,
    CharterLock,
    CharterMandate,
    CharterPlane,
    ColumnSpec,
    ContractClause,
    ContractsPlane,
    LatticePlane,
    NodeLifecycle,
    NodeWeight,
    PulsePlane,
    QloomDocument,
    QloomSyntaxError,
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
from .codec import compute_seal, dump_qloom, parse_qloom

MAX_WIRE_CHARS = 8_000
_MAX_SAFETY_INSPECT_CHARS = 262_144

_VALID_AGENT_STATES: frozenset[str] = frozenset(s.value for s in AgentState)
_SHELL_META_RE = re.compile(r"[;|&$`><\n\r]")
_SHELL_INTERPRETERS = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell"}
)
_PARENT_KNOT_RE = re.compile(r"^(?:[a-z][a-z0-9_]{1,15}-[0-9a-f]{12}|none)$")
_SAFE_TAG_RE = re.compile(r"^[A-Za-z0-9_.\-/: ]{1,64}$")

_BIDI_TROJAN_CHARS = frozenset(
    {
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


def _build_safety_rules() -> tuple[tuple[str, re.Pattern[str]], ...]:
    pem_pat = "-----" + "BEGIN (?:RSA |EC |DSA |OPENSSH |PRIVATE )?PRIVATE " + "KEY-----"
    gh_prefixes = "|".join(("gh" + "p", "gh" + "o", "gh" + "u", "gh" + "s", "gh" + "r"))
    tok_pat = (
        r"(?:\b(?:" + gh_prefixes + r")_[A-Za-z0-9_]{36,255}\b"
        r"|\bgithub_" + r"pat_[A-Za-z0-9_]{22,255}\b"
        r"|\bAI" + r"za[0-9A-Za-z\-_]{35}\b"
        r"|\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,255}\b"
        r"|\bxox[baprs]-[0-9A-Za-z\-]{24,255}\b"
        r"|\b(?:AK" + r"IA|AS" + r"IA)[0-9A-Z]{16}\b)"
    )
    dev_prefix = "/de" + "v/"
    power_cmds = "|".join(("shut" + "down", "re" + "boot", "power" + "off"))
    rm_pat = (
        r"\b" + "rm" + r"\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+|--recursive\s+|--force\s+)+/(?:\s|$|\*)"
    )
    mkfs_pat = r"\b" + "mk" + r"fs(?:\.[a-z0-9]+)?\s+" + dev_prefix
    dd_pat = (
        r"\bdd\s+[^\n]{0,120}\bof=" + dev_prefix + r"(?:sd[a-z]|nvme[0-9a-z]+|vd[a-z]|disk[0-9]+)"
    )
    subproc_pat = r"\bsubprocess\.[A-Za-z_]+\s*\([^\n]{0,200}\bshell\s*=\s*True\b"
    shell_pat = f"(?i)(?:{rm_pat}|{mkfs_pat}|{dd_pat}|\\b(?:{power_cmds})\\b|{subproc_pat})"
    return (
        ("Exposed private key PEM header", re.compile(pem_pat)),
        ("Exposed API token or credential prefix", re.compile(tok_pat)),
        ("Destructive host shell command pattern", re.compile(shell_pat)),
    )


_SAFETY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = _build_safety_rules()

_FLUFF_WORDS: frozenset[str] = frozenset(
    {
        "delve",
        "testament",
        "tapestry",
        "seamless",
        "crucial",
        "paramount",
        "furthermore",
        "meticulously",
        "spearhead",
        "robust",
        "leverage",
        "utilize",
        "pivotal",
        "game-changer",
        "beacon",
        "unwavering",
        "multifaceted",
    }
)

_PASSIVE_INDICATORS: tuple[str, ...] = (
    "is being",
    "was being",
    "has been",
    "have been",
    "had been",
    "will be",
    "is done by",
    "was done by",
    "are created by",
    "were created by",
)


def _add_finding(
    findings: list[dict[str, str]], law: str, plane: str, message: str, severity: str = "error"
) -> None:
    findings.append({"law": law, "plane": plane, "severity": severity, "message": message})


def _check_cycles(nodes: set[str], edges: dict[str, list[str]]) -> list[str]:
    """Detects cycle participants in a directed graph via Kahn's algorithm."""
    indegree: dict[str, int] = dict.fromkeys(nodes, 0)
    adj: dict[str, list[str]] = {n: [] for n in nodes}
    for src, targets in edges.items():
        for dst in targets:
            if src in adj and dst in indegree:
                adj[src].append(dst)
                indegree[dst] += 1
    queue = deque(sorted(n for n, deg in indegree.items() if deg == 0))
    visited = 0
    while queue:
        cur = queue.popleft()
        visited += 1
        for nxt in adj[cur]:
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                queue.append(nxt)
    return [] if visited == len(nodes) else sorted(n for n, deg in indegree.items() if deg > 0)


def _compute_ancestors(node_ids: set[str], deps_map: dict[str, list[str]]) -> dict[str, set[str]]:
    ancestors: dict[str, set[str]] = {}
    for nid in node_ids:
        seen: set[str] = set()
        stack = list(deps_map.get(nid, []))
        while stack:
            cur = stack.pop()
            if cur in seen or cur not in node_ids:
                continue
            seen.add(cur)
            stack.extend(deps_map.get(cur, []))
        ancestors[nid] = seen
    return ancestors


def _collect_tainted_ids(doc: QloomDocument) -> set[str]:
    tainted: set[str] = {b.blob_id for b in doc.vault.blobs}
    for rel in doc.lattice.relations:
        id_idx = next((i for i, c in enumerate(rel.columns) if c.col_type == "id"), 0)
        tier_idx = rel.column_index("tier")
        if tier_idx is not None:
            for row in rel.rows:
                if str(row[tier_idx]) in ("T2", "T3"):
                    tainted.add(str(row[id_idx]))
    return tainted


def _check_law01_seal(doc: QloomDocument, findings: list[dict[str, str]]) -> None:
    expected = compute_seal(doc)
    if doc.seal is None:
        _add_finding(findings, "LAW_01_KNOT_SEAL", "seal", "Missing ReconciliationSeal '=~'")
        return
    if doc.seal.sha256 != expected.sha256:
        _add_finding(
            findings,
            "LAW_01_KNOT_SEAL",
            "seal",
            f"SHA-256 mismatch: declared {doc.seal.sha256[:12]}... != {expected.sha256[:12]}...",
        )
    if doc.seal.knot != expected.knot:
        _add_finding(
            findings,
            "LAW_01_KNOT_SEAL",
            "seal",
            f"Knot mismatch: declared {doc.seal.knot} != expected {expected.knot}",
        )
    if not doc.seal.reconciled:
        _add_finding(findings, "LAW_01_KNOT_SEAL", "seal", "Document seal marked reconciled=false")


def _check_law02_content_safety(wire_text: str, findings: list[dict[str, str]]) -> None:
    sample = wire_text[:_MAX_SAFETY_INSPECT_CHARS]
    if "\x00" in sample:
        _add_finding(findings, "LAW_02_CONTENT_SAFETY", "global", "NUL byte detected in payload")
    if any(ch in _BIDI_TROJAN_CHARS for ch in sample):
        _add_finding(
            findings,
            "LAW_02_CONTENT_SAFETY",
            "global",
            "Bidirectional Unicode control character detected",
        )
    for label, pattern in _SAFETY_RULES:
        if pattern.search(sample):
            _add_finding(findings, "LAW_02_CONTENT_SAFETY", "global", label)


def _validate_argv_list(
    argv: list[str], clause_id: str, label: str, findings: list[dict[str, str]]
) -> None:
    exe = argv[0].strip()
    if not exe or any(ch.isspace() for ch in exe) or _SHELL_META_RE.search(exe):
        _add_finding(
            findings,
            "LAW_03_SAFE_ARGV",
            "contracts",
            f"Clause {clause_id} invalid {label}[0]={exe!r}",
        )
    base_exe = exe.rsplit("/", 1)[-1].lower()
    if base_exe in _SHELL_INTERPRETERS and len(argv) > 1 and argv[1] in ("-c", "/c", "-Command"):
        _add_finding(
            findings,
            "LAW_03_SAFE_ARGV",
            "contracts",
            f"Clause {clause_id} {label} uses shell command wrapper {argv[:2]}",
        )


def _check_law03_safe_argv(doc: QloomDocument, findings: list[dict[str, str]]) -> None:
    for clause in doc.contracts.clauses:
        if not clause.witness_argv:
            _add_finding(
                findings,
                "LAW_03_SAFE_ARGV",
                "contracts",
                f"Clause {clause.clause_id} missing non-empty witness_argv list",
            )
        else:
            _validate_argv_list(clause.witness_argv, clause.clause_id, "witness_argv", findings)
        if clause.rollback_argv:
            _validate_argv_list(clause.rollback_argv, clause.clause_id, "rollback_argv", findings)


def _check_relation_taint(
    rel: RelationTable, tainted_ids: set[str], findings: list[dict[str, str]]
) -> None:
    tier_idx = rel.column_index("tier")
    if tier_idx is None:
        return
    id_idx = next((i for i, c in enumerate(rel.columns) if c.col_type == "id"), 0)
    ref_cols = [i for i, c in enumerate(rel.columns) if c.col_type in ("ref", "ref?")]
    for row in rel.rows:
        if str(row[tier_idx]) not in ("T0", "T1"):
            continue
        for rc in ref_cols:
            target = row[rc]
            if target and str(target) in tainted_ids:
                _add_finding(
                    findings,
                    "LAW_04_TAINT_LATTICE",
                    "lattice",
                    f"Trusted {row[tier_idx]} row {row[id_idx]} references tainted ->{target}",
                )


def _check_law04_taint(doc: QloomDocument, findings: list[dict[str, str]]) -> None:
    tainted_ids = _collect_tainted_ids(doc)
    for clause in doc.contracts.clauses:
        for req in clause.requires:
            if req in tainted_ids:
                _add_finding(
                    findings,
                    "LAW_04_TAINT_LATTICE",
                    "contracts",
                    f"Clause {clause.clause_id} depends on tainted T2/T3 entity ->{req}",
                )
    if doc.pulse.focus and doc.pulse.focus in tainted_ids:
        _add_finding(
            findings,
            "LAW_04_TAINT_LATTICE",
            "pulse",
            f"@pulse focus points to tainted T2/T3 entity ->{doc.pulse.focus}",
        )
    for rel in doc.lattice.relations:
        _check_relation_taint(rel, tainted_ids, findings)


def _pair_bernstein_hazards(n1: WeaveNode, n2: WeaveNode) -> list[dict[str, Any]]:
    """Checks Bernstein's three disjointness invariants between two WeaveNodes."""
    r1 = {r.strip() for r in n1.reads if r.strip()}
    w1 = {w.strip() for w in n1.writes if w.strip()}
    r2 = {r.strip() for r in n2.reads if r.strip()}
    w2 = {w.strip() for w in n2.writes if w.strip()}
    pairs = (
        ("WRITE_WRITE_HAZARD", sorted(w1 & w2)),
        ("READ_WRITE_HAZARD", sorted(r1 & w2)),
        ("WRITE_READ_HAZARD", sorted(w1 & r2)),
    )
    return [
        {"type": kind, "nodes": (n1.node_id, n2.node_id), "overlapping_paths": paths}
        for kind, paths in pairs
        if paths
    ]


def find_concurrent_conflicts(nodes: list[WeaveNode]) -> list[dict[str, Any]]:
    """Finds pairwise Bernstein R/W hazards among unordered PENDING/ACTIVE weave nodes."""
    ancestors = _compute_ancestors(
        {n.node_id for n in nodes}, {n.node_id: list(n.deps) for n in nodes}
    )
    active = [n for n in nodes if n.lifecycle in (NodeLifecycle.PENDING, NodeLifecycle.ACTIVE)]
    conflicts: list[dict[str, Any]] = []
    for i, n1 in enumerate(active):
        for n2 in active[i + 1 :]:
            ordered = (n1.node_id in ancestors.get(n2.node_id, set())) or (
                n2.node_id in ancestors.get(n1.node_id, set())
            )
            if not ordered:
                conflicts.extend(_pair_bernstein_hazards(n1, n2))
    return conflicts


def _check_weave_node_spin_and_state(
    node: WeaveNode, mode: WorkspaceMode, findings: list[dict[str, str]]
) -> None:
    if node.spin == Spin.Z and node.writes:
        _add_finding(
            findings,
            "LAW_05_SPIN_AND_BERNSTEIN",
            "weave",
            f"Z-spin (read-only) node {node.node_id} declares writes {node.writes}",
        )
    if node.face == AttachFace.VERSO and mode == WorkspaceMode.SHARE and node.writes:
        _add_finding(
            findings,
            "LAW_05_SPIN_AND_BERNSTEIN",
            "weave",
            f"Shadow/canary node {node.node_id} (face=V) forbids writes in mode=share",
        )
    if node.state not in _VALID_AGENT_STATES:
        _add_finding(
            findings,
            "LAW_05_SPIN_AND_BERNSTEIN",
            "weave",
            f"Node {node.node_id} declares invalid AgentState {node.state!r}",
        )


def _check_law05_spin_bernstein(doc: QloomDocument, findings: list[dict[str, str]]) -> int:
    if doc.state not in _VALID_AGENT_STATES:
        _add_finding(
            findings, "LAW_05_SPIN_AND_BERNSTEIN", "header", f"Unknown AgentState {doc.state!r}"
        )
    nodes = doc.weave.nodes
    for node in nodes:
        _check_weave_node_spin_and_state(node, doc.weave.mode, findings)
    if doc.weave.mode == WorkspaceMode.INHERIT and any(n.writes for n in nodes):
        _add_finding(
            findings,
            "LAW_05_SPIN_AND_BERNSTEIN",
            "weave",
            "@weave mode=inherit forbids write sets; use mode=share or mode=branch",
        )
    conflicts = find_concurrent_conflicts(nodes)
    if conflicts and doc.weave.mode == WorkspaceMode.SHARE:
        _add_finding(
            findings,
            "LAW_05_SPIN_AND_BERNSTEIN",
            "weave",
            f"@weave mode=share has {len(conflicts)} concurrent Bernstein hazards: {conflicts[0]}",
        )
    return len(conflicts)


def _check_weave_graph_refs(doc: QloomDocument, findings: list[dict[str, str]]) -> None:
    weave_ids = {n.node_id for n in doc.weave.nodes}
    if len(weave_ids) != len(doc.weave.nodes):
        _add_finding(findings, "LAW_06_DAG_AND_REFS", "weave", "Duplicate node IDs in @weave")
    for n in doc.weave.nodes:
        for d in n.deps:
            if d not in weave_ids:
                _add_finding(
                    findings,
                    "LAW_06_DAG_AND_REFS",
                    "weave",
                    f"Node {n.node_id} depends on undeclared node {d!r}",
                )
    cyc = _check_cycles(weave_ids, {n.node_id: n.deps for n in doc.weave.nodes})
    if cyc:
        _add_finding(
            findings, "LAW_06_DAG_AND_REFS", "weave", f"Cyclic dependency detected in @weave: {cyc}"
        )


def _check_relation_refs_and_supersedes(
    rel: RelationTable, declared: set[str], findings: list[dict[str, str]]
) -> None:
    id_idx = next((i for i, c in enumerate(rel.columns) if c.col_type == "id"), 0)
    sup_idx = rel.column_index("supersedes")
    ref_cols = [i for i, c in enumerate(rel.columns) if c.col_type in ("ref", "ref?")]
    sup_nodes: set[str] = set()
    sup_edges: dict[str, list[str]] = {}
    for row in rel.rows:
        rid = str(row[id_idx])
        sup_nodes.add(rid)
        for rc in ref_cols:
            target = row[rc]
            if target is not None and str(target) not in declared:
                _add_finding(
                    findings,
                    "LAW_06_DAG_AND_REFS",
                    "lattice",
                    f"Relation {rel.name} row {rid} has unresolved ref ->{target}",
                )
        if sup_idx is not None and row[sup_idx] is not None:
            sup_edges.setdefault(rid, []).append(str(row[sup_idx]))
    cyc = _check_cycles(sup_nodes, sup_edges)
    if cyc:
        _add_finding(
            findings,
            "LAW_06_DAG_AND_REFS",
            "lattice",
            f"Cyclic supersedes chain in relation {rel.name}: {cyc}",
        )


def _check_contract_and_focus_refs(
    doc: QloomDocument, declared: set[str], findings: list[dict[str, str]]
) -> list[str]:
    for clause in doc.contracts.clauses:
        for req in clause.requires:
            if req not in declared:
                _add_finding(
                    findings,
                    "LAW_06_DAG_AND_REFS",
                    "contracts",
                    f"Clause {clause.clause_id} has unresolved ref ->{req}",
                )
    if doc.pulse.focus is not None and doc.pulse.focus not in declared:
        if doc.tier in (Tier.L0, Tier.L1) and not doc.weave.nodes:
            return [doc.pulse.focus]
        _add_finding(
            findings,
            "LAW_06_DAG_AND_REFS",
            "pulse",
            f"@pulse focus ->{doc.pulse.focus} does not resolve to any declared ID",
        )
    return []


def _check_law06_dag_refs(doc: QloomDocument, findings: list[dict[str, str]]) -> list[str]:
    declared = doc.declared_ids()
    _check_weave_graph_refs(doc, findings)
    for rel in doc.lattice.relations:
        _check_relation_refs_and_supersedes(rel, declared, findings)
    return _check_contract_and_focus_refs(doc, declared, findings)


def lint_clarity(text: str) -> dict[str, Any]:
    """Pure-stdlib English clarity scorer checking fluff, passive voice, and sentence length."""
    if not text.strip():
        return {
            "score": 100.0,
            "fluff_words_found": [],
            "passive_phrases_found": [],
            "long_sentences": [],
            "sentence_count": 0,
            "word_count": 0,
            "passed": True,
        }
    lowered = text.lower()
    words = re.findall(r"\b[a-zA-Z0-9_\-]+\b", lowered)
    fluff_found = sorted({w for w in words if w in _FLUFF_WORDS})
    passive_found = [p for p in _PASSIVE_INDICATORS if p in lowered]
    sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
    long_sentences = [
        f"{' '.join(s.split()[:6])}... ({len(s.split())} words)"
        for s in sentences
        if len(s.split()) > 25
    ]
    penalties = (len(fluff_found) * 10) + (len(passive_found) * 8) + (len(long_sentences) * 5)
    score = round(max(0.0, min(100.0, 100.0 - penalties)), 1)
    return {
        "score": score,
        "fluff_words_found": fluff_found,
        "passive_phrases_found": passive_found,
        "long_sentences": long_sentences,
        "sentence_count": len(sentences),
        "word_count": len(words),
        "passed": score >= 80.0 and not fluff_found,
    }


def _check_budget_limits(
    lock: CharterLock,
    wire_chars: int,
    est_tokens: int,
    slack: float,
    findings: list[dict[str, str]],
) -> None:
    if lock.max_chars is not None and wire_chars > int(lock.max_chars * slack):
        _add_finding(
            findings,
            "LAW_07_CLARITY_AND_CEILING",
            "charter",
            f"Lock {lock.lock_id} violated: {wire_chars} chars > {lock.max_chars}",
        )
    if lock.max_tokens is not None and est_tokens > int(lock.max_tokens * slack):
        _add_finding(
            findings,
            "LAW_07_CLARITY_AND_CEILING",
            "charter",
            f"Lock {lock.lock_id} violated: ~{est_tokens} tokens > {lock.max_tokens}",
        )


def _check_single_budget_lock(
    lock: CharterLock, wire_chars: int, est_tokens: int, findings: list[dict[str, str]]
) -> None:
    tol_valid = lock.tol_pct is None or (0.0 <= lock.tol_pct <= 100.0)
    if not tol_valid:
        _add_finding(
            findings,
            "LAW_07_CLARITY_AND_CEILING",
            "charter",
            f"Lock {lock.lock_id} invalid tol_pct",
        )
    slack = 1.0 + (lock.tol_pct / 100.0) if (lock.tol_pct is not None and tol_valid) else 1.0
    _check_budget_limits(lock, wire_chars, est_tokens, slack, findings)
    if lock.max_cost_usd is not None and lock.max_cost_usd < 0.0:
        _add_finding(
            findings,
            "LAW_07_CLARITY_AND_CEILING",
            "charter",
            f"Lock {lock.lock_id} negative max_cost_usd",
        )
    if lock.max_retries is not None and lock.max_retries < 0:
        _add_finding(
            findings,
            "LAW_07_CLARITY_AND_CEILING",
            "charter",
            f"Lock {lock.lock_id} negative max_retries",
        )


def _check_law07_clarity_ceiling(
    doc: QloomDocument, wire_chars: int, enforce_wire_ceiling: bool, findings: list[dict[str, str]]
) -> dict[str, Any]:
    segs = [doc.charter.goal] if doc.charter.goal else []
    segs.extend(m.statement for m in doc.charter.mandates if m.statement)
    segs.extend(doc.pulse.next_actions)
    clarity_text = " ".join(
        s if s.rstrip().endswith((".", "!", "?")) else f"{s}." for s in segs if s.strip()
    )
    clarity_report = lint_clarity(clarity_text)
    if not clarity_report["passed"]:
        _add_finding(
            findings,
            "LAW_07_CLARITY_AND_CEILING",
            "charter/pulse",
            f"Clarity lint failed (score={clarity_report['score']}): "
            f"fluff={clarity_report['fluff_words_found']} "
            f"passive={clarity_report['passive_phrases_found']} "
            f"long={clarity_report['long_sentences']}",
        )
    est_tokens = max(1, wire_chars // 4)
    if enforce_wire_ceiling and wire_chars > MAX_WIRE_CHARS:
        _add_finding(
            findings,
            "LAW_07_CLARITY_AND_CEILING",
            "wire",
            f"Serialized size {wire_chars} exceeds {MAX_WIRE_CHARS}-char wire ceiling",
        )
    for lock in doc.charter.locks:
        if lock.kind == "budget":
            _check_single_budget_lock(lock, wire_chars, est_tokens, findings)
    return clarity_report


def _compute_wire_efficiency(doc: QloomDocument, wire_chars: int) -> dict[str, Any]:
    est_tokens = max(1, wire_chars // 4)
    json_equiv_chars = len(json.dumps(doc.to_dict(), indent=2, ensure_ascii=False))
    saving_ratio = round(1.0 - (wire_chars / max(1, json_equiv_chars)), 4)
    score = round(max(0.0, min(100.0, saving_ratio * 100.0)), 2)
    return {
        "wire_chars": wire_chars,
        "est_tokens": est_tokens,
        "json_equiv_chars": json_equiv_chars,
        "compression_saving_ratio": saving_ratio,
        "efficiency": {
            "score": score,
            "saving_pct": round(saving_ratio * 100.0, 2),
            "efficient": wire_chars <= json_equiv_chars,
        },
    }


def _extract_num_series(
    rel: RelationTable,
    col_name: str,
    start_row: int | None,
    end_row: int | None,
    findings: list[dict[str, str]],
) -> list[float] | None:
    c_idx = rel.column_index(col_name)
    s = 0 if start_row is None else start_row
    e = len(rel.rows) if end_row is None else end_row + 1
    if c_idx is None or s < 0 or e > len(rel.rows) or s > e:
        _add_finding(
            findings,
            "LAW_09_RELATION_ARITHMETIC",
            "lattice",
            f"Invalid column/slice {col_name!r} in {rel.name}",
        )
        return None
    vals = [row[c_idx] for row in rel.rows[s:e]]
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in vals):
        _add_finding(
            findings,
            "LAW_09_RELATION_ARITHMETIC",
            "lattice",
            f"Non-numeric value in {rel.name}.{col_name}",
        )
        return None
    return [float(v) for v in vals]


def _check_tol_or_quota(
    rel: RelationTable, chk: RelationCheck, actual: float, findings: list[dict[str, str]]
) -> None:
    if chk.kind == "tol":
        pct = float(chk.pct or 5.0)
        diff = abs(actual - float(chk.expected)) / max(1.0, abs(float(chk.expected))) * 100.0
        if diff > pct + 1e-6:
            _add_finding(
                findings,
                "LAW_09_RELATION_ARITHMETIC",
                "lattice",
                f"Relation {rel.name} ^tol drift {diff:.2f}% > {pct}%",
            )
        return
    pct = float(chk.pct or 0.0)
    projected = (actual / (pct / 100.0)) if pct > 0.0 else 0.0
    if pct <= 0.0 or not math.isclose(projected, float(chk.expected), rel_tol=1e-6, abs_tol=1.0):
        _add_finding(
            findings,
            "LAW_09_RELATION_ARITHMETIC",
            "lattice",
            f"Relation {rel.name} ^quota={chk.expected} != {projected:.2f}",
        )


def _check_sum_or_net(
    rel: RelationTable, chk: RelationCheck, actual: float, findings: list[dict[str, str]]
) -> None:
    if chk.kind == "sum":
        if not math.isclose(actual, float(chk.expected), rel_tol=1e-6, abs_tol=1e-6):
            _add_finding(
                findings,
                "LAW_09_RELATION_ARITHMETIC",
                "lattice",
                f"Relation {rel.name} ^sum({chk.column})={chk.expected} != {actual}",
            )
        return
    debt = _extract_num_series(rel, chk.extra_column or "", None, None, findings)
    if debt is not None and not math.isclose(
        actual - sum(debt), float(chk.expected), rel_tol=1e-6, abs_tol=1e-6
    ):
        _add_finding(
            findings,
            "LAW_09_RELATION_ARITHMETIC",
            "lattice",
            f"Relation {rel.name} ^net={chk.expected} != {actual - sum(debt)}",
        )


def _eval_single_check(
    rel: RelationTable, chk: RelationCheck, findings: list[dict[str, str]]
) -> None:
    if chk.kind == "count":
        if len(rel.rows) != int(chk.expected):
            _add_finding(
                findings,
                "LAW_09_RELATION_ARITHMETIC",
                "lattice",
                f"Relation {rel.name} ^count={chk.expected} != {len(rel.rows)}",
            )
        return
    vals = _extract_num_series(rel, chk.column or "", chk.start_row, chk.end_row, findings)
    if vals is None:
        return
    actual = sum(vals)
    if chk.kind in ("sum", "net"):
        _check_sum_or_net(rel, chk, actual, findings)
    elif chk.kind in ("tol", "quota"):
        _check_tol_or_quota(rel, chk, actual, findings)


def _check_law09_relation_arithmetic(doc: QloomDocument, findings: list[dict[str, str]]) -> None:
    if doc.version != QLOOM_V2:
        return
    for rel in doc.lattice.relations:
        if rel.spacer_indices and (
            rel.spacer_indices != sorted(rel.spacer_indices)
            or any(i < 0 or i > len(rel.rows) for i in rel.spacer_indices)
        ):
            _add_finding(
                findings,
                "LAW_09_RELATION_ARITHMETIC",
                "lattice",
                f"Invalid band spacers in relation {rel.name}",
            )
        for chk in rel.checks:
            _eval_single_check(rel, chk, findings)


def _check_safe_tag(
    value: str | None, plane: str, label: str, findings: list[dict[str, str]]
) -> None:
    if value is not None and not _SAFE_TAG_RE.match(value):
        _add_finding(findings, "LAW_10_LINEAGE_AND_SAGA_BOUNDS", plane, f"Unsafe {label}={value!r}")


def _check_working_row_cap(doc: QloomDocument, findings: list[dict[str, str]]) -> None:
    if doc.admin != AdminWindow.WORKING:
        return
    for rel in doc.lattice.relations:
        if len(rel.rows) >= MAX_WORKING_ROWS:
            _add_finding(
                findings,
                "LAW_10_LINEAGE_AND_SAGA_BOUNDS",
                "lattice",
                f"Working relation {rel.name} has >= {MAX_WORKING_ROWS} rows",
            )


def _check_law10_lineage_saga(doc: QloomDocument, findings: list[dict[str, str]]) -> None:
    if doc.version != QLOOM_V2:
        return
    if not _PARENT_KNOT_RE.match(doc.parent):
        _add_finding(
            findings,
            "LAW_10_LINEAGE_AND_SAGA_BOUNDS",
            "header",
            f"Invalid parent lineage seal {doc.parent!r}",
        )
    _check_safe_tag(doc.tag, "header", "tag", findings)
    _check_safe_tag(doc.hub, "header", "hub", findings)
    for blob in doc.vault.blobs:
        _check_safe_tag(blob.wrap, "vault", "blob wrap", findings)
    _check_working_row_cap(doc, findings)
    for clause in doc.contracts.clauses:
        if clause.timeout_s is not None and not (1 <= clause.timeout_s <= 86_400):
            _add_finding(
                findings,
                "LAW_10_LINEAGE_AND_SAGA_BOUNDS",
                "contracts",
                f"Clause {clause.clause_id} timeout_s={clause.timeout_s} out of bounds",
            )


def verify_qloom(
    doc_or_text: QloomDocument | str,
    *,
    enforce_wire_ceiling: bool = True,
) -> dict[str, Any]:
    """Runs all 8 (QLOOM/1.0) or 10 (QLOOM/2.0) static verification laws."""
    if isinstance(doc_or_text, str):
        try:
            doc = parse_qloom(doc_or_text)
        except QloomSyntaxError as exc:
            return {
                "valid": False,
                "verdict": "SYNTAX_ERROR",
                "findings_count": 1,
                "findings": [
                    {
                        "law": "LAW_00_SYNTAX",
                        "plane": "wire",
                        "severity": "error",
                        "message": str(exc),
                    }
                ],
                "laws_checked": [],
                "metrics": {},
            }
    else:
        doc = doc_or_text

    findings: list[dict[str, str]] = []
    laws_checked = [
        "LAW_01_KNOT_SEAL",
        "LAW_02_CONTENT_SAFETY",
        "LAW_03_SAFE_ARGV",
        "LAW_04_TAINT_LATTICE",
        "LAW_05_SPIN_AND_BERNSTEIN",
        "LAW_06_DAG_AND_REFS",
        "LAW_07_CLARITY_AND_CEILING",
        "LAW_08_WIRE_EFFICIENCY",
    ]
    _check_law01_seal(doc, findings)
    canonical_wire = dump_qloom(doc, recompute_seal=False)
    _check_law02_content_safety(canonical_wire, findings)
    _check_law03_safe_argv(doc, findings)
    _check_law04_taint(doc, findings)
    hazards_count = _check_law05_spin_bernstein(doc, findings)
    deferred_refs = _check_law06_dag_refs(doc, findings)
    wire_chars = len(canonical_wire)
    clarity_report = _check_law07_clarity_ceiling(doc, wire_chars, enforce_wire_ceiling, findings)
    if doc.version == QLOOM_V2:
        laws_checked.extend(["LAW_09_RELATION_ARITHMETIC", "LAW_10_LINEAGE_AND_SAGA_BOUNDS"])
        _check_law09_relation_arithmetic(doc, findings)
        _check_law10_lineage_saga(doc, findings)

    metrics = _compute_wire_efficiency(doc, wire_chars)
    passed = len(findings) == 0
    return {
        "valid": passed,
        "verdict": "VERIFIED" if passed else "VIOLATION",
        "version": doc.version,
        "doc_id": doc.doc_id,
        "tier": doc.tier.value,
        "knot": doc.seal.knot if doc.seal else None,
        "findings_count": len(findings),
        "findings": findings,
        "laws_checked": laws_checked,
        "deferred_refs": deferred_refs,
        "clarity_score": clarity_report["score"],
        "clarity": clarity_report,
        "concurrent_hazards_count": hazards_count,
        "metrics": metrics,
    }


verify = verify_qloom


def _sample_lattice(is_v2: bool) -> LatticePlane:
    claims_checks = [RelationCheck(kind="count", expected=3)] if is_v2 else []
    claims_spacers = [2] if is_v2 else []
    return LatticePlane(
        relations=[
            RelationTable(
                name="artifacts",
                columns=[
                    ColumnSpec("id", "id"),
                    ColumnSpec("tier", "tier"),
                    ColumnSpec("path", "str"),
                ],
                rows=[
                    ["art_audit", "T1", "artifacts/auth_audit.md"],
                    ["adr_04", "T0", "docs/adr/0004_hmac_stdlib.md"],
                ],
            ),
            RelationTable(
                name="claims",
                columns=[
                    ColumnSpec("id", "id"),
                    ColumnSpec("mod", "mod"),
                    ColumnSpec("tier", "tier"),
                    ColumnSpec("claim", "str"),
                    ColumnSpec("source", "ref"),
                    ColumnSpec("supersedes", "ref?"),
                ],
                rows=[
                    [
                        "c1",
                        "superseded",
                        "T1",
                        "JWT parser uses custom base64 decoder.",
                        "art_audit",
                        None,
                    ],
                    [
                        "c2",
                        "verified",
                        "T0",
                        "Auth validator enforces stdlib HMAC-SHA256.",
                        "adr_04",
                        "c1",
                    ],
                    [
                        "c3",
                        "tentative",
                        "T2",
                        "External RFC 7519 draft notes key rotation window.",
                        "v_ext_rfc",
                        None,
                    ],
                ],
                checks=claims_checks,
                spacer_indices=claims_spacers,
            ),
        ]
    )


def _sample_weave(is_v2: bool) -> WeavePlane:
    return WeavePlane(
        mode=WorkspaceMode.SHARE,
        nodes=[
            WeaveNode(
                node_id="t_audit",
                spin=Spin.Z,
                face=AttachFace.RECTO if is_v2 else None,
                weight=NodeWeight.FINE if is_v2 else None,
                state=AgentState.SANDBOX_COMPUTE.value,
                deps=[],
                reads=["src/auth.py"],
                writes=[],
                lifecycle=NodeLifecycle.DONE,
            ),
            WeaveNode(
                node_id="t_patch",
                spin=Spin.S,
                face=AttachFace.RECTO if is_v2 else None,
                weight=NodeWeight.THICK if is_v2 else None,
                state=AgentState.MUTATION_PREPARE.value,
                deps=["t_audit"],
                reads=["src/auth.py"],
                writes=["src/auth.py"],
                lifecycle=NodeLifecycle.ACTIVE,
            ),
            WeaveNode(
                node_id="t_tests",
                spin=Spin.S,
                face=AttachFace.RECTO if is_v2 else None,
                weight=NodeWeight.MEDIUM if is_v2 else None,
                state=AgentState.CRITIQUE_GATE.value,
                deps=["t_patch"],
                reads=["src/auth.py"],
                writes=["tests/test_auth.py"],
                lifecycle=NodeLifecycle.PENDING,
            ),
        ],
    )


def sample_qloom(*, version: str = QLOOM_V2) -> QloomDocument:
    """Builds a verified L4 QLOOM/2.0 (default) or QLOOM/1.0 sample document across all 6 planes."""
    resolved = normalize_qloom_version(version)
    is_v2 = resolved == QLOOM_V2
    doc = QloomDocument(
        doc_id="epic.auth.v2",
        tier=Tier.L4,
        state=AgentState.MUTATION_PREPARE.value,
        parent="qloom-000000000000" if is_v2 else "quipu-000000000000",
        epoch=4,
        version=resolved,
        admin=AdminWindow.WORKING if is_v2 else None,
        tag="auth_migration" if is_v2 else None,
        charter=CharterPlane(
            goal="Migrate token validator to stdlib HMAC verification.",
            locks=[
                CharterLock(
                    lock_id="NO_SHELL_INTERP",
                    kind="forbid",
                    forbid_code="cwe78_shell_interpolation",
                ),
                CharterLock(
                    lock_id="WIRE_BUDGET",
                    kind="budget",
                    max_tokens=2000,
                    max_chars=8000,
                    tol_pct=5.0 if is_v2 else None,
                    max_retries=3 if is_v2 else None,
                ),
            ],
            mandates=[
                CharterMandate(
                    mandate_id="CLARITY_RULE",
                    statement="Keep each step concise and verify outputs with tests.",
                )
            ],
        ),
        lattice=_sample_lattice(is_v2),
        weave=_sample_weave(is_v2),
        contracts=ContractsPlane(
            clauses=[
                ContractClause(
                    clause_id="C_UNIT",
                    requires=["c2", "t_patch"],
                    ensures="Run unit tests and confirm zero HMAC regressions.",
                    witness_argv=["pytest", "tests/unit/test_auth.py", "-q"],
                    timeout_s=120 if is_v2 else None,
                    rollback_argv=["git", "checkout", "--", "src/auth.py"] if is_v2 else [],
                )
            ]
        ),
        vault=VaultPlane(
            blobs=[
                VaultBlob(
                    blob_id="v_ext_rfc",
                    tier="T2",
                    sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    size_bytes=4096,
                    origin="rfc7519",
                    uri="vault://blobs/v_ext_rfc",
                    wrap="rfc_excerpt" if is_v2 else None,
                )
            ]
        ),
        pulse=PulsePlane(
            focus="t_patch",
            filament=(
                "[QLOOM::FILAMENT] [-1:t_audit] ==> @[0:t_patch|MUTATION_PREPARE] "
                "==> [+1:t_tests] | save=90.0% | check=OK"
            ),
            next_actions=["Finish auth patch.", "Run pytest witness argv."],
            blockers=[],
        ),
    )
    doc.seal = compute_seal(doc)
    return doc
