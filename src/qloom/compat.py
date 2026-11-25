"""qloom.compat — QLOOM/1.0 <-> QLOOM/2.0 Compatibility, Distillation, Linking & Wave Planner.

Provides lossless upgrade/downgrade paths so QLOOM/2.0 transparently ingests
QLOOM/1.0 packets, exports compliant QLOOM/1.0 documents for legacy consumers,
compacts handoffs, links multi-agent packets into a federated hub, and schedules
Bernstein-safe parallel execution waves.
"""

from __future__ import annotations

import copy
from typing import Any

from .ast_nodes import (
    QLOOM_V1,
    QLOOM_V2,
    V1_GENESIS_PARENT,
    AdminWindow,
    AgentState,
    CharterLock,
    CharterMandate,
    CharterPlane,
    ColumnSpec,
    ContractClause,
    ContractsPlane,
    LatticePlane,
    NodeLifecycle,
    PulsePlane,
    QloomDocument,
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
from .codec import compute_seal, parse_qloom, project_qloom
from .verifier import find_concurrent_conflicts, sample_qloom, verify_qloom


def sample_qloom_v1() -> QloomDocument:
    """Returns a verified QLOOM/1.0 sample document with `quipu-*` knot prefix."""
    return sample_qloom(version=QLOOM_V1)


def detect_qloom_version(doc_or_text: QloomDocument | str) -> str:
    """Returns canonical protocol version ('QLOOM/1.0' or 'QLOOM/2.0')."""
    doc = parse_qloom(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    return normalize_qloom_version(doc.version)


def is_qloom_v1(doc_or_text: QloomDocument | str) -> bool:
    """Returns True if the given document or wire text is QLOOM/1.0."""
    return detect_qloom_version(doc_or_text) == QLOOM_V1


def is_qloom_v2(doc_or_text: QloomDocument | str) -> bool:
    """Returns True if the given document or wire text is QLOOM/2.0."""
    return detect_qloom_version(doc_or_text) == QLOOM_V2


def _clone_locks(locks: list[CharterLock], *, strip_v2: bool) -> list[CharterLock]:
    return [
        CharterLock(
            lock_id=lk.lock_id,
            kind=lk.kind,
            forbid_code=lk.forbid_code,
            max_tokens=lk.max_tokens,
            max_chars=lk.max_chars,
            max_cost_usd=None if strip_v2 else lk.max_cost_usd,
            max_retries=None if strip_v2 else lk.max_retries,
            tol_pct=None if strip_v2 else lk.tol_pct,
        )
        for lk in locks
    ]


def _clone_relations(relations: list[RelationTable], *, strip_v2: bool) -> list[RelationTable]:
    return [
        RelationTable(
            name=rel.name,
            columns=list(rel.columns),
            rows=[list(r) for r in rel.rows],
            checks=[] if strip_v2 else list(rel.checks),
            spacer_indices=[] if strip_v2 else list(rel.spacer_indices),
        )
        for rel in relations
    ]


def _clone_weave(weave: WeavePlane, *, strip_v2: bool) -> WeavePlane:
    return WeavePlane(
        mode=weave.mode,
        nodes=[
            WeaveNode(
                node_id=n.node_id,
                spin=n.spin,
                state=n.state,
                deps=list(n.deps),
                reads=list(n.reads),
                writes=list(n.writes),
                lifecycle=n.lifecycle,
                face=None if strip_v2 else n.face,
                weight=None if strip_v2 else n.weight,
            )
            for n in weave.nodes
        ],
    )


def _clone_contracts(contracts: ContractsPlane, *, strip_v2: bool) -> ContractsPlane:
    return ContractsPlane(
        clauses=[
            ContractClause(
                clause_id=c.clause_id,
                requires=list(c.requires),
                ensures=c.ensures,
                witness_argv=list(c.witness_argv),
                timeout_s=None if strip_v2 else c.timeout_s,
                rollback_argv=[] if strip_v2 else list(c.rollback_argv),
            )
            for c in contracts.clauses
        ]
    )


def _clone_vault(vault: VaultPlane, *, strip_v2: bool) -> VaultPlane:
    return VaultPlane(
        blobs=[
            VaultBlob(
                blob_id=b.blob_id,
                tier=b.tier,
                sha256=b.sha256,
                size_bytes=b.size_bytes,
                origin=b.origin,
                uri=b.uri,
                wrap=None if strip_v2 else b.wrap,
            )
            for b in vault.blobs
        ]
    )


def upgrade_qloom_to_v2(
    doc_or_text: QloomDocument | str,
    *,
    admin: AdminWindow | str | None = None,
    tag: str | None = None,
    hub: str | None = None,
    recompute_seal: bool = True,
) -> QloomDocument:
    """Upgrades a QLOOM/1.0 (or QLOOM/2.0) packet to QLOOM/2.0 preserving parent lineage."""
    src = parse_qloom(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    src_knot = src.seal.knot if src.seal else compute_seal(src).knot
    resolved_admin = (
        admin
        if isinstance(admin, AdminWindow)
        else (AdminWindow(admin) if admin is not None else src.admin)
    )
    upgraded = QloomDocument(
        doc_id=src.doc_id,
        tier=src.tier,
        state=src.state,
        parent=src_knot,
        epoch=src.epoch,
        version=QLOOM_V2,
        admin=resolved_admin,
        tag=tag if tag is not None else src.tag,
        hub=hub if hub is not None else src.hub,
        charter=copy.deepcopy(src.charter),
        lattice=copy.deepcopy(src.lattice),
        weave=copy.deepcopy(src.weave),
        contracts=copy.deepcopy(src.contracts),
        vault=copy.deepcopy(src.vault),
        pulse=copy.deepcopy(src.pulse),
    )
    if recompute_seal:
        upgraded.seal = compute_seal(upgraded)
    return upgraded


def downgrade_qloom_to_v1(
    doc_or_text: QloomDocument | str,
    *,
    recompute_seal: bool = True,
) -> QloomDocument:
    """Downgrades a QLOOM/2.0 document to strictly compliant 8-law QLOOM/1.0."""
    src = parse_qloom(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    downgraded = QloomDocument(
        doc_id=src.doc_id,
        tier=src.tier,
        state=src.state,
        parent=V1_GENESIS_PARENT,
        epoch=src.epoch,
        version=QLOOM_V1,
        charter=CharterPlane(
            goal=src.charter.goal,
            locks=_clone_locks(src.charter.locks, strip_v2=True),
            mandates=copy.deepcopy(src.charter.mandates),
        ),
        lattice=LatticePlane(relations=_clone_relations(src.lattice.relations, strip_v2=True)),
        weave=_clone_weave(src.weave, strip_v2=True),
        contracts=_clone_contracts(src.contracts, strip_v2=True),
        vault=_clone_vault(src.vault, strip_v2=True),
        pulse=copy.deepcopy(src.pulse),
    )
    if recompute_seal:
        downgraded.seal = compute_seal(downgraded)
    return downgraded


def distill_qloom_handoff(
    doc_or_text: QloomDocument | str,
    *,
    tier: Tier | str = Tier.L2,
    doc_id: str | None = None,
) -> QloomDocument:
    """Compacts a session QLOOM document into a summary QLOOM/2.0 handoff packet."""
    src = parse_qloom(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    projected = project_qloom(src, tier)
    projected.version = QLOOM_V2
    projected.admin = AdminWindow.SUMMARY
    if doc_id:
        projected.doc_id = doc_id
    projected.seal = compute_seal(projected)
    return projected


def link_qlooms(
    packets: dict[str, QloomDocument | str],
    *,
    hub_id: str = "HubA",
    doc_id: str = "qloom.swarm.hub",
) -> QloomDocument:
    """Links multiple QLOOM/1.0 and QLOOM/2.0 packets into one federated hub summary packet."""
    if not packets:
        raise ValueError("link_qlooms requires at least one member packet")
    rows: list[list[Any]] = []
    for slot, pkt in sorted(packets.items()):
        parsed = parse_qloom(pkt) if isinstance(pkt, str) else pkt
        rep = verify_qloom(parsed, enforce_wire_ceiling=False)
        rows.append(
            [
                str(slot),
                parsed.doc_id,
                parsed.version,
                parsed.tier.value,
                str(rep.get("knot") or "unsealed"),
                len(parsed.weave.nodes),
            ]
        )
    table = RelationTable(
        name="members",
        columns=[
            ColumnSpec("slot", "id"),
            ColumnSpec("doc_id", "str"),
            ColumnSpec("version", "str"),
            ColumnSpec("tier", "str"),
            ColumnSpec("knot", "str"),
            ColumnSpec("nodes", "int"),
        ],
        rows=rows,
        checks=[
            RelationCheck(kind="count", expected=len(rows)),
            RelationCheck(kind="sum", column="nodes", expected=sum(r[5] for r in rows)),
        ],
    )
    hub_doc = QloomDocument(
        doc_id=doc_id,
        tier=Tier.L2,
        state=AgentState.REASONING.value,
        version=QLOOM_V2,
        admin=AdminWindow.SUMMARY,
        tag="swarm_hub",
        hub=hub_id,
        charter=CharterPlane(
            goal=f"Aggregate {len(rows)} QLOOM packets under hub {hub_id}.",
            mandates=[
                CharterMandate(mandate_id="HUB_SYNC", statement="Keep member knots verified.")
            ],
        ),
        lattice=LatticePlane(relations=[table]),
        weave=WeavePlane(
            mode=WorkspaceMode.INHERIT,
            nodes=[
                WeaveNode(
                    node_id="n_hub_sync",
                    spin=Spin.Z,
                    state=AgentState.REASONING.value,
                    lifecycle=NodeLifecycle.DONE,
                )
            ],
        ),
        pulse=PulsePlane(
            focus="n_hub_sync",
            next_actions=["Dispatch next worker wave from hub."],
        ),
    )
    hub_doc.seal = compute_seal(hub_doc)
    return hub_doc


def _nodes_conflict_in_wave(n1: WeaveNode, n2: WeaveNode, mode: WorkspaceMode) -> bool:
    if mode != WorkspaceMode.SHARE:
        return False
    return bool(find_concurrent_conflicts([n1, n2]))


def plan_weave_waves(doc_or_text: QloomDocument | str) -> list[list[str]]:
    """Schedules executable `@weave` nodes into dependency- and Bernstein-safe parallel waves."""
    doc = parse_qloom(doc_or_text) if isinstance(doc_or_text, str) else doc_or_text
    pending_map = {n.node_id: n for n in doc.weave.nodes}
    completed: set[str] = set()
    waves: list[list[str]] = []

    while pending_map:
        ready = sorted(
            nid for nid, node in pending_map.items() if all(d in completed for d in node.deps)
        )
        if not ready:
            raise ValueError(
                f"Cycle or missing dependency blocks @weave nodes: {sorted(pending_map)}"
            )
        wave: list[str] = []
        for nid in ready:
            cand = pending_map[nid]
            if not any(_nodes_conflict_in_wave(cand, pending_map[w], doc.weave.mode) for w in wave):
                wave.append(nid)
        for nid in wave:
            completed.add(nid)
            pending_map.pop(nid)
        waves.append(wave)
    return waves
