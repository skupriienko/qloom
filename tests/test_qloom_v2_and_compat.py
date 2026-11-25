"""QLOOM/2.0 features, LAW_09/LAW_10 checks, compatibility shims, wave planner, and draw tests."""

from __future__ import annotations

import pytest

from qloom import (
    DEFAULT_QLOOM_VERSION,
    MAX_WORKING_ROWS,
    QLOOM_V1,
    QLOOM_V2,
    AdminWindow,
    AgentState,
    AttachFace,
    CharterLock,
    ColumnSpec,
    NodeLifecycle,
    NodeWeight,
    QloomDocument,
    RelationCheck,
    RelationTable,
    Spin,
    Tier,
    WeaveNode,
    WorkspaceMode,
    compute_seal,
    detect_qloom_version,
    distill_qloom_handoff,
    downgrade_qloom_to_v1,
    draw,
    draw_qloom,
    dump,
    is_qloom_v1,
    is_qloom_v2,
    link_qlooms,
    parse,
    plan_weave_waves,
    render_qloom_ascii,
    sample_qloom,
    sample_qloom_v1,
    upgrade_qloom_to_v2,
    verify,
)


def test_version_law_counts_and_charter_v2_budgets() -> None:
    assert DEFAULT_QLOOM_VERSION == QLOOM_V2 == "QLOOM/2.0"

    v1_doc = sample_qloom_v1()
    v2_doc = sample_qloom(version=QLOOM_V2)

    assert is_qloom_v1(v1_doc) is True
    assert is_qloom_v2(v1_doc) is False
    assert detect_qloom_version(v2_doc) == QLOOM_V2

    rep_v1 = verify(v1_doc)
    rep_v2 = verify(v2_doc)
    assert rep_v1["valid"] is True
    assert len(rep_v1["laws_checked"]) == 8
    assert rep_v2["valid"] is True
    assert len(rep_v2["laws_checked"]) == 10
    assert set(rep_v2["laws_checked"][-2:]) == {
        "LAW_09_RELATION_ARITHMETIC",
        "LAW_10_LINEAGE_AND_SAGA_BOUNDS",
    }

    bad_budget = sample_qloom(version=QLOOM_V2)
    bad_budget.charter.locks.append(
        CharterLock(
            lock_id="BAD_BUDGET",
            kind="budget",
            max_cost_usd=-0.5,
            max_retries=-1,
            tol_pct=150.0,
        )
    )
    bad_budget.seal = compute_seal(bad_budget)
    rep_bad = verify(bad_budget)
    assert rep_bad["valid"] is False
    assert [f["law"] for f in rep_bad["findings"]].count("LAW_07_CLARITY_AND_CEILING") == 3


def test_law09_relation_arithmetic_and_spacers() -> None:
    doc = QloomDocument(
        doc_id="ledger.v2",
        tier=Tier.L4,
        state=AgentState.REASONING.value,
        version=QLOOM_V2,
        admin=AdminWindow.WORKING,
        tag="fiscal_ops",
    )
    doc.charter.goal = "Audit ledger relation arithmetic."
    doc.lattice.relations.append(
        RelationTable(
            name="ledger",
            columns=[
                ColumnSpec("id", "id"),
                ColumnSpec("credit", "int"),
                ColumnSpec("debt", "int"),
                ColumnSpec("guard", "int"),
            ],
            rows=[
                ["r1", 300, 250, 200],
                ["r2", 300, 250, 200],
                ["r3", 200, 250, 250],
                ["r4", 200, 250, 250],
            ],
            spacer_indices=[2],
            checks=[
                RelationCheck(kind="count", expected=4),
                RelationCheck(kind="sum", column="credit", start_row=0, end_row=1, expected=600),
                RelationCheck(kind="net", column="credit", extra_column="debt", expected=0),
                RelationCheck(kind="tol", column="credit", pct=5.0, expected=980),
                RelationCheck(kind="quota", column="guard", pct=22.5, expected=4000),
            ],
        )
    )
    doc.pulse.focus = None
    doc.pulse.next_actions = ["Publish audited ledger."]
    doc.seal = compute_seal(doc)
    rep = verify(dump(doc))
    assert rep["valid"] is True, rep["findings"]

    # Mutate checks + spacer indices to trigger LAW_09 violations
    bad = parse(dump(doc))
    bad.lattice.relations[0].spacer_indices = [3, 1]
    bad.lattice.relations[0].checks = [
        RelationCheck(kind="count", expected=99),
        RelationCheck(kind="sum", column="credit", start_row=0, end_row=1, expected=999),
        RelationCheck(kind="net", column="credit", extra_column="debt", expected=50),
        RelationCheck(kind="tol", column="credit", pct=1.0, expected=500),
        RelationCheck(kind="quota", column="guard", pct=22.5, expected=9999),
    ]
    bad.seal = compute_seal(bad)
    rep_bad = verify(bad)
    assert rep_bad["valid"] is False
    assert [f["law"] for f in rep_bad["findings"]].count("LAW_09_RELATION_ARITHMETIC") >= 6


def test_v2_weave_face_weight_and_law10_saga_bounds() -> None:
    doc = sample_qloom(version=QLOOM_V2)
    doc.weave.nodes.append(
        WeaveNode(
            node_id="n_shadow",
            spin=Spin.S,
            face=AttachFace.VERSO,
            weight=NodeWeight.FINE,
            state=AgentState.CRITIQUE_GATE.value,
            deps=["t_tests"],
            reads=["src/auth.py"],
            writes=["src/shadow_illegal.py"],
            lifecycle=NodeLifecycle.PENDING,
        )
    )
    doc.parent = "bad_parent"
    doc.tag = "bad;tag"
    doc.hub = "bad$hub"
    doc.contracts.clauses[0].timeout_s = 100_000
    doc.seal = compute_seal(doc)

    rep = verify(doc)
    assert rep["valid"] is False
    laws = [f["law"] for f in rep["findings"]]
    assert "LAW_05_SPIN_AND_BERNSTEIN" in laws
    assert laws.count("LAW_10_LINEAGE_AND_SAGA_BOUNDS") == 4

    # Working row cap >= MAX_WORKING_ROWS fails in working, passes in summary
    cap_doc = QloomDocument(
        doc_id="cap.check",
        tier=Tier.L4,
        state=AgentState.REASONING.value,
        version=QLOOM_V2,
        admin=AdminWindow.WORKING,
    )
    cap_doc.charter.goal = "Check working row cap."
    cap_doc.lattice.relations.append(
        RelationTable(
            name="items",
            columns=[ColumnSpec("id", "id"), ColumnSpec("v", "int")],
            rows=[[f"i{i}", i] for i in range(MAX_WORKING_ROWS)],
        )
    )
    cap_doc.pulse.next_actions = ["Distill summary."]
    cap_doc.seal = compute_seal(cap_doc)
    rep_cap = verify(cap_doc, enforce_wire_ceiling=False)
    assert any(f["law"] == "LAW_10_LINEAGE_AND_SAGA_BOUNDS" for f in rep_cap["findings"])

    cap_doc.admin = AdminWindow.SUMMARY
    cap_doc.seal = compute_seal(cap_doc)
    assert verify(cap_doc, enforce_wire_ceiling=False)["valid"] is True


def test_compat_shims_distill_link_waves_and_ascii_draw() -> None:
    v1_doc = sample_qloom_v1()
    assert v1_doc.seal is not None
    v2_up = upgrade_qloom_to_v2(v1_doc, admin="working", tag="promoted", hub="HubWest")
    assert v2_up.version == QLOOM_V2
    assert v2_up.admin == AdminWindow.WORKING
    assert v2_up.tag == "promoted"
    assert v2_up.hub == "HubWest"
    assert v2_up.parent == v1_doc.seal.knot
    assert verify(v2_up)["valid"] is True

    v2_doc = sample_qloom(version=QLOOM_V2)
    v1_down = downgrade_qloom_to_v1(v2_doc)
    assert v1_down.version == QLOOM_V1
    assert v1_down.admin is None
    assert v1_down.tag is None
    assert v1_down.contracts.clauses[0].timeout_s is None
    assert v1_down.contracts.clauses[0].rollback_argv == []
    rep_down = verify(v1_down)
    assert rep_down["valid"] is True
    assert len(rep_down["laws_checked"]) == 8

    summary = distill_qloom_handoff(v2_doc, tier="L2", doc_id="auth.summary")
    assert summary.doc_id == "auth.summary"
    assert summary.admin == AdminWindow.SUMMARY
    assert summary.tier == Tier.L2
    assert verify(summary)["valid"] is True

    hub = link_qlooms({"legacy": v1_doc, "auth": summary}, hub_id="SwarmHub")
    assert hub.hub == "SwarmHub"
    assert hub.admin == AdminWindow.SUMMARY
    assert verify(hub)["valid"] is True
    assert len(hub.lattice.relations[0].rows) == 2

    with pytest.raises(ValueError, match="at least one member packet"):
        link_qlooms({})

    waves = plan_weave_waves(v2_doc)
    assert waves == [["t_audit"], ["t_patch"], ["t_tests"]]

    # Parallel disjoint nodes schedule into the same wave
    parallel_doc = QloomDocument(
        doc_id="waves.parallel",
        tier=Tier.L4,
        state=AgentState.MUTATION_PREPARE.value,
    )
    parallel_doc.charter.goal = "Schedule disjoint nodes."
    parallel_doc.weave.mode = WorkspaceMode.SHARE
    parallel_doc.weave.nodes = [
        WeaveNode(
            "root", Spin.Z, AgentState.REASONING.value, [], ["README.md"], [], NodeLifecycle.DONE
        ),
        WeaveNode(
            "api",
            Spin.S,
            AgentState.MUTATION_PREPARE.value,
            ["root"],
            ["api.py"],
            ["api.py"],
            NodeLifecycle.ACTIVE,
        ),
        WeaveNode(
            "ui",
            Spin.S,
            AgentState.MUTATION_PREPARE.value,
            ["root"],
            ["ui.py"],
            ["ui.py"],
            NodeLifecycle.ACTIVE,
        ),
    ]
    assert plan_weave_waves(parallel_doc) == [["root"], ["api", "ui"]]

    diagram = draw(v2_doc)
    assert diagram == draw_qloom(v2_doc) == render_qloom_ascii(dump(v2_doc))
    assert "QLOOM/2.0: epic.auth.v2" in diagram
    assert "@charter" in diagram
    assert "@weave (mode=share)" in diagram
    assert "@pulse" in diagram
