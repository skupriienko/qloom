"""Core AST, parser, serializer, L4->L0 projection, and LAW_01..LAW_08 tests for `qloom`."""

from __future__ import annotations

import copy
import io
from pathlib import Path

import pytest
from qloom import (
    MAX_WIRE_CHARS,
    QLOOM_V1,
    QLOOM_V2,
    AgentState,
    NodeLifecycle,
    QloomDocument,
    QloomSyntaxError,
    Spin,
    Tier,
    WeaveNode,
    WorkspaceMode,
    compute_seal,
    dump,
    dump_file,
    dumps,
    load,
    loads,
    normalize_qloom_version,
    parse,
    project,
    sample_qloom,
    verify,
)


def test_ast_json_roundtrip_and_stream_io(tmp_path: Path) -> None:
    doc = sample_qloom(version=QLOOM_V2)
    wire = dump(doc)
    assert wire == dumps(doc.to_dict())

    parsed = parse(wire)
    assert parsed.to_dict() == doc.to_dict()
    assert loads(wire) == doc.to_dict()
    assert "c2" in parsed.declared_ids()
    assert "t_patch" in parsed.declared_ids()

    out_path = tmp_path / "sample.qloom"
    written = dump_file(parsed, out_path)
    assert written == len(wire)
    assert load(out_path).to_dict() == doc.to_dict()

    buf = io.StringIO()
    dump_file(parsed, buf)
    buf.seek(0)
    assert load(buf).to_dict() == doc.to_dict()

    assert normalize_qloom_version("1.0") == QLOOM_V1
    assert normalize_qloom_version("2") == QLOOM_V2
    with pytest.raises(QloomSyntaxError, match="Unsupported QLOOM protocol version"):
        normalize_qloom_version("3.0")


def test_comments_and_wire_formatting_roundtrip() -> None:
    raw = """# Leading comment
~= QLOOM/2.0 id="comments.demo" tier=L4 state=REASONING parent="qloom-000000000000" epoch=1

@charter {
  # Goal comment
  goal: "Check comment stripping."
  lock L1: forbid "cwe78_shell_interpolation"
  mandate M1: must "Keep payloads clean."
}

@weave mode=inherit {
  node n1 spin=Z state=REASONING deps=[] R={"README.md"} W={} -> done # trailing comment
}

@pulse {
  focus: ->n1
  next: ["Finish review."]
  blockers: []
}
"""
    doc = parse(raw)
    doc.seal = compute_seal(doc)
    rep = verify(doc)
    assert rep["valid"] is True, rep["findings"]
    assert rep["verdict"] == "VERIFIED"
    assert len(rep["laws_checked"]) == 10


def test_progressive_projection_l4_to_l0_and_parent_chaining() -> None:
    l4 = sample_qloom(version=QLOOM_V2)
    assert l4.tier == Tier.L4
    assert l4.seal is not None
    l4_knot = l4.seal.knot

    l3 = project(l4, Tier.L3)
    assert l3.tier == Tier.L3
    assert l3.parent == l4_knot
    l3_claims = {r[0] for r in l3.lattice.relations[1].rows}
    assert "c1" not in l3_claims  # superseded row pruned
    assert {"c2", "c3"}.issubset(l3_claims)
    assert verify(l3)["valid"] is True

    l2 = project(l4, "L2")
    assert l2.tier == Tier.L2
    assert l2.parent == l4_knot
    assert l2.vault.blobs == []
    l2_claims = {r[0] for r in l2.lattice.relations[1].rows}
    assert l2_claims == {"c2"}  # superseded + T2 pruned
    assert verify(l2)["valid"] is True

    l1 = project(l4, Tier.L1)
    assert l1.tier == Tier.L1
    assert l1.weave.nodes == []
    assert l1.contracts.clauses == []
    rep_l1 = verify(l1)
    assert rep_l1["valid"] is True
    assert rep_l1["deferred_refs"] == ["t_patch"]

    l0 = project(l4, Tier.L0)
    assert l0.tier == Tier.L0
    assert l0.lattice.relations == []
    assert l0.weave.nodes == []
    assert l0.vault.blobs == []
    assert l0.charter.goal == l4.charter.goal
    assert l0.pulse.focus == "t_patch"
    rep_l0 = verify(l0)
    assert rep_l0["valid"] is True
    assert rep_l0["deferred_refs"] == ["t_patch"]


def test_law01_seal_and_syntax_error_handling() -> None:
    doc = sample_qloom(version=QLOOM_V2)
    wire = dump(doc)

    tampered = wire.replace("Migrate token validator", "Bypass token validator")
    rep = verify(tampered)
    assert rep["valid"] is False
    assert any(f["law"] == "LAW_01_KNOT_SEAL" for f in rep["findings"])

    no_seal = copy.deepcopy(doc)
    no_seal.seal = None
    assert any(f["law"] == "LAW_01_KNOT_SEAL" for f in verify(no_seal)["findings"])

    syn_rep = verify("not valid qloom wire")
    assert syn_rep["valid"] is False
    assert syn_rep["verdict"] == "SYNTAX_ERROR"
    assert syn_rep["findings"][0]["law"] == "LAW_00_SYNTAX"


def test_law02_content_safety_bounds() -> None:
    with pytest.raises(QloomSyntaxError, match="Null byte"):
        parse('~= QLOOM/2.0 id="nul\x00" tier=L0 state=IDLE parent="qloom-000000000000" epoch=1')

    bidi_doc = sample_qloom(version=QLOOM_V2)
    bidi_doc.charter.goal = "Check \u202e hidden text."
    bidi_doc.seal = compute_seal(bidi_doc)
    rep_bidi = verify(bidi_doc)
    assert any(f["law"] == "LAW_02_CONTENT_SAFETY" for f in rep_bidi["findings"])

    secret_doc = sample_qloom(version=QLOOM_V2)
    fake_tok = "gh" + "p_" + ("A" * 36)
    secret_doc.pulse.filament = fake_tok
    secret_doc.seal = compute_seal(secret_doc)
    rep_sec = verify(secret_doc)
    assert any(f["law"] == "LAW_02_CONTENT_SAFETY" for f in rep_sec["findings"])

    subproc_doc = sample_qloom(version=QLOOM_V2)
    subproc_doc.charter.goal = "Avoid subprocess.run('ls', shell=True) calls."
    subproc_doc.seal = compute_seal(subproc_doc)
    rep_sub = verify(subproc_doc)
    assert any(f["law"] == "LAW_02_CONTENT_SAFETY" for f in rep_sub["findings"])


def test_law03_safe_argv_cwe78() -> None:
    doc = sample_qloom(version=QLOOM_V2)
    doc.contracts.clauses[0].witness_argv = ["bash", "-c", "pytest -q"]
    doc.seal = compute_seal(doc)
    rep = verify(doc)
    assert any(f["law"] == "LAW_03_SAFE_ARGV" for f in rep["findings"])

    empty_argv = sample_qloom(version=QLOOM_V2)
    empty_argv.contracts.clauses[0].witness_argv = []
    empty_argv.seal = compute_seal(empty_argv)
    assert any(f["law"] == "LAW_03_SAFE_ARGV" for f in verify(empty_argv)["findings"])

    bad_rb = sample_qloom(version=QLOOM_V2)
    bad_rb.contracts.clauses[0].rollback_argv = ["git;rm", "status"]
    bad_rb.seal = compute_seal(bad_rb)
    assert any(f["law"] == "LAW_03_SAFE_ARGV" for f in verify(bad_rb)["findings"])


def test_law04_taint_lattice_isolation() -> None:
    doc_contract = sample_qloom(version=QLOOM_V2)
    doc_contract.contracts.clauses[0].requires.append("v_ext_rfc")
    doc_contract.seal = compute_seal(doc_contract)
    rep_c = verify(doc_contract)
    assert any(
        f["law"] == "LAW_04_TAINT_LATTICE" and f["plane"] == "contracts"
        for f in rep_c["findings"]
    )

    doc_focus = sample_qloom(version=QLOOM_V2)
    doc_focus.pulse.focus = "c3"
    doc_focus.seal = compute_seal(doc_focus)
    rep_f = verify(doc_focus)
    assert any(
        f["law"] == "LAW_04_TAINT_LATTICE" and f["plane"] == "pulse"
        for f in rep_f["findings"]
    )

    doc_row = sample_qloom(version=QLOOM_V2)
    doc_row.lattice.relations[1].rows[1][4] = "v_ext_rfc"  # T0 row referencing T2 vault blob
    doc_row.seal = compute_seal(doc_row)
    rep_r = verify(doc_row)
    assert any(
        f["law"] == "LAW_04_TAINT_LATTICE" and f["plane"] == "lattice"
        for f in rep_r["findings"]
    )


def test_law05_spin_and_bernstein_concurrency() -> None:
    z_write = sample_qloom(version=QLOOM_V2)
    z_write.weave.nodes[0].writes = ["src/auth.py"]
    z_write.seal = compute_seal(z_write)
    assert any(f["law"] == "LAW_05_SPIN_AND_BERNSTEIN" for f in verify(z_write)["findings"])

    inherit_write = sample_qloom(version=QLOOM_V2)
    inherit_write.weave.mode = WorkspaceMode.INHERIT
    inherit_write.seal = compute_seal(inherit_write)
    assert any(f["law"] == "LAW_05_SPIN_AND_BERNSTEIN" for f in verify(inherit_write)["findings"])

    racy = QloomDocument(
        doc_id="race.test",
        tier=Tier.L4,
        state=AgentState.MUTATION_PREPARE.value,
    )
    racy.charter.goal = "Detect concurrent write conflict."
    racy.weave.mode = WorkspaceMode.SHARE
    racy.weave.nodes = [
        WeaveNode(
            node_id="w1",
            spin=Spin.S,
            state=AgentState.MUTATION_PREPARE.value,
            reads=["a.py"],
            writes=["a.py"],
            lifecycle=NodeLifecycle.ACTIVE,
        ),
        WeaveNode(
            node_id="w2",
            spin=Spin.S,
            state=AgentState.MUTATION_PREPARE.value,
            reads=["a.py"],
            writes=["b.py"],
            lifecycle=NodeLifecycle.PENDING,
        ),
    ]
    racy.pulse.focus = "w1"
    racy.pulse.next_actions = ["Resolve read-write conflict."]
    racy.seal = compute_seal(racy)
    rep_race = verify(racy)
    assert rep_race["valid"] is False
    assert rep_race["concurrent_hazards_count"] >= 1
    assert any(f["law"] == "LAW_05_SPIN_AND_BERNSTEIN" for f in rep_race["findings"])

    # Ordering w2 after w1 removes the concurrent hazard
    racy.weave.nodes[1].deps = ["w1"]
    racy.seal = compute_seal(racy)
    assert verify(racy)["valid"] is True


def test_law06_dag_and_refs_and_law07_clarity_ceiling() -> None:
    cyc_doc = sample_qloom(version=QLOOM_V2)
    cyc_doc.weave.nodes[0].deps = ["t_tests"]
    cyc_doc.seal = compute_seal(cyc_doc)
    assert any(f["law"] == "LAW_06_DAG_AND_REFS" for f in verify(cyc_doc)["findings"])

    sup_cyc = sample_qloom(version=QLOOM_V2)
    sup_cyc.lattice.relations[1].rows[0][5] = "c2"  # c1 -> c2 -> c1
    sup_cyc.seal = compute_seal(sup_cyc)
    assert any(f["law"] == "LAW_06_DAG_AND_REFS" for f in verify(sup_cyc)["findings"])

    fluff_doc = sample_qloom(version=QLOOM_V2)
    fluff_doc.charter.goal = "Leverage a seamless tapestry to verify auth."
    fluff_doc.seal = compute_seal(fluff_doc)
    rep_fluff = verify(fluff_doc)
    assert any(f["law"] == "LAW_07_CLARITY_AND_CEILING" for f in rep_fluff["findings"])

    huge_doc = sample_qloom(version=QLOOM_V2)
    huge_doc.charter.locks = [
        lk for lk in huge_doc.charter.locks if lk.kind != "budget"
    ]
    huge_doc.pulse.filament = "x" * (MAX_WIRE_CHARS + 200)
    huge_doc.seal = compute_seal(huge_doc)
    assert any(f["law"] == "LAW_07_CLARITY_AND_CEILING" for f in verify(huge_doc)["findings"])
    rep_relaxed = verify(huge_doc, enforce_wire_ceiling=False)
    assert rep_relaxed["valid"] is True
    assert rep_relaxed["metrics"]["compression_saving_ratio"] is not None
    assert "LAW_08_WIRE_EFFICIENCY" in rep_relaxed["laws_checked"]
