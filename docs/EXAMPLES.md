# QLOOM/2.0 & QLOOM/1.0 Examples Cookbook

Practical, copy-pasteable recipes for multi-agent handoffs, Bernstein concurrency wave planning, `L4 -> L0` compaction, taint isolation, saga rollback contracts, version shims, CLI workflows, and Stdio MCP JSON-RPC.

Runnable `.qloom` fixtures referenced below live in [`examples/`](../examples/):
- [`examples/agent_handoff_v2.qloom`](../examples/agent_handoff_v2.qloom)
- [`examples/parallel_swarm_weave.qloom`](../examples/parallel_swarm_weave.qloom)
- [`examples/context_projected_l0.qloom`](../examples/context_projected_l0.qloom)
- [`examples/legacy_v1_compat.qloom`](../examples/legacy_v1_compat.qloom)

---

## 1. Verify & Inspect a 6-Plane Agent Handoff

```python
import qloom

with open("examples/agent_handoff_v2.qloom", encoding="utf-8") as fh:
    wire = fh.read()

report = qloom.verify(wire)
assert report["valid"] is True
assert report["verdict"] == "VERIFIED"
assert len(report["laws_checked"]) == 10

doc = qloom.parse(wire)
assert doc.doc_id == "epic.auth.v2"
assert doc.seal.knot == "qloom-fa62f41be2b0"
print(qloom.draw(doc))
```

---

## 2. Plan Bernstein-Safe Parallel Execution Waves (`plan_weave_waves`)

**What & Why**: In `@weave mode=share`, `plan_weave_waves()` groups ready nodes into parallel waves only when their `R={}` / `W={}` path sets satisfy Bernstein disjointness.

```python
import qloom

with open("examples/parallel_swarm_weave.qloom", encoding="utf-8") as fh:
    swarm_wire = fh.read()

waves = qloom.plan_weave_waves(swarm_wire)
assert waves == [
    ["n_plan"],
    ["n_api", "n_ui"],      # Disjoint: src/api.py vs src/ui.py
    ["n_qa", "n_shadow"],   # Safe: n_shadow is spin=Z face=V (W={})
]
```

If two active nodes share a write target in `mode=share`, `verify()` catches the race immediately under `LAW_05_SPIN_AND_BERNSTEIN`:

```python
import qloom

racy_wire = """~= QLOOM/2.0 id="race.demo" tier=L4 state=MUTATION_PREPARE parent="qloom-000000000000" epoch=1

@charter {
  goal: "Demonstrate Bernstein write conflict detection."
}

@weave mode=share {
  node w1 spin=S state=MUTATION_PREPARE deps=[] R={"app.py"} W={"app.py"} -> active
  node w2 spin=S state=MUTATION_PREPARE deps=[] R={"app.py"} W={"app.py"} -> active
}

@pulse {
  focus: ->w1
  next: ["Resolve write conflict."]
  blockers: []
}
"""
doc = qloom.parse(racy_wire)
doc.seal = qloom.compute_seal(doc)
rep = qloom.verify(doc)
assert rep["valid"] is False
assert any(f["law"] == "LAW_05_SPIN_AND_BERNSTEIN" for f in rep["findings"])
```

---

## 3. Progressive Context Compaction (`L4 -> L2 -> L0`)

**What & Why**: Shrink working state between turns without losing `@charter` constraints, `@pulse` focus, or cryptographic provenance (`parent=`).

```python
import qloom

with open("examples/agent_handoff_v2.qloom", encoding="utf-8") as fh:
    l4_doc = qloom.parse(fh.read())

l2_doc = qloom.project(l4_doc, "L2")
l0_doc = qloom.project(l4_doc, "L0")

assert l2_doc.parent == l4_doc.seal.knot
assert l0_doc.parent == l4_doc.seal.knot
assert len(l0_doc.lattice.relations) == 0
assert len(l0_doc.weave.nodes) == 0
assert qloom.verify(l0_doc)["valid"] is True
```

Compare with the pre-projected fixture [`examples/context_projected_l0.qloom`](../examples/context_projected_l0.qloom).

---

## 4. Taint Isolation (`@vault` `T2/T3` & `LAW_04_TAINT_LATTICE`)

**What & Why**: External inputs stored in `@vault` (`T2`/`T3`) can inform `tentative` `T2` rows in `@lattice`, but `LAW_04_TAINT_LATTICE` forbids `T0/T1` claims, `@contracts` `requires`, or `@pulse.focus` from trusting them directly.

```python
import qloom

tainted_doc = qloom.sample_qloom(version="QLOOM/2.0")
tainted_doc.contracts.clauses[0].requires.append("v_ext_rfc")
tainted_doc.seal = qloom.compute_seal(tainted_doc)

rep = qloom.verify(tainted_doc)
assert rep["valid"] is False
assert any(f["law"] == "LAW_04_TAINT_LATTICE" for f in rep["findings"])
```

---

## 5. Safe Tool `argv` & Saga Rollback Contracts (`LAW_03` & `LAW_10`)

**What & Why**: `@contracts` rejects shell command wrappers (`bash -c`, `sh -c`) under `LAW_03_SAFE_ARGV` (`CWE-78`) and enforces bounded `timeout_s` (`1..86,400s`) under `LAW_10_LINEAGE_AND_SAGA_BOUNDS`.

```python
import qloom

doc = qloom.sample_qloom(version="QLOOM/2.0")
doc.contracts.clauses[0].witness_argv = ["bash", "-c", "pytest -q"]
doc.contracts.clauses[0].timeout_s = 999_999
doc.seal = qloom.compute_seal(doc)

rep = qloom.verify(doc)
laws = {f["law"] for f in rep["findings"]}
assert "LAW_03_SAFE_ARGV" in laws
assert "LAW_10_LINEAGE_AND_SAGA_BOUNDS" in laws
```

---

## 6. Inline `@lattice` Arithmetic & Band Spacers (`LAW_09`)

**What & Why**: `@lattice` relations verify `^count`, full or sliced `^sum`, double-entry `^net(credit, debt)`, tolerance `^tol`, and cohort `^quota` with strict `bool != int` typing.

```python
import qloom

with open("examples/parallel_swarm_weave.qloom", encoding="utf-8") as fh:
    doc = qloom.parse(fh.read())

ledger = doc.lattice.relations[0]
assert ledger.spacer_indices == [2]
assert [c.kind for c in ledger.checks] == ["count", "sum", "net", "tol", "quota"]
assert qloom.verify(doc)["valid"] is True
```

---

## 7. `QLOOM/1.0` <-> `QLOOM/2.0`, Distillation & Hub Federation

```python
import qloom

with open("examples/legacy_v1_compat.qloom", encoding="utf-8") as fh:
    v1_wire = fh.read()

assert qloom.is_qloom_v1(v1_wire) is True
assert len(qloom.verify(v1_wire)["laws_checked"]) == 8

# Promote 1.0 -> 2.0 preserving the v1 knot in parent=
v2_doc = qloom.upgrade_qloom_to_v2(v1_wire, admin="working", tag="migrated")
assert v2_doc.parent == "quipu-975b6b0b31bd"
assert len(qloom.verify(v2_doc)["laws_checked"]) == 10

# Distill to summary & link heterogeneous workers into a federated hub
summary_doc = qloom.distill_qloom_handoff(v2_doc, tier="L2", doc_id="worker.summary")
hub_doc = qloom.link_qlooms({"migrated": summary_doc, "legacy": v1_wire}, hub_id="SwarmHub")
assert qloom.verify(hub_doc)["valid"] is True
assert len(hub_doc.lattice.relations[0].rows) == 2
```

---

## 8. CLI & Stdio MCP JSON-RPC 2.0 Workflows

### CLI Commands

```bash
qloom verify --file examples/agent_handoff_v2.qloom --json
qloom draw --file examples/parallel_swarm_weave.qloom
qloom waves --file examples/parallel_swarm_weave.qloom --json
qloom project --file examples/agent_handoff_v2.qloom --tier L0
qloom compile --file examples/agent_handoff_v2.qloom --to-json > ast.json
qloom compile --file ast.json --from-json
```

### Stdio MCP JSON-RPC 2.0 (`qloom mcp`)

Send newline-delimited JSON-RPC 2.0 messages to `qloom mcp` over `stdin`:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"qloom_compat","arguments":{"action":"sample","version":"QLOOM/2.0"}}}
```
