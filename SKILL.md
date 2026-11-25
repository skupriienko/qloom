---
name: qloom
description: Zero-dependency QLOOM/2.0 & QLOOM/1.0 (.qloom) algebraic agent state, Bernstein-safe multi-agent weave DAGs, L4->L0 context compaction, taint isolation, CLI, and Stdio MCP server.
---

# QLOOM Agent State & Weave Skill

Use `qloom` whenever serializing, validating, compacting, scheduling, or handoff-sealing structured AI/LLM agent state in `.qloom` (`QLOOM/2.0` and `QLOOM/1.0`) format.

## Format Highlights

- **Header & Cryptographic Seal**: `~= QLOOM/2.0 id="..." tier=L4 state=MUTATION_PREPARE parent="qloom-000000000000" epoch=1 admin=working tag="..." hub="..."` closed by `=~ knot="qloom-<12hex>" sha256="<64hex>" reconciled=true`.
- **Six Typed Planes**:
  - `@charter`: immutable goal, `forbid` locks, spend/size/tolerance `budget` locks (`tokens<=`, `chars<=`, `cost_usd<=`, `retries<=`, `tol_pct<=`), and concise `must` mandates.
  - `@lattice`: typed columnar relations (`id`, `mod`, `tier`, `str`, `int`, `float`, `bool`, `ref`, `ref?`) with `---` band spacers and inline checks (`^count`, `^sum`, slice `^sum(col, s..e)`, `^tol`, `^net`, `^quota`).
  - `@weave`: causal execution DAG (`mode=inherit|share|branch`) with `spin=Z|S`, `face=R|V`, `weight=fine|medium|thick`, explicit `R={}` / `W={}` Bernstein conflict sets, `deps=[]`, and lifecycle status.
  - `@contracts`: precondition `requires`, postcondition `ensures`, `CWE-78`-safe `witness_argv`, `timeout_s`, and `rollback_argv`.
  - `@vault`: out-of-band quarantine for `T2`/`T3` untrusted external payloads (`sha256`, `bytes`, `origin`, `uri`, `wrap`).
  - `@pulse`: active `focus`, single-line `filament`, machine `signals`, `next` actions, and `blockers`.

## Python API

```python
import qloom

# Generate, verify (10 laws in QLOOM/2.0, 8 in QLOOM/1.0), and draw
doc = qloom.sample_qloom(version="QLOOM/2.0")
wire = qloom.dump(doc)
report = qloom.verify(wire)
assert report["valid"] is True
print(qloom.draw(wire))

# Progressive L4 -> L0 compaction & Bernstein wave scheduling
l0_doc = qloom.project(doc, "L0")
waves = qloom.plan_weave_waves(doc)

# Compatibility & federation
v1_doc = qloom.downgrade_qloom_to_v1(wire)
v2_doc = qloom.upgrade_qloom_to_v2(v1_doc, admin="working", tag="release")
summary = qloom.distill_qloom_handoff(v2_doc, tier="L2")
hub = qloom.link_qlooms({"a": summary, "b": v1_doc}, hub_id="SwarmHub")
```

## CLI Commands

```bash
qloom sample --version QLOOM/2.0
qloom verify --file state.qloom --json
qloom project --file state.qloom --tier L0
qloom compile --file state.qloom --to-json
qloom draw --file state.qloom
qloom waves --file state.qloom --json
qloom upgrade --file v1.qloom --admin working --tag release
qloom downgrade --file v2.qloom
qloom distill --file v2.qloom --tier L2
qloom mcp
```

## Stdio MCP Server (`qloom mcp`)

Configure `qloom mcp` as a zero-dependency Stdio JSON-RPC 2.0 MCP server exposing five tools:

- `qloom_verify`: verify `QLOOM/2.0` (10 laws) or `QLOOM/1.0` (8 laws) packets (`qloom_text`, `enforce_wire_ceiling`).
- `qloom_project`: project `L4 -> L0` with chained `parent=` lineage (`qloom_text`, `tier`).
- `qloom_draw`: render compact 6-plane ASCII state & DAG diagram (`qloom_text`, `max_rows`, `max_chars`).
- `qloom_plan_waves`: schedule Bernstein-safe parallel execution waves (`qloom_text`).
- `qloom_compat`: `sample`, `upgrade`, `downgrade`, `distill`, `link`, `to_json`, `from_json`.
