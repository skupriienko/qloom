# qloom

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dependencies: Zero](https://img.shields.io/badge/dependencies-0%20(pure%20stdlib)-10b981.svg)](#installation)
[![MCP Ready](https://img.shields.io/badge/MCP-Stdio%20JSON--RPC%202.0-6366f1.svg)](#mcp-client-configuration)
[![Types: Mypy Strict](https://img.shields.io/badge/types-mypy%20strict-blue.svg)](https://mypy-lang.org/)

> **Standalone `QLOOM/2.0` & `QLOOM/1.0` (`.qloom`) Algebraic State, Multi-Agent Weave & Cryptographic Provenance Format**  
> A zero-dependency, pure-stdlib protocol and verification engine engineered for **AI/LLM agents, multi-agent coding swarms, CLI coding harnesses, tool sandboxes, and long-horizon context compaction**.

---

## What QLOOM Is & Why It Exists

AI/LLM agent harnesses routinely stitch together incompatible formats: raw JSON blobs for state checkpoints, untyped Markdown (`AGENTS.md` / `TODO.md`) for plans, YAML for policies, and ad-hoc shell strings for tool calls. Under multi-agent concurrency and long-horizon compaction, those formats fail silently:

- **Context Rot & Lossy Compaction**: Truncating agent history destroys provenance chains unless immutable constraints (`@charter`) and active continuations (`@pulse`) survive progressive projection (`L4 -> L0`) with cryptographic `parent=` lineage.
- **Multi-Agent Race Conditions**: Parallel coding or research workers overwrite shared files when execution plans lack explicit `R={}` / `W={}` read/write partitions and **Bernstein concurrency** checks (`mode=share`).
- **Prompt Injection & Taint Escalation**: Untrusted external payloads (web fetches, webhooks, third-party tool output) leak into trusted plans when a format cannot separate `T0/T1` verified facts from `T2/T3` quarantined blobs (`@vault`).
- **Shell-Injection & Unbounded Tool Runs**: Inline shell strings in agent plans invite `CWE-78` command injection and hung processes unless tool witnesses and saga rollbacks use strict `argv` lists with explicit timeouts (`@contracts`).
- **Arithmetic & Token-Budget Drift**: Row truncation, silent budget overruns, and hook-output clipping happen unnoticed without inline relation assertions (`^count`, `^sum`, `^tol`, `^net`, `^quota`) and an `8,000`-character wire ceiling.

**`QLOOM/2.0` (`.qloom`)** solves all five in a single human-readable, diff-friendly, cryptographically sealed (`=~`) 6-plane algebraic state file verified statically in sub-millisecond time before any agent mutates a workspace.

---

## Format Comparison

| Capability | **QLOOM/2.0 (`.qloom`)** | **JSON Checkpoints** | **YAML Agent Configs** | **Markdown (`AGENTS.md`)** | **TOML** | **XML** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Native 6-Plane Agent State** | ✅ Charter..Pulse | ❌ Ad-hoc keys | ⚠️ Untyped | ❌ Prose only | ❌ Flat KV | ⚠️ Verbose |
| **Lossless `L4 -> L0` Compaction** | ✅ + `parent=` chain | ❌ Manual trim | ❌ | ❌ Manual edit | ❌ | ❌ |
| **Bernstein Race-Free DAG (`R`/`W`)** | ✅ `mode=share` + waves | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Taint Quarantine (`T0..T3`)** | ✅ `@vault` + `LAW_04` | ❌ | ❌ | ❌ | ❌ | ❌ |
| **CWE-78 Safe `argv` + Rollback** | ✅ `@contracts` + `LAW_03` | ❌ | ⚠️ Strings | ❌ | ❌ | ❌ |
| **Typed Relations & Inline Math** | ✅ `^count`/`^net`/`^tol` | ❌ | ❌ | ❌ | ❌ | ⚠️ XSD |
| **Spend & 8KB Hook Ceiling** | ✅ `tokens<=`/`cost_usd<=` | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Built-In SHA-256 Knot Seal** | ✅ `=~ qloom-<12hex>` | ❌ | ❌ | ❌ | ❌ | ⚠️ DSig |
| **Safe Parsing (No Alias Bombs)** | ✅ Bounded pure stdlib | ✅ | ⚠️ `CWE-776` | ✅ | ✅ | ⚠️ XXE |

> **Legend:** ✅ Built-in & statically verified · ⚠️ Partial, external schema, or safety caveat · ❌ Not supported

---

## Architecture

```text
  QLOOM/1.0 Wire ──▶ parse_qloom() [8 Laws:  LAW_01..08] ──┐
                                                           ▼
  QLOOM/2.0 Wire ──▶ parse_qloom() [10 Laws: LAW_01..10] ──┴─▶ QloomDocument AST
                                                                       │
   ┌────────────────┬────────────────┬────────────────┬────────────────┤
   ▼                ▼                ▼                ▼                ▼
  Verifier        Projector        Wave Planner     Compat & Hub     Draw / MCP
  • verify_qloom  • project_qloom  • plan_weave_    • upgrade/       • draw() ASCII
  • 10 laws       • L4 ──▶ L0        waves()          downgrade      • Stdio MCP
  • =~ SHA-256    • parent= chain  • Bernstein R/W  • link_qlooms()  • 5 MCP tools
```

---

## All 6 Planes & `QLOOM/2.0` Primitives (What & Why)

### Header & Cryptographic Seal (`~=` / `=~`)

| Primitive | Syntax & AST Field | What It Is & Why It Exists |
| :--- | :--- | :--- |
| **Protocol Header** | `~= QLOOM/2.0 id="..." tier=L4 state=... parent="..." epoch=4` | Declares protocol version (`QLOOM/2.0` or `QLOOM/1.0`), document ID, disclosure tier (`L0..L4`), FSM `AgentState`, cryptographic `parent` knot, and monotonic `epoch`. |
| **Window Governance** | `admin=working\|summary`, `tag="..."`, `hub="..."` (`QLOOM/2.0`) | Caps `working` relations below `MAX_WORKING_ROWS = 1000` (`LAW_10`), routes by topic `tag`, and identifies federated `hub` manifests. |
| **SHA-256 Knot Seal** | `=~ knot="qloom-<12hex>" sha256="<64hex>" reconciled=true` | Deterministic Merkle-style SHA-256 footer over canonical body text (`quipu-<12hex>` in `1.0`). Detects single-byte tampering via `LAW_01_KNOT_SEAL`. |
| **Progressive Tiers** | `project_qloom(doc, "L0".."L4")` | Compacts `L4` (all 6 planes) down to `L3` (drops superseded claims), `L2` (drops `T2/T3` & vault), `L1` (drops weave/contracts), or `L0` (`@charter` + `@pulse` only), chaining `parent=` to the source knot. |

### The 6 Planes

| Plane | Primitives | What It Is & Why It Exists |
| :--- | :--- | :--- |
| **`@charter`** | `goal`, `lock ... forbid`, `lock ... budget` (`tokens<=`, `chars<=`, `cost_usd<=`, `retries<=`, `tol_pct<=`), `mandate ... must` | Non-overridable T0 mission constraints, spend/size circuit breakers, and concise rules verified by `LAW_07_CLARITY_AND_CEILING` (`<= 8,000` chars). |
| **`@lattice`** | `relation name(col:type, ...)` (`id`, `mod`, `tier`, `str`, `int`, `float`, `bool`, `ref`, `ref?`), `---` spacers, `^count`, `^sum(col[, s..e])`, `^net(a, b)`, `^tol(col, pct=P)`, `^quota(col, pct=P)` | Columnar epistemic tables tracking `verified`, `inferred`, `tentative`, and `superseded` claims with `T0..T3` trust tiers, band spacers (`---`), and inline arithmetic checks (`LAW_09`). |
| **`@weave`** | `mode=inherit\|share\|branch`, `node <id> spin=Z\|S [face=R\|V] [weight=fine\|medium\|thick] state=<AgentState> deps=[...] R={...} W={...} -> pending\|active\|done\|blocked\|skipped` | Causal execution DAG enforcing read-only `spin=Z`, shadow/canary `face=V`, model-weight routing (`fine`/`medium`/`thick`), and **Bernstein disjointness** (`R`/`W` race freedom under `LAW_05`). |
| **`@contracts`** | `clause <id> { requires: [...], ensures: "...", witness_argv: [...], timeout_s: N, rollback_argv: [...] }` | Pre/post-condition verification clauses using strict `argv` lists (`CWE-78` defense under `LAW_03`), bounded `timeout_s` (`1..86,400s`), and saga `rollback_argv` (`LAW_10`). |
| **`@vault`** | `blob <id> tier=T2\|T3 sha256="..." bytes=N origin="..." uri="..." [wrap="..."]` | Out-of-band quarantine for untrusted external data so `T0/T1` claims, contracts, and `@pulse` focus never depend directly on tainted inputs (`LAW_04_TAINT_LATTICE`). |
| **`@pulse`** | `focus: ->id\|_`, `filament: "..."`, `signals: [...]`, `next: [...]`, `blockers: [...]` | Hot execution cursor, compact single-line status filament, machine signals, bounded next actions, and explicit blockers preserved across every `L4 -> L0` compaction step. |

---

## 10 Real-World AI/LLM Agent & CLI Harness Use Cases

1. **Multi-Agent Coding Swarm Handoff without Race Conditions**: Declare explicit `R={...}` and `W={...}` path sets on `@weave mode=share` nodes and call `plan_weave_waves()` so parallel subagents never trigger `WRITE_WRITE`, `READ_WRITE`, or `WRITE_READ` hazards.
2. **Long-Horizon Context Compaction (`L4 -> L2 -> L0`)**: Run `project_qloom(doc, "L2")` or `distill_qloom_handoff(doc)` at session boundaries to prune superseded reasoning and untrusted blobs while preserving `@charter`, `@pulse`, and cryptographic `parent=` lineage.
3. **Untrusted External Data & Prompt-Injection Quarantine**: Store fetched web pages, webhook payloads, and third-party snippets in `@vault` at `T2`/`T3` so `LAW_04_TAINT_LATTICE` blocks trusted `T0/T1` plans, contracts, or `@pulse.focus` from referencing tainted sources.
4. **Guardrailed CLI Harness Tool Execution & Saga Rollbacks**: Replace raw shell strings with structured `witness_argv`, bounded `timeout_s`, and deterministic `rollback_argv` in `@contracts`, enforced statically by `LAW_03_SAFE_ARGV` and `LAW_10_LINEAGE_AND_SAGA_BOUNDS`.
5. **Planner -> Executor Model Routing**: Tag complex architecture/patching nodes with `weight=thick`, mid-complexity test nodes with `weight=medium`, and fast lint/canary checks with `weight=fine` inside `@weave` so orchestrators route steps to the right model tier.
6. **Evolving Belief & Claim Supersession in Deep Research Agents**: Track findings in `@lattice` with `mod=tentative|inferred|verified|superseded` and acyclic `supersedes:ref?` chains (`LAW_06_DAG_AND_REFS`) so outdated hypotheses drop cleanly at `L3`/`L2`.
7. **Shadow/Canary Dry-Run Verification (`face=V` vs `face=R`)**: Pair primary mutating nodes (`face=R`) with read-only shadow/canary verification twins (`face=V spin=Z`) in the same signed `.qloom` packet (`LAW_05` forbids writes on `face=V` in `mode=share`).
8. **Token & Dollar Spend Circuit Breakers**: Enforce `tokens<=`, `chars<=`, `cost_usd<=`, `retries<=`, and `tol_pct<=` locks in `@charter`, paired with `@lattice` `^tol` and `^net` checks to halt runaway agent loops before budget exhaustion.
9. **Federated Swarm Hub Rollup (`link_qlooms`)**: Aggregate heterogeneous `QLOOM/1.0` and `QLOOM/2.0` worker packets into a single sealed `hub` manifest (`admin=summary`, `tag="swarm_hub"`) with `^count` and `^sum(nodes)` invariants.
10. **Deterministic CI / Pre-Commit State & Ledger Audit Gates**: Run `qloom verify --file state.qloom --json` in pre-commit hooks and GitHub Actions to validate all 10 static laws, SHA-256 knot seals, and the `8,000`-char hook ceiling in under a millisecond.

---

## Visual CLI State & DAG Renderer (`qloom draw`)

Inspect any `QLOOM/1.0` or `QLOOM/2.0` packet as a compact ASCII/Unicode 6-plane diagram in your terminal or Python code:

```bash
qloom draw --file examples/agent_handoff_v2.qloom
qloom draw --file examples/parallel_swarm_weave.qloom --max-rows 8
```

```python
import qloom

with open("examples/agent_handoff_v2.qloom", encoding="utf-8") as fh:
    print(qloom.draw(fh.read()))  # aliases: qloom.draw_qloom(), qloom.render_qloom_ascii()
```

### Example 1: Guardrailed Auth Migration Handoff (`examples/agent_handoff_v2.qloom`)

```text
=== QLOOM/2.0: epic.auth.v2 [tier=L4 state=MUTATION_PREPARE epoch=4 admin=working tag=auth_migration | knot=qloom-fa62f41be2b0] ===
════════════════════════════════════════════════════════════════════════════════════
  ├─ @charter  goal: Migrate token validator to stdlib HMAC verification.
  │            locks=[G0_NO_SHELL, G0_BUDGET] mandates=1
  ├─ @lattice
  │   ├── relation artifacts (2 rows)
  │   │   [0] art_audit | T1 | "artifacts/auth_audit.md"
  │   │   [1] adr_04 | T0 | "docs/adr/0004_hmac_stdlib.md"
  │   ├── relation claims (3 rows) ^count=3
  │   │   [0] c1 | superseded | T1 | "JWT parser uses custom base64 decoder." | ->art_audit | _
  │   │   [1] c2 | verified | T0 | "Auth validator enforces stdlib HMAC-SHA256." | ->adr_04 | ->c1
  │   │   [2] c3 | tentative | T2 | "External RFC 7519 draft notes key rotation window." | ->v_ext_rfc | _
  ├─ @weave (mode=share)
  │   ├── [done] n_audit (spin=Z R fine) R=1 W=0
  │   ├── [active] n_patch (spin=S R thick) deps=[n_audit] R=1 W=1
  │   ├── [pending] n_canary (spin=Z V fine) deps=[n_patch] R=1 W=0
  │   └── [pending] n_tests (spin=S R medium) deps=[n_patch] R=1 W=1
  ├─ @contracts clauses=[C_UNIT]
  ├─ @vault    quarantined=[v_ext_rfc(T2)]
  └─ @pulse    focus=->n_patch next=2 blockers=0
════════════════════════════════════════════════════════════════════════════════════
```

### Example 2: Parallel Swarm Weave & Ledger Assertions (`examples/parallel_swarm_weave.qloom`)

```text
=== QLOOM/2.0: swarm.release.v2 [tier=L4 state=MUTATION_PREPARE epoch=2 admin=working tag=parallel_swarm hub=SwarmHub | knot=qloom-0bc681b7f44d] ===
════════════════════════════════════════════════════════════════════════════════════
  ├─ @charter  goal: Run parallel module updates with disjoint write sets and budget checks.
  │            locks=[L_NO_SHELL, L_SPEND] mandates=1
  ├─ @lattice
  │   ├── relation ledger (4 rows) ^count=4 ^sum(credit, 0..1)=600 ^net(credit, debt)=0 ^tol(credit, pct=5.0)=980 ^quota(guard, pct=22.5)=4000
  │   │   [0] w_api | verified | T0 | 300 | 250 | 200
  │   │   [1] w_ui | verified | T0 | 300 | 250 | 200
  │   │   [2] w_docs | inferred | T1 | 200 | 250 | 250
  │   │   [3] w_qa | verified | T0 | 200 | 250 | 250
  ├─ @weave (mode=share)
  │   ├── [done] n_plan (spin=Z R thick) R=1 W=0
  │   ├── [active] n_api (spin=S R medium) deps=[n_plan] R=1 W=1
  │   ├── [active] n_ui (spin=S R fine) deps=[n_plan] R=1 W=1
  │   ├── [pending] n_shadow (spin=Z V fine) deps=[n_api,n_ui] R=2 W=0
  │   └── [pending] n_qa (spin=S R medium) deps=[n_api,n_ui] R=2 W=1
  ├─ @contracts clauses=[C_SWARM]
  └─ @pulse    focus=->n_api next=2 blockers=0
════════════════════════════════════════════════════════════════════════════════════
```

---

## Installation

`qloom` requires **Python 3.10+** and has **zero runtime dependencies**.

```bash
# Install from PyPI (when published) or directly from GitHub
pip install qloom
pip install "git+https://github.com/skupriienko/qloom.git"

# Or clone and install in editable mode
git clone https://github.com/skupriienko/qloom.git
cd qloom
pip install -e .
```

---

## Quick Python API

```python
import qloom

# 1. Generate or parse a sealed QLOOM/2.0 document
doc = qloom.sample_qloom(version="QLOOM/2.0")
wire = qloom.dump(doc)

# 2. Parse, roundtrip AST dict, and run all 10 static verification laws
parsed = qloom.parse(wire)
ast_dict = qloom.loads(wire)
assert qloom.dumps(ast_dict) == wire

report = qloom.verify(wire)
assert report["valid"] is True
assert len(report["laws_checked"]) == 10  # 8 laws for QLOOM/1.0, 10 for QLOOM/2.0

# 3. Progressive disclosure compaction (L4 -> L2 -> L0) & wave scheduling
l0_doc = qloom.project(parsed, "L0")
assert l0_doc.parent == parsed.seal.knot
waves = qloom.plan_weave_waves(parsed)

# 4. Visual ASCII diagram, version shims, distillation & hub federation
print(qloom.draw(wire))
v1_doc = qloom.downgrade_qloom_to_v1(wire)
v2_doc = qloom.upgrade_qloom_to_v2(v1_doc, admin="working", tag="ci")
summary = qloom.distill_qloom_handoff(v2_doc, tier="L2")
hub = qloom.link_qlooms({"worker_a": summary, "legacy": v1_doc}, hub_id="SwarmHub")
```

---

## CLI Commands

```bash
# Emit a canonical verified QLOOM/2.0 (or QLOOM/1.0) sample packet
qloom sample --version QLOOM/2.0

# Verify all static laws, SHA-256 knot seal, and 8KB hook ceiling
qloom verify --file examples/agent_handoff_v2.qloom --json

# Project L4 state down to L2 or L0 with chained parent= lineage
qloom project --file examples/agent_handoff_v2.qloom --tier L0

# Compile between .qloom wire format and JSON AST
qloom compile --file examples/agent_handoff_v2.qloom --to-json > state.json
qloom compile --file state.json --from-json

# Draw visual 6-plane ASCII/Unicode state & DAG diagram
qloom draw --file examples/parallel_swarm_weave.qloom

# Compute dependency- and Bernstein-safe parallel execution waves
qloom waves --file examples/parallel_swarm_weave.qloom --json

# Upgrade 1.0 -> 2.0, downgrade 2.0 -> 1.0, or distill into summary handoff
qloom upgrade --file examples/legacy_v1_compat.qloom --admin working --tag release
qloom downgrade --file examples/agent_handoff_v2.qloom
qloom distill --file examples/agent_handoff_v2.qloom --tier L2

# Launch the zero-dependency Stdio JSON-RPC 2.0 MCP server
qloom mcp
```

---

## MCP Client Configuration

`qloom` ships a pure-stdlib Stdio JSON-RPC 2.0 MCP server (`qloom mcp`) exposing five tools: `qloom_verify`, `qloom_project`, `qloom_draw`, `qloom_plan_waves`, and `qloom_compat` (`sample`, `upgrade`, `downgrade`, `distill`, `link`, `to_json`, `from_json`).

Add the following block to your MCP client configuration (Claude Desktop, Cursor, Windsurf, etc.):

```json
{
  "mcpServers": {
    "qloom": {
      "command": "qloom",
      "args": ["mcp"]
    }
  }
}
```

---

## Andean Textile & Loom Heritage

Every wire keyword and Python identifier in `QLOOM/2.0` uses concise, explicit English. Historically, the format's structural model draws inspiration from Andean knotted-cord (*quipu/khipu*) accounting and weaving traditions:

| Historical Term | Origin | Concise English Meaning | `QLOOM/2.0` Concept |
| :--- | :--- | :--- | :--- |
| *quipu / khipu* | Quechua | Knotted-cord tactile record for accounting and structured memory | Legacy `quipu-<12hex>` knot seal |
| *waranqa* | Quechua | Administrative unit of 1,000 capping working-ledger granularity | `MAX_WORKING_ROWS = 1000` |
| *pachaka* | Quechua | Decimal unit of 100 used for intermediate grouped rollups | `admin=working\|summary` |
| *inokatha* | Aymara | Balanced double-entry pairing between credit and debt cords | `^net(credit, debt)` |
| *yapa* | Quechua | Small permissible positive margin before an overrun breach | `^tol(col, pct=N)` / `tol_pct<=` |
| *hanan / hurin* (recto / verso) | Quechua / Epigraphy | Complementary upper/primary vs lower/shadow attachment faces | `face=R\|V` (`AttachFace.RECTO\|VERSO`) |
| *top-cord* | Epigraphy | Upward summary cord aggregating pendant cord totals | `@lattice` `^count` / `^sum` checks & `=~` seal |
| *Z / S spin* | Epigraphy | Directional ply twist distinguishing immutable vs mutable threads | `spin=Z` (read-only) / `spin=S` (mutable) |

---

## Documentation & Examples

- **Formal Protocol Specification**: [docs/SPECIFICATION.md](docs/SPECIFICATION.md) — EBNF grammar, data model, canonical serialization, `L4..L0` projection, all 10 static verification laws, compatibility shims, CWE security bounds, and heritage glossary.
- **Examples Cookbook**: [docs/EXAMPLES.md](docs/EXAMPLES.md) — End-to-end recipes for multi-agent handoffs, Bernstein wave planning, `L4 -> L0` compaction, taint quarantine, saga rollbacks, CLI, and Stdio MCP JSON-RPC.
- **Runnable `.qloom` Fixtures**:
  - [examples/agent_handoff_v2.qloom](examples/agent_handoff_v2.qloom) — Sealed `QLOOM/2.0` 6-plane agent handoff with `T0..T2` claims, `@vault` isolation, `face=R|V`, `weight`, and rollback contract
  - [examples/parallel_swarm_weave.qloom](examples/parallel_swarm_weave.qloom) — Sealed `QLOOM/2.0` Bernstein-disjoint parallel swarm with `^net`, `^tol`, `^quota`, and `---` spacers
  - [examples/context_projected_l0.qloom](examples/context_projected_l0.qloom) — `L0` minimal compacted envelope chained via `parent="qloom-fa62f41be2b0"`
  - [examples/legacy_v1_compat.qloom](examples/legacy_v1_compat.qloom) — Sealed `QLOOM/1.0` packet for 8-law backward-compatibility and `upgrade` workflows

---

## License

MIT © [Serhii Kupriienko](https://github.com/skupriienko)
