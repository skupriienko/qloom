# QLOOM Syntax, 6 Planes, 10 Laws, CLI & MCP Reference

## 1. Header, Versioning & Projection Tiers (`L0`..`L4`)

- **Header (`~=`)**:
  ```text
  ~= QLOOM/2.0 id="epic.auth.v2" tier=L4 state=MUTATION_PREPARE parent="qloom-000000000000" epoch=4 admin=working tag="auth_migration" hub="SwarmHub"
  ```
- **Legacy (`QLOOM/1.0`)**: Uses `~= QLOOM/1.0 ... parent="quipu-000000000000" epoch=1` (rejects `2.0`-only fields: `admin`, `tag`, `hub`, `face`, `weight`, `---`, `^sum(c, s..e)`, `^net`, `^tol`, `^quota`, `signals`, `timeout_s`, `rollback_argv`, `wrap`).
- **Valid `AgentState` values**: `IDLE`, `PLANNING`, `REASONING`, `DOC_RESOLUTION`, `SANDBOX_COMPUTE`, `CRITIQUE_GATE`, `MUTATION_PREPARE`, `EXECUTING`, `VERIFYING`, `SYNTHESIS`, `HANDOFF`, `BLOCKED`, `DONE`.
- **Seal (`=~`)**: `=~ knot="qloom-<12hex>" sha256="<64hex>" reconciled=true` (`knot="quipu-<12hex>"` in `QLOOM/1.0`).
- **Progressive Disclosure Projections (`project_qloom(doc, tier)`)**:

| Tier | Retained Planes | `@lattice` Retention | Best Use |
| :--- | :--- | :--- | :--- |
| **`L4`** | All 6 planes | Full lossless history including `superseded` rows | Full cross-session checkpoint |
| **`L3`** | All 6 planes | Drops `superseded` rows; keeps active `T0..T3` | Active verification snapshot |
| **`L2`** | `@charter`, `@lattice`, `@weave`, `@contracts`, `@pulse` | Keeps only non-superseded `T0`/`T1` rows (drops `@vault`) | Clean worker/subagent handoff |
| **`L1`** | `@charter`, `@lattice`, `@pulse` | Keeps only non-superseded `T0`/`T1` rows (clears `->id` weave refs) | Lightweight epistemic summary |
| **`L0`** | `@charter`, `@pulse` | Cleared | Compact `< 1 KB` heartbeat/status |

Every projection sets `parent = doc.seal.knot` before sealing.

## 2. Six Algebraic Planes Summary

1. **`@charter`**:
   - `goal: "..."`
   - `lock <id>: forbid "<pattern>"` or `lock <id>: budget tokens<=N chars<=N cost_usd<=F retries<=N tol_pct<=F`
   - `mandate <id>: must "<active imperative sentence>"`
2. **`@lattice`**:
   - `relation <name>(col:type, ...) [^count=N] [^sum(col)=V] [^sum(col, s..e)=V] [^net(c, d)=V] [^tol(col, pct=P)=N] [^quota(col, pct=P)=Pop] { ... }`
   - Types: `id`, `mod`, `tier`, `str`, `int`, `float`, `bool`, `ref`, `ref?`; band spacers `---` permitted inside `{ ... }` (`2.0`).
3. **`@weave mode=inherit|share|branch`**:
   - `node <id> spin=Z|S [face=R|V] [weight=fine|medium|thick] state=<AgentState> deps=[...] R={"path", ...} W={"path", ...} -> pending|active|done|blocked|skipped`
   - `mode=inherit` forbids any non-empty `W={}`; `mode=share` enforces strict Bernstein R/W disjointness across concurrent `pending`/`active` nodes.
4. **`@contracts`**:
   - `clause <id> { requires: [->id, ...], ensures: "...", witness_argv: ["cmd", ...], timeout_s: 300, rollback_argv: ["cmd", ...] }`
5. **`@vault`**:
   - `blob <id> tier=T2|T3 sha256="<64hex>" bytes=N origin="..." uri="..." [wrap="..."]`
6. **`@pulse`**:
   - `focus: ->id | _`
   - `filament: "..."`
   - `signals: ["...", ...]` (`2.0`)
   - `next: ["...", ...]`
   - `blockers: ["...", ...]`

## 3. All 10 Verification Laws (`LAW_01`..`LAW_10`)

- **`LAW_01`..`LAW_08` (`1.0` & `2.0`)**:
  1. `LAW_01_KNOT_SEAL` — SHA-256 & knot prefix (`quipu-` in `1.0`, `qloom-` in `2.0`) match canonical body.
  2. `LAW_02_CONTENT_SAFETY` — Rejects NUL, bidi overrides, private keys/API tokens, and destructive commands.
  3. `LAW_03_SAFE_ARGV` — Direct non-empty `list[str]` in `witness_argv`/`rollback_argv` without shell wrappers or metacharacters.
  4. `LAW_04_TAINT_LATTICE` — Blocks `T0`/`T1` rows, `@contracts.requires`, and `@pulse.focus` from referencing `T2`/`T3`/`@vault`.
  5. `LAW_05_SPIN_AND_BERNSTEIN` — Enforces `AgentState`, `spin=Z => W={}`, `face=V => W={}` in `share`, and Bernstein R/W disjointness.
  6. `LAW_06_DAG_AND_REFS` — Acyclic `@weave.deps` and `@lattice.supersedes` + complete `->id` closure.
  7. `LAW_07_CLARITY_AND_CEILING` — Concise active-voice lint on charter/next actions, `<= 8_000` wire ceiling, and Charter budgets.
  8. `LAW_08_WIRE_EFFICIENCY` — Verifies compact `.qloom` representation relative to formatted AST JSON.
- **`LAW_09` & `LAW_10` (`QLOOM/2.0` additions)**:
  9. `LAW_09_RELATION_ARITHMETIC` — Row type/arity checks, `---` spacer sorting, `^count`, `^sum`, slice `^sum`, `^net`, `^tol`, `^quota`.
  10. `LAW_10_LINEAGE_AND_SAGA_BOUNDS` — Valid `parent`/`tag`/`hub`/`wrap`, `timeout_s` bounds, and `< 1_000` rows in `admin=working`.

## 4. CLI & Stdio MCP Server (`2024-11-05`)

- **CLI (`qloom <action>`)**: `sample`, `verify`, `project`, `draw`, `waves`, `compile`, `upgrade`, `downgrade`, `distill`, `mcp` (`-` reads `stdin`).
- **MCP (`qloom mcp`)**: Exposes `qloom_verify`, `qloom_project`, `qloom_draw`, `qloom_plan_waves`, and `qloom_compat` (`sample`, `upgrade`, `downgrade`, `distill`, `link`, `to_json`, `from_json`).
