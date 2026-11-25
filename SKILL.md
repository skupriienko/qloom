---
name: qloom
description: Author, verify, compact, schedule, and visualize QLOOM/2.0 and QLOOM/1.0 (.qloom) 6-plane algebraic agent state packets, Bernstein race-free multi-agent @weave DAGs, L4-to-L0 progressive context projections, taint-quarantined @vault blobs, and CWE-78-safe @contracts via the qloom CLI, Python API, or Stdio MCP server. Use when managing structured AI/LLM agent state, coordinating parallel subagents or coding swarms, compacting long-horizon session context without losing constraints, or enforcing static pre-execution safety gates.
license: MIT
---

# QLOOM Agent Skill (`QLOOM/2.0` & `QLOOM/1.0`)

Use `qloom` to checkpoint AI/LLM session state, verify safety and spend budgets before execution, isolate untrusted external inputs, compact `L4 -> L0` context across session boundaries, and schedule parallel multi-agent swarms without file write races.

## Prerequisites & Setup

Ensure Python `3.10+` is available, then install or verify `qloom`:

```bash
pip install "git+https://github.com/skupriienko/qloom.git"
# Or from a local clone:
pip install -e .
qloom verify --json
```

Optional MCP server setup (Claude Desktop, Cursor, Windsurf, Cline, Zed): run `qloom mcp` (protocol `2024-11-05`, exposes `qloom_verify`, `qloom_project`, `qloom_draw`, `qloom_plan_waves`, `qloom_compat`).

## When to Use

- Passing structured execution state between planner/coordinator and worker subagents (`project_qloom(..., "L2")`).
- Compacting long-horizon agent context across turns or checkpoints (`L4 -> L2 -> L0`) while preserving `parent=` cryptographic lineage.
- Scheduling parallel coding or research workers in `@weave mode=share` without `W∩W`, `W∩R`, or `R∩W` data races (`plan_weave_waves()`).
- Quarantining scraped web pages, webhooks, or third-party tool outputs (`@vault` `T2`/`T3`) away from verified plans and `@contracts`.
- Replacing ad-hoc shell strings in execution clauses with `CWE-78`-safe `witness_argv` lists, timeouts, and rollback commands.

## When Not to Use

- Final natural-language explanations or reports written for human readers.
- Pure data tables, static configuration maps, or billing records without multi-agent workflows or lifecycle state (use JSON or a columnar data format).

## Task Routing & Ordered Workflow

Load [references/syntax-and-laws.md](skills/qloom/references/syntax-and-laws.md) for the 6-plane grammar and 10 verification laws, or [references/agent-workflows-and-antipatterns.md](skills/qloom/references/agent-workflows-and-antipatterns.md) for verified `.qloom` templates and anti-pattern fixes.

| Task | Primary Tool / API | Ordered Action |
| :--- | :--- | :--- |
| **Verify State** | `qloom verify --file S --json` / `qloom_verify` | Validate all 10 (`2.0`) or 8 (`1.0`) static laws, seal, and 8 KB ceiling |
| **Inspect DAG** | `qloom draw --file S` / `qloom_draw` | Render compact 6-plane ASCII state, table assertions, and DAG overview |
| **Plan Swarm Waves** | `qloom waves --file S --json` / `qloom_plan_waves` | Compute dependency-ordered, Bernstein-disjoint parallel worker waves |
| **Compact Context** | `qloom project --file S --tier L2\|L0` / `qloom_project` | Prune superseded claims or vault/weave planes while chaining `parent=` |
| **Re-Seal / AST** | `qloom compile --file S` / `qloom.dump(doc)` | Recompute `=~` SHA-256 knot seal or convert JSON AST <-> `.qloom` |
| **Migrate / Federate** | `qloom upgrade` / `downgrade` / `distill` / `qloom_compat` | Upgrade `1.0 -> 2.0`, distill `L2` handoff, or link workers via `link_qlooms()` |

## Critical Rules for AI Agents

1. **Maintain the 6 planes cleanly**: `@charter`, `@lattice`, `@weave`, `@contracts`, `@vault`, `@pulse`.
2. **Never hand-invent `=~` seals**: Always compute `=~ knot="qloom-<12hex>" sha256="<64hex>" reconciled=true` (`quipu-<12hex>` in `QLOOM/1.0`) via `qloom.dump()`, `qloom compile`, or `qloom_compat`.
3. **Keep `spin=Z` and `face=V` read-only**: Any `@weave` node with `spin=Z` MUST have `W={}`, and in `mode=share`, `face=V` shadow/canary nodes MUST NOT write (`LAW_05`).
4. **Make parallel `mode=share` nodes Bernstein-disjoint**: Concurrent `pending`/`active` nodes lacking a dependency edge MUST NOT share paths across `(W1 ∩ W2)`, `(W1 ∩ R2)`, or `(R1 ∩ W2)`.
5. **Enforce `CWE-78`-safe `argv` lists (`LAW_03`)**: In `@contracts`, `witness_argv` and `rollback_argv` MUST be non-empty `list[str]` without shell wrappers (`sh`, `bash`, `powershell`, `cmd` with `-c`/`/c`) or shell metacharacters (`;`, `|`, `&`, `$`, `` ` ``, `>`, `<`).
6. **Prevent taint escalation (`LAW_04`)**: Never reference `T2`/`T3` `@lattice` rows or `@vault` blob IDs from `@contracts.requires`, `@pulse.focus`, or `T0`/`T1` relations.
7. **Keep mandates crisp and under 8,000 chars (`LAW_07`)**: Write active imperative `@charter` goals/mandates and `@pulse.next` entries (no filler/passive phrasing), and run `qloom project --tier L2|L0` if wire size exceeds `8_000` chars.
8. **Respect `working` table limits (`LAW_10`)**: Keep `@lattice` relations `< 1_000` rows in `admin=working`, set `timeout_s` within `1..86400`, and match `parent` to `^(?:[a-z][a-z0-9_]{1,15}-[0-9a-f]{12}|none)$`.

## Failure Diagnostics (`LAW_01`..`LAW_10`)

| Law ID | Failure Pattern | Fix |
| :--- | :--- | :--- |
| `LAW_01_KNOT_SEAL` | Edited packet without refreshing `=~` seal | Re-seal with `qloom compile --file S` or `qloom.dump(doc)` |
| `LAW_02_CONTENT_SAFETY` | NUL byte, bidi override char, private key/token, or destructive cmd | Strip secrets/bidi chars and avoid destructive shell patterns |
| `LAW_03_SAFE_ARGV` | Empty `witness_argv`, shell wrapper (`bash -c`), or metacharacters | Pass direct executable `argv` (`["pytest", "tests/", "-q"]`) |
| `LAW_04_TAINT_LATTICE` | `T0`/`T1` row, `requires`, or `focus` points to `T2`/`T3`/`@vault` | Isolate untrusted inputs inside `@vault` / `T2`/`T3` only |
| `LAW_05_SPIN_AND_BERNSTEIN` | `spin=Z` with non-empty `W={}`, or overlapping `R`/`W` in `mode=share` | Clear `W={}` on `spin=Z` or partition files / add `deps=[...]` |
| `LAW_06_DAG_AND_REFS` | Cycle in `deps`/`supersedes` or dangling `->id` pointer | Break cycles and declare missing IDs (or drop invalid refs) |
| `LAW_07_CLARITY_AND_CEILING` | Passive/fluff phrasing, `> 8_000` chars, or Charter budget breach | Rewrite concisely in active voice; project `L4 -> L2/L0` |
| `LAW_08_WIRE_EFFICIENCY` | Verbose wire bloated above JSON AST baseline | Compact prose or trim redundant fields |
| `LAW_09_RELATION_ARITHMETIC` | `^count`, `^sum`, slice `^sum`, `^net`, `^tol`, or `^quota` mismatch | Recompute row counts/totals or adjust tolerance bounds |
| `LAW_10_LINEAGE_AND_SAGA_BOUNDS` | Bad `parent`/`tag`/`hub`, `timeout_s` out of range, or `>= 1_000` rows | Fix header strings, clamp timeout, or `distill_qloom_handoff()` |

## Output Contract

When producing or updating a `.qloom` state packet:
1. Validate with `qloom verify --file <packet> --json` and confirm `valid: true` (`findings_count == 0`).
2. Confirm parallel `@weave mode=share` safety via `qloom waves --file <packet> --json`.
3. Report `version`, `tier`, `knot`, `laws_checked` count, and wave plan or compacted character count.

## Limitations

- `verify_qloom()` performs static analysis on contracts and `R`/`W` sets; it does **not** execute `witness_argv` commands inside `@contracts`.
- `SHA-256` `=~` seals prove integrity against tampering, not asymmetric identity authentication.
- CLI `--file` paths are confined by CWE-22 rules to CWD, `$HOME`, or the OS temp directory (or `-` for `stdin`).
