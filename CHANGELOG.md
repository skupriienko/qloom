# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-11-25

### Added
- Initial standalone public release of `qloom` implementing the `QLOOM/2.0` (`.qloom`) algebraic state, multi-agent weave, and cryptographic provenance format with zero runtime dependencies.
- 6-plane typed AST (`@charter`, `@lattice`, `@weave`, `@contracts`, `@vault`, `@pulse`) with lossless `QloomDocument.to_dict()` / `from_dict()` JSON round-tripping.
- `QLOOM/2.0` extensions: `admin=working|summary`, `tag`, `hub`, `@charter` spend/retry/tolerance locks (`cost_usd<=`, `retries<=`, `tol_pct<=`), `@lattice` `---` band spacers and inline arithmetic checks (`^count`, `^sum`, slice `^sum`, `^tol`, `^net`, `^quota`), `@weave` execution surfaces (`face=R|V`) and model weights (`weight=fine|medium|thick`), `@contracts` saga bounds (`timeout_s`, `rollback_argv`), and `@vault` `wrap` tags.
- 10-law static verification engine (`verify_qloom`) enforcing SHA-256 knot sealing (`LAW_01`), content/secret safety (`LAW_02`), `CWE-78` safe `argv` checks (`LAW_03`), `T0..T3` taint non-interference (`LAW_04`), spin and Bernstein R/W concurrency (`LAW_05`), DAG & reference closure (`LAW_06`), conciseness & `8,000`-char hook ceiling (`LAW_07`), compression efficiency (`LAW_08`), relation arithmetic (`LAW_09`), and lineage & saga bounds (`LAW_10`).
- Progressive disclosure projector (`project_qloom`) supporting `L4 -> L0` context compaction with chained cryptographic `parent=` knots.
- Bernstein-disjoint parallel execution wave planner (`plan_weave_waves` / `plan_waves`), visual 6-plane ASCII/Unicode renderer (`render_qloom_ascii` / `draw`), version shims (`upgrade_qloom_to_v2`, `downgrade_qloom_to_v1`), handoff distillation (`distill_qloom_handoff`), and multi-packet hub federation (`link_qlooms`).
- Standalone `qloom` CLI and pure-stdlib Stdio JSON-RPC 2.0 MCP server (`qloom mcp`, `QloomMCPServer`, `serve_mcp_stdio`).

## [1.0.0] - 2026-10-01

### Added
- Baseline `QLOOM/1.0` 6-plane wire specification (`~= QLOOM/1.0`) with `quipu-<12hex>` SHA-256 knot sealing.
- 8-law static verification (`LAW_01`..`LAW_08`), `L4..L0` progressive projection, `T0..T3` taint isolation, `spin=Z|S` read/write separation, Bernstein concurrency checks, and `CWE-78` safe `witness_argv` enforcement.
