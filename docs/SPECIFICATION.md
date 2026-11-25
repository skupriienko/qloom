# QLOOM/2.0 & QLOOM/1.0 Format Specification

- **Document Class**: Technical Protocol Specification
- **Protocol Versions**: `QLOOM/2.0` (Default), `QLOOM/1.0` (Legacy Compatible)
- **Media Type**: `application/qloom`
- **File Extension**: `.qloom`
- **Character Encoding**: UTF-8 (NUL `\x00` strictly forbidden)
- **Default Wire Header**: `~= QLOOM/2.0 id="<doc_id>" tier=L2 state=REASONING parent="qloom-000000000000" epoch=1`

---

## 1. Abstract & Conformance

This specification defines the lexical rules, formal EBNF grammar, 6-plane typed AST data model, canonical body serialization, SHA-256 knot sealing algorithm, `L4 -> L0` progressive context projection, backward-compatibility rules, and 10 static verification laws (`LAW_01`..`LAW_10`) of the **QLOOM** (`.qloom`) algebraic state and multi-agent handoff format.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHOULD**, and **MAY** in this document are to be interpreted as described in RFC 2119.

### 1.1 Design Goals

1. **Deterministic 6-Plane Agent State**: Separate immutable policies (`@charter`), typed epistemic tables (`@lattice`), causal execution graphs (`@weave`), tool verification clauses (`@contracts`), quarantined external blobs (`@vault`), and active continuation state (`@pulse`).
2. **Lossless Context Compaction (`L4 -> L0`)**: Shrink payloads progressively across disclosure tiers while preserving mission locks, continuation cursors, and cryptographic `parent=` lineage.
3. **Race-Free Parallel Execution**: Enforce read-only (`spin=Z`), shadow/canary (`face=V`), and **Bernstein concurrency** disjointness ($W_i \cap W_j = \emptyset$, $R_i \cap W_j = \emptyset$, $W_i \cap R_j = \emptyset$) across `@weave mode=share` nodes.
4. **Non-Interference Taint Isolation (`T0..T3`)**: Quarantine `T2`/`T3` external inputs inside `@vault` and reject references from trusted `T0`/`T1` claims, `@contracts`, or `@pulse.focus`.
5. **Inline Arithmetic & Cryptographic Tamper Evidence**: Verify `@lattice` invariants (`^count`, `^sum`, `^tol`, `^net`, `^quota`) and `=~` SHA-256 knot seals statically before execution.

---

## 2. Lexical Rules & Wire Bounds

A valid QLOOM payload MUST be a UTF-8 string containing zero NUL (`\x00`) bytes and MUST NOT exceed `MAX_QLOOM_BYTES` (`500_000` bytes).

### 2.1 Whitespace, Comments & Separators

- Horizontal whitespace (`' '`, `'\t'`, `'\r'`) separates tokens outside string literals.
- Comments begin with `#` outside string literals and run to the end of the line.
- Closing plane and relation braces (`}`) MUST sit on their own line after stripping comments and surrounding whitespace.
- Band spacers (`---`) inside `@lattice` relations MUST appear on their own line (invalid in `QLOOM/1.0`).

### 2.2 Lexical Tokens

| Token | Pattern / Definition | Notes |
| :--- | :--- | :--- |
| `HEADER_OP` | `~=` | Opens mandatory header on first non-empty line |
| `SEAL_OP` | `=~` | Opens optional/sealed footer on final non-empty line |
| `SPACER` | `---` | Band spacer inside `@lattice` `relation` (`QLOOM/2.0`) |
| `ARROW` | `->` | Node status transition or entity reference prefix (`->id`) |
| `IDENT` | `[A-Za-z_][A-Za-z0-9_.\-:/]*` | Identifiers, states, node/blob IDs |
| `STRING` | `"..."` | RFC 8259 JSON-compliant UTF-8 double-quoted string |
| `INT` / `FLOAT` | Base-10 integer or finite IEEE-754 float | `NaN` and `Inf` are rejected |

---

## 3. Formal EBNF Grammar

```ebnf
document       ::= header plane* [ seal ] EOF ;

header         ::= "~=" version header_kv+ ;
version        ::= "QLOOM/2.0" | "QLOOM/1.0" ;
header_kv      ::= IDENT "=" ( STRING | IDENT | INT ) ;

seal           ::= "=~" seal_kv+ ;
seal_kv        ::= IDENT "=" ( STRING | IDENT | "true" | "false" ) ;

plane          ::= charter_plane
                 | lattice_plane
                 | weave_plane
                 | contracts_plane
                 | vault_plane
                 | pulse_plane ;

charter_plane  ::= "@charter" "{" charter_stmt* "}" ;
charter_stmt   ::= "goal:" STRING
                 | "lock" IDENT ":" ( "forbid" STRING | "budget" budget_pred+ )
                 | "mandate" IDENT ":" "must" STRING ;
budget_pred    ::= ( "tokens<=" | "chars<=" | "retries<=" ) INT
                 | ( "cost_usd<=" | "tol_pct<=" ) NUMBER ;

lattice_plane  ::= "@lattice" "{" relation_blk* "}" ;
relation_blk   ::= "relation" IDENT "(" col_list ")" rel_check* "{" rel_body "}" ;
col_list       ::= col_spec ( "," col_spec )* ;
col_spec       ::= IDENT ":" ( "id" | "mod" | "tier" | "str" | "int" | "float" | "bool" | "ref" | "ref?" ) ;
rel_check      ::= "^count=" INT
                 | "^sum(" IDENT [ "," INT ".." INT ] ")=" NUMBER
                 | "^net(" IDENT "," IDENT ")=" NUMBER
                 | "^(tol|quota)(" IDENT "," "pct=" NUMBER ")=" NUMBER ;
rel_body       ::= ( row | "---" )* ;
row            ::= cell ( "|" cell )* ;
cell           ::= IDENT | STRING | NUMBER | "true" | "false" | "->" IDENT | "_" ;

weave_plane    ::= "@weave" [ "mode=" ( "inherit" | "share" | "branch" ) ] "{" weave_node* "}" ;
weave_node     ::= "node" IDENT node_kv+ "->" lifecycle ;
node_kv        ::= "spin=" ( "Z" | "S" )
                 | "face=" ( "R" | "V" )
                 | "weight=" ( "fine" | "medium" | "thick" )
                 | "state=" IDENT
                 | "deps=" "[" [ IDENT ( "," IDENT )* ] "]"
                 | "R=" "{" [ str_or_ident ( "," str_or_ident )* ] "}"
                 | "W=" "{" [ str_or_ident ( "," str_or_ident )* ] "}" ;
lifecycle      ::= "pending" | "active" | "done" | "blocked" | "skipped" ;

contracts_plane ::= "@contracts" "{" clause_blk* "}" ;
clause_blk     ::= "clause" IDENT "{" clause_attr* "}" ;
clause_attr    ::= "requires:" "[" [ "->" IDENT ( "," "->" IDENT )* ] "]"
                 | "ensures:" STRING
                 | "witness_argv:" "[" [ str_or_ident ( "," str_or_ident )* ] "]"
                 | "timeout_s:" INT
                 | "rollback_argv:" "[" [ str_or_ident ( "," str_or_ident )* ] "]" ;

vault_plane    ::= "@vault" "{" vault_blob* "}" ;
vault_blob     ::= "blob" IDENT "tier=" ( "T2" | "T3" ) vault_kv+ ;
vault_kv       ::= ( "sha256" | "origin" | "uri" | "wrap" ) "=" STRING
                 | "bytes=" INT ;

pulse_plane    ::= "@pulse" "{" pulse_attr* "}" ;
pulse_attr     ::= "focus:" ( "->" IDENT | "_" )
                 | "filament:" STRING
                 | "signals:" "[" [ str_or_ident ( "," str_or_ident )* ] "]"
                 | "next:" "[" [ str_or_ident ( "," str_or_ident )* ] "]"
                 | "blockers:" "[" [ str_or_ident ( "," str_or_ident )* ] "]" ;
```

---

## 4. Header Attributes, Data Model & Canonical Sealing

### 4.1 Header Attributes (`~=`)

| Attribute | Versions | Format / Values | AST Field | Description |
| :--- | :--- | :--- | :--- | :--- |
| `id` | `1.0`, `2.0` | Non-empty `STRING` (REQUIRED) | `QloomDocument.doc_id` | Stable logical packet identifier |
| `tier` | `1.0`, `2.0` | `L0`, `L1`, `L2`, `L3`, `L4` (default `L2`) | `QloomDocument.tier` | Progressive disclosure tier |
| `state` | `1.0`, `2.0` | Valid `AgentState` name or value (default `REASONING`) | `QloomDocument.state` | Agent workflow FSM state |
| `parent` | `1.0`, `2.0` | `quipu-<12hex>`, `qloom-<12hex>`, `<prefix>-<12hex>`, or `"none"` | `QloomDocument.parent` | Cryptographic parent knot for compaction/upgrade lineage |
| `epoch` | `1.0`, `2.0` | Non-negative `INT` (default `1`) | `QloomDocument.epoch` | Monotonic handoff epoch counter |
| `admin` | `2.0` | `working` or `summary` | `QloomDocument.admin` | Operational window scale (`working` caps relation rows `< 1,000`) |
| `tag` | `2.0` | Safe `STRING` (`^[A-Za-z0-9_.\-/: ]{1,64}$`) | `QloomDocument.tag` | Domain/topic routing label |
| `hub` | `2.0` | Safe `STRING` (`^[A-Za-z0-9_.\-/: ]{1,64}$`) | `QloomDocument.hub` | Federated swarm hub identifier |

### 4.2 Valid FSM Workflow States (`AgentState`)

`IDLE`, `PLANNING`, `REASONING`, `DOC_RESOLUTION`, `SANDBOX_COMPUTE`, `CRITIQUE_GATE`, `MUTATION_PREPARE`, `EXECUTING`, `VERIFYING`, `SYNTHESIS`, `HANDOFF`, `BLOCKED`, `DONE`.

### 4.3 Canonical Serialization (`serialize_body`) & SHA-256 Knot Seal (`=~`)

Before computing or verifying `=~`, `serialize_body(doc)` emits:

1. Header line: `~= <version> id=<json(doc_id)> tier=<tier> state=<state> parent=<json(parent)> epoch=<epoch>` plus `admin=...`, `tag=...`, `hub=...` in `QLOOM/2.0` when non-`None`.
2. Single blank line `""`.
3. `@charter { ... }` (always emitted).
4. `@lattice { ... }` (omitted if no relations).
5. `@weave mode=<mode> { ... }` (omitted if no nodes and `mode == inherit`).
6. `@contracts { ... }` (omitted if no clauses).
7. `@vault { ... }` (omitted if no blobs).
8. `@pulse { ... }` (always emitted).

The SHA-256 seal is computed over `serialize_body(doc).encode("utf-8")`:

```python
digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
prefix = "quipu" if doc.version == "QLOOM/1.0" else "qloom"
knot = f"{prefix}-{digest[:12]}"
```

The seal line is appended after `\n\n`:

```text
=~ knot="qloom-<12hex>" sha256="<64hex>" reconciled=true
```

---

## 5. Progressive Disclosure (`L4 -> L0`)

`project_qloom(doc, target_tier)` transforms an AST onto tier `L0..L4`, records `doc.seal.knot` (or computed knot) in `projected.parent`, and recomputes the `=~` seal:

| Target Tier | `@charter` & `@pulse` | `@lattice` | `@weave` & `@contracts` | `@vault` |
| :--- | :--- | :--- | :--- | :--- |
| **`L4`** | Preserved | Full (all rows, checks, spacers) | Preserved | Preserved |
| **`L3`** | Preserved | Drops `mod=superseded` rows | Preserved | Preserved |
| **`L2`** | Preserved | Drops `superseded` & `T2`/`T3` rows | Preserved | Stripped |
| **`L1`** | Preserved | Drops `superseded` & `T2`/`T3` rows | Stripped | Stripped |
| **`L0`** | Preserved | Stripped | Stripped | Stripped |

When rows are pruned from a `@lattice` relation, optional `ref?` references pointing to dropped IDs are nulled (`_`) and row-count/sum checks on modified relations are cleared so the compacted document remains self-consistent and passes all 10 verification laws. Note that at `L0`/`L1` (when `@weave` is stripped), an unresolved `@pulse.focus` is deferred rather than flagged by `LAW_06_DAG_AND_REFS`.

---

## 6. Static Verification Laws (`LAW_01`..`LAW_10`)

`verify_qloom(doc_or_text, *, enforce_wire_ceiling=True)` checks **8 laws** for `QLOOM/1.0` and **10 laws** for `QLOOM/2.0`:

| Law ID | Scope | Enforced Invariants |
| :--- | :--- | :--- |
| **`LAW_01_KNOT_SEAL`** | `1.0`, `2.0` | `=~` MUST exist, `reconciled` MUST be `true`, and `sha256` + `knot` MUST match `compute_seal(doc)`. |
| **`LAW_02_CONTENT_SAFETY`** | `1.0`, `2.0` | Rejects NUL bytes, Unicode bidirectional control trojans, leaked credentials/private keys (GitHub/AWS/OpenAI tokens, PEM private keys), destructive root-filesystem or block-device wipes, and `subprocess(..., shell=True)` patterns. |
| **`LAW_03_SAFE_ARGV`** | `1.0`, `2.0` | Every `@contracts` clause MUST have non-empty `witness_argv`; `witness_argv[0]` and `rollback_argv[0]` MUST have no whitespace or shell metacharacters `[;\|&$\`><\n\r]`; shell wrapper pairs (`sh -c`, `bash -c`, `cmd /c`, etc.) are rejected (`CWE-78`). |
| **`LAW_04_TAINT_LATTICE`** | `1.0`, `2.0` | `T2`/`T3` entities (`@vault` blobs and `T2`/`T3` `@lattice` rows) MUST NOT be referenced by `@contracts` `requires`, `@pulse.focus`, or `T0`/`T1` `@lattice` rows. |
| **`LAW_05_SPIN_AND_BERNSTEIN`** | `1.0`, `2.0` | Header and node `state` MUST be valid `AgentState` values; `spin=Z` nodes MUST NOT declare `W={...}`; `face=V` nodes MUST NOT declare `W={...}` in `mode=share`; `mode=inherit` forbids any `W={...}`; concurrent `pending`/`active` nodes in `mode=share` MUST satisfy Bernstein disjointness ($W_i \cap W_j = \emptyset$, $R_i \cap W_j = \emptyset$, $W_i \cap R_j = \emptyset$). |
| **`LAW_06_DAG_AND_REFS`** | `1.0`, `2.0` | `@weave` node IDs MUST be unique, dependencies declared, and dependency + `supersedes` graphs acyclic (via Kahn's algorithm); all `->ref` pointers MUST resolve to declared IDs (except deferred `@pulse.focus` at `L0`/`L1` without `@weave`). |
| **`LAW_07_CLARITY_AND_CEILING`** | `1.0`, `2.0` | `@charter.goal`, mandates, and `@pulse.next` MUST pass clarity/conciseness lint (no passive voice, no AI fluff words, sentences `<= 25` words, score `>= 80.0`); canonical wire MUST be `<= 8,000` chars when `enforce_wire_ceiling=True`; `@charter` `budget` locks (`tokens<=`, `chars<=`, `cost_usd<=`, `retries<=`, `tol_pct<=`) MUST hold. |
| **`LAW_08_WIRE_EFFICIENCY`** | `1.0`, `2.0` | Computes compression ratio vs equivalent JSON AST and operational efficiency score. |
| **`LAW_09_RELATION_ARITHMETIC`** | `2.0` | Validates sorted in-bounds `---` spacers and evaluates `^count`, `^sum` (full or `start..end` slice), `^net(credit, debt)`, `^tol(col, pct=P)`, and `^quota(col, pct=P)` with strict `bool != int` enforcement. |
| **`LAW_10_LINEAGE_AND_SAGA_BOUNDS`** | `2.0` | Validates `parent` format (`^[a-z][a-z0-9_]{1,15}-[0-9a-f]{12}$` or `"none"`), safe `tag`/`hub`/`wrap` identifiers (`CWE-20`), `admin=working` row count `< 1,000` (`MAX_WORKING_ROWS`), and `@contracts` `timeout_s` within `1..86,400`. |

---

## 7. Version Compatibility & Security Bounds

### 7.1 `QLOOM/1.0` <-> `QLOOM/2.0` Compatibility

- **`upgrade_qloom_to_v2(doc_or_text, *, admin=None, tag=None, hub=None, recompute_seal=True)`**: Promotes `1.0 -> 2.0`, sets `parent` to the source `quipu-<12hex>` knot, and applies optional governance metadata.
- **`downgrade_qloom_to_v1(doc_or_text, *, recompute_seal=True)`**: Strips `2.0`-only fields (`admin`, `tag`, `hub`, `cost_usd<=`, `retries<=`, `tol_pct<=`, relation `checks` & `spacer_indices`, `face`, `weight`, `timeout_s`, `rollback_argv`, `wrap`), resets genesis `parent` if needed, and emits strictly 8-law compliant `QLOOM/1.0`.
- **`distill_qloom_handoff(doc_or_text, *, tier="L2", doc_id=None)`**: Projects to `tier` and stamps `version="QLOOM/2.0"`, `admin="summary"`, and a fresh `=~` seal.
- **`link_qlooms(packets, *, hub_id="HubA", doc_id="qloom.swarm.hub")`**: Federates mixed `1.0` and `2.0` packets into a sealed `summary` hub manifest with verified `members` relation (`^count` + `^sum(nodes)`).
- **`plan_weave_waves(doc_or_text)`**: Topologically schedules `@weave` nodes into dependency- and Bernstein-safe parallel execution waves.

### 7.2 Security & Resource Limits

| Constant / Guard | Default Limit | Mitigated Risk |
| :--- | :--- | :--- |
| `MAX_QLOOM_BYTES` | `500_000` bytes | `CWE-400` Uncontrolled Resource Consumption |
| `MAX_RELATIONS` | `64` per document | Memory / table fan-out DoS |
| `MAX_ROWS_PER_RELATION` | `5_000` (and `< 1,000` in `admin=working`) | Unbounded working-log growth |
| `MAX_WEAVE_NODES` | `512` per document | Graph/scheduling exhaustion |
| `MAX_HOOK_OUTPUT_CHARS` | `8_000` chars | CLI harness silent output truncation |
| `MAX_ASCII_CHARS` | `8_000` chars | Terminal renderer overflow |
| CLI Path Containment | CWD or `$HOME` | `CWE-22` Path Traversal |
| Safe `argv` Guard | No shell wrapper or metacharacters | `CWE-78` OS Command Injection |

---

## 8. Andean Textile & Loom Heritage Glossary

All wire tokens and Python identifiers in `QLOOM` are concise English. The structural concepts draw on historical Andean *quipu/khipu* accounting and weaving practices:

| Historical Term | Origin | Concise English Explanation | `QLOOM/2.0` Equivalent |
| :--- | :--- | :--- | :--- |
| *quipu / khipu* | Quechua | Knotted-cord Andean device encoding numeric ledgers and archival narratives. | Legacy `quipu-<12hex>` knot seal |
| *waranqa* | Quechua | Decimal unit of 1,000 households bounding active working-tier records before rollup. | `MAX_WORKING_ROWS = 1000` |
| *pachaka* | Quechua | Decimal unit of 100 representing intermediate grouped summary rollups. | `admin=working\|summary` |
| *inokatha* | Aymara | Paired double-entry audit check verifying net balance across credit and obligation cords. | `^net(credit, debt)` |
| *yapa* | Quechua | Small permissible positive allowance distinguishing acceptable drift from a breach. | `^tol(col, pct=N)` / `tol_pct<=` |
| *hanan / hurin* (recto / verso) | Quechua / Epigraphy | Complementary upper/primary vs lower/shadow orientations on a shared frame. | `face=R\|V` (`AttachFace`) |
| *top-cord* | Epigraphy | Upward summary cord aggregating pendant totals and closing the bundle. | `@lattice` checks & `=~` seal |
| *Z / S spin* | Epigraphy | Directional ply twist distinguishing authoritative read-only threads from mutable ones. | `spin=Z` / `spin=S` |
