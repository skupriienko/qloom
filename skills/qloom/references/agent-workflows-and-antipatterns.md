# QLOOM Agent Workflows & Anti-Patterns

All valid `.qloom` examples below use real verified SHA-256 knots checked by `tests/test_agent_skill.py`.

---

## Pattern 1 — Happy Path: Single-Agent Execution & Verification Handoff (`QLOOM/2.0`)

Use when checkpointing an active refactoring step cleanly with concise constraints and direct `argv` verification:

```qloom
~= QLOOM/2.0 id="auth.hmac.step" tier=L4 state=MUTATION_PREPARE parent="qloom-000000000000" epoch=2 admin=working tag="auth_refactor"

@charter {
  goal: "Migrate token verification to standard library HMAC."
  lock NO_SHELL: forbid "shell_interpolation"
  lock SPEND_CAP: budget tokens<=2000 chars<=8000 cost_usd<=2.5 retries<=3
  mandate KEEP_CONCISE: must "Verify every code change with pytest before finishing."
}

@lattice {
  relation sources(id:id, tier:tier, path:str) {
    src_auth | T0 | "src/auth.py"
  }
  relation claims(id:id, mod:mod, tier:tier, claim:str, source:ref, supersedes:ref?) {
    c1 | verified | T0 | "Validator requires SHA-256 HMAC digests." | ->src_auth | _
  }
}

@weave mode=inherit {
  node n_audit spin=Z face=R weight=fine state=SANDBOX_COMPUTE deps=[] R={"src/auth.py"} W={} -> done
  node n_patch spin=Z face=R weight=thick state=MUTATION_PREPARE deps=[n_audit] R={"src/auth.py"} W={} -> active
}

@contracts {
  clause C_UNIT {
    requires: [->c1, ->n_patch]
    ensures: "Verify auth unit tests pass with zero failures."
    witness_argv: ["pytest", "tests/test_auth.py", "-q"]
    timeout_s: 120
    rollback_argv: ["git", "checkout", "--", "src/auth.py"]
  }
}

@vault {
}

@pulse {
  focus: ->n_patch
  filament: "[STEP] n_audit(done) -> n_patch(active)"
  signals: ["lint=clean"]
  next: ["Apply HMAC patch.", "Run pytest witness command."]
  blockers: []
}

=~ knot="qloom-46252c54785f" sha256="46252c54785f466868bbb739fb860f95e732db40019e9ebed6e702dfd0fc1ea9" reconciled=true
```

Inspect, verify, and compact down to `L0`:

```bash
qloom verify --file auth_step.qloom --json
qloom draw --file auth_step.qloom
qloom project --file auth_step.qloom --tier L0
```

---

## Pattern 2 — Secure Multi-Agent Variant: Disjoint Parallel Swarm, `@vault` Quarantine & Arithmetic Checks

Coordinate parallel workers in `mode=share`, isolate untrusted external inputs in `@vault` (`T3`), enforce `@lattice` double-entry/tolerance bounds, and compute wave schedules before dispatching subagents:

```qloom
~= QLOOM/2.0 id="swarm.release.handoff" tier=L4 state=MUTATION_PREPARE parent="qloom-000000000000" epoch=3 admin=working tag="parallel_swarm" hub="SwarmHub"

@charter {
  goal: "Execute disjoint module updates with quarantined web input."
  lock NO_SHELL: forbid "shell_interpolation"
  lock BUDGET_GUARD: budget tokens<=3500 chars<=8000 cost_usd<=5.0 tol_pct<=10.0
  mandate VERIFY_GATES: must "Partition worker write paths to avoid file conflicts."
}

@lattice {
  relation sources(id:id, tier:tier, path:str) {
    spec_doc | T0 | "docs/SPEC.md"
  }
  relation ledger(id:id, mod:mod, tier:tier, credit:int, debt:int, guard:int) ^count=4 ^sum(credit, 0..1)=600 ^net(credit, debt)=0 ^tol(credit, pct=5.0)=980 ^quota(guard, pct=22.5)=4000 {
    w_api | verified | T0 | 300 | 250 | 200
    w_ui | verified | T0 | 300 | 250 | 200
    ---
    w_docs | inferred | T1 | 200 | 250 | 250
    w_qa | verified | T0 | 200 | 250 | 250
  }
}

@weave mode=share {
  node n_plan spin=Z face=R weight=thick state=SANDBOX_COMPUTE deps=[] R={"docs/SPEC.md"} W={} -> done
  node n_api spin=S face=R weight=medium state=MUTATION_PREPARE deps=[n_plan] R={"src/api.py"} W={"src/api.py"} -> active
  node n_ui spin=S face=R weight=fine state=MUTATION_PREPARE deps=[n_plan] R={"src/ui.py"} W={"src/ui.py"} -> active
  node n_qa spin=S face=R weight=medium state=CRITIQUE_GATE deps=[n_api, n_ui] R={"src/api.py", "src/ui.py"} W={"tests/test_app.py"} -> pending
}

@contracts {
  clause C_SWARM {
    requires: [->w_api, ->n_qa]
    ensures: "Run full API and UI suite after parallel workers finish."
    witness_argv: ["pytest", "tests/test_app.py", "-q"]
    timeout_s: 300
  }
}

@vault {
  blob v_web_issue tier=T3 sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" bytes=512 origin="external_issue" uri="https://example.org/issue/1" wrap="html_stripped"
}

@pulse {
  focus: ->n_api
  filament: "[WAVE 1] n_api + n_ui active; n_qa pending"
  signals: ["waves=ok"]
  next: ["Complete n_api and n_ui edits.", "Run C_SWARM pytest witness."]
  blockers: []
}

=~ knot="qloom-2a7caa3f998d" sha256="2a7caa3f998dbbac63f536f70f68bcc908c53d535a4a2070fad2224c4149071a" reconciled=true
```

Schedule safe parallel waves and compact a clean `L2` worker packet (which automatically drops `@vault` `T3` blobs):

```python
import qloom

doc = qloom.parse_qloom(swarm_wire)
waves = qloom.plan_weave_waves(doc)
assert waves == [["n_plan"], ["n_api", "n_ui"], ["n_qa"]]

worker_doc = qloom.project_qloom(doc, "L2")
assert not worker_doc.vault.blobs
assert worker_doc.parent == doc.seal.knot
```

---

## Anti-Patterns & Corrected Fixes

### Anti-Pattern 1 — Shell Wrapper in `witness_argv` (`LAW_03_SAFE_ARGV`)

```qloom
# ANTI-PATTERN: triggers LAW_02_CONTENT_SAFETY / LAW_03_SAFE_ARGV
~= QLOOM/2.0 id="bad.argv" tier=L4 state=CRITIQUE_GATE parent="qloom-000000000000" epoch=1

@charter {
  goal: "Test package cleanly."
  mandate RUN_TESTS: must "Execute unit test suite."
}

@lattice {
}

@weave mode=inherit {
  node n_run spin=Z state=CRITIQUE_GATE deps=[] R={"src/app.py"} W={} -> active
}

@contracts {
  clause C_BAD {
    requires: [->n_run]
    ensures: "Run suite."
    witness_argv: ["bash", "-c", "pytest && echo done"]
  }
}

@vault {
}

@pulse {
  focus: ->n_run
  filament: "run"
  next: ["Run tests."]
  blockers: []
}
```

**Fix**: Replace `["bash", "-c", "..."]` with a direct executable vector: `witness_argv: ["pytest", "-q"]`.

### Anti-Pattern 2 — Parallel Write-Write Race in `mode=share` (`LAW_05_SPIN_AND_BERNSTEIN`)

```qloom
# ANTI-PATTERN: triggers LAW_05_SPIN_AND_BERNSTEIN (un-ordered W overlap on src/api.py)
~= QLOOM/2.0 id="bad.race" tier=L4 state=MUTATION_PREPARE parent="qloom-000000000000" epoch=1

@charter {
  goal: "Update API endpoints."
  mandate AVOID_RACES: must "Keep worker write sets disjoint."
}

@lattice {
}

@weave mode=share {
  node w1 spin=S state=MUTATION_PREPARE deps=[] R={"src/api.py"} W={"src/api.py"} -> active
  node w2 spin=S state=MUTATION_PREPARE deps=[] R={"src/api.py"} W={"src/api.py"} -> active
}

@contracts {
  clause C_OK {
    requires: [->w1]
    ensures: "Verify API tests pass."
    witness_argv: ["pytest", "tests/test_api.py"]
  }
}

@vault {
}

@pulse {
  focus: ->w1
  filament: "parallel"
  next: ["Merge changes."]
  blockers: []
}
```

**Fix**: Assign disjoint write files (`W={"src/api_v1.py"}` vs `W={"src/api_v2.py"}`) OR serialize via `deps=[w1]`.

### Anti-Pattern 3 — Taint Escalation (`LAW_04_TAINT_LATTICE`)

```qloom
# ANTI-PATTERN: triggers LAW_04_TAINT_LATTICE (@contracts.requires points to @vault T3 blob)
~= QLOOM/2.0 id="bad.taint" tier=L4 state=SANDBOX_COMPUTE parent="qloom-000000000000" epoch=1

@charter {
  goal: "Summarize external bug report."
  mandate ISOLATE_TAINT: must "Isolate external inputs inside vault."
}

@lattice {
}

@weave mode=inherit {
  node n_check spin=Z state=SANDBOX_COMPUTE deps=[] R={} W={} -> active
}

@contracts {
  clause C_TAINTED {
    requires: [->v_untrusted]
    ensures: "Process bug report."
    witness_argv: ["pytest", "-q"]
  }
}

@vault {
  blob v_untrusted tier=T3 sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" bytes=64 origin="web" uri="https://example.org"
}

@pulse {
  focus: ->n_check
  filament: "check"
  next: ["Inspect report."]
  blockers: []
}
```

**Fix**: Never place `->v_untrusted` in `@contracts.requires` or `@pulse.focus`; reference only `T0`/`T1` `@lattice` rows or `@weave` nodes.
