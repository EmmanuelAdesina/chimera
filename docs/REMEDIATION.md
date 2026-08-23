# Chimera Remediation Report — v2.1

**Date:** 2026-08-23 · **Branch:** `arena/01a02e67-chimera` · **Baseline:** field-test
assessments (`CHIMERA_ASSESSMENT.md` + independent critical evaluation, 3/10 → **all 10 fixed**)

This document maps every reported defect to its fix and its regression test.
Verification evidence is reproducible with:

```bash
python -m pip install -e . && python -m pytest tests/ -q      # 144 passed
python -m chimera analyze tests/targets/vuln_orders_app.py    # 9 confirmed
python -m chimera analyze tests/targets/safe_orders_app.py    # 0 confirmed
```

---

## A. Critical bugs (all fixed)

### A1. Test-code complete desynchronization → suite rebuilt
**Was:** 3/6 test files failed at *collection* (`CausalEngine`, `ParserLayer`,
`EpistemicMonitor`, `ChimeraMemory`, `GrammarModel` — none existed); 2 more
failed at runtime (`orch.run()`, `PythonParser().name`). Only `test_import.py` passed.
**Now:** the suite was regenerated against the real v2 API — 144 tests across
9 files: orchestrator, causal engine, epistemic engine, memory, debunker,
static verifier, python/sql parsers, swarm coordinator, terminal layer, and
integration (end-to-end + parser cascade). Stale v1 tests were deleted.
**Regression:** `python -m pytest tests/` → `144 passed`.

### A2. Orchestrator result structure mismatch
**Was:** `errors` was an int count, no `hypotheses` key, `completed_at` never set.
**Now:** `WorldState.summary()` returns counts under explicit keys
(`error_count`, `warning_count`, `parse_errors`) **and** detail lists
(`errors`, `warnings`, `parse_error_details`, `hypotheses`,
`confirmed_vulnerabilities`, plus a new `flagged_findings` tier for
below-threshold survivors). `completed_at` is stamped on COMPLETE.
**Regression:** `tests/unit/core/test_orchestrator.py::TestSummaryContract`.

### A3. SemanticGraph type confusion
**Was:** parsers crashed with naked `AttributeError` when handed a dict or
NetworkX graph.
**Now:** both parsers raise a clear `TypeError` ("graph must be a SemanticGraph
instance (or None)... a plain dict or networkx.Graph is not compatible"),
accept `graph=None` (parser populates `self.graph`), and document the contract.
The graph class itself is Chimera's own — it never required NetworkX (a
fictional dependency that has been removed from `pyproject.toml`).

### A4. SQL parser crashes on None graph / bad input
**Was:** `graph: SemanticGraph` was mandatory; `parse(..., None)` crashed.
**Now:** `graph` is optional (own graph exposed as `parser.graph`); `None`/blank/
garbage/partial DDL input never raises — malformed statements are skipped and
logged; FK edge failures degrade gracefully.
**Regression:** `tests/unit/parsers/test_sql_parser.py::TestRobustness`.

### A5. Memory system API mismatch
**Was:** documented methods missing; `StructuredMemory` used `os.makedirs`
**without importing `os`** (guaranteed `NameError` on first persist); the
orchestrator passed *itself* as `memory=self` to the causal engine, so the
novelty check (`hasattr(memory, 'semantic')`) silently never ran.
**Now:** `import os` fixed; `store_hypothesis`/`get_hypothesis`/
`list_hypotheses` added; new **`ChimeraMemory`** facade unifies the
structured+semantic planes (`recall_similar`, `record_result`, `stats`),
in-memory by default, persistence opt-in. The orchestrator builds a real
`ChimeraMemory` and passes it through — novelty checks execute for real.
**Regression:** `tests/unit/core/test_memory.py` (14 tests).

---

## B. The reasoning fixes ("critical reasoning" — the headliners)

### B1. Zero hypotheses on vulnerable targets (root: weak intent inference)
**Was:** `delete_order(order_id, current_user)` produced **no** intent
expectation: (a) auth expectations required a *scope word* (`admin|staff|...`)
in the name — plain sensitive actions like `delete`/`transfer` got nothing;
(b) ownership expectations required dual owner+requestor params, which real
handlers rarely have; (c) docstring "must be APPROVED" was misread as *auth*
intent ("contains 'must be'...").
**Now — IntentModel:**
- any sensitive action (38 verbs, incl. `refund`, `escalate`, `withdraw`…)
  without a scope hint still yields a baseline *authenticated* expectation;
- resource-identifier parameters (`order_id`, `pk`, `slug`, routes with
  `<int:order_id>`…) yield an *ownership* expectation — with caller-identity
  params excluded properly, so `current_user` is never the "resource" and a
  bare `user_id` **becomes** a resource when a strong identity param coexists
  (`list_user_orders(user_id, current_user)` IDOR is now caught);
- create-style actions (`create`, `register`, …) are excluded from ownership
  expectations (kills the create-FP class);
- docstring vocabulary was split: state-precondition phrases (`must be`,
  `already`, …) → **state_guard** intent; identity/role words → **auth** intent.

### B2. Guard detection was structurally blind (safe ≡ vulnerable)
**Was:** `if order["owner"] != current_user["id"]: raise PermissionError`
produced the **same 10 findings** as no guard at all: the parser stored
comparisons under `comparisons` while the model read `body_nodes` (never
populated); `_looks_like_ownership_check` required the literal token `request`
(`current_user` failed) and `==` (guard-by-exception `!=` failed); the
`attribute_checks` vocabulary was defined and *never referenced*;
`@login_required` AUTHORIZES-edges didn't match any name pattern.
**Now:**
- parser emits `auth_checks` (attribute gates `.is_admin`/`.get("role")`,
  `raise PermissionError`/`abort(403)`/return-403, auth predicate calls) and
  normalized `body_nodes` structural records — both consumed by the
  ImplementationModel (dead vocabulary revived);
- ownership comparison detection is token-based (attribute/subscript
  boundaries — `username` no longer reads as `user`) and accepts both `==`
  and `!=` styles;
- any AUTHORIZES/GUARDS edge is conclusive; bare route decorators
  (`@app.route`) are explicitly **not** guards in the state machine analyzer.
**Regression:** `tests/integration/test_end_to_end.py::
test_vulnerable_vs_guarded_differential` (safe twin must score 0 confirmed).

### B3. The loop was open — experiments planned, never executed
**Was:** `_phase_experimentation` counted plans; nothing ran; hypotheses had
`evidence: []`; epistemic weights summed to 0.80 with a zero evidence signal →
everything calibrated to ~0.15 < 0.6 threshold → **0 confirmed, always**.
**Now — the loop closes *statically*:**
1. **Evidence discipline**: the CausalDifferentialEngine attaches static
   evidence to every hypothesis at birth (DIFFERENTIAL_RESULT + graph-entity
   nodes, chain-of-custody sealed) and **seeds falsifiers** (an unfalsifiable
   claim is scientifically empty).
2. **Counter-hypotheses are born with the hypothesis** (phase 5), so the
   Debunker's confirmation-bias vector sees them.
3. **New `StaticVerifier`** executes falsification probes in the
   experimentation phase: inter-procedural caller-guard sweeps ("every caller
   guards first" ⇒ weaken), container-level protection, data-sink
   reachability, exposure analysis — each verdict emits EXPERIMENT_RESULT
   evidence. Genuinely disprovable claims (missing graph entity, fully
   guarded callers) get **rejected**.
4. **Post-experiment recalibration** (new phase 9) — belief updates with the
   fresh evidence.
5. **Epistemic engine rebalanced**: weights renormalize over active signal
   families, and a 4th signal — *adversarial survival* (the Debunker score) —
   counts as Bayesian evidence. Strong static findings can now cross 0.6;
   weak ones can't (weak-fixture test stays below threshold by design).
6. Planner URLs come from real route metadata; undispatchable plans are
   flagged (`static-analysis-only`), never synthesized garbage like `/4492016a`.

### B4. Parser cascade reachability
**Was:** only `.py`/`.sql` discovered; GraphQL/JS parsers dead code.
**Now:** discovery covers `.py/.pyi/.sql/.graphql/.gql/.js/.ts/...`; GraphQL
contradictions (`@auth` declared, resolver silent) become hypotheses through
`analyze()`; JS async-state findings become race-condition hypotheses. The
GraphQL resolver check no longer matches auth terms inside *docstrings*
(structural check now), and `admin`/`role`/`PermissionError` are in vocabulary.
**Regression:** `tests/integration/test_parser_cascade.py`.

### B5. State machines were never extracted (workflow bypass unreachable)
**Was:** analyzer read `op["value"]`; the parser emitted `op["new_value"]` —
every modifier had an empty state; plus `refund["status"] = "X"` (subscript)
was invisible; single-state machines aborted.
**Now:** key mismatch fixed (both keys, quote-normalized), subscript state
assignments captured, verb→state mapping (`approve_order` ⇒ `approved`),
modifiers/transitions/differentials deduped, unknown preconditions collapse to
one wildcard transition (no N× noise), model classes harvest `fields`
(incl. `choices=[...]`) for state extraction.

### B6. Debunker inconsistencies
**Was:** `recommendation="kill"` with `survived_all=True` left the hypothesis
UNDER_REVIEW; single-evidence overconfidence unchecked; the internal-function
discount hit plain handlers; "logical leap" detection fired on stopwords
("in", "on"). Killed 0/10 including obvious FPs.
**Now:** kill ⇒ `survived_all=False` + status DEBUNKED (recorded via a
transition-safe path); overall score recorded to `metadata` for epistemic
calibration; `DebunkResult/DebunkReport.to_dict()` added; internal-only
discount applies only to genuinely private helpers; leap detection uses
content-word sets. (Guard-kind mismatch: a role-gated handler missing
*ownership* lands below the confirmation threshold instead of disappearing —
visible in `flagged_findings`.)

### B7. Legacy flagship target produced 0 findings
**Was:** `tests/targets/vuln_app.py` (JSON→Python→SQL grammar differential)
yielded nothing — a bad look for the demo.
**Now:** new **injection** vulnerability class end-to-end: parser extracts
SQL string-construction taint (f-string/concat/`%`/`.format`) and
parameterization sanitizers (`execute(sql, (params,))`); `unsafe_sink`
differentials flow through severity/prereqs/falsifiers/counter-hypotheses/
debunker target set/experiment plans. Result: `get_user_unsafe` **CONFIRMED
injection @0.76**, `get_user_safe` untouched.
**Regression:** `tests/integration/test_parser_cascade.py::TestInjectionCascade`.

---

## C. Execution plane fixes

- **`dispatch_swarm` result order**: now returns results in **submission
  order** (`results[i] ↔ tasks[i]`); misattribution-by-completion-order
  eliminated. Regression test dispatches adversarially-ordered sleeps.
- **Terminal sandbox**: default policy now blocks inline-code flags
  (`-c/-e/-m/--eval`…) for allowlisted interpreters — the
  `python -c "open('/tmp/pwned.txt',...)"` escape from the assessment is
  blocked (opt-in via `allow_interpreter_code=True` for hardened sandboxes).
- **Caido bridge lifecycle** (follow-up pass): the bridge had defects far
  worse than the reported session leak, and all are now fixed in
  `chimera/plugins/caido_bridge.py` with 17 hermetic regression tests
  (aiohttp is an optional extra, so tests inject a fake module):
  1. **Infinite mutual recursion**: the old `initialize()` health-check called
     `graphql()`, and `graphql()` always called `initialize()` first. The
     first real call recursed until `RecursionError` (silently swallowed by
     `except Exception: pass`), then every unwinding frame fired its own
     health-check POST. **Measured: 495 HTTP POSTs for one user call** (494
     spurious) → now exactly 2 (1 health-check + 1 real query). The
     health-check now runs through a recursion-free `_post_json` transport
     guarded by an `_initialized` flag.
  2. **Stale-session bricking**: a closed `aiohttp.ClientSession` was never
     recreated (`session.closed` was never inspected), permanently breaking
     the bridge. Now `_ensure_session()` recreates absent-or-closed sessions.
  3. **Unattended session leak**: no deterministic cleanup path existed.
     `CaidoBridge` is now an async context manager
     (`async with CaidoBridge(cfg) as bridge: ...`) guaranteeing
     `cleanup()`/session close; `cleanup()` also resets initialization state
     so the bridge is reusable afterwards.
  - Registration contract unchanged (`initialize/execute/cleanup`, config
    dict constructor) so `swarm_bootstrap.py`'s `caido.execute` capability is
    unaffected.

## D. Packaging & honesty

- `pyproject.toml`: **zero hard dependencies** (they were all fictional —
  pydantic/networkx/openai/anthropic/requests/rank-bm25 are not imported
  anywhere); optional planes moved to extras (`vector`, `http`, `browser`,
  `dev`); pytest + pytest-asyncio configured (`asyncio_mode=auto`).
- **`python -m chimera analyze <path>` exists now** — the entrypoint the
  Makefile, README and `project.scripts` all promised (human report +
  `--json` + `--quiet` + `--dynamic` flags; exit 0 on successful analysis, 2 on
  usage/IO errors, and optional `--fail-on-findings` → exit 1 when confirmed
  vulnerabilities exist (CI gating, defaults unchanged).
- README badges/claims updated to the true state (144 tests, zero core deps,
  v2.1, injection class, quickstart actually works).
- State counters are idempotent (`record_debunked/confirmed/rejected` can't
  double-count on re-entry).

---

## E. Before / after evidence

| Scenario | Before | After |
|---|---|---|
| Demo target `vuln_app.py` | **0 hypotheses** | 1 confirmed (injection @0.76), safe function clean |
| Vulnerable order service | 0 hypotheses | **9/9 confirmed** (IDOR ×4, priv-esc ×4, both classes on destructive handlers) |
| Guarded twin service | same 10 findings as vulnerable | **0 confirmed** (1 flagged, guard-kind mismatch, below threshold) |
| Mixed dir (py+graphql+cascade) | 2 file types reachable | py+sql+graphql+js; GraphQL `@auth` contradiction flagged & confirmed |
| Malformed Python / SQL / None-graph | crashes | structured `ParseError` (file:line+snippet) or graceful skip |
| Static hypotheses' evidence | `[]` (0 pieces) | ≥1 static + verifier experiment evidence, chain-of-custody valid |
| Calibration ceiling | ~0.15 → nothing confirmable | honest findings reach 0.6–0.76; weak ones stay below |
| Loop closure | plans counted, never run | static falsification probes execute; verdicts attached; weak claims rejected |
| `python -m chimera analyze` | `__main__.py` missing | works; human + JSON reports |
| Test suite | 1/6 files passing (collection errors) | **144/144 passing** |
| Sandbox `python -c` escape | executed | blocked by default policy |
| Swarm result ordering | completion order (silent misattribution) | submission order, regression-tested |
| Hard dependencies | 7 fictional | 0 (stdlib core; extras are real) |

## F. What is deliberately NOT claimed

- **Dynamic confirmation**: orchestrator-run targets close the loop with
  *static* verification. Live HTTP falsification against `base_url` still
  requires running the swarm plane yourself (`swarm_bootstrap`), at which
  point plans carry real routes, expected/falsifying outcomes, and
  chain-of-custody evidence. This is honest: static certainty has a ceiling.
  The ceiling is now *visible*: `analyze()` summaries expose
  `pending_dynamic_confirmation` / `pending_dynamic_confirmation_count` —
  dispatchable, live-target plans the orchestrator deliberately did not fire
  (real route URLs joined to `base_url` when decorators exist; decorator-less
  service code honestly yields the non-dispatchable static marker rather
  than fabricated URLs).
- The Debunker targets a high FP kill rate on *generated* hypotheses; with
  guard detection fixed, most FPs die earlier (at observation time), which is
  the correct outcome — the kill-rate metric alone no longer tells the story.
