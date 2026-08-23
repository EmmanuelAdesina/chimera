# Chimera Assessment — Field Test Report

> **STATUS: RESOLVED (v2.1).** Every defect in this report was fixed in the
> follow-up remediation pass. See **[docs/REMEDIATION.md](docs/REMEDIATION.md)**
> for fix-by-fix mapping and regression tests (`144 passed`). The text below
> is preserved as the historical record of what the field test found.

**Date:** 2026-08-23 · **Commit:** `52fcd4e` · **Tester:** Arena agent, fresh clone, Python 3.11.2

**What was done:** installed and started Chimera, ran its reasoning loop against the shipped
demo target and a purpose-built 11-function order-management service (vulnerable + fully-guarded
variants), exercised the swarm execution plane with an 8-case battery + 32-task concurrency burst,
and traced three suspected root causes down to exact lines.

---

## Verdict in one line

Chimera v2.0 is a **well-architected hypothesis generator wired to a working concurrent tool
executor — but the loop is open**: experiments are planned and never run, guard detection is
structurally blind to the most common idioms (so guarded and unguarded code produce identical
findings), and the calibration math guarantees nothing is ever "confirmed" without dynamic
evidence that the system never collects.

---

## What genuinely works ✅

| Area | Evidence |
|---|---|
| **Graceful degradation** | Runs with zero third-party deps; chromadb/playwright/aiohttp all fail cleanly (fallback stores, clear errors). The orchestrator survived every error we threw at it. |
| **Swarm concurrency** | 32 × 0.5s terminal tasks completed in **0.66s wall** (serial ≈ 16s). Real asyncio fan-out with priority queue + semaphore. |
| **Terminal policy (shallow)** | Executable allowlist blocked `nmap`; cwd boundary blocked `/tmp` and `../../` escapes; unknown capability → clean SKIPPED. |
| **Evidence discipline** | Every terminal execution returns structured `Evidence` with SHA-256 chain-of-custody hash. The currency exists — where execution happens. |
| **GraphQL causal parser (standalone)** | Correctly flagged `@auth`-declared field whose resolver has no check, at 0.85 confidence, with real Evidence. |
| **Debunker heuristics (as ideas)** | The 9 vectors are genuinely good epistemics: falsifier requirements, counter-example search, "confidence must be proportional to evidence" (scope_creep). |
| **Intent extraction** | Docstring/name/decorator intent mining found all 10 declared business rules in my target (admin-only, owner-only, staff-only). |

## What's broken ❌

### 1. The shipped demo target cannot be parsed (fixed)
`tests/targets/vuln_app.py` has a UTF-8 BOM; `_parse_file` opened with `encoding="utf-8"` →
`SyntaxError: U+FEFF` → **0 files parsed, 0 hypotheses** on the project's own flagship demo.
**Fix applied:** `utf-8-sig` (one line, `orchestrator.py:229`).

### 2. The test suite is red and stale
- 3 of 6 test files fail at **collection** (import `CausalEngine`, `ParserLayer`, `EpistemicMonitor`, `ChimeraMemory` — none exist).
- `test_end_to_end.py` calls `orch.run(...)` — no such method; the API is `analyze()`.
- `test_python_parser.py` asserts `PythonParser().name` — attribute doesn't exist.
- Only `test_import.py` passes. The README badge "integration tests 9/9 passing" does not describe this tree.

### 3. There is no entrypoint
`python -m chimera analyze` (Makefile, README) fails — `chimera/__main__.py` doesn't exist. The only
way to run an analysis is to write your own driver around `ChimeraOrchestrator`.

### 4. Guard detection is structurally blind → identical findings on safe vs vulnerable code
**The headline finding.** A fully-guarded implementation of the same service produced **exactly
the same 10 differentials / 10 hypotheses** as the vulnerable one. Two root causes, both verified:

- **Ownership:** the Python parser faithfully extracts `ORDERS[order_id]['owner'] != current_user['id']`
  into `properties["comparisons"]` and even tags the function `ownership_check` — but
  `_check_ownership_via_graph()` reads `properties["body_nodes"]`, which the parser **never
  populates**. Property-name mismatch; the extracted guard is thrown away.
  **Fix applied (3 lines, `implementation_model.py`):** also read `comparisons` + honor the
  `ownership_check` tag. Result: safe target 10 → 8 hypotheses (both ownership FPs gone, incl. the
  control function); vulnerable target still flags the genuinely-missing ownership check.
- **Auth:** `_AUTH_CHECK_PATTERNS["attribute_checks"]` (containing `is_admin`, `is_staff`, …) is
  **defined once and never referenced** — dead vocabulary. Detection only sees decorator edges and
  calls to authy-*named* functions, so `if not current_user.get("is_admin"): raise PermissionError`
  is invisible. This accounts for the 8 remaining FPs on the guarded target. (Same blindness in
  `graphql_parser.py`: it flagged a resolver that checks `is_admin` because the term list there
  lacks `admin`.)

Until #4 is fixed, the "Debunker kills 90% of false positives" doctrine is unfalsifiable in the
other direction: it killed **0 of 10** hypotheses, including 2 obvious FPs.

### 5. The loop is open — experiments are never executed
`_phase_experimentation` calls `planner.prioritize()` and… increments a counter. No swarm dispatch,
no HTTP request, nothing. The plans themselves contain synthesized URLs like `/4492016a-5e4`
(hypothesis-id fragments, not real routes). The swarm plane (`swarm_bootstrap` et al.) and the
reasoning loop share no code path. Consequences:

- Static analysis attaches **0 evidence** to every hypothesis (all 10 had `supporting_evidence: []`).
- The epistemic engine makes confidence proportional to evidence → everything calibrates to **~0.15**.
- Reporting threshold is **0.6** → **0 confirmed, always**. On a target with 8 real, planted,
  trivially-visible authorization flaws, the final report is empty.

The "closed-loop causal reasoning engine" is currently a static docstring-intent differ that
generates plausible claims and then mathematically suppresses all of them.

### 6. Reachability gaps in the advertised "parser cascade"
The orchestrator only discovers `.py` and `.sql`. The **GraphQL and JS async parsers are dead code
from the main loop's perspective** — and they're the better parsers. The workflow-bypass /
race-condition classes the README leads with are unreachable through `analyze()`.

### 7. Sandbox is cosmetic against the "python" agent it allows
`python -c "open('/tmp/pwned.txt','w')…"` executed happily through the allowlisted `python`
executable (verified: file created outside the workspace). The docs do say "run in a container,"
but the default policy grants full code execution while appearing conservative.

### 8. Small sharp edges
- `dispatch_swarm` returns results in **completion order** — `results[i] ≠ tasks[i]`, silently. My
  first battery printed case 1's result against case 6's error until I remapped by `task_id`.
- Caido failure path leaks an unclosed `aiohttp.ClientSession` (asyncio warning on exit).
- Debunker `recommendation="kill"` (score < 0.3, survived_all=True) leaves the hypothesis
  `UNDER_REVIEW` instead of recording it debunked — recommendation/status inconsistency.
- `pyproject.toml` declares pydantic, networkx, pyyaml, openai, anthropic, rank-bm25 — **none are
  imported anywhere**. Install surface is fictional.
- `IntentModel` misreads state guards as auth: refund's docstring "must be APPROVED and not already
  refunded" → "contains 'must be', suggesting auth intent".
- `create_order` flagged IDOR for "resource ID parameter without ownership check" — create-style
  functions legitimately have no ownership check (FP class of its own).

---

## Scorecard

| Claim (README) | Reality |
|---|---|
| "Closed-loop" reasoning | 🔴 Loop never closes; experiments planned, never executed |
| "Falsifies assumptions" | 🟡 Generates falsifiable claims, then suppresses all of them (0 confirmations) |
| "Debunker kills 90% FPs" | 🔴 Killed 0/10, incl. 2 clear FPs (fixed case: 2/2 ownership FPs now die earlier, at observation stage) |
| "Swarm execution plane" | 🟢 Genuinely concurrent, policy-checked, evidence-bearing — as a standalone library |
| "Evidence is the currency" | 🟡 Real chain-of-custody in the execution plane; zero evidence in the reasoning plane |
| "9/9 integration tests passing" | 🔴 1/6 files pass; 3 don't even collect |
| Parser cascade (PY·SQL·GraphQL·JS) | 🟡 PY/SQL wired (with the BOM bug); GraphQL/JS work standalone but unreachable |

## Highest-leverage next steps (in order)

1. **Wire the swarm into `_phase_experimentation`** — plans → `SwarmTask`s → evidence → hypothesis.
   This single change makes confirmation reachable and the loop actually closed.
2. **Fix guard detection** (partially done here): consume `comparisons` + `ownership_check` tag
   (shipped in this assessment); revive the dead `attribute_checks` vocabulary by having the parser
   emit inline attribute checks; add `admin`/`role`/`PermissionError`/`AuthError` to the GraphQL
   resolver's term list.
3. **Add `chimera/__main__.py`** with `analyze <path>` + flags; make `make run` real.
4. **Regenerate the test suite** against the v2 API (`analyze()`, `CausalDifferentialEngine`, …)
   and add the safe-vs-vulnerable differential test from this report — it catches bug #4 in one run.
5. Stop declaring unused dependencies; pin the real ones (stdlib + lazy extras).

---

*Artifacts: `scripts/run_analysis.py` (driver), `scripts/swarm_battery.py` (execution battery),
probe targets in `/home/user/task_target/` (vulnerable + guarded). Two small fixes were applied
during testing and are in the working tree: BOM-safe file read (`orchestrator.py`), ownership-guard
detection via parser-emitted comparisons (`implementation_model.py`).*
