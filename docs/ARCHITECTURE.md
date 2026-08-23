# CHIMERA — Reasoning & Attack Architecture

> How Chimera observes, reasons, attacks, and remembers.

## 1. System Context

```mermaid
flowchart TB
    subgraph TARGET["Target System (Authorized Scope)"]
        APP[Application Code]
        DB[(Schema / DDL)]
        API[GraphQL / REST Surface]
    end

    subgraph CHIMERA["Chimera Engine"]
        PARSE[Parser Cascade]
        MODEL[System Models]
        CORE[Causal Core]
        ADV[Adversarial Validation]
        EXEC[Swarm Execution Plane]
        MEM[Hybrid Memory Moat]
    end

    APP --> PARSE
    DB --> PARSE
    API --> PARSE
    PARSE --> MODEL --> CORE --> ADV
    ADV -->|experiments| EXEC
    EXEC -->|evidence| ADV
    ADV -->|confirmed patterns| MEM
    MEM -->|decayed retrieval| CORE
```

## 2. The Reasoning Loop

| Phase | Actor | Output |
|---|---|---|
| 1 Observe | parsers | raw AST / DDL / schema artifacts |
| 2 Model | intent & implementation models | typed semantic graphs |
| 3 Hypothesize | causal differential engine | falsifiable claims |
| 4 Interrogate | debunker | counter-hypotheses, attack plans |
| 5 Test | swarm execution plane | controlled experiments |
| 6 Update | epistemic engine | Brier-calibrated confidence |
| 7 Decide | orchestrator | confirm / refute / iterate |
| 8 Remember | hybrid memory | decayed, retrievable patterns |

## 3. Attack Pipeline — Intent vs Implementation

Chimera's offensive power comes from attacking the **delta** between what a
system declares and what it implements.

```mermaid
flowchart TB
    subgraph PARSERS["Parser Cascade"]
        PY["python_parser<br/>full AST traversal"]
        SQ["sql_parser<br/>DDL + FK detection"]
        GQ["graphql_parser<br/>intent contracts"]
        JS["javascript_parser<br/>async-state analysis"]
    end

    subgraph MODELS["System Models"]
        IM["intent_model<br/>declared behavior graph"]
        PM["implementation_model<br/>AST / CFG observations"]
    end

    subgraph CORE["Causal Core"]
        WSA["workflow_state_analyzer<br/>state machine extraction"]
        CDE["causal_differential_engine<br/>intent − implementation"]
        HYP["hypothesis<br/>25-field falsifiable claim"]
    end

    subgraph ADV["Adversarial Validation"]
        DEB["debunker<br/>9+ attack vectors"]
        EPI["epistemic_engine<br/>calibration + Brier score"]
    end

    PARSERS --> MODELS
    MODELS --> CDE
    WSA --> CDE
    CDE --> HYP
    HYP --> DEB
    DEB --> EPI
    EPI -->|refute| HYP
    EPI -->|confirm| MEM[(Hybrid Memory)]
```

### 3.1 Example Contradiction

```
SCHEMA (intent):      type Query { user(id: ID!): User @auth }
RESOLVER (impl):      def resolve_user(...): return db.get(id)   # no check
DIFFERENTIAL:         auth declared ∧ auth absent  ⇒  hypothesis
FALSIFICATION:        swarm replays unauthenticated request ⇒ evidence
```

## 4. Evidence & Chain of Custody

No claim is admissible without provenance.

```mermaid
flowchart LR
    SRC["AST node / HTTP exchange / runtime trace"] --> EV["Evidence"]
    EV --> COC["ChainOfCustody<br/>immutable step ledger"]
    COC --> FP["finalize → SHA-256 fingerprint"]
    FP --> VER{"verify()"}
    VER -->|pass| ADM["admissible finding"]
    VER -->|fail| REJ["rejected artifact"]
```

## 5. Memory Is The Moat

```mermaid
flowchart LR
    subgraph MOAT["Hybrid Epistemic Memory"]
        SM["StructuredMemory<br/>exact KV lookups"]
        SEM["SemanticMemory<br/>ChromaDB embeddings"]
        HYB["HybridEpistemicMemory<br/>sparse fusion + e^-λt decay"]
    end
    EPI["Epistemic Engine"] -->|store| HYB
    HYB --> SEM
    HYB --> SM
    HYB -->|decay-weighted retrieval| EPI
```

Temporal decay `score × e^(−λ·age)` prevents attention drift during long
autonomous operations: stale hypotheses lose influence; fresh, calibrated
evidence dominates.

## 6. File Map

| File | Responsibility |
|---|---|
| `core/orchestrator.py` | 8-phase loop control |
| `core/workflow_state_analyzer.py` | state machine extraction |
| `core/causal_differential_engine.py` | differentials → hypotheses |
| `core/debunker.py` | hostile falsification vectors |
| `core/epistemic_engine.py` | calibration, counter-hypotheses |
| `core/memory.py` | structured + semantic memory |
| `parsers/*` | language cascades |
| `execution/swarm_coordinator.py` | tactical dispatch |
| `plugins/*` | epistemic sensors & exporters |
