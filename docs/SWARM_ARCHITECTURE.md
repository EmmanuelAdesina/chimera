# CHIMERA — Autonomous Swarm Architecture

> Strategic reasoning stays in the v2 orchestrator.
> Tactical execution is fanned out to a bounded, scoped swarm.

## 1. Plane Separation

```mermaid
flowchart TB
    subgraph STRATEGIC["Strategic Plane (Reasoning)"]
        ORCH["orchestrator.py<br/>8-phase loop"]
        PLAN["execution_planner.py<br/>class-specific planners"]
    end

    subgraph TACTICAL["Tactical Plane (Execution)"]
        COORD["SwarmCoordinator<br/>priority queue · semaphore backpressure"]
        REG["Capability Registry"]
        WORK["Worker Pool<br/>bounded concurrency"]
    end

    subgraph SENSORS["Layers & Plugins"]
        TERM["TerminalLayer<br/>allowlisted · sandboxed · timeouted"]
        BROW["BrowserLayer<br/>scoped headless observation"]
        CAID["CaidoBridge<br/>persistent GraphQL sensor"]
        SARIF["SARIFExporter"]
    end

    ORCH --> PLAN --> COORD --> REG --> WORK
    WORK --> TERM
    WORK --> BROW
    WORK --> CAID
    WORK --> NORM["Evidence normalization<br/>chain of custody"]
    NORM --> MEM["HybridEpistemicMemory"]
    MEM --> ORCH
    NORM --> SARIF
```

## 2. Operation Lifecycle

```mermaid
sequenceDiagram
    participant ORCH as Orchestrator
    participant CDE as Causal Engine
    participant DEB as Debunker
    participant SW as SwarmCoordinator
    participant EX as Layers / Plugins
    participant MEM as Hybrid Memory

    ORCH->>CDE: models from parser cascade
    CDE-->>ORCH: differentials → hypotheses
    ORCH->>DEB: interrogate hypotheses
    DEB->>SW: falsification experiments
    SW->>EX: bounded, scope-checked fan-out
    EX-->>SW: raw results
    SW-->>DEB: normalized Evidence
    DEB-->>ORCH: calibrated confidence updates
    ORCH->>MEM: remember confirmed patterns
    MEM-->>ORCH: decay-weighted retrieval
```

## 3. Coordinator Internals

- **SwarmTask** — capability name + payload + explicit authorization scope.
- **Priority queue** — strategic planner biases critical falsifications first.
- **Semaphore backpressure** — concurrency bounded; queue overflow rejected, never silent.
- **Capability registry** — sync or async callables; outputs normalized to `Evidence`.
- **SwarmResult** — status, error, timing, evidence list per task.

## 4. Safety Envelope

| Control | Layer |
|---|---|
| Executable allowlist, no `shell=True` | TerminalLayer |
| Workspace-root confinement | TerminalLayer |
| Hard timeouts + output caps | TerminalLayer |
| Host allowlist scoping | BrowserLayer / CaidoBridge |
| Active-scan opt-in flag | CaidoBridge |
| Chain-of-custody fingerprinting | Evidence model |

## 5. Scaling Ladder

```mermaid
flowchart LR
    S1["Stage 1<br/>asyncio local swarm"] --> S2["Stage 2<br/>Redis Streams / NATS bus"]
    S2 --> S3["Stage 3<br/>Ray / Kubernetes worker fleet"]
    S3 --> S4["Stage 4<br/>geo-distributed sensor mesh"]
```

The coordinator's queue is the only coupling point: swapping `asyncio.Queue`
for a distributed stream upgrades the swarm without touching the reasoning
core.

## 6. Registering A New Sensor

```python
swarm.register_agent_capability("nuclei.observe", my_adapter.execute)
```

Any object exposing `execute(payload) -> Evidence | list[Evidence]` becomes a
first-class swarm capability. Tools are sensors; evidence is the currency.
