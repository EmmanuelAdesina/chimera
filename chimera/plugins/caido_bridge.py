"""
Caido Bridge.

Persistent GraphQL bridge for using Caido as an epistemic HTTP sensor.

This bridge intentionally does not assume undocumented schema names. You can:
- run arbitrary configured GraphQL queries/mutations against your local Caido
- optionally enable active scan actions if your Caido schema supports them
- enforce target host scope before sending traffic-oriented requests

Lifecycle
---------
``initialize()`` is idempotent and lazily creates exactly one aiohttp session,
recreating it only if the previous session was closed. The bridge is also an
async context manager — ``async with CaidoBridge(cfg) as bridge: ...`` —
which guarantees ``cleanup()`` (session close) on exit, so unattended use
cannot leak connector sockets.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from chimera.models.evidence import Evidence, EvidenceSource, EvidenceType, ChainOfCustody
from chimera.plugins.base_plugin import ToolPlugin


class CaidoBridge(ToolPlugin):
    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.api_url = self.config.get("caido_url", "http://127.0.0.1:8080/graphql")
        self.token = self.config.get("token")
        self.allowed_hosts = set(self.config.get("allowed_hosts", []) or [])
        self.enable_active_scan = bool(self.config.get("enable_active_scan", False))
        self.session = None
        self._initialized = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """
        Prepare the bridge for use. Idempotent: creates the transport session
        at most once (recreating only a closed session) and runs the soft
        health-check exactly once. The health-check uses the transport helper
        directly so it can never recurse back into ``initialize()``.
        """
        await self._ensure_session()

        if self._initialized:
            return
        # Soft health-check. Some Caido builds may not expose introspection.
        try:
            await self._post_json("query { __typename }")
        except Exception:
            pass
        self._initialized = True

    async def cleanup(self) -> None:
        if self.session is not None:
            await self.session.close()
        self.session = None
        self._initialized = False

    async def __aenter__(self) -> "CaidoBridge":
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        await self.cleanup()
        return False

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    async def _ensure_session(self) -> None:
        """Create the aiohttp session if absent or closed. Recursion-free."""
        if self.session is not None and not self.session.closed:
            return
        # Close a stale (closed) session handle before replacing it so the
        # reference is never reused and the intent is explicit.
        self.session = None
        try:
            import aiohttp
        except ImportError as exc:
            raise RuntimeError("aiohttp is not installed. Run: pip install aiohttp") from exc

        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self.session = aiohttp.ClientSession(headers=headers)

    async def _post_json(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Single GraphQL round-trip against an existing session."""
        payload: Dict[str, Any] = {"query": query}
        if variables is not None:
            payload["variables"] = variables

        async with self.session.post(self.api_url, json=payload) as response:
            text = await response.text()
            if response.status >= 400:
                raise RuntimeError(f"Caido GraphQL HTTP {response.status}: {text[:500]}")
            try:
                data = await response.json()
            except Exception as exc:
                raise RuntimeError(f"Caido GraphQL returned non-JSON response: {text[:500]}") from exc

        if "errors" in data:
            raise RuntimeError(f"Caido GraphQL errors: {data['errors']}")
        return data

    async def graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        await self.initialize()
        return await self._post_json(query, variables)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    async def execute(self, payload: Dict[str, Any]) -> Evidence:
        action = payload.get("action", "graphql")

        if action == "graphql":
            query = payload.get("query")
            variables = payload.get("variables")
            if not query:
                raise ValueError("caido.execute action=graphql requires payload['query']")
            result = await self.graphql(query, variables)
            return self._evidence("graphql", {"result": result})

        if action == "replay_http":
            return await self._replay_http(payload)

        if action == "active_scan":
            if not self.enable_active_scan:
                raise PermissionError("Caido active_scan disabled. Set enable_active_scan=true in config.")
            return await self._active_scan(payload)

        raise ValueError(f"Unsupported Caido action: {action}")

    async def _replay_http(self, payload: Dict[str, Any]) -> Evidence:
        target_url = payload.get("target_url")
        raw_http_request = payload.get("raw_http_request")

        if not target_url or not raw_http_request:
            raise ValueError("replay_http requires target_url and raw_http_request")

        self._enforce_scope(target_url, payload.get("_scope", {}))

        mutation = self.config.get("replay_mutation")
        if not mutation:
            raise RuntimeError(
                "No Caido replay_mutation configured. Provide schema-specific GraphQL mutation in config."
            )

        variables = {
            "input": {
                "url": target_url,
                "raw": raw_http_request,
            }
        }

        result = await self.graphql(mutation, variables)
        return self._evidence("replay_http", {"target_url": target_url, "result": result})

    async def _active_scan(self, payload: Dict[str, Any]) -> Evidence:
        target_url = payload.get("target_url")
        request_id = payload.get("request_id")

        if target_url:
            self._enforce_scope(target_url, payload.get("_scope", {}))

        mutation = self.config.get("active_scan_mutation")
        if not mutation:
            raise RuntimeError(
                "No Caido active_scan_mutation configured. Provide schema-specific GraphQL mutation in config."
            )

        result = await self.graphql(mutation, {"requestId": request_id})
        return self._evidence("active_scan", {"target_url": target_url, "request_id": request_id, "result": result})

    def _enforce_scope(self, url: str, runtime_scope: Dict[str, Any]) -> None:
        host = urlparse(url).hostname or ""
        allowed = set(self.allowed_hosts)
        allowed.update(runtime_scope.get("allowed_hosts", []) or [])

        if allowed and host not in allowed:
            raise PermissionError(f"Host is outside authorized Caido scope: {host}")

    def _evidence(self, action: str, data: Dict[str, Any]) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="CaidoBridge",
            action=action,
            input_ref=self.api_url,
            output_ref=ev_id,
            parameters={"action": action},
        )
        chain.finalize()

        return Evidence(
            source=EvidenceSource.EXPERIMENT,
            evidence_type=EvidenceType.EXPERIMENT_RESULT,
            data=data,
            chain_of_custody=chain,
            confidence=0.9,
            description=f"Caido bridge executed action: {action}",
            metadata={"plugin": "caido", "action": action},
        )
