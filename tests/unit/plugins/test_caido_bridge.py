"""
Regression tests for the CaidoBridge lifecycle defects identified in the
critical evaluation follow-up:

1. **Infinite mutual recursion** — the old ``initialize()`` called
   ``graphql()`` for its health-check while ``graphql()`` called
   ``initialize()``. The first real call recursed until ``RecursionError``
   (swallowed by ``except Exception: pass``), then every unwinding frame fired
   its own health-check HTTP POST: up to ~1000 spurious requests per call.
2. **Session leak / stale session** — sessions were never recreated after an
   external close (``session.closed`` was never inspected) and there was no
   deterministic cleanup path (no async-context-manager protocol), so
   unattended use leaked connector sockets.

aiohttp is an optional dependency (the ``http`` extra) and is NOT installed in
the test environment, so these tests inject a hermetic fake ``aiohttp`` module
into ``sys.modules``. The bridge imports aiohttp lazily inside
``_ensure_session``, so the injection is safe and deterministic.
"""

from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from chimera.plugins.caido_bridge import CaidoBridge
from chimera.plugins.caido_testing_adapter import CaidoTestingAdapter


def _install_fake_aiohttp(monkeypatch, responder=None):
    """Install a fake ``aiohttp`` module and return handles to inspect it."""
    posts = []
    sessions = []

    class _FakeResponse:
        def __init__(self, url, payload):
            self.url = url
            self.payload = payload
            self.status = 200
            self._json = {"data": {"__typename": "Query"}}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def text(self):
            if isinstance(self._json, Exception):
                return "<html>not json</html>"
            return json.dumps(self._json)

        async def json(self):
            if isinstance(self._json, Exception):
                raise self._json
            return self._json

    class _FakeClientSession:
        def __init__(self, headers=None):
            self.headers = headers or {}
            self.closed = False
            sessions.append(self)

        def post(self, url, json=None):
            posts.append({"url": url, "payload": json, "session": self})
            resp = _FakeResponse(url, json)
            if responder is not None:
                responder(resp, url, json)
            return resp

        async def close(self):
            self.closed = True

    module = SimpleNamespace(ClientSession=_FakeClientSession)
    monkeypatch.setitem(sys.modules, "aiohttp", module)
    return SimpleNamespace(posts=posts, sessions=sessions)


class TestLifecycle:
    async def test_initialize_runs_health_check_exactly_once(self, monkeypatch):
        """Old code recursed here until RecursionError. Exactly one POST."""
        fake = _install_fake_aiohttp(monkeypatch)
        bridge = CaidoBridge({"allowed_hosts": []})

        await bridge.initialize()

        assert len(fake.posts) == 1
        assert fake.posts[0]["payload"]["query"] == "query { __typename }"
        assert bridge._initialized is True

    async def test_graphql_fires_exactly_one_post_per_call(self, monkeypatch):
        """No request amplification — one real POST per query, no cascade."""
        fake = _install_fake_aiohttp(monkeypatch)
        bridge = CaidoBridge({"allowed_hosts": []})

        await bridge.graphql("query { requests { id } }")

        assert len(fake.posts) == 2  # one health-check + one real query
        assert fake.posts[-1]["payload"]["query"] == "query { requests { id } }"

    async def test_session_created_exactly_once(self, monkeypatch):
        fake = _install_fake_aiohttp(monkeypatch)
        bridge = CaidoBridge({"allowed_hosts": []})

        for _ in range(5):
            await bridge.graphql("query { __typename }")

        assert len(fake.sessions) == 1
        assert len(fake.posts) == 6  # 1 health-check + 5 queries

    async def test_closed_session_is_recreated(self, monkeypatch):
        """Stale-session bug: a closed session used to brick the bridge."""
        fake = _install_fake_aiohttp(monkeypatch)
        bridge = CaidoBridge({"allowed_hosts": []})

        await bridge.graphql("query { __typename }")
        fake.sessions[0].closed = True  # simulate an external close

        result = await bridge.graphql("query { second }")

        assert len(fake.sessions) == 2
        assert result["data"]["__typename"] == "Query"
        # Second session already initialized -> no second health-check.
        assert len(fake.posts) == 3

    async def test_cleanup_closes_session_and_resets_state(self, monkeypatch):
        fake = _install_fake_aiohttp(monkeypatch)
        bridge = CaidoBridge({"allowed_hosts": []})

        await bridge.graphql("query { __typename }")
        await bridge.cleanup()

        assert fake.sessions[0].closed is True
        assert bridge.session is None
        assert bridge._initialized is False

        # Bridge is reusable after cleanup (re-initializes, incl. health-check).
        await bridge.graphql("query { after }")
        assert len(fake.sessions) == 2
        assert len(fake.posts) == 4  # hc+query ... fresh hc+query

    async def test_context_manager_guarantees_cleanup(self, monkeypatch):
        """Deterministic cleanup: exiting the block closes the session."""
        fake = _install_fake_aiohttp(monkeypatch)

        async with CaidoBridge({"allowed_hosts": []}) as bridge:
            await bridge.graphql("query { __typename }")
            assert bridge.session is not None

        assert len(fake.sessions) == 1
        assert fake.sessions[0].closed is True
        assert bridge.session is None

    async def test_missing_aiohttp_raises_runtime_error(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "aiohttp", None)  # import -> ImportError
        bridge = CaidoBridge({"allowed_hosts": []})

        with pytest.raises(RuntimeError, match="aiohttp is not installed"):
            await bridge.graphql("query { __typename }")


class TestTransportErrors:
    async def test_http_error_status_raises(self, monkeypatch):
        def boom(resp, url, payload):
            resp.status = 500

        _install_fake_aiohttp(monkeypatch, responder=boom)
        bridge = CaidoBridge({"allowed_hosts": []})

        with pytest.raises(RuntimeError, match="HTTP 500"):
            await bridge.graphql("query { __typename }")

    async def test_health_check_failure_is_soft_not_fatal(self, monkeypatch):
        """Health-check exceptions must be swallowed; the query still runs."""
        def freaky(resp, url, payload):
            if "__typename" in payload["query"]:
                resp.status = 503

        fake = _install_fake_aiohttp(monkeypatch, responder=freaky)
        bridge = CaidoBridge({"allowed_hosts": []})

        result = await bridge.graphql("query { real }")

        assert bridge._initialized is True
        assert result["data"]["__typename"] == "Query"
        assert len(fake.posts) == 2

    async def test_non_json_response_raises(self, monkeypatch):
        def html(resp, url, payload):
            resp._json = ValueError("Expecting value")

        _install_fake_aiohttp(monkeypatch, responder=html)
        bridge = CaidoBridge({"allowed_hosts": []})

        with pytest.raises(RuntimeError, match="non-JSON"):
            await bridge.graphql("query { real }")

    async def test_graphql_errors_raise(self, monkeypatch):
        def gql_errors(resp, url, payload):
            if payload["query"] != "query { __typename }":
                resp._json = {"errors": [{"message": "unknown field"}]}

        _install_fake_aiohttp(monkeypatch, responder=gql_errors)
        bridge = CaidoBridge({"allowed_hosts": []})

        with pytest.raises(RuntimeError, match="Caido GraphQL errors"):
            await bridge.graphql("query { bogus }")


class TestActions:
    async def test_execute_graphql_returns_evidence(self, monkeypatch):
        _install_fake_aiohttp(monkeypatch)
        bridge = CaidoBridge({"allowed_hosts": []})

        ev = await bridge.execute({"action": "graphql", "query": "query { x }"})

        assert ev.metadata == {"plugin": "caido", "action": "graphql"}
        assert "result" in ev.data
        assert ev.chain_of_custody is not None

    async def test_execute_graphql_requires_query(self, monkeypatch):
        _install_fake_aiohttp(monkeypatch)
        bridge = CaidoBridge({"allowed_hosts": []})
        with pytest.raises(ValueError, match=r"requires payload\['query'\]"):
            await bridge.execute({"action": "graphql"})

    async def test_active_scan_disabled_by_default(self, monkeypatch):
        _install_fake_aiohttp(monkeypatch)
        bridge = CaidoBridge({"allowed_hosts": []})
        with pytest.raises(PermissionError, match="active_scan disabled"):
            await bridge.execute({"action": "active_scan", "request_id": "1"})

    async def test_replay_http_blocks_out_of_scope_host(self, monkeypatch):
        _install_fake_aiohttp(monkeypatch)
        bridge = CaidoBridge({"allowed_hosts": ["example.com"]})
        with pytest.raises(PermissionError, match="outside authorized Caido scope"):
            await bridge.execute({
                "action": "replay_http",
                "target_url": "http://evil.other/x",
                "raw_http_request": "GET /x HTTP/1.1",
            })

    async def test_replay_http_in_scope_reaches_mutation_check(self, monkeypatch):
        _install_fake_aiohttp(monkeypatch)
        bridge = CaidoBridge({"allowed_hosts": ["example.com"]})
        with pytest.raises(RuntimeError, match="No Caido replay_mutation"):
            await bridge.execute({
                "action": "replay_http",
                "target_url": "http://example.com/x",
                "raw_http_request": "GET /x HTTP/1.1",
            })


class TestTestingAdapter:
    async def test_adapter_delegates_full_lifecycle(self, monkeypatch):
        fake = _install_fake_aiohttp(monkeypatch)
        adapter = CaidoTestingAdapter({"allowed_hosts": []})

        await adapter.initialize()
        ev = await adapter.execute({"action": "graphql", "query": "query { x }"})
        await adapter.cleanup()

        assert ev.metadata["plugin"] == "caido"
        assert len(fake.sessions) == 1
        assert fake.sessions[0].closed is True
        assert adapter.capability == "controlled_testing.http.caido"
