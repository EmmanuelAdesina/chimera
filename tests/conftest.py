"""Shared fixtures for the Chimera test suite."""

from __future__ import annotations

import pytest

from chimera.core.semantic_graph import SemanticGraph
from chimera.core.world_state import AnalysisConfig


@pytest.fixture
def graph() -> SemanticGraph:
    return SemanticGraph()


@pytest.fixture
def targets_dir() -> str:
    return "tests/targets"


@pytest.fixture
def vuln_app_path() -> str:
    return "tests/targets/vuln_app.py"


@pytest.fixture
def vuln_orders_path() -> str:
    return "tests/targets/vuln_orders_app.py"


@pytest.fixture
def safe_orders_path() -> str:
    return "tests/targets/safe_orders_app.py"


@pytest.fixture
def make_config():
    def _make(target_path: str = "", **overrides) -> AnalysisConfig:
        cfg = AnalysisConfig(target_path=target_path, **overrides)
        return cfg

    return _make


# Inline source fixtures --------------------------------------------------

VULNERABLE_HANDLER_SRC = '''
ORDERS = {}

def get_order(order_id, current_user):
    """Retrieve an order. Users may only view their own orders."""
    return ORDERS.get(order_id)

def delete_order(order_id, current_user):
    """Delete an order permanently."""
    del ORDERS[order_id]
    return True

def admin_dashboard(current_user):
    """Admin-only overview."""
    return {"orders": len(ORDERS)}
'''

GUARDED_HANDLER_SRC = '''
ORDERS = {}

def get_order(order_id, current_user):
    """Retrieve an order. Users may only view their own orders."""
    order = ORDERS.get(order_id)
    if order and order["owner"] != current_user["id"]:
        raise PermissionError("not your order")
    return order

def delete_order(order_id, current_user):
    """Delete an order permanently."""
    order = ORDERS.get(order_id)
    if not order or order["owner"] != current_user["id"]:
        raise PermissionError("not your order")
    del ORDERS[order_id]
    return True

def admin_dashboard(current_user):
    """Admin-only overview."""
    if not current_user.get("is_admin"):
        raise PermissionError("admin only")
    return {"orders": len(ORDERS)}
'''


@pytest.fixture
def vulnerable_source() -> str:
    return VULNERABLE_HANDLER_SRC


@pytest.fixture
def guarded_source() -> str:
    return GUARDED_HANDLER_SRC
