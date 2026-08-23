"""Intentionally VULNERABLE order-management service — Chimera test target.

Every planted flaw is a *real* missing guard that static analysis can see:

  1. get_order         — IDOR: resource id param, no ownership check
  2. delete_order      — IDOR + missing auth on a destructive action
  3. admin_dashboard   — missing role check (vertical privilege escalation)
  4. approve_refund    — missing auth + missing state guard (workflow bypass)
  5. list_user_orders  — IDOR via user path parameter
  6. transfer_balance  — missing auth + no ownership on the source account

The safe twin (safe_orders_app.py) implements the same API with the guards
present. Chimera must produce materially more findings here than there.
"""

ORDERS = {}
ACCOUNTS = {}
REFUNDS = {}


def get_order(order_id, current_user):
    """Retrieve an order. The caller should only see their own orders."""
    return ORDERS.get(order_id)


def delete_order(order_id, current_user):
    """Delete an order permanently."""
    if order_id in ORDERS:
        del ORDERS[order_id]
        return True
    return False


def admin_dashboard(current_user):
    """Administrative overview of all orders and accounts."""
    return {
        "orders": len(ORDERS),
        "accounts": len(ACCOUNTS),
        "refunds": len(REFUNDS),
    }


def approve_refund(refund_id, current_user):
    """Approve a pending refund. Must be PENDING; staff only."""
    refund = REFUNDS[refund_id]
    refund["status"] = "APPROVED"
    return refund


def list_user_orders(user_id, current_user):
    """List all orders belonging to the given user id."""
    return [o for o in ORDERS.values() if o["owner"] == user_id]


def transfer_balance(from_account_id, to_account_id, amount, current_user):
    """Move funds between two accounts."""
    ACCOUNTS[from_account_id]["balance"] -= amount
    ACCOUNTS[to_account_id]["balance"] += amount
    return True
