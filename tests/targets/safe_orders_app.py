"""Fully GUARDED order-management service — Chimera negative control.

Identical API surface to vuln_orders_app.py, but every handler enforces
its declared guard inline (the most common production idiom):

  * ownership:  resource owner compared against the caller identity
  * role:       `is_admin` / `is_staff` attribute gates with PermissionError
  * state:      explicit precondition checks on the workflow state

Chimera must produce materially FEWER findings here than on the vulnerable
twin. If both score the same, guard detection is blind.
"""

ORDERS = {}
ACCOUNTS = {}
REFUNDS = {}


def get_order(order_id, current_user):
    """Retrieve an order. The caller should only see their own orders."""
    order = ORDERS.get(order_id)
    if order is None:
        return None
    if order["owner"] != current_user["id"]:
        raise PermissionError("You do not own this order")
    return order


def delete_order(order_id, current_user):
    """Delete an order permanently."""
    order = ORDERS.get(order_id)
    if order is None:
        return False
    if order["owner"] != current_user["id"]:
        raise PermissionError("You do not own this order")
    del ORDERS[order_id]
    return True


def admin_dashboard(current_user):
    """Administrative overview of all orders and accounts."""
    if not current_user.get("is_admin"):
        raise PermissionError("Admin only")
    return {
        "orders": len(ORDERS),
        "accounts": len(ACCOUNTS),
        "refunds": len(REFUNDS),
    }


def approve_refund(refund_id, current_user):
    """Approve a pending refund. Must be PENDING; staff only."""
    if not current_user.get("is_staff"):
        raise PermissionError("Staff only")
    refund = REFUNDS[refund_id]
    if refund["status"] != "PENDING":
        raise ValueError("Refund is not pending")
    refund["status"] = "APPROVED"
    return refund


def list_user_orders(user_id, current_user):
    """List all orders belonging to the given user id."""
    if user_id != current_user["id"] and not current_user.get("is_staff"):
        raise PermissionError("Cannot list another user's orders")
    return [o for o in ORDERS.values() if o["owner"] == user_id]


def transfer_balance(from_account_id, to_account_id, amount, current_user):
    """Move funds between two accounts."""
    source = ACCOUNTS.get(from_account_id)
    if source is None or source["owner"] != current_user["id"]:
        raise PermissionError("You do not own the source account")
    if source["balance"] < amount:
        raise ValueError("Insufficient funds")
    ACCOUNTS[from_account_id]["balance"] -= amount
    ACCOUNTS[to_account_id]["balance"] += amount
    return True
