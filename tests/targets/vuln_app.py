# Intentionally vulnerable target for Chimera testing
# Demonstrates the JSON -> Python -> SQL grammar differential

import json

def get_user_unsafe(user_input: str):
    """
    Developer intent: safely retrieve user by ID from JSON input.
    Vulnerability: json.loads produces a Python str with bare quotes,
    which then breaks the SQL string literal boundary.
    """
    data = json.loads(user_input)
    user_id = data["id"]

    # Grammar differential here:
    # user_id is a Python str (quote is safe data)
    # But in the f-string, it becomes a SQL literal (quote is meta)
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return query


def get_user_safe(user_input: str):
    """Fixed version with parameterized query."""
    import sqlite3
    data = json.loads(user_input)
    user_id = data["id"]

    conn = sqlite3.connect(":memory:")
    # Sanitizer exists: parameterized query translates Python str -> SQL param
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()
