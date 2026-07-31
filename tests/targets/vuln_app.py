import json

def get_user_unsafe(user_input: str):
    data = json.loads(user_input)
    user_id = data['id']
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return query

def get_user_safe(user_input: str):
    import sqlite3
    data = json.loads(user_input)
    user_id = data['id']
    conn = sqlite3.connect(':memory:')
    cursor = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    return cursor.fetchall()
