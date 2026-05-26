"""
User discovery module for PluralLog Relay Server.
Handles searching and discovering users by handle.
"""
import sqlite3

from plurallog_relay import db


def search_by_handle(db_path, handle_prefix, requester_user_id):
    """
    Search for users by handle prefix.
    System users cannot see other system users.
    Friends can only see system users.
    """
    requester = db.get_user(db_path, requester_user_id)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Friends can only find system users
    if requester["client_type"] == "friend":
        cursor.execute("""
            SELECT user_id, handle, client_type, public_exchange_key
            FROM users
            WHERE handle LIKE ? AND client_type = 'system' AND deleted_at IS NULL
            ORDER BY handle
            LIMIT 100
        """, (handle_prefix + "%",))
    else:
        # System users can only find other friends (not other systems)
        cursor.execute("""
            SELECT user_id, handle, client_type, public_exchange_key
            FROM users
            WHERE handle LIKE ? AND client_type = 'friend' AND deleted_at IS NULL
            ORDER BY handle
            LIMIT 100
        """, (handle_prefix + "%",))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "user_id": row[0],
            "handle": row[1],
            "client_type": row[2],
            "public_exchange_key": row[3],
        }
        for row in rows
    ]
