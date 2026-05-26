"""
Database module for PluralLog Relay Server.
Handles SQLite schema, user registration, and data persistence.
"""
import sqlite3
import uuid
from datetime import datetime

from plurallog_relay.errors import DuplicateHandle, UserNotFound


def init_db(db_path):
    """Initialize database schema."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            handle TEXT UNIQUE NOT NULL,
            client_type TEXT NOT NULL,
            public_signing_key TEXT NOT NULL,
            public_exchange_key TEXT NOT NULL,
            protocol_version INTEGER,
            feature_set TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            deleted_at TIMESTAMP
        )
    """)
    
    # Auth challenges table (for nonce verification)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_challenges (
            challenge_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    
    # Auth tokens table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    
    # Volumes table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS volumes (
            volume_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            volume_name TEXT NOT NULL,
            version INTEGER NOT NULL,
            encrypted_payload BLOB,
            signature TEXT,
            size_bytes INTEGER,
            modified_at TIMESTAMP,
            event_tags TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            etag TEXT,
            UNIQUE(user_id, volume_name, version),
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)
    
    # Sharing relationships table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sharings (
            sharing_id TEXT PRIMARY KEY,
            from_user_id TEXT NOT NULL,
            to_user_id TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            friend_exchange_public_key TEXT,
            encrypted_vek_blob TEXT,
            permissions TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP,
            revoked_at TIMESTAMP,
            FOREIGN KEY (from_user_id) REFERENCES users(user_id),
            FOREIGN KEY (to_user_id) REFERENCES users(user_id)
        )
    """)
    
    # Invite codes table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS invite_codes (
            code TEXT PRIMARY KEY,
            system_user_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            redeemed_at TIMESTAMP,
            redeemed_by_user_id TEXT,
            FOREIGN KEY (system_user_id) REFERENCES users(user_id),
            FOREIGN KEY (redeemed_by_user_id) REFERENCES users(user_id)
        )
    """)
    
    conn.commit()
    conn.close()


def register_user(db_path, user_data):
    """Register a new user."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    user_id = str(uuid.uuid4())
    
    try:
        cursor.execute("""
            INSERT INTO users 
            (user_id, handle, client_type, public_signing_key, public_exchange_key, 
             protocol_version, feature_set)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            user_data["handle"],
            user_data["client_type"],
            user_data["public_signing_key"],
            user_data["public_exchange_key"],
            user_data["protocol_version"],
            ",".join(user_data.get("feature_set", [])),
        ))
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        raise DuplicateHandle(f"Handle '{user_data['handle']}' already exists")
    
    conn.close()
    return user_id


def get_user(db_path, user_id):
    """Retrieve user by ID."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE user_id = ? AND deleted_at IS NULL", (user_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise UserNotFound(f"User {user_id} not found")
    
    return {
        "user_id": row[0],
        "handle": row[1],
        "client_type": row[2],
        "public_signing_key": row[3],
        "public_exchange_key": row[4],
        "protocol_version": row[5],
        "feature_set": row[6].split(",") if row[6] else [],
    }


def delete_user(db_path, user_id):
    """Soft-delete a user."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE user_id = ?",
        (user_id,)
    )
    conn.commit()
    conn.close()


def get_user_by_handle(db_path, handle):
    """Retrieve user by handle."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT user_id FROM users WHERE handle = ? AND deleted_at IS NULL", (handle,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    return row[0]
