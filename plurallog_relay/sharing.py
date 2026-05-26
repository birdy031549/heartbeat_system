"""
Sharing module for PluralLog Relay Server.
Handles sharing relationships, invites, and permissions.
"""
import sqlite3
import uuid
import json
import secrets
from datetime import datetime

from plurallog_relay import db, config
from plurallog_relay.errors import (
    ConflictError, PermissionDenied, UserNotFound, ValidationError
)


def create_sharing_request(db_path, from_user_id, to_user_id):
    """
    Create a sharing request (friend → system only).
    Returns the sharing_id.
    """
    from_user = db.get_user(db_path, from_user_id)
    to_user = db.get_user(db_path, to_user_id)
    
    # Validate directionality: friend → system
    if from_user["client_type"] != "friend" or to_user["client_type"] != "system":
        raise ValidationError("Only friends can request sharing from systems")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    sharing_id = str(uuid.uuid4())
    
    cursor.execute("""
        INSERT INTO sharings 
        (sharing_id, from_user_id, to_user_id, status, friend_exchange_public_key)
        VALUES (?, ?, ?, 'pending', ?)
    """, (sharing_id, from_user_id, to_user_id, from_user["public_exchange_key"]))
    
    conn.commit()
    conn.close()
    
    return sharing_id


def get_sharing_request(db_path, sharing_id):
    """Retrieve a sharing request by ID."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT sharing_id, from_user_id, to_user_id, status, 
               friend_exchange_public_key, encrypted_vek_blob, permissions,
               created_at, updated_at
        FROM sharings WHERE sharing_id = ?
    """, (sharing_id,))
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise UserNotFound(f"Sharing request {sharing_id} not found")
    
    permissions = json.loads(row[6]) if row[6] else {}
    
    return {
        "id": row[0],
        "from_user_id": row[1],
        "to_user_id": row[2],
        "status": row[3],
        "friend_exchange_public_key": row[4],
        "encrypted_vek_blob": row[5],
        "permissions": permissions,
        "created_at": row[7],
        "updated_at": row[8],
    }


def list_user_sharing_requests(db_path, user_id, status=None):
    """List sharing requests for a user (as recipient/to_user_id)."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    if status:
        cursor.execute("""
            SELECT sharing_id, from_user_id, to_user_id, status, 
                   friend_exchange_public_key, encrypted_vek_blob, permissions,
                   created_at, updated_at
            FROM sharings 
            WHERE to_user_id = ? AND status = ?
            ORDER BY created_at DESC
        """, (user_id, status))
    else:
        cursor.execute("""
            SELECT sharing_id, from_user_id, to_user_id, status, 
                   friend_exchange_public_key, encrypted_vek_blob, permissions,
                   created_at, updated_at
            FROM sharings 
            WHERE to_user_id = ? AND revoked_at IS NULL
            ORDER BY created_at DESC
        """, (user_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        permissions = json.loads(row[6]) if row[6] else {}
        results.append({
            "id": row[0],
            "from_user_id": row[1],
            "to_user_id": row[2],
            "status": row[3],
            "friend_exchange_public_key": row[4],
            "encrypted_vek_blob": row[5],
            "permissions": permissions,
            "created_at": row[7],
            "updated_at": row[8],
        })
    
    return results


def respond_sharing_request(db_path, request_id, system_user_id, 
                            accepted, encrypted_vek_blob, permissions):
    """Accept or reject a sharing request."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT from_user_id, to_user_id FROM sharings WHERE sharing_id = ?
    """, (request_id,))
    
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise UserNotFound(f"Sharing request {request_id} not found")
    
    from_user_id, to_user_id = row
    
    if to_user_id != system_user_id:
        conn.close()
        raise PermissionDenied("Only the recipient can respond to a sharing request")
    
    if accepted:
        status = "active"
        permissions_json = json.dumps(permissions)
        cursor.execute("""
            UPDATE sharings 
            SET status = ?, encrypted_vek_blob = ?, permissions = ?, updated_at = CURRENT_TIMESTAMP
            WHERE sharing_id = ?
        """, (status, encrypted_vek_blob, permissions_json, request_id))
    else:
        cursor.execute("""
            DELETE FROM sharings WHERE sharing_id = ?
        """, (request_id,))
    
    conn.commit()
    conn.close()


def update_sharing_permissions(db_path, sharing_id, system_user_id, permissions):
    """Update permissions for an active sharing."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT to_user_id FROM sharings WHERE sharing_id = ?
    """, (sharing_id,))
    
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise UserNotFound(f"Sharing {sharing_id} not found")
    
    if row[0] != system_user_id:
        conn.close()
        raise PermissionDenied("Only the system user can update sharing permissions")
    
    permissions_json = json.dumps(permissions)
    cursor.execute("""
        UPDATE sharings 
        SET permissions = ?, updated_at = CURRENT_TIMESTAMP
        WHERE sharing_id = ?
    """, (permissions_json, sharing_id))
    
    conn.commit()
    conn.close()


def revoke_sharing(db_path, sharing_id, system_user_id):
    """Revoke a sharing relationship."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT to_user_id FROM sharings WHERE sharing_id = ?
    """, (sharing_id,))
    
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise UserNotFound(f"Sharing {sharing_id} not found")
    
    if row[0] != system_user_id:
        conn.close()
        raise PermissionDenied("Only the system user can revoke sharing")
    
    cursor.execute("""
        UPDATE sharings 
        SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP
        WHERE sharing_id = ?
    """, (sharing_id,))
    
    conn.commit()
    conn.close()


def create_invite_code(db_path, system_user_id):
    """Generate an invite code for a system user."""
    user = db.get_user(db_path, system_user_id)
    if user["client_type"] != "system":
        raise PermissionDenied("Only system users can generate invite codes")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    code = secrets.token_urlsafe(config.INVITE_CODE_LENGTH)
    
    cursor.execute("""
        INSERT INTO invite_codes (code, system_user_id)
        VALUES (?, ?)
    """, (code, system_user_id))
    
    conn.commit()
    conn.close()
    
    return code


def redeem_invite_code(db_path, code, friend_user_id):
    """Redeem an invite code to create a sharing request."""
    friend = db.get_user(db_path, friend_user_id)
    if friend["client_type"] != "friend":
        raise PermissionDenied("Only friends can redeem invite codes")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT system_user_id, redeemed_at FROM invite_codes WHERE code = ?
    """, (code,))
    
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise UserNotFound("Invite code not found")
    
    system_user_id, redeemed_at = row
    
    if redeemed_at is not None:
        conn.close()
        raise ValidationError("Invite code has already been redeemed", 410)
    
    # Mark as redeemed
    cursor.execute("""
        UPDATE invite_codes SET redeemed_at = CURRENT_TIMESTAMP, redeemed_by_user_id = ?
        WHERE code = ?
    """, (friend_user_id, code))
    
    # Create sharing request
    sharing_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO sharings 
        (sharing_id, from_user_id, to_user_id, status, friend_exchange_public_key)
        VALUES (?, ?, ?, 'pending', ?)
    """, (sharing_id, friend_user_id, system_user_id, friend["public_exchange_key"]))
    
    conn.commit()
    conn.close()
    
    return sharing_id
