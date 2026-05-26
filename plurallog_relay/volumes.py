"""
Volume management module for PluralLog Relay Server.
Handles encrypted volume uploads, storage, and sharing.
"""
import os
import sqlite3
import uuid
import json
import base64
import hashlib
from datetime import datetime

import nacl.signing
from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError

from plurallog_relay import db, config
from plurallog_relay.errors import (
    ConflictError, PermissionDenied, UserNotFound, UnauthorizedError
)


def upload_volume(db_path, vol_path, user_id, volume_name, control_header, 
                  encrypted_payload_b64, signature_b64):
    """
    Upload an encrypted volume with signature verification.
    
    Only system users can upload.
    """
    user = db.get_user(db_path, user_id)
    
    if user["client_type"] != "system":
        raise PermissionDenied("Only system users can upload volumes")
    
    # Decode the payload
    try:
        encrypted_payload = base64.b64decode(encrypted_payload_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 payload: {e}")
    
    # Verify signature: header_json + payload_bytes
    header_json = json.dumps(control_header, separators=(",", ":"))
    sign_input = header_json.encode("utf-8") + encrypted_payload
    
    try:
        signature_bytes = base64.b64decode(signature_b64)
        public_key_bytes = base64.b64decode(user["public_signing_key"])
        verify_key = nacl.signing.VerifyKey(public_key_bytes)
        verify_key.verify(sign_input, signature_bytes)
    except (BadSignatureError, ValueError) as e:
        raise UnauthorizedError(f"Signature verification failed: {e}")
    
    version = control_header.get("version")
    size_bytes = control_header.get("size_bytes")
    modified_at = control_header.get("modified_at")
    event_tags = control_header.get("event_tags", [])
    
    # Check for version conflict
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT volume_id FROM volumes
        WHERE user_id = ? AND volume_name = ? AND version = ?
    """, (user_id, volume_name, version))
    
    if cursor.fetchone():
        conn.close()
        raise ConflictError(f"Volume {volume_name} version {version} already exists")
    
    # Generate etag (hash of payload)
    etag = hashlib.sha256(encrypted_payload).hexdigest()
    
    # Store in database
    volume_id = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO volumes 
        (volume_id, user_id, volume_name, version, encrypted_payload, signature, 
         size_bytes, modified_at, event_tags, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        volume_id, user_id, volume_name, version, encrypted_payload, signature_b64,
        size_bytes, modified_at, json.dumps(event_tags), etag
    ))
    
    conn.commit()
    conn.close()


def list_user_volumes(db_path, user_id):
    """List all volumes for a user."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT volume_id, volume_name, version, size_bytes, modified_at, etag
        FROM volumes
        WHERE user_id = ?
        ORDER BY volume_name, version DESC
    """, (user_id,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "volume_id": row[0],
            "volume_name": row[1],
            "version": row[2],
            "size_bytes": row[3],
            "modified_at": row[4],
            "etag": row[5],
        }
        for row in rows
    ]


def list_shared_volumes(db_path, system_user_id, friend_user_id):
    """
    List volumes shared by system_user_id to friend_user_id,
    respecting permissions.
    """
    from plurallog_relay.permissions import permissions_to_volumes
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Find active sharing from friend to system
    cursor.execute("""
        SELECT permissions FROM sharings
        WHERE from_user_id = ? AND to_user_id = ? AND status = 'active'
    """, (friend_user_id, system_user_id))
    
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise PermissionDenied("No active sharing relationship")
    
    permissions = json.loads(row[0]) if row[0] else {}
    allowed_volumes = permissions_to_volumes(permissions)
    
    # Get shared volumes respecting permissions
    placeholders = ",".join("?" * len(allowed_volumes))
    cursor.execute(f"""
        SELECT volume_id, volume_name, version, size_bytes, modified_at, etag
        FROM volumes
        WHERE user_id = ? AND volume_name IN ({placeholders})
        ORDER BY volume_name, version DESC
    """, [system_user_id] + list(allowed_volumes))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "volume_id": row[0],
            "volume_name": row[1],
            "version": row[2],
            "size_bytes": row[3],
            "modified_at": row[4],
            "etag": row[5],
        }
        for row in rows
    ]


def get_shared_volume(db_path, vol_path, system_user_id, friend_user_id, 
                      volume_name, if_none_match_etag=None):
    """
    Retrieve a shared volume with conditional GET support.
    Returns None if etag matches (304 Not Modified).
    """
    from plurallog_relay.permissions import permissions_to_volumes
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Verify sharing relationship
    cursor.execute("""
        SELECT permissions FROM sharings
        WHERE from_user_id = ? AND to_user_id = ? AND status = 'active'
    """, (friend_user_id, system_user_id))
    
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise PermissionDenied("No active sharing relationship")
    
    permissions = json.loads(row[0]) if row[0] else {}
    allowed_volumes = permissions_to_volumes(permissions)
    
    if volume_name not in allowed_volumes:
        conn.close()
        raise PermissionDenied(f"Volume {volume_name} not shared")
    
    # Get latest version of volume
    cursor.execute("""
        SELECT volume_id, encrypted_payload, etag, size_bytes, 
               modified_at, event_tags
        FROM volumes
        WHERE user_id = ? AND volume_name = ?
        ORDER BY version DESC LIMIT 1
    """, (system_user_id, volume_name))
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise UserNotFound(f"Volume {volume_name} not found")
    
    volume_id, encrypted_payload, etag, size_bytes, modified_at, event_tags = row
    
    # Check conditional GET
    if if_none_match_etag == etag:
        return None  # 304 Not Modified
    
    # Get the stored encrypted_vek_blob from sharing
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT encrypted_vek_blob FROM sharings
        WHERE from_user_id = ? AND to_user_id = ? AND status = 'active'
    """, (friend_user_id, system_user_id))
    row = cursor.fetchone()
    conn.close()
    
    encrypted_vek_blob = row[0] if row else None
    
    return {
        "volume_id": volume_id,
        "volume_name": volume_name,
        "size_bytes": size_bytes,
        "modified_at": modified_at,
        "event_tags": json.loads(event_tags) if event_tags else [],
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "encrypted_vek_blob": encrypted_vek_blob,
        "etag": etag,
    }


def delete_user_volumes(vol_path, user_id):
    """Delete all stored volume files for a user."""
    user_vol_dir = os.path.join(vol_path, user_id)
    if os.path.exists(user_vol_dir):
        import shutil
        shutil.rmtree(user_vol_dir)
