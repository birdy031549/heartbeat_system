"""
Authentication module for PluralLog Relay Server.
Handles challenge-response authentication with Ed25519 signatures.
"""
import sqlite3
import secrets
import base64
from datetime import datetime, timedelta

import nacl.signing
from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError

from plurallog_relay import config, db
from plurallog_relay.errors import UnauthorizedError, UserNotFound


def create_challenge(db_path, user_id):
    """Create an authentication challenge (nonce) for a user."""
    user = db.get_user(db_path, user_id)  # Verify user exists
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    nonce = secrets.token_urlsafe(32)
    challenge_id = secrets.token_urlsafe(16)
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    
    cursor.execute("""
        INSERT INTO auth_challenges (challenge_id, user_id, nonce, expires_at)
        VALUES (?, ?, ?, ?)
    """, (challenge_id, user_id, nonce, expires_at))
    
    conn.commit()
    conn.close()
    
    return nonce


def verify_challenge(db_path, user_id, nonce, signature_b64):
    """
    Verify the challenge signature and issue an auth token.
    
    signature_b64: base64-encoded Ed25519 signature (64 bytes)
    """
    user = db.get_user(db_path, user_id)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Find the most recent challenge for this user
    cursor.execute("""
        SELECT nonce FROM auth_challenges
        WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP
        ORDER BY created_at DESC LIMIT 1
    """, (user_id,))
    
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise UnauthorizedError("No valid challenge found for user")
    
    nonce_from_db = row[0]
    
    if nonce_from_db != nonce:
        conn.close()
        raise UnauthorizedError("Nonce mismatch")
    
    # Verify the signature
    try:
        signature_bytes = base64.b64decode(signature_b64)
        public_key_bytes = base64.b64decode(user["public_signing_key"])
        verify_key = nacl.signing.VerifyKey(public_key_bytes)
        
        # Verify: signature over the UTF-8 encoded nonce
        verify_key.verify(nonce.encode("utf-8"), signature_bytes)
    except (BadSignatureError, ValueError) as e:
        conn.close()
        raise UnauthorizedError(f"Signature verification failed: {e}")
    
    # Issue a new token
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(seconds=config.TOKEN_EXPIRY_SECONDS)
    
    cursor.execute("""
        INSERT INTO auth_tokens (token, user_id, expires_at)
        VALUES (?, ?, ?)
    """, (token, user_id, expires_at))
    
    # Clean up old challenges
    cursor.execute("DELETE FROM auth_challenges WHERE user_id = ?", (user_id,))
    
    conn.commit()
    conn.close()
    
    return token


def verify_token(token, db_path):
    """Verify an auth token and return the user_id if valid."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT user_id FROM auth_tokens
        WHERE token = ? AND expires_at > CURRENT_TIMESTAMP
    """, (token,))
    
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    return row[0]
