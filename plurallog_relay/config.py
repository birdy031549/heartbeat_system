"""
Configuration module for PluralLog Relay Server.
"""

# Server version and protocol
SERVER_VERSION = "1.0.0"
MIN_PROTOCOL_VERSION = 1

# Invite code generation
INVITE_CODE_LENGTH = 32

# Cryptographic settings
SIGNING_ALGORITHM = "Ed25519"
EXCHANGE_ALGORITHM = "X25519"
ENCRYPTION_ALGORITHM = "ChaCha20-Poly1305"

# Token expiration
TOKEN_EXPIRY_SECONDS = 86400  # 24 hours

# Volume settings
VOLUME_CHUNK_SIZE = 4096  # 4KB alignment for padding
MAX_VOLUME_SIZE = 1024 * 1024 * 1024  # 1 GB max per volume

# Sharing permissions
DEFAULT_PERMISSIONS = {
    "share_front_status": False,
    "share_members": False,
    "share_front_history": False,
    "share_journal": False,
    "share_mood_trends": False,
    "share_polls": False,
}
