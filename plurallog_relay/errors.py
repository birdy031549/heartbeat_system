"""
Error classes for PluralLog Relay Server.
"""


class PluralLogError(Exception):
    """Base exception for all PluralLog errors."""
    pass


class InvalidProtocolVersion(PluralLogError):
    """Client protocol version is incompatible with server."""
    pass


class DuplicateHandle(PluralLogError):
    """User handle already exists."""
    pass


class UserNotFound(PluralLogError):
    """User does not exist."""
    pass


class UnauthorizedError(PluralLogError):
    """Authentication failed."""
    pass


class PermissionDenied(PluralLogError):
    """User lacks permission for this operation."""
    pass


class ConflictError(PluralLogError):
    """Operation conflicts with existing data."""
    pass


class ValidationError(PluralLogError):
    """Request data validation failed."""
    pass
