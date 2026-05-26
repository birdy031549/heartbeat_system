"""
PluralLog Relay Server - Flask Application Factory
Handles registration, authentication, volume storage, and secure sharing.
"""
import os
import json
import sqlite3
import logging
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify
from werkzeug.exceptions import HTTPException

from plurallog_relay import config, db, auth, volumes, sharing, discovery
from plurallog_relay.errors import (
    InvalidProtocolVersion, DuplicateHandle, UserNotFound,
    UnauthorizedError, PermissionDenied, ConflictError
)

logger = logging.getLogger(__name__)


def create_app(db_path=None, vol_path=None):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Use provided paths or defaults
    if db_path is None:
        db_path = os.path.join(os.path.dirname(__file__), "plurallog.db")
    if vol_path is None:
        vol_path = os.path.join(os.path.dirname(__file__), "volumes")
    
    app.config["DB_PATH"] = db_path
    app.config["VOLUME_PATH"] = vol_path
    app.config["TESTING"] = False
    
    # Ensure volume directory exists
    os.makedirs(vol_path, exist_ok=True)
    
    # Initialize database
    db.init_db(db_path)
    
    # Record startup time for uptime tracking
    app.config["START_TIME"] = datetime.utcnow()
    
    # ─── Error Handlers ────────────────────────────────────────────
    
    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return jsonify({"error": error.description}), error.code
    
    @app.errorhandler(InvalidProtocolVersion)
    def handle_protocol_version(error):
        return jsonify({"error": str(error)}), 426
    
    @app.errorhandler(DuplicateHandle)
    def handle_duplicate(error):
        return jsonify({"error": str(error)}), 409
    
    @app.errorhandler(UnauthorizedError)
    def handle_unauthorized(error):
        return jsonify({"error": str(error)}), 403
    
    @app.errorhandler(PermissionDenied)
    def handle_forbidden(error):
        return jsonify({"error": str(error)}), 403
    
    @app.errorhandler(ConflictError)
    def handle_conflict(error):
        return jsonify({"error": str(error)}), 409
    
    @app.errorhandler(UserNotFound)
    def handle_not_found(error):
        return jsonify({"error": str(error)}), 404
    
    # ─── Authentication Decorator ──────────────────────────────────
    
    def require_auth(f):
        """Require Bearer token authentication."""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing or invalid Authorization header"}), 401
            
            token = auth_header[7:]  # Remove "Bearer " prefix
            user_id = auth.verify_token(token, app.config["DB_PATH"])
            if not user_id:
                return jsonify({"error": "Invalid or expired token"}), 401
            
            # Store user_id in request context
            request.user_id = user_id
            return f(*args, **kwargs)
        return decorated
    
    # ─── Routes: Health ────────────────────────────────────────────
    
    @app.route("/api/v1/health", methods=["GET"])
    def health():
        """Health check endpoint."""
        uptime = (datetime.utcnow() - app.config["START_TIME"]).total_seconds()
        return jsonify({
            "status": "ok",
            "version": config.SERVER_VERSION,
            "min_protocol_version": config.MIN_PROTOCOL_VERSION,
            "uptime_seconds": uptime,
        }), 200
    
    # ─── Routes: Registration ──────────────────────────────────────
    
    @app.route("/api/v1/register", methods=["POST"])
    def register():
        """Register a new user (system or friend)."""
        data = request.get_json() or {}
        
        # Validate protocol version
        client_protocol = data.get("protocol_version", 0)
        if client_protocol < config.MIN_PROTOCOL_VERSION:
            raise InvalidProtocolVersion(
                f"Client protocol {client_protocol} < server minimum {config.MIN_PROTOCOL_VERSION}"
            )
        
        user = {
            "public_signing_key": data.get("public_signing_key"),
            "public_exchange_key": data.get("public_exchange_key"),
            "handle": data.get("handle"),
            "client_type": data.get("client_type", "friend"),  # 'system' or 'friend'
            "protocol_version": client_protocol,
            "feature_set": data.get("feature_set", []),
        }
        
        user_id = db.register_user(app.config["DB_PATH"], user)
        
        return jsonify({
            "user_id": user_id,
            "server_min_version": config.MIN_PROTOCOL_VERSION,
        }), 201
    
    # ─── Routes: Authentication ────────────────────────────────────
    
    @app.route("/api/v1/auth/challenge", methods=["POST"])
    def auth_challenge():
        """Get a challenge nonce for authentication."""
        data = request.get_json() or {}
        user_id = data.get("user_id")
        
        nonce = auth.create_challenge(app.config["DB_PATH"], user_id)
        return jsonify({"nonce": nonce}), 200
    
    @app.route("/api/v1/auth/token", methods=["POST"])
    def auth_token():
        """Exchange signed nonce for authentication token."""
        data = request.get_json() or {}
        user_id = data.get("user_id")
        nonce = data.get("nonce")
        signature = data.get("signature")  # base64-encoded
        
        token = auth.verify_challenge(
            app.config["DB_PATH"], user_id, nonce, signature
        )
        
        return jsonify({"token": token}), 200
    
    # ─── Routes: Volumes ──────────────────────────────────────────
    
    @app.route("/api/v1/volumes/<volume_name>", methods=["PUT"])
    @require_auth
    def upload_volume(volume_name):
        """Upload an encrypted volume."""
        data = request.get_json() or {}
        
        control_header = data.get("control_header", {})
        encrypted_payload = data.get("encrypted_payload")
        signature = data.get("signature")
        
        volumes.upload_volume(
            app.config["DB_PATH"],
            app.config["VOLUME_PATH"],
            request.user_id,
            volume_name,
            control_header,
            encrypted_payload,
            signature,
        )
        
        return jsonify({"status": "uploaded"}), 200
    
    @app.route("/api/v1/volumes", methods=["GET"])
    @require_auth
    def list_volumes():
        """List all volumes for the authenticated user."""
        vols = volumes.list_user_volumes(app.config["DB_PATH"], request.user_id)
        return jsonify({"volumes": vols}), 200
    
    # ─── Routes: Discovery ────────────────────────────────────────
    
    @app.route("/api/v1/discover", methods=["GET"])
    @require_auth
    def discover():
        """Discover users by handle prefix."""
        handle_prefix = request.args.get("handle", "")
        results = discovery.search_by_handle(
            app.config["DB_PATH"],
            handle_prefix,
            request.user_id
        )
        return jsonify({"results": results}), 200
    
    # ─── Routes: Sharing ──────────────────────────────────────────
    
    @app.route("/api/v1/sharing/request", methods=["POST"])
    @require_auth
    def create_sharing_request():
        """Create a sharing request (friend → system)."""
        data = request.get_json() or {}
        from_user_id = data.get("from_user_id")
        to_user_id = data.get("to_user_id")
        
        share_id = sharing.create_sharing_request(
            app.config["DB_PATH"],
            from_user_id,
            to_user_id,
        )
        
        share_obj = sharing.get_sharing_request(app.config["DB_PATH"], share_id)
        return jsonify(share_obj), 201
    
    @app.route("/api/v1/sharing/requests", methods=["GET"])
    @require_auth
    def list_sharing_requests():
        """List sharing requests for the user."""
        status = request.args.get("status", None)  # 'pending', 'active', None for all
        requests = sharing.list_user_sharing_requests(
            app.config["DB_PATH"],
            request.user_id,
            status
        )
        return jsonify({"requests": requests}), 200
    
    @app.route("/api/v1/sharing/respond", methods=["POST"])
    @require_auth
    def respond_sharing_request():
        """Accept or reject a sharing request."""
        data = request.get_json() or {}
        request_id = data.get("request_id")
        accepted = data.get("accepted", False)
        encrypted_vek_blob = data.get("encrypted_vek_blob")
        permissions = data.get("permissions", {})
        
        sharing.respond_sharing_request(
            app.config["DB_PATH"],
            request_id,
            request.user_id,
            accepted,
            encrypted_vek_blob,
            permissions,
        )
        
        share_obj = sharing.get_sharing_request(app.config["DB_PATH"], request_id)
        return jsonify(share_obj), 200
    
    @app.route("/api/v1/sharing/<sharing_id>/permissions", methods=["PATCH"])
    @require_auth
    def update_sharing_permissions(sharing_id):
        """Update permissions for an active sharing."""
        data = request.get_json() or {}
        permissions = data.get("permissions", {})
        
        sharing.update_sharing_permissions(
            app.config["DB_PATH"],
            sharing_id,
            request.user_id,
            permissions,
        )
        
        share_obj = sharing.get_sharing_request(app.config["DB_PATH"], sharing_id)
        return jsonify(share_obj), 200
    
    @app.route("/api/v1/sharing/<sharing_id>", methods=["DELETE"])
    @require_auth
    def revoke_sharing(sharing_id):
        """Revoke a sharing relationship."""
        sharing.revoke_sharing(app.config["DB_PATH"], sharing_id, request.user_id)
        return "", 204
    
    @app.route("/api/v1/sharing/invite", methods=["POST"])
    @require_auth
    def create_invite_code():
        """Generate an invite code for sharing."""
        code = sharing.create_invite_code(
            app.config["DB_PATH"],
            request.user_id,
        )
        return jsonify({"code": code}), 201
    
    @app.route("/api/v1/sharing/redeem", methods=["POST"])
    @require_auth
    def redeem_invite_code():
        """Redeem an invite code to start sharing."""
        data = request.get_json() or {}
        code = data.get("code")
        
        share_id = sharing.redeem_invite_code(
            app.config["DB_PATH"],
            code,
            request.user_id,
        )
        
        share_obj = sharing.get_sharing_request(app.config["DB_PATH"], share_id)
        return jsonify(share_obj), 201
    
    # ─── Routes: Shared Volumes ────────────────────────────────────
    
    @app.route("/api/v1/shared/<system_user_id>/volumes", methods=["GET"])
    @require_auth
    def list_shared_volumes(system_user_id):
        """List volumes shared by a system user to the authenticated friend."""
        vols = volumes.list_shared_volumes(
            app.config["DB_PATH"],
            system_user_id,
            request.user_id,
        )
        return jsonify({"volumes": vols}), 200
    
    @app.route("/api/v1/shared/<system_user_id>/volumes/<volume_name>", methods=["GET"])
    @require_auth
    def get_shared_volume(system_user_id, volume_name):
        """Download a shared volume with optional conditional GET support."""
        etag = request.args.get("If-None-Match")
        
        data = volumes.get_shared_volume(
            app.config["DB_PATH"],
            app.config["VOLUME_PATH"],
            system_user_id,
            request.user_id,
            volume_name,
            etag,
        )
        
        if data is None:
            # Not modified
            return "", 304
        
        return jsonify(data), 200
    
    # ─── Routes: Account Management ────────────────────────────────
    
    @app.route("/api/v1/users/me", methods=["DELETE"])
    @require_auth
    def delete_account():
        """Delete the authenticated user's account and all associated data."""
        db.delete_user(app.config["DB_PATH"], request.user_id)
        volumes.delete_user_volumes(app.config["VOLUME_PATH"], request.user_id)
        return "", 204
    
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=False, host="0.0.0.0", port=5000)
