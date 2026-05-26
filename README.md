# PluralLog Relay Server

A secure, privacy-preserving relay server for [PluralLog](https://plurallog.app/), a journal app for plural systems (people with Dissociative Identity Disorder, OSDD, and other plural experiences).

## Features

- **End-to-end encryption**: All data is encrypted on the client side; the server never has access to plaintext
- **Ed25519 signatures**: Cryptographic verification of all uploads
- **Homomorphic encryption**: Optional analytics sharing without decryption (Paillier cryptosystem)
- **Fine-grained permissions**: Friends can request limited access to specific data volumes
- **User discovery**: Safe discovery mechanism that prevents same-type users from finding each other
- **Invite codes**: One-time use codes for secure sharing initiation
- **Account deletion**: Full data deletion on user request

## API Overview

### Authentication

```
POST /api/v1/auth/challenge
POST /api/v1/auth/token
```

Challenge-response authentication using Ed25519 signatures.

### User Registration

```
POST /api/v1/register
```

Register a new system or friend user.

### Volume Management

```
PUT /api/v1/volumes/<name>
GET /api/v1/volumes
```

Upload and list encrypted volumes.

### Sharing

```
POST /api/v1/sharing/request
GET /api/v1/sharing/requests
POST /api/v1/sharing/respond
PATCH /api/v1/sharing/<id>/permissions
DELETE /api/v1/sharing/<id>
```

Manage sharing relationships with fine-grained permissions.

### Invite Codes

```
POST /api/v1/sharing/invite
POST /api/v1/sharing/redeem
```

Generate and redeem one-time invite codes.

### Shared Access

```
GET /api/v1/shared/<user_id>/volumes
GET /api/v1/shared/<user_id>/volumes/<name>
```

Access volumes shared by another user.

### Account

```
DELETE /api/v1/users/me
```

Delete your account and all data.

## Installation

```bash
pip install -r requirements.txt
```

## Running

### Development

```bash
python -m plurallog_relay.app
```

### Production

```bash
gunicorn -w 4 -b 0.0.0.0:5000 plurallog_relay.app:create_app()
```

## Testing

```bash
python -m pytest heart
```

See `heart` for comprehensive integration tests covering all API endpoints.

## Architecture

- **app.py**: Flask application factory and route definitions
- **db.py**: SQLite database initialization and user management
- **auth.py**: Challenge-response authentication with Ed25519
- **volumes.py**: Encrypted volume storage and retrieval
- **sharing.py**: Sharing relationship and permission management
- **discovery.py**: User discovery with privacy enforcement
- **permissions.py**: Permission-to-volume mapping
- **errors.py**: Custom exception classes
- **config.py**: Configuration constants

## Security Considerations

1. **The server is cryptographically blind**: All data is encrypted client-side. The server cannot decrypt or inspect the contents.
2. **Signatures prevent tampering**: All uploads are verified using Ed25519 signatures.
3. **Permissions are enforced server-side**: Friends cannot download volumes beyond their permissions, regardless of client-side behavior.
4. **One-time invite codes**: Prevent replay attacks when initiating sharing.
5. **Soft deletion**: User accounts are soft-deleted to maintain referential integrity.

## Database

SQLite is used for development and small deployments. For larger deployments, PostgreSQL is recommended.

## License

MIT
