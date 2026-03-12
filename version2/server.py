# TP02 v2 — Secure Messaging Server (Advanced)
#
# Improvements over v1:
#   - RSA signature verification on every session request
#   - Per-pair session ID tracking (prevents duplicate AES key generation)
#   - Timestamped structured logging
#   - /users endpoint: list all registered clients
#   - /session_info endpoint: query existing session metadata
#   - Graceful error codes (HTTP 400 / 404 / 409)
#   - In-memory audit log of all session events

from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import uuid
import datetime
import logging

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)

app = Flask(__name__)

# ── In-memory stores ───────────────────────────────────────────────────────────
clients_db  = {}   # { username: { "public_key": str, "registered_at": str } }
sessions_db = {}   # { session_id: { "initiator", "target", "created_at" } }
audit_log   = []   # list of event dicts


def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"


def _audit(event: str, **kwargs):
    entry = {"event": event, "timestamp": _now(), **kwargs}
    audit_log.append(entry)
    log.info("%s %s", event, kwargs)


# ── Health check ───────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return jsonify({
        "status": "ok",
        "registered_clients": len(clients_db),
        "active_sessions": len(sessions_db),
        "server_time": _now()
    })


# ── Register ───────────────────────────────────────────────────────────────────
@app.route('/register', methods=['POST'])
def register():
    """Register a client username + RSA-2048 public key.
    Re-registration is allowed (key rotation).
    """
    data     = request.json or {}
    username = data.get('username', '').strip()
    pub_key  = data.get('public_key', '').strip()

    if not username or not pub_key:
        return jsonify({"status": "error", "message": "Missing username or public_key"}), 400

    # Validate the key is parseable RSA
    try:
        RSA.import_key(pub_key)
    except (ValueError, TypeError) as exc:
        return jsonify({"status": "error", "message": f"Invalid RSA public key: {exc}"}), 400

    already_registered = username in clients_db
    clients_db[username] = {"public_key": pub_key, "registered_at": _now()}
    _audit("REGISTER", username=username, rotation=already_registered)

    return jsonify({
        "status": "success",
        "message": f"{'Key rotated' if already_registered else 'Registered'}: {username}",
        "registered_at": clients_db[username]["registered_at"]
    })


# ── List users ─────────────────────────────────────────────────────────────────
@app.route('/users', methods=['GET'])
def list_users():
    """Return all registered usernames and their registration timestamps."""
    return jsonify({
        "users": [
            {"username": u, "registered_at": v["registered_at"]}
            for u, v in clients_db.items()
        ]
    })


# ── Create session ─────────────────────────────────────────────────────────────
@app.route('/session', methods=['POST'])
def create_session():
    """Generate a unique AES-128 session key and return it encrypted for both parties.

    Request body (JSON):
        from        (str)  initiator username
        to          (str)  target username
        signature   (str)  base64 PSS-SHA256 signature of "from:to" signed by initiator

    The server verifies the signature to confirm the initiator owns their private key.
    If a session between the same pair already exists its ID is returned without
    generating a new key (idempotent — prevents key duplication).
    """
    data      = data = request.json or {}
    initiator = data.get('from', '').strip()
    target    = data.get('to', '').strip()
    sig_b64   = data.get('signature', '')

    # ── Validate both users exist ──────────────────────────────────────────────
    missing = [u for u in (initiator, target) if u not in clients_db]
    if missing:
        return jsonify({"status": "error", "message": f"Unknown client(s): {missing}"}), 404

    if initiator == target:
        return jsonify({"status": "error", "message": "Cannot open a session with yourself"}), 400

    # ── Verify initiator's signature ───────────────────────────────────────────
    if sig_b64:
        try:
            init_pub_key = RSA.import_key(clients_db[initiator]["public_key"])
            verifier     = pss.new(init_pub_key)
            h            = SHA256.new((f"{initiator}:{target}").encode())
            verifier.verify(h, base64.b64decode(sig_b64))
            sig_valid = True
            _audit("SIGNATURE_OK", initiator=initiator, target=target)
        except Exception as exc:
            _audit("SIGNATURE_FAIL", initiator=initiator, target=target, reason=str(exc))
            return jsonify({"status": "error", "message": "Invalid signature"}), 403
    else:
        # Signature is optional for backward compatibility with v1 clients
        sig_valid = False
        _audit("SIGNATURE_SKIPPED", initiator=initiator, target=target)

    # ── Idempotency: reuse existing session if present ─────────────────────────
    pair_key = tuple(sorted([initiator, target]))
    existing = next(
        (sid for sid, s in sessions_db.items()
         if tuple(sorted([s["initiator"], s["target"]])) == pair_key),
        None
    )
    if existing:
        _audit("SESSION_REUSE", session_id=existing, initiator=initiator, target=target)
        # We cannot return the AES key again (it is not stored), so instruct client to re-init
        return jsonify({
            "status": "exists",
            "session_id": existing,
            "message": "Session already active. Use /session/reset to force a new one."
        }), 409

    # ── Generate AES-128 session key ───────────────────────────────────────────
    session_key = get_random_bytes(16)
    session_id  = str(uuid.uuid4())

    # Encrypt for initiator
    cipher_init = PKCS1_OAEP.new(RSA.import_key(clients_db[initiator]["public_key"]))
    enc_init    = cipher_init.encrypt(session_key)

    # Encrypt for target
    cipher_tgt  = PKCS1_OAEP.new(RSA.import_key(clients_db[target]["public_key"]))
    enc_target  = cipher_tgt.encrypt(session_key)

    sessions_db[session_id] = {
        "initiator":  initiator,
        "target":     target,
        "created_at": _now(),
        "signed":     sig_valid
    }
    _audit("SESSION_CREATED", session_id=session_id, initiator=initiator, target=target)

    return jsonify({
        "status": "success",
        "session_id":                  session_id,
        "created_at":                  sessions_db[session_id]["created_at"],
        "session_key_initiator_b64":   base64.b64encode(enc_init).decode(),
        "session_key_target_b64":      base64.b64encode(enc_target).decode(),
        "signature_verified":          sig_valid
    })


# ── Reset session ──────────────────────────────────────────────────────────────
@app.route('/session/reset', methods=['POST'])
def reset_session():
    """Force-delete an existing session between two users so a new one can be created."""
    data      = request.json or {}
    initiator = data.get('from', '').strip()
    target    = data.get('to', '').strip()

    pair_key = tuple(sorted([initiator, target]))
    to_delete = [
        sid for sid, s in sessions_db.items()
        if tuple(sorted([s["initiator"], s["target"]])) == pair_key
    ]
    for sid in to_delete:
        del sessions_db[sid]
        _audit("SESSION_RESET", session_id=sid, initiator=initiator, target=target)

    return jsonify({"status": "success", "deleted_sessions": len(to_delete)})


# ── Session info ───────────────────────────────────────────────────────────────
@app.route('/session_info/<session_id>', methods=['GET'])
def session_info(session_id):
    """Return metadata about a session (no key material)."""
    s = sessions_db.get(session_id)
    if not s:
        return jsonify({"status": "error", "message": "Session not found"}), 404
    return jsonify({"session_id": session_id, **s})


# ── Audit log ──────────────────────────────────────────────────────────────────
@app.route('/audit', methods=['GET'])
def get_audit():
    """Return the server-side audit log."""
    return jsonify({"events": audit_log})


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    log.info("Starting key distribution server on port 5000")
    app.run(port=5000, debug=True)
