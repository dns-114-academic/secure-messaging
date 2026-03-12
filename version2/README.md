# Secure Messaging v2 — Advanced

End-to-end encrypted chat with **AES-128-GCM** (authenticated encryption), **RSA-PSS message signatures**, multi-session support, server-side audit log, and a modern dark-mode UI.

> This is the advanced version. For the baseline, see `../version1/`.

---

## Directory tree

```
version2/
├── server.py        # Key distribution server — signatures, audit log, idempotent sessions
├── client.py        # Chat client — AES-GCM, RSA-PSS sign/verify, multi-session
├── index_v2.html    # Dark-mode browser UI — sig badges, timestamps, status panel
├── report.tex       # LaTeX report source
├── report.pdf       # Compiled PDF report
└── README.md
```

---

## What's new vs v1

| Feature | v1 | v2 |
|---|---|---|
| Symmetric cipher | AES-128-CBC | **AES-128-GCM** (authenticated) |
| Message integrity | ✗ none | ✓ 128-bit GCM tag |
| Message signatures | ✗ none | ✓ RSA-PSS / SHA-256 |
| Session-request auth | ✗ none | ✓ RSA-PSS proof-of-identity |
| Multi-session | ✗ global key | ✓ per-peer key dict |
| Idempotent sessions | ✗ | ✓ HTTP 409 + `/session/reset` |
| Structured payloads | plain strings | JSON with timestamp + signature |
| Audit log | ✗ | ✓ `GET /audit` on server |
| Proper HTTP codes | 200 for errors | 400 / 403 / 404 / 409 |
| UI | Basic light | Dark theme + sig badges + status |

---

## Implemented components

| Component | File | Description |
|---|---|---|
| Key server | `server.py` | RSA-OAEP key wrap, PSS sig verification, session registry |
| `POST /session` | `server.py` | Verifies initiator identity before issuing AES key |
| `GET /audit` | `server.py` | Returns timestamped cryptographic event log |
| `GET /users` | `server.py` | Lists all registered clients |
| `POST /session/reset` | `server.py` | Force-deletes an active session |
| AES-GCM helpers | `client.py` | `encrypt_gcm` / `decrypt_gcm` — nonce+tag+ct blob |
| RSA-PSS helpers | `client.py` | `sign_message` / `verify_signature` |
| Multi-session store | `client.py` | `session_keys` dict keyed by peer username |
| `GET /status` | `client.py` | Exposes active sessions and message counts |
| `POST /reset_session` | `client.py` | Clears local AES key for a peer |
| Dark-mode UI | `index_v2.html` | Sig verification badges, timestamps, encryption panel |

---

## Requirements

- Python 3.8+

```bash
pip install flask pycryptodome requests
```

---

## How to run

```bash
# Terminal 1 — key server
python server.py

# Terminal 2 — Alice
python client.py 5001 Alice

# Terminal 3 — Bob
python client.py 5002 Bob
```

Open two browser tabs:
- Alice → http://127.0.0.1:5001
- Bob   → http://127.0.0.1:5002

### Useful endpoints to inspect

```bash
# Server audit log
curl http://127.0.0.1:5000/audit

# Registered users
curl http://127.0.0.1:5000/users

# Alice session state
curl http://127.0.0.1:5001/status

# Alice full message history
curl http://127.0.0.1:5001/messages

# Reset session between Alice and Bob
curl -X POST http://127.0.0.1:5001/reset_session \
     -H "Content-Type: application/json" \
     -d '{"peer": "Bob"}'
```

---

## Key design notes

Version 2 addresses the three main weaknesses of v1. First, replacing AES-CBC with AES-GCM eliminates the need for a separate MAC: the GCM authentication tag is computed atomically with encryption, and any tampering with the ciphertext causes `decrypt_and_verify` to raise before any plaintext is released. Second, RSA-PSS signatures on every message ensure non-repudiation — a compromised relay cannot forge messages that pass signature verification. Third, the server now validates the initiator's identity before issuing session keys by requiring a signed proof-of-possession of the private key, preventing a malicious third party from triggering key generation in someone else's name. The remaining trust assumption is that the key server sees the AES key in cleartext at generation time; eliminating this would require a Diffie–Hellman or ECDH exchange instead.

---

## References

- NIST SP 800-38D (AES-GCM): https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- RSA-PSS — RFC 8017: https://datatracker.ietf.org/doc/html/rfc8017
- PyCryptodome: https://pycryptodome.readthedocs.io
- Flask: https://flask.palletsprojects.com
