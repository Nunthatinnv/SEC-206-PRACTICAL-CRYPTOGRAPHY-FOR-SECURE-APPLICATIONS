# Assignment 2 - Database Encryption (App Layer)

## Overview
The goal of A2 is to protect message bodies at rest. In this app, messages are stored in SQLite on both the clients and the server, so A2 adds encryption in the application before those values reach the database.

The server temporarily stores incoming messages in its `inbox` table until the recipient pulls them, and each client stores its own local message history in its `messages` table. A2 protects the `body` values in those tables without changing the visible chat flow.

At a high level, A2 works like this:
1. store key-derivation metadata such as a salt and KDF parameters
2. combine that metadata with a password to derive a storage key
3. use that derived key to encrypt and decrypt stored message bodies

In the scaffold, the crypto side of A2 is centered around `StorageCipher` in `shared/storage_crypto.py`. The runtime already uses that object. Your job is to replace the placeholder behavior with real key derivation and authenticated encryption, and to decide what storage context should be authenticated at the client and server storage boundaries.

Reality caveat:
- This scaffold uses a simplified model where the storage key is derived directly from a password.
- Production systems usually separate KEKs and DEKs and support wrapping and rotation.

## Flow
The client side:
1. after login, the client asks the user to unlock the local database at `/unlock`
2. the client loads or creates a `user_key_meta` row
3. the client combines the unlock password with that metadata to derive a storage key
4. that derived key is kept in Flask session and used to rebuild a `StorageCipher` when local message bodies need to be encrypted or decrypted
5. local message bodies are stored in `messages.body` as JSON envelopes

The server side:
1. the server loads or creates `server_key_meta`
2. the server derives one storage key from `SERVER_DB_PASSWORD` (an environment variable; this is automatically handled by the run script)
3. the server uses a `StorageCipher` to protect `inbox.body`

Body message authentication is an important part of A2. Encrypting a message body is not enough on its own, because an attacker who can modify stored rows might copy a ciphertext into the wrong place and still get it decrypted later. To prevent that, the ciphertext should be authenticated together with the context that gives the row its meaning.

In practice, this means the client and server storage boundaries should pass an `aad_obj` that says what this body belongs to. That context should be strong enough to prevent row-swap or mix-up attacks, where a body encrypted for one message is accepted as if it belonged to a different message, direction, peer, sender, or recipient. Think about what identifies the meaning of the row at each storage boundary: which table and column the body belongs to, and what other metadata distinguishes one stored message from another. The same context must be reconstructed on both encryption and decryption, or verification should fail.

## TODOs
Implement in these places.

### `shared/storage_crypto.py`
1. `create_key_meta()`
   - return the metadata needed to derive the same key again later
   - keep the existing row shape:
     - `version`
     - `kdf`
     - `kdf_params`
     - `salt_b64`
     - `key_version`
   - in this scaffold, keep `key_version` fixed at `1`; key rotation is out of scope

2. `StorageCipher.from_password(password, key_meta)`
   - derive a 256-bit key from the password and metadata
   - return a `StorageCipher` that holds that derived key

3. `StorageCipher.encrypt_body(plaintext, aad_obj)`
   - encrypt the message body into a structured envelope
   - authenticate the caller-provided storage context
   - keep the current envelope shape:
     - `version`
     - `alg`
     - `key_version`
     - `nonce_b64`
     - `ct_b64`
     - `tag_b64`
     - `aad`

4. `StorageCipher.decrypt_body(envelope, aad_obj)`
   - verify and decrypt the envelope using the same caller-provided storage context
   - authenticate the reconstructed `aad_obj`, not whatever happens to be stored in `envelope["aad"]`
   - fail closed on bad key, bad ciphertext, or mismatched AAD

### `client_app/core.py`
5. In `_encrypt_local_body(...)` and `_decrypt_local_body(...)`, decide what local row context should be authenticated for stored message bodies, then pass that context into `StorageCipher.encrypt_body(...)` and `StorageCipher.decrypt_body(...)`.

### `server_app/message_service.py`
6. In `handle_send(...)` and `handle_pull(...)`, decide what inbox row context should be authenticated for stored message bodies, then pass that context into `StorageCipher.encrypt_body(...)` and `StorageCipher.decrypt_body(...)`.

## Files To Focus On
1. `shared/storage_crypto.py`
   - this is where the A2 crypto object lives
2. `client_app/core.py`
   - this is where the client chooses what local storage context to bind
3. `server_app/message_service.py`
   - this is where the server chooses what inbox storage context to bind

## What To Observe
Before you implement A2:
1. the app already runs and chat works
2. body fields are stored as structured envelopes, but the placeholder scaffold still reveals plaintext through reversible encoding
3. the debug pages already show the final metadata and envelope shapes

After you implement A2:
1. chat behavior should still work the same
2. `messages.body` and `inbox.body` should no longer reveal plaintext
3. wrong password, tampered ciphertext, or mismatched AAD should fail closed

## How To Debug
Client debug page:
1. `messages` shows locally stored message bodies
2. `user_key_meta` shows the metadata used to derive the client storage key

Server debug page:
1. `inbox` shows messages waiting to be pulled
2. `server_key_meta` shows the metadata used to derive the server storage key

What to expect:
1. before A2, stored bodies are still envelopes with visible placeholder ciphertext
2. after A2, the row shape should stay the same, but the body contents should no longer reveal plaintext
3. the app should still send, pull, and display messages normally

## Hints
- Use base64 for binary values that need to go into JSON, such as salts, nonces, ciphertexts, tags, and derived keys.
- If you use Argon2id, a reasonable starting point for this scaffold is:
  - `t = 3`
  - `m = 65536`
  - `p = 1`
  - output length `= 32`

## How To Run
```bash
uv run python scripts/reset_state.py
uv run python scripts/run_all.py
```

Useful pages:
- Alice: `http://127.0.0.1:5001`
- Bob: `http://127.0.0.1:5002`
- Server debug: `http://127.0.0.1:5000/debug`
