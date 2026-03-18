# Assignment 3 - Secure Channel Between Client and Server

## Overview
The goal of this assignment is to build a secure channel between the client and the server so that sensitive data is protected while it is in transit.

Conceptually, this channel should do two jobs: establish a fresh shared session between the client and server, then use that session to protect later requests and responses.

In this scaffold, the secure channel already sits underneath the app flow. The client opens the channel first, login then travels through that channel, and later send and pull requests also travel through that channel.

So the high-level story of A3 is:
1. build the handshake
2. derive shared session state
3. protect all later channel records

For A3, you should only edit `shared/channel_crypto.py`.
The rest of the scaffold already imports and uses the A3 protocol objects for you. You do not need to switch callsites or redesign the runtime flow.

Right now, the default A3 code is still placeholder code. The final object structure is already in place, but the handshake still uses placeholder values, the derived channel session still uses empty keys, and records still carry plaintext `payload_obj`, even though metadata checks already enforce session id, direction, counter, and route context.

Your job is to replace those placeholders with real secure-channel cryptography while keeping the visible app behavior unchanged.

Reality caveat:
1. this scaffold uses a simplified fixed protocol shape
2. in practice, a mature protocol such as TLS would normally be used instead of designing a custom secure channel like this
3. in a real TLS-protected protocol, request details such as `/api/login` would normally be hidden inside the protected channel; this scaffold keeps the route context visible for simplicity and debugging

## Stage 1 - Handshake and Session Setup
### Protocol Description
The purpose of this stage is to let the client and server establish a fresh shared session and let the client decide whether it trusts the server before using that session.

At the protocol level, the flow is:
1. the client creates fresh local handshake state and sends a `ClientHello`
2. the server creates its own local handshake state, checks the incoming `ClientHello`, and sends back a `ServerHello`
3. the client verifies the `ServerHello` and both sides derive the session state that later records will use

That means you should distinguish between:
1. local secret state, which stays inside the handshake object
2. public hello fields, which go on the wire

The `ClientHello` should carry enough information for freshness and key agreement, such as:
1. protocol version
2. client ephemeral public key
3. client nonce
4. client timestamp

The `ServerHello` should carry:
1. protocol version
2. server ephemeral public key
3. server nonce
4. session id
5. server timestamp
6. session expiry
7. server authentication material, such as an ECDSA signature over the expected hello transcript

Serialization convention:
1. any field ending in `_b64` should be treated as raw bytes encoded as base64 text for JSON transport
2. ordinary metadata such as `proto`, `ts`, `expires_at`, `counter`, `dir`, and `path` should stay as normal JSON strings or integers

Once the client accepts that `ServerHello`, both sides should derive the same session state from the handshake data. In this scaffold, that session state should contain:
1. `session_id_b64`
2. one key for client-to-server records
3. one key for server-to-client records
4. expiry information

The runtime already tracks record counters separately, so this stage is about producing the cryptographic session material that later record protection will use.

### API In This Scaffold
In code, the handshake is represented by two objects:
1. `ClientHandshake`
2. `ServerHandshake`

The intended split of responsibility is:
1. `init(...)` creates the local handshake state
2. `create_hello()` turns only the public part of that state into the wire message
3. `respond_to_client_hello(...)` lets the server validate the incoming client hello and prepare a server hello from its local handshake state
4. `verify_server_hello(...)` checks what came back from the server
5. the higher-level methods combine those smaller steps so the rest of the scaffold does not need to orchestrate the handshake manually

The scaffold already uses them in this order:
1. `ClientHandshake.init()`
2. `ClientHandshake.create_hello()`
3. `ServerHandshake.init()`
4. `ServerHandshake.handle_client_hello(client_hello)`
5. `ClientHandshake.accept_server_hello(server_hello)`

Inside `shared/channel_crypto.py`, those higher-level methods call the smaller handshake helpers for you:
1. `ServerHandshake.handle_client_hello(...)` calls `respond_to_client_hello(...)` and `finalize(client_hello)`
2. `ClientHandshake.accept_server_hello(...)` calls `verify_server_hello(...)` and `finalize(...)`

Those handshake steps happen in the channel layer before login happens.

The resulting `ChannelSessionState` is copied into the runtime channel state shape and then used by later record protection calls.

One important scaffold detail:
1. the server's private signing key lives under `server_app/dev_keys/`
2. the client's pinned copy of the matching public key lives under `client_app/pinned_keys/`
3. the checked-in demo signing key pair is a NIST P-256 key pair for server authentication
4. your client and server ephemeral handshake keys should also use `P-256`
5. any public/private key bytes that go into the scaffold's `*_b64` fields should be serialized as DER bytes and then base64-encoded for JSON transport
6. the final version of `ClientHandshake.verify_server_hello(...)` should use the pinned public key to verify the server's authentication material

### TODOs
Implement in `shared/channel_crypto.py`:
1. `ClientHandshake.init()`
   - generate and store the client's local handshake state
2. `ClientHandshake.create_hello()`
   - serialize only the public hello fields from that stored state
3. `ServerHandshake.init()`
   - generate and store the server's local handshake state
4. `ServerHandshake.respond_to_client_hello(...)`
   - validate the incoming client hello and return the public server hello fields from that stored state
5. `ClientHandshake.verify_server_hello(...)`
   - check that the returned server hello is valid before accepting the session
6. `ClientHandshake.finalize(...)`
   - derive the client-side channel session state
7. `ServerHandshake.finalize(client_hello)`
   - derive the server-side channel session state from the server's local state and the provided client hello

You do not need to change the higher-level runtime flow:
1. `ServerHandshake.handle_client_hello(...)`
2. `ClientHandshake.accept_server_hello(...)`

Those methods already call your Stage 1 helper methods.

What changes after this stage:
1. the hello messages should contain real handshake material instead of empty placeholders
2. the client should reject invalid or unauthenticated server hello messages
3. both sides should derive matching session keys instead of using empty placeholders
4. later record protection should have real session keys to use

### Debug This Stage
Look at both sides after opening the channel:

Client debug page:
1. check the first network entry for `/api/channel/open`
2. the `client_hello` and `server_hello` should now show real handshake fields instead of only empty placeholders
3. inspect `A3: Raw Session Channel State`
4. confirm the channel state no longer shows empty placeholder keys once your derivation is implemented
5. use `A3: Network Log` to inspect the raw `/api/channel/open` request and response

Server debug page:
1. inspect `channel_sessions`
2. check `client_hello_json` and `server_hello_json`
3. confirm the hello messages have the field values you expect for this stage
4. confirm the stored session fields match the session you expect from the handshake

## Stage 2 - Protected Records
### Protocol Description
After the handshake, every application request and response should travel as a protected record.

At the protocol level, a protected record has two parts:
1. the payload, which is encrypted
2. the context, which is authenticated along with the payload

The payload is the actual application data for this request or response. In this scaffold, that can include:
1. login data such as `username` and `password`
2. message API data such as `token`, `to`, `body`, and `msg_id`
3. pull responses such as the returned `messages`

That data should go inside the encrypted payload because it is sensitive and should not be exposed on the wire.

The context is the metadata that tells both sides how to interpret the record. In an AEAD design, this is what should go into AAD. In this scaffold, that context should include:
1. `session_id_b64`
   - so a record is bound to one session and cannot be replayed into another one
2. `direction`
   - so a client-to-server record cannot be accepted as a server-to-client record, or vice versa
3. `counter`
   - so records are bound to their expected sequence number and replayed or reordered records fail
4. `path`
   - so a record for `/api/login` cannot be replayed to `/api/messages/pull`

The important idea is that this context usually does not need confidentiality, but it does need integrity. That is why it belongs in AAD: both sides should detect if any of it has been changed.

In this scaffold, the request path such as `/api/login` or `/api/messages/pull` is still visible outside the protected payload. Your record format should still authenticate that path as part of the record context, even though it is not encrypted.

### API In This Scaffold
In code, record protection lives in `ChannelCipher`.

The scaffold creates a `ChannelCipher` object with the session key and `session_id_b64`, then uses that object for later channel traffic:
1. `cipher.encrypt_record(...)`
2. `cipher.decrypt_record(...)`

They are used for:
1. login through `/api/login`
2. send through `/api/messages/send`
3. pull through `/api/messages/pull`

In the function signatures, that route context is passed as the `path` parameter. The placeholder record stores it in the `path` field, and the secure version should bind that same path into the authenticated record context.

The placeholder code currently stores these context fields directly in the record so you can see them in the debug views. In the secure version, those same values should still be checked, but they should be authenticated through AAD rather than trusted as unauthenticated plaintext metadata.

The final protected record should keep the outer metadata fields:
1. `proto`
2. `session_id_b64`
3. `dir`
4. `counter`
5. `path`

but replace plaintext `payload_obj` with encrypted-record fields such as:
1. `nonce_b64`
2. `ct_b64`
3. `tag_b64`

So once these two methods are secure, the whole post-handshake channel becomes secure.

### TODOs
Implement in `shared/channel_crypto.py`:
1. `ChannelCipher.encrypt_record(...)`
2. `ChannelCipher.decrypt_record(...)`

What changes after this stage:
1. login credentials should no longer appear in plaintext on the wire
2. bearer tokens should no longer appear in plaintext on the wire
3. tampered records or mismatched context should fail closed
4. the first valid record counter is `0`, so your counter checks should treat `0` as a real value, not as “missing”

### Debug This Stage
Inspect the raw request and response records after login, send, and pull:

Client debug page:
1. the first protected record after channel open should be the login record
2. after your implementation, `payload_obj` should no longer reveal plaintext secrets
3. later send and pull records should also be protected

Server debug page:
1. confirm the session still advances counters correctly while handling protected traffic
2. compare the network records with the stored session row when debugging counter or context failures

## Files To Focus On
Required:
1. `shared/channel_crypto.py`

Optional context:
1. `client_app/channel.py`
2. `server_app/channel.py`

You should be able to complete A3 by editing `shared/channel_crypto.py` only.

## What To Observe
Before A3 is completed:
1. the app already runs and chat works
2. login, send, and pull all go through channel record wrappers
3. the network log still shows plaintext `payload_obj`, including login data and bearer tokens

After A3 is completed:
1. chat behavior should still work the same
2. login credentials and later channel records should be cryptographically protected
3. invalid handshake data, tampered records, or wrong counters should fail closed

## General Debugging Notes
Client debug page:
1. `A3: Raw Session Channel State` shows the client-side channel state
2. `A3: Network Log` shows raw request and response records

Server debug page:
1. `A3: Channel State (channel_sessions table)` shows stored channel sessions
2. `client_hello_json` and `server_hello_json` show what the current handshake sent

## Hints
1. work top-to-bottom in `shared/channel_crypto.py`
2. finish Stage 1 before Stage 2
3. the placeholder A3 objects already preserve the app flow; your job is to replace their contents with real cryptography
4. the fixed demo server authentication key material is split by trust boundary:
   - server private key in `server_app/dev_keys/`
   - pinned public key in `client_app/pinned_keys/`
5. when you need stable bytes for signing, verification, AAD, or transcript binding, serialize JSON objects in a deterministic way before encoding them to bytes

## How To Run
```bash
uv run python scripts/reset_state.py
uv run python scripts/run_all.py
```

Useful pages:
1. Alice: `http://127.0.0.1:5001`
2. Bob: `http://127.0.0.1:5002`
3. Client debug pages: open `Debug` after login and unlock
4. Server debug: `http://127.0.0.1:5000/debug`
