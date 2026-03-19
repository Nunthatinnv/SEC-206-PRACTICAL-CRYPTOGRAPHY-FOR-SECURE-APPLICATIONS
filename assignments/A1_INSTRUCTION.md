# Assignment 1 - Secure Password Storage

## Overview
The goal of this assignment is to secure password storage and password verification on the server. The authentication system in this app is still simple: the server stores login data for `alice` and `bob`, the client submits a login request, and the server checks the submitted password against the stored value. If the check succeeds, the server returns a bearer token that the client uses on later requests.

In the current baseline, the server stores plaintext passwords and compares plaintext strings directly at login. Your job in A1 is to replace that with secure password hashing and verification while keeping the visible login behavior unchanged.

This assignment is only about server-side authentication:
- it is for secure password storage and login verification
- it is not for database encryption of messages
- it is not for secure channel protection between client and server

Reality caveat:
- This assignment focuses only on password storage and verification.
- In a real system, authentication should also include online guessing protections such as throttling, rate limiting, or temporary lockout.

## Flow
1. Server startup in `server_app/app.py` creates `AuthService` and calls `auth.seed_default_users()`.
2. In `server_app/auth.py`, `seed_default_users()` simulates registration by pre-creating `alice` and `bob`.
3. Right now, `seed_default_users()` stores the provided password directly in `users.password_hash`, which is insecure.
4. The login request eventually reaches the `/api/login` route in `server_app/app.py`.
5. In the current scaffold, that login request is transported through the A3 channel wrapper first, but the actual password verification still happens inside `AuthService.login(...)` in `server_app/auth.py`.
6. In `server_app/auth.py`, `login()` reads the stored value from `users.password_hash`.
7. Right now, `login()` checks `password != stored`, which is also insecure because it assumes plaintext storage.
8. If login succeeds, the server returns a bearer token. A bearer token is a random credential issued by the server; whoever presents that token is treated as authenticated.
9. For A1, your implementation is complete only after:
   - `hash_password(...)` and `verify_password(...)` are implemented in `shared/passwords.py`
   - the insecure callsites in `server_app/auth.py` are switched to those secure functions

## TODOs
1. Implement `hash_password(...)` in `shared/passwords.py`.
   - purpose: transform a plaintext password into a secure storable value for `users.password_hash`.
2. Implement `verify_password(...)` in `shared/passwords.py`.
   - purpose: verify a login password against the stored encoded value and return `True/False`.
3. In `server_app/auth.py`, replace insecure runtime calls. This file is part of the assignment, not just context:
   - plaintext storage in `seed_default_users()` -> `hash_password(...)`
   - direct equality check in `login()` -> `verify_password(...)`

## Files to focus on
1. `shared/passwords.py`
   - this is where you implement the A1 password functions
2. `server_app/auth.py`
   - this shows where passwords are currently stored and verified
3. `server_app/app.py`
   - this shows how login requests reach `AuthService`

## What to observe
Before A1 is completed:
1. The app already runs and login works.
2. The server debug page shows plaintext values in `users.password_hash`.
3. Login succeeds only because the stored value is the same plaintext password.

After A1 is completed:
1. Login behavior should still work the same from the user perspective.
2. `users.password_hash` should no longer reveal the original password.
3. Wrong passwords should still fail cleanly.

## How to debug
Look at the server debug page: `http://127.0.0.1:5000/debug`

Check the `users` table:
1. Before A1, `password_hash` contains plaintext passwords.
2. After A1, `password_hash` should no longer reveal the original password.

Then test login from the client pages:
1. Correct password should still work.
2. Wrong password should still fail.

If the debug page still shows old plaintext values after your code change, reset the app state so the seeded users are recreated.

## Hints
- For this assignment, you may use high-level password APIs from the crypto library (recommended), instead of implementing low-level cryptographic building blocks yourself.
- It is acceptable to store salt and algorithm parameters in the same database field as the encoded password hash.
- A reasonable starting point is to use Argon2id through a high-level password hashing API rather than raw low-level primitives.
- Your verify function should fail closed: malformed stored values and wrong passwords should both return failure.

## How to run
```bash
uv run python scripts/reset_state.py
uv run python scripts/run_all.py
```

Useful pages while checking behavior:
- Alice client: `http://127.0.0.1:5001`
- Bob client: `http://127.0.0.1:5002`
- Server debug (inspect `users.password_hash`): `http://127.0.0.1:5000/debug`
