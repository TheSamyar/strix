---
name: cryptographic_failures
description: "Testing crypto misuse: weak/predictable randomness, ECB/IV reuse, padding oracles, predictable tokens & reset codes, JWT alg confusion, and hardcoded keys"
---

# Cryptographic Failures

Most real-world crypto bugs are *misuse*, not broken primitives: predictable randomness, reused IVs, a mode that leaks structure, a token you can forge, a key checked into git. Focus on what an attacker can predict, forge, or decrypt — not on academic cipher weaknesses.

## What To Map First

- **Secrets & tokens the app issues:** session IDs, password-reset/email-verify tokens, invite/share tokens, API keys, CSRF tokens, OTPs, signed URLs, coupon/referral codes.
- **Where crypto is applied:** cookies, JWTs (see `[[authentication-jwt]]`), encrypted fields, file/URL signing, password storage.
- **Sources of randomness:** any of the above generated from timestamps, counters, PIDs, `Math.random`, `rand()`, or a fixed seed.
- **Key material:** hardcoded keys/IVs in client bundles, repos, or config; default/example keys.

## Key Vulnerabilities

### Predictable / Weak Randomness

- Tokens derived from time, sequential counters, or non-CSPRNG (`Math.random`, `mt_rand`, `java.util.Random`, `rand()`).
- Collect many tokens back-to-back; look for monotonic bytes, shared prefixes, low entropy, timestamp-encoded segments.
- If a reset token embeds a predictable timestamp/user ID, forge another user's token → account takeover.
- Session IDs with insufficient entropy → prediction/fixation.

### Predictable Tokens & Reset Codes

- Numeric OTP/reset codes with a small space (4–6 digits) and no rate limit/lockout → brute force. Cross-link `[[weak-password-detection]]`.
- Reset tokens that are `base64(user_id)`, MD5 of email, or `hmac` with a leaked/guessable key.
- Invite/share tokens that are sequential or enumerable → `[[idor]]` over the token space.

### Encryption Mode & IV Misuse

- **ECB:** identical plaintext blocks → identical ciphertext blocks. Encrypt repetitive input and look for repeated 16-byte blocks (the "ECB penguin" pattern in hex).
- **IV/nonce reuse:** same IV across messages (CBC) or nonce reuse (CTR/GCM) leaks plaintext relationships and, for GCM, breaks authentication.
- **Padding oracle (CBC):** if the app reveals padding-valid vs invalid (distinct error/status/timing) on a ciphertext it decrypts, you can decrypt/forge without the key. Flip bytes and classify responses; automate with `padbuster`-style logic.
- Unauthenticated encryption (encrypt-without-MAC) → bit-flipping attacks on ciphertext.

### JWT / Signature Weaknesses

- `alg:none`, `HS256`↔`RS256` confusion (sign with the public key as HMAC secret), weak HMAC secret (crack with hashcat), `kid` path traversal/SQLi. Full playbook in `[[authentication-jwt]]`.

### Password Storage

- Fast/unsalted hashes (MD5/SHA1/SHA256 raw), no per-user salt, no work factor. Should be bcrypt/scrypt/argon2.
- Reversible "encryption" of passwords, or hashes leaked via API responses/timing.

### Hardcoded / Leaked Keys

- Signing/encryption keys, HMAC secrets, IVs, or API keys in client JS bundles, mobile apps, git history, or config. Cross-link `[[information-disclosure]]`.
- Default framework keys (Rails `secret_key_base`, Flask `SECRET_KEY`, Django `SECRET_KEY`) — with these you forge sessions/signatures directly.

### Transport & Certificate

- Weak TLS (see the `sslscan` tooling skill): deprecated protocols/ciphers, expired/self-signed in prod, missing HSTS. Mixed content leaking secrets over HTTP.

## Testing Methodology

1. **Inventory** every token/secret the app issues and every place crypto is applied.
2. **Entropy sweep** — collect token samples; test for predictability (structure, timestamps, low entropy, sequences).
3. **Forge** — if a token is predictable/derivable, generate another principal's token and use it.
4. **Mode/oracle** — probe encrypted blobs for ECB structure, IV reuse, and padding-oracle behavior.
5. **JWT** — run the `[[authentication-jwt]]` checks.
6. **Key hunt** — grep bundles/repo/history for keys and default framework secrets; forge if found.
7. **Storage/TLS** — confirm password hashing strength and TLS config.

## Validation Requirements

- Predictable token: forge a valid token for a principal you don't control and use it (e.g. reset another account).
- Padding oracle: decrypt a target ciphertext or forge a valid one using only the oracle.
- ECB/IV reuse: side-by-side ciphertexts showing repeated/related blocks.
- Hardcoded key: the key's location plus a forged signature/session proving impact.
- Prefer concrete forgery/decryption over "the algorithm is weak" assertions.
