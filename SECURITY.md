# Security Policy

Report security issues privately. Do **not** open a public issue containing exploit details, credentials or other secrets.

If the repository exposes GitHub's **Security → Report a vulnerability** action, use that private channel. Otherwise contact the repository owner privately before publishing technical details.

Never publish `MASTER_KEY`, `/data/master.key`, SSH passwords, private keys, OIDC client secrets, session cookies or database files.

## Current security model

The current `0.2.2-dev` tree includes:

- AES-256-GCM encryption for stored SSH and OIDC secrets
- one-time bootstrap token protection for creation of the first administrator
- strict master-key startup behavior; an invalid existing key is never silently replaced
- SSH host-key TOFU with SHA256 fingerprints and changed-key blocking; changing shared host-key trust requires workspace Edit permission
- independent host-key verification for Jump Host and target server
- HttpOnly web-session cookies with automatic Secure handling for HTTPS
- raw session bearer tokens are not stored directly in SQLite
- SameSite cookies and explicit CSRF validation for authenticated state-changing HTTP calls
- exact WebSocket Origin validation against the effective application origin; missing Origin is rejected by default
- login/MFA rate limiting based on the effective client IP plus a bounded global Argon2 password-hash concurrency limit
- trusted-proxy CIDR allowlisting before `X-Forwarded-*` headers are honored
- bounded interactive SFTP operation concurrency with idle upload/download deadlines
- bounded per-user browser-session history; password/MFA security changes revoke other browser sessions
- internal HTTP 500 responses use opaque request IDs while detailed errors remain server-side
- SQLite WAL operation uses a per-connection busy timeout and bounded connection pool
- CSP, frame protection, MIME sniffing protection, Referrer-Policy and Permissions-Policy; SFTP inline preview is restricted to passive raster-image formats
- HSTS when ZentSSH knows the effective request scheme is HTTPS
- WebSocket input/write limits, HTTP header/idle limits and graceful SIGTERM shutdown
- administrator user lifecycle controls with disabled-session revocation and database-enforced last-active-admin protection
- private server/folder ownership enforced server-side across list, mutation, terminal, SFTP, transfer, crontab, status, host-key and Jump Host paths; foreign IDs return not-found semantics
- shared credential profiles are assignable only by their owner; other workspace members can use them only through a workspace server that already references the profile, and changing that server's SSH route cannot silently reuse another user's stored credential
- OIDC identities are bound by provider + `sub`; `email_verified=false` does not by itself block sign-in, and an existing local account is never auto-linked solely by matching email
- Public OIDC SSO IDs are random stable routing identifiers, not authentication secrets. Direct `/?sso=<id>` launches only enabled providers; all normal OIDC State/Nonce/PKCE/token validation still applies. OIDC State is additionally bound to the initiating browser with an HttpOnly callback cookie, and adding another SSO identity requires local password/MFA step-up when available
- Email-first login resolves linked accounts to their active OIDC provider before any password prompt; local password authentication is rejected for actively SSO-managed accounts, and unknown email addresses are not routed into OIDC JIT provisioning
- ZentSSH TOTP protects only local password authentication. When an active SSO identity is linked, local MFA is preserved but paused and the IdP is responsible for MFA policy
- administrator backups use a consistent SQLite snapshot and package the database together with its matching master key; `.zsb` backups are password-protected with Argon2id plus chunked AES-256-GCM, and restore validates authentication, checksums and SQLite integrity before replacing live state

## Reverse proxy warning

Only configure real reverse proxy addresses/networks in `TRUSTED_PROXY_CIDRS`. A network listed there is trusted to influence the effective client IP and HTTPS/host information.

When internet-facing, use HTTPS and set `BASE_URL` to the canonical public URL.

## Development status

This remains a development release. Security-sensitive changes are expected to pass the repository CI gates: Go tests, race detector, `go vet`, `govulncheck`, frontend syntax/build checks and the clean Docker build. The frontend dependency graph is locked in `frontend/package-lock.json`, and container builds do not rewrite dependency manifests.

