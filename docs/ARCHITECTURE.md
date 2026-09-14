# Architecture

```text
Browser
  -> HTTP / WebSocket attachment
  -> ZentSSH Go backend
       -> SSH session manager + bounded terminal ring buffer
  -> SSH / SFTP
  -> managed server
        or
     Jump Host -> managed server
```

The browser never receives stored SSH secrets. SQLite and encrypted credentials live under `/data`. Terminal keystrokes use one bidirectional WebSocket and one remote PTY channel rather than per-key HTTP calls.

## Authentication

Local login uses Argon2id password hashing. OIDC uses Discovery, Authorization Code + PKCE, State/Nonce and ID-token signature validation against the provider JWKS.

The normal email-first entry point only routes already-known linked accounts to SSO; unknown email addresses are not used to guess or trigger an auto-create provider. Each OIDC provider also has a stable public eight-character SSO ID. `/?sso=<id>` resolves that ID server-side and starts the same validated OIDC authorization flow directly, which is suitable for an IdP portal launch URL.

A random web-session token is stored in an HttpOnly browser cookie. The database stores a SHA-256-derived identifier rather than that raw bearer value. State-changing authenticated HTTP requests also require a separate CSRF cookie/header pair.

## Reverse proxies

Forwarded client/scheme/host headers are accepted only when the direct peer matches `TRUSTED_PROXY_CIDRS`. `BASE_URL` can provide the canonical public origin and HTTPS scheme.

## Server authorization scopes

`servers` and `folders` always have a bookkeeping owner, but authorization is based on their scope. Rows with no `workspace_id` are private and remain accessible only to their owner. Rows with a `workspace_id` are shared resources and resolve access through `workspace_memberships`; administrators receive implicit full rights, while normal users can independently receive Use/Create/Edit/Delete. Read/list access exists only when at least one workspace right is assigned. Connection-bearing operations use the same central authorization boundary before SSH/SFTP is opened, so direct server IDs cannot bypass the UI permissions.

Workspace server credentials are encrypted exactly like private credentials and are decrypted only in the backend. Shared credential profiles may be referenced by workspace servers; secrets are never serialized to another user's browser. Workspace Jump Hosts must remain in the same workspace. Private Jump Hosts must remain with the same owner. A referenced Jump Host cannot be deleted until its dependencies are removed, preventing an implicit fallback to a direct route.

Deleting the user who originally created a workspace row does not delete that shared resource: its bookkeeping owner is reassigned during user deletion. Removing Use permission, removing membership or disabling/deleting the workspace terminates affected in-memory SSH sessions and server transfers.

## Server templates

`server_templates` are centrally managed infrastructure definitions, not shared credentials. A derived private `servers` row stores `template_id` plus the user's own SSH credentials/folder. Effective name, host, port, color, editor modes and Jump-template route are resolved from the live template; snapshot columns are synchronized as a safe conversion fallback. Template visibility can be global or granted to users/workspaces and is revalidated when a connection is used.

A template Jump Host references another template. At runtime ZentSSH resolves that to the same user's adopted private Jump-template server, keeping both credential sets personal. Nested template jumps are rejected. Template route/access changes revalidate affected live sessions/transfers. A used template can only be deleted through explicit conversion to standalone servers, and conversion is rejected if a required Jump-template adoption is missing.

Older databases that predate ownership are migrated deterministically: the former global server tree is assigned to the oldest administrator (or oldest account when no administrator exists). Existing private data is never inferred to be shared or template-derived.

## SSH trust

Credentials are decrypted only in the backend. SSH host keys must be explicitly trusted. Jump Host and target fingerprints are independent, and target scanning occurs through the Jump Host when required.

## SSH session lifecycle

Opening a terminal first creates a backend `LiveSession` containing the SSH client/PTTY, input stream, bounded terminal output buffer and attachment set. `/ws/ssh/<session-id>` attaches a browser to that existing session; it does not create a new SSH connection.

The initial ring-buffer snapshot and subsequent live output are queued under the same session lock so reconnects cannot receive live bytes before their snapshot. Each browser has its own bounded writer queue and write deadline. A slow browser is detached independently rather than blocking the PTY output path for all clients.

Explicit tab close terminates the backend session. Browser reload, crash or network loss only detaches it; the configured retention policy decides when an unattached session is cleaned up. Session limits are reserved atomically before opening SSH so simultaneous requests cannot oversubscribe the configured per-user/global limits.

## SFTP and transfer resource boundaries

Interactive SFTP/file operations and server-to-server transfers are bounded independently per user and globally. Streaming upload/download paths use idle deadlines so a stalled client cannot keep an SSH/SFTP stream open indefinitely. Server-to-server transfers stream through the backend in chunks rather than buffering complete files in browser or application memory.

## Backup and restore

Administrator backups use a consistent SQLite snapshot rather than copying a live database file. The snapshot and its matching master encryption key are packaged together in the ZentSSH `.zsb` backup format. Backup passwords are processed through Argon2id and the payload is authenticated/encrypted with AES-256-GCM.

Restore is fail-safe: ZentSSH decrypts and validates the package, verifies checksums and SQLite integrity, and checks master-key compatibility before replacing live state. Only after validation succeeds are active SSH sessions/transfers terminated and the database plus persistent master key replaced. A successful restore then requests a controlled process restart so the application cannot continue with stale in-memory state.

