package app

import (
	"fmt"
	"net/http"
)

func (a *App) apiDocs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZentSSH API</title><style>body{font:15px system-ui,sans-serif;background:#0b1017;color:#dbe7f3;max-width:980px;margin:40px auto;padding:0 20px}code,pre{font-family:ui-monospace,monospace}a{color:#71c7ff}.card{background:#111b26;border:1px solid #26394b;border-radius:12px;padding:18px;margin:14px 0}.method{display:inline-block;min-width:58px;color:#8fd7b0;font-weight:700}.muted{color:#8296aa}h1,h2{margin-bottom:.4em}</style></head><body><h1>ZentSSH API</h1><p class="muted">Local API overview. Authenticated state-changing requests require the ZentSSH CSRF header. SSH terminal data uses WebSocket attachments.</p><p><a href="/api/openapi.yaml">OpenAPI 3.1 YAML</a></p><div class="card"><h2>Core</h2><p><span class="method">GET</span><code>/api/health</code></p><p><span class="method">GET</span><code>/?sso=&lt;ssoId&gt;</code> — start one enabled OIDC provider directly by its stable public SSO ID</p><p><span class="method">POST</span><code>/api/login/discover</code> — resolve a known email to linked SSO or local password; unknown addresses are not sent into JIT SSO</p><p><span class="method">GET/PATCH</span><code>/api/me</code> — profile, SSO-managed local-login state, password and UI language</p><p><span class="method">GET/PATCH</span><code>/api/me/settings</code> — personal workspace settings</p><p><span class="method">GET</span><code>/api/admin/backup/status</code> — admin-only database/storage backup statistics</p><p><span class="method">POST</span><code>/api/admin/backup/export</code> — create a password-protected full backup</p><p><span class="method">POST</span><code>/api/admin/backup/restore</code> — validate and fully restore a backup, then restart ZentSSH</p><p><span class="method">GET/POST</span><code>/api/code-snippets</code> — private/shared terminal snippets organized in folders</p><p><span class="method">PATCH/DELETE</span><code>/api/code-snippets/{id}</code></p><p><span class="method">GET/POST</span><code>/api/snippet-folders</code> — personal/shared snippet folders</p><p><span class="method">PATCH/DELETE</span><code>/api/snippet-folders/{id}</code></p><p><span class="method">POST</span><code>/api/code-snippets/{id}/use</code> — resolve a snippet for terminal execution with folder permission checks</p><p><span class="method">GET</span><code>/api/snippet-permissions</code> — aggregated visible shared-folder capabilities</p><p><span class="method">GET/PATCH</span><code>/api/admin/snippet-folder-permissions</code> — assign shared snippet folders to users</p><p><span class="method">GET</span><code>/api/workspaces</code> — shared workspaces assigned to the current user; administrators see all</p><p><span class="method">GET</span><code>/api/server-search?q=...</code> — search personal and permitted workspace servers</p><p><span class="method">GET</span><code>/api/server-templates</code> — centrally managed server templates currently available to the user</p><p><span class="method">POST</span><code>/api/server-templates/{id}/adopt</code> — create a private server with inherited infrastructure and personal credentials</p><p><span class="method">GET/POST</span><code>/api/servers?workspaceId=...</code> — personal inventory by default or one permitted shared workspace</p><p><span class="method">GET/POST</span><code>/api/folders?workspaceId=...</code> — personal folders by default or one permitted shared workspace</p><p><span class="method">GET/POST/PATCH/DELETE</span><code>/api/admin/workspaces...</code> — manage shared workspaces and per-user use/create/edit/delete rights</p><p><span class="method">GET/POST/PATCH/DELETE</span><code>/api/admin/server-templates...</code> — manage inherited server templates and workspace visibility</p><p><span class="method">GET/PATCH</span><code>/api/admin/server-template-user-access</code> — manage server-template access by template or user</p><p><span class="method">PATCH</span><code>/api/servers/{id}/folder</code></p><p><span class="method">PATCH</span><code>/api/servers/{id}/preferences</code></p><p><span class="method">GET/PUT</span><code>/api/servers/{id}/crontab</code></p><p><span class="method">GET</span><code>/api/servers/{id}/status</code></p><p><span class="method">POST</span><code>/api/servers/{id}/connect-check</code></p></div><div class="card"><h2>SSH sessions</h2><p><span class="method">POST</span><code>/api/sessions</code></p><p><span class="method">POST</span><code>/api/sessions/quick</code></p><p><span class="method">GET</span><code>/api/sessions/{id}</code></p><p><span class="method">DELETE</span><code>/api/sessions/{id}</code></p><p><span class="method">WS</span><code>/ws/ssh/{sessionId}</code></p></div><div class="card"><h2>Files & transfers</h2><p><span class="method">GET</span><code>/api/files/{serverId}?path=...</code> — list / text / inline preview / download</p><p><span class="method">PUT</span><code>/api/files/{serverId}?path=...</code></p><p><span class="method">POST</span><code>/api/files/{serverId}</code> — mkdir/create/rename/chmod/chown/download_url</p><p><span class="method">POST</span><code>/api/transfers</code></p><p><span class="method">GET</span><code>/api/transfers</code></p></div><div class="card"><h2>Import</h2><p><span class="method">POST</span><code>/api/import/openssh/preview</code></p><p><span class="method">POST</span><code>/api/import/openssh</code></p></div></body></html>`)
}

func (a *App) openAPISpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = fmt.Fprint(w, openAPIYAML)
}

const openAPIYAML = `openapi: 3.1.0
info:
  title: ZentSSH API
  version: 0.2.2-dev
servers:
  - url: /
paths:
  /:
    get:
      summary: Start a direct SSO provider when the sso query parameter is present; otherwise serve the web application
      parameters:
        - name: sso
          in: query
          required: false
          description: Stable eight-character public SSO provider ID, for example k8m4p2xq
          schema: {type: string, pattern: '^[a-km-np-z2-9]{8}$'}
      responses:
        '200': {description: Web application}
        '302': {description: Redirect to the selected OIDC provider or back to login if unavailable}
  /api/health:
    get:
      summary: Health check
      responses:
        '200': {description: Healthy}
  /api/docs:
    get:
      summary: Human-readable local API overview
      responses:
        '200': {description: HTML API overview}
  /api/openapi.yaml:
    get:
      summary: OpenAPI 3.1 description of the ZentSSH HTTP API
      responses:
        '200': {description: OpenAPI YAML}
  /api/login/discover:
    post:
      summary: Resolve a known email-first login attempt to linked SSO or local password; unknown/disabled accounts return unavailable
      responses:
        '200': {description: Login method resolved}
        '400': {description: Email required}
  /api/setup/status:
    get:
      summary: Report whether the first-administrator setup is still required
      responses:
        '200': {description: Setup status}
  /api/setup:
    post:
      summary: Create the first administrator using the one-time setup token
      responses:
        '200': {description: Administrator created and signed in}
        '401': {description: Invalid setup token}
        '409': {description: Setup already completed}
        '503': {description: Initial setup is not available}
  /api/login:
    post:
      summary: Authenticate a local account with email and password
      responses:
        '200': {description: Signed in or MFA challenge returned}
        '401': {description: Invalid credentials}
        '409': {description: Account is managed by SSO}
        '429': {description: Login rate limit or password-hash capacity reached}
  /api/login/mfa:
    post:
      summary: Complete a pending local-login MFA challenge with TOTP or a recovery code
      responses:
        '200': {description: Signed in}
        '400': {description: Invalid challenge request}
        '401': {description: Invalid MFA code}
        '429': {description: MFA rate limit reached}
  /api/auth/providers:
    get:
      summary: List enabled public OIDC providers available for explicit sign-in
      responses:
        '200': {description: Public provider list}
  /api/auth/oidc/start:
    get:
      summary: Start an explicit OIDC sign-in flow
      responses:
        '302': {description: Redirect to OIDC provider}
        '400': {description: Invalid provider request}
  /api/auth/oidc/callback:
    get:
      summary: Validate OIDC callback state, token response and identity, then establish/link the ZentSSH account
      responses:
        '302': {description: Redirect back to ZentSSH after successful sign-in or linking}
        '400': {description: Invalid or expired OIDC callback}
  /api/logout:
    post:
      summary: Revoke the current browser session and clear authentication cookies
      responses:
        '200': {description: Signed out}
  /api/me:
    get:
      summary: Read the authenticated user profile, SSO-managed login state and resolved UI language
      responses:
        '200': {description: Current profile}
    patch:
      summary: Update own name, email, UI language and optional local password when SSO is not managing login
      responses:
        '200': {description: Profile updated}
        '400': {description: Invalid profile data}
        '401': {description: Current password is incorrect}
        '409': {description: Email conflict, no local password, or local password changes disabled by active SSO}
  /api/me/settings:
    get:
      summary: Read personal workspace settings including server-side UI language
      responses:
        '200': {description: User settings}
    patch:
      summary: Update SSH session retention, hidden-file preference, UI language and collapsed server-folder state
      responses:
        '200': {description: User settings updated}
        '400': {description: Invalid settings}
  /api/me/oidc:
    get:
      summary: List OIDC identities linked to the current account
      responses:
        '200': {description: Linked identities}
  /api/me/oidc/start:
    post:
      summary: Start account linking to an OIDC provider after local password/MFA step-up when applicable
      responses:
        '200': {description: OIDC authorization URL}
        '400': {description: Invalid provider or step-up request}
        '401': {description: Step-up authentication failed}
  /api/me/mfa:
    get:
      summary: Read local TOTP MFA status
      responses:
        '200': {description: MFA status}
  /api/me/mfa/setup:
    post:
      summary: Begin local TOTP MFA enrollment
      responses:
        '200': {description: Enrollment secret and QR payload}
        '409': {description: MFA unavailable for SSO-managed local login}
  /api/me/mfa/confirm:
    post:
      summary: Confirm TOTP enrollment and receive one-time recovery codes
      responses:
        '200': {description: MFA enabled}
        '400': {description: Invalid enrollment or TOTP code}
  /api/me/mfa/recovery:
    post:
      summary: Regenerate MFA recovery codes after local authentication confirmation
      responses:
        '200': {description: New recovery codes}
        '401': {description: Authentication confirmation failed}
  /api/me/mfa/disable:
    post:
      summary: Disable local MFA after local authentication confirmation
      responses:
        '200': {description: MFA disabled}
        '401': {description: Authentication confirmation failed}
  /api/admin/users:
    get:
      summary: List managed users and account/resource summary information
      responses:
        '200': {description: User administration list}
        '403': {description: Admin permission required}
    post:
      summary: Create a local user account
      responses:
        '201': {description: User created}
        '400': {description: Invalid user data}
        '409': {description: Email already exists}
  /api/admin/users/{id}:
    patch:
      summary: Update role, activation state, profile data or reset a user's local password
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: User updated}
        '409': {description: Last-active-administrator protection or resource conflict}
    delete:
      summary: Delete a user and owned private resources after safety checks
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: User deleted}
        '409': {description: Last administrator or shared credential still referenced}
  /api/admin/oidc/providers:
    get:
      summary: List configured OIDC providers
      responses:
        '200': {description: Provider list}
    post:
      summary: Create an OIDC provider
      responses:
        '201': {description: Provider created}
  /api/admin/oidc/providers/{id}:
    get:
      summary: Read one OIDC provider
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Provider detail}
    patch:
      summary: Update an OIDC provider while preserving its stable public SSO ID
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Provider updated}
    delete:
      summary: Delete an OIDC provider when no linked identities block removal
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Provider deleted}
        '409': {description: Provider is still referenced}
  /api/admin/oidc/test:
    post:
      summary: Test OIDC discovery/metadata for an administrator-supplied provider configuration
      responses:
        '200': {description: OIDC metadata check result}
        '400': {description: Invalid provider configuration}
  /api/admin/backup/status:
    get:
      summary: Read admin-only database and backup storage statistics
      responses:
        '200': {description: Backup status}
        '403': {description: Admin permission required}
  /api/admin/backup/export:
    post:
      summary: Create a password-protected full database and master-key backup
      responses:
        '200': {description: Encrypted ZentSSH backup file}
        '400': {description: Backup password is missing or too short}
        '403': {description: Admin permission required}
  /api/admin/backup/restore:
    post:
      summary: Validate and fully replace the current ZentSSH state from an encrypted backup
      responses:
        '200': {description: Restore installed and restart scheduled}
        '400': {description: Invalid backup, password or upload}
        '409': {description: Backup key conflicts with externally configured MASTER_KEY}
        '403': {description: Admin permission required}
  /api/code-snippets:
    get:
      summary: List own private or visible shared terminal code snippets
      parameters:
        - {name: scope, in: query, schema: {type: string, enum: [private, shared]}}
      responses:
        '200': {description: Snippet list}
        '403': {description: Shared snippet permission required}
    post:
      summary: Create a private snippet or, with permission, a shared snippet
      responses:
        '201': {description: Snippet created}
        '403': {description: Shared create permission required}
  /api/code-snippets/{id}:
    patch:
      summary: Update an owned private snippet or a shared snippet with edit permission
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Snippet updated}
        '403': {description: Shared edit permission required}
    delete:
      summary: Delete an owned private snippet or a shared snippet with delete permission
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Snippet deleted}
        '403': {description: Shared delete permission required}
  /api/code-snippets/{id}/use:
    post:
      summary: Return the selected snippet for execution after enforcing private ownership/shared use permission
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Snippet ready for terminal execution}
        '403': {description: Shared use permission required}
  /api/snippet-folders:
    get:
      summary: List the current user's private folders or visible shared snippet folders
      parameters:
        - {name: scope, in: query, schema: {type: string, enum: [private, shared]}}
      responses:
        '200': {description: Folder list including effective shared-folder permissions}
    post:
      summary: Create a private snippet folder; administrators may create shared folders
      responses:
        '201': {description: Folder created}
        '403': {description: Administrator required for shared folder creation}
  /api/snippet-folders/{id}:
    patch:
      summary: Rename an owned private folder or an administrator-managed shared folder
      responses:
        '200': {description: Folder updated}
    delete:
      summary: Delete an owned private folder (snippets become unfiled) or an empty administrator-managed shared folder
      responses:
        '200': {description: Folder deleted}
        '409': {description: Folder still contains snippets}
  /api/snippet-permissions:
    get:
      summary: Read aggregated capabilities/counts from shared snippet folders visible to the current user
      responses:
        '200': {description: Aggregated shared-folder capabilities}
  /api/admin/snippet-folder-permissions:
    get:
      summary: List shared-folder assignments for one user or user assignments for one shared folder
      parameters:
        - {name: userId, in: query, required: false, schema: {type: integer}}
        - {name: folderId, in: query, required: false, schema: {type: integer}}
      responses:
        '200': {description: Shared folder assignments}
    patch:
      summary: Assign/unassign a shared snippet folder and update use/create/edit/delete rights for a user
      responses:
        '200': {description: Folder permissions updated}
  /api/admin/snippet-permissions:
    get:
      deprecated: true
      summary: Legacy aggregate shared-snippet permission view
      responses:
        '200': {description: Legacy aggregate permission list}
  /api/admin/snippet-permissions/{userId}:
    patch:
      deprecated: true
      summary: Legacy helper that applies the same rights to every shared snippet folder
      parameters:
        - {name: userId, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Legacy permissions updated}
  /api/workspaces:
    get:
      summary: List shared workspaces assigned to the current user; administrators see every workspace
      responses:
        '200': {description: Workspace list with effective use/create/edit/delete rights}
  /api/server-search:
    get:
      summary: Search the personal server tree and every shared workspace visible to the current user
      parameters:
        - {name: q, in: query, required: true, schema: {type: string, maxLength: 160}}
      responses:
        '200': {description: Scoped server search results including their workspace/template origin}
  /api/server-templates:
    get:
      summary: List active or disabled server templates currently visible to the current user
      responses:
        '200': {description: Visible server templates and adoption state}
  /api/server-templates/{id}/adopt:
    post:
      summary: Adopt a visible server template as a private server; infrastructure stays inherited while credentials remain personal
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '201': {description: Private template-derived server created}
        '404': {description: Template is not visible}
        '409': {description: Template disabled or already adopted}
  /api/admin/workspaces:
    get:
      summary: List all shared workspaces with member/server/folder counts
      responses:
        '200': {description: Workspace administration list}
    post:
      summary: Create a shared workspace
      responses:
        '201': {description: Workspace created}
  /api/admin/workspaces/{id}:
    get:
      summary: Read a workspace and all non-admin membership assignments
      responses:
        '200': {description: Workspace detail}
    patch:
      summary: Update workspace metadata or active state
      responses:
        '200': {description: Workspace updated}
    delete:
      summary: Delete a workspace; non-empty workspaces require force=1 after explicit confirmation
      responses:
        '200': {description: Workspace deleted}
        '409': {description: Workspace still contains servers/folders}
  /api/admin/workspace-memberships:
    get:
      summary: List all workspaces and explicit membership state for one user
      parameters:
        - {name: userId, in: query, required: true, schema: {type: integer}}
      responses:
        '200': {description: Workspace membership list}
    patch:
      summary: Assign or unassign one user and set use/create/edit/delete workspace rights
      responses:
        '200': {description: Membership updated}
  /api/admin/server-templates:
    get:
      summary: List all centrally managed server templates
      responses:
        '200': {description: Server template administration list}
    post:
      summary: Create a server template and optional user/workspace visibility grants
      responses:
        '201': {description: Server template created}
  /api/admin/server-template-user-access:
    get:
      summary: List explicit server-template access by template or user
      parameters:
        - {name: templateId, in: query, required: false, schema: {type: integer}}
        - {name: userId, in: query, required: false, schema: {type: integer}}
      responses:
        '200': {description: User or template access list}
    patch:
      summary: Grant or revoke one user's explicit access to a server template
      responses:
        '200': {description: User access updated}
  /api/admin/server-templates/{id}:
    get:
      summary: Read one server template including visibility grants and adoption count
      responses:
        '200': {description: Server template detail}
    patch:
      summary: Update inherited infrastructure and visibility; route changes invalidate affected live connections
      responses:
        '200': {description: Server template updated}
    delete:
      summary: Delete an unused template or convert its derived private servers to standalone snapshots with convert=1
      responses:
        '200': {description: Server template deleted}
        '409': {description: Template is in use or referenced as a jump template}
  /api/credential-profiles:
    get:
      summary: List credential profiles owned by the current user
      responses:
        '200': {description: Credential profile list without stored secrets}
    post:
      summary: Create an encrypted SSH credential profile owned by the current user
      responses:
        '201': {description: Credential profile created}
        '400': {description: Invalid credential data}
  /api/credential-profiles/{id}:
    patch:
      summary: Update an owned credential profile; stored secrets remain encrypted and are never returned
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Credential profile updated}
        '403': {description: Only the owner may change the profile}
        '409': {description: Profile is still required by workspace servers}
    delete:
      summary: Delete an owned credential profile when it is no longer referenced
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Credential profile deleted}
        '409': {description: Credential profile is still in use}
  /api/servers:
    get:
      summary: List personal servers by default or one permitted shared workspace selected with workspaceId
      parameters:
        - {name: workspaceId, in: query, schema: {type: integer, minimum: 1}}
      responses:
        '200': {description: Scoped server list with effective permissions}
    post:
      summary: Create a personal server or, with create permission, a server in the selected workspace
      parameters:
        - {name: workspaceId, in: query, schema: {type: integer, minimum: 1}}
      responses:
        '201': {description: Created}
        '403': {description: Workspace create permission required}
  /api/folders:
    get:
      summary: List personal server folders by default or folders in one permitted shared workspace
      parameters:
        - {name: workspaceId, in: query, schema: {type: integer, minimum: 1}}
      responses:
        '200': {description: Scoped folder list}
    post:
      summary: Create a personal folder or, with create permission, a folder in the selected workspace
      parameters:
        - {name: workspaceId, in: query, schema: {type: integer, minimum: 1}}
      responses:
        '201': {description: Created}
        '403': {description: Workspace create permission required}
  /api/folders/{id}:
    patch:
      summary: Update a folder in its personal/workspace scope when edit permission is available
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Folder updated}
        '404': {description: Folder not found for this user}
    delete:
      summary: Delete an empty folder in its personal/workspace scope when delete permission is available
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Folder deleted}
        '409': {description: Folder is not empty}
  /api/servers/{id}:
    patch:
      summary: Update a personal server or shared-workspace server when edit permission is available
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Server updated}
        '403': {description: Workspace edit permission required}
        '409': {description: Route/credential safety conflict}
    delete:
      summary: Delete a personal server or shared-workspace server when delete permission is available
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Server deleted}
        '409': {description: Server is still referenced as a jump host}
  /api/servers/{id}/connect-check:
    post:
      summary: Validate SSH reachability/host-key state for a managed server
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Connection check result}
        '409': {description: Host-key trust action required}
  /api/servers/{id}/trust-host-key:
    post:
      summary: Trust the presented SSH host key; shared workspace servers require edit permission
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Host key trusted}
        '403': {description: Edit permission required}
  /api/servers/{id}/status:
    get:
      summary: Lightweight reachability status
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Status}
  /api/servers/{id}/folder:
    patch:
      summary: Move a server within its personal/workspace folder scope when edit permission is available
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Server moved}
        '400': {description: Invalid target folder}
        '404': {description: Server not found}
  /api/servers/{id}/preferences:
    patch:
      summary: Update per-server terminal editor and visual crontab preferences
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Preferences updated}
  /api/servers/{id}/crontab:
    get:
      summary: Read the current SSH user's crontab
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Crontab content}
    put:
      summary: Validate and install the current SSH user's crontab through the remote crontab command
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200': {description: Crontab installed}
        '400': {description: Invalid crontab or remote crontab error}
  /api/sessions:
    get:
      summary: List restorable SSH sessions
      responses:
        '200': {description: Sessions}
    post:
      summary: Create an SSH session for a personal or shared-workspace server the user may use
      responses:
        '201': {description: Session created}
  /api/sessions/quick:
    post:
      summary: Create transient Quick Connect session
      responses:
        '201': {description: Session created}
  /api/sessions/{id}:
    get:
      summary: Read one live/restorable SSH session that belongs to the current user (administrators may inspect managed sessions)
      parameters:
        - {name: id, in: path, required: true, schema: {type: string}}
      responses:
        '200': {description: Session information}
        '404': {description: Session not found}
    delete:
      summary: Terminate one live SSH session
      parameters:
        - {name: id, in: path, required: true, schema: {type: string}}
      responses:
        '200': {description: Session terminated}
  /api/files/{serverId}:
    get:
      summary: List, download, inline-preview or load a file on a personal or shared-workspace server the user may use
      parameters:
        - {name: serverId, in: path, required: true, schema: {type: integer}}
        - {name: path, in: query, schema: {type: string}}
        - {name: realpath, in: query, schema: {type: integer, enum: [1]}, description: Resolve a remote path through SFTP}
        - {name: text, in: query, schema: {type: integer, enum: [1]}, description: Load a bounded UTF-8/text payload for the web editor}
        - {name: inline, in: query, schema: {type: integer, enum: [1]}, description: Stream a file inline for same-origin previews}
        - {name: download, in: query, schema: {type: integer, enum: [1]}, description: Stream a file as an attachment}
      responses:
        '200': {description: File data}
    put:
      summary: Upload or save a file
      responses:
        '200': {description: Saved}
    post:
      summary: File action (mkdir, create, rename, chmod, chown, download_url)
      responses:
        '200': {description: Action completed}
    delete:
      summary: Delete file or empty directory
      responses:
        '200': {description: Deleted}
  /api/transfers:
    get:
      summary: Transfer history
      responses:
        '200': {description: Transfers}
    post:
      summary: Start an SFTP transfer between two servers the authenticated user may use
      responses:
        '201': {description: Transfer started}
  /api/transfers/{id}:
    get:
      summary: Read one SFTP transfer belonging to the current user (administrators may inspect managed transfers)
      parameters:
        - {name: id, in: path, required: true, schema: {type: string}}
      responses:
        '200': {description: Transfer information}
        '404': {description: Transfer not found}
    delete:
      summary: Cancel an active transfer
      parameters:
        - {name: id, in: path, required: true, schema: {type: string}}
      responses:
        '200': {description: Cancellation requested}
        '409': {description: Transfer is not active}
  /api/transfers/{id}/retry:
    post:
      summary: Retry a completed, failed, cancelled or interrupted transfer using the same endpoints/paths
      parameters:
        - {name: id, in: path, required: true, schema: {type: string}}
      responses:
        '201': {description: Retry transfer created}
        '409': {description: Original transfer is still active}
  /api/import/openssh/preview:
    post:
      summary: Parse OpenSSH config without importing
      responses:
        '200': {description: Preview}
  /api/import/openssh:
    post:
      summary: Import selected OpenSSH hosts into the authenticated user's private server inventory
      responses:
        '201': {description: Import report}
`
