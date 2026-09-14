import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import './style.css';
import { qrSvg } from './qr.js';

const A = '/api';
const app = document.querySelector('#app');
const state = {
  me: null,
  servers: [],
  folders: [],
  workspaces: [],
  serverTemplates: [],
  activeWorkspaceId: 0,
  serverSearchResults: [],
  serverSearchPending: false,
  serverSearchSequence: 0,
  profiles: [],
  liveSessions: [],
  tabs: [],
  active: null,
  fileServer: null,
  filePath: '.',
  notice: '',
  userSettings: { sshSessionRetention: 'inherit', showHiddenFiles: false, language: '', collapsedFolderIds: [] },
  snippetPermissions: { canUse: false, canCreate: false, canEdit: false, canDelete: false, sharedCount: 0, sharedFolderCount: 0 },
  serverStatus: {},
  statusPending: new Set(),
  selectedServerId: null,
  draggingServerId: null,
  serverDragTargetFolderId: undefined,
  suppressServerClickUntil: 0,
  draggingTabId: null,
  suppressTabClickUntil: 0,
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s = '') => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function browserLanguage() {
  const value = String(navigator.languages?.[0] || navigator.language || 'en').toLowerCase();
  return value === 'de' || value.startsWith('de-') ? 'de' : 'en';
}

function uiLanguage() {
  const value = String(state.me?.language || state.userSettings?.language || '').toLowerCase();
  return value === 'de' ? 'de' : (value === 'en' ? 'en' : browserLanguage());
}

function L(de, en) { return uiLanguage() === 'de' ? de : en; }

function applyDocumentLanguage() { document.documentElement.lang = uiLanguage(); }

const STATIC_EN = new Map([
  ['Einstellungen', 'Settings'], ['Abmelden', 'Sign out'], ['Abbrechen', 'Cancel'], ['Speichern', 'Save'], ['Löschen', 'Delete'], ['Bearbeiten', 'Edit'], ['Schließen', 'Close'], ['Zurück', 'Back'],
  ['Server hinzufügen', 'Add server'], ['Server bearbeiten', 'Edit server'], ['Ordner hinzufügen', 'Add folder'], ['Ordner bearbeiten', 'Edit folder'], ['Server anlegen', 'Create server'], ['Ordner anlegen', 'Create folder'], ['Server suchen', 'Search servers'],
  ['Direkt verbinden', 'Connect directly'], ['Zugangsvorlage', 'Credential profile'], ['Direkte Zugangsdaten', 'Direct credentials'], ['Benutzername', 'Username'], ['Passwort', 'Password'], ['Private Key', 'Private key'], ['Key-Passphrase', 'Key passphrase'], ['Farbe', 'Color'], ['Jump Host', 'Jump host'], ['Oberste Ebene', 'Top level'],
  ['Terminal-Dateieditor', 'Terminal file editor'], ['Crontab-Editor', 'Crontab editor'], ['Beim ersten Mal fragen', 'Ask the first time'], ['ZentSSH Webeditor', 'ZentSSH web editor'], ['Im Terminal öffnen', 'Open in terminal'],
  ['Quick Connect', 'Quick Connect'], ['Als Server speichern', 'Save as server'], ['Servername', 'Server name'], ['Verbinden', 'Connect'],
  ['Neue Datei', 'New file'], ['Neuer Ordner', 'New folder'], ['Datei hochladen', 'Upload file'], ['Upload via URL', 'Upload via URL'], ['Versteckte anzeigen', 'Show hidden'], ['Versteckte ausblenden', 'Hide hidden'], ['Neu laden', 'Refresh'], ['Dual-Ansicht', 'Dual view'], ['Öffnen', 'Open'], ['Herunterladen', 'Download'], ['Umbenennen / Verschieben', 'Rename / move'], ['Rechte ändern', 'Change permissions'], ['Eigentümer ändern', 'Change owner'], ['Server-Transfer', 'Server transfer'], ['Anschauen', 'View'], ['Im Editor öffnen', 'Open in editor'],
  ['Datei', 'File'], ['Ordner', 'Folder'], ['Dateiname', 'File name'], ['Ordnername', 'Folder name'], ['Neuer vollständiger Pfad', 'New full path'], ['Dateirechte ändern', 'Change file permissions'], ['Aktueller Eigentümer', 'Current owner'], ['Aktuelle Gruppe', 'Current group'],
  ['Transfers', 'Transfers'], ['Transfer starten', 'Start transfer'], ['Zielserver', 'Target server'], ['Zielpfad', 'Target path'], ['Abbrechen', 'Cancel'],
  ['Sicherheit', 'Security'], ['SSH-Sessions', 'SSH sessions'], ['File Manager', 'File manager'], ['Sprache', 'Language'], ['Benutzer', 'Users'], ['Aktive Sessions', 'Active sessions'],
  ['Zwei-Faktor-Authentifizierung', 'Two-factor authentication'], ['MFA einrichten', 'Set up MFA'], ['MFA deaktivieren', 'Disable MFA'], ['Recovery Codes erneuern', 'Renew recovery codes'], ['Bestätigungscode', 'Verification code'], ['Aktuelles Passwort', 'Current password'], ['Neues Passwort', 'New password'], ['Rolle', 'Role'],
  ['Zugangsvorlagen', 'Credential profiles'], ['Zugangsvorlage hinzufügen', 'Add credential profile'], ['Zugangsvorlage bearbeiten', 'Edit credential profile'], ['Vorlage teilen', 'Share profile'], ['Geteilt', 'Shared'], ['Aktiv', 'Active'], ['Deaktiviert', 'Disabled'], ['Verknüpfen', 'Link'], ['Verbunden', 'Connected'], ['Nicht verbunden', 'Not connected'],
  ['OpenSSH Config importieren', 'Import OpenSSH config'], ['Import starten', 'Start import'], ['Vorschau prüfen', 'Check preview'], ['Ausgewählte Hosts importieren', 'Import selected hosts'], ['Vorlage auswählen…', 'Select profile…'],
  ['OIDC-Provider hinzufügen', 'Add OIDC provider'], ['OIDC-Provider bearbeiten', 'Edit OIDC provider'], ['Providername', 'Provider name'], ['Aktiviert', 'Enabled'],
  ['Dieser SSO-Anmeldeweg ist nicht verfügbar.', 'This SSO sign-in route is not available.'],
  ['Visuellen Editor verwenden', 'Use visual editor'], ['Den gewählten Terminal-Editor normal starten.', 'Start the selected terminal editor normally.'], ['Jobs zeilenweise und verständlich verwalten.', 'Manage jobs line by line in a friendly interface.'], ['Cronjob hinzufügen', 'Add cron job'], ['Umgebungsvariable hinzufügen', 'Add environment variable'], ['Kommentar', 'Comment'], ['Erweitert', 'Advanced'], ['Variable', 'Variable'], ['Befehl', 'Command'], ['Ausführung', 'Schedule'], ['Benutzerdefiniert', 'Custom'], ['Stündlich', 'Hourly'], ['Täglich', 'Daily'], ['Wöchentlich', 'Weekly'], ['Monatlich', 'Monthly'], ['Beim Neustart', 'At reboot'], ['Duplizieren', 'Duplicate'], ['Aktivieren', 'Enable'], ['Deaktivieren', 'Disable'],
  ['Lade…', 'Loading…'], ['Speichere…', 'Saving…'], ['Prüfe…', 'Checking…'], ['Prüfe Host Key…', 'Checking host key…'], ['Prüfe Verbindungen…', 'Checking connections…'], ['Starte Transfer…', 'Starting transfer…'], ['Keine weiteren Angaben nötig.', 'No additional details required.'],
  ['Dieser Ordner ist leer.', 'This folder is empty.'], ['Rechtsklick hier öffnet die Dateiaktionen.', 'Right-click here to open file actions.'], ['Noch keine Transfers vorhanden.', 'No transfers yet.'], ['Keine laufenden SSH-Sessions.', 'No active SSH sessions.'], ['Keine Benutzer gefunden.', 'No users found.'], ['Noch keine Zugangsvorlage vorhanden.', 'No credential profile yet.'],
  ['Mindestens 10 Zeichen', 'At least 10 characters'], ['Leer = unverändert', 'Leave empty to keep unchanged'], ['Optional', 'Optional'], ['Anzeigen', 'Show'], ['Unbegrenzt', 'Unlimited'], ['Sofort beenden', 'End immediately'], ['Server-Standard', 'Server default'],
  ['SSH-Zugangsvorlagen', 'SSH credential profiles'], ['Benutzername + Passwort oder Key einmal speichern und auf mehreren Servern verwenden.', 'Store a username plus password or key once and reuse it across multiple servers.'],
  ['TOTP für lokale Anmeldung. Recovery Codes werden nur einmal angezeigt.', 'TOTP for local sign-in. Recovery codes are shown only once.'], ['Nicht aktiv', 'Not active'], ['TOTP aktiv', 'TOTP active'], ['Neue Recovery Codes', 'New recovery codes'],
  ['Persönliche Darstellung für deine SFTP-Ansichten.', 'Personal display preferences for your SFTP views.'], ['Versteckte Dateien', 'Hidden files'], ['Dateien und Ordner anzeigen, deren Name mit einem Punkt beginnt.', 'Show files and folders whose names start with a dot.'],
  ['SSO mit deinem Konto verknüpfen', 'Link SSO to your account'], ['Optional eine externe OIDC-Identität mit diesem Konto verbinden.', 'Optionally link an external OIDC identity to this account.'], ['Keine aktivierten SSO-Provider vorhanden.', 'No enabled SSO providers available.'],
  ['Lokale und per SSO angelegte ZentSSH-Konten verwalten.', 'Manage local and SSO-created ZentSSH accounts.'], ['Serverseitige Shells bleiben je nach Persistenz auch ohne Browser verbunden.', 'Server-side shells can remain connected without a browser depending on persistence settings.'],
  ['Config zuerst prüfen, Hosts auswählen und erst danach als ZentSSH-Server anlegen.', 'Review the config first, select hosts, then create ZentSSH servers.'], ['Vorschau vor Import', 'Preview before import'], ['Sicherer Import', 'Safe import'],
  ['OIDC / SSO Provider', 'OIDC / SSO providers'], ['Noch kein OIDC-Provider konfiguriert.', 'No OIDC provider configured yet.'],
  ['Gespeichert.', 'Saved.'], ['Gespeichert. Gilt auch für bereits laufende Sessions.', 'Saved. Also applies to already running sessions.'], ['Session-Persistenz gespeichert.', 'Session persistence saved.'], ['File-Manager-Einstellung gespeichert.', 'File manager setting saved.'], ['Profil gespeichert.', 'Profile saved.'],
  ['Direkt verbinden, ohne vorher einen Server anlegen zu müssen.', 'Connect directly without creating a server first.'], ['Nach erfolgreicher Verbindung dauerhaft in ZentSSH anlegen.', 'Save permanently in ZentSSH after a successful connection.'],
  ['SSH-Ziel, Zugangsdaten und optionalen Jump Host konfigurieren.', 'Configure the SSH target, credentials and optional jump host.'], ['Secrets werden verschlüsselt gespeichert und niemals wieder über die API ausgegeben.', 'Secrets are stored encrypted and are never returned through the API.'],
  ['Prüfe den Fingerprint mit einer vertrauenswürdigen Quelle, bevor du diesem Server vertraust.', 'Verify the fingerprint using a trusted source before trusting this server.'], ['Neuen Key ausdrücklich vertrauen', 'Explicitly trust new key'],
  ['ZentSSH lädt die Datei serverseitig und streamt sie direkt per SFTP.', 'ZentSSH downloads the file server-side and streams it directly over SFTP.'], ['URL', 'URL'], ['Zieldatei', 'Target file'],
  ['Aktiv, abgeschlossen, fehlgeschlagen oder unterbrochen.', 'Active, completed, failed or interrupted.'], ['Erneut', 'Retry'],
  ['Konto aktiv', 'Account active'], ['Benutzer anlegen', 'Create user'], ['Benutzer bearbeiten', 'Edit user'],
  ['Datei bearbeiten', 'Edit file'], ['Crontab bearbeiten', 'Edit crontab'], ['Wie sollen nano, vi und vim auf diesem Server geöffnet werden?', 'How should nano, vi and vim be opened on this server?'], ['ZentSSH kann crontab -e als visuellen Editor öffnen.', 'ZentSSH can open crontab -e in a visual editor.'],
  ['Authenticator verbinden', 'Connect authenticator'], ['Füge das Secret in deiner TOTP-App hinzu und bestätige anschließend einen aktuellen Code.', 'Add the secret to your TOTP app and then confirm a current code.'], ['MFA ist aktiv', 'MFA is active'], ['Recovery Codes', 'Recovery codes'], ['Fertig', 'Done'], ['Kopieren', 'Copy'],
  ['MFA deaktivieren', 'Disable MFA'], ['Erfordert aktuelles Passwort und TOTP- oder Recovery-Code.', 'Requires the current password and a TOTP or recovery code.'], ['Recovery Codes erneuern', 'Renew recovery codes'], ['Alte Recovery Codes werden ungültig.', 'Old recovery codes will become invalid.'],
  ['Host Key vertrauen', 'Trust host key'], ['SSH Host Key hat sich geändert', 'SSH host key changed'], ['Fingerprint', 'Fingerprint'],
  ['Neuer vollständiger Pfad', 'New full path'], ['Modus', 'Mode'], ['UID', 'UID'], ['GID', 'GID'], ['Aktueller Stand', 'Current value'],
  ['Datei konnte nicht geöffnet werden', 'File could not be opened'], ['Nochmal versuchen', 'Try again'], ['Suchen', 'Search'], ['Nächster Treffer', 'Next match'],
]);

function staticEnglishText(value) {
  const original = String(value || '');
  const trimmed = original.trim();
  const translated = STATIC_EN.get(trimmed);
  if (!translated) return original;
  const start = original.slice(0, original.indexOf(trimmed));
  const end = original.slice(original.indexOf(trimmed) + trimmed.length);
  return start + translated + end;
}

function skipStaticLocalization(element) {
  return Boolean(element?.closest?.('.terminal,.xterm,.file-entry,.pane-row,.server,.tab-label,.server-context-title strong,.file-context-title strong,.transfer-dock-title b,.transfer-history-main,.provider-list .provider-row b,.provider-list .provider-row small,.snippet-launch-meta,.snippet-preview-title,.snippet-settings-row,.snippet-permission-user,code,pre,textarea'));
}

function localizeStaticSubtree(root) {
  if (uiLanguage() !== 'en' || !root) return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) {
    const parent = node.parentElement;
    if (!parent || skipStaticLocalization(parent)) continue;
    const next = staticEnglishText(node.nodeValue);
    if (next !== node.nodeValue) node.nodeValue = next;
  }
  const elements = root.nodeType === Node.ELEMENT_NODE ? [root, ...root.querySelectorAll('*')] : [...root.querySelectorAll?.('*') || []];
  for (const element of elements) {
    if (skipStaticLocalization(element)) continue;
    for (const attr of ['placeholder', 'aria-label', 'data-tooltip', 'title']) {
      if (!element.hasAttribute?.(attr)) continue;
      const current = element.getAttribute(attr);
      const translated = STATIC_EN.get(String(current || '').trim());
      if (translated) element.setAttribute(attr, translated);
    }
  }
}

const staticLocalizationObserver = new MutationObserver(mutations => {
  if (uiLanguage() !== 'en') return;
  for (const mutation of mutations) for (const node of mutation.addedNodes) {
    if (node.nodeType === Node.ELEMENT_NODE) localizeStaticSubtree(node);
    else if (node.nodeType === Node.TEXT_NODE && node.parentElement && !skipStaticLocalization(node.parentElement)) node.nodeValue = staticEnglishText(node.nodeValue);
  }
});
staticLocalizationObserver.observe(document.body, { childList: true, subtree: true });

function normalizeHexColor(value, fallback = '#5aa9ff') {
  const color = String(value || '').trim();
  return /^#[0-9a-f]{6}$/i.test(color) ? color.toLowerCase() : fallback;
}

function knownServer(serverId) {
  const id = Number(serverId);
  if (!Number.isFinite(id)) return null;
  return state.servers.find(item => Number(item.id) === id)
    || state.tabs.map(tab => tab.serverSnapshot).find(item => Number(item?.id) === id)
    || null;
}

function configuredServerColor(serverId, fallback = '#79bee7') {
  return normalizeHexColor(knownServer(serverId)?.color, '') || fallback;
}

function numericDatasetValue(value) {
  if (value == null || value === '') return null;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
}

let modalAutofocusObserver = null;
function installModalAutofocus() {
  const modal = $('#modal');
  if (!modal) return;
  modalAutofocusObserver?.disconnect();
  modalAutofocusObserver = new MutationObserver(() => scheduleModalAutofocus(modal));
  modalAutofocusObserver.observe(modal, { childList: true });
}

function scheduleModalAutofocus(modal = $('#modal')) {
  if (!modal?.firstElementChild) return;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    const layer = modal.lastElementChild || modal;
    if (!modal?.firstElementChild || layer.contains(document.activeElement) && document.activeElement?.matches?.('input:not([type="hidden"]),select,textarea')) return;
    const fields = [...layer.querySelectorAll('.dialog input:not([type="hidden"]):not(:disabled), .dialog select:not(:disabled), .dialog textarea:not(:disabled)')]
      .filter(field => field.getClientRects().length && getComputedStyle(field).visibility !== 'hidden');
    const target = fields.find(field => field.hasAttribute('autofocus')) || fields[0] || layer.querySelector('.dialog button:not(:disabled)');
    target?.focus({ preventScroll: true });
  }));
}

function closeActiveModal() {
  const modal = $('#modal');
  if (!modal || !modal.firstElementChild) return false;
  const layer = modal.lastElementChild || modal;
  const close = $('[data-close]', layer) || $('[data-cancel]', layer);
  if (close) close.click();
  else if (layer !== modal) layer.remove();
  else modal.innerHTML = '';
  return true;
}

document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  if (closeContextMenus() || closeActiveModal()) {
    event.preventDefault();
    event.stopPropagation();
  }
}, true);

document.addEventListener('keydown', event => {
  const shortcut = (event.metaKey || event.ctrlKey) && event.shiftKey && event.code === 'Space';
  if (!shortcut) return;
  const target = event.target;
  if (target?.closest?.('input,textarea,select,[contenteditable="true"]') && !target.closest?.('.xterm')) return;
  const tab = activeTerminalTab();
  if (!tab) return;
  event.preventDefault();
  event.stopPropagation();
  if ($('#modal')?.firstElementChild) return;
  openSnippetLauncher(tab.id);
}, true);

document.addEventListener('pointerdown', event => {
  if (!event.target.closest?.('.app-context-menu')) closeContextMenus();
}, true);
document.addEventListener('scroll', () => closeContextMenus(), true);
window.addEventListener('resize', () => closeContextMenus());

// In modal dialogs, Enter on a normal input triggers the positive/default action.
// Textareas/editors are intentionally excluded so Enter keeps inserting a newline.
document.addEventListener('keydown', event => {
  if (event.key !== 'Enter' || event.defaultPrevented || event.ctrlKey || event.metaKey || event.altKey || event.shiftKey) return;
  const input = event.target.closest?.('#modal .dialog input');
  if (!input || input.closest('.editorbar') || input.dataset.enterIgnore === '1' || ['checkbox', 'file', 'color', 'range'].includes(String(input.type || '').toLowerCase())) return;
  const dialog = input.closest('.dialog');
  const primary = dialog?.querySelector('[data-primary]:not(:disabled), .actions .primary:not(:disabled), button.primary:not(:disabled)');
  if (!primary) return;
  event.preventDefault();
  primary.click();
});

function setButtonBusy(button, busy, label = 'Bitte warten…') {
  if (!button) return;
  if (busy) {
    if (!button.dataset.originalLabel) button.dataset.originalLabel = button.textContent;
    button.disabled = true;
    button.classList.add('is-busy');
    button.textContent = label;
  } else {
    button.disabled = false;
    button.classList.remove('is-busy');
    if (button.dataset.originalLabel) {
      button.textContent = button.dataset.originalLabel;
      delete button.dataset.originalLabel;
    }
  }
}

function cookieValue(name) {
  const prefix = `${encodeURIComponent(name)}=`;
  for (const part of document.cookie.split(';')) {
    const item = part.trim();
    if (item.startsWith(prefix)) return decodeURIComponent(item.slice(prefix.length));
  }
  return '';
}

async function api(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  const method = String(options.method || 'GET').toUpperCase();
  if (options.body != null && !(options.body instanceof FormData) && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = cookieValue('zentssh_csrf');
    if (csrf) headers['X-CSRF-Token'] = csrf;
  }
  const response = await fetch(A + url, { ...options, headers });
  const text = await response.text();
  let data = {};
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (!response.ok) {
    const error = new Error(data.error || response.statusText || `HTTP ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

async function downloadAdminBackup(password) {
  const headers = { 'Content-Type': 'application/json' };
  const csrf = cookieValue('zentssh_csrf');
  if (csrf) headers['X-CSRF-Token'] = csrf;
  const response = await fetch(`${A}/admin/backup/export`, { method: 'POST', headers, body: JSON.stringify({ password }) });
  if (!response.ok) {
    const text = await response.text();
    let data = {};
    try { data = JSON.parse(text); } catch { data = { error: text }; }
    throw new Error(data.error || response.statusText || `HTTP ${response.status}`);
  }
  const blob = await response.blob();
  const disposition = response.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="([^"]+)"/i);
  const filename = match?.[1] || `zentssh-backup-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.zsb`;
  const href = URL.createObjectURL(blob);
  try {
    const link = document.createElement('a');
    link.href = href;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(href), 1000);
  }
}

async function reloadAfterRestore() {
  await new Promise(resolve => setTimeout(resolve, 1800));
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const response = await fetch(`${A}/health`, { cache: 'no-store' });
      if (response.ok) { location.reload(); return; }
    } catch { /* container is restarting */ }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  location.reload();
}

function consumeOIDCResult() {
  const url = new URL(location.href);
  const error = url.searchParams.get('oidc_error');
  const linked = url.searchParams.get('oidc_linked');
  if (error) state.notice = error;
  if (linked === '1') state.notice = L('SSO-Identität wurde erfolgreich mit deinem ZentSSH-Konto verknüpft.','SSO identity was linked to your ZentSSH account successfully.');
  if (error || linked) {
    url.searchParams.delete('oidc_error');
    url.searchParams.delete('oidc_linked');
    history.replaceState(null, '', url.pathname + url.search + url.hash);
  }
}

async function boot() {
  consumeOIDCResult();
  const setupState = await api('/setup/status');
  if (setupState.needed) return renderSetup();
  try {
    state.me = await api('/me');
    applyDocumentLanguage();
  } catch {
    return renderLogin();
  }
  await loadWorkspace();
  applyDocumentLanguage();
  renderApp();
  bootstrapTransferMonitor();
}

function renderSetup() {
  app.innerHTML = `
    <div class="auth">
      <div class="card authcard">
        <div class="authlogo"><img src="/zentssh-logo.png" alt="" aria-hidden="true"></div>
        <h1>ZentSSH</h1>
        <p>${L('Ersten Administrator anlegen. Danach kannst du sofort Server hinzufügen.','Create the first administrator. You can add servers immediately afterwards.')}</p>
        <label>${L('Name','Name')}<input id="setup-name" placeholder="Steffen" autocomplete="off"></label>
        <label>${L('E-Mail','Email')}<input id="setup-email" type="email" placeholder="admin@example.com" autocomplete="off"></label>
        <label>${L('Passwort','Password')}<input id="setup-password" type="password" placeholder="Mindestens 10 Zeichen" autocomplete="new-password"></label>
		<label>${L('Setup-Token','Setup token')}<input id="setup-token" type="password" autocomplete="off" placeholder="SETUP_TOKEN / Container-Log"></label>
        <button id="setup-submit" class="primary">${L('Admin erstellen','Create admin')}</button>
        <div id="setup-error" class="err"></div>
      </div>
    </div>`;
  $('#setup-submit').onclick = async () => {
    const error = $('#setup-error');
    error.textContent = '';
    try {
      await api('/setup', {
        method: 'POST',
        body: JSON.stringify({
          name: $('#setup-name').value.trim(),
          email: $('#setup-email').value.trim(),
          password: $('#setup-password').value,
		  setupToken: $('#setup-token').value,
        }),
      });
      location.reload();
    } catch (e) { error.textContent = e.message; }
  };
}

async function renderLogin(prefillEmail = '') {
  app.innerHTML = `
    <div class="auth">
      <div class="card authcard">
        <div class="authlogo"><img src="/zentssh-logo.png" alt="" aria-hidden="true"></div>
        <h1>ZentSSH</h1>
        <p>${L('SSH, Files und Server-Transfers in einem Workspace.','SSH, files and server transfers in one workspace.')}</p>
        ${state.notice ? `<div class="notice errornotice">${esc(state.notice)}</div>` : ''}
        <label>${L('E-Mail-Adresse','Email address')}<input id="login-email" type="email" value="${esc(prefillEmail)}" placeholder="name@example.com" autocomplete="username" autofocus></label>
        <button id="login-continue" class="primary">${L('Weiter','Continue')}</button>
        <div id="login-error" class="err"></div>
      </div>
    </div>`;
  const submit = async () => {
    const email = $('#login-email').value.trim();
    const error = $('#login-error');
    error.textContent = '';
    if (!email) { error.textContent = L('Bitte E-Mail-Adresse eingeben.','Enter your email address.'); return; }
    const button = $('#login-continue');
    setButtonBusy(button, true, L('Prüfe…','Checking…'));
    try {
      const result = await api('/login/discover', { method: 'POST', body: JSON.stringify({ email }) });
      if (result.method === 'sso' && result.providerId) {
        location.href = `${A}/auth/oidc/start?provider=${encodeURIComponent(result.providerId)}`;
        return;
      }
      if (result.method === 'unavailable') {
        error.textContent = L('Anmeldung mit dieser E-Mail-Adresse nicht möglich.','Sign-in with this email address is not available.');
        setButtonBusy(button, false);
        return;
      }
      renderPasswordLogin(email);
    } catch (e) {
      error.textContent = e.message;
      setButtonBusy(button, false);
    }
  };
  $('#login-continue').onclick = submit;
  $('#login-email').addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
}

function renderPasswordLogin(email) {
  app.innerHTML = `
    <div class="auth">
      <div class="card authcard">
        <div class="authlogo"><img src="/zentssh-logo.png" alt="" aria-hidden="true"></div>
        <h1>${L('Anmelden','Sign in')}</h1>
        <div class="login-identity">
          <div><small>${L('E-Mail-Adresse','Email address')}</small><b>${esc(email)}</b></div>
          <button id="login-change-email" type="button">${L('Ändern','Change')}</button>
        </div>
        <label>${L('Passwort','Password')}<input id="login-password" type="password" placeholder="${esc(L('Passwort','Password'))}" autocomplete="current-password" autofocus></label>
        <button id="login-submit" class="primary">${L('Anmelden','Sign in')}</button>
        <div id="login-error" class="err"></div>
      </div>
    </div>`;
  const submit = async () => {
    const error = $('#login-error');
    error.textContent = '';
    const button = $('#login-submit');
    setButtonBusy(button, true, L('Anmelden…','Signing in…'));
    try {
      const result = await api('/login', {
        method: 'POST',
        body: JSON.stringify({ email, password: $('#login-password').value }),
      });
      if (result.mfaRequired && result.challengeId) { renderMFALogin(result.challengeId, email); return; }
      location.reload();
    } catch (e) {
      if (e.data?.code === 'sso_required' && e.data?.providerId) {
        location.href = `${A}/auth/oidc/start?provider=${encodeURIComponent(e.data.providerId)}`;
        return;
      }
      error.textContent = e.message;
      setButtonBusy(button, false);
    }
  };
  $('#login-submit').onclick = submit;
  $('#login-password').addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  $('#login-change-email').onclick = () => renderLogin(email);
}

function renderMFALogin(challengeId, email = '') {
  app.innerHTML = `
    <div class="auth">
      <div class="card authcard">
        <div class="authlogo"><img src="/zentssh-logo.png" alt="" aria-hidden="true"></div>
        <h1>${L('Zwei-Faktor-Anmeldung','Two-factor sign-in')}</h1>
        <p>${L('Gib den 6-stelligen Code deiner Authenticator-App oder einen Recovery Code ein.','Enter the 6-digit code from your authenticator app or a recovery code.')}</p>
        <label>${L('MFA / Recovery Code','MFA / recovery code')}<input id="mfa-login-code" autocomplete="one-time-code" autofocus></label>
        <button id="mfa-login-submit" class="primary">${L('Anmelden','Sign in')}</button>
        <button id="mfa-login-back">${L('Zurück','Back')}</button>
        <div id="mfa-login-error" class="err"></div>
      </div>
    </div>`;
  const submit = async () => {
    const error = $('#mfa-login-error'); error.textContent = '';
    try { await api('/login/mfa', { method: 'POST', body: JSON.stringify({ challengeId, code: $('#mfa-login-code').value.trim() }) }); location.reload(); }
    catch (e) {
      if (e.data?.code === 'sso_required' && e.data?.providerId) { location.href = `${A}/auth/oidc/start?provider=${encodeURIComponent(e.data.providerId)}`; return; }
      error.textContent = e.message;
    }
  };
  $('#mfa-login-submit').onclick = submit;
  $('#mfa-login-code').addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  $('#mfa-login-back').onclick = () => email ? renderPasswordLogin(email) : renderLogin();
}

async function loadWorkspaceScope(workspaceId = state.activeWorkspaceId) {
  const query = Number(workspaceId) > 0 ? `?workspaceId=${encodeURIComponent(Number(workspaceId))}` : '';
  [state.servers, state.folders] = await Promise.all([api(`/servers${query}`), api(`/folders${query}`)]);
  state.selectedServerId = null;
}

function currentWorkspace() {
  const id = Number(state.activeWorkspaceId || 0);
  return id > 0 ? state.workspaces.find(item => Number(item.id) === id) || null : null;
}

function currentWorkspacePermissions() {
  const workspace = currentWorkspace();
  if (!workspace) return { canUse: true, canCreate: true, canEdit: true, canDelete: true, active: true };
  if (!workspace.active) return { canUse: false, canCreate: false, canEdit: false, canDelete: false, active: false };
  return { canUse: Boolean(workspace.canUse), canCreate: Boolean(workspace.canCreate), canEdit: Boolean(workspace.canEdit), canDelete: Boolean(workspace.canDelete), active: true };
}

function personalWorkspaceLabel() { return L('Mein Arbeitsbereich', 'My workspace'); }

async function loadWorkspace() {
  const previousWorkspace = Number(state.activeWorkspaceId || 0);
  const [workspaces, profiles, liveSessions, userSettings, snippetPermissions, serverTemplates] = await Promise.all([
    api('/workspaces'), api('/credential-profiles'), api('/sessions'), api('/me/settings'), api('/snippet-permissions'), api('/server-templates'),
  ]);
  state.workspaces = workspaces || [];
  state.profiles = profiles || [];
  state.liveSessions = liveSessions || [];
  state.userSettings = userSettings || state.userSettings;
  state.snippetPermissions = snippetPermissions || state.snippetPermissions;
  state.serverTemplates = serverTemplates || [];
  if (previousWorkspace > 0 && !state.workspaces.some(item => Number(item.id) === previousWorkspace)) state.activeWorkspaceId = 0;
  await loadWorkspaceScope(state.activeWorkspaceId);
}

async function switchWorkspace(workspaceId, options = {}) {
  const target = Number(workspaceId || 0);
  if (target > 0 && !state.workspaces.some(item => Number(item.id) === target)) return;
  state.activeWorkspaceId = target;
  state.serverSearchResults = [];
  state.serverSearchPending = false;
  const search = $('#server-search');
  if (search) search.value = '';
  const tree = $('#tree');
  if (tree) tree.innerHTML = `<div class="tree-loading">${esc(L('Lade…','Loading…'))}</div>`;
  try {
    await loadWorkspaceScope(target);
    const selector = $('#workspace-selector');
    if (selector) selector.value = String(target);
    syncWorkspaceControls();
    renderTree();
    if (options.selectServerId) {
      const row = $(`.server[data-id="${Number(options.selectServerId)}"]`);
      if (row) { selectServerRow(Number(options.selectServerId)); row.scrollIntoView({ block: 'nearest' }); }
    }
  } catch (e) {
    state.activeWorkspaceId = 0;
    showToast(e.message, true);
    await loadWorkspaceScope(0);
    if ($('#workspace-selector')) $('#workspace-selector').value = '0';
    syncWorkspaceControls();
    renderTree();
  }
}

function syncWorkspaceControls() {
  const permissions = currentWorkspacePermissions();
  const addServer = $('#add-server');
  const addFolder = $('#add-folder');
  if (addServer) addServer.disabled = !permissions.canCreate;
  if (addFolder) addFolder.disabled = !permissions.canCreate;
}

let serverSearchTimer = null;
function queueServerSearch() {
  const query = ($('#server-search')?.value || '').trim();
  clearTimeout(serverSearchTimer);
  state.serverSearchSequence += 1;
  const sequence = state.serverSearchSequence;
  if (!query) {
    state.serverSearchResults = [];
    state.serverSearchPending = false;
    renderTree();
    return;
  }
  state.serverSearchPending = true;
  renderTree();
  serverSearchTimer = setTimeout(async () => {
    try {
      const results = await api(`/server-search?q=${encodeURIComponent(query)}`);
      if (sequence !== state.serverSearchSequence) return;
      state.serverSearchResults = results || [];
    } catch (e) {
      if (sequence !== state.serverSearchSequence) return;
      state.serverSearchResults = [];
      showToast(e.message, true);
    } finally {
      if (sequence === state.serverSearchSequence) {
        state.serverSearchPending = false;
        renderTree();
      }
    }
  }, 180);
}

const LIVE_SESSION_KEY = 'zentssh.openSessions.v1';
const TAB_ORDER_KEY = 'zentssh.tabOrder.v1';
function trackedSessionIds() {
  try { return new Set(JSON.parse(localStorage.getItem(LIVE_SESSION_KEY) || '[]').filter(v => typeof v === 'string')); }
  catch { return new Set(); }
}
function saveTrackedSessionIds(ids) {
  localStorage.setItem(LIVE_SESSION_KEY, JSON.stringify([...ids]));
}
function trackSession(id) { const ids = trackedSessionIds(); ids.add(id); saveTrackedSessionIds(ids); }
function untrackSession(id) { const ids = trackedSessionIds(); ids.delete(id); saveTrackedSessionIds(ids); }
function tabStableKey(tab) {
  if (!tab) return '';
  if ((tab.type || 'terminal') === 'terminal' && tab.sessionId) return `terminal:${tab.sessionId}`;
  if (tab.type === 'files' && tab.serverId) return `files:${tab.serverId}`;
  return '';
}
function savedTabOrder() {
  try { return JSON.parse(localStorage.getItem(TAB_ORDER_KEY) || '[]').filter(v => typeof v === 'string'); }
  catch { return []; }
}
function saveTabOrder() {
  const keys = state.tabs.map(tabStableKey).filter(Boolean);
  localStorage.setItem(TAB_ORDER_KEY, JSON.stringify(keys));
}
function restoreTrackedSessions() {
  if (state.tabs.length) return;
  const wanted = trackedSessionIds();
  const order = savedTabOrder();
  const orderIndex = new Map(order.map((key, index) => [key, index]));
  const restorable = state.liveSessions
    .filter(s => wanted.has(s.id))
    .sort((a, b) => {
      const ai = orderIndex.has(`terminal:${a.id}`) ? orderIndex.get(`terminal:${a.id}`) : Number.MAX_SAFE_INTEGER;
      const bi = orderIndex.has(`terminal:${b.id}`) ? orderIndex.get(`terminal:${b.id}`) : Number.MAX_SAFE_INTEGER;
      return ai - bi;
    });
  for (const live of restorable) {
    const server = state.servers.find(s => s.id === live.serverId) || { id: live.serverId || 0, name: live.serverName, host: live.host, username: live.username, port: live.port || 22, color: '#35a4ff' };
    const tid = `t${Date.now()}${Math.random().toString(16).slice(2, 7)}`;
    state.tabs.push({ id: tid, type: 'terminal', name: live.serverName || server.name, serverId: live.serverId, sessionId: live.id, reconnectDelay: 750, serverSnapshot: server });
  }
  // Remove markers for sessions that no longer exist server-side.
  const existing = new Set(state.liveSessions.map(s => s.id));
  for (const id of wanted) if (!existing.has(id)) wanted.delete(id);
  saveTrackedSessionIds(wanted);
  if (!state.tabs.length) return;
  saveTabOrder();
  state.active = state.tabs[0].id;
  const tab = state.tabs[0];
  const server = state.servers.find(s => s.id === tab.serverId) || tab.serverSnapshot;
  paintTerminal(tab.id, server);
  renderTabs();
  setTimeout(() => startTerminal(tab.id, server), 0);
}

function renderApp() {
  closeServerContextMenu();
  const workspaceSelector = state.workspaces.length ? `<div class="workspace-switcher"><select id="workspace-selector" aria-label="${esc(L('Arbeitsbereich auswählen','Select workspace'))}"><option value="0">${esc(personalWorkspaceLabel())}</option>${state.workspaces.map(workspace => `<option value="${workspace.id}">${esc(workspace.name)}${workspace.active ? '' : ` · ${esc(L('deaktiviert','disabled'))}`}</option>`).join('')}</select></div>` : '';
  app.innerHTML = `
    <div class="shell">
      <aside>
        <div class="brand"><div class="brand-identity"><img class="brand-logo" src="/zentssh-logo.png" alt="" aria-hidden="true"><div class="brand-copy"><b>ZentSSH</b><small>Workspace</small></div></div><button id="profile-menu" class="brand-profile" type="button" data-tooltip="${esc(L('Mein Profil','My profile'))}">${esc(state.me?.name || '')}</button></div>
        <div class="toolbar"><div class="toolbar-create"><button id="add-server"><span class="toolbar-action-icon">+</span><span>${L('Server','Server')}</span></button><button id="add-folder"><span class="toolbar-action-icon">+</span><span>${L('Ordner','Folder')}</span></button></div><button id="quick-connect" class="quick-connect-button"><span class="toolbar-action-icon">⚡</span><span>Quick Connect</span></button></div>
        ${workspaceSelector}
        <div class="search"><input id="server-search" placeholder="${esc(L('Server suchen','Search servers'))}" autocomplete="off"></div>
        <div id="tree" class="tree"></div>
        <div class="asidefoot">
          <button id="transfers">⇄ ${L('Transfers','Transfers')}</button>
          <button id="settings">⚙ ${L('Einstellungen','Settings')}</button>
          <button id="logout">${L('Abmelden','Sign out')}</button>
        </div>
      </aside>
      <main>
        <div id="tabs" class="tabs"></div>
        <div id="workspace" class="workspace">
          <div class="empty"><h2>${L('Server auswählen → arbeiten.','Select a server → start working.')}</h2><p>${L('Rechtsklick auf einen Server öffnet SSH, Transfer und Einstellungen.','Right-click a server to open SSH, file transfer or settings.')}</p></div>
        </div>
      </main>
      <div id="modal"></div>
      <div id="server-context-menu" class="server-context-menu app-context-menu" hidden></div>
      <div id="file-context-menu" class="file-context-menu app-context-menu" hidden></div>
    </div>`;
  installModalAutofocus();
  $('#logout').onclick = async () => { await api('/logout', { method: 'POST' }); location.reload(); };
  $('#settings').onclick = () => openSettings();
  $('#profile-menu').onclick = () => openProfile();
  if ($('#transfers')) $('#transfers').onclick = () => openTransferCenter();
  if ($('#add-server')) $('#add-server').onclick = () => serverModal();
  if ($('#add-folder')) $('#add-folder').onclick = () => folderModal();
  if ($('#quick-connect')) $('#quick-connect').onclick = () => quickConnectModal();
  if ($('#workspace-selector')) {
    $('#workspace-selector').value = String(Number(state.activeWorkspaceId || 0));
    $('#workspace-selector').onchange = () => switchWorkspace(Number($('#workspace-selector').value || 0));
  }
  $('#server-search').oninput = queueServerSearch;
  syncWorkspaceControls();
  renderTree();
  renderTabs();
  restoreTrackedSessions();
  if (state.notice) {
    showToast(state.notice);
    state.notice = '';
  }
}

function renderTree() {
  const tree = $('#tree');
  if (!tree) return;
  const query = ($('#server-search')?.value || '').trim();
  if (query) {
    if (state.serverSearchPending) {
      tree.innerHTML = `<div class="tree-loading">${esc(L('Suche…','Searching…'))}</div>`;
      return;
    }
    const results = state.serverSearchResults || [];
    tree.innerHTML = results.length ? `<div class="server-search-results">${results.map(result => `<button class="server-search-result" type="button" data-id="${result.id}" data-workspace-id="${result.workspaceId || 0}"><span class="server-status unknown"></span><span class="server-meta"><strong>${esc(result.name)}</strong><small>${esc(result.username || '')}${result.username ? '@' : ''}${esc(result.host)}</small><em>${esc(result.workspaceName || personalWorkspaceLabel())}${result.templateName ? ` · ${esc(L('Vorlage','Template'))}: ${esc(result.templateName)}` : ''}</em></span></button>`).join('')}</div>` : `<div class="tree-empty">${esc(L('Keine Server gefunden.','No servers found.'))}</div>`;
    $$('.server-search-result', tree).forEach(row => row.onclick = () => switchWorkspace(Number(row.dataset.workspaceId || 0), { selectServerId: Number(row.dataset.id) }));
    return;
  }
  const permissions = currentWorkspacePermissions();
  const canManageFolders = permissions.canEdit || permissions.canDelete;
  const byParent = new Map();
  for (const folder of state.folders) {
    const key = folder.parentId ?? 0;
    if (!byParent.has(key)) byParent.set(key, []);
    byParent.get(key).push(folder);
  }
  const serverRows = (folderId, depth) => state.servers
    .filter(s => (s.folderId ?? 0) === folderId)
    .map(s => {
      const canDrag = permissions.canEdit && s.canEdit !== false;
      const inherited = s.templateId ? `<span class="server-template-mark" data-tooltip="${esc(L('Infrastruktur wird von einer Server-Vorlage geerbt','Infrastructure is inherited from a server template'))}">↻</span>` : '';
      return `<div class="server ${canDrag ? 'can-drag' : ''} ${Number(state.selectedServerId) === Number(s.id) ? 'selected' : ''}" data-id="${s.id}" style="--depth:${depth}" tabindex="0" aria-selected="${Number(state.selectedServerId) === Number(s.id) ? 'true' : 'false'}">
      <div class="server-indicators"><span class="server-status ${esc(state.serverStatus[s.id]?.status || 'unknown')}" data-tooltip="${esc(serverStatusLabel(state.serverStatus[s.id]?.status || 'unknown'))}" aria-label="${esc(serverStatusLabel(state.serverStatus[s.id]?.status || 'unknown'))}"></span>${inherited}</div>
      <div class="server-meta"><strong>${esc(s.name)}</strong><small>${esc(s.username)}@${esc(s.host)}:${Number(s.port || 22)}</small></div>
    </div>`;
    }).join('');
  const collapsedFolderIds = new Set((state.userSettings?.collapsedFolderIds || []).map(Number));
  const folderRows = (parentId = 0, depth = 0) => (byParent.get(parentId) || []).map(folder => {
    const collapsed = collapsedFolderIds.has(Number(folder.id));
    return `
    <div class="folder-group ${collapsed ? 'collapsed' : ''}" data-folder-id="${folder.id}">
      <div class="folder" data-id="${folder.id}" style="padding-left:${10 + depth * 12}px" role="button" tabindex="0" aria-expanded="${collapsed ? 'false' : 'true'}"><span class="folder-label"><span class="folder-chevron" aria-hidden="true">${collapsed ? '▸' : '▾'}</span><span>${esc(folder.name)}</span></span>${canManageFolders ? '<button class="manage-folder" aria-label="Ordner bearbeiten">⋮</button>' : ''}</div>
      <div class="folder-children">${serverRows(folder.id, depth + 1)}${folderRows(folder.id, depth + 1)}</div>
    </div>`;
  }).join('');
  const rootDrop = permissions.canEdit ? '<div class="tree-root-drop" data-folder-id=""><span>↰</span> Oberste Ebene</div>' : '';
  tree.innerHTML = rootDrop + serverRows(0, 0) + folderRows();

  $$('.server', tree).forEach(row => {
    const id = Number(row.dataset.id);
    const server = state.servers.find(item => Number(item.id) === id);
    row.onclick = () => {
      if (Date.now() < state.suppressServerClickUntil) return;
      selectServerRow(id, tree);
    };
    row.oncontextmenu = event => {
      event.preventDefault();
      selectServerRow(id, tree);
      showServerContextMenu(event, id, row);
    };
    row.onkeydown = event => {
      if (event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')) {
        event.preventDefault();
        row.oncontextmenu({ preventDefault() {}, clientX: 0, clientY: 0 });
      }
    };
    if (permissions.canEdit && server?.canEdit !== false) row.onpointerdown = event => startServerPointerDrag(event, row, id, tree);
  });
  $$('.folder', tree).forEach(row => {
    const toggle = () => toggleFolderCollapsed(Number(row.dataset.id), row.closest('.folder-group'));
    row.onclick = event => {
      if (event.target.closest('.manage-folder')) return;
      toggle();
    };
    row.onkeydown = event => {
      if (event.target.closest('.manage-folder')) return;
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        toggle();
      }
    };
  });
  $$('.manage-folder', tree).forEach(button => button.onclick = event => {
    event.stopPropagation();
    const row = button.closest('.folder');
    folderModal(state.folders.find(f => Number(f.id) === Number(row.dataset.id)) || {});
  });
  scheduleServerStatusChecks(state.servers.filter(server => server.canUse !== false).map(server => Number(server.id)));
}

let folderCollapseSaveTimer = null;

function normalizedCollapsedFolderIds(values = state.userSettings?.collapsedFolderIds) {
  return [...new Set((Array.isArray(values) ? values : []).map(Number).filter(id => Number.isInteger(id) && id > 0))];
}

function scheduleFolderCollapseSave() {
  clearTimeout(folderCollapseSaveTimer);
  folderCollapseSaveTimer = setTimeout(async () => {
    const collapsedFolderIds = normalizedCollapsedFolderIds();
    state.userSettings.collapsedFolderIds = collapsedFolderIds;
    try {
      const saved = await api('/me/settings', { method: 'PATCH', body: JSON.stringify({
        sshSessionRetention: state.userSettings.sshSessionRetention || 'inherit',
        showHiddenFiles: Boolean(state.userSettings.showHiddenFiles),
        language: state.userSettings.language || state.me?.language || uiLanguage(),
        collapsedFolderIds,
      }) });
      state.userSettings = { ...state.userSettings, ...saved };
    } catch (e) {
      showToast(L('Ordnerzustand konnte nicht gespeichert werden.','Folder state could not be saved.'), true);
    }
  }, 180);
}

function toggleFolderCollapsed(folderId, group = null) {
  if (!Number.isInteger(Number(folderId))) return;
  const collapsed = new Set(normalizedCollapsedFolderIds());
  const id = Number(folderId);
  if (collapsed.has(id)) collapsed.delete(id);
  else collapsed.add(id);
  state.userSettings.collapsedFolderIds = [...collapsed];
  if (group) {
    const isCollapsed = collapsed.has(id);
    group.classList.toggle('collapsed', isCollapsed);
    const row = $('.folder', group);
    if (row) {
      row.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
      const chevron = $('.folder-chevron', row);
      if (chevron) chevron.textContent = isCollapsed ? '▸' : '▾';
    }
  } else renderTree();
  scheduleFolderCollapseSave();
}

function selectServerRow(id, tree = $('#tree')) {
  state.selectedServerId = id;
  if (!tree) return;
  $$('.server', tree).forEach(other => {
    const selected = Number(other.dataset.id) === Number(id);
    other.classList.toggle('selected', selected);
    other.setAttribute('aria-selected', selected ? 'true' : 'false');
  });
}

function clearServerDropTargets(tree = $('#tree')) {
  if (!tree) return;
  $$('.server-drop-target', tree).forEach(element => element.classList.remove('server-drop-target'));
}

function resolveServerDropTarget(clientX, clientY, tree) {
  const hit = document.elementFromPoint(clientX, clientY);
  if (!hit || !tree?.contains(hit)) return null;
  const root = hit.closest('.tree-root-drop');
  if (root && tree.contains(root)) return { folderId: null, element: root };
  const folder = hit.closest('.folder');
  if (folder && tree.contains(folder)) return { folderId: Number(folder.dataset.id), element: folder.closest('.folder-group') || folder };
  const group = hit.closest('.folder-group');
  if (group && tree.contains(group)) return { folderId: Number(group.dataset.folderId), element: group };
  return { folderId: null, element: $('.tree-root-drop', tree) };
}

function autoScrollServerTree(clientY, tree) {
  const rect = tree?.getBoundingClientRect();
  if (!rect) return;
  const edge = 42;
  if (clientY < rect.top + edge) tree.scrollTop -= Math.max(4, Math.ceil((rect.top + edge - clientY) / 3));
  else if (clientY > rect.bottom - edge) tree.scrollTop += Math.max(4, Math.ceil((clientY - (rect.bottom - edge)) / 3));
}

function startServerPointerDrag(event, row, serverId, tree) {
  if (event.button !== 0 || !event.isPrimary || event.target.closest('button')) return;
  const startX = event.clientX;
  const startY = event.clientY;
  const pointerId = event.pointerId;
  let armed = false;
  let dragging = false;
  let ghost = null;
  let latestEvent = event;
  let distance = 0;
  const armTimer = setTimeout(() => {
    armed = true;
    row.classList.add('drag-armed');
    if (!dragging && distance >= 5) startDragging(latestEvent);
  }, 140);

  const cleanup = () => {
    clearTimeout(armTimer);
    document.removeEventListener('pointermove', onMove, true);
    document.removeEventListener('pointerup', onUp, true);
    document.removeEventListener('pointercancel', onCancel, true);
    ghost?.remove();
    state.draggingServerId = null;
    state.serverDragTargetFolderId = undefined;
    tree.classList.remove('server-dragging');
    row.classList.remove('dragging', 'drag-armed');
    document.body.classList.remove('server-drag-active');
    clearServerDropTargets(tree);
  };

  const startDragging = currentEvent => {
    if (!armed || dragging) return;
    dragging = true;
    state.draggingServerId = serverId;
    state.serverDragTargetFolderId = undefined;
    closeContextMenus();
    tree.classList.add('server-dragging');
    row.classList.add('dragging');
    document.body.classList.add('server-drag-active');
    const server = state.servers.find(item => Number(item.id) === Number(serverId));
    ghost = document.createElement('div');
    ghost.className = 'server-drag-ghost';
    ghost.innerHTML = `<span>${actionIcon('terminal')}</span><div><b>${esc(server?.name || 'Server')}</b><small>${esc(server?.host || '')}</small></div>`;
    document.body.appendChild(ghost);
    moveGhost(currentEvent);
  };

  const moveGhost = currentEvent => {
    if (!ghost) return;
    ghost.style.left = `${currentEvent.clientX + 14}px`;
    ghost.style.top = `${currentEvent.clientY + 14}px`;
  };

  const updateTarget = currentEvent => {
    clearServerDropTargets(tree);
    const target = resolveServerDropTarget(currentEvent.clientX, currentEvent.clientY, tree);
    state.serverDragTargetFolderId = target ? target.folderId : undefined;
    if (target?.element) target.element.classList.add('server-drop-target');
  };

  const onMove = currentEvent => {
    if (currentEvent.pointerId !== pointerId) return;
    latestEvent = currentEvent;
    distance = Math.hypot(currentEvent.clientX - startX, currentEvent.clientY - startY);
    if (!dragging && armed && distance >= 5) startDragging(currentEvent);
    if (!dragging) return;
    currentEvent.preventDefault();
    moveGhost(currentEvent);
    autoScrollServerTree(currentEvent.clientY, tree);
    updateTarget(currentEvent);
  };

  const onUp = async currentEvent => {
    if (currentEvent.pointerId !== pointerId) return;
    if (!dragging) {
      cleanup();
      return;
    }
    currentEvent.preventDefault();
    const targetFolderId = state.serverDragTargetFolderId;
    state.suppressServerClickUntil = Date.now() + 300;
    cleanup();
    if (targetFolderId !== undefined) await moveServerToFolder(serverId, targetFolderId);
  };

  const onCancel = currentEvent => {
    if (currentEvent.pointerId !== pointerId) return;
    if (dragging) state.suppressServerClickUntil = Date.now() + 300;
    cleanup();
  };

  document.addEventListener('pointermove', onMove, { capture: true, passive: false });
  document.addEventListener('pointerup', onUp, true);
  document.addEventListener('pointercancel', onCancel, true);
}

async function moveServerToFolder(serverId, folderId) {
  const server = state.servers.find(item => Number(item.id) === Number(serverId));
  if (!server) return;
  const currentFolderId = server.folderId == null ? null : Number(server.folderId);
  const targetFolderId = folderId == null ? null : Number(folderId);
  if (currentFolderId === targetFolderId) return;
  try {
    const result = await api(`/servers/${serverId}/folder`, { method: 'PATCH', body: JSON.stringify({ folderId: targetFolderId }) });
    server.folderId = result.folderId == null ? null : Number(result.folderId);
    renderTree();
    const folder = targetFolderId == null ? null : state.folders.find(item => Number(item.id) === targetFolderId);
    showToast(folder ? `„${server.name}“ nach „${folder.name}“ verschoben.` : `„${server.name}“ auf die oberste Ebene verschoben.`);
  } catch (e) {
    renderTree();
    showToast(e.message, true);
  }
}

function closeContextMenus() {
  const serverClosed = closeServerContextMenu();
  const fileClosed = closeFileContextMenu();
  return serverClosed || fileClosed;
}

function closeServerContextMenu() {
  const menu = $('#server-context-menu');
  if (!menu || menu.hidden) return false;
  menu.hidden = true;
  menu.innerHTML = '';
  state.selectedServerId = null;
  const tree = $('#tree');
  if (tree) {
    $$('.server.selected', tree).forEach(row => {
      row.classList.remove('selected');
      row.setAttribute('aria-selected', 'false');
    });
  }
  return true;
}

function actionIcon(type) {
  const icons = {
    terminal: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h16v14H4z"/><path d="m7 9 3 3-3 3M12 15h5"/></svg>',
    server: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01M12 6.5h5M12 17.5h5"/></svg>',
    files: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6.5a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v8.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M8 13h8M13 10l3 3-3 3"/></svg>',
    settings: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.09a2 2 0 0 1 1 1.74v.5a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.38a2 2 0 0 0-.73-2.73l-.15-.09a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2Z"/><circle cx="12" cy="12" r="3"/></svg>',
    eye: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/></svg>',
    eyeOff: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18"/><path d="M10.6 6.2A10 10 0 0 1 12 6c6 0 9.5 6 9.5 6a15 15 0 0 1-2.6 3.2M6.2 6.2C3.8 8 2.5 12 2.5 12s3.5 6 9.5 6a9.6 9.6 0 0 0 3.3-.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>',
    plus: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>',
    new: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h10l3 3h3v11H4z"/><path d="M12 10v6M9 13h6"/></svg>',
    upload: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16V4M8 8l4-4 4 4"/><path d="M5 13v6h14v-6"/></svg>',
    urlUpload: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.1.1l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.1-.1l-2 2A5 5 0 0 0 12 20l1.1-1.1"/><path d="M12 8v8M9 13l3 3 3-3"/></svg>',
    dual: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5" width="7" height="14" rx="1"/><rect x="14" y="5" width="7" height="14" rx="1"/><path d="m11 9 2-2M13 17l-2-2"/></svg>',
    open: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7h7l2 2h9v10H3z"/><path d="m13 12 3 3-3 3"/></svg>',
    edit: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20h4l11-11-4-4L4 16z"/><path d="m13.5 6.5 4 4"/></svg>',
    download: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v12M8 12l4 4 4-4"/><path d="M5 20h14"/></svg>',
    rename: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 7h10M5 17h10M9 4v16"/><path d="m16 12 3-3 2 2-3 3-3 1z"/></svg>',
    permissions: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="8" cy="12" r="4"/><path d="M12 12h9M17 12v3M20 12v2"/></svg>',
    owner: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3"/><path d="M3.5 19a5.5 5.5 0 0 1 11 0"/><path d="M17 10h4M19 8v4"/></svg>',
    transfer: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h14M14 3l4 4-4 4M20 17H6M10 13l-4 4 4 4"/></svg>',
    delete: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13"/><path d="M10 11v5M14 11v5"/></svg>',
    search: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>',
    clock: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
    retry: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 7v5h-5"/><path d="M19 12a7 7 0 1 0-2 5"/></svg>',
    refresh: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 7v5h-5"/><path d="M19 12a7 7 0 1 0-2 5"/></svg>',
    newFile: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5M12 11v6M9 14h6"/></svg>',
    newFolder: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h7l2 2h9v11H3z"/><path d="M12 11v5M9.5 13.5h5"/></svg>',
    folder: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h7l2 2h9v11H3z"/></svg>',
    file: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5"/></svg>',
    image: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m5 17 4.5-4.5 3 3 2.5-2.5 4 4"/></svg>',
    code: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m8 8-4 4 4 4M16 8l4 4-4 4M14 4l-4 16"/></svg>',
    profile: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>',
    shield: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 20 6v5c0 5-3.3 8.2-8 10-4.7-1.8-8-5-8-10V6z"/><path d="m9 12 2 2 4-4"/></svg>',
    key: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="8" cy="12" r="4"/><path d="M12 12h9M17 12v3M20 12v2"/></svg>',
    users: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3"/><path d="M3 20a6 6 0 0 1 12 0"/><circle cx="17" cy="9" r="2"/><path d="M16 15a5 5 0 0 1 5 5"/></svg>',
    activity: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12h4l2-6 4 12 2-6h6"/></svg>',
    import: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12M8 11l4 4 4-4"/><path d="M4 20h16"/></svg>',
    provider: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/></svg>',
    backup: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="5" rx="1.5"/><path d="M5 9v10h14V9"/><path d="M9 13h6"/></svg>',
    link: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.1.1l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.1-.1l-2 2A5 5 0 0 0 12 20l1.1-1.1"/></svg>',
    copy: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
    shared: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 12h8M12 8v8"/><circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="12" cy="19" r="2"/><path d="m7.5 7.5 3 8M16.5 7.5l-3 8"/></svg>',
  };
  return icons[type] || icons.file;
}

function iconLabel(type, label) {
  return `<span class="button-icon">${actionIcon(type)}</span><span>${esc(label)}</span>`;
}

function serverMenuIcon(type) {
  return actionIcon(type === 'files' ? 'files' : type === 'settings' ? 'settings' : 'terminal');
}

function positionContextMenu(menu, event, row) {
  const rect = row?.getBoundingClientRect();
  const anchorX = Number(event.clientX) || (rect ? rect.left + Math.min(rect.width - 12, 42) : 12);
  const anchorY = Number(event.clientY) || (rect ? rect.top + Math.min(rect.height - 8, 28) : 12);
  requestAnimationFrame(() => {
    const bounds = menu.getBoundingClientRect();
    menu.style.left = `${Math.max(8, Math.min(anchorX, window.innerWidth - bounds.width - 8))}px`;
    menu.style.top = `${Math.max(8, Math.min(anchorY, window.innerHeight - bounds.height - 8))}px`;
    $('button', menu)?.focus({ preventScroll: true });
  });
}

function showServerContextMenu(event, serverId, row) {
  const menu = $('#server-context-menu');
  const server = state.servers.find(item => Number(item.id) === Number(serverId));
  if (!menu || !server) return;
  const items = [
    ...(server.canUse !== false ? [{ action: 'ssh', label: 'SSH', icon: serverMenuIcon('terminal') }, { action: 'files', label: 'Transfer', icon: serverMenuIcon('files') }] : []),
    ...((server.canEdit !== false || server.canDelete !== false) ? [{ action: 'settings', label: L('Einstellungen','Settings'), icon: serverMenuIcon('settings') }] : []),
  ];
  menu.innerHTML = `<div class="server-context-title"><strong>${esc(server.name)}</strong><small>${esc(server.username)}@${esc(server.host)}:${Number(server.port || 22)}</small></div>${items.map(item => `<button data-action="${item.action}"><span>${item.icon}</span><b>${item.label}</b></button>`).join('')}`;
  menu.hidden = false;
  menu.oncontextmenu = e => e.preventDefault();
  positionContextMenu(menu, event, row);
  $$('button[data-action]', menu).forEach(button => {
    button.onclick = () => {
      const action = button.dataset.action;
      closeServerContextMenu();
      if (action === 'ssh') openTerm(serverId);
      else if (action === 'files') openFiles(serverId);
      else if (action === 'settings') serverModal(server);
    };
  });
}



function serverStatusLabel(status) {
  return ({ active: 'Aktive SSH-Session', reachable: 'Erreichbar', unreachable: 'Nicht erreichbar', unknown: 'Unbekannt' })[status] || 'Unbekannt';
}

function scheduleServerStatusChecks(ids) {
  const now = Date.now();
  const queue = ids.filter(id => {
    const cached = state.serverStatus[id];
    return !state.statusPending.has(id) && (!cached || now - cached.checkedAt > 60000);
  });
  if (!queue.length) return;
  let cursor = 0;
  const worker = async () => {
    while (cursor < queue.length) {
      const id = queue[cursor++]; state.statusPending.add(id);
      try {
        const result = await api(`/servers/${id}/status`);
        state.serverStatus[id] = { status: result.status || 'unknown', checkedAt: Date.now() };
      } catch { state.serverStatus[id] = { status: 'unknown', checkedAt: Date.now() }; }
      finally { state.statusPending.delete(id); }
      const row = $(`.server[data-id="${id}"]`);
      const dot = row?.querySelector('.server-status');
      if (dot) { const status = state.serverStatus[id]?.status || 'unknown'; const label = serverStatusLabel(status); dot.className = `server-status ${status}`; dot.dataset.tooltip = label; dot.setAttribute('aria-label', label); }
    }
  };
  for (let i = 0; i < Math.min(4, queue.length); i++) worker();
}

function tabIcon(type) {
  return actionIcon(type === 'files' ? 'files' : 'terminal');
}

function renderTabs() {
  const tabs = $('#tabs');
  if (!tabs) return;
  tabs.innerHTML = state.tabs.map(t => {
    const type = t.type || 'terminal';
    const label = type === 'files' ? `${t.name} · Files` : t.name;
    const server = state.servers.find(s => Number(s.id) === Number(t.serverId)) || t.serverSnapshot;
    const color = normalizeHexColor(server?.color, '#35a4ff');
    return `<div class="tab ${state.active === t.id ? 'active' : ''}" data-id="${t.id}" data-type="${type}" style="--tab-color:${esc(color)}"><span class="tab-kind">${tabIcon(type)}</span><span class="tab-label">${esc(label)}</span><button class="tab-close" aria-label="Tab schließen">×</button></div>`;
  }).join('');
  $$('.tab', tabs).forEach(tab => {
    tab.onclick = event => {
      if (Date.now() < state.suppressTabClickUntil) return;
      const id = tab.dataset.id;
      if (event.target.closest('.tab-close')) closeTab(id);
      else activate(id);
    };
    tab.onpointerdown = event => startTabPointerDrag(event, tab, tabs);
  });
}

function startTabPointerDrag(event, tab, tabs) {
  if (event.button !== 0 || !event.isPrimary || event.target.closest('button')) return;
  const pointerId = event.pointerId;
  const startX = event.clientX;
  const startY = event.clientY;
  let latestEvent = event;
  let distance = 0;
  let armed = false;
  let dragging = false;
  const armTimer = setTimeout(() => {
    armed = true;
    tab.classList.add('drag-armed');
    if (distance >= 5) startDragging(latestEvent);
  }, 140);

  const cleanup = () => {
    clearTimeout(armTimer);
    document.removeEventListener('pointermove', onMove, true);
    document.removeEventListener('pointerup', onUp, true);
    document.removeEventListener('pointercancel', onCancel, true);
    state.draggingTabId = null;
    tab.classList.remove('drag-armed', 'dragging');
    document.body.classList.remove('tab-drag-active');
    clearTabDropMarkers(tabs);
  };

  const startDragging = currentEvent => {
    if (!armed || dragging) return;
    dragging = true;
    state.draggingTabId = tab.dataset.id;
    tab.classList.add('dragging');
    document.body.classList.add('tab-drag-active');
    closeContextMenus();
    updateTarget(currentEvent);
  };

  const updateTarget = currentEvent => {
    clearTabDropMarkers(tabs);
    const hit = document.elementFromPoint(currentEvent.clientX, currentEvent.clientY);
    const target = hit?.closest?.('.tab');
    if (target && tabs.contains(target) && target !== tab) {
      const rect = target.getBoundingClientRect();
      target.classList.add(currentEvent.clientX >= rect.left + rect.width / 2 ? 'drop-after' : 'drop-before');
      return;
    }
    const rect = tabs.getBoundingClientRect();
    if (currentEvent.clientX >= rect.left && currentEvent.clientX <= rect.right && currentEvent.clientY >= rect.top && currentEvent.clientY <= rect.bottom) tabs.classList.add('drop-at-end');
  };

  const onMove = currentEvent => {
    if (currentEvent.pointerId !== pointerId) return;
    latestEvent = currentEvent;
    distance = Math.hypot(currentEvent.clientX - startX, currentEvent.clientY - startY);
    if (!dragging && armed && distance >= 5) startDragging(currentEvent);
    if (!dragging) return;
    currentEvent.preventDefault();
    updateTarget(currentEvent);
  };

  const onUp = currentEvent => {
    if (currentEvent.pointerId !== pointerId) return;
    if (!dragging) { cleanup(); return; }
    currentEvent.preventDefault();
    const target = $('.tab.drop-before,.tab.drop-after', tabs);
    const atEnd = tabs.classList.contains('drop-at-end');
    const targetId = target?.dataset.id;
    const placeAfter = Boolean(target?.classList.contains('drop-after'));
    const dragId = tab.dataset.id;
    state.suppressTabClickUntil = Date.now() + 260;
    cleanup();
    if (targetId && targetId !== dragId) reorderTab(dragId, targetId, placeAfter);
    else if (atEnd) moveTabToEnd(dragId);
  };

  const onCancel = currentEvent => {
    if (currentEvent.pointerId !== pointerId) return;
    if (dragging) state.suppressTabClickUntil = Date.now() + 260;
    cleanup();
  };

  document.addEventListener('pointermove', onMove, { capture: true, passive: false });
  document.addEventListener('pointerup', onUp, true);
  document.addEventListener('pointercancel', onCancel, true);
}

function clearTabDropMarkers(tabs = $('#tabs')) {
  if (!tabs) return;
  $$('.tab.drop-before,.tab.drop-after', tabs).forEach(tab => tab.classList.remove('drop-before', 'drop-after'));
  tabs.classList.remove('drop-at-end');
}

function reorderTab(dragId, targetId, placeAfter) {
  const fromIndex = state.tabs.findIndex(tab => tab.id === dragId);
  if (fromIndex < 0) return;
  const [moved] = state.tabs.splice(fromIndex, 1);
  let targetIndex = state.tabs.findIndex(tab => tab.id === targetId);
  if (targetIndex < 0) {
    state.tabs.splice(fromIndex, 0, moved);
    return;
  }
  if (placeAfter) targetIndex += 1;
  state.tabs.splice(targetIndex, 0, moved);
  saveTabOrder();
  renderTabs();
}

function moveTabToEnd(dragId) {
  const fromIndex = state.tabs.findIndex(tab => tab.id === dragId);
  if (fromIndex < 0 || fromIndex === state.tabs.length - 1) {
    clearTabDropMarkers();
    return;
  }
  const [moved] = state.tabs.splice(fromIndex, 1);
  state.tabs.push(moved);
  saveTabOrder();
  renderTabs();
}


function quickConnectModal() {
  const modal = $('#modal');
  const profileOptions = state.profiles.map(p => `<option value="${p.id}">${esc(p.name)} · ${esc(p.username)}${p.isOwner ? '' : ' · geteilt'}</option>`).join('');
  const jumpOptions = state.servers.filter(s => s.kind === 'ssh' && s.canUse !== false).map(s => `<option value="${s.id}">${esc(s.name)} · ${esc(s.host)}</option>`).join('');
  modal.innerHTML = `<div class="backdrop"><div class="dialog quickdialog modal-scroll">
    <div class="dialogtitle"><div><h3>Quick Connect</h3><p>Direkt verbinden, ohne vorher einen Server anlegen zu müssen.</p></div><button data-close class="iconbutton" aria-label="Schließen">×</button></div>
    <label>Ziel<input id="quick-target" placeholder="root@192.168.1.20 · user@host:2222 · ssh user@host -p 2222" autocomplete="off" autofocus></label>
    <label>Zugangsvorlage<select id="quick-profile"><option value="">Direkte Zugangsdaten</option>${profileOptions}</select></label>
    <div id="quick-inline">
      <label>Authentifizierung<select id="quick-auth"><option value="password">Passwort</option><option value="keyboard-interactive">Keyboard Interactive</option><option value="key">Private Key</option></select></label>
      <label id="quick-password-label"><span id="quick-password-title">Passwort</span><input id="quick-password" type="password" autocomplete="off"></label>
      <label id="quick-key-label" style="display:none">Private Key<textarea id="quick-key" autocomplete="off" spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></label>
      <label id="quick-passphrase-label" style="display:none">Key Passphrase<input id="quick-passphrase" type="password" autocomplete="off"></label>
      <label id="quick-cert-label" style="display:none">OpenSSH User Certificate<textarea id="quick-cert" autocomplete="off" spellcheck="false"></textarea></label>
    </div>
    <label>Jump Host<select id="quick-jump"><option value="">Direkt verbinden</option>${jumpOptions}</select></label>
    <label class="toggle-row"><span><b>Als Server speichern</b><small>${esc(currentWorkspace() ? `${L('Speichern in','Save to')} „${currentWorkspace().name}“` : L('Nach erfolgreicher Verbindung dauerhaft in ZentSSH anlegen.','Save permanently in ZentSSH after a successful connection.'))}</small></span><input id="quick-save" type="checkbox" aria-label="Als Server speichern" ${currentWorkspacePermissions().canCreate ? '' : 'disabled'}></label><label id="quick-save-name-label" style="display:none">Servername<input id="quick-save-name" placeholder="web01" autocomplete="off"></label>
    <div class="securitynote"><b>Host-Key-Schutz:</b> Ein bestätigter Quick-Connect-Host-Key wird für dich gespeichert. Solange sich Key, Host, Port und Route nicht ändern, fragt ZentSSH nicht erneut.</div>
    <div id="quick-error" class="err"></div>
    <div class="actions"><button data-cancel>Abbrechen</button><button id="quick-start" class="primary">Verbinden</button></div>
  </div></div>`;
  $('[data-close]', modal).onclick = () => { modal.innerHTML = ''; };
  $('[data-cancel]', modal).onclick = () => { modal.innerHTML = ''; };
  const sync = () => {
    const profile = $('#quick-profile').value !== '';
    $('#quick-inline').classList.toggle('disabledsection', profile);
    for (const el of $$('input,select,textarea', $('#quick-inline'))) el.disabled = profile;
    const isKey = !profile && $('#quick-auth').value === 'key';
    $('#quick-password-label').style.display = isKey ? 'none' : '';
    $('#quick-key-label').style.display = isKey ? '' : 'none';
    $('#quick-passphrase-label').style.display = isKey ? '' : 'none';
    $('#quick-cert-label').style.display = isKey ? '' : 'none';
    $('#quick-password-title').textContent = $('#quick-auth').value === 'keyboard-interactive' ? 'Keyboard-Interactive Secret' : 'Passwort';
  };
  $('#quick-profile').onchange = sync;
  $('#quick-auth').onchange = sync;
  sync();
  if ($('#quick-save')) $('#quick-save').onchange = () => { $('#quick-save-name-label').style.display = $('#quick-save').checked ? '' : 'none'; };
  $('#quick-start').onclick = async () => {
    const button = $('#quick-start');
    const error = $('#quick-error');
    error.textContent = '';
    const profileId = $('#quick-profile').value ? Number($('#quick-profile').value) : null;
    const authType = profileId ? '' : $('#quick-auth').value;
    const isKey = authType === 'key';
    const saveRequested = Boolean($('#quick-save')?.checked);
    const requestedSaveName = $('#quick-save-name')?.value.trim() || '';
    const request = {
      target: $('#quick-target').value.trim(),
      authType,
      secret: profileId ? '' : (isKey ? $('#quick-key').value : $('#quick-password').value),
      passphrase: profileId || !isKey ? '' : $('#quick-passphrase').value,
      certificate: profileId || !isKey ? '' : $('#quick-cert').value,
      credentialProfileId: profileId,
      jumpHostId: $('#quick-jump').value ? Number($('#quick-jump').value) : null,
      cols: 120,
      rows: 36,
      fingerprint: '',
    };
    if (!request.target) { error.textContent = 'Ziel ist erforderlich.'; return; }
    setButtonBusy(button, true, 'Prüfe Host Key…');
    let result;
    try {
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          result = await api('/sessions/quick', { method: 'POST', body: JSON.stringify(request) });
          break;
        } catch (e) {
          const d = e.data || {};
          if (e.status !== 409 || !['host_key_required', 'host_key_changed'].includes(d.code)) throw e;
          if (d.serverId) {
            const accepted = await confirmHostKey(d);
            if (!accepted) throw new Error('cancelled');
            await api(`/servers/${d.serverId}/trust-host-key`, { method: 'POST', body: JSON.stringify({ fingerprint: d.actual?.fingerprint, replace: d.code === 'host_key_changed' }) });
            continue;
          }
          const accepted = await confirmHostKey(d);
          if (!accepted) throw new Error('cancelled');
          request.fingerprint = d.actual?.fingerprint || '';
        }
      }
      if (!result?.session?.id) throw new Error('Quick Connect konnte nicht gestartet werden.');
      const live = result.session;
      const pseudo = { id: 0, name: live.serverName, host: live.host || result.target?.host, username: live.username || result.username, port: live.port || result.target?.port || 22, color: '#35a4ff' };
      const tid = `t${Date.now()}${Math.random().toString(16).slice(2, 7)}`;
      state.tabs.push({ id: tid, type: 'terminal', name: pseudo.name, serverId: 0, sessionId: live.id, reconnectDelay: 750, serverSnapshot: pseudo });
      saveTabOrder();
      trackSession(live.id);
      state.active = tid;
      let saveWarning = '';
      let savedName = '';
      if (saveRequested) {
        try {
          savedName = requestedSaveName || pseudo.name;
          const workspaceQuery = Number(state.activeWorkspaceId || 0) > 0 ? `?workspaceId=${encodeURIComponent(Number(state.activeWorkspaceId))}` : '';
          const saved = await api(`/servers${workspaceQuery}`, { method: 'POST', body: JSON.stringify({
            name: savedName,
            host: result.target.host,
            port: result.target.port,
            username: result.username,
            authType: profileId ? (state.profiles.find(p => Number(p.id) === Number(profileId))?.authType || 'password') : (request.authType || 'password'),
            secret: profileId ? '' : request.secret,
            credentialProfileId: profileId,
            jumpHostId: request.jumpHostId,
            folderId: null,
            color: '#35a4ff',
            kind: 'ssh',
          }) });
          if (saved?.id && result.hostKey?.fingerprint) {
            await api(`/servers/${saved.id}/trust-host-key`, { method: 'POST', body: JSON.stringify({ fingerprint: result.hostKey.fingerprint, replace: false }) });
          }
          const refreshedServers = await api(`/servers${workspaceQuery}`);
          const persisted = refreshedServers.find(item => Number(item.id) === Number(saved?.id));
          if (!persisted) throw new Error('Server wurde vom Backend nicht in der Serverliste bestätigt.');
          state.servers = refreshedServers;
          if ($('#server-search')) $('#server-search').value = '';
          renderTree();
          const savedRow = $(`.server[data-id="${Number(saved.id)}"]`);
          if (savedRow) {
            savedRow.classList.add('just-saved');
            savedRow.scrollIntoView({ block: 'nearest' });
            setTimeout(() => savedRow.classList.remove('just-saved'), 1800);
          }
        } catch (e) {
          saveWarning = `Verbindung läuft, Speichern fehlgeschlagen: ${e.message}`;
          savedName = '';
        }
      }
      modal.innerHTML = '';
      paintTerminal(tid, pseudo);
      renderTabs();
      setTimeout(() => startTerminal(tid, pseudo), 0);
      if (saveWarning) showToast(saveWarning, true);
      else if (savedName) showToast(`Verbunden und als „${savedName}“ gespeichert.`);
      else showToast('Quick Connect verbunden.');
    } catch (e) {
      if (e.message !== 'cancelled') error.textContent = e.message;
      setButtonBusy(button, false);
    }
  };
}

function serverModal(server = {}) {
  const modal = $('#modal');
  const editing = Boolean(server.id);
  const workspaceId = editing ? Number(server.workspaceId || 0) : Number(state.activeWorkspaceId || 0);
  const workspace = workspaceId > 0 ? state.workspaces.find(item => Number(item.id) === workspaceId) : null;
  const scopePermissions = editing ? { canEdit: server.canEdit !== false, canDelete: server.canDelete !== false } : currentWorkspacePermissions();
  const canEdit = editing ? scopePermissions.canEdit : Boolean(scopePermissions.canCreate);
  const canDelete = editing && scopePermissions.canDelete;
  const inheritedServer = editing && Boolean(server.templateId);
  const selectableTemplates = !editing && workspaceId === 0 ? state.serverTemplates.filter(t => t.active && !t.adoptedServerId) : [];
  const knownProfile = state.profiles.some(p => Number(p.id) === Number(server.credentialProfileId || 0));
  const retainedWorkspaceProfile = editing && workspaceId > 0 && server.credentialProfileId && !knownProfile
    ? `<option value="${Number(server.credentialProfileId)}" data-retained="1">${esc(L('Bestehender Workspace-Zugang','Existing workspace credential'))}</option>`
    : '';
  const profileOptions = retainedWorkspaceProfile + state.profiles.map(p => `<option value="${p.id}" data-owner="${p.isOwner ? '1' : '0'}" data-shared="${p.shared ? '1' : '0'}">${esc(p.name)} · ${esc(p.username)}</option>`).join('');
  const jumpOptions = state.servers.filter(s => s.id !== server.id && s.kind === 'ssh').map(s => `<option value="${s.id}">${esc(s.name)} · ${esc(s.host)}</option>`).join('');
  const serverColor = normalizeHexColor(server.color, '#5aa9ff');
  const templateSelector = selectableTemplates.length ? `<label class="wide">${L('Server-Vorlage','Server template')}<select id="server-template"><option value="">${L('Keine Vorlage','No template')}</option>${selectableTemplates.map(t => `<option value="${t.id}">${esc(t.name)} · ${esc(t.host)}:${Number(t.port || 22)}</option>`).join('')}</select></label>` : '';
  const templateInfo = inheritedServer ? `<div class="template-inheritance-note"><b>${esc(L('Von Server-Vorlage geerbt','Inherited from server template'))}: ${esc(server.templateName || '')}</b><span>${esc(L('Einstellungen werden zentral verwaltet.','Settings are managed centrally.'))}</span>${server.templateAccessible === false ? `<strong>${esc(L('Die Freigabe dieser Vorlage wurde entzogen. Verbinden ist derzeit nicht möglich.','Access to this template was revoked. Connecting is currently unavailable.'))}</strong>` : ''}${server.templateActive === false ? `<strong>${esc(L('Diese Vorlage ist deaktiviert.','This template is disabled.'))}</strong>` : ''}${server.templateJumpMissing ? `<strong>${esc(L('Die benötigte Jump-Server-Vorlage muss zuerst übernommen werden.','The required jump server template must be adopted first.'))}</strong>` : ''}</div>` : `<div id="server-template-note" class="template-inheritance-note" hidden></div>`;
  modal.innerHTML = `<div class="backdrop"><div class="dialog serverdialog modal-scroll">
    <div class="dialogtitle"><div><h3>${editing ? L('Server bearbeiten','Edit server') : L('Server hinzufügen','Add server')}</h3><p>${workspace ? `${L('Arbeitsbereich','Workspace')}: ${esc(workspace.name)}` : L('SSH-Ziel, Zugangsdaten und optionalen Jump Host konfigurieren.','Configure the SSH target, credentials and optional jump host.')}</p></div><button data-close class="iconbutton" aria-label="Schließen">×</button></div>
    ${templateInfo}
    <div class="formgrid">
      ${templateSelector}
      <label class="wide">Name<input id="server-name" value="${esc(server.name || '')}" autocomplete="off"></label>
      <label>Host / IP<input id="server-host" value="${esc(server.host || '')}" autocomplete="off"></label>
      <label>Port<input id="server-port" type="number" min="1" max="65535" value="${server.port || 22}"></label>
      <label class="wide">${L('Zugangsvorlage','Credential profile')}<select id="server-profile"><option value="">${L('Direkte Zugangsdaten','Direct credentials')}</option>${profileOptions}</select></label>
    </div>
    <div id="inline-credentials" class="credential-box">
      <div class="formgrid">
        <label>${L('Benutzer','User')}<input id="server-user" value="${esc(server.username || 'root')}" autocomplete="off"></label>
        <label>${L('Authentifizierung','Authentication')}<select id="server-auth"><option value="password">${L('Passwort','Password')}</option><option value="keyboard-interactive">Keyboard Interactive</option><option value="key">Private Key</option></select></label>
        <label id="server-password-label" class="wide"><span id="server-password-title">${editing ? L('Neues Passwort','New password') : L('Passwort','Password')}</span><input id="server-password" type="password" placeholder="${editing ? L('Leer = unverändert','Leave empty to keep unchanged') : L('Passwort','Password')}" autocomplete="new-password"></label>
        <label id="server-key-label" class="wide" style="display:none"><span>${editing ? L('Neuer Private Key','New private key') : 'Private Key'}</span><textarea id="server-key" placeholder="${editing ? L('Leer = unverändert','Leave empty to keep unchanged') : '-----BEGIN OPENSSH PRIVATE KEY-----'}" autocomplete="off" spellcheck="false"></textarea></label>
      </div>
      <small class="fieldhint">${L('Key-Passphrase und OpenSSH User Certificate verwaltest du über eine Zugangsvorlage.','Manage key passphrases and OpenSSH user certificates through a credential profile.')}</small>
    </div>
    <div class="formgrid">
      <label>Jump Host<select id="server-jump"><option value="">${L('Direkt verbinden','Connect directly')}</option>${jumpOptions}</select></label>
      <label>${L('Ordner','Folder')}<select id="server-folder"><option value="">${L('Kein Ordner','No folder')}</option>${state.folders.map(f => `<option value="${f.id}">${esc(f.name)}</option>`).join('')}</select></label>
      <label class="server-color-label">${L('Farbe','Color')}<div class="server-color-control"><input id="server-color" type="color" value="${esc(serverColor)}" aria-label="Serverfarbe auswählen"><input id="server-color-hex" value="${esc(serverColor)}" maxlength="7" pattern="#[0-9A-Fa-f]{6}" autocomplete="off" spellcheck="false" aria-label="Serverfarbe als Hex-Wert"></div></label>
      <div class="server-editor-settings">
        <label>${L('Terminal-Dateieditor','Terminal file editor')}<select id="server-terminal-editor"><option value="ask">${L('Beim ersten Mal fragen','Ask the first time')}</option><option value="web">ZentSSH Webeditor</option><option value="terminal">${L('Im Terminal öffnen','Open in terminal')}</option></select></label>
        <label>${L('Crontab-Editor','Crontab editor')}<select id="server-crontab-editor"><option value="ask">${L('Beim ersten Mal fragen','Ask the first time')}</option><option value="visual">Visueller ZentSSH Editor</option><option value="terminal">${L('Im Terminal öffnen','Open in terminal')}</option></select></label>
      </div>
    </div>
    <div id="server-error" class="err"></div>
    <div class="actions spread"><div>${canDelete ? `<button id="server-delete" class="danger">${L('Löschen','Delete')}</button>` : ''}<button id="manage-profiles">${L('Zugangsvorlagen','Credential profiles')}</button></div><div><button data-cancel>${L('Abbrechen','Cancel')}</button>${canEdit ? `<button id="server-save" class="primary">${editing ? L('Speichern','Save') : L('Server anlegen','Create server')}</button>` : ''}</div></div>
  </div></div>`;
  $('#server-auth').value = server.authType || 'password';
  $('#server-profile').value = server.credentialProfileId || '';
  $('#server-jump').value = server.jumpHostId || '';
  $('#server-folder').value = server.folderId || '';
  $('#server-terminal-editor').value = server.terminalEditorMode || 'ask';
  $('#server-crontab-editor').value = server.crontabEditorMode || 'ask';
  const colorPicker = $('#server-color');
  const colorHex = $('#server-color-hex');
  colorPicker.oninput = () => { colorHex.value = colorPicker.value.toLowerCase(); };
  colorHex.oninput = () => { const normalized = normalizeHexColor(colorHex.value, ''); if (normalized) colorPicker.value = normalized; };
  colorHex.onblur = () => { colorHex.value = normalizeHexColor(colorHex.value, colorPicker.value); };

  const inheritedFields = () => [$('#server-name'), $('#server-host'), $('#server-port'), $('#server-jump'), $('#server-color'), $('#server-color-hex'), $('#server-terminal-editor'), $('#server-crontab-editor')].filter(Boolean);
  const selectedTemplate = () => {
    const id = inheritedServer ? Number(server.templateId) : Number($('#server-template')?.value || 0);
    return id ? state.serverTemplates.find(item => Number(item.id) === id) || (inheritedServer ? { ...server, id, name: server.templateName || server.name } : null) : null;
  };
  const syncTemplateMode = () => {
    const template = selectedTemplate();
    const inherited = Boolean(template);
    if (template && !editing) {
      $('#server-name').value = template.name || '';
      $('#server-host').value = template.host || '';
      $('#server-port').value = Number(template.port || 22);
      const color = normalizeHexColor(template.color, '#5aa9ff');
      colorPicker.value = color; colorHex.value = color;
      $('#server-terminal-editor').value = template.terminalEditorMode || 'ask';
      $('#server-crontab-editor').value = template.crontabEditorMode || 'ask';
      $('#server-jump').value = '';
      const note = $('#server-template-note');
      if (note) { note.hidden = false; note.innerHTML = `<b>${esc(template.name)}</b><span>${esc(L('Einstellungen werden zentral verwaltet.','Settings are managed centrally.'))}</span>${template.jumpTemplateName ? `<span>Jump: ${esc(template.jumpTemplateName)}</span>` : ''}`; }
    } else if (!inheritedServer) {
      const note = $('#server-template-note'); if (note) { note.hidden = true; note.innerHTML = ''; }
    }
    inheritedFields().forEach(field => { field.disabled = !canEdit || inherited; });
    $$('#server-profile option').forEach(option => {
      if (!option.value) { option.disabled = false; return; }
	  if (option.dataset.retained === '1') { option.disabled = false; return; }
      const owner = option.dataset.owner === '1';
      const shared = option.dataset.shared === '1';
      option.disabled = inherited ? !owner : (workspaceId > 0 ? !shared : false);
    });
    if ($('#server-profile').selectedOptions[0]?.disabled) $('#server-profile').value = '';
    syncCredentialMode();
  };
  const syncCredentialMode = () => {
    const profile = $('#server-profile').value !== '';
    $('#inline-credentials').classList.toggle('disabledsection', profile || !canEdit);
    for (const el of $$('input,select,textarea', $('#inline-credentials'))) el.disabled = profile || !canEdit;
    const isKey = !profile && $('#server-auth').value === 'key';
    $('#server-password-label').style.display = isKey ? 'none' : '';
    $('#server-key-label').style.display = isKey ? '' : 'none';
    $('#server-password-title').textContent = $('#server-auth').value === 'keyboard-interactive'
      ? (editing ? L('Neues Keyboard-Interactive Secret','New keyboard-interactive secret') : 'Keyboard-Interactive Secret')
      : (editing ? L('Neues Passwort','New password') : L('Passwort','Password'));
  };
  $('#server-profile').onchange = syncCredentialMode;
  $('#server-auth').onchange = syncCredentialMode;
  if ($('#server-template')) $('#server-template').onchange = syncTemplateMode;
  if (!canEdit) $$('input,select,textarea', modal).forEach(field => { if (field.id !== 'server-folder') field.disabled = true; });
  syncTemplateMode();
  $('[data-close]', modal).onclick = () => { modal.innerHTML = ''; };
  $('[data-cancel]', modal).onclick = () => { modal.innerHTML = ''; };
  $('#manage-profiles').onclick = () => openSettings('credentials');
  if ($('#server-save')) $('#server-save').onclick = async () => {
    const button = $('#server-save');
    const profileId = $('#server-profile').value ? Number($('#server-profile').value) : null;
    const profile = profileId ? state.profiles.find(p => Number(p.id) === profileId) : null;
    const authType = profileId ? (profile?.authType || 'password') : $('#server-auth').value;
    const isKey = authType === 'key';
    const body = {
      name: $('#server-name').value.trim(), host: $('#server-host').value.trim(), port: Number($('#server-port').value || 22),
      username: profileId ? (profile?.username || 'profile') : $('#server-user').value.trim(), authType,
      secret: profileId ? '' : (isKey ? $('#server-key').value : $('#server-password').value), credentialProfileId: profileId,
      jumpHostId: $('#server-jump').value ? Number($('#server-jump').value) : null,
      folderId: $('#server-folder').value ? Number($('#server-folder').value) : null,
      color: normalizeHexColor($('#server-color-hex').value, $('#server-color').value), terminalEditorMode: $('#server-terminal-editor').value,
      crontabEditorMode: $('#server-crontab-editor').value, kind: 'ssh',
    };
    $('#server-error').textContent = '';
    setButtonBusy(button, true, editing ? L('Speichere…','Saving…') : L('Speichere…','Saving…'));
    try {
      const template = selectedTemplate();
      let endpoint;
      let method;
      if (!editing && template) { endpoint = `/server-templates/${template.id}/adopt`; method = 'POST'; }
      else if (editing) { endpoint = `/servers/${server.id}`; method = 'PATCH'; }
      else { endpoint = `/servers${workspaceId > 0 ? `?workspaceId=${encodeURIComponent(workspaceId)}` : ''}`; method = 'POST'; }
      const savedServer = await api(endpoint, { method, body: JSON.stringify(body) });
      const savedServerId = Number(server.id || savedServer.id || 0);
      if (savedServerId) { localStorage.removeItem(localServerPreferenceKey(savedServerId, 'editor')); localStorage.removeItem(localServerPreferenceKey(savedServerId, 'crontab')); }
      modal.innerHTML = '';
      await loadWorkspace();
      renderTree();
      showToast(editing ? L('Server gespeichert.','Server saved.') : (template ? L('Server-Vorlage übernommen.','Server template adopted.') : L('Server angelegt.','Server created.')));
    } catch (e) { $('#server-error').textContent = e.message; setButtonBusy(button, false); }
  };
  if ($('#server-delete')) $('#server-delete').onclick = async () => {
    if (!confirm(`${L('Server wirklich löschen?','Delete server?')} „${server.name}“`)) return;
    try { await api(`/servers/${server.id}`, { method: 'DELETE' }); modal.innerHTML = ''; await loadWorkspace(); renderTree(); showToast(L('Server gelöscht.','Server deleted.')); }
    catch (e) { $('#server-error').textContent = e.message; }
  };
}

function folderModal(folder = {}) {
  const modal = $('#modal');
  const editing = Boolean(folder.id);
  const permissions = currentWorkspacePermissions();
  const canEdit = editing ? folder.canEdit !== false : permissions.canCreate;
  const canDelete = editing && folder.canDelete !== false;
  const opts = state.folders.filter(f => Number(f.id) !== Number(folder.id)).map(f => `<option value="${f.id}">${esc(f.name)}</option>`).join('');
  modal.innerHTML = `<div class="backdrop"><div class="dialog"><h3>${editing ? L('Ordner bearbeiten','Edit folder') : L('Ordner erstellen','Create folder')}</h3><label>${L('Name','Name')}<input id="folder-name" value="${esc(folder.name || '')}" autocomplete="off" ${canEdit ? '' : 'disabled'}></label><label>${L('Übergeordneter Ordner','Parent folder')}<select id="folder-parent" ${canEdit ? '' : 'disabled'}><option value="">${L('Oberste Ebene','Top level')}</option>${opts}</select></label><div id="folder-error" class="err"></div><div class="actions spread">${canDelete ? `<button id="folder-delete" class="danger">${L('Löschen','Delete')}</button>` : '<span></span>'}<div><button data-close>${L('Abbrechen','Cancel')}</button>${canEdit ? `<button id="folder-save" class="primary">${editing ? L('Speichern','Save') : L('Erstellen','Create')}</button>` : ''}</div></div></div></div>`;
  $('#folder-parent').value = folder.parentId || '';
  $('[data-close]', modal).onclick = () => modal.innerHTML = '';
  if ($('#folder-save')) $('#folder-save').onclick = async () => {
    const button = $('#folder-save'); setButtonBusy(button, true, L('Speichere…','Saving…'));
    try {
      const body = { name: $('#folder-name').value.trim(), parentId: $('#folder-parent').value ? Number($('#folder-parent').value) : null, sortOrder: folder.sortOrder || 0 };
      const workspaceQuery = !editing && Number(state.activeWorkspaceId || 0) > 0 ? `?workspaceId=${encodeURIComponent(Number(state.activeWorkspaceId))}` : '';
      await api(editing ? `/folders/${folder.id}` : `/folders${workspaceQuery}`, { method: editing ? 'PATCH' : 'POST', body: JSON.stringify(body) });
      modal.innerHTML = ''; await loadWorkspace(); renderTree(); showToast(editing ? L('Ordner gespeichert.','Folder saved.') : L('Ordner erstellt.','Folder created.'));
    } catch (e) { $('#folder-error').textContent = e.message; setButtonBusy(button, false); }
  };
  if ($('#folder-delete')) $('#folder-delete').onclick = async () => {
    if (!confirm(`${L('Ordner wirklich löschen? Der Ordner muss leer sein.','Delete folder? The folder must be empty.')} „${folder.name}“`)) return;
    try { await api(`/folders/${folder.id}`, { method: 'DELETE' }); modal.innerHTML = ''; await loadWorkspace(); renderTree(); showToast(L('Ordner gelöscht.','Folder deleted.')); }
    catch (e) { $('#folder-error').textContent = e.message; }
  };
}

async function openTerm(serverId) {
  const server = state.servers.find(s => s.id === serverId);
  if (!server) return;
  try {
    await ensureServerReady(serverId);
    const live = await api('/sessions', { method: 'POST', body: JSON.stringify({ serverId, cols: 120, rows: 36 }) });
    const tid = `t${Date.now()}${Math.random().toString(16).slice(2, 7)}`;
    state.tabs.push({ id: tid, type: 'terminal', name: server.name, serverId, sessionId: live.id, reconnectDelay: 750 });
    saveTabOrder();
    trackSession(live.id);
    state.active = tid;
    paintTerminal(tid, server);
    renderTabs();
    setTimeout(() => startTerminal(tid, server), 0);
  } catch (e) {
    if (e.message !== 'cancelled') showToast(e.message, true);
  }
}

function paintTerminal(tid, server) {
  const workspace = $('#workspace');
  const tab = state.tabs.find(t => t.id === tid);
  if (!workspace || !tab) return;
  if (!tab.panel) {
    const panel = document.createElement('div');
    panel.className = 'termwrap';
    panel.innerHTML = `<div class="termhead"><div class="termhead-server"><span style="--c:${esc(server.color)}">${esc(server.name)}</span><small>${esc(server.username)}@${esc(server.host)}:${server.port}</small></div><button class="terminal-snippet-button iconbutton has-tooltip" type="button" data-tooltip="${esc(L('Code-Schnipsel · Strg/⌘ + Shift + Leertaste','Code snippets · Ctrl/⌘ + Shift + Space'))}" aria-label="${esc(L('Code-Schnipsel öffnen','Open code snippets'))}">${actionIcon('code')}</button></div><div class="terminal"></div>`;
    tab.panel = panel;
    tab.termElement = $('.terminal', panel);
    $('.terminal-snippet-button', panel).onclick = () => openSnippetLauncher(tid);
  }
  workspace.replaceChildren(tab.panel);
}

function activeTerminalTab() {
  const tab = state.tabs.find(item => item.id === state.active);
  return tab?.type === 'terminal' ? tab : null;
}

function snippetSummary(content) {
  const lines = String(content || '').replace(/\r\n?/g, '\n').split('\n').map(line => line.trim()).filter(Boolean);
  return lines[0] || L('Leerer Schnipsel','Empty snippet');
}

function snippetScopeLabel(scope) {
  return scope === 'shared' ? L('Geteilt','Shared') : L('Meine Schnipsel','My snippets');
}

function snippetsForFolder(snippets, folderId) {
  return snippets.filter(item => Number(item.folderId || 0) === Number(folderId || 0));
}

function snippetFolderTreeHTML(folders, snippets, options = {}) {
  const scope = options.scope || 'private';
  const selectable = Boolean(options.selectable);
  const selectedId = Number(options.selectedId || 0);
  const includeUnfiled = scope === 'private';
  const groups = [];
  if (includeUnfiled) groups.push({ id: 0, name: L('Ohne Ordner','No folder'), synthetic: true, canUse: true, canCreate: true, canEdit: true, canDelete: true });
  groups.push(...folders);
  if (!groups.length) return `<div class="snippet-empty"><span>${actionIcon('folder')}</span><p>${esc(L('Noch keine Ordner vorhanden.','No folders yet.'))}</p></div>`;
  return groups.map(folder => {
    const items = snippetsForFolder(snippets, folder.id).filter(item => scope !== 'shared' || item.canUse !== false);
    if (folder.synthetic && !items.length && folders.length) return '';
    return `<div class="snippet-folder-block" data-folder-id="${folder.id}">
      <div class="snippet-folder-head"><span class="snippet-folder-icon">${actionIcon('folder')}</span><b>${esc(folder.name)}</b><span class="badge">${items.length}</span></div>
      <div class="snippet-folder-items">${items.length ? items.map(item => `<button class="snippet-launch-row ${selectedId === Number(item.id) ? 'selected' : ''}" data-id="${item.id}" type="button"><span class="snippet-launch-icon">${actionIcon('code')}</span><span class="snippet-launch-meta"><b>${esc(item.name)}</b><small>${esc(snippetSummary(item.content))}</small></span></button>`).join('') : `<div class="snippet-folder-empty">${esc(L('Leer','Empty'))}</div>`}</div>
    </div>`;
  }).join('');
}

async function executeCodeSnippet(tab, snippet) {
  if (!tab || tab.type !== 'terminal' || tab.ws?.readyState !== WebSocket.OPEN) throw new Error(L('Die SSH-Session ist nicht verbunden.','The SSH session is not connected.'));
  if (!(tab.promptLikely || tab.commandCaptureForced || tab.commandCaptureActive)) throw new Error(L('Kein normaler Shell-Prompt erkannt. Beende zuerst laufende Terminalprogramme wie htop oder mc.','No regular shell prompt was detected. Exit terminal programs such as htop or mc first.'));
  if (tab.commandCaptureActive && String(tab.commandLine || '').trim()) throw new Error(L('Im Terminal steht bereits eine Eingabe. Führe sie zuerst aus oder lösche sie.','There is already input in the terminal. Execute or clear it first.'));
  const content = String(snippet?.content || '').replace(/\r\n?/g, '\n');
  if (!content.trim()) throw new Error(L('Der Code-Schnipsel ist leer.','The code snippet is empty.'));
  const payload = content.replace(/\n/g, '\r');
  resetTerminalCommandCapture(tab);
  tab.promptLikely = false;
  tab.commandCaptureForced = false;
  sendTerminalInput(tab, payload.endsWith('\r') ? payload : `${payload}\r`);
  const server = state.servers.find(item => Number(item.id) === Number(tab.serverId)) || tab.serverSnapshot;
  if (server) {
    for (const line of content.split('\n')) {
      const command = line.trim();
      if (command) trackTerminalCwdAfterCommand(tab, server, command);
    }
  }
}

async function openSnippetLauncher(tid = state.active) {
  const tab = state.tabs.find(item => item.id === tid);
  if (!tab || tab.type !== 'terminal') {
    showToast(L('Code-Schnipsel können nur in einem SSH-Terminal verwendet werden.','Code snippets can only be used in an SSH terminal.'), true);
    return;
  }
  const modal = $('#modal');
  if (!modal) return;
  let permissions, privateFolders, privateSnippets, sharedFolders = [], sharedSnippets = [];
  try {
    [permissions, privateFolders, privateSnippets] = await Promise.all([api('/snippet-permissions'), api('/snippet-folders?scope=private'), api('/code-snippets?scope=private')]);
    state.snippetPermissions = permissions;
    if (Number(permissions.sharedFolderCount || 0) > 0) {
      [sharedFolders, sharedSnippets] = await Promise.all([api('/snippet-folders?scope=shared'), api('/code-snippets?scope=shared')]);
    }
  } catch (e) {
    showToast(e.message, true);
    return;
  }
  sharedFolders = sharedFolders.filter(folder => folder.canUse !== false);
  sharedSnippets = sharedSnippets.filter(item => item.canUse !== false);
  const sharedSelectable = sharedFolders.length > 0 && sharedSnippets.length > 0;
  let currentScope = 'private';
  let selectedId = null;

  const currentData = () => currentScope === 'shared'
    ? { folders: sharedFolders, snippets: sharedSnippets }
    : { folders: privateFolders, snippets: privateSnippets };

  const renderList = () => {
    const list = $('#snippet-launcher-list', modal);
    if (!list) return;
    const { folders, snippets } = currentData();
    const needle = ($('#snippet-launcher-search', modal)?.value || '').trim().toLowerCase();
    const filtered = snippets.filter(item => !needle || item.name.toLowerCase().includes(needle) || String(item.content || '').toLowerCase().includes(needle) || String(item.folderName || '').toLowerCase().includes(needle));
    list.innerHTML = filtered.length
      ? snippetFolderTreeHTML(folders, filtered, { scope: currentScope, selectedId })
      : `<div class="snippet-empty"><span>${actionIcon('code')}</span><p>${esc(currentScope === 'shared' ? L('Keine geteilten Code-Schnipsel vorhanden.','No shared code snippets available.') : L('Noch keine eigenen Code-Schnipsel vorhanden.','No personal code snippets yet.'))}</p></div>`;
    $$('.snippet-launch-row', list).forEach(row => row.onclick = () => {
      selectedId = Number(row.dataset.id);
      renderList();
      const item = currentData().snippets.find(candidate => Number(candidate.id) === selectedId);
      const preview = $('#snippet-launcher-preview', modal);
      const use = $('#snippet-launcher-use', modal);
      if (preview && item) {
        preview.hidden = false;
        preview.innerHTML = `<div class="snippet-preview-title"><div><b>${esc(item.name)}</b>${item.folderName ? `<small>${actionIcon('folder')} ${esc(item.folderName)}</small>` : ''}</div><span class="badge">${esc(snippetScopeLabel(item.scope))}</span></div><pre>${esc(item.content)}</pre>`;
      }
      if (use) use.disabled = !item;
    });
  };

  const switchScope = scope => {
    currentScope = scope;
    selectedId = null;
    const preview = $('#snippet-launcher-preview', modal);
    if (preview) { preview.hidden = true; preview.innerHTML = ''; }
    const use = $('#snippet-launcher-use', modal);
    if (use) use.disabled = true;
    renderList();
  };

  modal.innerHTML = `<div class="backdrop"><div class="dialog snippet-launcher-dialog">
    <div class="dialogtitle"><div><h3>${L('Code-Schnipsel','Code snippets')}</h3><p>${esc(L('Befehle und mehrzeilige Shell-Sequenzen direkt im aktuellen Terminal ausführen.','Run commands and multi-line shell sequences directly in the current terminal.'))}</p></div><button data-close class="iconbutton" aria-label="${esc(L('Schließen','Close'))}">×</button></div>
    <div class="snippet-launcher-toolbar ${sharedSelectable ? '' : 'no-scope'}">
      ${sharedSelectable ? `<label class="snippet-scope-select"><span>${L('Bereich','Scope')}</span><select id="snippet-launcher-scope"><option value="private">${L('Meine Schnipsel','My snippets')}</option><option value="shared">${L('Geteilte Schnipsel','Shared snippets')}</option></select></label>` : ''}
      <label class="snippet-search"><span class="sr-only">${L('Suchen','Search')}</span><input id="snippet-launcher-search" placeholder="${esc(L('Schnipsel suchen…','Search snippets…'))}" autocomplete="off" autofocus></label>
      <button id="snippet-launcher-add" class="iconbutton has-tooltip" type="button" data-tooltip="${esc(L('Code-Schnipsel anlegen','Create code snippet'))}" aria-label="${esc(L('Code-Schnipsel anlegen','Create code snippet'))}">${actionIcon('plus')}</button>
    </div>
    <div id="snippet-launcher-list" class="snippet-launcher-list"></div>
    <div id="snippet-launcher-preview" class="snippet-launcher-preview" hidden></div>
    <div id="snippet-launcher-error" class="err"></div>
    <div class="actions"><button data-cancel>${L('Abbrechen','Cancel')}</button><button id="snippet-launcher-use" class="primary" disabled data-primary>${L('Verwenden','Use')}</button></div>
  </div></div>`;
  const close = () => { modal.innerHTML = ''; };
  $('[data-close]', modal).onclick = close;
  $('[data-cancel]', modal).onclick = close;
  $('#snippet-launcher-search', modal).oninput = renderList;
  if ($('#snippet-launcher-scope', modal)) $('#snippet-launcher-scope', modal).onchange = event => switchScope(event.target.value);
  $('#snippet-launcher-add', modal).onclick = () => snippetEditorModal({}, currentScope, { returnTo: 'launcher', terminalTabId: tid });
  $('#snippet-launcher-use', modal).onclick = async () => {
    const selected = currentData().snippets.find(item => Number(item.id) === Number(selectedId));
    if (!selected) return;
    const button = $('#snippet-launcher-use', modal);
    setButtonBusy(button, true, L('Starte…','Running…'));
    $('#snippet-launcher-error', modal).textContent = '';
    try {
      const resolved = await api(`/code-snippets/${selected.id}/use`, { method: 'POST' });
      modal.innerHTML = '';
      await executeCodeSnippet(tab, resolved);
      tab.term?.focus();
    } catch (e) {
      if ($('#snippet-launcher-error', modal)) $('#snippet-launcher-error', modal).textContent = e.message;
      setButtonBusy(button, false);
    }
  };
  renderList();
}

async function snippetEditorModal(snippet = {}, defaultScope = 'private', options = {}) {
  const modal = $('#modal');
  const editing = Boolean(snippet.id);
  let privateFolders = [], sharedFolders = [];
  try {
    [privateFolders, sharedFolders] = await Promise.all([api('/snippet-folders?scope=private'), api('/snippet-folders?scope=shared').catch(() => [])]);
  } catch (e) {
    showToast(e.message, true);
    return;
  }
  const creatableSharedFolders = sharedFolders.filter(folder => folder.canCreate !== false);
  const editableSharedFolders = sharedFolders.filter(folder => folder.canCreate !== false || folder.canEdit !== false);
  const canChooseShared = creatableSharedFolders.length > 0;
  let scope = editing ? snippet.scope : (defaultScope === 'shared' && canChooseShared ? 'shared' : 'private');
  const returnAfter = () => {
    if (options.returnTo === 'launcher') openSnippetLauncher(options.terminalTabId || state.active);
    else openSettings(scope === 'shared' ? 'shared-snippets' : 'snippets');
  };
  const initialFolderId = Number(options.folderId || snippet.folderId || 0);
  const folderOptions = currentScope => {
    const folders = currentScope === 'shared' ? (editing ? editableSharedFolders : creatableSharedFolders) : privateFolders;
    const empty = currentScope === 'private' ? `<option value="">${L('Ohne Ordner','No folder')}</option>` : '';
    return empty + folders.map(folder => `<option value="${folder.id}">${esc(folder.name)}</option>`).join('');
  };
  modal.innerHTML = `<div class="backdrop"><div class="dialog snippet-editor-dialog">
    <div class="dialogtitle"><div><h3>${editing ? L('Code-Schnipsel bearbeiten','Edit code snippet') : L('Code-Schnipsel anlegen','Create code snippet')}</h3></div><button data-close class="iconbutton" aria-label="${esc(L('Schließen','Close'))}">×</button></div>
    <label>${L('Name','Name')}<input id="snippet-name" value="${esc(snippet.name || '')}" maxlength="120" autocomplete="off" autofocus placeholder="${esc(L('z. B. Wartung starten','e.g. Start maintenance'))}"></label>
    ${(!editing && canChooseShared) ? `<label id="snippet-scope-label">${L('Bereich','Scope')}<select id="snippet-scope"><option value="private">${L('Meine Schnipsel','My snippets')}</option><option value="shared">${L('Geteilte Schnipsel','Shared snippets')}</option></select></label>` : ''}
    <label id="snippet-folder-label">${L('Ordner','Folder')}<select id="snippet-folder"></select></label>
    <label>${L('Befehl / Shell-Code','Command / shell code')}<textarea id="snippet-content" class="snippet-code-editor" maxlength="65536" autocomplete="off" spellcheck="false" placeholder="cd /opt/aurora-app
docker compose pull
docker compose up -d">${esc(snippet.content || '')}</textarea></label>
    <div id="snippet-editor-error" class="err"></div>
    <div class="actions"><button data-cancel>${L('Abbrechen','Cancel')}</button><button id="snippet-save" class="primary" data-primary>${L('Speichern','Save')}</button></div>
  </div></div>`;
  const scopeSelect = $('#snippet-scope', modal);
  const folderSelect = $('#snippet-folder', modal);
  const syncFolders = () => {
    scope = editing ? snippet.scope : (scopeSelect?.value || scope);
    folderSelect.innerHTML = folderOptions(scope);
    const preferred = initialFolderId && [...folderSelect.options].some(opt => Number(opt.value) === initialFolderId) ? String(initialFolderId) : folderSelect.options[0]?.value || '';
    folderSelect.value = preferred;
    $('#snippet-folder-label', modal).hidden = scope === 'shared' && !folderSelect.options.length;
  };
  if (scopeSelect) { scopeSelect.value = scope; scopeSelect.onchange = syncFolders; }
  syncFolders();
  $('[data-close]', modal).onclick = returnAfter;
  $('[data-cancel]', modal).onclick = returnAfter;
  $('#snippet-save', modal).onclick = async () => {
    const button = $('#snippet-save', modal);
    const error = $('#snippet-editor-error', modal);
    error.textContent = '';
    const activeScope = editing ? snippet.scope : (scopeSelect?.value || 'private');
    const folderId = Number(folderSelect?.value || 0);
    const body = { name: $('#snippet-name', modal).value.trim(), content: $('#snippet-content', modal).value, scope: activeScope, folderId };
    if (!body.name || !body.content.trim()) { error.textContent = L('Name und Befehl sind erforderlich.','Name and command are required.'); return; }
    if (activeScope === 'shared' && !folderId) { error.textContent = L('Wähle einen geteilten Ordner aus.','Select a shared folder.'); return; }
    setButtonBusy(button, true, L('Speichere…','Saving…'));
    try {
      await api(editing ? `/code-snippets/${snippet.id}` : '/code-snippets', { method: editing ? 'PATCH' : 'POST', body: JSON.stringify(body) });
      state.snippetPermissions = await api('/snippet-permissions');
      returnAfter();
    } catch (e) { error.textContent = e.message; setButtonBusy(button, false); }
  };
}

async function deleteCodeSnippet(snippet, returnTo = 'settings', terminalTabId = null) {
  if (!snippet?.id || !confirm(`${L('Code-Schnipsel löschen','Delete code snippet')} „${snippet.name}“?`)) return;
  try {
    await api(`/code-snippets/${snippet.id}`, { method: 'DELETE' });
    state.snippetPermissions = await api('/snippet-permissions');
    showToast(L('Code-Schnipsel gelöscht.','Code snippet deleted.'));
    if (returnTo === 'launcher') openSnippetLauncher(terminalTabId || state.active);
    else openSettings(snippet.scope === 'shared' ? 'shared-snippets' : 'snippets');
  } catch (e) { showToast(e.message, true); }
}

function snippetFolderModal(folder = {}, scope = 'private') {
  const modal = $('#modal');
  const editing = Boolean(folder.id);
  modal.innerHTML = `<div class="backdrop"><div class="dialog fileactiondialog">
    <div class="dialogtitle"><div><h3>${editing ? L('Schnipsel-Ordner bearbeiten','Edit snippet folder') : L('Schnipsel-Ordner anlegen','Create snippet folder')}</h3></div><button data-close class="iconbutton" aria-label="${esc(L('Schließen','Close'))}">×</button></div>
    <label>${L('Name','Name')}<input id="snippet-folder-name" value="${esc(folder.name || '')}" maxlength="120" autocomplete="off" autofocus placeholder="${esc(L('z. B. Docker','e.g. Docker'))}"></label>
    <div id="snippet-folder-error" class="err"></div>
    <div class="actions spread">${editing ? `<button id="snippet-folder-delete" class="danger">${L('Löschen','Delete')}</button>` : '<span></span>'}<div><button data-cancel>${L('Abbrechen','Cancel')}</button><button id="snippet-folder-save" class="primary">${L('Speichern','Save')}</button></div></div>
  </div></div>`;
  const returnToSettings = () => openSettings(scope === 'shared' ? 'shared-snippets' : 'snippets');
  $('[data-close]', modal).onclick = returnToSettings;
  $('[data-cancel]', modal).onclick = returnToSettings;
  $('#snippet-folder-save', modal).onclick = async () => {
    const name = $('#snippet-folder-name', modal).value.trim();
    if (!name) { $('#snippet-folder-error', modal).textContent = L('Name ist erforderlich.','Name is required.'); return; }
    const button = $('#snippet-folder-save', modal);
    setButtonBusy(button, true, L('Speichere…','Saving…'));
    try {
      await api(editing ? `/snippet-folders/${folder.id}` : '/snippet-folders', { method: editing ? 'PATCH' : 'POST', body: JSON.stringify({ name, scope }) });
      returnToSettings();
    } catch (e) { $('#snippet-folder-error', modal).textContent = e.message; setButtonBusy(button, false); }
  };
  if (editing) $('#snippet-folder-delete', modal).onclick = async () => {
    if (!confirm(`${L('Ordner löschen','Delete folder')} „${folder.name}“?`)) return;
    try {
      await api(`/snippet-folders/${folder.id}`, { method: 'DELETE' });
      returnToSettings();
    } catch (e) {
      $('#snippet-folder-error', modal).textContent = String(e.message || '').includes('not empty')
        ? L('Der Ordner enthält noch Schnipsel. Verschiebe oder lösche sie zuerst.','The folder still contains snippets. Move or delete them first.')
        : e.message;
    }
  };
}

async function movePrivateSnippetToFolder(snippet, folderId) {
  if (!snippet?.id || snippet.scope !== 'private' || Number(snippet.folderId || 0) === Number(folderId || 0)) return;
  try {
    await api(`/code-snippets/${snippet.id}`, { method: 'PATCH', body: JSON.stringify({ name: snippet.name, content: snippet.content, folderId: Number(folderId || 0) }) });
    openSettings('snippets');
  } catch (e) { showToast(e.message, true); }
}

function sendTerminalInput(tab, data) {
  if (tab?.ws?.readyState === WebSocket.OPEN) tab.ws.send(JSON.stringify({ type: 'input', data }));
}

function stripTerminalControl(text) {
  return String(text || '')
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, '')
    .replace(/\x1b\[[0-?]*[ -\/]*[@-~]/g, '')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
}

function observeTerminalOutput(tab, chunk) {
  const clean = stripTerminalControl(chunk);
  if (!clean) return;
  tab.outputTail = `${tab.outputTail || ''}${clean}`.slice(-2000);
  const lastLine = tab.outputTail.split(/\r?\n/).at(-1) || '';
  tab.promptLikely = /(?:^|\s|[:~/\w.-])[#$%❯>]\s*$/.test(lastLine);
  if (tab.promptLikely) tab.commandCaptureForced = false;
}

function resetTerminalCommandCapture(tab) {
  tab.commandCaptureActive = false;
  tab.commandCaptureReliable = true;
  tab.commandLine = '';
}

function updateTerminalCommandCapture(tab, data) {
  if (!tab) return;
  if (!tab.commandCaptureActive) {
    if (!tab.promptLikely && !tab.commandCaptureForced) return;
    tab.commandCaptureActive = true;
    tab.commandCaptureReliable = true;
    tab.commandLine = '';
  }
  if (!tab.commandCaptureReliable) return;
  if (data === '\x7f' || data === '\b') {
    tab.commandLine = [...tab.commandLine].slice(0, -1).join('');
    return;
  }
  if (data === '\x15') {
    tab.commandLine = '';
    return;
  }
  if (data === '\x17') {
    tab.commandLine = tab.commandLine.replace(/\s*\S+\s*$/, '');
    return;
  }
  if (data === '\x03' || data === '\x04') {
    resetTerminalCommandCapture(tab);
    return;
  }
  if (data.includes('\x1b') || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(data)) {
    tab.commandCaptureReliable = false;
    return;
  }
  tab.commandLine += data;
}

function isInterceptableTerminalCommand(command) {
  return Boolean(parseTerminalEditorCommand(command) || isVisualCrontabCommand(command));
}

function terminalBufferLogicalLine(tab) {
  const buffer = tab?.term?.buffer?.active;
  if (!buffer) return '';
  try {
    const currentY = buffer.baseY + buffer.cursorY;
    let firstY = currentY;
    while (firstY > 0 && buffer.getLine(firstY)?.isWrapped) firstY--;
    let text = '';
    for (let y = firstY; y <= currentY; y++) {
      const line = buffer.getLine(y);
      if (!line) continue;
      const end = y === currentY ? buffer.cursorX : undefined;
      text += line.translateToString(false, 0, end);
    }
    return text.trimEnd();
  } catch {
    return '';
  }
}

function terminalBufferCommand(tab) {
  const line = terminalBufferLogicalLine(tab);
  if (!line) return '';
  const promptMatch = line.match(/(?:^|[#$%❯>]\s*)((?:nano|vi|vim|crontab)\b.*)$/);
  if (promptMatch && isInterceptableTerminalCommand(promptMatch[1].trim())) return promptMatch[1].trim();
  const direct = line.trim();
  return isInterceptableTerminalCommand(direct) ? direct : '';
}

function terminalCommandForEnter(tab) {
  const candidates = [];
  if (tab?.commandCaptureActive && tab.commandCaptureReliable && tab.commandLine?.trim()) candidates.push(tab.commandLine.trim());
  const bufferCommand = terminalBufferCommand(tab);
  if (bufferCommand) candidates.push(bufferCommand);
  return candidates.filter(isInterceptableTerminalCommand).sort((a, b) => b.length - a.length)[0] || (candidates[0] || '');
}

function armTerminalCaptureAfterIntercept(tab) {
  resetTerminalCommandCapture(tab);
  tab.promptLikely = true;
  tab.commandCaptureForced = true;
}

function simpleShellWords(command) {
  const input = String(command || '').trim();
  if (!input || /[|;&<>`$()\n\r]/.test(input)) return null;
  const out = [];
  let word = '', quote = '', escaped = false;
  for (const ch of input) {
    if (escaped) { word += ch; escaped = false; continue; }
    if (ch === '\\' && quote !== "'") { escaped = true; continue; }
    if (quote) {
      if (ch === quote) quote = '';
      else word += ch;
      continue;
    }
    if (ch === "'" || ch === '"') { quote = ch; continue; }
    if (/\s/.test(ch)) {
      if (word) { out.push(word); word = ''; }
      continue;
    }
    word += ch;
  }
  if (escaped || quote) return null;
  if (word) out.push(word);
  return out;
}

function parseTerminalEditorCommand(command) {
  const words = simpleShellWords(command);
  if (!words?.length || !['nano', 'vi', 'vim'].includes(words[0])) return null;
  const paths = [];
  for (let i = 1; i < words.length; i++) {
    const word = words[i];
    if (word === '--') { paths.push(...words.slice(i + 1)); break; }
    if (word.startsWith('-') || (words[0] !== 'nano' && word.startsWith('+'))) continue;
    paths.push(word);
  }
  if (paths.length !== 1 || paths[0] === '-') return null;
  return { editor: words[0], path: paths[0] };
}

function isVisualCrontabCommand(command) {
  const words = simpleShellWords(command);
  return Boolean(words && words.length === 2 && words[0] === 'crontab' && words[1] === '-e');
}

function localServerPreferenceKey(serverId, kind) {
  return `zentssh.serverPref.${state.me?.id || 'user'}.${Number(serverId)}.${kind}`;
}

function getServerPreference(server, kind) {
  const property = kind === 'crontab' ? 'crontabEditorMode' : 'terminalEditorMode';
  const allowed = kind === 'crontab' ? new Set(['ask', 'visual', 'terminal']) : new Set(['ask', 'web', 'terminal']);
  const value = allowed.has(server?.[property]) ? server[property] : 'ask';
  if (value !== 'ask') return value;
  const local = localStorage.getItem(localServerPreferenceKey(server.id, kind));
  if (local && allowed.has(local)) return local;
  return 'ask';
}

async function saveServerPreference(server, kind, value) {
  if (!server?.id) return;
  const property = kind === 'crontab' ? 'crontabEditorMode' : 'terminalEditorMode';
  server[property] = value;
  localStorage.setItem(localServerPreferenceKey(server.id, kind), value);
  const body = kind === 'crontab' ? { crontabEditorMode: value } : { terminalEditorMode: value };
  try {
    const result = await api(`/servers/${server.id}/preferences`, { method: 'PATCH', body: JSON.stringify(body) });
    if (result.terminalEditorMode) server.terminalEditorMode = result.terminalEditorMode;
    if (result.crontabEditorMode) server.crontabEditorMode = result.crontabEditorMode;
  } catch (e) {
    showToast(`Editor-Auswahl konnte nur lokal gespeichert werden: ${e.message}`, true);
  }
}

function terminalEditorChoiceModal(kind, server) {
  const modal = $('#modal');
  if (!modal || modal.firstElementChild) return Promise.resolve('terminal');
  const crontab = kind === 'crontab';
  return new Promise(resolve => {
    let done = false;
    const finish = value => {
      if (done) return;
      done = true;
      modal.innerHTML = '';
      resolve(value);
    };
    modal.innerHTML = `<div class="backdrop"><div class="dialog terminal-choice-dialog">
      <div class="dialogtitle"><div><h3>${crontab ? 'Crontab bearbeiten' : 'Datei bearbeiten'}</h3><p>${crontab ? 'ZentSSH kann crontab -e als visuellen Editor öffnen.' : 'Wie sollen nano, vi und vim auf diesem Server geöffnet werden?'}</p></div><button data-close class="iconbutton" aria-label="Schließen">×</button></div>
      <div class="terminal-choice-cards">
        <button data-choice="${crontab ? 'visual' : 'web'}" class="terminal-choice primary-choice"><span>${actionIcon(crontab ? 'clock' : 'edit')}</span><div><b>${crontab ? 'Visuellen Editor verwenden' : 'ZentSSH Webeditor'}</b><small>${crontab ? 'Jobs zeilenweise und verständlich verwalten.' : 'Datei direkt im Browser bearbeiten und per SFTP speichern.'}</small></div></button>
        <button data-choice="terminal" class="terminal-choice"><span>${actionIcon('terminal')}</span><div><b>Im Terminal öffnen</b><small>${crontab ? 'crontab -e normal auf dem Server ausführen.' : 'Den gewählten Terminal-Editor normal starten.'}</small></div></button>
      </div>
      <p class="muted terminal-choice-note">Die Auswahl wird für „${esc(server.name)}“ gespeichert und kann in den Server-Einstellungen separat geändert werden.</p>
    </div></div>`;
    $('[data-close]', modal).onclick = () => finish('terminal');
    $$('[data-choice]', modal).forEach(button => button.onclick = () => finish(button.dataset.choice));
  });
}

function normalizeRemotePath(path) {
  const absolute = String(path || '').startsWith('/');
  const parts = [];
  for (const part of String(path || '').split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') { if (parts.length) parts.pop(); continue; }
    parts.push(part);
  }
  return `${absolute ? '/' : ''}${parts.join('/')}` || (absolute ? '/' : '.');
}

async function ensureTerminalHome(tab, server) {
  if (tab.homeDir) return tab.homeDir;
  const result = await api(`/files/${server.id}?path=.&realpath=1`);
  tab.homeDir = result.path || '.';
  if (!tab.cwd) {
    tab.cwd = tab.homeDir;
    tab.cwdVerified = true;
  }
  return tab.homeDir;
}

async function resolveEditorRemotePath(tab, server, rawPath) {
  const input = String(rawPath || '').trim();
  if (!input) throw new Error('Kein Dateipfad erkannt.');
  if (input.startsWith('/')) return normalizeRemotePath(input);
  const home = await ensureTerminalHome(tab, server);
  if (input === '~') return home;
  if (input.startsWith('~/')) return normalizeRemotePath(`${home}/${input.slice(2)}`);
  let cwd = tab.cwd || home;
  if (!cwd || cwd === '.') throw new Error('Aktuelles Terminal-Verzeichnis konnte nicht sicher bestimmt werden.');
  if (tab.cwdVerified === false) {
    const checked = await api(`/files/${server.id}?path=${encodeURIComponent(cwd)}&realpath=1`);
    cwd = checked.path || cwd;
    tab.cwd = cwd;
    tab.cwdVerified = true;
  }
  return normalizeRemotePath(`${cwd.replace(/\/$/, '')}/${input}`);
}

async function verifyTerminalCwd(tab, server, candidate, previous, previousVerified) {
  try {
    const checked = await api(`/files/${server.id}?path=${encodeURIComponent(candidate)}&realpath=1`);
    if (tab.cwd === candidate) {
      tab.cwd = checked.path || candidate;
      tab.cwdVerified = true;
    }
  } catch {
    if (tab.cwd === candidate) {
      tab.cwd = previous || null;
      tab.cwdVerified = Boolean(previous && previousVerified !== false);
    }
  }
}

async function trackTerminalCwdAfterCommand(tab, server, command) {
  const words = simpleShellWords(command);
  if (!words?.length) {
    if (/\b(?:cd|pushd|popd)\b/.test(String(command || ''))) { tab.cwd = null; tab.cwdVerified = false; }
    return;
  }
  if (['pushd', 'popd'].includes(words[0])) { tab.cwd = null; tab.cwdVerified = false; return; }
  if (words[0] !== 'cd') return;
  if (words.length > 2 || (words[1] && words[1].includes('$'))) { tab.cwd = null; tab.cwdVerified = false; return; }
  const arg = words[1];
  if (arg === '-') { tab.cwd = null; tab.cwdVerified = false; return; }
  const previous = tab.cwd;
  const previousVerified = tab.cwdVerified;
  let candidate = null;
  if (arg?.startsWith('/')) candidate = normalizeRemotePath(arg);
  else if (tab.cwd && arg && arg !== '~' && !arg.startsWith('~/')) candidate = normalizeRemotePath(`${tab.cwd.replace(/\/$/, '')}/${arg}`);
  if (candidate) {
    tab.cwd = candidate;
    tab.cwdVerified = false;
    verifyTerminalCwd(tab, server, candidate, previous, previousVerified);
    return;
  }
  try {
    const home = await ensureTerminalHome(tab, server);
    candidate = !arg || arg === '~' ? home : arg.startsWith('~/') ? normalizeRemotePath(`${home}/${arg.slice(2)}`) : normalizeRemotePath(`${home}/${arg}`);
    tab.cwd = candidate;
    tab.cwdVerified = candidate === home;
    if (candidate !== home) verifyTerminalCwd(tab, server, candidate, previous, previousVerified);
  } catch { tab.cwd = null; tab.cwdVerified = false; }
}

async function interceptTerminalCommand(tab, server, command, enterData) {
  if (!server?.id || tab.interceptPending) return false;
  const editor = parseTerminalEditorCommand(command);
  const crontab = isVisualCrontabCommand(command);
  if (!editor && !crontab) return false;
  tab.interceptPending = true;
  try {
    const kind = crontab ? 'crontab' : 'editor';
    let mode = getServerPreference(server, kind);
    if (mode === 'ask') {
      mode = await terminalEditorChoiceModal(kind, server);
      saveServerPreference(server, kind, mode);
    }
    if (mode === 'terminal') {
      tab.commandCaptureForced = false;
      sendTerminalInput(tab, enterData);
      return true;
    }

    // The command has been typed into the remote TTY but Enter was withheld.
    // Ctrl-U clears the pending shell line so nano/vim/crontab never starts.
    sendTerminalInput(tab, '\x15');
    if (crontab) {
      await openCrontabEditor(server.id, server.name);
      armTerminalCaptureAfterIntercept(tab);
      return true;
    }
    try {
      const remotePath = await resolveEditorRemotePath(tab, server, editor.path);
      await fileEditorModal(server.id, remotePath, parent(remotePath), { createIfMissing: true, source: editor.editor });
      armTerminalCaptureAfterIntercept(tab);
    } catch (e) {
      showToast(`${e.message} Terminal-Befehl wird normal ausgeführt.`, true);
      tab.commandCaptureForced = false;
      sendTerminalInput(tab, `${command}${enterData}`);
    }
    return true;
  } finally {
    tab.interceptPending = false;
  }
}

function handleTerminalData(tab, server, data) {
  if (!tab || tab.interceptPending) return;
  if (data === '\r' || data === '\n') {
    const command = terminalCommandForEnter(tab);
    const canIntercept = isInterceptableTerminalCommand(command);
    resetTerminalCommandCapture(tab);
    tab.promptLikely = false;
    if (canIntercept) {
      interceptTerminalCommand(tab, server, command, data);
      return;
    }
    tab.commandCaptureForced = false;
    sendTerminalInput(tab, data);
    if (command) trackTerminalCwdAfterCommand(tab, server, command);
    return;
  }
  updateTerminalCommandCapture(tab, data);
  sendTerminalInput(tab, data);
}

function startTerminal(tid, server) {
  const tab = state.tabs.find(t => t.id === tid);
  const element = tab?.termElement;
  if (!tab || !element || !tab.sessionId) return;
  if (!tab.term) {
    const term = new Terminal({ cursorBlink: true, fontFamily: 'ui-monospace,SFMono-Regular,Menlo,Consolas,monospace', fontSize: 14, theme: { background: '#0b1017', foreground: '#d8e2ef' } });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(element);
    fit.fit();
    tab.term = term; tab.fit = fit;
    term.onData(data => handleTerminalData(tab, server, data));
    term.onBinary(data => {
      if (tab.ws?.readyState !== WebSocket.OPEN) return;
      const bytes = Uint8Array.from(data, character => character.charCodeAt(0) & 0xff);
      tab.ws.send(bytes);
    });
    term.onResize(size => { if (tab.ws?.readyState === WebSocket.OPEN) tab.ws.send(JSON.stringify({ type: 'resize', cols: size.cols, rows: size.rows })); });
    const resize = () => { if (state.active === tid) fit.fit(); };
    window.addEventListener('resize', resize, { passive: true });
    tab.resize = resize;
  } else {
    tab.fit?.fit();
  }
  if (server?.id && !tab.homePrefetchStarted) {
    tab.homePrefetchStarted = true;
    ensureTerminalHome(tab, server).catch(() => { tab.homePrefetchStarted = false; });
  }
  connectTerminal(tab, server);
}

function connectTerminal(tab, server) {
  if (!tab || tab.closing || !state.tabs.includes(tab)) return;
  if (tab.ws && (tab.ws.readyState === WebSocket.OPEN || tab.ws.readyState === WebSocket.CONNECTING)) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/ssh/${encodeURIComponent(tab.sessionId)}`);
  ws.binaryType = 'arraybuffer';
  tab.ws = ws;
  ws.onopen = () => {
    tab.reconnectDelay = 750;
    tab.reconnectNotice = false;
    tab.fit?.fit();
    ws.send(JSON.stringify({ type: 'resize', cols: tab.term.cols, rows: tab.term.rows }));
  };
  ws.onmessage = event => {
    if (typeof event.data === 'string') {
      observeTerminalOutput(tab, event.data);
      tab.term.write(event.data);
    } else {
      const bytes = new Uint8Array(event.data);
      try { observeTerminalOutput(tab, new TextDecoder().decode(bytes)); } catch { /* binary terminal output can stay unobserved */ }
      tab.term.write(bytes);
    }
  };
  ws.onclose = event => {
    if (tab.closing || !state.tabs.includes(tab)) return;
    if (event.code === 1000 && event.reason) {
      untrackSession(tab.sessionId);
      const sessionName = tab.name || server?.name || tab.sessionId;
      const message = event.reason === 'remote_closed' ? `SSH-Session „${sessionName}“ beendet.` : `SSH-Session „${sessionName}“ geschlossen.`;
      closeTab(tab.id, false);
      showToast(message);
      return;
    }
    if (!tab.reconnectNotice) {
      tab.term.write('\r\n\x1b[33m[Verbindung unterbrochen. Wiederverbinden…]\x1b[0m\r\n');
      tab.reconnectNotice = true;
    }
    const delay = Math.min(tab.reconnectDelay || 750, 10000);
    tab.reconnectDelay = Math.min(delay * 1.7, 10000);
    clearTimeout(tab.reconnectTimer);
    tab.reconnectTimer = setTimeout(async () => {
      if (tab.closing || !state.tabs.includes(tab)) return;
      try {
        await api(`/sessions/${encodeURIComponent(tab.sessionId)}`);
        connectTerminal(tab, server);
      } catch (e) {
        if (e.status === 404) {
          untrackSession(tab.sessionId);
          closeTab(tab.id, false);
          showToast(`SSH-Session „${tab.name || server?.name || tab.sessionId}“ beendet.`);
        } else {
          connectTerminal(tab, server);
        }
      }
    }, delay);
  };
}

function activate(id) {
  const tab = state.tabs.find(t => t.id === id);
  if (!tab) return;
  state.active = id;
  renderTabs();
  if (tab.type === 'files') {
    renderFileTab(tab, tab.filePath || '.');
    return;
  }
  const server = state.servers.find(s => s.id === tab.serverId) || tab.serverSnapshot;
  if (!server) return;
  paintTerminal(id, server);
  if (tab.term) {
    tab.fit.fit();
    if (!tab.ws || tab.ws.readyState === WebSocket.CLOSED) connectTerminal(tab, server);
  } else startTerminal(id, server);
}

function closeTab(id, deleteRemote = true) {
  const index = state.tabs.findIndex(t => t.id === id);
  if (index < 0) return;
  const tab = state.tabs[index];
  const wasActive = state.active === id;
  tab.closing = true;
  if ((tab.type || 'terminal') === 'terminal') {
    clearTimeout(tab.reconnectTimer);
    tab.ws?.close();
    if (tab.sessionId) {
      untrackSession(tab.sessionId);
      if (deleteRemote) api(`/sessions/${encodeURIComponent(tab.sessionId)}`, { method: 'DELETE' }).catch(() => {});
    }
    if (tab.resize) window.removeEventListener('resize', tab.resize);
    tab.term?.dispose();
  }
  state.tabs.splice(index, 1);
  saveTabOrder();
  if (wasActive) {
    const fallback = state.tabs[Math.min(index, state.tabs.length - 1)] || state.tabs.at(-1);
    state.active = fallback?.id || null;
  }
  renderTabs();
  if (wasActive && state.active) activate(state.active);
  else if (wasActive && !state.active) $('#workspace').innerHTML = `<div class="empty"><h2>${L('Server auswählen → arbeiten.','Select a server → start working.')}</h2><p>${L('Rechtsklick auf einen Server öffnet SSH, Transfer und Einstellungen.','Right-click a server to open SSH, file transfer or settings.')}</p></div>`;
}

const IMAGE_FILE_EXTENSIONS = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp', 'avif', 'ico']);
function isImageFile(remotePath = '') {
  const name = remoteNameFromPath(remotePath).toLowerCase();
  const dot = name.lastIndexOf('.');
  return dot > -1 && IMAGE_FILE_EXTENSIONS.has(name.slice(dot + 1));
}

function sortRemoteEntries(entries = []) {
  return [...entries].sort((a, b) => {
    const aHidden = String(a?.name || '').startsWith('.');
    const bHidden = String(b?.name || '').startsWith('.');
    // Normal folders A-Z, normal files A-Z, then hidden folders A-Z and hidden files A-Z.
    const bucket = entry => {
      const hidden = String(entry?.name || '').startsWith('.');
      return hidden ? (entry?.dir ? 2 : 3) : (entry?.dir ? 0 : 1);
    };
    const bucketDiff = bucket(a) - bucket(b);
    if (bucketDiff) return bucketDiff;
    if (aHidden !== bHidden) return aHidden ? 1 : -1;
    return String(a?.name || '').localeCompare(String(b?.name || ''), undefined, { sensitivity: 'base', numeric: true });
  });
}

async function openFiles(serverId, path = '.') {
  const server = knownServer(serverId);
  if (!server) return;
  let tab = state.tabs.find(t => t.type === 'files' && Number(t.serverId) === Number(serverId));
  if (!tab) {
    tab = {
      id: `f${Date.now()}${Math.random().toString(16).slice(2, 7)}`,
      type: 'files',
      name: server.name,
      serverId: Number(serverId),
      filePath: path || '.',
      serverSnapshot: { ...server },
    };
    state.tabs.push(tab);
    saveTabOrder();
  }
  tab.name = server.name;
  tab.serverSnapshot = { ...server };
  tab.filePath = path || tab.filePath || '.';
  state.active = tab.id;
  state.fileServer = Number(serverId);
  state.filePath = tab.filePath;
  renderTabs();
  await renderFileTab(tab, tab.filePath);
}

async function renderFileTab(tab, path = '.') {
  closeFileContextMenu();
  if (!tab || tab.type !== 'files' || !state.tabs.includes(tab)) return;
  const serverId = Number(tab.serverId);
  const currentServer = state.servers.find(s => Number(s.id) === serverId);
  const server = currentServer || tab.serverSnapshot;
  if (!server) {
    closeTab(tab.id, false);
    return;
  }
  if (currentServer) tab.serverSnapshot = { ...currentServer };
  state.active = tab.id;
  state.fileServer = serverId;
  state.filePath = path;
  tab.filePath = path;
  const workspace = $('#workspace');
  if (!workspace) return;

  if (!tab.filePanel) {
    workspace.innerHTML = `<div class="fileworkspace"><div class="fileloading">Verbinde mit ${esc(server.name)}…</div></div>`;
    try {
      await ensureServerReady(serverId);
    } catch (e) {
      workspace.innerHTML = `<div class="fileworkspace"><div class="fileempty errorstate"><b>Files konnten nicht geöffnet werden</b><span>${esc(e.message === 'cancelled' ? 'Verbindung abgebrochen.' : e.message)}</span><button id="file-connect-retry">${iconLabel('retry', 'Erneut versuchen')}</button></div></div>`;
      if ($('#file-connect-retry')) $('#file-connect-retry').onclick = () => renderFileTab(tab, path);
      if (e.message !== 'cancelled') showToast(e.message, true);
      return;
    }
    tab.filePanel = createFilePanel(tab, server);
  }

  if (workspace.firstElementChild !== tab.filePanel) workspace.replaceChildren(tab.filePanel);
  await refreshFileDirectory(tab, path, { initial: !tab.fileLoadedOnce });
}

function createFilePanel(tab, server) {
  const panel = document.createElement('div');
  panel.className = 'fileworkspace';
  panel.innerHTML = `
    <div class="filetopbar">
      <div class="fileidentity"><span class="fileidentity-icon">${tabIcon('files')}</span><div><strong>${esc(server.name)}</strong><small>${esc(server.username)}@${esc(server.host)}:${Number(server.port || 22)}</small></div></div>
      <div class="filetop-actions">
        <button data-file-action="hidden" class="icononly file-top-action has-tooltip" aria-label="Versteckte Dateien" data-tooltip="Versteckte Dateien">${actionIcon('eyeOff')}</button>
        <button data-file-action="dual" class="icononly file-top-action has-tooltip" aria-label="Dual-Ansicht" data-tooltip="Dual-Ansicht">${actionIcon('dual')}</button>
        <button data-file-action="create-menu" class="icononly file-top-action has-tooltip" aria-label="Neu / Upload" data-tooltip="Neu / Upload">${actionIcon('plus')}</button><input data-file-upload type="file" hidden>
      </div>
    </div>
    <div class="filepathrow">
      <div data-file-breadcrumbs class="file-breadcrumbs"></div>
      <div class="filepathinput"><input data-file-path value="${esc(tab.filePath || '.')}" autocomplete="off"><button data-file-action="open" class="button-with-icon">${iconLabel('open', 'Öffnen')}</button></div>
    </div>
    <div data-upload-progress class="upload-progress" hidden><i></i><span>Upload…</span></div>
    <div class="filelist-head"><span>Name</span><span>Größe</span><span>Rechte</span></div>
    <div data-file-body class="filebody clean-filebody"><div class="fileloading">Lade Verzeichnis…</div></div>`;

  const pathInput = $('[data-file-path]', panel);
  $('[data-file-action="open"]', panel).onclick = () => refreshFileDirectory(tab, pathInput.value.trim() || '.');
  pathInput.addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      event.preventDefault();
      refreshFileDirectory(tab, pathInput.value.trim() || '.');
    }
  });
  $('[data-file-action="hidden"]', panel).onclick = () => toggleHiddenFiles(async () => {
    updateFileHiddenButton(tab);
    await refreshFileDirectory(tab, tab.filePath || '.');
  }, () => updateFileHiddenButton(tab));
  $('[data-file-action="dual"]', panel).onclick = () => openDualFiles(Number(tab.serverId), Number(tab.serverId), tab.filePath || '.', tab.filePath || '.');
  if ($('[data-file-action="create-menu"]', panel)) $('[data-file-action="create-menu"]', panel).onclick = event => showFileCreateMenu(event, tab, $('[data-file-action="create-menu"]', panel));
  if ($('[data-file-upload]', panel)) $('[data-file-upload]', panel).onchange = async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    const currentPath = tab.filePath || '.';
    const dest = joinRemotePath(currentPath, file.name);
    try {
      await uploadRemoteFile(Number(tab.serverId), dest, file, panel);
      event.target.value = '';
      await refreshFileDirectory(tab, currentPath);
      showToast(`${file.name} hochgeladen.`);
    } catch (e) { showToast(e.message, true); }
  };
  const body = $('[data-file-body]', panel);
  panel.oncontextmenu = event => {
    if (!event.target.closest('[data-file-body]') && event.target !== panel) return;
    if (event.target.closest('.file-entry,button,input,select,textarea,label,a')) return;
    event.preventDefault();
    event.stopPropagation();
    showFileBackgroundContextMenu(event, tab, body || panel, canWriteFiles);
  };
  updateFileHiddenButton(tab);
  return panel;
}

function updateFileHiddenButton(tab) {
  const button = tab?.filePanel?.querySelector('[data-file-action="hidden"]');
  if (!button) return;
  const shown = Boolean(state.userSettings?.showHiddenFiles);
  const label = shown ? 'Versteckte Dateien ausblenden' : 'Versteckte Dateien anzeigen';
  button.innerHTML = actionIcon(shown ? 'eye' : 'eyeOff');
  button.classList.toggle('active', shown);
  button.setAttribute('aria-label', label);
  button.dataset.tooltip = label;
}

async function toggleHiddenFiles(onChanged = null, onRollback = null) {
  const oldValue = Boolean(state.userSettings.showHiddenFiles);
  state.userSettings.showHiddenFiles = !oldValue;
  try {
    await api('/me/settings', { method: 'PATCH', body: JSON.stringify({ sshSessionRetention: state.userSettings.sshSessionRetention || 'inherit', showHiddenFiles: state.userSettings.showHiddenFiles, language: state.userSettings.language || state.me?.language || uiLanguage(), collapsedFolderIds: normalizedCollapsedFolderIds() }) });
    if (onChanged) await onChanged();
  } catch (e) {
    state.userSettings.showHiddenFiles = oldValue;
    if (onRollback) onRollback();
    showToast(e.message, true);
  }
}

function showFileCreateMenu(event, tab, anchor) {
  const menu = $('#file-context-menu');
  if (!menu || !tab?.filePanel) return;
  closeServerContextMenu();
  closeFileContextMenu();
  const items = [
    { action: 'upload', label: 'Datei hochladen', icon: actionIcon('upload') },
    { action: 'url-upload', label: 'Upload via URL', icon: actionIcon('urlUpload') },
    { separator: true },
    { action: 'new-file', label: 'Neue Datei', icon: actionIcon('newFile') },
    { action: 'new-folder', label: 'Neuer Ordner', icon: actionIcon('newFolder') },
  ];
  menu.innerHTML = items.map(item => item.separator ? '<div class="context-separator"></div>' : `<button data-action="${item.action}"><span>${item.icon}</span><b>${esc(item.label)}</b></button>`).join('');
  menu.hidden = false;
  menu.oncontextmenu = e => e.preventDefault();
  positionContextMenu(menu, event, anchor);
  $$('button[data-action]', menu).forEach(button => {
    button.onclick = () => {
      const action = button.dataset.action;
      closeFileContextMenu();
      const serverId = Number(tab.serverId);
      const currentPath = tab.filePath || '.';
      const refresh = () => refreshFileDirectory(tab, currentPath);
      if (action === 'new-file') return newRemoteItemModal(serverId, currentPath, 'file', refresh);
      if (action === 'new-folder') return newRemoteItemModal(serverId, currentPath, 'folder', refresh);
      if (action === 'upload') return $('[data-file-upload]', tab.filePanel)?.click();
      if (action === 'url-upload') return urlUploadModal(serverId, currentPath, refresh);
    };
  });
}

async function refreshFileDirectory(tab, path = '.', options = {}) {
  if (!tab?.filePanel || !state.tabs.includes(tab)) return;
  const serverId = Number(tab.serverId);
  const panel = tab.filePanel;
  const body = $('[data-file-body]', panel);
  const requestId = (tab.fileRefreshSeq || 0) + 1;
  tab.fileRefreshSeq = requestId;
  closeFileContextMenu();
  panel.classList.add('file-refreshing');
  body?.setAttribute('aria-busy', 'true');
  if (options.initial && body) body.innerHTML = '<div class="fileloading">Lade Verzeichnis…</div>';

  let data;
  try {
    data = await api(`/files/${serverId}?path=${encodeURIComponent(path)}`);
  } catch (e) {
    if (requestId !== tab.fileRefreshSeq) return;
    panel.classList.remove('file-refreshing');
    body?.removeAttribute('aria-busy');
    if (!tab.fileLoadedOnce && body) {
      body.innerHTML = `<div class="fileempty errorstate"><b>Verzeichnis konnte nicht geladen werden</b><span>${esc(e.message)}</span><button data-file-retry class="button-with-icon">${iconLabel('retry', 'Erneut versuchen')}</button></div>`;
      $('[data-file-retry]', body).onclick = () => refreshFileDirectory(tab, path, { initial: true });
    } else showToast(e.message, true);
    return;
  }
  if (requestId !== tab.fileRefreshSeq) return;

  path = data.path || path;
  tab.filePath = path;
  tab.fileLoadedOnce = true;
  state.filePath = path;
  state.fileServer = serverId;
  const pathInput = $('[data-file-path]', panel);
  if (pathInput && document.activeElement !== pathInput) pathInput.value = path;
  const breadcrumbs = $('[data-file-breadcrumbs]', panel);
  if (breadcrumbs) {
    breadcrumbs.innerHTML = remoteBreadcrumbs(path);
    $$('.crumb', breadcrumbs).forEach(button => button.onclick = () => refreshFileDirectory(tab, button.dataset.path));
  }
  updateFileHiddenButton(tab);

  const parentColor = configuredServerColor(serverId);
  const parentRow = path === '.' || path === '/' ? '' : `<div class="file-entry parent-entry" data-path="${esc(parent(path))}" data-dir="1" data-name=".." tabindex="0"><div class="file-name-cell"><span class="file-type-icon parent-icon" style="color:${esc(parentColor)}">↰</span><div><b>..</b><small>Eine Ebene hoch</small></div></div><span></span><span></span></div>`;
  const sortedEntries = sortRemoteEntries(data.entries || []);
  if (body) {
    body.innerHTML = parentRow + (sortedEntries.length ? sortedEntries.map(entry => `<div class="file-entry" data-path="${esc(entry.path)}" data-dir="${entry.dir ? 1 : 0}" data-name="${esc(entry.name)}" data-uid="${entry.uid == null ? '' : esc(entry.uid)}" data-gid="${entry.gid == null ? '' : esc(entry.gid)}" tabindex="0">
      <div class="file-name-cell"><span class="file-type-icon">${actionIcon(entry.dir ? 'folder' : (isImageFile(entry.name) ? 'image' : 'file'))}</span><div><b>${esc(entry.name)}</b><small>${entry.dir ? 'Ordner' : (isImageFile(entry.name) ? 'Bild' : 'Datei')}</small></div></div>
      <span class="file-size">${entry.dir ? '—' : fmtSize(entry.size)}</span>
      <span class="file-mode">${esc(entry.mode)}</span>
    </div>`).join('') : '<div class="fileempty"><b>Dieser Ordner ist leer.</b><span>Rechtsklick hier öffnet die Dateiaktionen.</span></div>');

    $$('.file-entry', body).forEach(row => {
      const isDir = row.dataset.dir === '1';
      if (isDir) row.onclick = () => refreshFileDirectory(tab, row.dataset.path);
      else row.ondblclick = () => isImageFile(row.dataset.path) ? imageViewerModal(serverId, row.dataset.path) : fileEditorModal(serverId, row.dataset.path, path);
      if (!row.classList.contains('parent-entry')) {
        row.oncontextmenu = event => {
          event.preventDefault();
          event.stopPropagation();
          showFileContextMenu(event, row, serverId, row.dataset.path, row.dataset.name, isDir, path, true, {
            uid: numericDatasetValue(row.dataset.uid),
            gid: numericDatasetValue(row.dataset.gid),
          });
        };
        row.onkeydown = event => {
          if (event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')) {
            event.preventDefault();
            row.oncontextmenu({ preventDefault() {}, stopPropagation() {}, clientX: 0, clientY: 0 });
          }
        };
      }
    });
  }
  panel.classList.remove('file-refreshing');
  body?.removeAttribute('aria-busy');
}

function showFileBackgroundContextMenu(event, tab, anchor, canWrite) {
  const menu = $('#file-context-menu');
  if (!menu) return;
  closeServerContextMenu();
  closeFileContextMenu();
  const hiddenShown = Boolean(state.userSettings?.showHiddenFiles);
  const items = [];
  if (canWrite) {
    items.push({ action: 'new-file', label: 'Neue Datei', icon: actionIcon('newFile') });
    items.push({ action: 'new-folder', label: 'Neuer Ordner', icon: actionIcon('newFolder') });
    items.push({ action: 'upload', label: 'Datei hochladen', icon: actionIcon('upload') });
    items.push({ action: 'url-upload', label: 'Upload via URL', icon: actionIcon('urlUpload') });
    items.push({ separator: true });
  }
  items.push({ action: 'hidden', label: hiddenShown ? 'Versteckte ausblenden' : 'Versteckte anzeigen', icon: actionIcon(hiddenShown ? 'eye' : 'eyeOff') });
  items.push({ action: 'dual', label: 'Dual-Ansicht', icon: actionIcon('dual') });
  items.push({ action: 'refresh', label: 'Neu laden', icon: actionIcon('refresh') });
  menu.innerHTML = `<div class="server-context-title file-context-title file-background-title"><span class="file-context-title-icon">${actionIcon('folder')}</span><div><strong>${esc(tab.filePath || '.')}</strong><small>Dateibrowser</small></div></div>${items.map(item => item.separator ? '<div class="context-separator"></div>' : `<button data-action="${item.action}"><span>${item.icon}</span><b>${esc(item.label)}</b></button>`).join('')}`;
  menu.hidden = false;
  menu.oncontextmenu = e => e.preventDefault();
  positionContextMenu(menu, event, anchor);
  $$('button[data-action]', menu).forEach(button => {
    button.onclick = async () => {
      const action = button.dataset.action;
      closeFileContextMenu();
      const serverId = Number(tab.serverId);
      const currentPath = tab.filePath || '.';
      const refresh = () => refreshFileDirectory(tab, currentPath);
      if (action === 'new-file') return newRemoteItemModal(serverId, currentPath, 'file', refresh);
      if (action === 'new-folder') return newRemoteItemModal(serverId, currentPath, 'folder', refresh);
      if (action === 'upload') return $('[data-file-upload]', tab.filePanel)?.click();
      if (action === 'url-upload') return urlUploadModal(serverId, currentPath, refresh);
      if (action === 'dual') return openDualFiles(serverId, serverId, currentPath, currentPath);
      if (action === 'refresh') return refreshFileDirectory(tab, currentPath);
      if (action === 'hidden') return $('[data-file-action="hidden"]', tab.filePanel)?.click();
    };
  });
}

function closeFileContextMenu() {
  const menu = $('#file-context-menu');
  $$('.file-entry.context-open,.pane-row.context-open').forEach(row => row.classList.remove('context-open'));
  if (!menu || menu.hidden) return false;
  menu.hidden = true;
  menu.innerHTML = '';
  return true;
}

function showFileContextMenu(event, row, serverId, remotePath, name, isDir, currentPath, canWrite, options = {}) {
  const menu = $('#file-context-menu');
  if (!menu) return;
  closeServerContextMenu();
  $$('.file-entry.context-open,.pane-row.context-open').forEach(item => item.classList.remove('context-open'));
  row?.classList.add('context-open');
  const items = [];
  const imageFile = !isDir && isImageFile(remotePath || name);
  if (isDir) items.push({ action: 'open', label: 'Öffnen', icon: actionIcon('open') });
  else {
    items.push({ action: imageFile ? 'view' : 'edit', label: imageFile ? 'Anschauen' : 'Im Editor öffnen', icon: actionIcon(imageFile ? 'image' : 'edit') });
    items.push({ action: 'download', label: 'Herunterladen', icon: actionIcon('download') });
  }
  if (canWrite) {
    items.push({ separator: true });
    items.push({ action: 'rename', label: 'Umbenennen / Verschieben', icon: actionIcon('rename') });
    items.push({ action: 'chmod', label: 'Rechte ändern', icon: actionIcon('permissions') });
    items.push({ action: 'chown', label: 'Eigentümer ändern', icon: actionIcon('owner') });
    items.push({ action: 'transfer', label: 'Server-Transfer', icon: actionIcon('transfer') });
    items.push({ separator: true });
    items.push({ action: 'delete', label: 'Löschen', icon: actionIcon('delete'), danger: true });
  }
  menu.innerHTML = `<div class="server-context-title file-context-title"><span class="file-context-title-icon">${actionIcon(isDir ? 'folder' : (imageFile ? 'image' : 'file'))}</span><div><strong>${esc(name || remoteNameFromPath(remotePath))}</strong><small>${isDir ? 'Ordner' : (imageFile ? 'Bild' : 'Datei')}</small></div></div>${items.map(item => item.separator ? '<div class="context-separator"></div>' : `<button data-action="${item.action}" class="${item.danger ? 'context-danger' : ''}"><span>${item.icon}</span><b>${esc(item.label)}</b></button>`).join('')}`;
  menu.hidden = false;
  menu.oncontextmenu = e => e.preventDefault();
  positionContextMenu(menu, event, row);
  $$('button[data-action]', menu).forEach(button => {
    button.onclick = async () => {
      const action = button.dataset.action;
      closeFileContextMenu();
      if (action === 'open') return options.openDir ? options.openDir(remotePath) : openFiles(serverId, remotePath);
      if (action === 'view') return imageViewerModal(serverId, remotePath);
      if (action === 'edit') return fileEditorModal(serverId, remotePath, currentPath);
      if (action === 'download') { location.href = `${A}/files/${serverId}?path=${encodeURIComponent(remotePath)}&download=1`; return; }
      if (action === 'transfer') return transferModal(serverId, remotePath);
      if (action === 'rename') return promptRemoteAction('Umbenennen / Verschieben', 'Neuer vollständiger Pfad', remotePath, async value => {
        await api(`/files/${serverId}`, { method: 'POST', body: JSON.stringify({ action: 'rename', path: remotePath, target: value }) });
      }, serverId, currentPath, options.onChanged);
      if (action === 'chmod') return promptRemoteAction('Dateirechte ändern', 'Oktaler Modus', isDir ? '0755' : '0644', async value => {
        if (!/^0?[0-7]{3,4}$/.test(value)) throw new Error('Ungültiger chmod-Modus. Beispiel: 0644 oder 0755.');
        await api(`/files/${serverId}`, { method: 'POST', body: JSON.stringify({ action: 'chmod', path: remotePath, mode: value }) });
      }, serverId, currentPath, options.onChanged);
      if (action === 'chown') return chownRemoteModal(serverId, remotePath, currentPath, options.onChanged, { uid: options.uid, gid: options.gid });
      if (action === 'delete') await deleteRemoteItem(serverId, remotePath, name, isDir, currentPath, options.onChanged);
    };
  });
}

async function refreshFileAfterMutation(serverId, currentPath, onChanged = null) {
  if (onChanged) return onChanged();
  const tab = state.tabs.find(item => item.type === 'files' && Number(item.serverId) === Number(serverId));
  if (tab?.filePanel) return refreshFileDirectory(tab, currentPath);
  return openFiles(serverId, currentPath);
}

async function deleteRemoteItem(serverId, remotePath, name, isDir, currentPath, onChanged = null) {
  const safeName = name || remoteNameFromPath(remotePath);
  if (!confirm(`${isDir ? 'Ordner' : 'Datei'} „${safeName}“ wirklich löschen?${isDir ? '\nNicht-leere Ordner werden aus Sicherheitsgründen nicht rekursiv gelöscht.' : ''}`)) return;
  try {
    await api(`/files/${serverId}?path=${encodeURIComponent(remotePath)}`, { method: 'DELETE' });
    await refreshFileAfterMutation(serverId, currentPath, onChanged);
    showToast('Gelöscht.');
  } catch (e) { showToast(e.message, true); }
}

function remoteBreadcrumbs(remotePath) {
  const raw = String(remotePath || '.');
  if (raw === '.' || raw === '') return '<button class="crumb" data-path=".">.</button>';
  const absolute = raw.startsWith('/');
  const parts = raw.split('/').filter(Boolean);
  const out = [absolute ? '<button class="crumb" data-path="/">/</button>' : '<button class="crumb" data-path=".">.</button>'];
  let current = absolute ? '' : '.';
  for (const part of parts) {
    current = absolute ? `${current}/${part}` : (current === '.' ? part : `${current}/${part}`);
    out.push(`<span>/</span><button class="crumb" data-path="${esc(current || '/')}">${esc(part)}</button>`);
  }
  return out.join('');
}

function uploadRemoteFile(serverId, remotePath, file, panel = null) {
  return new Promise((resolve, reject) => {
    const root = panel?.querySelector('[data-upload-progress]') || $('#upload-progress'); const bar = root?.querySelector('i'); const label = root?.querySelector('span');
    if (root) root.hidden = false;
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', `${A}/files/${serverId}?path=${encodeURIComponent(remotePath)}`);
    const csrf = cookieValue('zentssh_csrf'); if (csrf) xhr.setRequestHeader('X-CSRF-Token', csrf);
    xhr.upload.onprogress = event => {
      if (!event.lengthComputable) return;
      const pct = Math.max(0, Math.min(100, Math.round(event.loaded / event.total * 100)));
      if (bar) bar.style.width = `${pct}%`; if (label) label.textContent = `Upload ${pct}% · ${fmtSize(event.loaded)} / ${fmtSize(event.total)}`;
    };
    xhr.onerror = () => { if (root) root.hidden = true; reject(new Error('Upload-Verbindung fehlgeschlagen.')); };
    xhr.onload = () => {
      if (root) root.hidden = true;
      if (xhr.status >= 200 && xhr.status < 300) resolve();
      else { let msg = xhr.responseText || `HTTP ${xhr.status}`; try { msg = JSON.parse(msg).error || msg; } catch {} reject(new Error(msg)); }
    };
    xhr.send(file);
  });
}

function remoteNameFromPath(remotePath) {
  const parts = String(remotePath || '').split('/').filter(Boolean);
  return parts.at(-1) || '';
}

function suggestedRemoteNameFromURL(rawURL) {
  try {
    const url = new URL(String(rawURL || '').trim());
    let name = decodeURIComponent(url.pathname.split('/').filter(Boolean).at(-1) || 'download');
    name = name.replace(/[\\/\0]/g, '').trim();
    return name || 'download';
  } catch {
    return '';
  }
}

function urlUploadModal(serverId, currentPath, onChanged = null) {
  const modal = $('#modal');
  modal.innerHTML = `<div class="backdrop"><div class="dialog fileactiondialog">
    <div class="dialogtitle"><div><h3>Upload via URL</h3><p>ZentSSH lädt die Datei serverseitig und streamt sie direkt per SFTP nach <code>${esc(currentPath)}</code>.</p></div><button data-close class="iconbutton" aria-label="Schließen">×</button></div>
    <label>Webadresse<input id="url-upload-url" type="url" placeholder="https://example.com/datei.tar.gz" autocomplete="off" spellcheck="false"></label>
    <label>Dateiname<input id="url-upload-name" placeholder="datei.tar.gz" autocomplete="off" spellcheck="false"></label>
    <div class="securitynote">Nur öffentliche HTTP/HTTPS-Ziele sind erlaubt. Lokale/private Adressen und Redirects dorthin werden blockiert.</div>
    <div id="url-upload-error" class="err"></div>
    <div class="actions"><button data-cancel>Abbrechen</button><button id="url-upload-start" class="primary">Download starten</button></div>
  </div></div>`;
  const close = () => { modal.innerHTML = ''; };
  $('[data-close]', modal).onclick = close;
  $('[data-cancel]', modal).onclick = close;
  const urlInput = $('#url-upload-url');
  const nameInput = $('#url-upload-name');
  let nameWasEdited = false;
  nameInput.addEventListener('input', () => { nameWasEdited = true; });
  urlInput.addEventListener('input', () => {
    if (!nameWasEdited || !nameInput.value.trim()) nameInput.value = suggestedRemoteNameFromURL(urlInput.value);
  });
  $('#url-upload-start').onclick = async () => {
    const rawURL = urlInput.value.trim();
    const name = nameInput.value.trim();
    const error = $('#url-upload-error');
    error.textContent = '';
    if (!/^https?:\/\//i.test(rawURL)) { error.textContent = 'Bitte eine vollständige http:// oder https:// Adresse eingeben.'; return; }
    if (!name || name === '.' || name === '..' || name.includes('/') || name.includes('\\')) { error.textContent = 'Bitte einen gültigen Dateinamen ohne / oder \\ eingeben.'; return; }
    const button = $('#url-upload-start');
    setButtonBusy(button, true, 'Lade herunter…');
    try {
      await api(`/files/${serverId}`, { method: 'POST', body: JSON.stringify({ action: 'download_url', path: joinRemotePath(currentPath, name), url: rawURL }) });
      close();
      await refreshFileAfterMutation(serverId, currentPath, onChanged);
      showToast(`„${name}“ heruntergeladen.`);
    } catch (e) {
      error.textContent = e.message;
      setButtonBusy(button, false);
    }
  };
  setTimeout(() => urlInput.focus(), 0);
}

function newRemoteItemModal(serverId, currentPath, fixedType = null, onChanged = null) {
  const modal = $('#modal');
  const typeLabel = fixedType === 'folder' ? 'Neuer Ordner' : fixedType === 'file' ? 'Neue Datei' : 'Neu anlegen';
  modal.innerHTML = `<div class="backdrop"><div class="dialog fileactiondialog"><div class="dialogtitle"><div><h3>${typeLabel}</h3><p>${esc(currentPath)}</p></div><button data-close class="iconbutton">×</button></div>
    ${fixedType ? '' : '<label>Typ<select id="new-remote-type"><option value="file">Datei</option><option value="folder">Ordner</option></select></label>'}
    <label>Name<input id="new-remote-name" autocomplete="off" placeholder="${fixedType === 'folder' ? 'neuer-ordner' : 'compose.yml'}"></label>
    <div id="new-remote-error" class="err"></div><div class="actions"><button data-cancel>Abbrechen</button><button id="new-remote-save" class="primary">Anlegen</button></div></div></div>`;
  const close = () => { modal.innerHTML = ''; };
  $('[data-close]', modal).onclick = close; $('[data-cancel]', modal).onclick = close;
  $('#new-remote-save').onclick = async () => {
    const name = $('#new-remote-name').value.trim();
    if (!name || name === '.' || name === '..' || name.includes('/')) { $('#new-remote-error').textContent = 'Bitte einen gültigen Namen ohne / eingeben.'; return; }
    const target = joinRemotePath(currentPath, name);
    const button = $('#new-remote-save'); button.disabled = true; button.textContent = 'Lege an…';
    try {
      const type = fixedType || $('#new-remote-type')?.value || 'file';
      await api(`/files/${serverId}`, { method: 'POST', body: JSON.stringify({ action: type === 'folder' ? 'mkdir' : 'create', path: target }) });
      close(); await refreshFileAfterMutation(serverId, currentPath, onChanged); showToast(`${name} angelegt.`);
    } catch (e) { $('#new-remote-error').textContent = e.message; button.disabled = false; button.textContent = 'Anlegen'; }
  };
}

function promptRemoteAction(title, label, initial, action, serverId, currentPath, onChanged = null) {
  const modal = $('#modal');
  modal.innerHTML = `<div class="backdrop"><div class="dialog fileactiondialog"><div class="dialogtitle"><div><h3>${esc(title)}</h3></div><button data-close class="iconbutton">×</button></div><label>${esc(label)}<input id="remote-action-value" value="${esc(initial)}" autocomplete="off"></label><div id="remote-action-error" class="err"></div><div class="actions"><button data-cancel>Abbrechen</button><button id="remote-action-save" class="primary">Speichern</button></div></div></div>`;
  const close = () => { modal.innerHTML = ''; };
  $('[data-close]', modal).onclick = close; $('[data-cancel]', modal).onclick = close;
  $('#remote-action-save').onclick = async () => {
    const button = $('#remote-action-save'); button.disabled = true;
    try { await action($('#remote-action-value').value.trim()); close(); await refreshFileAfterMutation(serverId, currentPath, onChanged); showToast('Gespeichert.'); }
    catch (e) { $('#remote-action-error').textContent = e.message; button.disabled = false; }
  };
}

function chownRemoteModal(serverId, remotePath, currentPath, onChanged = null, ownership = {}) {
  const modal = $('#modal');
  const currentUid = Number.isInteger(ownership.uid) && ownership.uid >= 0 ? ownership.uid : '';
  const currentGid = Number.isInteger(ownership.gid) && ownership.gid >= 0 ? ownership.gid : '';
  modal.innerHTML = `<div class="backdrop"><div class="dialog fileactiondialog"><div class="dialogtitle"><div><h3>Eigentümer ändern</h3><p><code>${esc(remotePath)}</code></p></div><button data-close class="iconbutton">×</button></div><div class="formgrid"><label>UID<input id="chown-uid" type="number" min="0" step="1" value="${esc(currentUid)}" autocomplete="off"></label><label>GID<input id="chown-gid" type="number" min="0" step="1" value="${esc(currentGid)}" autocomplete="off"></label></div><p class="muted">ZentSSH verwendet numerische UID/GID, damit keine falsche lokale Namensauflösung auf dem ZentSSH-Host stattfindet.</p><div id="chown-error" class="err"></div><div class="actions"><button data-cancel>Abbrechen</button><button id="chown-save" class="primary">Übernehmen</button></div></div></div>`;
  const close = () => { modal.innerHTML = ''; };
  $('[data-close]', modal).onclick = close; $('[data-cancel]', modal).onclick = close;
  $('#chown-save').onclick = async () => {
    const uid = Number($('#chown-uid').value), gid = Number($('#chown-gid').value);
    if (!Number.isInteger(uid) || !Number.isInteger(gid) || uid < 0 || gid < 0) { $('#chown-error').textContent = 'UID und GID müssen nicht-negative ganze Zahlen sein.'; return; }
    try { await api(`/files/${serverId}`, { method: 'POST', body: JSON.stringify({ action: 'chown', path: remotePath, uid, gid }) }); close(); await refreshFileAfterMutation(serverId, currentPath, onChanged); showToast('Eigentümer geändert.'); }
    catch (e) { $('#chown-error').textContent = e.message; }
  };
}


let cronRowSequence = 0;

function parseCronJobLine(line, enabled = true) {
  const macro = String(line).match(/^\s*(@(?:reboot|yearly|annually|monthly|weekly|daily|midnight|hourly))\s+(.+)$/i);
  if (macro) return { id: ++cronRowSequence, kind: 'job', enabled, schedule: macro[1].toLowerCase(), command: macro[2] };
  const normal = String(line).match(/^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$/);
  if (!normal) return null;
  return { id: ++cronRowSequence, kind: 'job', enabled, schedule: normal.slice(1, 6).join(' '), command: normal[6] };
}

function parseCrontabContent(content) {
  cronRowSequence = 0;
  const rows = [];
  const lines = String(content || '').replace(/\r\n/g, '\n').split('\n');
  if (lines.length && lines.at(-1) === '') lines.pop();
  for (const line of lines) {
    if (line.startsWith('# ZENTSSH-DISABLED ')) {
      const job = parseCronJobLine(line.slice('# ZENTSSH-DISABLED '.length), false);
      rows.push(job || { id: ++cronRowSequence, kind: 'raw', raw: line });
      continue;
    }
    if (/^\s*#/.test(line)) {
      rows.push({ id: ++cronRowSequence, kind: 'comment', raw: line });
      continue;
    }
    const env = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (env) {
      rows.push({ id: ++cronRowSequence, kind: 'env', key: env[1], value: env[2] });
      continue;
    }
    if (!line.trim()) {
      rows.push({ id: ++cronRowSequence, kind: 'blank', raw: '' });
      continue;
    }
    const job = parseCronJobLine(line, true);
    rows.push(job || { id: ++cronRowSequence, kind: 'raw', raw: line });
  }
  return rows;
}

function cronJobUi(job) {
  if (job.ui) return job.ui;
  const schedule = String(job.schedule || '').trim();
  if (schedule === '@reboot') return (job.ui = { preset: 'reboot' });
  if (['@hourly', '@daily', '@weekly', '@monthly'].includes(schedule)) return (job.ui = { preset: schedule.slice(1) });
  let m = schedule.match(/^\*\/(\d+) \* \* \* \*$/);
  if (m) return (job.ui = { preset: 'everyN', interval: Number(m[1]) || 5 });
  m = schedule.match(/^(\d+) \* \* \* \*$/);
  if (m) return (job.ui = { preset: 'hourlyAt', minute: Number(m[1]) || 0 });
  m = schedule.match(/^(\d+) (\d+) \* \* \*$/);
  if (m) return (job.ui = { preset: 'dailyAt', minute: Number(m[1]), hour: Number(m[2]) });
  m = schedule.match(/^(\d+) (\d+) \* \* ([0-7])$/);
  if (m) return (job.ui = { preset: 'weeklyAt', minute: Number(m[1]), hour: Number(m[2]), weekday: Number(m[3]) === 7 ? 0 : Number(m[3]) });
  m = schedule.match(/^(\d+) (\d+) (\d+) \* \*$/);
  if (m) return (job.ui = { preset: 'monthlyAt', minute: Number(m[1]), hour: Number(m[2]), monthday: Number(m[3]) });
  return (job.ui = { preset: 'custom', custom: schedule || '0 3 * * *' });
}

function cronPad(value) { return String(Math.max(0, Number(value) || 0)).padStart(2, '0'); }

function cronScheduleFromUi(job) {
  const ui = cronJobUi(job);
  switch (ui.preset) {
    case 'reboot': return '@reboot';
    case 'hourly': return '@hourly';
    case 'daily': return '@daily';
    case 'weekly': return '@weekly';
    case 'monthly': return '@monthly';
    case 'everyN': return `*/${Math.max(1, Math.min(59, Number(ui.interval) || 5))} * * * *`;
    case 'hourlyAt': return `${Math.max(0, Math.min(59, Number(ui.minute) || 0))} * * * *`;
    case 'dailyAt': return `${Math.max(0, Math.min(59, Number(ui.minute) || 0))} ${Math.max(0, Math.min(23, Number(ui.hour) || 0))} * * *`;
    case 'weeklyAt': return `${Math.max(0, Math.min(59, Number(ui.minute) || 0))} ${Math.max(0, Math.min(23, Number(ui.hour) || 0))} * * ${Math.max(0, Math.min(7, Number(ui.weekday) || 0))}`;
    case 'monthlyAt': return `${Math.max(0, Math.min(59, Number(ui.minute) || 0))} ${Math.max(0, Math.min(23, Number(ui.hour) || 0))} ${Math.max(1, Math.min(31, Number(ui.monthday) || 1))} * *`;
    default: return String(ui.custom || job.schedule || '').trim();
  }
}

function cronHumanLabel(job) {
  const ui = cronJobUi(job);
  const time = () => `${cronPad(ui.hour)}:${cronPad(ui.minute)}`;
  const days = ['Sonntag', 'Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag', 'Sonntag'];
  return ({
    reboot: 'Beim Server-/Systemstart', hourly: 'Stündlich', daily: 'Täglich', weekly: 'Wöchentlich', monthly: 'Monatlich',
    everyN: `Alle ${Math.max(1, Number(ui.interval) || 5)} Minuten`, hourlyAt: `Stündlich bei Minute ${Math.max(0, Number(ui.minute) || 0)}`,
    dailyAt: `Täglich um ${time()} Uhr`, weeklyAt: `${days[Math.max(0, Math.min(7, Number(ui.weekday) || 0))]} um ${time()} Uhr`,
    monthlyAt: `Jeden Monat am ${Math.max(1, Number(ui.monthday) || 1)}. um ${time()} Uhr`, custom: 'Benutzerdefinierter Cron-Ausdruck',
  })[ui.preset] || 'Cronjob';
}

function cronPresetOptions(selected) {
  const options = [
    ['everyN', 'Alle X Minuten'], ['hourlyAt', 'Stündlich'], ['dailyAt', 'Täglich'], ['weeklyAt', 'Wöchentlich'], ['monthlyAt', 'Monatlich'],
    ['reboot', 'Beim Neustart'], ['hourly', '@hourly'], ['daily', '@daily'], ['weekly', '@weekly'], ['monthly', '@monthly'], ['custom', 'Benutzerdefiniert'],
  ];
  return options.map(([value, label]) => `<option value="${value}" ${selected === value ? 'selected' : ''}>${label}</option>`).join('');
}

function cronDetailFields(job) {
  const ui = cronJobUi(job);
  const timeFields = () => `<label>Uhrzeit<input data-cron-ui="hour" type="number" min="0" max="23" value="${Number(ui.hour) || 0}"></label><label>Minute<input data-cron-ui="minute" type="number" min="0" max="59" value="${Number(ui.minute) || 0}"></label>`;
  if (ui.preset === 'everyN') return `<label>Intervall<input data-cron-ui="interval" type="number" min="1" max="59" value="${Number(ui.interval) || 5}"><small>Minuten</small></label>`;
  if (ui.preset === 'hourlyAt') return `<label>Minute<input data-cron-ui="minute" type="number" min="0" max="59" value="${Number(ui.minute) || 0}"></label>`;
  if (ui.preset === 'dailyAt') return timeFields();
  if (ui.preset === 'weeklyAt') return `<label>Wochentag<select data-cron-ui="weekday">${['Sonntag','Montag','Dienstag','Mittwoch','Donnerstag','Freitag','Samstag'].map((d, i) => `<option value="${i}" ${Number(ui.weekday) === i ? 'selected' : ''}>${d}</option>`).join('')}</select></label>${timeFields()}`;
  if (ui.preset === 'monthlyAt') return `<label>Tag<input data-cron-ui="monthday" type="number" min="1" max="31" value="${Number(ui.monthday) || 1}"></label>${timeFields()}`;
  if (ui.preset === 'custom') return `<label class="cron-custom-field">Cron-Ausdruck<input data-cron-ui="custom" value="${esc(ui.custom || job.schedule || '')}" autocomplete="off" spellcheck="false"><small>Minute · Stunde · Tag · Monat · Wochentag</small></label>`;
  return '<span class="cron-no-details">Keine weiteren Angaben nötig.</span>';
}

function serializeCrontabRows(rows) {
  const lines = [];
  for (const row of rows) {
    if (row.kind === 'blank') { lines.push(''); continue; }
    if (row.kind === 'comment' || row.kind === 'raw') { lines.push(row.raw || ''); continue; }
    if (row.kind === 'env') {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(row.key || '')) throw new Error(`Ungültiger Variablenname: ${row.key || '(leer)'}`);
      lines.push(`${row.key}=${row.value ?? ''}`);
      continue;
    }
    if (row.kind === 'job') {
      const schedule = cronScheduleFromUi(row);
      const command = String(row.command || '').trim();
      if (!command) throw new Error('Ein Cronjob hat keinen Befehl.');
      if (!schedule.startsWith('@') && schedule.split(/\s+/).length !== 5) throw new Error(`Ungültiger Cron-Ausdruck: ${schedule}`);
      row.schedule = schedule;
      lines.push(`${row.enabled ? '' : '# ZENTSSH-DISABLED '}${schedule} ${command}`);
    }
  }
  return lines.join('\n') + (lines.length ? '\n' : '');
}

async function openCrontabEditor(serverId, serverName = 'Server') {
  const modal = $('#modal');
  modal.innerHTML = `<div class="backdrop"><div class="dialog crontab-dialog"><div class="dialogtitle"><div><h3>Crontab · ${esc(serverName)}</h3><p>Lade aktuelle Benutzer-Crontab…</p></div><button data-close class="iconbutton">×</button></div><div class="editorloading">Lade Cronjobs…</div></div></div>`;
  $('[data-close]', modal).onclick = () => { modal.innerHTML = ''; };
  let data;
  try { data = await api(`/servers/${serverId}/crontab`); }
  catch (e) {
    modal.innerHTML = `<div class="backdrop"><div class="dialog fileactiondialog"><h3>Crontab konnte nicht geladen werden</h3><div class="err">${esc(e.message)}</div><div class="actions"><button id="cron-error-close">Schließen</button></div></div></div>`;
    $('#cron-error-close').onclick = () => { modal.innerHTML = ''; };
    return;
  }
  const rows = parseCrontabContent(data.content || '');
  const render = () => {
    const jobs = rows.filter(row => row.kind === 'job').length;
    modal.innerHTML = `<div class="backdrop"><div class="dialog crontab-dialog">
      <div class="dialogtitle"><div><h3>Crontab · ${esc(serverName)}</h3><p>${jobs} Cronjob${jobs === 1 ? '' : 's'} · visuelle Bearbeitung der Benutzer-Crontab</p></div><button data-close class="iconbutton" aria-label="Schließen">×</button></div>
      <div class="cron-toolbar"><button id="cron-add-job" class="primary button-with-icon">${iconLabel('clock', 'Cronjob')}</button><button id="cron-add-env" class="button-with-icon">${iconLabel('settings', 'Variable')}</button><span class="muted">Komplexe oder unbekannte Zeilen bleiben als „Erweitert“ erhalten.</span></div>
      <div id="cron-rows" class="cron-rows">${rows.map(row => {
        if (row.kind === 'blank') return `<div class="cron-preserved-blank" data-cron-id="${row.id}"></div>`;
        if (row.kind === 'comment') return `<div class="cron-row cron-meta-row" data-cron-id="${row.id}"><span class="cron-kind">Kommentar</span><input data-cron-comment value="${esc(row.raw)}" autocomplete="off"><button data-cron-delete class="cron-icon-button" aria-label="Kommentar löschen">${actionIcon('delete')}</button></div>`;
        if (row.kind === 'raw') return `<div class="cron-row cron-meta-row cron-raw-row" data-cron-id="${row.id}"><span class="cron-kind">Erweitert</span><input data-cron-raw value="${esc(row.raw)}" autocomplete="off" spellcheck="false"><button data-cron-delete class="cron-icon-button" aria-label="Zeile löschen">${actionIcon('delete')}</button></div>`;
        if (row.kind === 'env') return `<div class="cron-row cron-env-row" data-cron-id="${row.id}"><span class="cron-kind">Variable</span><input data-cron-env-key value="${esc(row.key)}" placeholder="MAILTO" autocomplete="off"><input data-cron-env-value value="${esc(row.value)}" placeholder="Wert" autocomplete="off"><button data-cron-delete class="cron-icon-button" aria-label="Variable löschen">${actionIcon('delete')}</button></div>`;
        const ui = cronJobUi(row);
        return `<div class="cron-row cron-job-row ${row.enabled ? '' : 'disabled'}" data-cron-id="${row.id}">
          <label class="cron-enable"><input data-cron-enabled type="checkbox" ${row.enabled ? 'checked' : ''}><span>${row.enabled ? 'Aktiv' : 'Aus'}</span></label>
          <div class="cron-job-main"><div class="cron-job-top"><select data-cron-preset>${cronPresetOptions(ui.preset)}</select><span data-cron-summary class="cron-summary">${esc(cronHumanLabel(row))}</span></div><div class="cron-details">${cronDetailFields(row)}</div><label class="cron-command">Befehl<input data-cron-command value="${esc(row.command)}" autocomplete="off" spellcheck="false" placeholder="/opt/scripts/backup.sh"></label></div>
          <div class="cron-job-actions"><button data-cron-duplicate class="cron-icon-button has-tooltip" data-tooltip="Duplizieren" aria-label="Duplizieren">${actionIcon('files')}</button><button data-cron-delete class="cron-icon-button danger has-tooltip" data-tooltip="Löschen" aria-label="Löschen">${actionIcon('delete')}</button></div>
        </div>`;
      }).join('')}</div>
      <div id="cron-error" class="err"></div><div class="actions"><button data-cancel>Abbrechen</button><button id="cron-save" class="primary">Crontab speichern</button></div>
    </div></div>`;

    const close = () => { modal.innerHTML = ''; };
    $('[data-close]', modal).onclick = close;
    $('[data-cancel]', modal).onclick = close;
    $('#cron-add-job').onclick = () => { const row = { id: ++cronRowSequence, kind: 'job', enabled: true, schedule: '0 3 * * *', command: '' }; rows.push(row); render(); setTimeout(() => $(`[data-cron-id="${row.id}"] [data-cron-command]`, modal)?.focus(), 0); };
    $('#cron-add-env').onclick = () => { const row = { id: ++cronRowSequence, kind: 'env', key: '', value: '' }; rows.push(row); render(); setTimeout(() => $(`[data-cron-id="${row.id}"] [data-cron-env-key]`, modal)?.focus(), 0); };

    $$('.cron-row', modal).forEach(element => {
      const id = Number(element.dataset.cronId);
      const row = rows.find(item => item.id === id);
      if (!row) return;
      const remove = () => { const index = rows.findIndex(item => item.id === id); if (index >= 0) rows.splice(index, 1); render(); };
      $('[data-cron-delete]', element).onclick = remove;
      if (row.kind === 'comment') $('[data-cron-comment]', element).oninput = e => { row.raw = e.target.value; };
      if (row.kind === 'raw') $('[data-cron-raw]', element).oninput = e => { row.raw = e.target.value; };
      if (row.kind === 'env') {
        $('[data-cron-env-key]', element).oninput = e => { row.key = e.target.value; };
        $('[data-cron-env-value]', element).oninput = e => { row.value = e.target.value; };
      }
      if (row.kind === 'job') {
        $('[data-cron-enabled]', element).onchange = e => { row.enabled = e.target.checked; element.classList.toggle('disabled', !row.enabled); $('.cron-enable span', element).textContent = row.enabled ? 'Aktiv' : 'Aus'; };
        $('[data-cron-command]', element).oninput = e => { row.command = e.target.value; };
        $('[data-cron-preset]', element).onchange = e => { row.ui = { preset: e.target.value, ...(e.target.value === 'custom' ? { custom: row.schedule } : {}) }; render(); };
        $$('[data-cron-ui]', element).forEach(input => input.oninput = input.onchange = e => {
          const key = e.target.dataset.cronUi;
          row.ui[key] = ['hour','minute','weekday','monthday','interval'].includes(key) ? Number(e.target.value) : e.target.value;
          row.schedule = cronScheduleFromUi(row);
          const summary = $('[data-cron-summary]', element); if (summary) summary.textContent = cronHumanLabel(row);
        });
        $('[data-cron-duplicate]', element).onclick = () => {
          const index = rows.findIndex(item => item.id === id);
          const copy = JSON.parse(JSON.stringify(row)); copy.id = ++cronRowSequence; copy.command = row.command; rows.splice(index + 1, 0, copy); render();
        };
      }
    });

    $('#cron-save').onclick = async () => {
      const button = $('#cron-save');
      $('#cron-error').textContent = '';
      let content;
      try { content = serializeCrontabRows(rows); }
      catch (e) { $('#cron-error').textContent = e.message; return; }
      setButtonBusy(button, true, 'Prüfe & speichere…');
      try {
        await api(`/servers/${serverId}/crontab`, { method: 'PUT', body: JSON.stringify({ content }) });
        modal.innerHTML = '';
        showToast('Crontab gespeichert.');
      } catch (e) {
        $('#cron-error').textContent = e.message;
        setButtonBusy(button, false);
      }
    };
  };
  render();
}

function imageViewerModal(serverId, remotePath) {
  const modal = $('#modal');
  const imageURL = `${A}/files/${serverId}?path=${encodeURIComponent(remotePath)}&inline=1`;
  modal.innerHTML = `<div class="backdrop"><div class="dialog imageviewerdialog">
    <div class="dialogtitle"><div><h3>${esc(remoteNameFromPath(remotePath))}</h3><p><code>${esc(remotePath)}</code></p></div><button data-close class="iconbutton" aria-label="Schließen">×</button></div>
    <div class="imageviewer-stage"><div class="editorloading" data-image-loading>Bild wird geladen…</div><img data-image-viewer alt="${esc(remoteNameFromPath(remotePath))}" hidden></div>
    <div id="imageviewer-error" class="err"></div>
    <div class="actions"><button id="imageviewer-download" class="button-with-icon">${iconLabel('download', 'Herunterladen')}</button><button data-cancel class="primary">Schließen</button></div>
  </div></div>`;
  const close = () => { modal.innerHTML = ''; };
  $('[data-close]', modal).onclick = close;
  $('[data-cancel]', modal).onclick = close;
  $('#imageviewer-download').onclick = () => { location.href = `${A}/files/${serverId}?path=${encodeURIComponent(remotePath)}&download=1`; };
  const image = $('[data-image-viewer]', modal);
  const loading = $('[data-image-loading]', modal);
  image.onload = () => { if (loading) loading.remove(); image.hidden = false; };
  image.onerror = () => { if (loading) loading.remove(); $('#imageviewer-error').textContent = 'Bild konnte nicht geladen werden.'; };
  image.src = imageURL;
}

async function fileEditorModal(serverId, remotePath, currentPath, options = {}) {
  const modal = $('#modal');
  modal.innerHTML = `<div class="backdrop"><div class="dialog fileeditordialog"><div class="dialogtitle"><div><h3>${esc(remoteNameFromPath(remotePath))}</h3><p><code>${esc(remotePath)}</code>${options.source ? ` · via ${esc(options.source)}` : ''}</p></div><button data-close class="iconbutton">×</button></div><div class="editorloading">Lade Datei…</div></div></div>`;
  let data;
  let createdNew = false;
  try {
    data = await api(`/files/${serverId}?path=${encodeURIComponent(remotePath)}&text=1`);
  } catch (e) {
    const missing = e.status === 404 || /no such file|not exist/i.test(e.message || '');
    if (options.createIfMissing && missing) {
      data = { path: remotePath, content: '', size: 0, mode: 'neu' };
      createdNew = true;
    } else {
      modal.innerHTML = `<div class="backdrop"><div class="dialog fileactiondialog"><h3>Datei konnte nicht geöffnet werden</h3><div class="err">${esc(e.message)}</div><div class="actions"><button id="editor-error-close">Schließen</button></div></div></div>`;
      $('#editor-error-close').onclick = () => { modal.innerHTML = ''; };
      return;
    }
  }

  modal.innerHTML = `<div class="backdrop"><div class="dialog fileeditordialog"><div class="dialogtitle"><div><h3>${esc(remoteNameFromPath(remotePath))}</h3><p><code>${esc(remotePath)}</code> · ${createdNew ? 'Neue Datei' : `${fmtSize(data.size || 0)} · ${esc(data.mode || '')}`}${options.source ? ` · ${esc(options.source)} → Webeditor` : ''}</p></div><button data-close class="iconbutton">×</button></div>
    <div class="editorbar"><input id="editor-find" placeholder="Suchen…" autocomplete="off"><button id="editor-find-next" class="icononly has-tooltip" aria-label="Nächster Treffer" data-tooltip="Nächster Treffer">${actionIcon('search')}</button><span id="editor-status" class="muted">${createdNew ? 'Neue Datei' : 'Unverändert'}</span></div>
    <div class="simpleeditor"><pre id="editor-lines" aria-hidden="true"></pre><textarea id="editor-content" spellcheck="false" autocomplete="off"></textarea></div>
    <div id="editor-error" class="err"></div><div class="actions"><button data-cancel>Abbrechen</button><button id="editor-save" class="primary">Speichern</button></div></div></div>`;
  const textarea = $('#editor-content');
  const lines = $('#editor-lines');
  let dirty = createdNew;
  let findFrom = 0;
  textarea.value = data.content || '';
  const syncLines = () => { lines.textContent = Array.from({ length: Math.max(1, textarea.value.split('\n').length) }, (_, i) => i + 1).join('\n'); };
  syncLines();
  textarea.onscroll = () => { lines.scrollTop = textarea.scrollTop; };
  textarea.oninput = () => { dirty = true; $('#editor-status').textContent = 'Ungespeichert'; syncLines(); };
  textarea.onkeydown = e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); $('#editor-save').click(); return; }
    if (e.key === 'Tab') { e.preventDefault(); const start = textarea.selectionStart, end = textarea.selectionEnd; textarea.setRangeText('  ', start, end, 'end'); dirty = true; syncLines(); $('#editor-status').textContent = 'Ungespeichert'; }
  };
  $('#editor-find-next').onclick = () => {
    const q = $('#editor-find').value;
    if (!q) return;
    const text = textarea.value;
    let i = text.indexOf(q, findFrom);
    if (i < 0 && findFrom > 0) i = text.indexOf(q, 0);
    if (i < 0) { $('#editor-status').textContent = 'Kein Treffer'; return; }
    textarea.focus(); textarea.setSelectionRange(i, i + q.length); findFrom = i + q.length; $('#editor-status').textContent = `Treffer bei Zeichen ${i + 1}`;
  };
  const close = () => { if (dirty && !confirm('Ungespeicherte Änderungen verwerfen?')) return; modal.innerHTML = ''; };
  $('[data-close]', modal).onclick = close;
  $('[data-cancel]', modal).onclick = close;
  $('#editor-save').onclick = async () => {
    const button = $('#editor-save');
    setButtonBusy(button, true, 'Speichere…');
    $('#editor-error').textContent = '';
    try {
      const response = await fetch(`${A}/files/${serverId}?path=${encodeURIComponent(remotePath)}`, { method: 'PUT', body: textarea.value, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'X-CSRF-Token': cookieValue('zentssh_csrf') } });
      if (!response.ok) {
        const text = await response.text();
        try { throw new Error(JSON.parse(text).error || text); } catch (parseError) { if (parseError instanceof SyntaxError) throw new Error(text || `HTTP ${response.status}`); throw parseError; }
      }
      dirty = false;
      createdNew = false;
      $('#editor-status').textContent = 'Gespeichert';
      setButtonBusy(button, false);
      const fileTab = state.tabs.find(t => t.type === 'files' && Number(t.serverId) === Number(serverId));
      if (fileTab?.filePanel && normalizeRemotePath(fileTab.filePath || '.') === normalizeRemotePath(currentPath || '.')) refreshFileDirectory(fileTab, fileTab.filePath || '.');
      showToast('Datei gespeichert.');
    } catch (e) {
      $('#editor-error').textContent = e.message;
      setButtonBusy(button, false);
    }
  };
}

async function openDualFiles(leftServerId, rightServerId = null, leftPath = '.', rightPath = null) {
  const workspace = $('#workspace');
  const canTransfer = true;
  rightServerId = Number(rightServerId || leftServerId);
  rightPath = rightPath == null ? leftPath : rightPath;
  const serverOptions = selected => {
    const options = [...state.servers];
    for (const id of [leftServerId, rightServerId, selected]) {
      const known = knownServer(id);
      if (known && !options.some(server => Number(server.id) === Number(known.id))) options.unshift(known);
    }
    return options.map(s => `<option value="${s.id}" ${Number(s.id) === Number(selected) ? 'selected' : ''}>${esc(s.name)} · ${esc(s.host)}</option>`).join('');
  };
  const paneMarkup = (side, serverId, panePath) => `<section class="filepane" data-side="${side}"><div class="panehead"><select class="pane-server">${serverOptions(serverId)}</select><div><input class="pane-path" value="${esc(panePath)}"><button class="pane-open button-with-icon">${iconLabel('open', 'Öffnen')}</button></div><input class="pane-upload" type="file" hidden></div><div class="pane-body">Lade…</div></section>`;
  workspace.innerHTML = `<div class="dual-files" data-dual-files>
    <div class="dual-toolbar"><b class="dual-title"><span class="dual-title-icon">${actionIcon('dual')}</span><span>Dual File Manager</span></b><button id="dual-close" class="button-with-icon">${iconLabel('files', 'Einzelansicht')}</button></div>
    <div class="dual-grid">
      ${paneMarkup('left', leftServerId, leftPath)}
      <div class="dual-divider" aria-hidden="true">⇄</div>
      ${paneMarkup('right', rightServerId, rightPath)}
    </div>
  </div>`;
  $('#dual-close').onclick = () => openFiles(Number($('.filepane[data-side="left"] .pane-server').value), $('.filepane[data-side="left"] .pane-path').value || '.');
  for (const pane of $$('.filepane', workspace)) {
    $('.pane-server', pane).onchange = () => loadDualPane(pane, Number($('.pane-server', pane).value), '.');
    $('.pane-open', pane).onclick = () => loadDualPane(pane, Number($('.pane-server', pane).value), $('.pane-path', pane).value || '.');
    $('.pane-path', pane).addEventListener('keydown', e => { if (e.key === 'Enter') $('.pane-open', pane).click(); });
    $('.pane-upload', pane).onchange = async event => {
      const file = event.target.files?.[0];
      if (!file) return;
      const targetServerId = Number($('.pane-server', pane).value);
      const currentPath = $('.pane-path', pane).value || '.';
      try {
        await uploadRemoteFile(targetServerId, joinRemotePath(currentPath, file.name), file);
        event.target.value = '';
        await loadDualPane(pane, targetServerId, currentPath);
        showToast(`${file.name} hochgeladen.`);
      } catch (e) { showToast(e.message, true); }
    };
    const paneBody = $('.pane-body', pane);
    paneBody.oncontextmenu = event => {
      if (event.target.closest('.pane-row,button,input,select,textarea,label,a')) return;
      event.preventDefault();
      event.stopPropagation();
      showDualBackgroundContextMenu(event, pane, canTransfer);
    };
    if (canTransfer) {
      pane.ondragover = e => { e.preventDefault(); pane.classList.add('drop-target'); };
      pane.ondragleave = e => { if (!pane.contains(e.relatedTarget)) pane.classList.remove('drop-target'); };
      pane.ondrop = async e => {
        e.preventDefault(); pane.classList.remove('drop-target');
        const payload = readTransferDrag(e);
        if (!payload) return;
        const targetServerId = Number($('.pane-server', pane).value);
        const targetViewPath = $('.pane-path', pane).value || '.';
        const base = String(payload.path).split('/').filter(Boolean).at(-1) || 'transfer';
        const targetPath = joinRemotePath(targetViewPath, base);
        await startDragTransfer(payload.serverId, payload.path, targetServerId, targetPath, {
          onCompleted: () => refreshDualRecipientPane(pane, targetServerId),
        });
      };
    }
  }
  await Promise.all([
    loadDualPane($('.filepane[data-side="left"]'), Number(leftServerId), leftPath),
    loadDualPane($('.filepane[data-side="right"]'), rightServerId, rightPath),
  ]);
}

async function refreshDualRecipientPane(pane, expectedServerId) {
  if (!pane?.isConnected) return;
  const currentServerId = Number($('.pane-server', pane)?.value);
  if (currentServerId !== Number(expectedServerId)) return;
  await loadDualPane(pane, currentServerId, $('.pane-path', pane)?.value || '.');
}

async function loadDualPane(pane, serverId, path = '.') {
  if (!pane) return;
  const body = $('.pane-body', pane);
  $('.pane-server', pane).value = String(serverId);
  $('.pane-path', pane).value = path;
  pane.classList.add('pane-refreshing');
  body.setAttribute('aria-busy', 'true');
  if (!body.dataset.loaded) body.innerHTML = '<p class="muted pane-loading">Lade…</p>';
  let data;
  try {
    await ensureServerReady(serverId);
    data = await api(`/files/${serverId}?path=${encodeURIComponent(path)}`);
  } catch (e) {
    pane.classList.remove('pane-refreshing');
    body.removeAttribute('aria-busy');
    body.innerHTML = `<div class="err">${esc(e.message)}</div>`;
    return;
  }
  const currentPath = data.path || path;
  $('.pane-path', pane).value = currentPath;
  body.dataset.loaded = '1';
  const rows = [{ name: '..', path: parent(currentPath), dir: true, parent: true, uid: null, gid: null }, ...sortRemoteEntries(data.entries || [])];
  const parentColor = configuredServerColor(serverId);
  body.innerHTML = rows.map(entry => `<div class="pane-row ${entry.parent ? 'parent-pane-row' : ''}" data-path="${esc(entry.path)}" data-name="${esc(entry.name)}" data-dir="${entry.dir ? 1 : 0}" data-parent="${entry.parent ? 1 : 0}" data-uid="${entry.uid == null ? '' : esc(entry.uid)}" data-gid="${entry.gid == null ? '' : esc(entry.gid)}" draggable="${!entry.parent ? 'true' : 'false'}"><span class="pane-type-icon"${entry.parent ? ` style="color:${esc(parentColor)}"` : ''}>${entry.parent ? '↰' : actionIcon(entry.dir ? 'folder' : (isImageFile(entry.name) ? 'image' : 'file'))}</span><b>${esc(entry.name)}</b><small>${entry.dir ? '' : fmtSize(entry.size)}</small></div>`).join('');
  $$('.pane-row', body).forEach(row => {
    const isDir = row.dataset.dir === '1';
    const isParent = row.dataset.parent === '1';
    if (isDir) row.onclick = () => loadDualPane(pane, serverId, row.dataset.path);
    else row.ondblclick = () => isImageFile(row.dataset.path) ? imageViewerModal(serverId, row.dataset.path) : fileEditorModal(serverId, row.dataset.path, currentPath);
    if (!isParent) {
      row.oncontextmenu = event => {
        event.preventDefault();
        event.stopPropagation();
        showFileContextMenu(event, row, serverId, row.dataset.path, row.dataset.name, isDir, currentPath, true, {
          openDir: remotePath => loadDualPane(pane, serverId, remotePath),
          onChanged: () => refreshDualRecipientPane(pane, serverId),
          uid: numericDatasetValue(row.dataset.uid),
          gid: numericDatasetValue(row.dataset.gid),
        });
      };
    }
    if (row.draggable) row.ondragstart = e => {
      e.dataTransfer.effectAllowed = 'copy';
      e.dataTransfer.setData('application/x-zentssh-transfer', JSON.stringify({ serverId, path: row.dataset.path }));
      e.dataTransfer.setData('text/plain', row.dataset.path);
    };
    if (isDir) {
      row.ondragover = e => { e.preventDefault(); e.stopPropagation(); row.classList.add('drop-row'); };
      row.ondragleave = () => row.classList.remove('drop-row');
      row.ondrop = async e => {
        e.preventDefault(); e.stopPropagation(); row.classList.remove('drop-row');
        const payload = readTransferDrag(e);
        if (!payload) return;
        const base = String(payload.path).split('/').filter(Boolean).at(-1) || 'transfer';
        await startDragTransfer(payload.serverId, payload.path, serverId, joinRemotePath(row.dataset.path, base), {
          onCompleted: () => refreshDualRecipientPane(pane, serverId),
        });
      };
    }
  });
  pane.classList.remove('pane-refreshing');
  body.removeAttribute('aria-busy');
}

function showDualBackgroundContextMenu(event, pane, canWrite) {
  const menu = $('#file-context-menu');
  if (!menu || !pane) return;
  closeServerContextMenu();
  closeFileContextMenu();
  const serverId = Number($('.pane-server', pane).value);
  const currentPath = $('.pane-path', pane).value || '.';
  const hiddenShown = Boolean(state.userSettings?.showHiddenFiles);
  const items = [];
  if (canWrite) {
    items.push({ action: 'new-file', label: 'Neue Datei', icon: actionIcon('newFile') });
    items.push({ action: 'new-folder', label: 'Neuer Ordner', icon: actionIcon('newFolder') });
    items.push({ action: 'upload', label: 'Datei hochladen', icon: actionIcon('upload') });
    items.push({ action: 'url-upload', label: 'Upload via URL', icon: actionIcon('urlUpload') });
    items.push({ separator: true });
  }
  items.push({ action: 'hidden', label: hiddenShown ? 'Versteckte ausblenden' : 'Versteckte anzeigen', icon: actionIcon(hiddenShown ? 'eye' : 'eyeOff') });
  items.push({ action: 'refresh', label: 'Neu laden', icon: actionIcon('refresh') });
  menu.innerHTML = `<div class="server-context-title file-context-title file-background-title"><span class="file-context-title-icon">${actionIcon('folder')}</span><div><strong>${esc(currentPath)}</strong><small>${esc(knownServer(serverId)?.name || 'Dateibrowser')}</small></div></div>${items.map(item => item.separator ? '<div class="context-separator"></div>' : `<button data-action="${item.action}"><span>${item.icon}</span><b>${esc(item.label)}</b></button>`).join('')}`;
  menu.hidden = false;
  menu.oncontextmenu = e => e.preventDefault();
  positionContextMenu(menu, event, pane);
  $$('button[data-action]', menu).forEach(button => {
    button.onclick = async () => {
      const action = button.dataset.action;
      closeFileContextMenu();
      const refresh = () => refreshDualRecipientPane(pane, serverId);
      if (action === 'new-file') return newRemoteItemModal(serverId, currentPath, 'file', refresh);
      if (action === 'new-folder') return newRemoteItemModal(serverId, currentPath, 'folder', refresh);
      if (action === 'upload') return $('.pane-upload', pane)?.click();
      if (action === 'url-upload') return urlUploadModal(serverId, currentPath, refresh);
      if (action === 'refresh') return loadDualPane(pane, serverId, currentPath);
      if (action === 'hidden') return toggleHiddenFiles(async () => {
        await Promise.all($$('.filepane', $('[data-dual-files]')).map(other => loadDualPane(other, Number($('.pane-server', other).value), $('.pane-path', other).value || '.')));
      });
    };
  });
}

function readTransferDrag(event) {
  try { return JSON.parse(event.dataTransfer.getData('application/x-zentssh-transfer') || ''); }
  catch { return null; }
}

function joinRemotePath(dir, name) {
  dir = String(dir || '.');
  if (dir === '.' || dir === '') return name;
  if (dir === '/') return `/${name}`;
  return `${dir.replace(/\/$/, '')}/${name}`;
}

async function refreshVisibleDualTarget(targetServerId, targetPath) {
  const root = $('[data-dual-files]');
  if (!root) return;
  const targetDirectory = parent(targetPath || '.');
  const jobs = $$('.filepane', root).filter(pane => {
    const paneServerId = Number($('.pane-server', pane)?.value);
    const panePath = $('.pane-path', pane)?.value || '.';
    return paneServerId === Number(targetServerId) && normalizeRemotePath(panePath) === normalizeRemotePath(targetDirectory);
  }).map(pane => refreshDualRecipientPane(pane, targetServerId));
  if (jobs.length) await Promise.all(jobs);
}

const trackedTransfers = new Map();
const TERMINAL_TRANSFER_VISIBLE_MS = 30000;
let transferSnapshot = [];
let transferMonitorTimer = null;
let transferMonitorBusy = false;
let transferMonitorBootstrapped = false;

function isActiveTransferStatus(status) { return ['queued', 'running'].includes(String(status || '')); }
function isTerminalTransferStatus(status) { return ['completed', 'failed', 'cancelled', 'interrupted'].includes(String(status || '')); }

function bootstrapTransferMonitor() {
  transferMonitorBootstrapped = false;
  scheduleTransferMonitor(120);
}

function trackTransfer(transfer, onCompleted = null) {
  if (!transfer?.id) return;
  const id = String(transfer.id);
  const entry = trackedTransfers.get(id) || { record: transfer, callbacks: new Set(), callbackFired: false };
  entry.record = transfer;
  if (onCompleted) entry.callbacks.add(onCompleted);
  trackedTransfers.set(id, entry);
  renderTransferDock();
  scheduleTransferMonitor(150);
}

function scheduleTransferMonitor(delay = 1000) {
  clearTimeout(transferMonitorTimer);
  transferMonitorTimer = setTimeout(() => syncTransferMonitor(), delay);
}

async function syncTransferMonitor() {
  if (transferMonitorBusy) return;
  transferMonitorBusy = true;
  try {
    transferSnapshot = await api('/transfers');
    const byId = new Map(transferSnapshot.map(item => [String(item.id), item]));
    // Active transfers survive browser reloads. Pick them up automatically once the workspace is ready.
    for (const transfer of transferSnapshot) {
      if (!isActiveTransferStatus(transfer.status)) continue;
      const id = String(transfer.id);
      if (!trackedTransfers.has(id)) trackedTransfers.set(id, { record: transfer, callbacks: new Set(), callbackFired: false });
    }
    transferMonitorBootstrapped = true;
    const now = Date.now();
    for (const [id, entry] of [...trackedTransfers]) {
      const current = byId.get(id);
      if (current) entry.record = current;
      const status = entry.record?.status;
      if (isActiveTransferStatus(status)) entry.terminalAt = 0;
      if (isTerminalTransferStatus(status)) {
        if (status === 'completed' && !entry.callbackFired) {
          entry.callbackFired = true;
          for (const callback of entry.callbacks) {
            try { await callback(entry.record); } catch { /* target refresh is best effort */ }
          }
        }
        if (!entry.terminalAt) entry.terminalAt = now;
        if (now - entry.terminalAt >= TERMINAL_TRANSFER_VISIBLE_MS) trackedTransfers.delete(id);
      }
    }
    renderTransferDock();
    renderTransferCenterList();
  } catch (e) {
    if ($('[data-transfer-center]') && $('#transfer-list')) $('#transfer-list').innerHTML = `<div class="err">${esc(e.message)}</div>`;
  } finally {
    transferMonitorBusy = false;
  }
  if (trackedTransfers.size || $('[data-transfer-center]')) scheduleTransferMonitor(1000);
}

function renderTransferDock() {
  let dock = $('#transfer-dock');
  const entries = [...trackedTransfers.values()]
    .filter(entry => isActiveTransferStatus(entry.record?.status) || isTerminalTransferStatus(entry.record?.status))
    .sort((a, b) => new Date(b.record?.createdAt || 0) - new Date(a.record?.createdAt || 0));
  if (!entries.length) {
    dock?.remove();
    return;
  }
  if (!dock) {
    dock = document.createElement('section');
    dock.id = 'transfer-dock';
    dock.className = 'transfer-dock';
    document.body.appendChild(dock);
  }
  dock.innerHTML = `<div class="transfer-dock-head"><div><span class="transfer-dock-icon">⇄</span><b>${L('Transfers','Transfers')}</b></div><span>${entries.length}</span></div><div class="transfer-dock-list">${entries.map(entry => transferDockRow(entry.record)).join('')}</div>`;
  $$('.transfer-dock-cancel', dock).forEach(button => button.onclick = async () => {
    button.disabled = true;
    try { await api(`/transfers/${encodeURIComponent(button.dataset.id)}`, { method: 'DELETE' }); scheduleTransferMonitor(80); }
    catch (e) { button.disabled = false; showToast(e.message, true); }
  });
}

function transferDockRow(t) {
  const pct = t?.bytesTotal > 0 ? Math.min(100, Math.round((t.bytesDone / t.bytesTotal) * 100)) : (t?.status === 'completed' ? 100 : 0);
  const active = isActiveTransferStatus(t?.status);
  const speed = t?.speedBps > 0 ? `${fmtSize(t.speedBps)}/s` : '';
  const eta = t?.etaSeconds > 0 ? `${L('noch','ETA')} ${fmtETA(t.etaSeconds)}` : '';
  const fileName = remoteNameFromPath(t?.targetPath || t?.sourcePath || '') || L('Transfer','Transfer');
  const statusClass = t?.status === 'completed' ? 'success' : (['failed', 'interrupted'].includes(t?.status) ? 'error' : '');
  return `<article class="transfer-dock-row ${statusClass}" data-id="${esc(t?.id || '')}">
    <div class="transfer-dock-title"><div><b>${esc(fileName)}</b><small>${esc(t?.sourceServer || '')} → ${esc(t?.targetServer || '')}</small></div><span>${esc(transferStatusLabel(t?.status))}</span></div>
    ${active ? `<div class="progress compact"><i style="width:${pct}%"></i></div>
    <div class="transfer-dock-meta"><span>${fmtSize(t?.bytesDone || 0)}${t?.bytesTotal ? ` / ${fmtSize(t.bytesTotal)}` : ''} · ${pct}%</span><span>${[speed, eta].filter(Boolean).join(' · ')}</span></div>` : `<div class="transfer-dock-meta transfer-dock-finished"><span>${fmtSize(t?.bytesTotal || t?.bytesDone || 0)}</span></div>`}
    ${t?.error ? `<small class="transfer-dock-error">${esc(t.error)}</small>` : ''}
    ${active ? `<button class="transfer-dock-cancel" data-id="${esc(t.id)}">${L('Abbrechen','Cancel')}</button>` : ''}
  </article>`;
}

async function startDragTransfer(sourceServerId, sourcePath, targetServerId, targetPath, options = {}) {
  try {
    await ensureServerReady(sourceServerId);
    if (targetServerId !== sourceServerId) await ensureServerReady(targetServerId);
    const transfer = await api('/transfers', { method: 'POST', body: JSON.stringify({ sourceServerId, sourcePath, targetServerId, targetPath }) });
    trackTransfer(transfer, options.onCompleted);
    return transfer;
  } catch (e) {
    if (e.message !== 'cancelled') showToast(e.message, true);
    return null;
  }
}

function transferModal(sourceServerId, sourcePath) {
  const modal = $('#modal');
  const source = knownServer(sourceServerId);
  const targets = [...state.servers];
  if (source && !targets.some(server => Number(server.id) === Number(source.id))) targets.unshift(source);
  const basename = String(sourcePath || '').split('/').filter(Boolean).at(-1) || 'transfer';
  modal.innerHTML = `<div class="backdrop"><div class="dialog transferdialog">
    <div class="dialogtitle"><div><h3>${L('Server-zu-Server übertragen','Server-to-server transfer')}</h3><p>${esc(source?.name || '')}:<code>${esc(sourcePath)}</code></p></div><button data-close class="iconbutton">×</button></div>
    <label>${L('Zielserver','Target server')}<select id="transfer-target">${targets.map(s => `<option value="${s.id}">${esc(s.name)} · ${esc(s.host)}</option>`).join('')}</select></label>
    <label>${L('Zielpfad','Target path')}<input id="transfer-path" placeholder="/backups/${esc(basename)}" autocomplete="off"></label>
    <div class="securitynote">${L('Die Daten laufen direkt als Stream','Data is streamed directly')} <b>${L('Quelle → ZentSSH Backend → Ziel','source → ZentSSH backend → target')}</b>. ${L('Die komplette Datei wird weder im Browser noch im RAM zwischengespeichert.','The complete file is never buffered in the browser or in memory.')}</div>
    <div id="transfer-error" class="err"></div>
    <div class="actions"><button data-cancel>${L('Abbrechen','Cancel')}</button><button id="transfer-start" class="primary">${L('Transfer starten','Start transfer')}</button></div>
  </div></div>`;
  $('[data-close]', modal).onclick = () => { modal.innerHTML = ''; };
  $('[data-cancel]', modal).onclick = () => { modal.innerHTML = ''; };
  $('#transfer-start').onclick = async () => {
    const targetServerId = Number($('#transfer-target').value);
    const targetPath = $('#transfer-path').value.trim();
    if (!targetPath) { $('#transfer-error').textContent = L('Zielpfad ist erforderlich.','Target path is required.'); return; }
    const button = $('#transfer-start'); button.disabled = true; button.textContent = L('Prüfe Verbindungen…','Checking connections…');
    try {
      await ensureServerReady(sourceServerId);
      if (targetServerId !== sourceServerId) await ensureServerReady(targetServerId);
      button.textContent = L('Starte Transfer…','Starting transfer…');
      const transfer = await api('/transfers', { method: 'POST', body: JSON.stringify({ sourceServerId, sourcePath, targetServerId, targetPath }) });
      trackTransfer(transfer, () => refreshVisibleDualTarget(targetServerId, targetPath));
      modal.innerHTML = '';
      scheduleTransferMonitor(80);
    } catch (e) {
      if (e.message !== 'cancelled') $('#transfer-error').textContent = e.message;
      button.disabled = false; button.textContent = L('Transfer starten','Start transfer');
    }
  };
}

async function openTransferCenter() {
  const modal = $('#modal');
  modal.innerHTML = `<div class="backdrop"><div class="dialog transfercenter" data-transfer-center><div class="dialogtitle"><div><h3>${L('Transfers','Transfers')}</h3></div><button data-close class="iconbutton">×</button></div><div id="transfer-list" class="transfer-list compact-history"><p class="muted">${L('Lade…','Loading…')}</p></div></div></div>`;
  $('[data-close]', modal).onclick = () => { modal.innerHTML = ''; scheduleTransferMonitor(0); };
  await syncTransferMonitor();
}

function renderTransferCenterList() {
  const root = $('[data-transfer-center]');
  const list = $('#transfer-list');
  if (!root || !list) return;
  const transfers = [...trackedTransfers.values()].map(entry => entry.record).filter(t => isActiveTransferStatus(t?.status) || isTerminalTransferStatus(t?.status)).sort((a, b) => new Date(b?.createdAt || 0) - new Date(a?.createdAt || 0)).slice(0, 60);
  list.innerHTML = transfers.length ? transfers.map(t => {
    const pct = t.bytesTotal > 0 ? Math.min(100, Math.round((t.bytesDone / t.bytesTotal) * 100)) : (t.status === 'completed' ? 100 : 0);
    const active = isActiveTransferStatus(t.status);
    const statusClass = t.status === 'completed' ? 'success' : (['failed', 'interrupted'].includes(t.status) ? 'error' : '');
    const name = remoteNameFromPath(t.targetPath || t.sourcePath || '') || L('Transfer','Transfer');
    return `<div class="transfer-history-row ${statusClass}" data-id="${esc(t.id)}">
      <span class="transfer-history-state">${t.status === 'completed' ? '✓' : (active ? '⇄' : '!')}</span>
      <div class="transfer-history-main"><b>${esc(name)}</b><small>${esc(t.sourceServer)} → ${esc(t.targetServer)}</small><small>${esc(t.sourcePath)} → ${esc(t.targetPath)}</small>${active ? `<div class="progress compact"><i style="width:${pct}%"></i></div>` : ''}</div>
      <div class="transfer-history-meta"><span class="badge ${t.status === 'completed' ? 'success' : ''}">${esc(transferStatusLabel(t.status))}</span><small>${fmtSize(t.bytesDone)}${t.bytesTotal ? ` / ${fmtSize(t.bytesTotal)}` : ''}</small><small>${fmtDateTime(t.finishedAt || t.startedAt || t.createdAt)}</small>${active ? `<button class="cancel-transfer danger" data-id="${esc(t.id)}">${L('Abbrechen','Cancel')}</button>` : ''}</div>
    </div>`;
  }).join('') : `<p class="muted">${L('Keine laufenden Transfers.','No active transfers.')}</p>`;
  $$('.cancel-transfer', list).forEach(button => button.onclick = async () => {
    button.disabled = true;
    try { await api(`/transfers/${encodeURIComponent(button.dataset.id)}`, { method: 'DELETE' }); scheduleTransferMonitor(60); }
    catch (e) { button.disabled = false; showToast(e.message, true); }
  });
}

async function refreshTransferCenter() { await syncTransferMonitor(); }

function transferStatusLabel(status) {
  const de = ({ queued: 'Wartet', running: 'Läuft', completed: 'Fertig', failed: 'Fehlgeschlagen', cancelled: 'Abgebrochen', interrupted: 'Unterbrochen' })[status] || status;
  const en = ({ queued: 'Queued', running: 'Running', completed: 'Done', failed: 'Failed', cancelled: 'Cancelled', interrupted: 'Interrupted' })[status] || status;
  return L(de, en);
}

function fmtETA(seconds) {
  seconds = Math.max(0, Math.round(Number(seconds) || 0));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function openProfile() { openSettings('profile'); }

function settingsNavIcon(type) {
  return `<span class="settings-nav-icon">${actionIcon(type)}</span>`;
}

function snippetManagementToolbarHTML(scope, folders) {
  const isShared = scope === 'shared';
  const isAdmin = state.me?.role === 'admin';
  const canCreateAny = !isShared || folders.some(folder => isAdmin || folder.canCreate);
  return `<div class="snippet-page-toolbar">
    ${(!isShared || isAdmin) ? `<button class="snippet-toolbar-button" id="add-${scope}-folder" type="button">${iconLabel('newFolder', L('Ordner','Folder'))}</button>` : ''}
    ${canCreateAny ? `<button class="snippet-toolbar-button primary" id="add-${scope}-snippet" type="button">${iconLabel('plus', L('Schnipsel','Snippet'))}</button>` : ''}
  </div>`;
}

function snippetManagementHTML(scope, folders, snippets) {
  const isShared = scope === 'shared';
  const isAdmin = state.me?.role === 'admin';
  const groups = [];
  if (!isShared) groups.push({ id: 0, name: L('Ohne Ordner','No folder'), synthetic: true, canCreate: true, canEdit: true, canDelete: true });
  groups.push(...folders);
  const body = groups.length ? groups.map(folder => {
    const items = snippetsForFolder(snippets, folder.id);
    const folderCanCreate = !isShared || isAdmin || Boolean(folder.canCreate);
    const folderCanManage = !folder.synthetic && (!isShared || isAdmin);
    const drop = !isShared ? ' snippet-private-drop-target' : '';
    return `<div class="snippet-manage-folder${drop}" data-folder-id="${folder.id}">
      <div class="snippet-manage-folder-head">
        <div class="snippet-manage-folder-title"><span>${actionIcon('folder')}</span><b>${esc(folder.name)}</b><span class="badge">${items.length}</span></div>
        <div class="snippet-manage-actions">
          ${folderCanCreate ? `<button class="iconbutton snippet-add-to-folder has-tooltip" data-scope="${scope}" data-folder-id="${folder.id}" type="button" data-tooltip="${esc(L('Schnipsel anlegen','Create snippet'))}" aria-label="${esc(L('Schnipsel anlegen','Create snippet'))}">${actionIcon('plus')}</button>` : ''}
          ${folderCanManage && isShared ? `<button class="iconbutton snippet-folder-users has-tooltip" data-folder-id="${folder.id}" type="button" data-tooltip="${esc(L('Benutzer verwalten','Manage users'))}" aria-label="${esc(L('Benutzer verwalten','Manage users'))}">${actionIcon('users')}</button>` : ''}
          ${folderCanManage ? `<button class="iconbutton snippet-edit-folder has-tooltip" data-scope="${scope}" data-folder-id="${folder.id}" type="button" data-tooltip="${esc(L('Ordner bearbeiten','Edit folder'))}" aria-label="${esc(L('Ordner bearbeiten','Edit folder'))}">${actionIcon('edit')}</button>` : ''}
        </div>
      </div>
      <div class="snippet-manage-list">${items.length ? items.map(item => {
        const canEdit = !isShared || isAdmin || Boolean(item.canEdit);
        const canDelete = !isShared || isAdmin || Boolean(item.canDelete);
        return `<div class="snippet-manage-row${!isShared ? ' snippet-private-draggable' : ''}" data-id="${item.id}" ${!isShared ? 'draggable="true"' : ''}>
          <span class="snippet-manage-code">${actionIcon('code')}</span>
          <div class="snippet-manage-meta"><b>${esc(item.name)}</b><small>${esc(item.content ? snippetSummary(item.content) : L('Inhalt nicht freigegeben','Content not available'))}</small></div>
          <div class="snippet-manage-row-actions">${canEdit ? `<button class="snippet-edit-item" data-id="${item.id}" data-scope="${scope}" type="button">${iconLabel('edit', L('Bearbeiten','Edit'))}</button>` : ''}${canDelete ? `<button class="snippet-delete-item danger" data-id="${item.id}" data-scope="${scope}" type="button">${iconLabel('delete', L('Löschen','Delete'))}</button>` : ''}</div>
        </div>`;
      }).join('') : `<div class="snippet-manage-empty">${esc(L('Keine Schnipsel in diesem Ordner.','No snippets in this folder.'))}</div>`}</div>
    </div>`;
  }).join('') : `<div class="snippet-empty"><span>${actionIcon('folder')}</span><p>${esc(isShared ? L('Noch keine geteilten Ordner vorhanden.','No shared folders yet.') : L('Noch keine Schnipsel-Ordner vorhanden.','No snippet folders yet.'))}</p></div>`;
  return `<div class="snippet-manage-tree">${body}</div>`;
}

function accessUsersModal({ title, users, permissions = false, returnTo, onSave }) {
  const modal = $('#modal');
  const entries = (users || []).map(item => ({
    ...item,
    assigned: Boolean(item.assigned),
    canUse: Boolean(item.canUse),
    canCreate: Boolean(item.canCreate),
    canEdit: Boolean(item.canEdit),
    canDelete: Boolean(item.canDelete),
    _initial: {
      assigned: Boolean(item.assigned),
      canUse: Boolean(item.canUse),
      canCreate: Boolean(item.canCreate),
      canEdit: Boolean(item.canEdit),
      canDelete: Boolean(item.canDelete),
    },
  })).sort((a, b) => Number(b.assigned) - Number(a.assigned) || String(a.name || '').localeCompare(String(b.name || ''), uiLanguage()));
  modal.innerHTML = `<div class="backdrop"><div class="dialog access-users-dialog modal-scroll">
    <div class="dialogtitle"><div><h3>${esc(title)}</h3></div><button data-close class="iconbutton" aria-label="${esc(L('Schließen','Close'))}">×</button></div>
    <div class="access-user-search"><span>${actionIcon('search')}</span><input id="access-user-search" type="search" placeholder="${esc(L('Benutzer suchen','Search users'))}" autocomplete="off" autofocus></div>
    <div id="access-user-list" class="access-user-list"></div>
    <div id="access-user-error" class="err"></div>
    <div class="actions"><button data-cancel>${L('Abbrechen','Cancel')}</button><button id="access-user-save" class="primary">${L('Speichern','Save')}</button></div>
  </div></div>`;

  const renderRows = () => {
    const query = String($('#access-user-search', modal)?.value || '').trim().toLocaleLowerCase();
    const visible = entries.filter(item => !query || `${item.name || ''} ${item.email || ''}`.toLocaleLowerCase().includes(query));
    const list = $('#access-user-list', modal);
    list.innerHTML = visible.length ? visible.map(item => `<div class="access-user-row${item.assigned ? ' assigned' : ''}${permissions ? '' : ' simple'}" data-user-id="${item.userId}">
      <div class="access-user-identity"><b>${esc(item.name)}</b><small>${esc(item.email)}</small></div>
      ${permissions ? `<div class="access-user-rights"><label><input type="checkbox" data-right="canUse" ${item.canUse ? 'checked' : ''} ${item.assigned ? '' : 'disabled'}><span>${L('Verwenden','Use')}</span></label><label><input type="checkbox" data-right="canCreate" ${item.canCreate ? 'checked' : ''} ${item.assigned ? '' : 'disabled'}><span>${L('Erstellen','Create')}</span></label><label><input type="checkbox" data-right="canEdit" ${item.canEdit ? 'checked' : ''} ${item.assigned ? '' : 'disabled'}><span>${L('Bearbeiten','Edit')}</span></label><label><input type="checkbox" data-right="canDelete" ${item.canDelete ? 'checked' : ''} ${item.assigned ? '' : 'disabled'}><span>${L('Löschen','Delete')}</span></label></div>` : ''}
      <label class="access-user-assignment"><input class="access-user-assigned" type="checkbox" ${item.assigned ? 'checked' : ''} aria-label="${esc(L('Zugriff','Access'))}"></label>
    </div>`).join('') : `<div class="access-user-empty">${esc(L('Keine Benutzer gefunden.','No users found.'))}</div>`;
    $$('.access-user-row', list).forEach(row => {
      const item = entries.find(candidate => Number(candidate.userId) === Number(row.dataset.userId));
      if (!item) return;
      $('.access-user-assigned', row).onchange = event => {
        item.assigned = event.target.checked;
        if (permissions && item.assigned && !item.canUse && !item.canCreate && !item.canEdit && !item.canDelete) item.canUse = true;
        if (!item.assigned && permissions) item.canUse = item.canCreate = item.canEdit = item.canDelete = false;
        renderRows();
      };
      if (permissions) $$('[data-right]', row).forEach(input => input.onchange = () => { item[input.dataset.right] = input.checked; });
    });
  };

  $('#access-user-search', modal).oninput = renderRows;
  renderRows();
  $('[data-close]', modal).onclick = () => openSettings(returnTo);
  $('[data-cancel]', modal).onclick = () => openSettings(returnTo);
  $('#access-user-save', modal).onclick = async () => {
    const button = $('#access-user-save', modal), error = $('#access-user-error', modal);
    error.textContent = '';
    setButtonBusy(button, true, L('Speichere…','Saving…'));
    try { await onSave(entries); }
    catch (e) { error.textContent = e.message; setButtonBusy(button, false); }
  };
}

async function workspaceUsersModal(workspace) {
  try {
    const detail = await api(`/admin/workspaces/${workspace.id}`);
    accessUsersModal({
      title: `${L('Benutzer','Users')} · ${detail.name}`,
      users: detail.members || [],
      permissions: true,
      returnTo: 'workspaces',
      onSave: async entries => {
        const changed = entries.filter(item => ['assigned','canUse','canCreate','canEdit','canDelete'].some(key => Boolean(item[key]) !== Boolean(item._initial[key])));
        for (const item of changed) {
          await api('/admin/workspace-memberships', { method: 'PATCH', body: JSON.stringify({ workspaceId: Number(workspace.id), userId: Number(item.userId), assigned: Boolean(item.assigned), canUse: Boolean(item.assigned && item.canUse), canCreate: Boolean(item.assigned && item.canCreate), canEdit: Boolean(item.assigned && item.canEdit), canDelete: Boolean(item.assigned && item.canDelete) }) });
        }
        await loadWorkspace(); state.notice = L('Benutzerrechte gespeichert.','User permissions saved.'); openSettings('workspaces');
      },
    });
  } catch (e) { showToast(e.message, true); }
}

async function snippetFolderUsersModal(folder) {
  try {
    const detail = await api(`/admin/snippet-folder-permissions?folderId=${encodeURIComponent(folder.id)}`);
    accessUsersModal({
      title: `${L('Benutzer','Users')} · ${detail.name || folder.name}`,
      users: detail.users || [],
      permissions: true,
      returnTo: 'shared-snippets',
      onSave: async entries => {
        const changed = entries.filter(item => ['assigned','canUse','canCreate','canEdit','canDelete'].some(key => Boolean(item[key]) !== Boolean(item._initial[key])));
        for (const item of changed) {
          await api('/admin/snippet-folder-permissions', { method: 'PATCH', body: JSON.stringify({ userId: Number(item.userId), folderId: Number(folder.id), assigned: Boolean(item.assigned), canUse: Boolean(item.assigned && item.canUse), canCreate: Boolean(item.assigned && item.canCreate), canEdit: Boolean(item.assigned && item.canEdit), canDelete: Boolean(item.assigned && item.canDelete) }) });
        }
        state.notice = L('Benutzerrechte gespeichert.','User permissions saved.'); openSettings('shared-snippets');
      },
    });
  } catch (e) { showToast(e.message, true); }
}

async function serverTemplateUsersModal(template) {
  try {
    const detail = await api(`/admin/server-template-user-access?templateId=${encodeURIComponent(template.id)}`);
    accessUsersModal({
      title: `${L('Benutzer','Users')} · ${detail.name || template.name}`,
      users: detail.users || [],
      permissions: false,
      returnTo: 'server-templates',
      onSave: async entries => {
        const changed = entries.filter(item => Boolean(item.assigned) !== Boolean(item._initial.assigned));
        for (const item of changed) {
          await api('/admin/server-template-user-access', { method: 'PATCH', body: JSON.stringify({ templateId: Number(template.id), userId: Number(item.userId), assigned: Boolean(item.assigned) }) });
        }
        await loadWorkspace(); state.notice = L('Benutzerfreigaben gespeichert.','User access saved.'); openSettings('server-templates');
      },
    });
  } catch (e) { showToast(e.message, true); }
}

async function workspaceAdminModal(workspace = {}) {
  const modal = $('#modal');
  let detail = null;
  try {
    if (workspace.id) detail = await api(`/admin/workspaces/${workspace.id}`);
  } catch (e) { showToast(e.message, true); return; }
  const editing = Boolean(workspace.id);
  modal.innerHTML = `<div class="backdrop"><div class="dialog workspace-admin-dialog modal-scroll">
    <div class="dialogtitle"><div><h3>${editing ? L('Arbeitsbereich bearbeiten','Edit workspace') : L('Arbeitsbereich erstellen','Create workspace')}</h3></div><button data-close class="iconbutton">×</button></div>
    <div class="formgrid"><label class="wide">${L('Name','Name')}<input id="workspace-name" value="${esc(detail?.name || workspace.name || '')}" autocomplete="off" autofocus></label><label class="wide">${L('Beschreibung','Description')}<textarea id="workspace-description" autocomplete="off">${esc(detail?.description || workspace.description || '')}</textarea></label></div>
    <label class="toggle-row"><span><b>${L('Arbeitsbereich aktiv','Workspace active')}</b><small>${L('Deaktivieren beendet laufende Verbindungen zu diesem Arbeitsbereich.','Disabling ends running connections to this workspace.')}</small></span><input id="workspace-active" type="checkbox" ${(detail?.active ?? workspace.active ?? true) ? 'checked' : ''}></label>
    <div id="workspace-admin-error" class="err"></div>
    <div class="actions spread"><div>${editing ? `<button id="workspace-delete" class="danger">${L('Löschen','Delete')}</button>` : ''}</div><div><button data-cancel>${L('Abbrechen','Cancel')}</button><button id="workspace-save" class="primary">${L('Speichern','Save')}</button></div></div>
  </div></div>`;
  $('[data-close]', modal).onclick = () => openSettings('workspaces');
  $('[data-cancel]', modal).onclick = () => openSettings('workspaces');
  $('#workspace-save').onclick = async () => {
    const button = $('#workspace-save'); const error = $('#workspace-admin-error'); error.textContent = '';
    const body = { name: $('#workspace-name').value.trim(), description: $('#workspace-description').value.trim(), active: $('#workspace-active').checked };
    if (!body.name) { error.textContent = L('Name ist erforderlich.','Name is required.'); return; }
    setButtonBusy(button, true, L('Speichere…','Saving…'));
    try {
      await api(editing ? `/admin/workspaces/${workspace.id}` : '/admin/workspaces', { method: editing ? 'PATCH' : 'POST', body: JSON.stringify(body) });
      await loadWorkspace();
      state.notice = L('Arbeitsbereich gespeichert.','Workspace saved.');
      openSettings('workspaces');
    } catch (e) { error.textContent = e.message; setButtonBusy(button, false); }
  };
  if ($('#workspace-delete')) $('#workspace-delete').onclick = async () => {
    const error = $('#workspace-admin-error'); error.textContent = '';
    if (!confirm(`${L('Arbeitsbereich wirklich löschen?','Delete workspace?')} „${detail?.name || workspace.name}“`)) return;
    try {
      await api(`/admin/workspaces/${workspace.id}`, { method: 'DELETE' });
    } catch (e) {
      if (e.status !== 409 || e.data?.error !== 'workspace is not empty') { error.textContent = e.message; return; }
      const servers = Number(e.data?.serverCount || 0), folders = Number(e.data?.folderCount || 0);
      if (!confirm(L(`Dieser Arbeitsbereich enthält ${servers} Server und ${folders} Ordner. Beim Löschen werden diese gemeinsamen Daten endgültig entfernt. Trotzdem löschen?`,`This workspace contains ${servers} servers and ${folders} folders. Deleting it permanently removes this shared data. Delete anyway?`))) return;
      await api(`/admin/workspaces/${workspace.id}?force=1`, { method: 'DELETE' });
    }
    if (Number(state.activeWorkspaceId) === Number(workspace.id)) state.activeWorkspaceId = 0;
    await loadWorkspace(); state.notice = L('Arbeitsbereich gelöscht.','Workspace deleted.'); openSettings('workspaces');
  };
}

async function serverTemplateAdminModal(template = {}) {
  const modal = $('#modal');
  let detail = template.id ? null : template;
  let workspaces = [], templates = [];
  try {
    [workspaces, templates] = await Promise.all([api('/admin/workspaces'), api('/admin/server-templates')]);
    if (template.id) detail = await api(`/admin/server-templates/${template.id}`);
  } catch (e) { showToast(e.message, true); return; }
  detail = detail || {};
  const editing = Boolean(template.id);
  const allowedWorkspaces = new Set((detail.workspaceIds || []).map(Number));
  const jumpOptions = templates.filter(item => Number(item.id) !== Number(template.id) && !item.jumpTemplateId).map(item => `<option value="${item.id}">${esc(item.name)} · ${esc(item.host)}</option>`).join('');
  modal.innerHTML = `<div class="backdrop"><div class="dialog server-template-admin-dialog modal-scroll">
    <div class="dialogtitle"><div><h3>${editing ? L('Server-Vorlage bearbeiten','Edit server template') : L('Server-Vorlage erstellen','Create server template')}</h3></div><button data-close class="iconbutton">×</button></div>
    <div class="formgrid"><label class="wide">${L('Name','Name')}<input id="template-name" value="${esc(detail.name || '')}" autocomplete="off" autofocus></label><label>Host / IP<input id="template-host" value="${esc(detail.host || '')}" autocomplete="off"></label><label>Port<input id="template-port" type="number" min="1" max="65535" value="${Number(detail.port || 22)}"></label><label>Jump Host ${L('Vorlage','template')}<select id="template-jump"><option value="">${L('Direkt verbinden','Connect directly')}</option>${jumpOptions}</select></label><label>${L('Farbe','Color')}<input id="template-color" type="color" value="${esc(normalizeHexColor(detail.color, '#5aa9ff'))}"></label><label>${L('Terminal-Dateieditor','Terminal file editor')}<select id="template-terminal-editor"><option value="ask">${L('Beim ersten Mal fragen','Ask the first time')}</option><option value="web">ZentSSH Webeditor</option><option value="terminal">${L('Im Terminal öffnen','Open in terminal')}</option></select></label><label>${L('Crontab-Editor','Crontab editor')}<select id="template-crontab-editor"><option value="ask">${L('Beim ersten Mal fragen','Ask the first time')}</option><option value="visual">Visueller ZentSSH Editor</option><option value="terminal">${L('Im Terminal öffnen','Open in terminal')}</option></select></label><label class="wide">${L('Beschreibung','Description')}<textarea id="template-description" autocomplete="off">${esc(detail.description || '')}</textarea></label></div>
    <label class="toggle-row"><span><b>${L('Vorlage aktiv','Template active')}</b><small>${L('Deaktivieren blockiert die Nutzung aller daraus abgeleiteten Server.','Disabling blocks use of all derived servers.')}</small></span><input id="template-active" type="checkbox" ${(detail.active ?? true) ? 'checked' : ''}></label>
    <label class="toggle-row"><span><b>${L('Für alle Benutzer verfügbar','Available to all users')}</b><small>${L('Ausgeschaltet: Zugriff gezielt über Benutzer oder Arbeitsbereiche freigeben.','Off: grant access through selected users or workspaces.')}</small></span><input id="template-visible-all" type="checkbox" ${(detail.visibleToAll ?? true) ? 'checked' : ''}></label>
    <div id="template-access" class="template-access-grid single">
      <div><b>${L('Arbeitsbereiche','Workspaces')}</b><div class="template-access-list">${workspaces.map(workspace => `<label><input class="template-workspace-access" type="checkbox" value="${workspace.id}" ${allowedWorkspaces.has(Number(workspace.id)) ? 'checked' : ''}><span>${esc(workspace.name)}<small>${workspace.active ? L('Aktiv','Active') : L('Deaktiviert','Disabled')}</small></span></label>`).join('') || `<span class="muted">${L('Keine Arbeitsbereiche.','No workspaces.')}</span>`}</div></div>
    </div>
    <div id="server-template-admin-error" class="err"></div>
    <div class="actions spread"><div>${editing ? `<button id="server-template-delete" class="danger">${L('Löschen','Delete')}</button>` : ''}</div><div><button data-cancel>${L('Abbrechen','Cancel')}</button><button id="server-template-save" class="primary">${L('Speichern','Save')}</button></div></div>
  </div></div>`;
  $('#template-jump').value = detail.jumpTemplateId || '';
  $('#template-terminal-editor').value = detail.terminalEditorMode || 'ask';
  $('#template-crontab-editor').value = detail.crontabEditorMode || 'ask';
  const syncAccess = () => { $('#template-access').classList.toggle('disabledsection', $('#template-visible-all').checked); $$('#template-access input').forEach(input => input.disabled = $('#template-visible-all').checked); };
  $('#template-visible-all').onchange = syncAccess; syncAccess();
  $('[data-close]', modal).onclick = () => openSettings('server-templates');
  $('[data-cancel]', modal).onclick = () => openSettings('server-templates');
  $('#server-template-save').onclick = async () => {
    const button = $('#server-template-save'), error = $('#server-template-admin-error'); error.textContent = '';
    const body = { name: $('#template-name').value.trim(), host: $('#template-host').value.trim(), port: Number($('#template-port').value || 22), color: $('#template-color').value, kind: 'ssh', terminalEditorMode: $('#template-terminal-editor').value, crontabEditorMode: $('#template-crontab-editor').value, jumpTemplateId: $('#template-jump').value ? Number($('#template-jump').value) : null, description: $('#template-description').value.trim(), active: $('#template-active').checked, visibleToAll: $('#template-visible-all').checked, workspaceIds: $$('.template-workspace-access:checked').map(input => Number(input.value)) };
    if (!body.name || !body.host) { error.textContent = L('Name und Host sind erforderlich.','Name and host are required.'); return; }
    setButtonBusy(button, true, L('Speichere…','Saving…'));
    try { await api(editing ? `/admin/server-templates/${template.id}` : '/admin/server-templates', { method: editing ? 'PATCH' : 'POST', body: JSON.stringify(body) }); await loadWorkspace(); state.notice = L('Server-Vorlage gespeichert.','Server template saved.'); openSettings('server-templates'); }
    catch (e) { error.textContent = e.message; setButtonBusy(button, false); }
  };
  if ($('#server-template-delete')) $('#server-template-delete').onclick = async () => {
    const error = $('#server-template-admin-error'); error.textContent = '';
    if (!confirm(`${L('Server-Vorlage wirklich löschen?','Delete server template?')} „${detail.name}“`)) return;
    try { await api(`/admin/server-templates/${template.id}`, { method: 'DELETE' }); }
    catch (e) {
      if (e.status === 409 && Number(e.data?.usageCount || 0) > 0) {
        const count = Number(e.data.usageCount);
        if (!confirm(L(`Diese Vorlage wird von ${count} Benutzer-Servern verwendet. Diese Server in eigenständige private Server umwandeln und die Vorlage löschen?`,`This template is used by ${count} user servers. Convert them to standalone private servers and delete the template?`))) return;
        try { await api(`/admin/server-templates/${template.id}?convert=1`, { method: 'DELETE' }); }
        catch (convertError) { error.textContent = convertError.message; return; }
      } else { error.textContent = e.message; return; }
    }
    await loadWorkspace(); state.notice = L('Server-Vorlage gelöscht.','Server template deleted.'); openSettings('server-templates');
  };
}

async function openSettings(focus = "") {
  const modal = $('#modal');
  let linked = [];
  let publicProviders = [];
  let mfaStatus = { enabled: false, recoveryCodesRemaining: 0, localPasswordAvailable: true };
  let userSettings = { sshSessionRetention: 'inherit', showHiddenFiles: false, language: state.me?.language || uiLanguage() };
  try {
    [linked, publicProviders, mfaStatus, userSettings] = await Promise.all([api('/me/oidc'), api('/auth/providers'), api('/me/mfa'), api('/me/settings')]);
  } catch { /* sections can remain empty */ }

  let snippetPermissions = state.snippetPermissions || { canUse: false, canCreate: false, canEdit: false, canDelete: false, sharedCount: 0, sharedFolderCount: 0 };
  let privateSnippets = [], sharedSnippets = [], privateSnippetFolders = [], sharedSnippetFolders = [];
  try {
    [snippetPermissions, privateSnippets, privateSnippetFolders] = await Promise.all([api('/snippet-permissions'), api('/code-snippets?scope=private'), api('/snippet-folders?scope=private')]);
    state.snippetPermissions = snippetPermissions;
    if (state.me?.role === 'admin' || Number(snippetPermissions.sharedFolderCount || 0) > 0) {
      [sharedSnippets, sharedSnippetFolders] = await Promise.all([api('/code-snippets?scope=shared'), api('/snippet-folders?scope=shared')]);
    }
  } catch { /* snippet settings can remain empty */ }

  let adminProviders = [], adminUsers = [], adminSessions = [], adminWorkspaces = [], adminServerTemplates = [];
  let backupStatus = { databaseBytes: 0, walBytes: 0, shmBytes: 0, storageBytes: 0, masterKeySource: 'persistent' };
  if (state.me?.role === 'admin') {
    try {
      [adminProviders, adminUsers, adminSessions, adminWorkspaces, adminServerTemplates] = await Promise.all([api('/admin/oidc/providers'), api('/admin/users'), api('/sessions?all=1'), api('/admin/workspaces'), api('/admin/server-templates')]);
    } catch { /* individual sections may remain empty */ }
    try { backupStatus = await api('/admin/backup/status'); } catch { /* backup panel shows zeros when status is temporarily unavailable */ }
  }
  const linkedIds = new Set(linked.map(x => Number(x.providerId)));
  const showShared = state.me?.role === 'admin' || sharedSnippetFolders.length > 0;
  const sharedNavItems = [];
  if (showShared) sharedNavItems.push(['shared-snippets', L('Geteilte Schnipsel','Shared snippets'), 'shared']);
  if (state.me?.role === 'admin') {
    sharedNavItems.push(['workspaces', L('Arbeitsbereiche','Workspaces'), 'shared']);
    sharedNavItems.push(['server-templates', L('Server-Vorlagen','Server templates'), 'server']);
  }
  const navGroups = [
    { label: L('Mein ZentSSH','My ZentSSH'), items: [
      ['profile', L('Mein Profil','My profile'), 'profile'],
      ['security', L('Sicherheit','Security'), 'shield'],
      ['sso', 'SSO', 'link'],
      ['files', L('File Manager','File manager'), 'files'],
      ['snippets', L('Meine Schnipsel','My snippets'), 'code'],
      ['credentials', L('SSH Zugänge','SSH credentials'), 'key'],
      ['sessions', L('SSH Session','SSH session'), 'terminal'],
      ['import', 'OpenSSH Import', 'import'],
    ]},
    ...(sharedNavItems.length ? [{ label: L('Geteilt','Shared'), items: sharedNavItems }] : []),
    ...(state.me?.role === 'admin' ? [{ label: 'Admin', items: [
      ['users', L('Benutzer','Users'), 'users'],
      ['active-sessions', L('Aktive Sessions','Active sessions'), 'activity'],
      ['backup', L('Backup / Restore','Backup / Restore'), 'backup'],
      ['providers', 'OIDC Provider', 'provider'],
    ]}] : []),
  ];
  const firstTarget = navGroups[0].items[0][0];
  const me = state.me || {};
  const hasLocalPassword = Boolean(me.localPasswordAvailable ?? mfaStatus.localPasswordAvailable);
  const ssoManaged = Boolean(me.ssoManaged ?? mfaStatus.ssoManaged);
  const ssoProviderName = String(me.ssoProviderName || mfaStatus.ssoProviderName || linked[0]?.providerName || '').trim();

  modal.innerHTML = `<div class="backdrop"><div class="dialog settingsdialog">
    <div class="dialogtitle settingsheader"><div><h3>${L('Einstellungen','Settings')}</h3><p>${esc(state.me?.email || '')}</p></div><button data-close class="iconbutton" aria-label="${esc(L('Schließen','Close'))}">×</button></div>
    <div class="settingslayout">
      <nav class="settingsnav" aria-label="${esc(L('Einstellungskategorien','Settings categories'))}">
        ${navGroups.map(group => `<div class="settings-nav-group"><div class="settings-nav-group-title">${esc(group.label)}</div>${group.items.map(([id, label, icon], index) => `<button class="${id === firstTarget ? 'active' : ''}" data-settings-target="settings-${id}">${settingsNavIcon(icon)}<span>${esc(label)}</span></button>`).join('')}</div>`).join('')}
      </nav>
      <div class="settingscontent">
        <section class="settingssection" id="settings-profile"><div class="sectiontitle"><div><h4>${L('Mein Profil','My profile')}</h4></div></div>
          <div class="formgrid settings-profile-grid">
            <label>${L('Name','Name')}<input id="settings-profile-name" value="${esc(me.name || '')}" autocomplete="name"></label>
            <label>${L('E-Mail','Email')}<input id="settings-profile-email" type="email" value="${esc(me.email || '')}" autocomplete="email"></label>
            <label>${L('UI-Sprache','UI language')}<select id="settings-profile-language"><option value="de">Deutsch</option><option value="en">English</option></select></label>
            <label>${L('Rolle','Role')}<input value="${esc(userRoleLabel(me.role))}" disabled></label>
          </div>
          ${ssoManaged ? `<div class="profile-password-section settings-profile-password settings-managed-block" aria-disabled="true"><div class="settings-managed-icon">${actionIcon('shield')}</div><div><h4>${L('Lokale Passwort-Anmeldung deaktiviert','Local password sign-in disabled')}</h4><p>${esc(L(`Die Anmeldung wird über ${ssoProviderName || 'SSO'} verwaltet. Die lokale Passwort-Anmeldung ist solange deaktiviert und das Passwort kann hier nicht geändert werden.`,`Sign-in is managed by ${ssoProviderName || 'SSO'}. Local password sign-in is disabled while this SSO connection is active, and the password cannot be changed here.`))}</p></div></div>` : (hasLocalPassword ? `<div class="profile-password-section settings-profile-password"><h4>${L('Passwort ändern','Change password')}</h4><div class="formgrid"><label>${L('Aktuelles Passwort','Current password')}<input id="settings-profile-current-password" type="password" autocomplete="current-password"></label><span></span><label>${L('Neues Passwort','New password')}<input id="settings-profile-new-password" type="password" autocomplete="new-password" placeholder="${esc(L('Leer = unverändert','Leave empty to keep current password'))}"></label><label>${L('Neues Passwort wiederholen','Repeat new password')}<input id="settings-profile-new-password-repeat" type="password" autocomplete="new-password"></label></div></div>` : `<div class="securitynote">${L('Dieses Konto wird über SSO verwaltet und besitzt kein lokales Passwort.','This account is managed through SSO and has no local password.')}</div>`)}
          <div id="settings-profile-error" class="err"></div><div class="settings-inline-actions"><button id="settings-profile-save" class="primary">${iconLabel('profile', L('Profil speichern','Save profile'))}</button></div>
        </section>

        <section class="settingssection" id="settings-security"><div class="sectiontitle"><div><h4>${L('Zwei-Faktor-Authentifizierung','Two-factor authentication')}</h4><p>${L('TOTP schützt die lokale Passwort-Anmeldung.','TOTP protects local password sign-in.')}</p></div>${ssoManaged ? `<span class="badge sso-managed-badge">SSO</span>` : (mfaStatus.enabled ? `<span class="badge success">${L('Aktiv','Active')}</span>` : `<span class="badge">${L('Nicht aktiv','Not active')}</span>`)}</div>
          ${ssoManaged ? `<div class="settings-managed-block settings-security-managed" aria-disabled="true"><div class="settings-managed-icon">${actionIcon('shield')}</div><div><h4>${L('Sicherheit wird durch SSO verwaltet','Security is managed by SSO')}</h4><p>${esc(L(`Nach einer erfolgreichen Anmeldung über ${ssoProviderName || 'SSO'} fragt ZentSSH keinen zusätzlichen eigenen MFA-Code ab.`,`After a successful sign-in through ${ssoProviderName || 'SSO'}, ZentSSH does not ask for an additional ZentSSH MFA code.`))}</p>${mfaStatus.enabled ? `<small>${L('Deine zuvor eingerichtete lokale MFA bleibt gespeichert, ist während SSO aber pausiert und wird erst wieder relevant, wenn keine aktive SSO-Verknüpfung verwendet wird.','Your previously configured local MFA remains stored, but is paused while SSO is active and only becomes relevant again when no active SSO link is used.')}</small>` : `<small>${L('MFA-Regeln für SSO konfigurierst du direkt beim Identity Provider.','Configure SSO MFA rules directly in the identity provider.')}</small>`}</div></div>` : (!mfaStatus.localPasswordAvailable ? `<p class="muted">${L('Dieses Konto besitzt kein lokales Passwort. MFA gilt nur für lokale Passwort-Anmeldungen.','This account has no local password. MFA only applies to local password sign-ins.')}</p>` : (mfaStatus.enabled ? `<div class="provider-row"><div><b>${L('TOTP aktiv','TOTP active')}</b><small>${mfaStatus.recoveryCodesRemaining} ${L('Recovery Codes verbleibend','recovery codes remaining')}</small></div><div class="rowactions"><button id="mfa-recovery" class="settings-row-button">${iconLabel('retry', L('Neue Recovery Codes','New recovery codes'))}</button><button id="mfa-disable" class="settings-row-button danger">${iconLabel('delete', L('MFA deaktivieren','Disable MFA'))}</button></div></div>` : `<button id="mfa-enable" class="settings-action-button primary">${iconLabel('shield', L('MFA einrichten','Set up MFA'))}</button>`))}
        </section>

        <section class="settingssection" id="settings-credentials"><div class="sectiontitle"><div><h4>${L('SSH-Zugangsvorlagen','SSH credential profiles')}</h4><p>${L('Benutzername + Passwort oder Key einmal speichern und auf mehreren Servern verwenden.','Store a username plus password or key once and reuse it across multiple servers.')}</p></div><button id="add-credential" class="settings-action-button primary">${iconLabel('plus', L('Vorlage','Profile'))}</button></div>
          <div class="provider-list">${state.profiles.length ? state.profiles.map(p => `<div class="provider-row"><div><b>${esc(p.name)}</b><small>${esc(p.username)} · ${esc(p.authType)}${p.isOwner ? '' : ` · ${L('geteilt','shared')}`}</small></div><div class="rowactions">${p.isOwner ? `<button class="edit-credential settings-row-button" data-id="${p.id}">${iconLabel('edit', L('Bearbeiten','Edit'))}</button>` : `<span class="badge">${L('Geteilt','Shared')}</span>`}</div></div>`).join('') : `<p class="muted">${L('Noch keine Zugangsvorlage vorhanden.','No credential profile yet.')}</p>`}</div>
        </section>

        <section class="settingssection" id="settings-sessions"><div class="sectiontitle"><div><h4>${L('SSH-Session-Persistenz','SSH session persistence')}</h4><p>${L('Bestimmt, wie lange eine Remote-Shell nach dem Schließen oder Trennen des Browsers weiterläuft.','Controls how long a remote shell keeps running after the browser closes or disconnects.')}</p></div></div>
          <div class="provider-row settings-wrap-row settings-session-row"><div><b>${L('Session nach Browser-Schließen','Session after browser closes')}</b><small>${L('Reloads und kurze Netzunterbrechungen können dieselbe Shell wieder übernehmen.','Reloads and short network interruptions can reattach to the same shell.')}</small></div><select id="session-retention"><option value="inherit">${L('Server-Standard','Server default')}</option><option value="immediate">${L('Sofort beenden','End immediately')}</option><option value="5m">5 ${L('Minuten','minutes')}</option><option value="30m">30 ${L('Minuten','minutes')}</option><option value="2h">2 ${L('Stunden','hours')}</option><option value="8h">8 ${L('Stunden','hours')}</option><option value="unlimited">${L('Unbegrenzt','Unlimited')}</option></select></div>
          <div id="session-retention-status" class="muted"></div>
        </section>

        <section class="settingssection" id="settings-files"><div class="sectiontitle"><div><h4>File Manager</h4><p>${L('Persönliche Darstellung für deine SFTP-Ansichten.','Personal display preferences for your SFTP views.')}</p></div></div>
          <div class="provider-row"><div><b>${L('Versteckte Dateien','Hidden files')}</b><small>${L('Dateien und Ordner anzeigen, deren Name mit einem Punkt beginnt.','Show files and folders whose names start with a dot.')}</small></div><label class="toggle-row compact"><span>${L('Anzeigen','Show')}</span><input id="show-hidden-files" type="checkbox" ${userSettings.showHiddenFiles ? 'checked' : ''}></label></div>
          <div id="file-settings-status" class="muted"></div>
        </section>

        <section class="settingssection" id="settings-snippets"><div class="sectiontitle snippet-section-title"><div><h4>${L('Meine Schnipsel','My snippets')}</h4></div>${snippetManagementToolbarHTML('private', privateSnippetFolders)}</div>${snippetManagementHTML('private', privateSnippetFolders, privateSnippets)}</section>
        ${showShared ? `<section class="settingssection" id="settings-shared-snippets"><div class="sectiontitle snippet-section-title"><div><h4>${L('Geteilte Schnipsel','Shared snippets')}</h4></div>${snippetManagementToolbarHTML('shared', sharedSnippetFolders)}</div>${snippetManagementHTML('shared', sharedSnippetFolders, sharedSnippets)}</section>` : ''}

        <section class="settingssection" id="settings-sso"><div class="sectiontitle"><div><h4>${L('SSO mit deinem Konto verknüpfen','Link SSO to your account')}</h4><p>${L('Optional eine externe OIDC-Identität mit diesem Konto verbinden.','Optionally link an external OIDC identity to this account.')}</p></div></div>
          ${publicProviders.length ? `<div class="provider-list">${publicProviders.map(p => `<div class="provider-row"><div><b>${esc(p.name)}</b><small>${linkedIds.has(Number(p.id)) ? L('Verbunden','Connected') : L('Nicht verbunden','Not connected')}</small></div>${linkedIds.has(Number(p.id)) ? `<span class="badge success">${L('Verbunden','Connected')}</span>` : `<button class="link-provider settings-row-button" data-id="${p.id}">${iconLabel('link', L('Verknüpfen','Link'))}</button>`}</div>`).join('')}</div>` : `<p class="muted">${L('Keine aktivierten SSO-Provider vorhanden.','No enabled SSO providers available.')}</p>`}
        </section>

        ${state.me?.role === 'admin' ? `<section class="settingssection" id="settings-users"><div class="sectiontitle"><div><h4>${L('Benutzer','Users')}</h4><p>${L('Lokale und per SSO angelegte ZentSSH-Konten verwalten.','Manage local and SSO-created ZentSSH accounts.')}</p></div><button id="add-user" class="settings-action-button primary">${iconLabel('plus', L('Benutzer','User'))}</button></div>
          <div class="provider-list">${adminUsers.length ? adminUsers.map(u => `<div class="provider-row"><div><b>${esc(u.name)}</b><small>${esc(u.email)} · ${userRoleLabel(u.role)} · ${u.active ? L('aktiv','active') : L('deaktiviert','disabled')}${u.lastLoginAt ? ` · ${L('letzter Login','last login')} ${fmtDateTime(u.lastLoginAt)}` : ''}</small></div><div class="rowactions">${u.ssoConnected ? `<span class="badge success">SSO</span>` : ''}${u.active ? `<span class="badge success">${L('Aktiv','Active')}</span>` : `<span class="badge">${L('Deaktiviert','Disabled')}</span>`}<button class="edit-user settings-row-button" data-id="${u.id}">${iconLabel('edit', L('Bearbeiten','Edit'))}</button></div></div>`).join('') : `<p class="muted">${L('Keine Benutzer gefunden.','No users found.')}</p>`}</div>
        </section>` : ''}
        ${state.me?.role === 'admin' ? `<section class="settingssection" id="settings-workspaces"><div class="sectiontitle"><div><h4>${L('Arbeitsbereiche','Workspaces')}</h4></div><button id="add-workspace" class="settings-action-button primary">${iconLabel('plus', L('Arbeitsbereich','Workspace'))}</button></div>
          <div class="provider-list">${adminWorkspaces.length ? adminWorkspaces.map(workspace => `<div class="provider-row"><div><b>${esc(workspace.name)}</b><small>${workspace.memberCount || 0} ${L('Benutzer','users')} · ${workspace.serverCount || 0} Server · ${workspace.folderCount || 0} ${L('Ordner','folders')}</small></div><div class="rowactions">${workspace.active ? `<span class="badge success">${L('Aktiv','Active')}</span>` : `<span class="badge">${L('Deaktiviert','Disabled')}</span>`}<button class="workspace-users settings-row-icon-button has-tooltip" data-id="${workspace.id}" type="button" data-tooltip="${esc(L('Benutzer verwalten','Manage users'))}" aria-label="${esc(L('Benutzer verwalten','Manage users'))}">${actionIcon('users')}</button><button class="edit-workspace settings-row-button" data-id="${workspace.id}">${iconLabel('edit', L('Bearbeiten','Edit'))}</button></div></div>`).join('') : `<p class="muted">${L('Noch keine Arbeitsbereiche vorhanden.','No workspaces yet.')}</p>`}</div>
        </section>` : ''}
        ${state.me?.role === 'admin' ? `<section class="settingssection" id="settings-server-templates"><div class="sectiontitle"><div><h4>${L('Server-Vorlagen','Server templates')}</h4></div><button id="add-server-template" class="settings-action-button primary">${iconLabel('plus', L('Server-Vorlage','Server template'))}</button></div>
          <div class="provider-list">${adminServerTemplates.length ? adminServerTemplates.map(template => `<div class="provider-row"><div><b>${esc(template.name)}</b><small>${esc(template.host)}:${Number(template.port || 22)}${template.jumpTemplateName ? ` · Jump: ${esc(template.jumpTemplateName)}` : ''} · ${template.usageCount || 0} ${L('Übernahmen','adoptions')}</small></div><div class="rowactions"><span class="badge ${template.active ? 'success' : ''}">${template.active ? L('Aktiv','Active') : L('Deaktiviert','Disabled')}</span><span class="badge">${template.visibleToAll ? L('Alle Benutzer','All users') : L('Gezielt freigegeben','Restricted')}</span><button class="server-template-users settings-row-icon-button has-tooltip" data-id="${template.id}" type="button" data-tooltip="${esc(L('Benutzer verwalten','Manage users'))}" aria-label="${esc(L('Benutzer verwalten','Manage users'))}">${actionIcon('users')}</button><button class="edit-server-template settings-row-button" data-id="${template.id}">${iconLabel('edit', L('Bearbeiten','Edit'))}</button></div></div>`).join('') : `<p class="muted">${L('Noch keine Server-Vorlagen vorhanden.','No server templates yet.')}</p>`}</div>
        </section>` : ''}
        ${state.me?.role === 'admin' ? `<section class="settingssection" id="settings-active-sessions"><div class="sectiontitle"><div><h4>${L('Aktive SSH-Sessions','Active SSH sessions')}</h4><p>${L('Serverseitige Shells bleiben je nach Persistenz auch ohne Browser verbunden.','Server-side shells can remain connected without a browser depending on persistence settings.')}</p></div>${adminSessions.length ? `<span class="badge">${adminSessions.length}</span>` : ''}</div>
          ${adminSessions.length ? `<div class="provider-list">${adminSessions.map(s => `<div class="provider-row"><div><b>${esc(s.userName || `User ${s.userId}`)} → ${esc(s.serverName)}</b><small>${s.attached ? `${s.attachments} ${L('Browser verbunden','browser attached')}` : 'Detached'} · ${L('seit','since')} ${fmtElapsed(s.createdAt)} · ${L('Persistenz','persistence')} ${esc(s.retention || '')}</small></div><div class="rowactions"><span class="badge ${s.attached ? 'success' : ''}">${s.attached ? L('Aktiv','Active') : 'Detached'}</span><button class="close-admin-session settings-row-button danger" data-id="${esc(s.id)}">${iconLabel('delete', L('Beenden','End'))}</button></div></div>`).join('')}</div>` : `<div class="settings-empty-state"><span class="settings-empty-icon">${actionIcon('terminal')}</span><b>${L('Keine aktiven SSH-Sessions','No active SSH sessions')}</b><small>${L('Sobald eine serverseitige Shell läuft, erscheint sie hier.','Running server-side shells will appear here.')}</small></div>`}
        </section>` : ''}
        <section class="settingssection" id="settings-import"><div class="sectiontitle"><div><h4>${L('OpenSSH Config importieren','Import OpenSSH config')}</h4><p>${L('Config zuerst prüfen, Hosts auswählen und erst danach als ZentSSH-Server anlegen.','Review the config first, select hosts, then create ZentSSH servers.')}</p></div><button id="openssh-import" class="settings-action-button primary">${iconLabel('import', L('Import starten','Start import'))}</button></div>
          <div class="provider-row"><div><b>${L('Vorschau vor Import','Preview before import')}</b><small>IdentityFile wird nur als Hinweis gelesen. Zugangsdaten kommen aus einer ZentSSH-Zugangsvorlage.</small></div><span class="badge">${L('Sicherer Import','Safe import')}</span></div>
        </section>
        ${state.me?.role === 'admin' ? `<section class="settingssection" id="settings-backup"><div class="sectiontitle"><div><h4>${L('Backup / Restore','Backup / Restore')}</h4><p>${L('Vollständige, passwortgeschützte Sicherung von Datenbank und Verschlüsselungsschlüssel.','Complete password-protected backup of the database and encryption key.')}</p></div></div>
          <div class="backup-stats-grid">
            <div class="backup-stat"><small>${L('Datenbank','Database')}</small><b>${fmtSize(backupStatus.databaseBytes || 0)}</b></div>
            <div class="backup-stat"><small>WAL</small><b>${fmtSize(backupStatus.walBytes || 0)}</b></div>
            <div class="backup-stat"><small>${L('Aktuell belegt','Currently used')}</small><b>${fmtSize(backupStatus.storageBytes || 0)}</b></div>
            <div class="backup-stat"><small>${L('Master-Key','Master key')}</small><b>${backupStatus.masterKeySource === 'environment' ? 'ENV' : L('Persistent','Persistent')}</b></div>
          </div>
          <div class="backup-history"><span>${L('Letztes Backup','Last backup')}: <b>${backupStatus.lastBackupAt ? fmtDateTime(backupStatus.lastBackupAt) : '—'}</b></span><span>${L('Letzter Restore','Last restore')}: <b>${backupStatus.lastRestoreAt ? fmtDateTime(backupStatus.lastRestoreAt) : '—'}</b></span></div>
          <div class="backup-panels">
            <div class="backup-panel"><div><h5>${L('Backup erstellen','Create backup')}</h5><p>${L('Das Backup enthält die vollständige ZentSSH-Datenbank und den dazugehörigen Master-Key. Das Passwort wird nicht gespeichert.','The backup contains the complete ZentSSH database and its matching master key. The password is never stored.')}</p></div>
              <div class="formgrid backup-form"><label>${L('Backup-Passwort','Backup password')}<input id="backup-password" type="password" minlength="10" autocomplete="new-password" placeholder="${esc(L('Mindestens 10 Zeichen','At least 10 characters'))}"></label><label>${L('Passwort wiederholen','Repeat password')}<input id="backup-password-repeat" type="password" minlength="10" autocomplete="new-password"></label></div>
              <div id="backup-export-error" class="err"></div><div class="settings-inline-actions"><button id="backup-export" class="primary">${iconLabel('download', L('Backup herunterladen','Download backup'))}</button></div>
            </div>
            <div class="backup-panel restore-panel is-collapsed">
              <div class="restore-panel-header" id="backup-restore-toggle" role="button" tabindex="0" aria-expanded="false" aria-controls="backup-restore-content">
                <div><h5>${L('Backup wiederherstellen','Restore backup')}</h5><p>${L('Die Datei wird vollständig geprüft, bevor Daten verändert werden.','The file is fully validated before any data is changed.')}</p></div>
                <span class="restore-panel-chevron" aria-hidden="true">⌄</span>
              </div>
              <div class="restore-panel-content" id="backup-restore-content" hidden>
                <div class="restore-warning"><b>${L('Achtung: Der aktuelle ZentSSH-Stand wird vollständig ersetzt.','Warning: The current ZentSSH state will be completely replaced.')}</b><span>${L('Benutzer, Server, Workspaces, Vorlagen, Zugänge, Schnipsel, OIDC, MFA und Einstellungen werden auf den Backup-Stand zurückgesetzt. Laufende SSH-Sessions und Transfers werden beendet. ZentSSH startet danach neu.','Users, servers, workspaces, templates, credentials, snippets, OIDC, MFA and settings are reset to the backup state. Running SSH sessions and transfers are stopped. ZentSSH then restarts.')}</span></div>
                ${backupStatus.masterKeySource === 'environment' ? `<div class="securitynote"><b>MASTER_KEY via ENV:</b> ${L('Restore ist nur möglich, wenn das Backup denselben Master-Key enthält. Einen Docker-ENV-Wert kann ZentSSH nicht selbst ersetzen.','Restore is only possible when the backup contains the same master key. ZentSSH cannot replace a Docker environment value itself.')}</div>` : ''}
                <div class="formgrid backup-form"><label class="wide">${L('Backup-Datei','Backup file')}<input id="backup-restore-file" type="file" accept=".zsb,application/octet-stream"></label><label>${L('Backup-Passwort','Backup password')}<input id="backup-restore-password" type="password" minlength="10" autocomplete="current-password"></label></div>
                <label class="restore-confirm"><input id="backup-restore-confirm" type="checkbox"><span>${L('Ich verstehe, dass der aktuelle Stand vollständig überschrieben wird.','I understand that the current state will be completely overwritten.')}</span></label>
                <div id="backup-restore-error" class="err"></div><div class="settings-inline-actions"><button id="backup-restore" class="danger" disabled>${iconLabel('retry', L('Vollständig wiederherstellen','Restore completely'))}</button></div>
              </div>
            </div>
          </div>
        </section>` : ''}
        ${state.me?.role === 'admin' ? `<section class="settingssection" id="settings-providers"><div class="sectiontitle"><div><h4>${L('OIDC / SSO Provider','OIDC / SSO providers')}</h4><p>Authentik, Keycloak, Authelia, Entra ID, Google Workspace, Zitadel und andere OIDC-Provider.</p></div><button id="add-provider" class="settings-action-button primary">${iconLabel('plus', L('Provider','Provider'))}</button></div>
          <div class="provider-list">${adminProviders.length ? adminProviders.map(p => `<div class="provider-row"><div><b>${esc(p.name)}</b><small>${esc(p.issuerUrl)} · ${p.enabled ? L('aktiv','active') : L('deaktiviert','disabled')} ${p.ssoId ? `· ${L('SSO-ID','SSO ID')} <span class="provider-sso-id">${esc(p.ssoId)}</span>` : ''}</small></div><div class="rowactions"><button class="edit-provider settings-row-button" data-id="${p.id}">${iconLabel('edit', L('Bearbeiten','Edit'))}</button></div></div>`).join('') : `<p class="muted">${L('Noch kein OIDC-Provider konfiguriert.','No OIDC provider configured yet.')}</p>`}</div>
        </section>` : ''}
      </div>
    </div>
  </div></div>`;
  $('[data-close]', modal).onclick = () => { modal.innerHTML = ''; };

  const activateCategory = targetId => {
    const section = document.getElementById(targetId);
    if (!section) return;
    $$('.settingssection', modal).forEach(item => item.classList.toggle('active', item.id === targetId));
    $$('.settingsnav button', modal).forEach(button => button.classList.toggle('active', button.dataset.settingsTarget === targetId));
    const content = $('.settingscontent', modal);
    if (content) content.scrollTop = 0;
    scheduleModalAutofocus(modal);
  };
  $$('.settingsnav button', modal).forEach(button => { button.onclick = () => activateCategory(button.dataset.settingsTarget); });

  $('#settings-profile-language').value = userSettings.language || me.language || uiLanguage();
  $('#settings-profile-save').onclick = async () => {
    const error = $('#settings-profile-error');
    error.textContent = '';
    const name = $('#settings-profile-name').value.trim();
    const email = $('#settings-profile-email').value.trim();
    const language = $('#settings-profile-language').value;
    const newPassword = $('#settings-profile-new-password')?.value || '';
    if (!name || !email) { error.textContent = L('Name und E-Mail sind erforderlich.','Name and email are required.'); return; }
    if (newPassword && newPassword !== ($('#settings-profile-new-password-repeat')?.value || '')) { error.textContent = L('Die neuen Passwörter stimmen nicht überein.','The new passwords do not match.'); return; }
    const button = $('#settings-profile-save');
    setButtonBusy(button, true, L('Speichere…','Saving…'));
    try {
      const oldLanguage = state.me?.language;
      const updated = await api('/me', { method: 'PATCH', body: JSON.stringify({ name, email, language, currentPassword: $('#settings-profile-current-password')?.value || '', newPassword }) });
      state.me = { ...state.me, ...updated };
      state.userSettings.language = updated.language || language;
      if (String(oldLanguage || '') !== String(state.userSettings.language || '')) { location.reload(); return; }
      const profileButton = $('#profile-menu'); if (profileButton) profileButton.textContent = state.me.name || '';
      showToast(L('Profil gespeichert.','Profile saved.'));
      setButtonBusy(button, false);
    } catch (e) { error.textContent = e.message; setButtonBusy(button, false); }
  };

  if ($('#session-retention')) {
    $('#session-retention').value = userSettings.sshSessionRetention || 'inherit';
    $('#session-retention').onchange = async () => {
      const status = $('#session-retention-status'); status.textContent = L('Speichere…','Saving…');
      try {
        await api('/me/settings', { method: 'PATCH', body: JSON.stringify({ sshSessionRetention: $('#session-retention').value, showHiddenFiles: Boolean(userSettings.showHiddenFiles), language: userSettings.language || state.me?.language || uiLanguage(), collapsedFolderIds: normalizedCollapsedFolderIds(userSettings.collapsedFolderIds) }) });
        userSettings.sshSessionRetention = $('#session-retention').value; state.userSettings.sshSessionRetention = userSettings.sshSessionRetention;
        status.textContent = L('Gespeichert. Gilt auch für bereits laufende Sessions.','Saved. Also applies to already running sessions.'); showToast(L('Session-Persistenz gespeichert.','Session persistence saved.'));
      } catch (e) { status.textContent = e.message; showToast(e.message, true); }
    };
  }
  if ($('#show-hidden-files')) $('#show-hidden-files').onchange = async () => {
    const status = $('#file-settings-status'); status.textContent = L('Speichere…','Saving…');
    try {
      userSettings.showHiddenFiles = $('#show-hidden-files').checked; state.userSettings.showHiddenFiles = userSettings.showHiddenFiles;
      await api('/me/settings', { method: 'PATCH', body: JSON.stringify({ sshSessionRetention: userSettings.sshSessionRetention || 'inherit', showHiddenFiles: userSettings.showHiddenFiles, language: userSettings.language || state.me?.language || uiLanguage(), collapsedFolderIds: normalizedCollapsedFolderIds(userSettings.collapsedFolderIds) }) });
      status.textContent = L('Gespeichert.','Saved.'); showToast(L('File-Manager-Einstellung gespeichert.','File manager setting saved.'));
      if (state.fileServer) openFiles(state.fileServer, state.filePath);
    } catch (e) { status.textContent = e.message; showToast(e.message, true); }
  };

  if ($('#add-private-folder')) $('#add-private-folder').onclick = () => snippetFolderModal({}, 'private');
  if ($('#add-shared-folder')) $('#add-shared-folder').onclick = () => snippetFolderModal({}, 'shared');
  if ($('#add-private-snippet')) $('#add-private-snippet').onclick = () => snippetEditorModal({}, 'private', { returnTo: 'settings' });
  if ($('#add-shared-snippet')) $('#add-shared-snippet').onclick = () => snippetEditorModal({}, 'shared', { returnTo: 'settings' });
  $$('.snippet-add-to-folder', modal).forEach(button => button.onclick = () => snippetEditorModal({}, button.dataset.scope, { returnTo: 'settings', folderId: Number(button.dataset.folderId || 0) }));
  $$('.snippet-edit-folder', modal).forEach(button => {
    button.onclick = () => {
      const scope = button.dataset.scope;
      const source = scope === 'shared' ? sharedSnippetFolders : privateSnippetFolders;
      snippetFolderModal(source.find(folder => Number(folder.id) === Number(button.dataset.folderId)) || {}, scope);
    };
  });
  $$('.snippet-folder-users', modal).forEach(button => {
    button.onclick = () => snippetFolderUsersModal(sharedSnippetFolders.find(folder => Number(folder.id) === Number(button.dataset.folderId)) || {});
  });
  $$('.snippet-edit-item', modal).forEach(button => {
    button.onclick = () => {
      const source = button.dataset.scope === 'shared' ? sharedSnippets : privateSnippets;
      snippetEditorModal(source.find(item => Number(item.id) === Number(button.dataset.id)) || {}, button.dataset.scope, { returnTo: 'settings' });
    };
  });
  $$('.snippet-delete-item', modal).forEach(button => {
    button.onclick = () => {
      const source = button.dataset.scope === 'shared' ? sharedSnippets : privateSnippets;
      deleteCodeSnippet(source.find(item => Number(item.id) === Number(button.dataset.id)), 'settings');
    };
  });
  $$('.snippet-private-draggable', modal).forEach(row => {
    row.addEventListener('dragstart', event => { event.dataTransfer.effectAllowed = 'move'; event.dataTransfer.setData('text/plain', row.dataset.id); row.classList.add('dragging'); });
    row.addEventListener('dragend', () => { row.classList.remove('dragging'); $$('.snippet-private-drop-target', modal).forEach(target => target.classList.remove('drop-active')); });
  });
  $$('.snippet-private-drop-target', modal).forEach(target => {
    target.addEventListener('dragover', event => { event.preventDefault(); target.classList.add('drop-active'); });
    target.addEventListener('dragleave', event => { if (!target.contains(event.relatedTarget)) target.classList.remove('drop-active'); });
    target.addEventListener('drop', event => {
      event.preventDefault(); target.classList.remove('drop-active');
      const id = Number(event.dataTransfer.getData('text/plain'));
      const snippet = privateSnippets.find(item => Number(item.id) === id);
      if (snippet) movePrivateSnippetToFolder(snippet, Number(target.dataset.folderId || 0));
    });
  });

  if ($('#mfa-enable')) $('#mfa-enable').onclick = () => mfaSetupModal();
  if ($('#mfa-recovery')) $('#mfa-recovery').onclick = () => mfaRecoveryModal();
  if ($('#mfa-disable')) $('#mfa-disable').onclick = () => mfaDisableModal();
  if ($('#add-credential')) $('#add-credential').onclick = () => credentialProfileModal();
  $$('.edit-credential', modal).forEach(button => { button.onclick = () => credentialProfileModal(state.profiles.find(p => Number(p.id) === Number(button.dataset.id)) || {}); });
  $$('.link-provider', modal).forEach(button => { button.onclick = () => oidcLinkStepUpModal(Number(button.dataset.id)); });
  if ($('#openssh-import')) $('#openssh-import').onclick = () => openSSHImportModal();
  if (state.me?.role === 'admin') {
    if ($('#add-user')) $('#add-user').onclick = () => userModal();
    $$('.edit-user', modal).forEach(button => { button.onclick = () => userModal(adminUsers.find(u => Number(u.id) === Number(button.dataset.id)) || {}); });
    $$('.close-admin-session', modal).forEach(button => { button.onclick = async () => {
      if (!confirm(L('SSH-Session wirklich beenden?','End SSH session?'))) return;
      try { await api(`/sessions/${encodeURIComponent(button.dataset.id)}`, { method: 'DELETE' }); state.notice = L('SSH-Session beendet.','SSH session ended.'); openSettings('active-sessions'); }
      catch (e) { showToast(e.message, true); }
    }; });
    const restorePanel = $('.restore-panel');
    const restoreToggle = $('#backup-restore-toggle');
    const restoreContent = $('#backup-restore-content');
    const setRestoreExpanded = expanded => {
      if (!restorePanel || !restoreToggle || !restoreContent) return;
      restorePanel.classList.toggle('is-collapsed', !expanded);
      restoreToggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      restoreContent.hidden = !expanded;
    };
    if (restoreToggle) {
      restoreToggle.onclick = () => setRestoreExpanded(restoreToggle.getAttribute('aria-expanded') !== 'true');
      restoreToggle.onkeydown = event => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        restoreToggle.click();
      };
    }
    const restoreFile = $('#backup-restore-file');
    const restorePassword = $('#backup-restore-password');
    const restoreConfirm = $('#backup-restore-confirm');
    const restoreButton = $('#backup-restore');
    const updateRestoreReady = () => {
      if (!restoreButton || restoreButton.classList.contains('is-busy')) return;
      restoreButton.disabled = !(restoreFile?.files?.length && String(restorePassword?.value || '').length >= 10 && restoreConfirm?.checked);
    };
    if (restoreFile) restoreFile.onchange = updateRestoreReady;
    if (restorePassword) restorePassword.oninput = updateRestoreReady;
    if (restoreConfirm) restoreConfirm.onchange = updateRestoreReady;
    if ($('#backup-export')) $('#backup-export').onclick = async () => {
      const password = $('#backup-password')?.value || '';
      const repeat = $('#backup-password-repeat')?.value || '';
      const error = $('#backup-export-error');
      error.textContent = '';
      if (password.length < 10) { error.textContent = L('Das Backup-Passwort muss mindestens 10 Zeichen lang sein.','The backup password must be at least 10 characters long.'); return; }
      if (password !== repeat) { error.textContent = L('Die Backup-Passwörter stimmen nicht überein.','The backup passwords do not match.'); return; }
      const button = $('#backup-export');
      setButtonBusy(button, true, L('Backup wird erstellt…','Creating backup…'));
      try {
        await downloadAdminBackup(password);
        $('#backup-password').value = '';
        $('#backup-password-repeat').value = '';
        state.notice = L('Backup wurde erstellt und heruntergeladen.','Backup was created and downloaded.');
        openSettings('backup');
      } catch (e) {
        error.textContent = e.message;
        setButtonBusy(button, false);
      }
    };
    if (restoreButton) restoreButton.onclick = async () => {
      const error = $('#backup-restore-error');
      error.textContent = '';
      const file = restoreFile?.files?.[0];
      const password = restorePassword?.value || '';
      if (!file || password.length < 10 || !restoreConfirm?.checked) { updateRestoreReady(); return; }
      if (!confirm(L('Wirklich vollständig wiederherstellen? Der aktuelle ZentSSH-Stand wird ersetzt und ZentSSH startet neu.','Restore completely? The current ZentSSH state will be replaced and ZentSSH will restart.'))) return;
      setButtonBusy(restoreButton, true, L('Backup wird geprüft…','Validating backup…'));
      if (restoreFile) restoreFile.disabled = true;
      if (restorePassword) restorePassword.disabled = true;
      if (restoreConfirm) restoreConfirm.disabled = true;
      const form = new FormData();
      form.append('backup', file, file.name);
      form.append('password', password);
      try {
        await api('/admin/backup/restore', { method: 'POST', body: form });
        const panel = $('#settings-backup');
        if (panel) panel.innerHTML = `<div class="settings-empty-state backup-restarting"><span class="settings-empty-icon">${actionIcon('retry')}</span><b>${esc(L('Restore erfolgreich. ZentSSH startet neu…','Restore successful. ZentSSH is restarting…'))}</b><small>${esc(L('Sobald der Dienst wieder erreichbar ist, wird die Seite automatisch neu geladen.','The page will reload automatically as soon as the service is available again.'))}</small></div>`;
        reloadAfterRestore();
      } catch (e) {
        error.textContent = e.message;
        if (restoreFile) restoreFile.disabled = false;
        if (restorePassword) restorePassword.disabled = false;
        if (restoreConfirm) restoreConfirm.disabled = false;
        setButtonBusy(restoreButton, false);
        updateRestoreReady();
      }
    };
    if ($('#add-workspace')) $('#add-workspace').onclick = () => workspaceAdminModal();
    $$('.edit-workspace', modal).forEach(button => { button.onclick = () => workspaceAdminModal(adminWorkspaces.find(item => Number(item.id) === Number(button.dataset.id)) || {}); });
    $$('.workspace-users', modal).forEach(button => { button.onclick = () => workspaceUsersModal(adminWorkspaces.find(item => Number(item.id) === Number(button.dataset.id)) || {}); });
    if ($('#add-server-template')) $('#add-server-template').onclick = () => serverTemplateAdminModal();
    $$('.edit-server-template', modal).forEach(button => { button.onclick = () => serverTemplateAdminModal(adminServerTemplates.find(item => Number(item.id) === Number(button.dataset.id)) || {}); });
    $$('.server-template-users', modal).forEach(button => { button.onclick = () => serverTemplateUsersModal(adminServerTemplates.find(item => Number(item.id) === Number(button.dataset.id)) || {}); });
    if ($('#add-provider')) $('#add-provider').onclick = () => oidcProviderModal();
    $$('.edit-provider', modal).forEach(button => { button.onclick = () => oidcProviderModal(adminProviders.find(p => Number(p.id) === Number(button.dataset.id)) || {}); });
  }

  const focusMap = { profile: 'settings-profile', credentials: 'settings-credentials', security: 'settings-security', sessions: 'settings-sessions', files: 'settings-files', snippets: 'settings-snippets', 'shared-snippets': 'settings-shared-snippets', sso: 'settings-sso', users: 'settings-users', workspaces: 'settings-workspaces', 'server-templates': 'settings-server-templates', 'active-sessions': 'settings-active-sessions', backup: 'settings-backup', import: 'settings-import', providers: 'settings-providers' };
  activateCategory(focusMap[focus] || 'settings-profile');
  if (state.notice) { showToast(state.notice); state.notice = ''; }
}

function openSSHImportModal() {
  const modal = $('#modal');
  const renderInput = () => {
    modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog opensshimportdialog">
      <div class="dialogtitle"><div><h3>OpenSSH Config importieren</h3><p>Füge deine OpenSSH-Konfiguration ein. ZentSSH legt noch keine Server an, bevor du die Vorschau ausdrücklich bestätigst.</p></div><button data-close class="iconbutton">×</button></div>
      <label class="wide">OpenSSH Config<textarea id="openssh-config" class="configtextarea" placeholder="Host web01\n    HostName 192.168.1.10\n    User root\n    Port 22\n    IdentityFile ~/.ssh/id_ed25519\n\nHost db01\n    HostName 10.0.0.20\n    ProxyJump web01" autocomplete="off"></textarea></label>
      <div class="securitynote"><b>Keine lokalen Keys werden gelesen:</b> <code>IdentityFile</code> wird in der Vorschau angezeigt, aber die eigentlichen Zugangsdaten stammen aus einer verschlüsselten ZentSSH-Zugangsvorlage.</div>
      <div id="openssh-error" class="err"></div>
      <div class="actions"><button data-cancel>Abbrechen</button><button id="openssh-preview" class="primary">Vorschau prüfen</button></div>
    </div></div>`;
    $('[data-close]', modal).onclick = () => openSettings('import');
    $('[data-cancel]', modal).onclick = () => openSettings('import');
    $('#openssh-preview').onclick = async () => {
      const config = $('#openssh-config').value;
      const button = $('#openssh-preview');
      const error = $('#openssh-error');
      error.textContent = '';
      button.disabled = true; button.textContent = 'Prüfe…';
      try {
        const [preview, personalFolders] = await Promise.all([
          api('/import/openssh/preview', { method: 'POST', body: JSON.stringify({ config }) }),
          api('/folders')
        ]);
        renderPreview(config, preview, Array.isArray(personalFolders) ? personalFolders : []);
      } catch (e) {
        error.textContent = e.message;
        button.disabled = false; button.textContent = 'Vorschau prüfen';
      }
    };
  };

  const renderPreview = (config, preview, personalFolders) => {
    const entries = Array.isArray(preview.entries) ? preview.entries : [];
    modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog opensshimportdialog">
      <div class="dialogtitle"><div><h3>Import-Vorschau</h3><p>${entries.length} konkrete Host${entries.length === 1 ? '' : 's'} erkannt. Wähle aus, was wirklich importiert werden soll.</p></div><button data-close class="iconbutton">×</button></div>
      ${preview.warnings?.length ? `<div class="import-global-warnings"><b>Hinweise aus der Config</b>${preview.warnings.map(w => `<div>• ${esc(w)}</div>`).join('')}</div>` : ''}
      <div class="import-toolbar">
        <label><input id="openssh-select-all" type="checkbox" ${entries.length ? 'checked' : ''}> Alle importierbaren Hosts auswählen</label>
        <span class="badge">${entries.length} erkannt</span>
      </div>
      <div class="import-entry-list">${entries.length ? entries.map((entry, index) => `<label class="import-entry">
        <input class="openssh-entry-check" type="checkbox" data-index="${index}" checked>
        <div class="import-entry-main"><b>${esc(entry.alias)}</b><small>${esc(entry.user || '(User aus Vorlage)')}@${esc(entry.hostName)}:${entry.port || 22}${entry.proxyJump ? ` · via ${esc(entry.proxyJump)}` : ''}</small>
          <div class="import-meta">${entry.identityFile ? `<span>IdentityFile: ${esc(entry.identityFile)}</span>` : ''}${entry.preferredAuthentications ? `<span>Auth: ${esc(entry.preferredAuthentications)}</span>` : ''}${entry.serverAliveInterval ? `<span>Keepalive: ${Number(entry.serverAliveInterval)}s</span>` : ''}</div>
          ${entry.warnings?.length ? `<div class="import-entry-warnings">${entry.warnings.map(w => `<span>⚠ ${esc(w)}</span>`).join('')}</div>` : ''}
        </div>
      </label>`).join('') : '<p class="muted">Keine konkreten importierbaren Host-Blöcke gefunden.</p>'}</div>
      <div class="formgrid import-targets">
        <label>Zugangsvorlage<select id="openssh-profile"><option value="">Vorlage auswählen…</option>${state.profiles.map(p => `<option value="${p.id}">${esc(p.name)} · ${esc(p.username)}</option>`).join('')}</select></label>
        <label>Zielordner<select id="openssh-folder"><option value="">Kein Ordner</option>${personalFolders.map(f => `<option value="${f.id}">${esc(f.name)}</option>`).join('')}</select></label>
      </div>
      ${state.profiles.length ? '' : '<div class="securitynote">Für den Import brauchst du mindestens eine SSH-Zugangsvorlage. Lege zuerst eine Vorlage an; <code>IdentityFile</code> aus der Config wird nicht als Secret importiert.</div>'}
      <div id="openssh-import-error" class="err"></div>
      <div class="actions spread"><button id="openssh-back">Zurück</button><div><button id="openssh-import-submit" class="primary" ${(!entries.length || !state.profiles.length) ? 'disabled' : ''}>Ausgewählte Hosts importieren</button></div></div>
    </div></div>`;
    $('[data-close]', modal).onclick = () => openSettings('import');
    $('#openssh-back').onclick = renderInput;
    const all = $('#openssh-select-all');
    const checks = () => $$('.openssh-entry-check', modal);
    if (all) all.onchange = () => checks().forEach(c => { c.checked = all.checked; });
    checks().forEach(c => c.onchange = () => { if (all) all.checked = checks().length > 0 && checks().every(x => x.checked); });
    $('#openssh-import-submit').onclick = async () => {
      const aliases = checks().filter(c => c.checked).map(c => entries[Number(c.dataset.index)]?.alias).filter(Boolean);
      const profileId = Number($('#openssh-profile').value || 0);
      const folderRaw = $('#openssh-folder').value;
      const error = $('#openssh-import-error');
      if (!aliases.length) { error.textContent = 'Wähle mindestens einen Host aus.'; return; }
      if (!profileId) { error.textContent = 'Wähle eine Zugangsvorlage aus.'; return; }
      const button = $('#openssh-import-submit');
      button.disabled = true; button.textContent = 'Importiere…'; error.textContent = '';
      try {
        const result = await api('/import/openssh', { method: 'POST', body: JSON.stringify({ config, aliases, credentialProfileId: profileId, folderId: folderRaw ? Number(folderRaw) : null }) });
        await loadWorkspace();
        renderResult(result);
      } catch (e) {
        error.textContent = e.message;
        button.disabled = false; button.textContent = 'Ausgewählte Hosts importieren';
      }
    };
  };

  const renderResult = result => {
    const imported = Array.isArray(result.imported) ? result.imported : [];
    const skipped = Array.isArray(result.skipped) ? result.skipped : [];
    const warnings = Array.isArray(result.warnings) ? result.warnings : [];
    modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog opensshimportdialog">
      <div class="dialogtitle"><div><h3>OpenSSH Import abgeschlossen</h3><p>${imported.length} importiert · ${skipped.length} übersprungen · ${warnings.length} Hinweis${warnings.length === 1 ? '' : 'e'}</p></div><button data-close class="iconbutton">×</button></div>
      <div class="import-result-grid">
        <div class="import-result-card success"><b>${imported.length}</b><span>Importiert</span></div>
        <div class="import-result-card"><b>${skipped.length}</b><span>Übersprungen</span></div>
        <div class="import-result-card"><b>${warnings.length}</b><span>Hinweise</span></div>
      </div>
      ${imported.length ? `<div class="provider-list"><h4>Neue Server</h4>${imported.map(s => `<div class="provider-row"><div><b>${esc(s.name)}</b><small>${esc(s.username)}@${esc(s.host)}:${s.port || 22}${s.jumpHostId ? ' · Jump Host zugeordnet' : ''}</small></div><span class="badge success">Importiert</span></div>`).join('')}</div>` : ''}
      ${skipped.length ? `<div class="import-report"><h4>Übersprungen</h4>${skipped.map(x => `<div>• ${esc(x)}</div>`).join('')}</div>` : ''}
      ${warnings.length ? `<div class="import-report warning"><h4>Hinweise</h4>${warnings.map(x => `<div>• ${esc(x)}</div>`).join('')}</div>` : ''}
      <div class="actions"><button id="openssh-done" class="primary">Fertig</button></div>
    </div></div>`;
    $('[data-close]', modal).onclick = () => { modal.innerHTML = ''; render(); };
    $('#openssh-done').onclick = () => { modal.innerHTML = ''; render(); showToast(`${imported.length} Server importiert.`); };
  };

  renderInput();
}

function recoveryCodesView(codes, title = 'Recovery Codes') {
  return `<div class="recoverybox"><h4>${esc(title)}</h4><p>Speichere diese Codes jetzt sicher. Sie werden danach nicht erneut angezeigt.</p><div class="recoverygrid">${codes.map(code => `<code>${esc(code)}</code>`).join('')}</div><button id="copy-recovery">Alle kopieren</button></div>`;
}

async function oidcLinkStepUpModal(providerId) {
  if (!state.me?.localPasswordAvailable) {
    showToast(L('Zusätzliches SSO-Verknüpfen ist für reine SSO-Konten nicht verfügbar.','Additional SSO linking is not available for SSO-only accounts.'), true);
    return;
  }
  let mfa = { enabled: false };
  try { mfa = await api('/me/mfa'); } catch {}
  const modal = $('#modal');
  modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog"><div class="dialogtitle"><div><h3>${L('SSO verknüpfen','Link SSO')}</h3><p>${L('Bestätige deine Identität, bevor ein weiterer Anmeldeweg hinzugefügt wird.','Confirm your identity before adding another sign-in method.')}</p></div><button data-close class="iconbutton">×</button></div><label>${L('Aktuelles Passwort','Current password')}<input id="oidc-link-password" type="password" autocomplete="current-password"></label>${mfa.enabled ? `<label>${L('MFA-Code','MFA code')}<input id="oidc-link-mfa" inputmode="numeric" autocomplete="one-time-code"></label>` : ''}<div id="oidc-link-error" class="err"></div><div class="actions"><button data-cancel>${L('Abbrechen','Cancel')}</button><button id="oidc-link-start" class="primary">${L('Weiter','Continue')}</button></div></div></div>`;
  const close = () => openSettings('sso');
  $('[data-close]', modal).onclick = close;
  $('[data-cancel]', modal).onclick = close;
  $('#oidc-link-start').onclick = async () => {
    const button = $('#oidc-link-start');
    const error = $('#oidc-link-error');
    error.textContent = '';
    setButtonBusy(button, true, L('Prüfe…','Checking…'));
    try {
      const result = await api('/me/oidc/start', { method: 'POST', body: JSON.stringify({ providerId, password: $('#oidc-link-password').value, mfaCode: $('#oidc-link-mfa')?.value || '' }) });
      location.href = result.url;
    } catch (e) { error.textContent = e.message; setButtonBusy(button, false); }
  };
}

function mfaSetupModal() {
  const modal = $('#modal');
  modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog"><div class="dialogtitle"><div><h3>MFA einrichten</h3><p>Bestätige zuerst dein aktuelles Passwort.</p></div><button data-close class="iconbutton">×</button></div><label>Aktuelles Passwort<input id="mfa-setup-password" type="password" autocomplete="current-password"></label><div id="mfa-setup-error" class="err"></div><div class="actions"><button data-cancel>Abbrechen</button><button id="mfa-setup-start" class="primary">Weiter</button></div></div></div>`;
  $('[data-close]', modal).onclick = () => openSettings('security'); $('[data-cancel]', modal).onclick = () => openSettings('security');
  $('#mfa-setup-start').onclick = async () => {
    const error = $('#mfa-setup-error'); error.textContent = '';
    try {
      const setup = await api('/me/mfa/setup', { method: 'POST', body: JSON.stringify({ password: $('#mfa-setup-password').value }) });
      modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog mfa-setup-dialog"><div class="dialogtitle"><div><h3>${L('Authenticator verbinden','Connect authenticator')}</h3><p>${L('Scanne den QR-Code mit deiner Authenticator-App und bestätige anschließend einen aktuellen Code.','Scan the QR code with your authenticator app, then confirm a current code.')}</p></div><button data-close class="iconbutton">×</button></div><div class="mfa-enrollment"><div class="mfa-qr-card"><div class="mfa-qr" id="mfa-qr"></div><small>${L('Mit Authenticator-App scannen','Scan with authenticator app')}</small></div><div class="mfa-manual"><div class="fingerprintbox"><small>${L('Manuelles TOTP-Secret','Manual TOTP secret')}</small><code>${esc(setup.secret)}</code></div><small class="fieldhint">${L('Falls du keinen QR-Code scannen kannst, kannst du dieses Secret manuell in deiner App eintragen.','If you cannot scan the QR code, enter this secret manually in your app.')}</small></div></div><label>${L('Bestätigungscode','Verification code')}<input id="mfa-confirm-code" inputmode="numeric" autocomplete="one-time-code"></label><div id="mfa-confirm-error" class="err"></div><div class="actions"><button data-cancel>${L('Abbrechen','Cancel')}</button><button id="mfa-confirm" class="primary">${L('MFA aktivieren','Enable MFA')}</button></div></div></div>`;
      const qrTarget = $('#mfa-qr');
      if (qrTarget) qrTarget.innerHTML = qrSvg(setup.otpauthUri, { scale: 4, errorLevel: 'M' });
      $('[data-close]', modal).onclick = () => openSettings('security'); $('[data-cancel]', modal).onclick = () => openSettings('security');
      $('#mfa-confirm').onclick = async () => {
        try {
          const result = await api('/me/mfa/confirm', { method: 'POST', body: JSON.stringify({ code: $('#mfa-confirm-code').value.trim() }) });
          modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog"><h3>MFA ist aktiv</h3>${recoveryCodesView(result.recoveryCodes || [])}<div class="actions"><button id="mfa-finish" class="primary">Fertig</button></div></div></div>`;
          if ($('#copy-recovery')) $('#copy-recovery').onclick = () => navigator.clipboard?.writeText((result.recoveryCodes || []).join('\n'));
          $('#mfa-finish').onclick = () => openSettings('security');
        } catch (e) { $('#mfa-confirm-error').textContent = e.message; }
      };
    } catch (e) { error.textContent = e.message; }
  };
}

function mfaRecoveryModal() {
  const modal = $('#modal');
  modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog"><div class="dialogtitle"><div><h3>Recovery Codes erneuern</h3><p>Alte Recovery Codes werden ungültig.</p></div><button data-close class="iconbutton">×</button></div><label>Aktuelles Passwort<input id="mfa-rec-password" type="password" autocomplete="current-password"></label><label>Aktueller TOTP Code<input id="mfa-rec-code" inputmode="numeric" autocomplete="one-time-code"></label><div id="mfa-rec-error" class="err"></div><div class="actions"><button data-cancel>Abbrechen</button><button id="mfa-rec-submit" class="primary">Neue Codes erzeugen</button></div></div></div>`;
  $('[data-close]', modal).onclick = () => openSettings('security'); $('[data-cancel]', modal).onclick = () => openSettings('security');
  $('#mfa-rec-submit').onclick = async () => {
    try { const result = await api('/me/mfa/recovery', { method: 'POST', body: JSON.stringify({ password: $('#mfa-rec-password').value, code: $('#mfa-rec-code').value.trim() }) }); modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog">${recoveryCodesView(result.recoveryCodes || [], 'Neue Recovery Codes')}<div class="actions"><button id="mfa-finish" class="primary">Fertig</button></div></div></div>`; if ($('#copy-recovery')) $('#copy-recovery').onclick = () => navigator.clipboard?.writeText((result.recoveryCodes || []).join('\n')); $('#mfa-finish').onclick = () => openSettings('security'); }
    catch (e) { $('#mfa-rec-error').textContent = e.message; }
  };
}

function mfaDisableModal() {
  const modal = $('#modal');
  modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog"><div class="dialogtitle"><div><h3>MFA deaktivieren</h3><p>Erfordert aktuelles Passwort und TOTP- oder Recovery-Code.</p></div><button data-close class="iconbutton">×</button></div><label>Aktuelles Passwort<input id="mfa-off-password" type="password" autocomplete="current-password"></label><label>MFA / Recovery Code<input id="mfa-off-code" autocomplete="one-time-code"></label><div id="mfa-off-error" class="err"></div><div class="actions"><button data-cancel>Abbrechen</button><button id="mfa-off-submit" class="danger">MFA deaktivieren</button></div></div></div>`;
  $('[data-close]', modal).onclick = () => openSettings('security'); $('[data-cancel]', modal).onclick = () => openSettings('security');
  $('#mfa-off-submit').onclick = async () => { try { await api('/me/mfa/disable', { method: 'POST', body: JSON.stringify({ password: $('#mfa-off-password').value, code: $('#mfa-off-code').value.trim() }) }); state.notice = 'MFA deaktiviert.'; openSettings('security'); } catch (e) { $('#mfa-off-error').textContent = e.message; } };
}

function userRoleLabel(role) {
  const de = ({ admin: 'Admin', user: 'User', readonly: 'User', 'read-only': 'User' })[role] || role;
  const en = ({ admin: 'Admin', user: 'User', readonly: 'User', 'read-only': 'User' })[role] || role;
  return L(de, en);
}

function fmtDateTime(value) {
  try { return new Intl.DateTimeFormat(uiLanguage() === 'de' ? 'de-DE' : 'en-US', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value)); }
  catch { return String(value || ''); }
}

function fmtElapsed(value) {
  const ms = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(ms) || ms < 0) return L('gerade eben','just now');
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m`;
  const hours = Math.floor(min / 60);
  if (hours < 48) return `${hours}h ${min % 60}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}

async function userModal(user = {}) {
  const modal = $('#modal');
  const editing = Boolean(user.id);
  let workspaceAccess = [];
  let snippetAccess = [];
  let templateAccess = [];
  if (editing) {
    const userID = encodeURIComponent(user.id);
    const results = await Promise.allSettled([
      api(`/admin/workspace-memberships?userId=${userID}`),
      api(`/admin/snippet-folder-permissions?userId=${userID}`),
      api(`/admin/server-template-user-access?userId=${userID}`),
    ]);
    const [workspacesResult, snippetsResult, templatesResult] = results;
    if (workspacesResult.status === 'fulfilled') {
      workspaceAccess = Array.isArray(workspacesResult.value.workspaces) ? workspacesResult.value.workspaces.map(item => ({ ...item, assigned: Boolean(item.assigned), _initialAssigned: Boolean(item.assigned) })) : [];
    } else showToast(workspacesResult.reason?.message || L('Arbeitsbereiche konnten nicht geladen werden.','Workspaces could not be loaded.'), true);
    if (snippetsResult.status === 'fulfilled') {
      snippetAccess = Array.isArray(snippetsResult.value.folders) ? snippetsResult.value.folders.map(item => ({ ...item, assigned: Boolean(item.assigned), _initialAssigned: Boolean(item.assigned) })) : [];
    } else showToast(snippetsResult.reason?.message || L('Geteilte Schnipsel konnten nicht geladen werden.','Shared snippets could not be loaded.'), true);
    if (templatesResult.status === 'fulfilled') {
      templateAccess = Array.isArray(templatesResult.value.templates) ? templatesResult.value.templates.map(item => ({ ...item, assigned: Boolean(item.assigned), visibleToAll: Boolean(item.visibleToAll), viaWorkspace: Boolean(item.viaWorkspace), _initialAssigned: Boolean(item.assigned) })) : [];
    } else showToast(templatesResult.reason?.message || L('Server-Vorlagen konnten nicht geladen werden.','Server templates could not be loaded.'), true);
  }
  modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog user-edit-dialog modal-scroll">
    <div class="dialogtitle"><div><h3>${editing ? L('Benutzer bearbeiten','Edit user') : L('Benutzer anlegen','Create user')}</h3></div><button data-close class="iconbutton">×</button></div>
    ${editing && user.ssoConnected ? `<div class="settings-managed-block user-sso-admin-hint"><div class="settings-managed-icon">${actionIcon('shield')}</div><div><h4>${L('SSO aktiv','SSO active')}</h4><p>${esc(L(`Dieses Konto ist aktuell über ${user.ssoProviders || 'SSO'} verknüpft. Die lokale Passwort-Anmeldung und ZentSSH-MFA werden während dieser aktiven SSO-Verknüpfung nicht verwendet.`,`This account is currently linked through ${user.ssoProviders || 'SSO'}. Local password sign-in and ZentSSH MFA are not used while this SSO link is active.`))}</p></div></div>` : ''}
    <div class="formgrid">
      <label>${L('Name','Name')}<input id="user-name" value="${esc(user.name || '')}" autocomplete="off" autofocus></label>
      <label>${L('E-Mail','Email')}<input id="user-email" type="email" value="${esc(user.email || '')}" autocomplete="off"></label>
      <label>${L('Rolle','Role')}<select id="user-role"><option value="admin">Admin</option><option value="user">User</option></select></label>
      <label>${editing ? L('Neues Passwort','New password') : L('Passwort','Password')}<input id="user-password" type="password" ${editing && user.ssoConnected ? 'disabled' : ''} placeholder="${editing && user.ssoConnected ? L('Durch SSO verwaltet','Managed by SSO') : (editing ? L('Leer = unverändert','Leave empty to keep unchanged') : L('Mindestens 10 Zeichen','At least 10 characters'))}" autocomplete="new-password"></label>
    </div>
    <div class="checkrow"><label><input id="user-active" type="checkbox" ${editing ? (user.active ? 'checked' : '') : 'checked'}> ${L('Konto aktiv','Account active')}</label></div>
    ${editing ? `<div id="user-shared-access" class="user-shared-access"></div>` : ''}
    <div id="user-error" class="err"></div>
    <div class="actions spread">${editing ? `<button id="user-delete" class="danger">${L('Löschen','Delete')}</button>` : '<span></span>'}<div><button data-cancel>${L('Abbrechen','Cancel')}</button><button id="user-save" class="primary">${L('Speichern','Save')}</button></div></div>
  </div></div>`;
  const normalizeRole = value => ['readonly','read-only'].includes(value) ? 'user' : (value || 'user');
  $('#user-role').value = normalizeRole(user.role);

  const sectionDefinitions = () => [
    { key: 'workspace', title: L('Arbeitsbereiche','Workspaces'), icon: 'shared', items: workspaceAccess, idKey: 'workspaceId', empty: L('Keine Arbeitsbereiche vorhanden.','No workspaces available.') },
    { key: 'snippet', title: L('Geteilte Schnipsel','Shared snippets'), icon: 'code', items: snippetAccess, idKey: 'folderId', empty: L('Keine geteilten Schnipsel vorhanden.','No shared snippets available.') },
    { key: 'template', title: L('Server-Vorlagen','Server templates'), icon: 'server', items: templateAccess, idKey: 'templateId', empty: L('Keine Server-Vorlagen vorhanden.','No server templates available.') },
  ];
  const effectiveAccess = (section, item, admin) => admin || Boolean(item.assigned) || (section.key === 'template' && (Boolean(item.visibleToAll) || Boolean(item.viaWorkspace)));
  const templateAccessLocked = item => Boolean(item.visibleToAll) || Boolean(item.viaWorkspace);

  const renderSharedAccess = () => {
    const root = $('#user-shared-access', modal);
    if (!root) return;
    const admin = $('#user-role').value === 'admin';
    root.innerHTML = sectionDefinitions().map(section => {
      const ordered = [...section.items].sort((a, b) => Number(effectiveAccess(section, b, admin)) - Number(effectiveAccess(section, a, admin)) || String(a.name || '').localeCompare(String(b.name || ''), uiLanguage()));
      const count = ordered.filter(item => effectiveAccess(section, item, admin)).length;
      const rows = ordered.length ? ordered.map(item => {
        const effective = effectiveAccess(section, item, admin);
        const locked = admin || (section.key === 'template' && templateAccessLocked(item));
        const status = [];
        if ('active' in item && !item.active) status.push(L('Deaktiviert','Disabled'));
        if (section.key === 'template' && item.visibleToAll) status.push(L('Für alle','For all'));
        else if (section.key === 'template' && item.viaWorkspace) status.push(L('Arbeitsbereich','Workspace'));
        return `<div class="user-access-row${effective ? ' assigned' : ''}" data-access-kind="${section.key}" data-access-id="${item[section.idKey]}"><div><b>${esc(item.name)}</b>${status.length ? `<small>${esc(status.join(' · '))}</small>` : ''}</div><input class="user-access-toggle" type="checkbox" ${effective ? 'checked' : ''} ${locked ? 'disabled' : ''} aria-label="${esc(L('Zugriff zuweisen','Assign access'))}"></div>`;
      }).join('') : `<div class="user-access-note">${esc(section.empty)}</div>`;
      return `<details class="user-access-details"><summary><span>${actionIcon(section.icon)}<b>${esc(section.title)}</b></span><span class="badge" data-access-count="${section.key}">${admin ? L('Alle','All') : count}</span></summary><div class="user-access-list">${rows}</div></details>`;
    }).join('');

    $$('.user-access-row', root).forEach(row => {
      const section = sectionDefinitions().find(candidate => candidate.key === row.dataset.accessKind);
      if (!section) return;
      const item = section.items.find(candidate => Number(candidate[section.idKey]) === Number(row.dataset.accessId));
      const toggle = $('.user-access-toggle', row);
      if (!item || !toggle || toggle.disabled) return;
      toggle.onchange = event => {
        item.assigned = event.target.checked;
        row.classList.toggle('assigned', item.assigned);
        const badge = $(`[data-access-count="${section.key}"]`, root);
        if (badge) badge.textContent = String(section.items.filter(candidate => effectiveAccess(section, candidate, false)).length);
      };
    });
  };

  $('#user-role').onchange = renderSharedAccess;
  renderSharedAccess();
  $('[data-close]', modal).onclick = () => openSettings('users');
  $('[data-cancel]', modal).onclick = () => openSettings('users');
  $('#user-save').onclick = async () => {
    const body = { name: $('#user-name').value.trim(), email: $('#user-email').value.trim(), role: $('#user-role').value, active: $('#user-active').checked, password: $('#user-password').value };
    const button = $('#user-save');
    setButtonBusy(button, true, L('Speichere…','Saving…'));
    try {
      await api(editing ? `/admin/users/${user.id}` : '/admin/users', { method: editing ? 'PATCH' : 'POST', body: JSON.stringify(body) });
      if (editing && body.role !== 'admin') {
        for (const item of workspaceAccess.filter(candidate => Boolean(candidate.assigned) !== Boolean(candidate._initialAssigned))) {
          await api('/admin/workspace-memberships', { method: 'PATCH', body: JSON.stringify({ workspaceId: Number(item.workspaceId), userId: Number(user.id), assigned: Boolean(item.assigned), canUse: Boolean(item.assigned), canCreate: false, canEdit: false, canDelete: false }) });
        }
        for (const item of snippetAccess.filter(candidate => Boolean(candidate.assigned) !== Boolean(candidate._initialAssigned))) {
          await api('/admin/snippet-folder-permissions', { method: 'PATCH', body: JSON.stringify({ folderId: Number(item.folderId), userId: Number(user.id), assigned: Boolean(item.assigned), canUse: Boolean(item.assigned), canCreate: false, canEdit: false, canDelete: false }) });
        }
        for (const item of templateAccess.filter(candidate => !templateAccessLocked(candidate) && Boolean(candidate.assigned) !== Boolean(candidate._initialAssigned))) {
          await api('/admin/server-template-user-access', { method: 'PATCH', body: JSON.stringify({ templateId: Number(item.templateId), userId: Number(user.id), assigned: Boolean(item.assigned) }) });
        }
      }
      state.notice = editing ? L('Benutzer gespeichert.','User saved.') : L('Benutzer angelegt.','User created.');
      if (editing && Number(user.id) === Number(state.me?.id)) { location.reload(); return; }
      openSettings('users');
    } catch (e) { $('#user-error').textContent = e.message; setButtonBusy(button, false); }
  };
  if (editing) $('#user-delete').onclick = async () => {
    const serverCount = Number(user.serverCount || 0);
    const folderCount = Number(user.folderCount || 0);
    const credentialProfileCount = Number(user.credentialProfileCount || 0);
    const hasOwnedData = serverCount || folderCount || credentialProfileCount;
    const ownedText = hasOwnedData ? L(`\n\nDabei werden auch ${serverCount} private Server, ${folderCount} private Ordner und ${credentialProfileCount} SSH-Zugangsvorlagen dieses Benutzers gelöscht.`,`\n\nThis also deletes ${serverCount} private servers, ${folderCount} private folders and ${credentialProfileCount} SSH credential profiles owned by this user.`) : '';
    if (!confirm(`${L('Benutzer wirklich löschen?','Delete user?')} „${user.name}“${ownedText}`)) return;
    try { await api(`/admin/users/${user.id}${hasOwnedData ? '?force=1' : ''}`, { method: 'DELETE' }); state.notice = L('Benutzer gelöscht.','User deleted.'); openSettings('users'); }
    catch (e) { $('#user-error').textContent = e.message; }
  };
}

function credentialProfileModal(profile = {}) {
  const modal = $('#modal');
  modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog modal-scroll">
    <div class="dialogtitle"><div><h3>${profile.id ? 'Zugangsvorlage bearbeiten' : 'Zugangsvorlage hinzufügen'}</h3><p>Secrets werden verschlüsselt gespeichert und niemals wieder über die API ausgegeben.</p></div><button data-close class="iconbutton">×</button></div>
    <div class="formgrid">
      <label>Name<input id="cred-name" value="${esc(profile.name || '')}" placeholder="deploy-prod" autocomplete="off"></label>
      <label>Benutzername<input id="cred-user" value="${esc(profile.username || 'root')}" autocomplete="off"></label>
      <label>Authentifizierung<select id="cred-auth"><option value="password">Passwort</option><option value="keyboard-interactive">Keyboard Interactive</option><option value="key">Private Key</option></select></label>
      <label id="cred-password-label"><span id="cred-password-title">Passwort</span><input id="cred-password" type="password" placeholder="${profile.hasSecret ? 'Gespeichert – leer = beibehalten' : 'Passwort'}" autocomplete="new-password"></label>
      <label id="cred-key-label" class="wide" style="display:none">Private Key<textarea id="cred-key" placeholder="${profile.hasSecret ? 'Gespeichert – leer = beibehalten' : '-----BEGIN OPENSSH PRIVATE KEY-----'}" autocomplete="off" spellcheck="false"></textarea></label>
      <label id="cred-passphrase-label">Key-Passphrase<input id="cred-passphrase" type="password" placeholder="${profile.hasPassphrase ? 'Gespeichert – leer = beibehalten' : 'Optional'}" autocomplete="new-password"></label>
      <label id="cred-cert-label" class="wide">OpenSSH User Certificate<textarea id="cred-cert" placeholder="${profile.hasCertificate ? 'Gespeichert – leer = beibehalten' : 'Optional: ssh-ed25519-cert-v01@openssh.com …'}" spellcheck="false"></textarea></label>
    </div>
    <label class="toggle-row"><span><b>Vorlage teilen</b><small>Für andere ZentSSH-Benutzer zur Auswahl freigeben.</small></span><input id="cred-shared" type="checkbox" ${profile.shared ? 'checked' : ''}></label>
    <div id="cred-error" class="err"></div>
    <div class="actions spread">${profile.id ? '<button id="cred-delete" class="danger">Löschen</button>' : '<span></span>'}<div><button data-cancel>Abbrechen</button><button id="cred-save" class="primary">Speichern</button></div></div>
  </div></div>`;
  $('#cred-auth').value = profile.authType || 'password';
  const sync = () => {
    const isKey = $('#cred-auth').value === 'key';
    $('#cred-password-label').style.display = isKey ? 'none' : '';
    $('#cred-key-label').style.display = isKey ? '' : 'none';
    $('#cred-passphrase-label').style.display = isKey ? '' : 'none';
    $('#cred-cert-label').style.display = isKey ? '' : 'none';
    $('#cred-password-title').textContent = $('#cred-auth').value === 'keyboard-interactive' ? 'Keyboard-Interactive Secret' : 'Passwort';
  };
  $('#cred-auth').onchange = sync;
  sync();
  $('[data-close]', modal).onclick = () => openSettings('credentials');
  $('[data-cancel]', modal).onclick = () => openSettings('credentials');
  $('#cred-save').onclick = async () => {
    const button = $('#cred-save');
    const isKey = $('#cred-auth').value === 'key';
    const body = {
      name: $('#cred-name').value.trim(),
      username: $('#cred-user').value.trim(),
      authType: $('#cred-auth').value,
      secret: isKey ? $('#cred-key').value : $('#cred-password').value,
      passphrase: isKey ? $('#cred-passphrase').value : '',
      certificate: isKey ? $('#cred-cert').value : '',
      shared: $('#cred-shared').checked,
    };
    $('#cred-error').textContent = '';
    setButtonBusy(button, true, 'Speichere…');
    try {
      await api(profile.id ? `/credential-profiles/${profile.id}` : '/credential-profiles', { method: profile.id ? 'PATCH' : 'POST', body: JSON.stringify(body) });
      await loadWorkspace();
      state.notice = profile.id ? 'Zugangsvorlage gespeichert.' : 'Zugangsvorlage angelegt.';
      openSettings('credentials');
    } catch (e) {
      $('#cred-error').textContent = e.message;
      setButtonBusy(button, false);
    }
  };
  if (profile.id) $('#cred-delete').onclick = async () => {
    if (!confirm(`Zugangsvorlage „${profile.name}“ wirklich löschen?`)) return;
    try {
      await api(`/credential-profiles/${profile.id}`, { method: 'DELETE' });
      await loadWorkspace();
      state.notice = 'Zugangsvorlage gelöscht.';
      openSettings('credentials');
    } catch (e) { $('#cred-error').textContent = e.message; }
  };
}

async function ensureServerReady(serverId) {
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      await api(`/servers/${serverId}/connect-check`, { method: 'POST' });
      return true;
    } catch (e) {
      const d = e.data || {};
      if (e.status !== 409 || !['host_key_required', 'host_key_changed'].includes(d.code)) throw e;
      const accepted = await confirmHostKey(d);
      if (!accepted) throw new Error('cancelled');
      await api(`/servers/${d.serverId}/trust-host-key`, { method: 'POST', body: JSON.stringify({ fingerprint: d.actual?.fingerprint, replace: d.code === 'host_key_changed' }) });
    }
  }
  throw new Error('Host-Key-Vertrauen konnte nicht abgeschlossen werden.');
}

function confirmHostKey(info) {
  return new Promise(resolve => {
    const modal = $('#modal');
    const changed = info.code === 'host_key_changed';
    const layer = document.createElement('div');
    layer.className = 'backdrop hostkey-backdrop';
    layer.innerHTML = `<div class="dialog hostkeydialog">
      <div class="fingerprinticon ${changed ? 'dangericon' : ''}">${changed ? '!' : '✓'}</div>
      <h3>${changed ? 'SSH Host Key hat sich geändert' : 'Unbekannter SSH Host Key'}</h3>
      <p>${changed ? 'Die Identität dieses Servers stimmt nicht mehr mit dem gespeicherten Key überein. Prüfe den Fingerprint außerhalb von ZentSSH, bevor du ihn ersetzt.' : 'Prüfe den Fingerprint mit einer vertrauenswürdigen Quelle, bevor du diesem Server vertraust.'}</p>
      <div class="fingerprintbox"><small>${esc(info.server || '')} · ${esc(info.host || '')}:${info.port || 22}</small><code>${esc(info.actual?.fingerprint || '')}</code><span>${esc(info.actual?.algorithm || '')}</span></div>
      ${changed && info.expected ? `<div class="oldfingerprint"><small>Bisher vertraut</small><code>${esc(info.expected.fingerprint || '')}</code></div>` : ''}
      <div class="actions"><button class="hostkey-cancel" data-cancel>Abbrechen</button><button class="hostkey-trust ${changed ? 'danger' : 'primary'}">${changed ? 'Neuen Key ausdrücklich vertrauen' : 'Diesem Key vertrauen'}</button></div>
    </div>`;
    modal.append(layer);
    const finish = accepted => { layer.remove(); resolve(accepted); };
    $('.hostkey-cancel', layer).onclick = () => finish(false);
    $('.hostkey-trust', layer).onclick = () => finish(true);
    scheduleModalAutofocus(modal);
  });
}

function oidcProviderModal(provider = {}) {
  const modal = $('#modal');
  const callback = `${location.origin}${A}/auth/oidc/callback`;
  const directLoginURL = provider.ssoId ? `${location.origin}/?sso=${encodeURIComponent(provider.ssoId)}` : '';
  modal.innerHTML = `<div class="backdrop"><div class="dialog oidcdialog">
    <div class="dialogtitle"><div><h3>${provider.id ? L('OIDC-Provider bearbeiten','Edit OIDC provider') : L('OIDC-Provider hinzufügen','Add OIDC provider')}</h3>${provider.ssoId ? `<small class="oidc-modal-sso-id">${L('SSO-ID','SSO ID')}: <code>${esc(provider.ssoId)}</code></small>` : `<small class="oidc-modal-sso-id muted">${L('Die SSO-ID wird beim Speichern automatisch erzeugt.','The SSO ID is generated automatically when saved.')}</small>`}<p>${L('Discovery, PKCE, State/Nonce und ID-Token-Signaturprüfung sind automatisch aktiv.','Discovery, PKCE, state/nonce and ID-token signature validation are enabled automatically.')}</p></div><button data-close class="iconbutton">×</button></div>
    <div class="formgrid">
      <label>${L('Name','Name')}<input id="oidc-name" value="${esc(provider.name || '')}" placeholder="Authentik" autocomplete="off"></label>
      <label class="wide">Issuer URL<input id="oidc-issuer" value="${esc(provider.issuerUrl || '')}" placeholder="https://auth.example.com/application/o/zentssh/" autocomplete="off"></label>
      <label>Client ID<input id="oidc-client" value="${esc(provider.clientId || '')}" autocomplete="off"></label>
      <label>Client Secret<input id="oidc-secret" type="password" placeholder="${provider.hasClientSecret ? L('Gespeichert – leer lassen zum Beibehalten','Stored – leave empty to keep') : L('Optional bei Public Client','Optional for public client')}" autocomplete="new-password"></label>
      <label class="wide">Redirect URL<input id="oidc-redirect" value="${esc(provider.redirectUrl || callback)}" autocomplete="off"></label>
      <label class="wide">Scopes<input id="oidc-scopes" value="${esc(provider.scopes || 'openid email profile')}" autocomplete="off"></label>
      <label>Token Auth<select id="oidc-auth"><option value="client_secret_basic">client_secret_basic</option><option value="client_secret_post">client_secret_post</option><option value="none">none / Public Client</option></select></label>
      <label>${L('Gruppen-Claim','Group claim')}<input id="oidc-groups" value="${esc(provider.groupClaim || 'groups')}" autocomplete="off"></label>
      <label>${L('Erforderliche Gruppe','Required group')}<input id="oidc-required-group" value="${esc(provider.requiredGroup || '')}" placeholder="${esc(L('Optional, z. B. zentssh-users','Optional, e.g. zentssh-users'))}" autocomplete="off"></label>
      <label>${L('Admin-Gruppe für neue Nutzer','Admin group for new users')}<input id="oidc-admin-group" value="${esc(provider.adminGroup || '')}" placeholder="${esc(L('Optional, z. B. zentssh-admins','Optional, e.g. zentssh-admins'))}" autocomplete="off"></label>
    </div>
    <div class="checkrow"><label><input id="oidc-enabled" type="checkbox" ${provider.id ? (provider.enabled ? 'checked' : '') : 'checked'}> ${L('Provider aktiv','Provider active')}</label><label><input id="oidc-autocreate" type="checkbox" ${provider.id ? (provider.autoCreate ? 'checked' : '') : 'checked'}> ${L('ZentSSH-Benutzer beim ersten SSO-Login automatisch anlegen','Automatically create ZentSSH users on first SSO sign-in')}</label></div>
    <div class="securitynote"><b>${L('Sicheres Account-Mapping:','Secure account mapping:')}</b> ${L('Bestehende lokale Accounts werden nie automatisch nur anhand derselben E-Mail übernommen. Der Benutzer muss SSO nach lokalem Login explizit verknüpfen.','Existing local accounts are never auto-linked solely because the email matches. The user must explicitly link SSO after a local sign-in.')}</div>
    ${directLoginURL ? `<div class="securitynote oidc-direct-login"><div><b>${L('Direkter SSO-Login','Direct SSO sign-in')}</b><p>${L('Mit dieser URL wird die E-Mail-Abfrage übersprungen und dieser Provider direkt gestartet. Ideal als Launch-URL im SSO-Portal.','This URL skips the email step and starts this provider directly. It is ideal as the launch URL in your SSO portal.')}</p></div><div class="oidc-direct-url"><code>${esc(directLoginURL)}</code><button id="oidc-copy-direct" type="button" class="settings-row-button">${iconLabel('copy', L('Kopieren','Copy'))}</button></div></div>` : ''}
    <div id="oidc-status" class="err"></div>
    <div class="actions spread">${provider.id ? `<button id="oidc-delete" class="danger">${L('Löschen','Delete')}</button>` : '<span></span>'}<div><button id="oidc-test">${L('Verbindung testen','Test connection')}</button><button id="oidc-save" class="primary">${L('Speichern','Save')}</button></div></div>
  </div></div>`;
  $('#oidc-auth').value = provider.tokenAuthMethod || 'client_secret_basic';
  $('[data-close]', modal).onclick = () => openSettings('providers');
  const body = () => ({
    name: $('#oidc-name').value.trim(), issuerUrl: $('#oidc-issuer').value.trim(), clientId: $('#oidc-client').value.trim(), clientSecret: $('#oidc-secret').value,
    redirectUrl: $('#oidc-redirect').value.trim(), scopes: $('#oidc-scopes').value.trim(), groupClaim: $('#oidc-groups').value.trim(),
    requiredGroup: $('#oidc-required-group').value.trim(), adminGroup: $('#oidc-admin-group').value.trim(), tokenAuthMethod: $('#oidc-auth').value,
    enabled: $('#oidc-enabled').checked, autoCreate: $('#oidc-autocreate').checked,
  });
  if ($('#oidc-copy-direct')) $('#oidc-copy-direct').onclick = async () => {
    const button = $('#oidc-copy-direct');
    try {
      await navigator.clipboard.writeText(directLoginURL);
      showToast(L('Direktlink kopiert.','Direct sign-in link copied.'));
    } catch {
      showToast(L('Direktlink konnte nicht kopiert werden.','Could not copy direct sign-in link.'), true);
    }
    button?.focus();
  };
  $('#oidc-test').onclick = async () => {
    const status = $('#oidc-status');
    status.className = 'err'; status.textContent = L('Prüfe Discovery und JWKS …','Checking discovery and JWKS …');
    try {
      const result = await api('/admin/oidc/test', { method: 'POST', body: JSON.stringify({ issuerUrl: $('#oidc-issuer').value.trim() }) });
      status.className = 'oktext';
      status.textContent = L(`Verbindung OK · ${result.keyCount} Signaturschlüssel gefunden.`,`Connection OK · ${result.keyCount} signing keys found.`);
    } catch (e) { status.className = 'err'; status.textContent = e.message; }
  };
  $('#oidc-save').onclick = async () => {
    const status = $('#oidc-status');
    status.textContent = '';
    const save = $('#oidc-save');
    setButtonBusy(save, true, L('Speichere…','Saving…'));
    try {
      const saved = await api(provider.id ? `/admin/oidc/providers/${provider.id}` : '/admin/oidc/providers', { method: provider.id ? 'PATCH' : 'POST', body: JSON.stringify(body()) });
      if (provider.id) {
        state.notice = L('SSO-Provider gespeichert.','SSO provider saved.');
        openSettings('providers');
      } else {
        showToast(L('SSO-Provider angelegt.','SSO provider created.'));
        oidcProviderModal(saved);
      }
    } catch (e) {
      status.className = 'err'; status.textContent = e.message;
      setButtonBusy(save, false);
    }
  };
  if (provider.id) $('#oidc-delete').onclick = async () => {
    if (!confirm(L(`OIDC-Provider „${provider.name}“ wirklich löschen?`,`Really delete OIDC provider “${provider.name}”?`))) return;
    try { await api(`/admin/oidc/providers/${provider.id}`, { method: 'DELETE' }); state.notice = L('SSO-Provider gelöscht.','SSO provider deleted.'); openSettings('providers'); }
    catch (e) { $('#oidc-status').textContent = e.message; }
  };
  scheduleModalAutofocus(modal);
}

function showToast(message, error = false) {
  let toast = $('#toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    document.body.appendChild(toast);
  }
  toast.className = `toast ${error ? 'toast-error' : ''}`;
  toast.textContent = uiLanguage() === 'en' ? staticEnglishText(message) : message;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.remove(), 4500);
}

function parent(path) {
  if (!path || path === '.' || path === '/') return path;
  const parts = path.split('/').filter(Boolean);
  parts.pop();
  return path.startsWith('/') ? '/' + parts.join('/') : (parts.join('/') || '.');
}

function fmtSize(n) {
  let value = Number(n || 0);
  for (const unit of ['B', 'KB', 'MB', 'GB', 'TB']) {
    if (value < 1024) return `${value.toFixed(value < 10 ? 1 : 0)} ${unit}`;
    value /= 1024;
  }
  return value.toFixed(1) + ' PB';
}

boot().catch(e => { app.innerHTML = `<pre>${esc(e.stack || e.message)}</pre>`; });
