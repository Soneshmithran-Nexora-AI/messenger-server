'use strict';
/*
  Messaging server: accounts, contacts, messages between people, voice-call signaling.

  Privacy design
  - Every route checks who is asking. People only ever receive their own data and the parts
    of other people's profiles that those people's privacy settings allow.
  - Message text, saved contact names and "about" text are encrypted at rest (AES-256-GCM)
    with a key that lives outside the database (DATA_KEY, or a key file next to it).
  - Passwords are salted scrypt hashes. Session tokens are stored only as SHA-256 hashes.
  - Deleting an account removes the person's rows for good: SQLite runs with secure_delete
    and the write-ahead log is truncated right after.
  - Message bodies are never written to logs.

  No dependencies. Needs Node 22.13 or newer (built-in SQLite).

  Run:   node server.js
  Env:   PORT (3000), DB_FILE (./accounts.db), COOKIE_SECURE=1 behind HTTPS,
         DATA_KEY (base64, 32 bytes) or KEY_FILE (default: DB_FILE + ".key"),
         ICE_SERVERS (JSON array for voice calls, default: a public STUN server),
         RATE_MULTIPLIER (raise the rate limits, handy for load tests)
*/
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'accounts.db');
const SECURE = process.env.COOKIE_SECURE === '1';
const PAGE = path.join(__dirname, 'public', 'index.html');
const RATE_MULT = Number(process.env.RATE_MULTIPLIER) || 1;
const LONG_SESSION_MS = 30 * 24 * 3600 * 1000;
const SHORT_SESSION_MS = 12 * 3600 * 1000;

/* ---------- encryption at rest ---------- */
function loadKey() {
  if (process.env.DATA_KEY) {
    const k = Buffer.from(process.env.DATA_KEY, 'base64');
    if (k.length !== 32) throw new Error('DATA_KEY must be 32 bytes, base64 encoded.');
    return k;
  }
  const file = process.env.KEY_FILE || DB_FILE + '.key';
  try {
    const k = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64');
    if (k.length === 32) return k;
    throw new Error(`The key file ${file} is not a 32 byte base64 key.`);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  if (fs.existsSync(DB_FILE) && fs.statSync(DB_FILE).size > 0) {
    const has = (() => { try { const d = new DatabaseSync(DB_FILE, { readOnly: true }); const r = d.prepare("SELECT name FROM sqlite_master WHERE name = 'msgs'").get(); d.close(); return !!r; } catch { return false; } })();
    if (has) throw new Error(`No encryption key found for ${DB_FILE}. Restore the key file (${file}) or set DATA_KEY. Starting without it would make saved messages unreadable.`);
  }
  const k = crypto.randomBytes(32);
  fs.writeFileSync(file, k.toString('base64') + '\n', { mode: 0o600 });
  return k;
}
const KEY = loadKey();
function seal(s) {
  if (s === null || s === undefined) return null;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([c.update(String(s), 'utf8'), c.final()]);
  return 'e1:' + Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64');
}
function unseal(v) {
  if (v === null || v === undefined) return '';
  if (typeof v !== 'string' || !v.startsWith('e1:')) return String(v);
  try {
    const b = Buffer.from(v.slice(3), 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', KEY, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
  } catch { return ''; }
}

/* ---------- database ---------- */
const db = new DatabaseSync(DB_FILE);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA secure_delete = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL UNIQUE,
    phone_national TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    avatar TEXT,
    handle TEXT,
    about TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    status_at INTEGER,
    privacy TEXT,
    last_seen INTEGER
  );
  CREATE INDEX IF NOT EXISTS users_national ON users (phone_national);
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
`);
/* databases from earlier versions get the new columns, and everyone gets an @ID */
{
  const have = new Set(db.prepare('PRAGMA table_info(users)').all().map((c) => c.name));
  const add = [['avatar', 'TEXT'], ['handle', 'TEXT'], ['about', 'TEXT'], ['status', "TEXT NOT NULL DEFAULT 'active'"], ['status_at', 'INTEGER'], ['privacy', 'TEXT'], ['last_seen', 'INTEGER']];
  for (const [col, ddl] of add) if (!have.has(col)) db.exec(`ALTER TABLE users ADD COLUMN ${col} ${ddl}`);
}
db.exec(`
  CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    saved_name TEXT NOT NULL,
    via_number INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE UNIQUE INDEX IF NOT EXISTS contacts_owner_user ON contacts (owner_id, user_id) WHERE user_id IS NOT NULL;
  CREATE INDEX IF NOT EXISTS contacts_user ON contacts (user_id);
  CREATE TABLE IF NOT EXISTS blocks (
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (owner_id, blocked_id)
  );
  CREATE TABLE IF NOT EXISTS convs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    a INTEGER REFERENCES users(id) ON DELETE SET NULL,
    b INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    a_visible INTEGER NOT NULL DEFAULT 1,
    b_visible INTEGER NOT NULL DEFAULT 0,
    a_cleared INTEGER NOT NULL DEFAULT 0,
    b_cleared INTEGER NOT NULL DEFAULT 0,
    a_read INTEGER NOT NULL DEFAULT 0,
    b_read INTEGER NOT NULL DEFAULT 0
  );
  CREATE UNIQUE INDEX IF NOT EXISTS convs_pair ON convs (a, b);
  CREATE INDEX IF NOT EXISTS convs_b ON convs (b);
  CREATE TABLE IF NOT EXISTS msgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conv_id INTEGER NOT NULL REFERENCES convs(id) ON DELETE CASCADE,
    sender INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL DEFAULT 'text',
    body TEXT,
    ai INTEGER NOT NULL DEFAULT 0,
    undelivered INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS msgs_conv ON msgs (conv_id, id);
  CREATE INDEX IF NOT EXISTS msgs_sender ON msgs (sender);
`);

const RESERVED = new Set(['admin', 'administrator', 'support', 'help', 'root', 'system', 'staff', 'moderator', 'about', 'privacy', 'settings', 'null', 'undefined', 'me', 'you', 'everyone', 'official']);
const HANDLE_RE = /^[a-z][a-z0-9_]{2,23}$/;
const cleanHandle = (v) => String(v || '').trim().replace(/^@/, '').toLowerCase();
const handleProblem = (h) => (!HANDLE_RE.test(h) ? 'Use 3 to 24 letters, numbers or underscores, starting with a letter.' : RESERVED.has(h) ? 'That @ID is reserved. Choose another.' : '');

const q = {
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  userByHandle: db.prepare('SELECT * FROM users WHERE handle = ?'),
  userByPhone: db.prepare('SELECT * FROM users WHERE phone = ?'),
  handleTaken: db.prepare('SELECT id FROM users WHERE handle = ?'),
  insertUser: db.prepare('INSERT INTO users (name, email, phone, phone_national, pw_hash, created_at, avatar, handle, status, status_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  updateProfile: db.prepare('UPDATE users SET name = ?, avatar = ?, about = ?, handle = ? WHERE id = ?'),
  updatePrivacy: db.prepare('UPDATE users SET privacy = ? WHERE id = ?'),
  updateStatus: db.prepare('UPDATE users SET status = ?, status_at = ? WHERE id = ?'),
  touchSeen: db.prepare('UPDATE users SET last_seen = ? WHERE id = ?'),
  deleteUser: db.prepare('DELETE FROM users WHERE id = ?'),
  findLogin: db.prepare('SELECT * FROM users WHERE email = ? OR phone = ? OR phone_national = ?'),
  insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)'),
  sessionUser: db.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  purgeSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
  countSessions: db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND expires_at > ?'),

  contactsOf: db.prepare('SELECT * FROM contacts WHERE owner_id = ?'),
  contactOf: db.prepare('SELECT * FROM contacts WHERE owner_id = ? AND user_id = ?'),
  contactById: db.prepare('SELECT * FROM contacts WHERE id = ? AND owner_id = ?'),
  insertContact: db.prepare('INSERT INTO contacts (owner_id, user_id, saved_name, via_number, created_at) VALUES (?, ?, ?, ?, ?)'),
  renameContact: db.prepare('UPDATE contacts SET saved_name = ? WHERE id = ?'),
  deleteContact: db.prepare('DELETE FROM contacts WHERE id = ?'),
  countContacts: db.prepare('SELECT COUNT(*) AS n FROM contacts WHERE owner_id = ?'),
  savedBy: db.prepare('SELECT DISTINCT owner_id AS id FROM contacts WHERE user_id = ?'),

  isBlocked: db.prepare('SELECT 1 AS x FROM blocks WHERE owner_id = ? AND blocked_id = ?'),
  insertBlock: db.prepare('INSERT OR IGNORE INTO blocks (owner_id, blocked_id, created_at) VALUES (?, ?, ?)'),
  deleteBlock: db.prepare('DELETE FROM blocks WHERE owner_id = ? AND blocked_id = ?'),
  blocksOf: db.prepare('SELECT * FROM blocks WHERE owner_id = ? ORDER BY created_at DESC'),

  convById: db.prepare('SELECT * FROM convs WHERE id = ?'),
  convPair: db.prepare('SELECT * FROM convs WHERE a = ? AND b = ?'),
  insertConv: db.prepare('INSERT INTO convs (a, b, created_at, updated_at, a_visible, b_visible) VALUES (?, ?, ?, ?, ?, ?)'),
  convsOf: db.prepare('SELECT * FROM convs WHERE (a = ? AND a_visible = 1) OR (b = ? AND b_visible = 1)'),
  convsAll: db.prepare('SELECT * FROM convs WHERE a = ? OR b = ?'),
  touchConv: db.prepare('UPDATE convs SET updated_at = ? WHERE id = ?'),
  deleteConv: db.prepare('DELETE FROM convs WHERE id = ?'),
  cleanupConvs: db.prepare('DELETE FROM convs WHERE (a IS NULL AND b IS NULL) OR NOT EXISTS (SELECT 1 FROM msgs WHERE msgs.conv_id = convs.id)'),

  insertMsg: db.prepare('INSERT INTO msgs (conv_id, sender, kind, body, ai, undelivered, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  listMsgs: db.prepare('SELECT * FROM msgs WHERE conv_id = ? AND id > ? AND (undelivered = 0 OR sender = ?) ORDER BY id DESC LIMIT 500'),
  allMsgs: db.prepare('SELECT * FROM msgs WHERE conv_id = ? AND id > ? AND (undelivered = 0 OR sender = ?) ORDER BY id'),
  lastMsg: db.prepare('SELECT * FROM msgs WHERE conv_id = ? AND id > ? AND (undelivered = 0 OR sender = ?) ORDER BY id DESC LIMIT 1'),
  unread: db.prepare('SELECT COUNT(*) AS n FROM msgs WHERE conv_id = ? AND id > ? AND sender <> ? AND undelivered = 0'),
  maxMsg: db.prepare('SELECT COALESCE(MAX(id), 0) AS m FROM msgs WHERE conv_id = ?'),
  purgeMsgs: db.prepare('DELETE FROM msgs WHERE conv_id = ? AND id <= ?'),
  purgeUndelivered: db.prepare('DELETE FROM msgs WHERE conv_id = ? AND sender = ? AND undelivered = 1 AND id <= ?'),
  countMsgs: db.prepare('SELECT COUNT(*) AS n FROM msgs WHERE conv_id = ?'),
  sentCount: db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(body)), 0) AS bytes FROM msgs WHERE sender = ? AND kind = 'text'"),
  receivedCount: db.prepare(`SELECT COUNT(*) AS n FROM msgs m JOIN convs c ON c.id = m.conv_id
    WHERE m.sender <> ? AND m.kind = 'text' AND m.undelivered = 0 AND ((c.a = ? AND m.id > c.a_cleared) OR (c.b = ? AND m.id > c.b_cleared))`),
  callCount: db.prepare(`SELECT COUNT(*) AS n FROM msgs m JOIN convs c ON c.id = m.conv_id
    WHERE m.kind = 'call' AND ((c.a = ? AND m.id > c.a_cleared) OR (c.b = ? AND m.id > c.b_cleared))`),
  convCount: db.prepare('SELECT COUNT(*) AS n FROM convs WHERE (a = ? AND a_visible = 1) OR (b = ? AND b_visible = 1)'),
  contactBytes: db.prepare('SELECT COALESCE(SUM(LENGTH(saved_name)), 0) AS bytes FROM contacts WHERE owner_id = ?')
};
const sideStmts = {};
function sideStmt(kind, side) {
  const key = kind + side;
  if (!sideStmts[key]) {
    const col = { visible: `${side}_visible`, cleared: `${side}_cleared`, read: `${side}_read` }[kind];
    if (!col) throw new Error('bad side statement');
    sideStmts[key] = db.prepare(`UPDATE convs SET ${col} = ? WHERE id = ?`);
  }
  return sideStmts[key];
}
function tx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { try { db.exec('ROLLBACK'); } catch { /* already closed */ } throw e; }
}

/* ---------- @IDs ---------- */
function suggestHandle(name) {
  let base = String(name || '').toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 18);
  if (!base) base = 'user';
  if (!/^[a-z]/.test(base)) base = 'u' + base;
  while (base.length < 3) base += '_';
  if (RESERVED.has(base)) base += '_1';
  if (!q.handleTaken.get(base)) return base;
  for (let i = 0; i < 40; i++) {
    const h = base.slice(0, 20) + '_' + (10 + crypto.randomInt(990));
    if (!q.handleTaken.get(h)) return h;
  }
  return base.slice(0, 12) + '_' + crypto.randomBytes(4).toString('hex');
}
tx(() => {
  const upd = db.prepare('UPDATE users SET handle = ? WHERE id = ?');
  for (const u of db.prepare('SELECT id, name FROM users WHERE handle IS NULL ORDER BY id').all()) upd.run(suggestHandle(u.name), u.id);
});
db.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_handle ON users (handle)');

/* ---------- privacy settings ---------- */
const PRIVACY_DEFAULTS = { profile: 'saved_me', find: 'everyone', message: 'everyone', call: 'everyone', lastSeen: 'saved_me' };
const PRIVACY_OPTIONS = {
  profile: ['everyone', 'saved_me', 'nobody'],
  find: ['everyone', 'nobody'],
  message: ['everyone', 'my_contacts'],
  call: ['everyone', 'my_contacts', 'nobody'],
  lastSeen: ['everyone', 'saved_me', 'nobody']
};
function privacyOf(u) {
  let saved = {};
  try { saved = JSON.parse(u.privacy || '{}') || {}; } catch { saved = {}; }
  const out = {};
  for (const k of Object.keys(PRIVACY_DEFAULTS)) out[k] = PRIVACY_OPTIONS[k].includes(saved[k]) ? saved[k] : PRIVACY_DEFAULTS[k];
  return out;
}
/* "saved_me" = the person looking has saved this person's number */
const allows = (rule, viewerSavedThem) => rule === 'everyone' || (rule === 'saved_me' && viewerSavedThem);

const selfView = (u) => ({
  id: u.id, handle: u.handle, name: u.name, email: u.email, phone: u.phone, avatar: u.avatar || '', about: unseal(u.about),
  createdAt: u.created_at, status: u.status || 'active', statusAt: u.status_at || null, privacy: privacyOf(u)
});

/* ---------- live connections (server-sent events) ---------- */
const clients = new Map();
const isOnline = (id) => (clients.get(id) ? clients.get(id).size : 0) > 0;
function push(userId, type, data) {
  const set = clients.get(userId);
  if (!set) return;
  const payload = `data: ${JSON.stringify({ type, ...(data || {}) })}\n\n`;
  for (const r of set) { try { r.write(payload); } catch { /* connection is closing */ } }
}
function related(userId) {
  const ids = new Set();
  for (const r of q.savedBy.all(userId)) ids.add(r.id);
  for (const c of q.convsAll.all(userId, userId)) { const o = c.a === userId ? c.b : c.a; if (o) ids.add(o); }
  ids.delete(userId);
  return ids;
}
const refreshRelated = (userId) => { for (const id of related(userId)) push(id, 'refresh'); push(userId, 'refresh'); };
setInterval(() => { for (const set of clients.values()) for (const r of set) { try { r.write(': ping\n\n'); } catch { /* closing */ } } }, 20000).unref();

/* ---------- passwords and sessions ---------- */
const scrypt = (pw, salt) => new Promise((resolve, reject) => {
  crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (e, key) => (e ? reject(e) : resolve(key)));
});
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(pw, salt);
  return `scrypt$${salt.toString('base64')}$${key.toString('base64')}`;
}
async function verifyPassword(pw, stored) {
  const [kind, salt, hash] = String(stored).split('$');
  if (kind !== 'scrypt' || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64');
  const actual = await scrypt(pw, Buffer.from(salt, 'base64'));
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}
const DUMMY_HASH = `scrypt$${crypto.randomBytes(16).toString('base64')}$${crypto.randomBytes(64).toString('base64')}`;
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
function cookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}
function sessionCookie(token, maxAgeSec) {
  let c = `sid=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/`;
  if (maxAgeSec !== null) c += `; Max-Age=${maxAgeSec}`;
  if (SECURE) c += '; Secure';
  return c;
}
function startSession(res, userId, remember) {
  const now = Date.now();
  q.purgeSessions.run(now);
  const token = crypto.randomBytes(32).toString('base64url');
  q.insertSession.run(sha256(token), userId, now + (remember ? LONG_SESSION_MS : SHORT_SESSION_MS));
  res.setHeader('Set-Cookie', sessionCookie(token, remember ? LONG_SESSION_MS / 1000 : null));
}
const currentUser = (req) => { const t = cookies(req).sid; return t ? q.sessionUser.get(sha256(t), Date.now()) || null : null; };

/* ---------- rate limits ---------- */
const buckets = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  let h = buckets.get(key);
  if (!h || h.reset < now) { h = { n: 0, reset: now + windowMs }; buckets.set(key, h); }
  h.n += 1;
  return h.n > max * RATE_MULT;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of buckets) if (v.reset < now) buckets.delete(k); }, 60 * 1000).unref();
/* behind a reverse proxy (Caddy, nginx, a host's load balancer) set TRUST_PROXY=1 so rate limits count each visitor, not the proxy */
const ipOf = (req) => (process.env.TRUST_PROXY === '1' && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || 'x';

/* ---------- http helpers ---------- */
function send(res, status, body, extra) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...(extra || {}) });
  res.end(data);
}
const fail = (status, error, code) => Object.assign(new Error(error), { status, code });
function readJson(req, limit = 10 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(fail(413, 'Request too large.')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { const j = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); resolve(j && typeof j === 'object' && !Array.isArray(j) ? j : {}); } catch { reject(fail(400, 'Invalid request.')); } });
    req.on('error', reject);
  });
}
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}
const str = (v, max) => (typeof v === 'string' && v.length <= max ? v : '');
const AVATAR_BODY = 400 * 1024;
const AVATAR_RE = /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
const cleanAvatar = (v) => (typeof v === 'string' && v.length <= 300000 && AVATAR_RE.test(v) ? v : null);
const AVATAR_ERROR = 'That photo could not be saved. Try a smaller image.';
const cleanName = (v) => str(v, 80).trim().replace(/\s+/g, ' ');
const cleanSaved = (v) => str(v, 60).trim().replace(/\s+/g, ' ');

/* ---------- how one person sees another ---------- */
function peerView(viewerId, p, contact) {
  if (!p) {
    const sn = contact ? unseal(contact.saved_name) : '';
    return { handle: '', displayName: sn || 'Deleted account', savedName: sn, saved: !!contact, contactId: contact ? contact.id : null, status: 'deleted', name: '', avatar: '', about: '', phone: '', online: null, lastSeen: null, blocked: false };
  }
  const c = contact === undefined ? q.contactOf.get(viewerId, p.id) : contact;
  const saved = !!c;
  const priv = privacyOf(p);
  const theyBlockedMe = !!q.isBlocked.get(p.id, viewerId);
  const active = p.status !== 'deactivated';
  const showProfile = active && !theyBlockedMe && allows(priv.profile, saved);
  const showSeen = p.status === 'active' && !theyBlockedMe && allows(priv.lastSeen, saved);
  const savedName = c ? unseal(c.saved_name) : '';
  const profileName = showProfile ? p.name : '';
  return {
    handle: p.handle, displayName: savedName || profileName || '@' + p.handle, savedName, saved, contactId: c ? c.id : null,
    status: active ? 'active' : 'unavailable', name: profileName, avatar: showProfile ? (p.avatar || '') : '', about: showProfile ? unseal(p.about) : '',
    phone: c && c.via_number && active ? p.phone : '', online: showSeen ? isOnline(p.id) : null, lastSeen: showSeen ? (p.last_seen || null) : null,
    blocked: !!q.isBlocked.get(viewerId, p.id)
  };
}

/* ---------- conversations ---------- */
const sideOf = (c, uid) => (c.a === uid ? 'a' : c.b === uid ? 'b' : null);
const peerIdOf = (c, uid) => (c.a === uid ? c.b : c.a);
function ownConv(uid, id) {
  const c = q.convById.get(id);
  return c && sideOf(c, uid) ? c : null;
}
function msgPreview(m) {
  if (!m) return '';
  if (m.kind === 'call') { try { const j = JSON.parse(unseal(m.body)); return j.status === 'completed' ? 'Voice call' : 'Missed call'; } catch { return 'Voice call'; } }
  return unseal(m.body).slice(0, 90);
}
function convView(c, uid) {
  const side = sideOf(c, uid);
  const cleared = c[side + '_cleared'], read = c[side + '_read'];
  const pid = peerIdOf(c, uid);
  const last = q.lastMsg.get(c.id, cleared, uid);
  return {
    id: c.id, peer: peerView(uid, pid ? q.userById.get(pid) : null), preview: msgPreview(last), lastAt: last ? last.created_at : c.updated_at,
    lastMine: !!(last && last.sender === uid), unread: q.unread.get(c.id, Math.max(read, cleared), uid).n
  };
}
function msgView(m, uid) {
  const base = { id: m.id, mine: m.sender === uid, kind: m.kind, createdAt: m.created_at };
  if (m.kind === 'call') {
    let j = {}; try { j = JSON.parse(unseal(m.body)); } catch { j = {}; }
    return { ...base, call: { status: j.status || 'missed', duration: j.duration || 0 } };
  }
  return { ...base, text: unseal(m.body), ai: !!m.ai };
}
function purgeConv(convId) {
  const c = q.convById.get(convId);
  if (!c) return;
  const th = [];
  if (c.a !== null) th.push(c.a_cleared);
  if (c.b !== null) th.push(c.b_cleared);
  if (th.length) q.purgeMsgs.run(convId, Math.min(...th));
  const left = q.countMsgs.get(convId).n;
  const seen = (c.a !== null && c.a_visible) || (c.b !== null && c.b_visible);
  if (!left && !seen) q.deleteConv.run(convId);
}
function convFor(uid, peerId, create) {
  const a = Math.min(uid, peerId), b = Math.max(uid, peerId);
  let c = q.convPair.get(a, b);
  if (!c && create) {
    const now = Date.now();
    q.insertConv.run(a, b, now, now, a === uid ? 1 : 0, b === uid ? 1 : 0);
    c = q.convPair.get(a, b);
  } else if (c && create && !c[sideOf(c, uid) + '_visible']) {
    sideStmt('visible', sideOf(c, uid)).run(1, c.id);
    c = q.convById.get(c.id);
  }
  return c;
}
function canSendTo(uid, peer) {
  if (!peer) return { ok: false, reason: 'This account no longer exists.' };
  if (q.isBlocked.get(uid, peer.id)) return { ok: false, reason: 'You blocked this contact. Unblock them to send messages.' };
  if (peer.status === 'deactivated') return { ok: false, reason: 'This person is unavailable right now.' };
  return { ok: true };
}
/* can this person reach that person? (messages and calls are dropped quietly when they cannot) */
function reachable(fromId, to, kind) {
  if (q.isBlocked.get(to.id, fromId)) return false;
  if (to.status === 'deactivated') return false;
  const rule = privacyOf(to)[kind];
  if (rule === 'nobody') return false;
  if (rule === 'my_contacts' && !q.contactOf.get(to.id, fromId)) return false;
  return true;
}

/* ---------- voice calls (signaling only: the audio goes directly between the two browsers) ---------- */
const calls = new Map();
const RING_MS = 40000;
const busyCall = (uid) => { for (const c of calls.values()) if (c.state !== 'ended' && (c.caller === uid || c.callee === uid)) return c; return null; };
function logCall(convId, callerId, status, duration, deliverToCallee) {
  const conv = q.convById.get(convId);
  if (!conv) return;
  const now = Date.now();
  q.insertMsg.run(convId, callerId, 'call', seal(JSON.stringify({ status, duration })), 0, 0, now);
  q.touchConv.run(now, convId);
  const calleeId = peerIdOf(conv, callerId);
  if (deliverToCallee && calleeId) sideStmt('visible', sideOf(conv, calleeId)).run(1, convId);
  sideStmt('visible', sideOf(conv, callerId)).run(1, convId);
  push(callerId, 'msg', { convId });
  if (calleeId) push(calleeId, 'msg', { convId });
}
function finishCall(call, status, by) {
  if (call.state === 'ended') return;
  clearTimeout(call.timer);
  call.state = 'ended';
  const duration = call.answeredAt ? Math.max(0, Math.round((Date.now() - call.answeredAt) / 1000)) : 0;
  const final = call.answeredAt && status !== 'declined' ? 'completed' : status;
  try { logCall(call.convId, call.caller, final, duration, true); } catch { /* the conversation was removed */ }
  const ev = { callId: call.id, status: final, by, duration };
  push(call.caller, 'call', { kind: 'ended', ...ev });
  push(call.callee, 'call', { kind: 'ended', ...ev });
  setTimeout(() => calls.delete(call.id), 30000).unref();
}
function endCallsOf(uid, status) { for (const c of calls.values()) if (c.state !== 'ended' && (c.caller === uid || c.callee === uid)) finishCall(c, status || 'missed', 'system'); }
function iceServers() {
  try { const v = JSON.parse(process.env.ICE_SERVERS || ''); if (Array.isArray(v)) return v; } catch { /* use the default */ }
  return [{ urls: 'stun:stun.l.google.com:19302' }];
}

/* ---------- routes ---------- */
const routes = [];
const route = (method, pattern, opts, fn) => routes.push({ method, re: new RegExp('^' + pattern + '$'), opts, fn });
const ok = (res, body, status) => send(res, status || 200, body);

/* sign up, log in, log out */
route('POST', '/api/register', { auth: false }, async ({ req, res }) => {
  if (limited('auth:' + ipOf(req), 20, 15 * 60 * 1000)) throw fail(429, 'Too many attempts. Please wait a few minutes and try again.');
  const b = await readJson(req, AVATAR_BODY);
  const name = cleanName(b.name);
  const email = str(b.email, 254).trim().toLowerCase();
  const cc = str(b.countryCode, 5);
  const national = str(b.phone, 20).replace(/\D/g, '').replace(/^0+/, '');
  const password = str(b.password, 128);
  if (name.length < 2) throw fail(400, 'Enter your full name.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) throw fail(400, 'Enter a valid email address.');
  if (!/^\+\d{1,4}$/.test(cc) || national.length < 6 || national.length > 14) throw fail(400, 'Enter a valid mobile number, without the country code.');
  if (password.length < 8) throw fail(400, 'Your password needs at least 8 characters.');
  let avatar = null;
  if (b.avatar) { avatar = cleanAvatar(b.avatar); if (!avatar) throw fail(400, AVATAR_ERROR); }
  let handle = cleanHandle(b.handle);
  if (handle) {
    const p = handleProblem(handle);
    if (p) throw fail(400, p);
    if (q.handleTaken.get(handle)) throw fail(409, 'That @ID is taken. Choose another.');
  }
  const phone = cc + national;
  const hash = await hashPassword(password);
  const now = Date.now();
  let id;
  try {
    id = tx(() => {
      const h = handle || suggestHandle(name);
      return Number(q.insertUser.run(name, email, phone, national, hash, now, avatar, h, 'active', now, now).lastInsertRowid);
    });
  } catch (e) {
    const m = String(e.message);
    if (m.includes('users.email')) throw fail(409, 'An account with this email already exists. Try logging in.');
    if (m.includes('users.phone')) throw fail(409, 'An account with this mobile number already exists. Try logging in.');
    if (m.includes('users.handle')) throw fail(409, 'That @ID is taken. Choose another.');
    throw e;
  }
  startSession(res, id, true);
  ok(res, { user: selfView(q.userById.get(id)) }, 201);
});

route('POST', '/api/login', { auth: false }, async ({ req, res }) => {
  if (limited('auth:' + ipOf(req), 20, 15 * 60 * 1000)) throw fail(429, 'Too many attempts. Please wait a few minutes and try again.');
  const b = await readJson(req);
  const identifier = str(b.identifier, 254).trim();
  const password = str(b.password, 128);
  const remember = b.remember !== false;
  const BAD = fail(401, 'The email, mobile number or password is incorrect.');
  if (!identifier || !password) throw BAD;
  const digits = identifier.replace(/[^\d+]/g, '');
  const national = digits.replace(/\D/g, '');
  const rows = identifier.includes('@') ? q.findLogin.all(identifier.toLowerCase(), '', '') : q.findLogin.all('', digits, national);
  if (!rows.length) { await verifyPassword(password, DUMMY_HASH); throw BAD; }
  for (const u of rows) {
    if (await verifyPassword(password, u.pw_hash)) {
      startSession(res, u.id, remember);
      return ok(res, { user: selfView(u) });
    }
  }
  throw BAD;
});

route('POST', '/api/logout', { auth: false, deact: true }, ({ req, res }) => {
  const token = cookies(req).sid;
  if (token) q.deleteSession.run(sha256(token));
  res.setHeader('Set-Cookie', sessionCookie('', 0));
  ok(res, { ok: true });
});

route('GET', '/api/me', { auth: false, deact: true }, ({ res, user }) => ok(res, { user: user ? selfView(user) : null }));

route('GET', '/api/handle', { auth: false }, ({ req, res, url, user }) => {
  if (limited('handle:' + ipOf(req), 90, 15 * 60 * 1000)) throw fail(429, 'Too many checks. Please wait a moment.');
  const h = cleanHandle(url.searchParams.get('h'));
  const problem = handleProblem(h);
  if (problem) return ok(res, { available: false, problem });
  const row = q.handleTaken.get(h);
  ok(res, { available: !row || (user && row.id === user.id), problem: row && !(user && row.id === user.id) ? 'That @ID is taken.' : '' });
});

/* profile and privacy */
route('POST', '/api/profile', { deact: false }, async ({ req, res, user }) => {
  if (limited('profile:' + user.id, 40, 3600 * 1000)) throw fail(429, 'Too many changes. Please try again later.');
  const b = await readJson(req, AVATAR_BODY);
  let name = user.name;
  if ('name' in b) { name = cleanName(b.name); if (name.length < 2) throw fail(400, 'Enter your full name.'); }
  let avatar = user.avatar || null;
  if ('avatar' in b) {
    if (b.avatar === null || b.avatar === '') avatar = null;
    else { avatar = cleanAvatar(b.avatar); if (!avatar) throw fail(400, AVATAR_ERROR); }
  }
  let about = user.about;
  if ('about' in b) {
    const t = str(b.about, 140).trim();
    if (b.about && !t && String(b.about).length > 140) throw fail(400, 'Keep your About text under 140 characters.');
    about = t ? seal(t) : null;
  }
  let handle = user.handle;
  if ('handle' in b) {
    handle = cleanHandle(b.handle);
    const p = handleProblem(handle);
    if (p) throw fail(400, p);
    const other = q.handleTaken.get(handle);
    if (other && other.id !== user.id) throw fail(409, 'That @ID is taken. Choose another.');
  }
  try { q.updateProfile.run(name, avatar, about, handle, user.id); } catch (e) {
    if (String(e.message).includes('users.handle')) throw fail(409, 'That @ID is taken. Choose another.');
    throw e;
  }
  refreshRelated(user.id);
  ok(res, { user: selfView(q.userById.get(user.id)) });
});

route('GET', '/api/privacy', {}, ({ res, user }) => ok(res, { privacy: privacyOf(user), options: PRIVACY_OPTIONS }));
route('POST', '/api/privacy', {}, async ({ req, res, user }) => {
  const b = await readJson(req);
  const next = privacyOf(user);
  for (const k of Object.keys(PRIVACY_DEFAULTS)) {
    if (!(k in b)) continue;
    if (!PRIVACY_OPTIONS[k].includes(b[k])) throw fail(400, 'That privacy choice is not available.');
    next[k] = b[k];
  }
  q.updatePrivacy.run(JSON.stringify(next), user.id);
  refreshRelated(user.id);
  ok(res, { privacy: next, user: selfView(q.userById.get(user.id)) });
});

/* contacts: saved by name and mobile number */
const contactRowView = (uid, c) => peerView(uid, c.user_id ? q.userById.get(c.user_id) : null, c);
route('GET', '/api/contacts', {}, ({ res, user }) => {
  const list = q.contactsOf.all(user.id).map((c) => contactRowView(user.id, c));
  list.sort((x, y) => x.displayName.localeCompare(y.displayName, undefined, { sensitivity: 'base' }));
  ok(res, { contacts: list });
});
route('POST', '/api/contacts', {}, async ({ req, res, user }) => {
  if (limited('contacts:' + user.id, 60, 3600 * 1000)) throw fail(429, 'You have added a lot of contacts in a short time. Please try again later.');
  const b = await readJson(req);
  const name = cleanSaved(b.name);
  if (!name) throw fail(400, 'Give this contact a name of up to 60 characters.');
  if (q.countContacts.get(user.id).n >= 1000) throw fail(400, 'You have reached the limit of 1000 contacts.');
  let target; let via = 1;
  if (b.convId !== undefined) {
    const conv = ownConv(user.id, Number(b.convId));
    const pid = conv ? peerIdOf(conv, user.id) : null;
    target = pid ? q.userById.get(pid) : null;
    via = 0;
    if (!target) throw fail(404, 'That person could not be found.');
  } else {
    const cc = str(b.countryCode, 5);
    const national = str(b.phone, 20).replace(/\D/g, '').replace(/^0+/, '');
    if (!/^\+\d{1,4}$/.test(cc) || national.length < 6 || national.length > 14) throw fail(400, 'Enter a valid mobile number, without the country code.');
    target = q.userByPhone.get(cc + national);
    if (target && target.id === user.id) throw fail(400, "That's your own number.");
    if (!target || target.status === 'deactivated' || privacyOf(target).find === 'nobody' || q.isBlocked.get(target.id, user.id)) {
      throw fail(404, "We couldn't find an account with that number.");
    }
  }
  if (target.id === user.id) throw fail(400, "That's your own number.");
  const existing = q.contactOf.get(user.id, target.id);
  if (existing) throw fail(409, `You already saved this person as "${unseal(existing.saved_name)}".`);
  const id = Number(q.insertContact.run(user.id, target.id, seal(name), via, Date.now()).lastInsertRowid);
  push(target.id, 'refresh');
  ok(res, { contact: contactRowView(user.id, q.contactById.get(id, user.id)) }, 201);
});
route('POST', '/api/contacts/(\\d+)/rename', {}, async ({ req, res, user }, id) => {
  const c = q.contactById.get(Number(id), user.id);
  if (!c) throw fail(404, 'Contact not found.');
  const name = cleanSaved((await readJson(req)).name);
  if (!name) throw fail(400, 'Give this contact a name of up to 60 characters.');
  q.renameContact.run(seal(name), c.id);
  push(user.id, 'refresh');
  ok(res, { contact: contactRowView(user.id, q.contactById.get(c.id, user.id)) });
});
route('DELETE', '/api/contacts/(\\d+)', {}, ({ res, user }, id) => {
  const c = q.contactById.get(Number(id), user.id);
  if (!c) throw fail(404, 'Contact not found.');
  q.deleteContact.run(c.id);
  if (c.user_id) push(c.user_id, 'refresh');
  push(user.id, 'refresh');
  ok(res, { ok: true });
});

/* blocklist */
route('GET', '/api/blocks', {}, ({ res, user }) => {
  const list = q.blocksOf.all(user.id).map((b) => ({ ...peerView(user.id, q.userById.get(b.blocked_id)), blockedAt: b.created_at }));
  ok(res, { blocks: list });
});
route('POST', '/api/blocks', {}, async ({ req, res, user }) => {
  const h = cleanHandle((await readJson(req)).handle);
  const t = h ? q.userByHandle.get(h) : null;
  if (!t) throw fail(404, 'That person could not be found.');
  if (t.id === user.id) throw fail(400, "You can't block yourself.");
  q.insertBlock.run(user.id, t.id, Date.now());
  for (const c of calls.values()) if (c.state !== 'ended' && ((c.caller === user.id && c.callee === t.id) || (c.caller === t.id && c.callee === user.id))) finishCall(c, 'missed', 'system');
  push(t.id, 'refresh'); push(user.id, 'refresh');
  ok(res, { ok: true });
});
route('DELETE', '/api/blocks/([a-z0-9_]+)', {}, ({ res, user }, h) => {
  const t = q.userByHandle.get(h);
  if (!t) throw fail(404, 'That person could not be found.');
  q.deleteBlock.run(user.id, t.id);
  push(t.id, 'refresh'); push(user.id, 'refresh');
  ok(res, { ok: true });
});

/* conversations and messages */
route('GET', '/api/convs', {}, ({ res, user }) => {
  const list = q.convsOf.all(user.id, user.id).map((c) => convView(c, user.id));
  list.sort((x, y) => y.lastAt - x.lastAt);
  ok(res, { convs: list });
});
route('POST', '/api/convs', {}, async ({ req, res, user }) => {
  const c = q.contactById.get(Number((await readJson(req)).contactId), user.id);
  if (!c) throw fail(404, 'Contact not found.');
  const peer = c.user_id ? q.userById.get(c.user_id) : null;
  const can = canSendTo(user.id, peer);
  if (!peer) throw fail(410, 'This account no longer exists.');
  if (peer.status === 'deactivated') throw fail(409, can.reason);
  const conv = convFor(user.id, peer.id, true);
  ok(res, { conv: convView(conv, user.id) });
});
route('GET', '/api/convs/(\\d+)/messages', {}, ({ res, user }, id) => {
  const c = ownConv(user.id, Number(id));
  if (!c) throw fail(404, 'Chat not found.');
  const side = sideOf(c, user.id), pid = peerIdOf(c, user.id), peer = pid ? q.userById.get(pid) : null;
  const msgs = q.listMsgs.all(c.id, c[side + '_cleared'], user.id).reverse().map((m) => msgView(m, user.id));
  const can = canSendTo(user.id, peer);
  ok(res, { messages: msgs, peer: peerView(user.id, peer), canSend: can.ok, reason: can.ok ? '' : can.reason });
});
route('POST', '/api/convs/(\\d+)/messages', {}, async ({ req, res, user }, id) => {
  if (limited('msg:' + user.id, 120, 60 * 1000)) throw fail(429, 'You are sending messages very quickly. Please slow down.');
  const c = ownConv(user.id, Number(id));
  if (!c) throw fail(404, 'Chat not found.');
  const b = await readJson(req, 16 * 1024);
  const text = str(b.text, 4000).trim();
  if (!text) throw fail(400, 'Write a message first, up to 4000 characters.');
  const pid = peerIdOf(c, user.id), peer = pid ? q.userById.get(pid) : null;
  const can = canSendTo(user.id, peer);
  if (!can.ok) throw fail(403, can.reason);
  const deliver = reachable(user.id, peer, 'message');
  const now = Date.now();
  const mid = tx(() => {
    const m = Number(q.insertMsg.run(c.id, user.id, 'text', seal(text), b.ai ? 1 : 0, deliver ? 0 : 1, now).lastInsertRowid);
    q.touchConv.run(now, c.id);
    sideStmt('visible', sideOf(c, user.id)).run(1, c.id);
    if (deliver) sideStmt('visible', sideOf(c, peer.id)).run(1, c.id);
    return m;
  });
  push(user.id, 'msg', { convId: c.id });
  if (deliver) push(peer.id, 'msg', { convId: c.id });
  ok(res, { message: msgView({ id: mid, sender: user.id, kind: 'text', body: seal(text), ai: b.ai ? 1 : 0, created_at: now }, user.id) }, 201);
});
route('POST', '/api/convs/(\\d+)/read', {}, ({ res, user }, id) => {
  const c = ownConv(user.id, Number(id));
  if (!c) throw fail(404, 'Chat not found.');
  sideStmt('read', sideOf(c, user.id)).run(q.maxMsg.get(c.id).m, c.id);
  ok(res, { ok: true });
});
function clearFor(user, c, hide) {
  const side = sideOf(c, user.id);
  const max = q.maxMsg.get(c.id).m;
  sideStmt('cleared', side).run(max, c.id);
  sideStmt('read', side).run(max, c.id);
  if (hide) sideStmt('visible', side).run(0, c.id);
  q.purgeUndelivered.run(c.id, user.id, max);
  purgeConv(c.id);
}
route('POST', '/api/convs/(\\d+)/clear', {}, ({ res, user }, id) => {
  const c = ownConv(user.id, Number(id));
  if (!c) throw fail(404, 'Chat not found.');
  clearFor(user, c, false);
  push(user.id, 'msg', { convId: c.id });
  ok(res, { ok: true });
});
route('DELETE', '/api/convs/(\\d+)', {}, ({ res, user }, id) => {
  const c = ownConv(user.id, Number(id));
  if (!c) throw fail(404, 'Chat not found.');
  clearFor(user, c, true);
  push(user.id, 'refresh');
  ok(res, { ok: true });
});

/* voice calls */
route('GET', '/api/ice', {}, ({ res }) => ok(res, { iceServers: iceServers() }));
route('POST', '/api/calls', {}, async ({ req, res, user }) => {
  if (limited('call:' + user.id, 30, 10 * 60 * 1000)) throw fail(429, 'Too many calls in a short time. Please wait a moment.');
  const c = ownConv(user.id, Number((await readJson(req)).convId));
  if (!c) throw fail(404, 'Chat not found.');
  const pid = peerIdOf(c, user.id), peer = pid ? q.userById.get(pid) : null;
  const can = canSendTo(user.id, peer);
  if (!can.ok) throw fail(403, can.reason);
  if (busyCall(user.id)) throw fail(409, "You're already in a call.");
  const unavailable = () => ok(res, { reason: 'unavailable' });
  if (!reachable(user.id, peer, 'call') || peer.status === 'sleep') return unavailable();
  if (!isOnline(peer.id) || busyCall(peer.id)) { logCall(c.id, user.id, 'missed', 0, true); return unavailable(); }
  const call = { id: crypto.randomBytes(12).toString('hex'), convId: c.id, caller: user.id, callee: peer.id, state: 'ringing', startedAt: Date.now(), answeredAt: 0, timer: null };
  call.timer = setTimeout(() => finishCall(call, 'missed', 'system'), RING_MS);
  calls.set(call.id, call);
  push(peer.id, 'call', { kind: 'incoming', callId: call.id, convId: c.id, from: peerView(peer.id, q.userById.get(user.id)) });
  ok(res, { call: { id: call.id, state: 'ringing' } }, 201);
});
function callFor(uid, id) {
  const call = calls.get(String(id));
  if (!call || call.state === 'ended' || (call.caller !== uid && call.callee !== uid)) throw fail(404, 'This call has ended.');
  return call;
}
route('POST', '/api/calls/([a-f0-9]{24})/accept', {}, ({ res, user }, id) => {
  const call = callFor(user.id, id);
  if (call.callee !== user.id || call.state !== 'ringing') throw fail(409, 'This call can no longer be answered.');
  clearTimeout(call.timer);
  call.state = 'active'; call.answeredAt = Date.now();
  push(call.caller, 'call', { kind: 'accepted', callId: call.id });
  for (const r of clients.get(user.id) || []) { /* other tabs of the callee stop ringing */ }
  push(call.callee, 'call', { kind: 'taken', callId: call.id });
  ok(res, { ok: true });
});
route('POST', '/api/calls/([a-f0-9]{24})/decline', {}, ({ res, user }, id) => {
  const call = callFor(user.id, id);
  if (call.callee !== user.id || call.state !== 'ringing') throw fail(409, 'This call can no longer be declined.');
  finishCall(call, 'declined', 'callee');
  ok(res, { ok: true });
});
route('POST', '/api/calls/([a-f0-9]{24})/end', {}, ({ res, user }, id) => {
  const call = calls.get(String(id));
  if (call && call.state !== 'ended' && (call.caller === user.id || call.callee === user.id)) finishCall(call, 'missed', call.caller === user.id ? 'caller' : 'callee');
  ok(res, { ok: true });
});
route('POST', '/api/calls/([a-f0-9]{24})/signal', {}, async ({ req, res, user }, id) => {
  if (limited('signal:' + user.id, 600, 60 * 1000)) throw fail(429, 'Too many signals.');
  const call = callFor(user.id, id);
  if (call.state !== 'active') throw fail(409, 'This call is not connected yet.');
  const b = await readJson(req, 24 * 1024);
  if (!['offer', 'answer', 'candidate'].includes(b.kind)) throw fail(400, 'Unknown signal.');
  push(call.caller === user.id ? call.callee : call.caller, 'call', { kind: 'signal', callId: call.id, signal: { kind: b.kind, data: b.data === undefined ? null : b.data } });
  ok(res, { ok: true });
});

/* account status, data and deletion */
route('POST', '/api/account/status', { deact: true }, async ({ req, res, user }) => {
  const s = (await readJson(req)).status;
  if (!['active', 'sleep', 'deactivated'].includes(s)) throw fail(400, 'That status is not available.');
  q.updateStatus.run(s, Date.now(), user.id);
  if (s === 'deactivated') endCallsOf(user.id, 'missed');
  refreshRelated(user.id);
  push(user.id, 'account');
  ok(res, { user: selfView(q.userById.get(user.id)) });
});
route('GET', '/api/account/data', {}, ({ res, user }) => {
  const sent = q.sentCount.get(user.id);
  const photoBytes = user.avatar ? Math.round(user.avatar.length * 0.75) : 0;
  const stored = photoBytes + sent.bytes + q.contactBytes.get(user.id).bytes + (user.about ? user.about.length : 0);
  ok(res, {
    usage: {
      contacts: q.countContacts.get(user.id).n, blocked: q.blocksOf.all(user.id).length, chats: q.convCount.get(user.id, user.id).n,
      sent: sent.n, received: q.receivedCount.get(user.id, user.id, user.id).n, calls: q.callCount.get(user.id, user.id).n,
      photoBytes, storedBytes: stored, devices: q.countSessions.get(user.id, Date.now()).n, createdAt: user.created_at
    }
  });
});
route('GET', '/api/account/export', { deact: true }, ({ res, user }) => {
  const contacts = q.contactsOf.all(user.id).map((c) => { const v = contactRowView(user.id, c); return { savedName: v.savedName, handle: v.handle || null, phone: v.phone || null, savedAt: c.created_at }; });
  const blocked = q.blocksOf.all(user.id).map((b) => { const t = q.userById.get(b.blocked_id); return { handle: t ? t.handle : null, blockedAt: b.created_at }; });
  const chats = q.convsOf.all(user.id, user.id).map((c) => {
    const side = sideOf(c, user.id), v = convView(c, user.id);
    return { with: v.peer.displayName, handle: v.peer.handle || null, messages: q.allMsgs.all(c.id, c[side + '_cleared'], user.id).map((m) => { const x = msgView(m, user.id); return { from: x.mine ? 'me' : 'them', at: x.createdAt, ...(x.kind === 'call' ? { call: x.call } : { text: x.text }) }; }) };
  });
  const body = JSON.stringify({ exportedAt: Date.now(), profile: selfView(user), contacts, blocked, chats }, null, 2);
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="my-data.json"', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(body);
});
route('POST', '/api/account/delete', { deact: true }, async ({ req, res, user }) => {
  if (limited('delete:' + user.id, 5, 15 * 60 * 1000)) throw fail(429, 'Too many attempts. Please wait a few minutes and try again.');
  const b = await readJson(req);
  const password = str(b.password, 128);
  if (!password || !(await verifyPassword(password, user.pw_hash))) throw fail(403, 'That password is not correct.');
  const people = related(user.id);
  endCallsOf(user.id, 'missed');
  tx(() => {
    q.deleteUser.run(user.id);
    q.cleanupConvs.run();
  });
  db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  const set = clients.get(user.id);
  if (set) { for (const r of set) { try { r.write('data: {"type":"gone"}\n\n'); r.end(); } catch { /* closing */ } } clients.delete(user.id); }
  for (const id of people) push(id, 'refresh');
  res.setHeader('Set-Cookie', sessionCookie('', 0));
  ok(res, { ok: true });
});

/* live updates */
route('GET', '/api/events', { deact: true }, ({ req, res, user }) => {
  const set = clients.get(user.id) || new Set();
  if (set.size >= 8) throw fail(429, 'Too many open tabs.');
  req.socket.setTimeout(0);
  res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no', 'X-Content-Type-Options': 'nosniff' });
  res.write('retry: 2500\n\ndata: {"type":"hello"}\n\n');
  const first = set.size === 0;
  set.add(res); clients.set(user.id, set);
  if (first) refreshRelated(user.id);
  res.on('close', () => {
    set.delete(res);
    if (set.size > 0) return;
    clients.delete(user.id);
    try { q.touchSeen.run(Date.now(), user.id); } catch { /* user was deleted */ }
    refreshRelated(user.id);
    setTimeout(() => { if (!isOnline(user.id)) endCallsOf(user.id, 'missed'); }, 8000).unref();
  });
});

/* ---------- server ---------- */
const PAGE_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'microphone=(self), camera=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
};
/* the few files that make the page installable: only these exact paths are served from public/ */
const STATIC = {
  '/manifest.webmanifest': ['application/manifest+json; charset=utf-8', 'manifest.webmanifest', 'public, max-age=3600'],
  '/sw.js': ['text/javascript; charset=utf-8', 'sw.js', 'no-cache', { 'Service-Worker-Allowed': '/' }],
  '/icons/icon-192.png': ['image/png', 'icons/icon-192.png', 'public, max-age=86400'],
  '/icons/icon-512.png': ['image/png', 'icons/icon-512.png', 'public, max-age=86400'],
  '/icons/maskable-512.png': ['image/png', 'icons/maskable-512.png', 'public, max-age=86400'],
  '/icons/apple-touch-icon.png': ['image/png', 'icons/apple-touch-icon.png', 'public, max-age=86400']
};
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, PAGE_HEADERS);
      return res.end(fs.readFileSync(PAGE));
    }
    const asset = req.method === 'GET' ? STATIC[url.pathname] : null;
    if (asset) {
      let data;
      try { data = fs.readFileSync(path.join(__dirname, 'public', asset[1])); } catch { return send(res, 404, { error: 'Not found.' }); }
      res.writeHead(200, { 'Content-Type': asset[0], 'Cache-Control': asset[2], 'X-Content-Type-Options': 'nosniff', ...(asset[3] || {}) });
      return res.end(data);
    }
    if (url.pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && !sameOrigin(req)) return send(res, 403, { error: 'Request blocked.' });
      for (const r of routes) {
        if (r.method !== req.method) continue;
        const m = url.pathname.match(r.re);
        if (!m) continue;
        const user = currentUser(req);
        if (r.opts.auth !== false) {
          if (!user) return send(res, 401, { error: 'Please log in again.' });
          if (user.status === 'deactivated' && !r.opts.deact) return send(res, 403, { error: 'Your account is deactivated. Reactivate it to continue.', code: 'deactivated' });
        }
        return await r.fn({ req, res, url, user }, ...m.slice(1));
      }
    }
    send(res, 404, { error: 'Not found.' });
  } catch (e) {
    if (res.headersSent) return;
    if (e.status) return send(res, e.status, { error: e.message, ...(e.code ? { code: e.code } : {}) });
    console.error(e.stack || e);
    send(res, 500, { error: 'Something went wrong. Please try again.' });
  }
});

function shutdown() { try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* ignore */ } process.exit(0); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
server.listen(PORT, () => console.log(`Messaging server running at http://localhost:${PORT}`));
