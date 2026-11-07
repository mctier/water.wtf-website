'use strict';

/**
 * water.wtf community config backend.
 *
 * A small HTTP API: browse approved community configs (what the client's
 * COMMUNITY_URL points at), submit new ones, and moderate them with an admin token.
 *
 * Security posture (the 12-step checklist):
 *  - Secrets only in env vars (ADMIN_TOKEN, IP_SALT) — never in code or the client.
 *  - Every SQL statement is a prepared statement with bound parameters (no concatenation).
 *  - Submissions and downloads are rate-limited per IP; body size is capped.
 *  - Uploads (configs) are validated: field lengths, allowed shapes, share-code format.
 *  - Admin actions (approve / delete / list pending) require the admin token — checked server-side.
 *  - helmet sets security headers; x-powered-by is removed; stack traces never leak in production.
 *  - IPs are stored only as a salted hash, so no raw PII is kept.
 * Run behind a TLS-terminating proxy (HTTPS everywhere); set NODE_ENV=production in prod.
 */

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');

// ---- config (all via env) ------------------------------------------------
const PORT = parseInt(process.env.PORT || '8787', 10);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'community.db');
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';                 // required for moderation
const IP_SALT = process.env.IP_SALT || crypto.randomBytes(16).toString('hex'); // rotates on restart if unset
const AUTO_APPROVE = /^(1|true|yes)$/i.test(process.env.AUTO_APPROVE || '');
const PROD = process.env.NODE_ENV === 'production';

if (!ADMIN_TOKEN) {
  console.warn('[community] ADMIN_TOKEN is not set — moderation endpoints are disabled until it is.');
}

// ---- limits --------------------------------------------------------------
const MAX = { name: 48, author: 32, desc: 160, code: 8000 };
const SHARE_PREFIX = 'UM1-';

// ---- database (prepared statements only) ---------------------------------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS configs (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    author     TEXT NOT NULL,
    descr      TEXT NOT NULL,
    code       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',
    downloads  INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    ip_hash    TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_status_created ON configs(status, created_at DESC);
`);

const q = {
  insert: db.prepare(`INSERT INTO configs (id,name,author,descr,code,status,downloads,created_at,ip_hash)
                      VALUES (@id,@name,@author,@descr,@code,@status,0,@created_at,@ip_hash)`),
  listApproved: db.prepare(`SELECT id,name,author,descr AS desc,code,downloads,created_at
                            FROM configs WHERE status='approved' ORDER BY created_at DESC LIMIT ?`),
  getApproved: db.prepare(`SELECT id,name,author,descr AS desc,code,downloads,created_at
                           FROM configs WHERE id=? AND status='approved'`),
  listPending: db.prepare(`SELECT id,name,author,descr AS desc,code,created_at
                           FROM configs WHERE status='pending' ORDER BY created_at ASC LIMIT ?`),
  approve: db.prepare(`UPDATE configs SET status='approved' WHERE id=?`),
  remove: db.prepare(`DELETE FROM configs WHERE id=?`),
  bumpDownload: db.prepare(`UPDATE configs SET downloads=downloads+1 WHERE id=? AND status='approved'`),
  countByIpSince: db.prepare(`SELECT COUNT(*) AS n FROM configs WHERE ip_hash=? AND created_at > ?`),
};

// ---- helpers -------------------------------------------------------------
function hashIp(ip) {
  return crypto.createHmac('sha256', IP_SALT).update(String(ip || '')).digest('hex').slice(0, 32);
}

function validSubmission(body) {
  if (!body || typeof body !== 'object') return 'Invalid body.';
  const name = String(body.name ?? '').trim();
  const author = String(body.author ?? '').trim();
  const desc = String(body.desc ?? '').trim();
  const code = String(body.code ?? '').trim();
  if (name.length < 2 || name.length > MAX.name) return `Name must be 2–${MAX.name} characters.`;
  if (author.length < 1 || author.length > MAX.author) return `Author must be 1–${MAX.author} characters.`;
  if (desc.length > MAX.desc) return `Description must be ≤ ${MAX.desc} characters.`;
  if (code.length < 8 || code.length > MAX.code) return `Config code must be 8–${MAX.code} characters.`;
  // allowed shapes: a UM1- share code, or a JSON object
  const isShare = code.startsWith(SHARE_PREFIX) && /^[A-Za-z0-9=_\-]+$/.test(code.slice(SHARE_PREFIX.length));
  let isJson = false;
  if (!isShare) { try { isJson = typeof JSON.parse(code) === 'object'; } catch { isJson = false; } }
  if (!isShare && !isJson) return 'Config must be a UM1- share code or a JSON object.';
  // control characters are not allowed in the display fields
  if (/[\u0000-\u001f\u007f]/.test(name + author + desc)) return 'Fields contain invalid characters.';
  return { name, author, desc, code };
}

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: 'Moderation is not configured.' });
  const token = req.get('x-admin-token') || '';
  // constant-time comparison
  const a = Buffer.from(token);
  const b = Buffer.from(ADMIN_TOKEN);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  next();
}

// ---- app -----------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);                       // behind one reverse proxy; fixes req.ip for rate-limit
app.use(helmet());
app.use(cors({ origin: true, methods: ['GET', 'POST', 'DELETE'] }));
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: PROD ? '1h' : 0 }));

const submitLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many submissions — try again later.' } });
const dlLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });

app.get('/health', (_req, res) => res.json({ ok: true }));

// browse (public) — this is the URL the client's COMMUNITY_URL points at
app.get('/configs', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 200);
  res.json(q.listApproved.all(limit));
});

app.get('/configs/:id', (req, res) => {
  const row = q.getApproved.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found.' });
  res.json(row);
});

// submit (public, rate-limited, validated)
app.post('/configs', submitLimiter, (req, res) => {
  const v = validSubmission(req.body);
  if (typeof v === 'string') return res.status(400).json({ error: v });

  const ipHash = hashIp(req.ip);
  const since = Date.now() - 24 * 60 * 60 * 1000;
  if (q.countByIpSince.get(ipHash, since).n >= 20) {
    return res.status(429).json({ error: 'Daily submission limit reached.' });
  }

  const id = crypto.randomBytes(9).toString('base64url');
  q.insert.run({
    id, name: v.name, author: v.author, descr: v.desc, code: v.code,
    status: AUTO_APPROVE ? 'approved' : 'pending',
    created_at: Date.now(), ip_hash: ipHash,
  });
  res.status(201).json({ id, status: AUTO_APPROVE ? 'approved' : 'pending' });
});

// count a download (public)
app.post('/configs/:id/download', dlLimiter, (req, res) => {
  q.bumpDownload.run(req.params.id);
  res.json({ ok: true });
});

// ---- moderation (admin token) -------------------------------------------
app.get('/admin/pending', requireAdmin, (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 200);
  res.json(q.listPending.all(limit));
});
app.post('/admin/:id/approve', requireAdmin, (req, res) => {
  const r = q.approve.run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'Not found.' });
  res.json({ ok: true });
});
app.delete('/admin/:id', requireAdmin, (req, res) => {
  const r = q.remove.run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'Not found.' });
  res.json({ ok: true });
});

// ---- errors (no stack traces to clients) --------------------------------
app.use((err, _req, res, _next) => {
  if (!PROD) console.error(err);
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Payload too large.' });
  res.status(500).json({ error: 'Server error.' });
});

app.listen(PORT, () => console.log(`[community] listening on :${PORT} (${PROD ? 'production' : 'dev'})`));
