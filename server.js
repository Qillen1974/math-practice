// math-practice — Express server with SQLite attempt logging + parent dashboard.
//
// Two deployment modes via MATH_MODE:
//   private (default) — single-child instance (Caleb): no accounts, PIN-gated parent view.
//   public            — multi-user freemium: email accounts, per-user attempts,
//                       daily free cap, waitlist for the paid Parent Plan.

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const MODE = process.env.MATH_MODE === 'public' ? 'public' : 'private';
const PORT = parseInt(process.env.PORT || '4600', 10);
const PARENT_PIN = process.env.MATH_PARENT_PIN || '1607';
const FREE_DAILY_CAP = parseInt(process.env.MATH_FREE_DAILY_CAP || '30', 10);
if (MODE === 'public' && !process.env.MATH_COOKIE_SECRET) {
  console.error('[math-practice] MATH_MODE=public requires MATH_COOKIE_SECRET to be set');
  process.exit(1);
}
const COOKIE_SECRET = process.env.MATH_COOKIE_SECRET ||
  crypto.createHash('sha256').update('math-practice-' + PARENT_PIN).digest('hex').slice(0, 32);
const COOKIE_NAME = 'math_parent';
const SESSION_COOKIE = 'math_session';
const SESSION_TTL = 90 * 24 * 60 * 60 * 1000;
const DATA_DIR = process.env.MATH_DATA_DIR || path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'practice.db');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    mode TEXT NOT NULL,
    fraction_sub TEXT,
    problem_text TEXT NOT NULL,
    expected TEXT NOT NULL,
    given TEXT NOT NULL,
    correct INTEGER NOT NULL,
    ms_taken INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_attempts_ts ON attempts(ts DESC);
  CREATE INDEX IF NOT EXISTS idx_attempts_mode ON attempts(mode);
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    child_name TEXT,
    plan TEXT NOT NULL DEFAULT 'free',
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS waitlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email TEXT NOT NULL UNIQUE,
    ts INTEGER NOT NULL
  );
`);

// Migration: topic tag (finer-grained than mode, e.g. decimal_align sub-shapes)
const hasCol = (name) =>
  db.prepare(`SELECT COUNT(*) AS n FROM pragma_table_info('attempts') WHERE name = ?`).get(name).n > 0;
if (!hasCol('topic')) db.exec(`ALTER TABLE attempts ADD COLUMN topic TEXT`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_attempts_topic ON attempts(topic)`);
// Migration: daily flag (1 = attempt made inside a Daily Session, 0 = free practice)
if (!hasCol('daily')) db.exec(`ALTER TABLE attempts ADD COLUMN daily INTEGER NOT NULL DEFAULT 0`);
// Migration: difficulty tier (easy/medium/hard; null for word problems + pre-existing rows)
if (!hasCol('difficulty')) db.exec(`ALTER TABLE attempts ADD COLUMN difficulty TEXT`);
// Migration: owning account (null on private instances / legacy rows)
if (!hasCol('user_id')) db.exec(`ALTER TABLE attempts ADD COLUMN user_id INTEGER`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_attempts_user_ts ON attempts(user_id, ts DESC)`);

const insertAttempt = db.prepare(
  `INSERT INTO attempts (ts, mode, fraction_sub, topic, problem_text, expected, given, correct, ms_taken, daily, difficulty, user_id)
   VALUES (@ts, @mode, @fraction_sub, @topic, @problem_text, @expected, @given, @correct, @ms_taken, @daily, @difficulty, @user_id)`
);

// ---------- Accounts (public mode) ----------

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 32);
  return salt.toString('hex') + ':' + hash.toString('hex');
}

function verifyPassword(pw, stored) {
  const [saltHex, hashHex] = String(stored).split(':');
  if (!saltHex || !hashHex) return false;
  const hash = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), 32);
  const expected = Buffer.from(hashHex, 'hex');
  return hash.length === expected.length && crypto.timingSafeEqual(hash, expected);
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function createSession(res, userId, req) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`)
    .run(sha256(token), userId, now, now + SESSION_TTL);
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    signed: true,
    maxAge: SESSION_TTL,
  });
}

function currentUser(req) {
  const token = req.signedCookies?.[SESSION_COOKIE];
  if (!token) return null;
  return db.prepare(
    `SELECT u.id, u.email, u.child_name, u.plan FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  ).get(sha256(token), Date.now()) || null;
}

function requireUser(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  req.user = user;
  next();
}

// Singapore has no DST, so a fixed +8h offset is safe.
function sgtDayStart(now = Date.now()) {
  const SGT = 8 * 3600 * 1000;
  return Math.floor((now + SGT) / 86400000) * 86400000 - SGT;
}

const usedTodayStmt = db.prepare(`SELECT COUNT(*) AS n FROM attempts WHERE user_id = ? AND ts >= ?`);
const usedToday = (userId) => usedTodayStmt.get(userId, sgtDayStart()).n;

// Basic brute-force guard for auth endpoints (in-memory, per IP)
const authHits = new Map();
function authRateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || 'unknown';
  const now = Date.now();
  const rec = authHits.get(ip);
  if (!rec || now > rec.resetAt) {
    authHits.set(ip, { count: 1, resetAt: now + 15 * 60 * 1000 });
    return next();
  }
  if (rec.count >= 20) return res.status(429).json({ error: 'too_many_attempts' });
  rec.count += 1;
  next();
}

const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(cookieParser(COOKIE_SECRET));

// ---------- Child side ----------

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/healthz', (_req, res) => res.json({ ok: true, ts: Date.now() }));

app.get('/api/config', (_req, res) => res.json({ mode: MODE, freeDailyCap: FREE_DAILY_CAP }));

if (MODE === 'public') {
  app.post('/api/signup', authRateLimit, (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const childName = String(req.body?.child_name || '').trim().slice(0, 64) || null;
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'bad_email' });
    if (password.length < 8) return res.status(400).json({ error: 'weak_password' });
    try {
      const info = db.prepare(`INSERT INTO users (email, password_hash, child_name, created_at) VALUES (?, ?, ?, ?)`)
        .run(email, hashPassword(password), childName, Date.now());
      createSession(res, info.lastInsertRowid, req);
      res.json({ ok: true });
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'email_taken' });
      res.status(500).json({ error: 'server_error' });
    }
  });

  app.post('/api/login', authRateLimit, (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const user = db.prepare(`SELECT id, password_hash FROM users WHERE email = ?`).get(email);
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: 'bad_credentials' });
    }
    createSession(res, user.id, req);
    res.json({ ok: true });
  });

  app.post('/api/logout', (req, res) => {
    const token = req.signedCookies?.[SESSION_COOKIE];
    if (token) db.prepare(`DELETE FROM sessions WHERE token_hash = ?`).run(sha256(token));
    res.clearCookie(SESSION_COOKIE);
    res.json({ ok: true });
  });

  app.get('/api/me', (req, res) => {
    const user = currentUser(req);
    if (!user) return res.json({ authed: false });
    const used = usedToday(user.id);
    res.json({
      authed: true,
      email: user.email,
      child_name: user.child_name,
      plan: user.plan,
      quota: { used, cap: FREE_DAILY_CAP, remaining: Math.max(0, FREE_DAILY_CAP - used) },
    });
  });

  app.post('/api/waitlist', requireUser, (req, res) => {
    db.prepare(`INSERT OR IGNORE INTO waitlist (user_id, email, ts) VALUES (?, ?, ?)`)
      .run(req.user.id, req.user.email, Date.now());
    res.json({ ok: true });
  });
}

app.post('/api/log', (req, res) => {
  let userId = null;
  if (MODE === 'public') {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ ok: false, error: 'unauthorized' });
    const used = usedToday(user.id);
    if (user.plan === 'free' && used >= FREE_DAILY_CAP) {
      return res.status(429).json({ ok: false, error: 'cap_reached', used, cap: FREE_DAILY_CAP });
    }
    userId = user.id;
  }
  const b = req.body || {};
  const clip = (v, n) => (typeof v === 'string' ? v.slice(0, n) : String(v ?? '').slice(0, n));
  try {
    insertAttempt.run({
      ts: Date.now(),
      mode: clip(b.mode, 32),
      fraction_sub: b.fraction_sub ? clip(b.fraction_sub, 32) : null,
      topic: b.topic ? clip(b.topic, 48) : null,
      problem_text: clip(b.problem_text, 512),
      expected: clip(b.expected, 128),
      given: clip(b.given, 128),
      correct: b.correct ? 1 : 0,
      ms_taken: Number.isFinite(b.ms_taken) ? Math.max(0, Math.min(600000, b.ms_taken | 0)) : null,
      daily: b.daily ? 1 : 0,
      difficulty: ['easy', 'medium', 'hard'].includes(b.difficulty) ? b.difficulty : null,
      user_id: userId,
    });
    const out = { ok: true };
    if (userId !== null) out.remaining = Math.max(0, FREE_DAILY_CAP - usedToday(userId));
    res.json(out);
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

// Aggregate accuracy stats for Daily Session adaptive weighting (no problem
// content exposed). Public mode scopes to the signed-in account.
app.get('/api/topic-stats', (req, res) => {
  const since = Date.now() - 30 * 24 * 60 * 60 * 1000;
  let userWhere = '';
  const args = [since];
  if (MODE === 'public') {
    const user = currentUser(req);
    if (!user) return res.json({ byMode: [], byTopic: [] });
    userWhere = ' AND user_id = ?';
    args.push(user.id);
  }
  const byMode = db.prepare(
    `SELECT mode, COUNT(*) AS n, SUM(correct) AS got
     FROM attempts WHERE ts >= ?${userWhere} GROUP BY mode`
  ).all(...args);
  const byTopic = db.prepare(
    `SELECT COALESCE(topic, mode) AS topic, COUNT(*) AS n, SUM(correct) AS got
     FROM attempts WHERE ts >= ?${userWhere} GROUP BY COALESCE(topic, mode)`
  ).all(...args);
  res.json({ byMode, byTopic });
});

// ---------- Parent side ----------
// private mode: PIN cookie. public mode: the account itself is the parent.

function isParent(req) {
  if (MODE === 'public') return !!currentUser(req);
  return req.signedCookies?.[COOKIE_NAME] === 'ok';
}

function requireParent(req, res, next) {
  if (!isParent(req)) return res.status(401).json({ error: 'unauthorized' });
  if (MODE === 'public') req.user = currentUser(req);
  next();
}

app.get('/parent', (_req, res) => res.sendFile(path.join(__dirname, 'parent.html')));

app.post('/api/parent/auth', authRateLimit, (req, res) => {
  if (MODE === 'public') {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const user = db.prepare(`SELECT id, password_hash FROM users WHERE email = ?`).get(email);
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: 'bad_credentials' });
    }
    createSession(res, user.id, req);
    return res.json({ ok: true });
  }
  if ((req.body?.pin || '').toString() === PARENT_PIN) {
    res.cookie(COOKIE_NAME, 'ok', {
      httpOnly: true,
      sameSite: 'strict',
      secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
      signed: true,
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: 'bad_pin' });
});

app.post('/api/parent/logout', (req, res) => {
  if (MODE === 'public') {
    const token = req.signedCookies?.[SESSION_COOKIE];
    if (token) db.prepare(`DELETE FROM sessions WHERE token_hash = ?`).run(sha256(token));
    res.clearCookie(SESSION_COOKIE);
  } else {
    res.clearCookie(COOKIE_NAME);
  }
  res.json({ ok: true });
});

app.get('/api/parent/me', (req, res) => res.json({ authed: isParent(req) }));

app.get('/api/parent/attempts', requireParent, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  const mode = req.query.mode && typeof req.query.mode === 'string' ? req.query.mode : null;
  const since = parseInt(req.query.since) || 0;
  const until = parseInt(req.query.until) || 0;
  const onlyWrong = req.query.only === 'wrong';
  const onlyDaily = req.query.daily === '1';
  const topic = req.query.topic && typeof req.query.topic === 'string' ? req.query.topic : null;
  let sql = 'SELECT id, ts, mode, fraction_sub, topic, problem_text, expected, given, correct, ms_taken, daily, difficulty FROM attempts WHERE ts >= ?';
  const args = [since];
  if (MODE === 'public') { sql += ' AND user_id = ?'; args.push(req.user.id); }
  if (until > 0) { sql += ' AND ts < ?'; args.push(until); }
  if (mode) { sql += ' AND mode = ?'; args.push(mode); }
  if (topic) { sql += ' AND topic = ?'; args.push(topic); }
  if (onlyWrong) sql += ' AND correct = 0';
  if (onlyDaily) sql += ' AND daily = 1';
  sql += ' ORDER BY ts DESC LIMIT ?';
  args.push(limit);
  res.json({ attempts: db.prepare(sql).all(...args) });
});

app.get('/api/parent/summary', requireParent, (req, res) => {
  const since = parseInt(req.query.since) || 0;
  const until = parseInt(req.query.until) || 0;
  const onlyDaily = req.query.daily === '1';
  let where = 'ts >= ?';
  const args = [since];
  if (MODE === 'public') { where += ' AND user_id = ?'; args.push(req.user.id); }
  if (until > 0) { where += ' AND ts < ?'; args.push(until); }
  if (onlyDaily) where += ' AND daily = 1';
  const overall = db.prepare(
    `SELECT COUNT(*) AS n, SUM(correct) AS got FROM attempts WHERE ${where}`
  ).get(...args);
  const byMode = db.prepare(
    `SELECT mode, COUNT(*) AS n, SUM(correct) AS got
     FROM attempts WHERE ${where}
     GROUP BY mode ORDER BY n DESC`
  ).all(...args);
  const byTopic = db.prepare(
    `SELECT COALESCE(topic, mode) AS topic, COUNT(*) AS n, SUM(correct) AS got
     FROM attempts WHERE ${where}
     GROUP BY COALESCE(topic, mode) ORDER BY n DESC`
  ).all(...args);
  res.json({ overall, byMode, byTopic });
});

// Hourly sweep of expired sessions
setInterval(() => {
  try { db.prepare(`DELETE FROM sessions WHERE expires_at <= ?`).run(Date.now()); } catch (_) {}
}, 3600 * 1000).unref();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[math-practice] listening on http://0.0.0.0:${PORT}  (mode: ${MODE}, db: ${DB_PATH})`);
});
