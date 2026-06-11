// math-practice — Express server with SQLite attempt logging + parent dashboard.
//
// Pass 1: served static HTML.
// Pass 2 (current): adds /api/log (Caleb side, no auth) + /api/parent/* (PIN-gated)
//                   and /parent dashboard page.

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const PORT = parseInt(process.env.PORT || '4600', 10);
const PARENT_PIN = process.env.MATH_PARENT_PIN || '1607';
const COOKIE_SECRET = process.env.MATH_COOKIE_SECRET ||
  crypto.createHash('sha256').update('math-practice-' + PARENT_PIN).digest('hex').slice(0, 32);
const COOKIE_NAME = 'math_parent';
const DATA_DIR = path.join(__dirname, 'data');
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
`);

// Migration: topic tag (finer-grained than mode, e.g. decimal_align sub-shapes)
const hasTopic = db.prepare(`SELECT COUNT(*) AS n FROM pragma_table_info('attempts') WHERE name = 'topic'`).get().n > 0;
if (!hasTopic) db.exec(`ALTER TABLE attempts ADD COLUMN topic TEXT`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_attempts_topic ON attempts(topic)`);

// Migration: daily flag (1 = attempt made inside a Daily Session, 0 = free practice)
const hasDaily = db.prepare(`SELECT COUNT(*) AS n FROM pragma_table_info('attempts') WHERE name = 'daily'`).get().n > 0;
if (!hasDaily) db.exec(`ALTER TABLE attempts ADD COLUMN daily INTEGER NOT NULL DEFAULT 0`);

const insertAttempt = db.prepare(
  `INSERT INTO attempts (ts, mode, fraction_sub, topic, problem_text, expected, given, correct, ms_taken, daily)
   VALUES (@ts, @mode, @fraction_sub, @topic, @problem_text, @expected, @given, @correct, @ms_taken, @daily)`
);

const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(cookieParser(COOKIE_SECRET));

// ---------- Caleb side: no auth ----------

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/healthz', (_req, res) => res.json({ ok: true, ts: Date.now() }));

app.post('/api/log', (req, res) => {
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
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});

// Aggregate accuracy stats for Daily Session adaptive weighting (no auth:
// exposes only counts/accuracy, no problem content). Last 30 days.
app.get('/api/topic-stats', (_req, res) => {
  const since = Date.now() - 30 * 24 * 60 * 60 * 1000;
  const byMode = db.prepare(
    `SELECT mode, COUNT(*) AS n, SUM(correct) AS got
     FROM attempts WHERE ts >= ? GROUP BY mode`
  ).all(since);
  const byTopic = db.prepare(
    `SELECT COALESCE(topic, mode) AS topic, COUNT(*) AS n, SUM(correct) AS got
     FROM attempts WHERE ts >= ? GROUP BY COALESCE(topic, mode)`
  ).all(since);
  res.json({ byMode, byTopic });
});

// ---------- Parent side: PIN-gated ----------

function isParent(req) {
  return req.signedCookies?.[COOKIE_NAME] === 'ok';
}

function requireParent(req, res, next) {
  if (!isParent(req)) return res.status(401).json({ error: 'unauthorized' });
  next();
}

app.get('/parent', (_req, res) => res.sendFile(path.join(__dirname, 'parent.html')));

app.post('/api/parent/auth', (req, res) => {
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

app.post('/api/parent/logout', (_req, res) => {
  res.clearCookie(COOKIE_NAME);
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
  let sql = 'SELECT id, ts, mode, fraction_sub, topic, problem_text, expected, given, correct, ms_taken, daily FROM attempts WHERE ts >= ?';
  const args = [since];
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[math-practice] listening on http://0.0.0.0:${PORT}  (db: ${DB_PATH})`);
});
