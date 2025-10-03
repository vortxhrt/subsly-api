/ server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { Client } from 'pg';
import { ServerClient } from 'postmark'; // using the 'postmark' package
import crypto from 'crypto';

const {
  DATABASE_URL,
  JWT_SECRET,
  MAIL_PROVIDER,
  MAIL_API_KEY,
  MAIL_FROM,
  PUBLIC_WEB_BASE,
  PUBLIC_API_BASE,
  PORT,
  DEV_ECHO_LOGIN_CODES, // "true" in dev to echo login codes
} = process.env;

// --- DB ---
const db = new Client({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
await db.connect();

// --- Mail ---
if (MAIL_PROVIDER !== 'postmark') {
  console.warn('MAIL_PROVIDER is not "postmark" (value:', MAIL_PROVIDER, ')');
}
const postmark = new ServerClient(MAIL_API_KEY);

// --- App ---
const app = express();
app.use(cors({ origin: '*', credentials: false }));
app.use(express.json());

// Helpers
const hashCode = (code) => crypto.createHash('sha256').update(code).digest('hex');
const now = () => new Date().toISOString();
const addMinutes = (m) => new Date(Date.now() + m * 60000);

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// Debug: DB ping
app.get('/debug/db', async (_req, res) => {
  try {
    const r = await db.query('select now() as now');
    res.json({ ok: true, now: r.rows[0].now });
  } catch (e) {
    console.error('DB PING ERROR:', e);
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// === Auth: request login code ===
app.post('/v1/auth/request', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = hashCode(code);
    const expiresAt = addMinutes(10).toISOString();

    await db.query(
      `INSERT INTO login_codes (email, code_hash, expires_at) VALUES ($1,$2,$3)`,
      [email.toLowerCase(), codeHash, expiresAt]
    );

    // Attempt to email (best-effort in dev)
    try {
      await postmark.sendEmail({
        From: MAIL_FROM,
        To: email,
        Subject: 'Your Subsly login code',
        TextBody: `Your code is ${code}. It expires in 10 minutes.`,
        MessageStream: 'outbound', // Postmark transactional stream
      });
    } catch (mailErr) {
      console.warn('Mail send failed (dev tolerant):', mailErr?.message || mailErr);
    }

    // DEV convenience: echo code if enabled
    const echo = (DEV_ECHO_LOGIN_CODES || '').toLowerCase() === 'true';
    if (echo) {
      console.log('[DEV] login code for', email, '=>', code);
      return res.json({ ok: true, code, expires_at: expiresAt });
    }

    return res.json({ ok: true, expires_at: expiresAt });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// === Auth: verify login code ===
app.post('/v1/auth/verify', async (req, res) => {
  try {
    const { email, code, username } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: 'Missing email or code' });

    const codeHash = hashCode(code);
    const { rows } = await db.query(
      `SELECT id, email, code_hash, expires_at, consumed_at
         FROM login_codes
        WHERE email = $1 AND code_hash = $2
        ORDER BY created_at DESC
        LIMIT 1`,
      [email.toLowerCase(), codeHash]
    );

    const row = rows[0];
    if (!row) return res.status(401).json({ error: 'Invalid code' });
    if (row.consumed_at) return res.status(401).json({ error: 'Code already used' });
    if (new Date(row.expires_at) < new Date()) return res.status(401).json({ error: 'Code expired' });

    await db.query(`UPDATE login_codes SET consumed_at = $1 WHERE id = $2`, [now(), row.id]);

    const upsert = await db.query(
      `INSERT INTO users (email, username)
       VALUES ($1, NULLIF($2, ''))
       ON CONFLICT (email)
       DO UPDATE SET username = COALESCE(users.username, EXCLUDED.username)
       RETURNING id, email, username, display_name, avatar_url, created_at`,
      [email.toLowerCase(), username ? username.toLowerCase() : null]
    );
    const user = upsert.rows[0];

    const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, user });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// === Auth middleware ===
const auth = (req, res, next) => {
  const authz = req.headers.authorization || '';
  const token = authz.startsWith('Bearer ') ? authz.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// === Start/open DM by username ===
app.post('/v1/conversations', auth, async (req, res) => {
  try {
    const { username } = req.body || {};
    if (!username) return res.status(400).json({ error: 'Missing username' });

    const target = await db.query(`SELECT id FROM users WHERE username = $1`, [username.toLowerCase()]);
    if (!target.rows[0]) return res.status(404).json({ error: 'User not found' });

    const me = req.userId;
    const them = target.rows[0].id;

    const blocked = await db.query(
      `SELECT 1 FROM blocks
        WHERE (blocker_id = $1 AND blocked_id = $2)
           OR (blocker_id = $2 AND blocked_id = $1)
        LIMIT 1`,
      [me, them]
    );
    if (blocked.rows[0]) return res.status(403).json({ error: 'Blocked' });

    const conv = await db.query(`SELECT get_or_create_conversation($1,$2) AS id`, [me, them]);
    return res.json({ conversation_id: conv.rows[0].id });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// === List messages ===
app.get('/v1/messages', auth, async (req, res) => {
  try {
    const { conversation_id, after, limit = 50 } = req.query;
    if (!conversation_id) return res.status(400).json({ error: 'Missing conversation_id' });
    const params = [conversation_id, after || '1970-01-01', Math.min(Number(limit), 100)];
    const { rows } = await db.query(
      `SELECT id, conversation_id, sender_id, kind, text, media_key, mime, nsfw, created_at
         FROM messages
        WHERE conversation_id = $1 AND created_at > $2::timestamptz
        ORDER BY created_at ASC
        LIMIT $3`,
      params
    );
    return res.json({ items: rows, nextCursor: rows.length ? rows[rows.length - 1].created_at : null });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// === Send message (text-only MVP) ===
app.post('/v1/messages', auth, async (req, res) => {
  try {
    const { conversation_id, kind, text } = req.body || {};
    if (!conversation_id) return res.status(400).json({ error: 'Missing conversation_id' });
    const k = Number(kind ?? 0);
    if (k !== 0 && !text) return res.status(400).json({ error: 'Only text supported in this MVP' });

    const { rows } = await db.query(
      `INSERT INTO messages (conversation_id, sender_id, kind, text)
       VALUES ($1, $2, $3, $4)
       RETURNING id, conversation_id, sender_id, kind, text, created_at`,
      [conversation_id, req.userId, k, text || '']
    );
    return res.json(rows[0]);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// --- Start server ---
const port = PORT || 8080; // Render provides PORT
app.listen(port, () => console.log(`Subsly API listening on ${port}`));
