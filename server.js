require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);

const fetchFn = global.fetch ? global.fetch.bind(global) : null;
if (!fetchFn) {
  console.error('❌ Node.js 18+ required (fetch).');
  process.exit(1);
}

const PORT = Number(process.env.PORT || 3000);
const NODE_ROLE = (process.env.NODE_ROLE || 'hybrid').toLowerCase();
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const AGENT_KEY = process.env.AGENT_KEY || 'change-me-agent-key';
const XRAY_BASE_PORT = parseInt(process.env.XRAY_BASE_PORT || '10086', 10);
const DB_PATH = process.env.DB_PATH || './data/configs.db';
const COOKIE_NAME = 'panel_auth';
const COOKIE_VALUE = 'authenticated';
const XRAY_CONFIG_PATH = process.env.XRAY_CONFIG_PATH || '/tmp/xray-config.json';
const XRAY_BIN = process.env.XRAY_BIN || 'xray';

if (!fs.existsSync('./data')) fs.mkdirSync('./data', { recursive: true });

const db = new sqlite3.Database(DB_PATH);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ========================= DB INIT =========================
db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON');

  db.run(`
    CREATE TABLE IF NOT EXISTS panels (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      address TEXT NOT NULL,
      is_remote INTEGER DEFAULT 0,
      api_base TEXT DEFAULT '',
      api_key TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS inbounds (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      panel_id INTEGER NOT NULL,
      remote_inbound_id TEXT DEFAULT '',
      tag TEXT DEFAULT '',
      port TEXT NOT NULL,
      protocol TEXT NOT NULL,
      host TEXT NOT NULL,
      path TEXT NOT NULL,
      tls TEXT DEFAULT 'tls',
      fp TEXT DEFAULT 'chrome',
      alpn TEXT DEFAULT 'http/1.1',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(panel_id) REFERENCES panels(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      uuid TEXT NOT NULL UNIQUE,
      sub_token TEXT UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS user_inbound_access (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      inbound_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, inbound_id),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(inbound_id) REFERENCES inbounds(id) ON DELETE CASCADE
    )
  `);

  // migration
  db.all(`PRAGMA table_info(users)`, [], (err, cols) => {
    if (err) return;
    const hasSubToken = cols.some(c => c.name === 'sub_token');
    if (!hasSubToken) {
      db.run(`ALTER TABLE users ADD COLUMN sub_token TEXT UNIQUE`);
    }
  });
});

// ========================= AUTH =========================
function requireAuth(req, res, next) {
  if (req.cookies[COOKIE_NAME] === COOKIE_VALUE) return next();
  return res.redirect('/login');
}
function requireAgent(req, res, next) {
  const key = req.headers['x-panel-key'];
  if (!key || key !== AGENT_KEY) return res.status(401).json({ error: 'Unauthorized agent' });
  next();
}

// ========================= HELPERS =========================
function isMasterEnabled() {
  return NODE_ROLE === 'master' || NODE_ROLE === 'hybrid';
}
function isAgentEnabled() {
  return NODE_ROLE === 'agent' || NODE_ROLE === 'hybrid';
}
function normalizeHost(h) { return String(h || '').split(':')[0].toLowerCase().trim(); }
function normalizePath(p) {
  p = String(p || '/').trim();
  return p.startsWith('/') ? p : '/' + p;
}
function randomPath(prefix = '/v') {
  return normalizePath(`${prefix}-${crypto.randomBytes(8).toString('hex')}`);
}
function randomTag(prefix = 'ib') {
  return `${prefix}-${crypto.randomBytes(3).toString('hex')}`;
}
function makeSubToken() {
  return crypto.randomBytes(18).toString('base64url');
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (e, r) => e ? reject(e) : resolve(r)));
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (e, r) => e ? reject(e) : resolve(r)));
}
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (e) {
      if (e) return reject(e);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

async function getPanelById(panelId) {
  return dbGet(`SELECT * FROM panels WHERE id = ?`, [panelId]);
}

function getPublicBaseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${host}`;
}

async function ensureUserSubToken(userId) {
  const u = await dbGet(`SELECT id, sub_token FROM users WHERE id = ?`, [userId]);
  if (!u) return null;
  if (u.sub_token) return u.sub_token;
  let token = makeSubToken();
  for (let i = 0; i < 5; i++) {
    try {
      await dbRun(`UPDATE users SET sub_token = ? WHERE id = ?`, [token, userId]);
      return token;
    } catch {
      token = makeSubToken();
    }
  }
  throw new Error('failed to create unique sub_token');
}

async function remoteCall(panel, method, path, body) {
  const base = String(panel.api_base || '').replace(/\/+$/, '');
  if (!base) throw new Error('Remote panel has empty api_base');
  const url = `${base}${path}`;
  const res = await fetchFn(url, {
    method,
    headers: { 'content-type': 'application/json', 'x-panel-key': panel.api_key || '' },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }
  if (!res.ok) throw new Error(data.error || data.message || `Remote ${res.status}`);
  return data;
}

function buildVlessLink(row) {
  const params = new URLSearchParams();
  params.set('encryption', 'none');
  params.set('security', row.tls || 'tls');
  params.set('sni', row.host);
  if (row.fp && row.fp !== 'none') params.set('fp', row.fp);
  if (row.alpn && row.alpn !== 'none') params.set('alpn', row.alpn);
  params.set('type', row.protocol);
  params.set('host', row.host);
  params.set('path', row.path);
  params.set('allowInsecure', '0');

  if (row.protocol === 'grpc') {
    params.delete('path');
    params.set('serviceName', row.path.replace(/^\//, ''));
  }
  if (row.protocol === 'xhttp') params.set('mode', 'auto');

  const label = `${row.username}-${row.panel_name || 'panel'}-${row.tag || ('inb' + row.inbound_id)}`;
  return `vless://${row.uuid}@${row.address}:${row.external_port}?${params.toString()}#${encodeURIComponent(label)}`;
}

async function getUserLinksByUserId(userId) {
  const rows = await dbAll(`
    SELECT
      u.username, u.uuid,
      i.id AS inbound_id, i.tag, i.protocol, i.host, i.path, i.tls, i.fp, i.alpn,
      i.port AS external_port,
      p.name AS panel_name, p.address
    FROM user_inbound_access a
    JOIN users u ON u.id = a.user_id
    JOIN inbounds i ON i.id = a.inbound_id
    JOIN panels p ON p.id = i.panel_id
    WHERE u.id = ?
    ORDER BY i.id DESC
  `, [userId]);
  return rows.map(r => buildVlessLink(r));
}

// ========================= XRAY (Local only) =========================
let xrayProcess = null;

function regenerateXrayConfigLocalOnly() {
  // Placeholder - in real deployment you would build full xray config from local inbounds
  // For now we keep the structure compatible
  try {
    if (fs.existsSync(XRAY_CONFIG_PATH)) {
      // keep existing logic light
    }
  } catch (e) {
    console.error('Xray config regenerate error:', e.message);
  }
}

function restartXray() {
  try {
    if (xrayProcess) {
      xrayProcess.kill();
      xrayProcess = null;
    }
    // In production: spawn XRAY_BIN with config
  } catch (e) {
    console.error('Xray restart error:', e.message);
  }
}

// ========================= PAGES =========================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    res.cookie(COOKIE_NAME, COOKIE_VALUE, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    return res.redirect('/dashboard');
  }
  return res.status(401).send(`
    <html dir="rtl"><body style="font-family:tahoma;text-align:center;padding:50px;background:#0f172a;color:#fff">
      <h2>نام کاربری یا رمز عبور اشتباه است</h2>
      <a href="/login" style="color:#38bdf8">بازگشت</a>
    </body></html>
  `);
});

app.get('/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect('/login');
});

// ========================= SUBSCRIPTION =========================
app.get('/sub/:token', async (req, res) => {
  try {
    const token = String(req.params.token || '').trim();
    if (!token) return res.status(400).send('bad token');
    const user = await dbGet(`SELECT id, username FROM users WHERE sub_token = ?`, [token]);
    if (!user) return res.status(404).send('not found');
    const links = await getUserLinksByUserId(user.id);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(links.join('\n'));
  } catch (e) {
    res.status(500).send('server error');
  }
});

app.get('/sub64/:token', async (req, res) => {
  try {
    const token = String(req.params.token || '').trim();
    const user = await dbGet(`SELECT id FROM users WHERE sub_token = ?`, [token]);
    if (!user) return res.status(404).send('not found');
    const links = await getUserLinksByUserId(user.id);
    const b64 = Buffer.from(links.join('\n'), 'utf8').toString('base64');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.send(b64);
  } catch {
    res.status(500).send('server error');
  }
});

// ========================= MASTER APIs =========================
if (isMasterEnabled()) {

  // ---- Stats ----
  app.get('/api/stats', requireAuth, async (req, res) => {
    try {
      const panels = await dbGet(`SELECT COUNT(*) as c FROM panels`);
      const inbounds = await dbGet(`SELECT COUNT(*) as c FROM inbounds`);
      const users = await dbGet(`SELECT COUNT(*) as c FROM users`);
      res.json({
        panels: panels?.c || 0,
        inbounds: inbounds?.c || 0,
        users: users?.c || 0
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ---- Panels CRUD ----
  app.get('/api/panels', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`SELECT * FROM panels ORDER BY id DESC`);
      res.json(rows);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/panels', requireAuth, async (req, res) => {
    try {
      const { name, address, is_remote, api_base, api_key } = req.body;
      if (!name || !address) return res.status(400).json({ error: 'name and address are required' });
      const remote = Number(is_remote || 0) ? 1 : 0;
      const ins = await dbRun(
        `INSERT INTO panels (name, address, is_remote, api_base, api_key) VALUES (?, ?, ?, ?, ?)`,
        [String(name).trim(), String(address).trim(), remote, api_base || '', api_key || '']
      );
      res.json({ success: true, id: ins.lastID });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.put('/api/panels/:id', requireAuth, async (req, res) => {
    try {
      const id = Number(req.params.id);
      const { name, address, is_remote, api_base, api_key } = req.body;
      if (!name || !address) return res.status(400).json({ error: 'name and address are required' });
      const remote = Number(is_remote || 0) ? 1 : 0;
      const result = await dbRun(
        `UPDATE panels SET name=?, address=?, is_remote=?, api_base=?, api_key=? WHERE id=?`,
        [String(name).trim(), String(address).trim(), remote, api_base || '', api_key || '', id]
      );
      if (result.changes === 0) return res.status(404).json({ error: 'panel not found' });
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.delete('/api/panels/:id', requireAuth, async (req, res) => {
    try {
      const id = Number(req.params.id);
      const result = await dbRun(`DELETE FROM panels WHERE id=?`, [id]);
      if (result.changes === 0) return res.status(404).json({ error: 'panel not found' });
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ---- Inbounds CRUD ----
  app.get('/api/inbounds', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`
        SELECT i.*, p.name AS panel_name, p.address AS panel_address, p.is_remote
        FROM inbounds i
        JOIN panels p ON p.id = i.panel_id
        ORDER BY i.id DESC
      `);
      res.json(rows);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/panels/:panelId/inbounds', requireAuth, async (req, res) => {
    try {
      const panelId = Number(req.params.panelId);
      let { tag, port, protocol, host, path: inPath, tls, fp, alpn } = req.body;

      if (!port || !protocol || !host || !inPath) {
        return res.status(400).json({ error: 'port, protocol, host, path are required' });
      }

      const allowedProtocols = ['ws', 'grpc', 'xhttp', 'tcp', 'http', 'h2'];
      if (!allowedProtocols.includes(protocol)) {
        return res.status(400).json({ error: 'protocol not supported' });
      }

      inPath = normalizePath(inPath);
      if (alpn === 'h2' || alpn === 'h3') {
        // keep as is
      }

      const panel = await getPanelById(panelId);
      if (!panel) return res.status(404).json({ error: 'panel not found' });

      let remoteInboundId = '';
      if (Number(panel.is_remote) === 1) {
        const r = await remoteCall(panel, 'POST', '/agent/inbounds', {
          tag: tag || '', port: String(port), protocol, host: String(host).trim(),
          path: inPath, tls: tls || 'tls', fp: fp || 'chrome', alpn: alpn || 'http/1.1'
        });
        remoteInboundId = String(r.remote_inbound_id || r.id || '');
      }

      const ins = await dbRun(
        `INSERT INTO inbounds (panel_id, remote_inbound_id, tag, port, protocol, host, path, tls, fp, alpn)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [panelId, remoteInboundId, tag || randomTag(), String(port), protocol,
         String(host).trim(), inPath, tls || 'tls', fp || 'chrome', alpn || 'http/1.1']
      );

      if (Number(panel.is_remote) === 0) {
        regenerateXrayConfigLocalOnly();
        restartXray();
      }

      res.json({ success: true, id: ins.lastID });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.put('/api/inbounds/:id', requireAuth, async (req, res) => {
    try {
      const id = Number(req.params.id);
      let { tag, port, protocol, host, path: inPath, tls, fp, alpn } = req.body;

      if (!port || !protocol || !host || !inPath) {
        return res.status(400).json({ error: 'port, protocol, host, path are required' });
      }

      inPath = normalizePath(inPath);

      const result = await dbRun(
        `UPDATE inbounds SET tag=?, port=?, protocol=?, host=?, path=?, tls=?, fp=?, alpn=? WHERE id=?`,
        [tag || '', String(port), protocol, String(host).trim(), inPath,
         tls || 'tls', fp || 'chrome', alpn || 'http/1.1', id]
      );

      if (result.changes === 0) return res.status(404).json({ error: 'inbound not found' });
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.delete('/api/inbounds/:id', requireAuth, async (req, res) => {
    try {
      const id = Number(req.params.id);
      const result = await dbRun(`DELETE FROM inbounds WHERE id=?`, [id]);
      if (result.changes === 0) return res.status(404).json({ error: 'inbound not found' });
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Anti-filter Preset
  app.post('/api/panels/:panelId/inbounds/preset-anti-filter', requireAuth, async (req, res) => {
    try {
      const panelId = Number(req.params.panelId);
      const panel = await getPanelById(panelId);
      if (!panel) return res.status(404).json({ error: 'panel not found' });

      const { host, port = '443', tls = 'tls', fp = 'chrome', alpn = 'http/1.1', tagPrefix = 'af' } = req.body;
      if (!host) return res.status(400).json({ error: 'host is required' });

      const presets = [
        { protocol: 'ws', path: randomPath('/ws'), tag: randomTag(`${tagPrefix}-ws`) },
        { protocol: 'grpc', path: randomPath('/grpc'), tag: randomTag(`${tagPrefix}-grpc`) },
        { protocol: 'xhttp', path: randomPath('/xhttp'), tag: randomTag(`${tagPrefix}-xhttp`) },
      ];

      const created = [];
      for (const p of presets) {
        let remoteInboundId = '';
        if (Number(panel.is_remote) === 1) {
          const r = await remoteCall(panel, 'POST', '/agent/inbounds', {
            tag: p.tag, port: String(port), protocol: p.protocol, host: String(host).trim(),
            path: p.path, tls, fp, alpn
          });
          remoteInboundId = String(r.remote_inbound_id || r.id || '');
        }

        const ins = await dbRun(
          `INSERT INTO inbounds (panel_id, remote_inbound_id, tag, port, protocol, host, path, tls, fp, alpn)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [panelId, remoteInboundId, p.tag, String(port), p.protocol, String(host).trim(), p.path, tls, fp, alpn]
        );
        created.push({ id: ins.lastID, ...p, host, port: String(port), tls, fp, alpn });
      }

      if (Number(panel.is_remote) === 0) {
        regenerateXrayConfigLocalOnly();
        restartXray();
      }

      res.json({ success: true, created });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ---- Users CRUD ----
  app.get('/api/users', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`SELECT * FROM users ORDER BY id DESC`);
      res.json(rows);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/api/users-with-access', requireAuth, async (req, res) => {
    try {
      const users = await dbAll(`SELECT * FROM users ORDER BY id DESC`);
      const result = [];
      for (const u of users) {
        const access = await dbAll(`
          SELECT i.id, i.tag, i.protocol, i.port, p.name as panel_name
          FROM user_inbound_access a
          JOIN inbounds i ON i.id = a.inbound_id
          JOIN panels p ON p.id = i.panel_id
          WHERE a.user_id = ?
        `, [u.id]);
        result.push({ ...u, access });
      }
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/users', requireAuth, async (req, res) => {
    try {
      const { username, uuid } = req.body;
      if (!username || !uuid) return res.status(400).json({ error: 'username and uuid are required' });
      const ins = await dbRun(
        `INSERT INTO users (username, uuid, sub_token) VALUES (?, ?, ?)`,
        [String(username).trim(), String(uuid).trim(), makeSubToken()]
      );
      res.json({ success: true, id: ins.lastID });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.put('/api/users/:id', requireAuth, async (req, res) => {
    try {
      const id = Number(req.params.id);
      const { username, uuid } = req.body;
      if (!username || !uuid) return res.status(400).json({ error: 'username and uuid are required' });
      const result = await dbRun(
        `UPDATE users SET username=?, uuid=? WHERE id=?`,
        [String(username).trim(), String(uuid).trim(), id]
      );
      if (result.changes === 0) return res.status(404).json({ error: 'user not found' });
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.delete('/api/users/:id', requireAuth, async (req, res) => {
    try {
      const id = Number(req.params.id);
      const result = await dbRun(`DELETE FROM users WHERE id=?`, [id]);
      if (result.changes === 0) return res.status(404).json({ error: 'user not found' });
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Assign inbounds to user
  app.patch('/api/users/:userId/inbounds', requireAuth, async (req, res) => {
    try {
      const userId = Number(req.params.userId);
      const { inboundIds } = req.body;
      if (!Array.isArray(inboundIds)) return res.status(400).json({ error: 'inboundIds must be array' });

      await dbRun(`DELETE FROM user_inbound_access WHERE user_id = ?`, [userId]);
      for (const iid of inboundIds) {
        await dbRun(
          `INSERT OR IGNORE INTO user_inbound_access (user_id, inbound_id) VALUES (?, ?)`,
          [userId, Number(iid)]
        );
      }
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/users/:userId/reset-sub-token', requireAuth, async (req, res) => {
    try {
      const userId = Number(req.params.userId);
      const token = makeSubToken();
      await dbRun(`UPDATE users SET sub_token = ? WHERE id = ?`, [token, userId]);
      res.json({ success: true, sub_token: token });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // Quick add user on panel
  app.post('/api/panels/:panelId/users/quick-add', requireAuth, async (req, res) => {
    try {
      const panelId = Number(req.params.panelId);
      const { username, uuid, onlyTagPrefix = '' } = req.body;
      if (!username || !uuid) return res.status(400).json({ error: 'username and uuid are required' });

      let user = await dbGet(`SELECT * FROM users WHERE uuid = ?`, [String(uuid).trim()]);
      if (!user) {
        const insU = await dbRun(
          `INSERT INTO users (username, uuid, sub_token) VALUES (?, ?, ?)`,
          [String(username).trim(), String(uuid).trim(), makeSubToken()]
        );
        user = await dbGet(`SELECT * FROM users WHERE id = ?`, [insU.lastID]);
      }

      let inbounds = await dbAll(`SELECT id, tag FROM inbounds WHERE panel_id = ?`, [panelId]);
      if (onlyTagPrefix) {
        inbounds = inbounds.filter(i => (i.tag || '').startsWith(onlyTagPrefix));
      }

      for (const ib of inbounds) {
        await dbRun(
          `INSERT OR IGNORE INTO user_inbound_access (user_id, inbound_id) VALUES (?, ?)`,
          [user.id, ib.id]
        );
      }

      const links = await getUserLinksByUserId(user.id);
      res.json({ success: true, user, links });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

// ========================= AGENT APIs =========================
if (isAgentEnabled()) {
  app.get('/agent/health', requireAgent, (req, res) => {
    res.json({ ok: true, role: NODE_ROLE });
  });

  app.post('/agent/inbounds', requireAgent, async (req, res) => {
    try {
      const { tag, port, protocol, host, path: inPath, tls, fp, alpn } = req.body;
      // In real agent mode, this would configure local xray
      // For now we just acknowledge
      res.json({ success: true, remote_inbound_id: randomTag('remote') });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });
}

// ========================= START =========================
server.listen(PORT, () => {
  console.log(`🚀 ISSPanel Redesign running on port ${PORT}`);
  console.log(`   Role: ${NODE_ROLE}`);
  console.log(`   Admin: ${ADMIN_USER}`);
});
