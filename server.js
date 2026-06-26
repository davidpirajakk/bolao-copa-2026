const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const JOGOS_DATA = require('./public/jogos.js'); // fonte única de jogos (compartilhada com o cliente)

const app = express();
app.use(express.json());

// ===== DATABASE =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        username_lower TEXT NOT NULL UNIQUE,
        hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        player_id INTEGER NOT NULL,
        campeao TEXT
      )
    `);
    // Migration: add campeao column if table already exists without it
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS campeao TEXT`);
    // Migration: created_at — usuários existentes ficam ANTES do prazo (travados);
    // novos cadastros recebem NOW() automaticamente e podem escolher o campeão.
    await client.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ`);
    await client.query(`UPDATE users SET created_at = '2026-06-01T00:00:00Z' WHERE created_at IS NULL`);
    await client.query(`ALTER TABLE users ALTER COLUMN created_at SET DEFAULT NOW()`);
    // Migration: origem do resultado — 'manual' (admin) nunca é sobrescrito pelas APIs
    await client.query(`ALTER TABLE resultados ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'api'`);
    // Migration: aposta extra do mata-mata (só vale quando o palpite é empate)
    await client.query(`ALTER TABLE palpites ADD COLUMN IF NOT EXISTS prorrogacao BOOLEAN DEFAULT FALSE`);
    await client.query(`ALTER TABLE palpites ADD COLUMN IF NOT EXISTS penaltis BOOLEAN DEFAULT FALSE`);
    await client.query(`ALTER TABLE palpites ADD COLUMN IF NOT EXISTS classificado INTEGER`);
    await client.query(`ALTER TABLE resultados ADD COLUMN IF NOT EXISTS classificado INTEGER`);
    // Jogos do mata-mata descobertos automaticamente via ESPN
    await client.query(`
      CREATE TABLE IF NOT EXISTS mata_jogos (
        id INTEGER PRIMARY KEY,
        espn_id TEXT UNIQUE NOT NULL,
        fase TEXT NOT NULL,
        data TEXT NOT NULL,
        hora TEXT NOT NULL,
        time1 TEXT NOT NULL,
        time2 TEXT NOT NULL
      )
    `);
    // Garante sequência para IDs de mata_jogos a partir de 1000
    await client.query(`
      CREATE SEQUENCE IF NOT EXISTS mata_jogos_seq START 1000 MINVALUE 1000
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS players (
        id SERIAL PRIMARY KEY,
        nome TEXT NOT NULL
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS palpites (
        player_id INTEGER NOT NULL,
        jogo_id INTEGER NOT NULL,
        g1 INTEGER NOT NULL,
        g2 INTEGER NOT NULL,
        PRIMARY KEY (player_id, jogo_id)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS resultados (
        jogo_id INTEGER PRIMARY KEY,
        g1 INTEGER NOT NULL,
        g2 INTEGER NOT NULL,
        overtime BOOLEAN DEFAULT FALSE,
        penalties BOOLEAN DEFAULT FALSE
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS live_status (
        jogo_id INTEGER PRIMARY KEY,
        status TEXT NOT NULL
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    `);
    console.log('✅ Banco de dados inicializado');
  } finally {
    client.release();
  }
}

async function getState() {
  const [playersR, palpitesR, resultadosR, liveR, settingsR, campeaoRealR, mataJogosR] = await Promise.all([
    pool.query('SELECT id, nome FROM players ORDER BY id'),
    pool.query('SELECT player_id, jogo_id, g1, g2, prorrogacao, penaltis, classificado FROM palpites'),
    pool.query('SELECT jogo_id, g1, g2, overtime, penalties, classificado FROM resultados'),
    pool.query('SELECT jogo_id, status FROM live_status'),
    pool.query("SELECT value FROM settings WHERE key = 'api_key'"),
    pool.query("SELECT value FROM settings WHERE key = 'campeao_real'"),
    pool.query('SELECT id, fase, data, hora, time1, time2 FROM mata_jogos ORDER BY id'),
  ]);

  const palpites = {};
  for (const row of palpitesR.rows) {
    const pid = String(row.player_id);
    if (!palpites[pid]) palpites[pid] = {};
    palpites[pid][String(row.jogo_id)] = { g1: row.g1, g2: row.g2, prorrogacao: row.prorrogacao, penaltis: row.penaltis, classificado: row.classificado };
  }

  const resultados = {};
  for (const row of resultadosR.rows) {
    resultados[String(row.jogo_id)] = { g1: row.g1, g2: row.g2, overtime: row.overtime, penalties: row.penalties, classificado: row.classificado };
  }

  const liveStatus = {};
  for (const row of liveR.rows) {
    liveStatus[String(row.jogo_id)] = row.status;
  }

  const campeaoR = await pool.query('SELECT player_id, campeao FROM users WHERE campeao IS NOT NULL');
  const campeoes = {};
  for (const row of campeaoR.rows) {
    campeoes[String(row.player_id)] = row.campeao;
  }

  return {
    players: playersR.rows,
    palpites,
    resultados,
    liveStatus,
    campeoes,
    campeaoReal: campeaoRealR.rows.length ? campeaoRealR.rows[0].value : null,
    hasApiKey: settingsR.rows.length > 0 && !!settingsR.rows[0].value,
    mataJogos: mataJogosR.rows,
  };
}

async function getApiKey() {
  const r = await pool.query("SELECT value FROM settings WHERE key = 'api_key'");
  return r.rows.length ? r.rows[0].value : null;
}

// ===== AUTH =====
const SESSION_SECRET = process.env.SESSION_SECRET || (() => {
  console.warn('⚠️  SESSION_SECRET não definido — defina no Railway em Variables.');
  return crypto.randomBytes(32).toString('hex');
})();

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}

function verifyPassword(password, hash, salt) {
  try {
    const verify = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(verify, 'hex'));
  } catch { return false; }
}

function createToken(userId) {
  const payload = `${userId}|${Date.now()}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
  return Buffer.from(`${payload}|${sig}`).toString('base64url');
}

function verifyToken(token) {
  if (!token) return null;
  try {
    const decoded = Buffer.from(token, 'base64url').toString();
    const lastPipe = decoded.lastIndexOf('|');
    const payload = decoded.substring(0, lastPipe);
    const sig = decoded.substring(lastPipe + 1);
    const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('hex');
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
    const userId = parseInt(payload.split('|')[0]);
    return isNaN(userId) ? null : userId;
  } catch { return null; }
}

function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const idx = c.indexOf('=');
    if (idx < 0) return;
    cookies[c.slice(0, idx).trim()] = decodeURIComponent(c.slice(idx + 1).trim());
  });
  return cookies;
}

async function getAuthUser(req) {
  const token = parseCookies(req).bolao_session;
  const userId = verifyToken(token);
  if (!userId) return null;
  const r = await pool.query('SELECT id, username, player_id FROM users WHERE id = $1', [userId]);
  if (!r.rows.length) return null;
  const u = r.rows[0];
  return { id: u.id, username: u.username, playerId: u.player_id };
}

function requireAuth(req, res, next) {
  getAuthUser(req).then(user => {
    if (!user) return res.redirect('/');
    req.user = user;
    next();
  }).catch(() => res.redirect('/'));
}

function requireAdmin(req, res, next) {
  getAuthUser(req).then(user => {
    const ADMIN = (process.env.ADMIN_USERNAME || 'david').toLowerCase();
    if (!user || user.username.toLowerCase() !== ADMIN) return res.status(403).json({ error: 'Acesso negado' });
    req.user = user;
    next();
  }).catch(() => res.status(403).json({ error: 'Acesso negado' }));
}

const COOKIE_OPTS = { httpOnly: true, sameSite: 'lax', maxAge: 30 * 24 * 60 * 60 * 1000 };

// ===== SSE =====
const clients = new Set();

async function broadcast() {
  if (clients.size === 0) return;
  try {
    const state = await getState();
    const msg = `data: ${JSON.stringify(state)}\n\n`;
    clients.forEach(res => {
      try { res.write(msg); } catch (_) { clients.delete(res); }
    });
  } catch (e) {
    console.error('[broadcast] erro:', e.message);
  }
}

// ===== STATIC =====
app.get('/', async (req, res) => {
  const user = await getAuthUser(req);
  if (user) return res.redirect('/app');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/app', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

// ===== AUTH ROUTES =====
app.post('/api/auth/register', async (req, res) => {
  const username = (req.body.username || '').trim().substring(0, 30);
  const password = req.body.password || '';

  if (username.length < 2) return res.status(400).json({ error: 'Nome muito curto (mínimo 2 caracteres)' });
  if (password.length < 4) return res.status(400).json({ error: 'Senha muito curta (mínimo 4 caracteres)' });

  const existing = await pool.query('SELECT id FROM users WHERE username_lower = $1', [username.toLowerCase()]);
  if (existing.rows.length) return res.status(400).json({ error: 'Este nome já está sendo usado' });

  const { hash, salt } = hashPassword(password);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const playerR = await client.query('INSERT INTO players (nome) VALUES ($1) RETURNING id', [username]);
    const playerId = playerR.rows[0].id;
    const userR = await client.query(
      'INSERT INTO users (username, username_lower, hash, salt, player_id) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [username, username.toLowerCase(), hash, salt, playerId]
    );
    await client.query('COMMIT');
    const token = createToken(userR.rows[0].id);
    res.cookie('bolao_session', token, COOKIE_OPTS);
    broadcast();
    res.json({ ok: true, username, playerId });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('[register] erro:', e.message);
    res.status(500).json({ error: 'Erro ao criar conta' });
  } finally {
    client.release();
  }
});

app.post('/api/auth/login', async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  const r = await pool.query('SELECT id, username, hash, salt, player_id FROM users WHERE username_lower = $1', [username.toLowerCase()]);
  const user = r.rows[0];
  if (!user || !verifyPassword(password, user.hash, user.salt)) {
    return res.status(401).json({ error: 'Usuário ou senha incorretos' });
  }

  const token = createToken(user.id);
  res.cookie('bolao_session', token, COOKIE_OPTS);
  res.json({ ok: true, username: user.username, playerId: user.player_id });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('bolao_session');
  res.json({ ok: true });
});

app.get('/api/auth/me', async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: 'Não autenticado' });
  const ADMIN = (process.env.ADMIN_USERNAME || 'david').toLowerCase();
  const r = await pool.query('SELECT campeao, created_at FROM users WHERE id = $1', [user.id]);
  const campeao = r.rows[0]?.campeao || null;
  res.json({ id: user.id, username: user.username, playerId: user.playerId, isAdmin: user.username.toLowerCase() === ADMIN, campeao, canPickCampeao: canPickCampeao(r.rows[0]?.created_at) });
});

const CAMPEAO_LOCK = new Date(Date.UTC(2026, 5, 11, 18, 0)); // 11/jun 15h BRT = 18h UTC

// Pode escolher o campeão se: antes do prazo global, OU se cadastrou depois do prazo (entrada atrasada)
function canPickCampeao(createdAt) {
  if (Date.now() < CAMPEAO_LOCK.getTime()) return true;
  return createdAt && new Date(createdAt).getTime() >= CAMPEAO_LOCK.getTime();
}

app.put('/api/campeao', async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ error: 'Não autenticado' });
  const campeao = (req.body.campeao || '').trim();
  if (!campeao) return res.status(400).json({ error: 'Seleção inválida' });
  const existing = await pool.query('SELECT campeao, created_at FROM users WHERE id = $1', [user.id]);
  if (!canPickCampeao(existing.rows[0]?.created_at)) {
    return res.status(400).json({ error: 'Prazo encerrado. As apostas do campeão fecharam 1h antes do início da Copa.' });
  }
  if (existing.rows[0]?.campeao) return res.status(400).json({ error: 'Você já fez sua aposta. Não é possível alterar.' });
  await pool.query('UPDATE users SET campeao = $1 WHERE id = $2', [campeao, user.id]);
  broadcast();
  res.json({ ok: true });
});

// Admin: definir/alterar campeão de um jogador (ignora o prazo de bloqueio)
app.put('/api/admin/campeao/:playerId', requireAdmin, async (req, res) => {
  const playerId = parseInt(req.params.playerId);
  const campeao = (req.body.campeao || '').trim();
  if (isNaN(playerId)) return res.status(400).json({ error: 'Jogador inválido' });
  if (!campeao) return res.status(400).json({ error: 'Seleção inválida' });
  const upd = await pool.query('UPDATE users SET campeao = $1 WHERE player_id = $2 RETURNING id, username', [campeao, playerId]);
  if (!upd.rows.length) return res.status(404).json({ error: 'Jogador não encontrado' });
  broadcast();
  res.json({ ok: true, username: upd.rows[0].username, campeao });
});

// ===== API ROUTES =====
app.get('/api/state', async (req, res) => res.json(await getState()));

// Admin: exportar backup completo (sem senhas)
app.get('/api/admin/export', requireAdmin, async (req, res) => {
  const [usersR, playersR, palpitesR, resultadosR] = await Promise.all([
    pool.query('SELECT id, username, player_id, campeao FROM users ORDER BY id'),
    pool.query('SELECT id, nome FROM players ORDER BY id'),
    pool.query('SELECT player_id, jogo_id, g1, g2 FROM palpites ORDER BY player_id, jogo_id'),
    pool.query('SELECT jogo_id, g1, g2, overtime, penalties FROM resultados ORDER BY jogo_id'),
  ]);
  const backup = {
    exportedAt: new Date().toISOString(),
    counts: {
      usuarios: usersR.rows.length,
      palpites: palpitesR.rows.length,
      resultados: resultadosR.rows.length,
    },
    users: usersR.rows,
    players: playersR.rows,
    palpites: palpitesR.rows,
    resultados: resultadosR.rows,
  };
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="backup-bolao-${stamp}.json"`);
  res.send(JSON.stringify(backup, null, 2));
});

// Admin: listar usuários
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const r = await pool.query('SELECT u.id, u.username, p.nome, p.id as player_id FROM users u JOIN players p ON p.id = u.player_id ORDER BY u.id');
  res.json(r.rows);
});

// Admin: redefinir senha de usuário
app.put('/api/admin/reset-senha/:id', requireAdmin, async (req, res) => {
  const userId = parseInt(req.params.id);
  const { senha } = req.body;
  if (!senha || senha.trim().length < 4) return res.status(400).json({ error: 'Senha muito curta (mínimo 4 caracteres)' });
  try {
    const { hash, salt } = hashPassword(senha.trim());
    const r = await pool.query('UPDATE users SET hash = $1, salt = $2 WHERE id = $3 RETURNING id', [hash, salt, userId]);
    if (!r.rowCount) return res.status(404).json({ error: 'Usuário não encontrado' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Erro ao redefinir senha' });
  }
});

// Admin: criar jogo de mata-mata manualmente
app.post('/api/admin/mata-jogos', requireAdmin, async (req, res) => {
  const { time1, time2, data, hora, fase } = req.body;
  if (!time1 || !time2) return res.status(400).json({ error: 'time1 e time2 obrigatórios' });
  try {
    const newId = (await pool.query(`SELECT nextval('mata_jogos_seq') AS id`)).rows[0].id;
    const r = await pool.query(
      `INSERT INTO mata_jogos (id, time1, time2, data, hora, fase) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [newId, time1, time2, data || '??/??', hora || '??:??', fase || 'Mata-mata']
    );
    mataJogosCache = null;
    broadcastState();
    res.json({ ok: true, jogo: r.rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: apagar usuário e seu player
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const userId = parseInt(req.params.id);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const u = await client.query('SELECT player_id FROM users WHERE id = $1', [userId]);
    if (!u.rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Usuário não encontrado' }); }
    const playerId = u.rows[0].player_id;
    await client.query('DELETE FROM palpites WHERE player_id = $1', [playerId]);
    await client.query('DELETE FROM users WHERE id = $1', [userId]);
    await client.query('DELETE FROM players WHERE id = $1', [playerId]);
    await client.query('COMMIT');
    broadcast();
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get('/api/events', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  clients.add(res);
  try {
    const state = await getState();
    res.write(`data: ${JSON.stringify(state)}\n\n`);
  } catch (_) {}

  const hb = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (_) { clearInterval(hb); clients.delete(res); }
  }, 25000);

  req.on('close', () => { clearInterval(hb); clients.delete(res); });
});

app.put('/api/palpites/:playerId/:jogoId', async (req, res) => {
  const playerId = parseInt(req.params.playerId);
  const jogoId = parseInt(req.params.jogoId);
  const g1 = parseInt(req.body.g1);
  const g2 = parseInt(req.body.g2);

  if (isNaN(g1) || isNaN(g2) || g1 < 0 || g2 < 0 || g1 > 20 || g2 > 20)
    return res.status(400).json({ error: 'Placar inválido' });

  if (await isGameLockedAsync(jogoId)) return res.status(400).json({ error: 'Palpites encerrados (menos de 1h para o jogo)' });

  const hasResult = await pool.query('SELECT 1 FROM resultados WHERE jogo_id = $1', [jogoId]);
  if (hasResult.rows.length) return res.status(400).json({ error: 'Jogo já encerrado' });

  // Apostas extras do mata-mata — só valem quando o palpite é empate
  const empate = g1 === g2;
  const prorrogacao = empate && !!req.body.prorrogacao;
  const penaltis = empate && !!req.body.penaltis;
  const classificado = empate && [1, 2].includes(parseInt(req.body.classificado)) ? parseInt(req.body.classificado) : null;

  await pool.query(
    `INSERT INTO palpites (player_id, jogo_id, g1, g2, prorrogacao, penaltis, classificado) VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (player_id, jogo_id) DO UPDATE SET g1 = $3, g2 = $4, prorrogacao = $5, penaltis = $6, classificado = $7`,
    [playerId, jogoId, g1, g2, prorrogacao, penaltis, classificado]
  );
  broadcast();
  res.json({ ok: true });
});

// Admin: lançar/corrigir palpite ignorando a trava de tempo (ex: palpite perdido por bug)
app.put('/api/admin/palpite/:playerId/:jogoId', requireAdmin, async (req, res) => {
  const playerId = parseInt(req.params.playerId);
  const jogoId = parseInt(req.params.jogoId);
  const g1 = parseInt(req.body.g1);
  const g2 = parseInt(req.body.g2);
  if (isNaN(g1) || isNaN(g2) || g1 < 0 || g2 < 0 || g1 > 20 || g2 > 20)
    return res.status(400).json({ error: 'Placar inválido' });
  const empate = g1 === g2;
  const prorrogacao = empate && !!req.body.prorrogacao;
  const penaltis = empate && !!req.body.penaltis;
  const classificado = empate && [1, 2].includes(parseInt(req.body.classificado)) ? parseInt(req.body.classificado) : null;
  await pool.query(
    `INSERT INTO palpites (player_id, jogo_id, g1, g2, prorrogacao, penaltis, classificado) VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (player_id, jogo_id) DO UPDATE SET g1 = $3, g2 = $4, prorrogacao = $5, penaltis = $6, classificado = $7`,
    [playerId, jogoId, g1, g2, prorrogacao, penaltis, classificado]
  );
  broadcast();
  res.json({ ok: true });
});

app.put('/api/results/:jogoId', requireAdmin, async (req, res) => {
  const jogoId = parseInt(req.params.jogoId);
  const g1 = parseInt(req.body.g1);
  const g2 = parseInt(req.body.g2);
  const overtime = !!req.body.overtime;
  const penalties = !!req.body.penalties;
  const classificado = [1, 2].includes(parseInt(req.body.classificado)) ? parseInt(req.body.classificado) : null;

  if (isNaN(g1) || isNaN(g2) || g1 < 0 || g2 < 0 || g1 > 20 || g2 > 20)
    return res.status(400).json({ error: 'Placar inválido' });

  await pool.query(
    `INSERT INTO resultados (jogo_id, g1, g2, overtime, penalties, classificado, source) VALUES ($1, $2, $3, $4, $5, $6, 'manual')
     ON CONFLICT (jogo_id) DO UPDATE SET g1 = $2, g2 = $3, overtime = $4, penalties = $5, classificado = $6, source = 'manual'`,
    [jogoId, g1, g2, overtime, penalties, classificado]
  );
  broadcast();
  res.json({ ok: true });
});

app.delete('/api/results/:jogoId', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM resultados WHERE jogo_id = $1', [parseInt(req.params.jogoId)]);
  broadcast();
  res.json({ ok: true });
});

// Admin: marcar jogo como finalizado (ou reabrir)
app.put('/api/finish/:jogoId', requireAdmin, async (req, res) => {
  const jogoId = parseInt(req.params.jogoId);
  if (isNaN(jogoId)) return res.status(400).json({ error: 'Jogo inválido' });
  const status = req.body.finished === false ? 'TIMED' : 'FINISHED';
  await pool.query(
    'INSERT INTO live_status (jogo_id, status) VALUES ($1, $2) ON CONFLICT (jogo_id) DO UPDATE SET status = $2',
    [jogoId, status]
  );
  broadcast();
  res.json({ ok: true, status });
});

app.put('/api/settings/campeao-real', requireAdmin, async (req, res) => {
  const campeao = (req.body.campeao || '').trim();
  if (!campeao) return res.status(400).json({ error: 'Seleção inválida' });
  await pool.query(
    "INSERT INTO settings (key, value) VALUES ('campeao_real', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
    [campeao]
  );
  broadcast();
  res.json({ ok: true });
});

app.put('/api/settings/apikey', requireAdmin, async (req, res) => {
  const key = (req.body.key || '').trim();
  if (!key) return res.status(400).json({ error: 'Chave inválida' });
  await pool.query(
    "INSERT INTO settings (key, value) VALUES ('api_key', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
    [key]
  );
  res.json({ ok: true });
});

// ===== GAME TIME LOCK =====
// Derivado da fonte única (public/jogos.js) — sem duplicação de datas.
const JOGOS_TIMES = Object.fromEntries(JOGOS_DATA.map(j => [j.id, [j.data, j.hora]]));

const MONTH_MAP_SRV = {jan:1,fev:2,mar:3,abr:4,mai:5,jun:6,jul:7,ago:8,set:9,out:10,nov:11,dez:12};
function parseGameTime(data, hora) {
  if (!hora || hora === '—') return null;
  const horMatch = hora.match(/^(\d+)h(\d+)?$/);
  if (!horMatch) return null;
  const h = parseInt(horMatch[1]);
  const m = parseInt(horMatch[2] || '0');
  const dataPart = data.split('–')[0];
  const dateMatch = dataPart.match(/^(\d+)\/(\w+)$/);
  if (!dateMatch) return null;
  const day = parseInt(dateMatch[1]);
  const mon = MONTH_MAP_SRV[dateMatch[2]];
  if (!mon) return null;
  // Games are in BRT (UTC-3); convert to UTC by adding 3h
  return new Date(Date.UTC(2026, mon - 1, day, h + 3, m));
}

// Cache em memória dos mata_jogos para isGameLocked
const mataJogosCache = {};
async function getMataJogoTime(jogoId) {
  if (mataJogosCache[jogoId]) return mataJogosCache[jogoId];
  const r = await pool.query('SELECT data, hora FROM mata_jogos WHERE id = $1', [jogoId]);
  if (r.rows.length) mataJogosCache[jogoId] = [r.rows[0].data, r.rows[0].hora];
  return mataJogosCache[jogoId] || null;
}

function isGameLocked(jogoId) {
  const times = JOGOS_TIMES[jogoId];
  if (!times) return false; // mata_jogos checam separado (async)
  const gameTime = parseGameTime(times[0], times[1]);
  if (!gameTime) return false;
  return Date.now() >= gameTime.getTime() - 60 * 60 * 1000; // 1h before
}

async function isGameLockedAsync(jogoId) {
  if (JOGOS_TIMES[jogoId]) return isGameLocked(jogoId);
  // mata_jogos
  const times = await getMataJogoTime(jogoId);
  if (!times) return false;
  const gameTime = parseGameTime(times[0], times[1]);
  if (!gameTime) return false;
  return Date.now() >= gameTime.getTime() - 60 * 60 * 1000;
}

// ===== FOOTBALL-DATA SYNC =====
const API_NAME_MAP = {
  'Mexico':'México','South Africa':'África do Sul','South Korea':'Coreia do Sul',
  'Czech Republic':'Rep. Tcheca','Canada':'Canadá','Bosnia and Herzegovina':'Bósnia-Herz.',
  'United States':'Estados Unidos','Paraguay':'Paraguai','Australia':'Austrália',
  'Turkey':'Turquia','Qatar':'Catar','Switzerland':'Suíça','Brazil':'Brasil',
  'Morocco':'Marrocos','Haiti':'Haiti','Scotland':'Escócia','Germany':'Alemanha',
  'Curaçao':'Curaçao','Ivory Coast':'Costa do Marfim','Ecuador':'Equador',
  'Netherlands':'Holanda','Japan':'Japão','Sweden':'Suécia','Tunisia':'Tunísia',
  'Spain':'Espanha','Cape Verde':'Cabo Verde','Saudi Arabia':'Arábia Saudita',
  'Uruguay':'Uruguai','Belgium':'Bélgica','Egypt':'Egito','Iran':'Irã',
  'New Zealand':'Nova Zelândia','Austria':'Áustria','Jordan':'Jordânia',
  'France':'França','Senegal':'Senegal','Iraq':'Iraque','Norway':'Noruega',
  'Argentina':'Argentina','Algeria':'Argélia','Portugal':'Portugal',
  'DR Congo':'Congo (RD)','Uzbekistan':'Uzbequistão','Colombia':'Colômbia',
  'England':'Inglaterra','Croatia':'Croácia','Ghana':'Gana','Panama':'Panamá',
};

const JOGOS_MAP = Object.fromEntries(
  JOGOS_DATA.filter(j => j.time1 !== 'A definir' && j.time2 !== 'A definir')
           .map(j => [`${j.time1}|${j.time2}`, j.id])
);

async function doSync() {
  const apiKey = await getApiKey();
  if (!apiKey) return 0;

  const apiRes = await fetch('https://api.football-data.org/v4/competitions/WC/matches?season=2026', {
    headers: { 'X-Auth-Token': apiKey }
  });
  if (!apiRes.ok) return 0;
  const data = await apiRes.json();

  let updated = 0;
  for (const m of (data.matches || [])) {
    const t1 = API_NAME_MAP[m.homeTeam?.name] || m.homeTeam?.name;
    const t2 = API_NAME_MAP[m.awayTeam?.name] || m.awayTeam?.name;
    const jogoId = JOGOS_MAP[`${t1}|${t2}`];
    if (!jogoId) continue;

    await pool.query(
      "INSERT INTO live_status (jogo_id, status) VALUES ($1, $2) ON CONFLICT (jogo_id) DO UPDATE SET status = $2 WHERE live_status.status IS DISTINCT FROM 'FINISHED'",
      [jogoId, m.status]
    );

    if (['FINISHED', 'IN_PLAY', 'PAUSED'].includes(m.status) && m.score?.fullTime) {
      const g1 = m.score.fullTime.home;
      const g2 = m.score.fullTime.away;
      if (g1 != null && g2 != null) {
        await pool.query(
          `INSERT INTO resultados (jogo_id, g1, g2, overtime, penalties, source) VALUES ($1, $2, $3, $4, $5, 'api')
           ON CONFLICT (jogo_id) DO UPDATE SET g1 = $2, g2 = $3, overtime = $4, penalties = $5, source = 'api'
           WHERE resultados.source IS DISTINCT FROM 'manual'`,
          [jogoId, g1, g2, m.score.extraTime != null, m.score.penalties != null]
        );
        updated++;
      }
    }
  }

  if (updated > 0) broadcast();
  return updated;
}

app.post('/api/sync', requireAdmin, async (req, res) => {
  const apiKey = await getApiKey();
  let updated = 0;
  // Fonte 1: football-data (OPCIONAL — se falhar, não aborta; segue pra TheSportsDB)
  if (apiKey) {
    try {
      const apiRes = await fetch('https://api.football-data.org/v4/competitions/WC/matches?season=2026', {
        headers: { 'X-Auth-Token': apiKey }
      });
      if (apiRes.ok) {
        const data = await apiRes.json();
        for (const m of (data.matches || [])) {
          const t1 = API_NAME_MAP[m.homeTeam?.name] || m.homeTeam?.name;
          const t2 = API_NAME_MAP[m.awayTeam?.name] || m.awayTeam?.name;
          const jogoId = JOGOS_MAP[`${t1}|${t2}`];
          if (!jogoId) continue;
          await pool.query(
            "INSERT INTO live_status (jogo_id, status) VALUES ($1, $2) ON CONFLICT (jogo_id) DO UPDATE SET status = $2 WHERE live_status.status IS DISTINCT FROM 'FINISHED'",
            [jogoId, m.status]
          );
          if (['FINISHED', 'IN_PLAY', 'PAUSED'].includes(m.status) && m.score?.fullTime) {
            const g1 = m.score.fullTime.home;
            const g2 = m.score.fullTime.away;
            if (g1 != null && g2 != null) {
              await pool.query(
                `INSERT INTO resultados (jogo_id, g1, g2, overtime, penalties) VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (jogo_id) DO UPDATE SET g1 = $2, g2 = $3, overtime = $4, penalties = $5`,
                [jogoId, g1, g2, m.score.extraTime != null, m.score.penalties != null]
              );
              updated++;
            }
          }
        }
      }
    } catch (_) { /* football-data falhou — ignora, ESPN cobre */ }
  }
  // Fonte 2: ESPN (a confiável, tempo real — sempre roda)
  let espn = 0;
  try { espn = await syncEspn(); } catch (_) {}
  broadcast();
  res.json({ ok: true, updated: updated + espn });
});

// ===== FONTE SECUNDÁRIA: TheSportsDB (placar + status ao vivo, confiável) =====
// Salvaguardas: timeout curto, nunca trava, nunca sobrescreve 'manual'.
// Controla também o status (ao vivo/encerrado) porque é confiável nisso.

// Nomes da TheSportsDB que diferem do mapa da football-data
const SPORTSDB_ALIAS = {
  'Bosnia-Herzegovina': 'Bósnia-Herz.', 'Bosnia and Herzegovina': 'Bósnia-Herz.',
  'USA': 'Estados Unidos', 'United States': 'Estados Unidos',
  'Czechia': 'Rep. Tcheca', 'Czech Republic': 'Rep. Tcheca',
  'South Korea': 'Coreia do Sul', 'Korea Republic': 'Coreia do Sul',
  'DR Congo': 'Congo (RD)', 'Congo DR': 'Congo (RD)',
  'Ivory Coast': 'Costa do Marfim', 'Curacao': 'Curaçao',
};
function sdbTeam(nome) {
  return SPORTSDB_ALIAS[nome] || API_NAME_MAP[nome] || nome;
}
// status TheSportsDB → { status interno, overtime, penalties }
function sdbStatus(s) {
  const st = (s || '').toUpperCase();
  if (['1H', '2H', 'ET', 'BT', 'P', 'LIVE', 'INPLAY'].includes(st)) return { status: 'IN_PLAY' };
  if (st === 'HT') return { status: 'PAUSED' };
  if (st === 'FT') return { status: 'FINISHED' };
  if (st === 'AET') return { status: 'FINISHED', overtime: true };
  if (['PEN', 'AP'].includes(st)) return { status: 'FINISHED', penalties: true };
  return null; // NS, PST, etc → não mexe
}

async function syncSportsDB() {
  // Janela de 3 dias UTC para pegar jogos que viram a meia-noite
  const dias = [-1, 0, 1].map(off => new Date(Date.now() + off * 86400000).toISOString().slice(0, 10));
  const eventos = [];
  for (const d of dias) {
    let data;
    try {
      const res = await fetch(`https://www.thesportsdb.com/api/v1/json/3/eventsday.php?d=${d}&l=4429`, { signal: AbortSignal.timeout(6000) });
      if (!res.ok) continue;
      data = await res.json();
    } catch { continue; } // best-effort
    for (const e of data.events || []) eventos.push(e);
  }
  if (!eventos.length) return 0;

  let updated = 0;
  for (const e of eventos) {
    const info = sdbStatus(e.strStatus);
    if (!info) continue; // jogo não começou ou estado irrelevante

    const t1 = sdbTeam(e.strHomeTeam);
    const t2 = sdbTeam(e.strAwayTeam);
    const jogoId = JOGOS_MAP[`${t1}|${t2}`];
    if (!jogoId) continue;

    // Status (ao vivo / encerrado) — fonte confiável
    await pool.query(
      "INSERT INTO live_status (jogo_id, status) VALUES ($1, $2) ON CONFLICT (jogo_id) DO UPDATE SET status = $2 WHERE live_status.status IS DISTINCT FROM 'FINISHED'",
      [jogoId, info.status]
    );

    const g1 = parseInt(e.intHomeScore);
    const g2 = parseInt(e.intAwayScore);
    if (isNaN(g1) || isNaN(g2)) continue;

    // Placar — nunca sobrescreve 'manual'; só atualiza se mudou
    const r = await pool.query(
      `INSERT INTO resultados (jogo_id, g1, g2, overtime, penalties, source) VALUES ($1, $2, $3, $4, $5, 'api')
       ON CONFLICT (jogo_id) DO UPDATE SET g1 = $2, g2 = $3, source = 'api'
       WHERE resultados.source IS DISTINCT FROM 'manual' AND (resultados.g1 <> $2 OR resultados.g2 <> $3)`,
      [jogoId, g1, g2, !!info.overtime, !!info.penalties]
    );
    if (r.rowCount) updated++;
  }
  if (updated > 0) broadcast();
  return updated;
}

// ===== FONTE PRINCIPAL: ESPN (placar + status AO VIVO em tempo real, grátis) =====
const ESPN_ALIAS = {
  'Türkiye': 'Turquia', 'Turkey': 'Turquia', 'USA': 'Estados Unidos', 'United States': 'Estados Unidos',
  'Czech Republic': 'Rep. Tcheca', 'Czechia': 'Rep. Tcheca', 'South Korea': 'Coreia do Sul', 'Korea Republic': 'Coreia do Sul',
  'Bosnia-Herzegovina': 'Bósnia-Herz.', 'Bosnia & Herzegovina': 'Bósnia-Herz.', 'Bosnia and Herzegovina': 'Bósnia-Herz.',
  'Congo DR': 'Congo (RD)', 'DR Congo': 'Congo (RD)', 'Ivory Coast': 'Costa do Marfim', "Côte d'Ivoire": 'Costa do Marfim',
  'Cape Verde': 'Cabo Verde', 'Curaçao': 'Curaçao', 'New Zealand': 'Nova Zelândia', 'IR Iran': 'Irã',
};
function espnTeam(n) { return ESPN_ALIAS[n] || API_NAME_MAP[n] || n; }

// Determina a fase do mata-mata pela data do jogo
function faseMataMata(dateStr) {
  const d = new Date(dateStr + 'T12:00:00Z');
  const ymd = d.toISOString().slice(0, 10);
  if (ymd <= '2026-07-03') return 'Rodada de 32';
  if (ymd <= '2026-07-09') return 'Oitavas de Final';
  if (ymd <= '2026-07-12') return 'Quartas de Final';
  if (ymd <= '2026-07-16') return 'Semifinais';
  if (ymd === '2026-07-18') return 'Disputa 3º Lugar';
  return '🏆 Grande Final';
}

async function syncEspn() {
  const dts = [-1, 0, 1].map(off => new Date(Date.now() + off * 86400000).toISOString().slice(0, 10).replace(/-/g, ''));
  let updated = 0;

  // Carrega mata_jogos existentes indexados por espn_id
  const mataR = await pool.query('SELECT id, espn_id FROM mata_jogos');
  const mataByEspnId = Object.fromEntries(mataR.rows.map(r => [r.espn_id, r.id]));

  for (const dt of dts) {
    let data;
    try {
      const res = await fetch(`https://site.api.espn.com/apis/site/v2/sports/soccer/fifa.world/scoreboard?dates=${dt}`, { signal: AbortSignal.timeout(6000) });
      if (!res.ok) continue;
      data = await res.json();
    } catch { continue; }
    for (const ev of data.events || []) {
      const comp = ev.competitions?.[0];
      if (!comp) continue;
      const espnId = String(ev.id || comp.id || '');
      const state = comp.status?.type?.state; // pre / in / post
      const homeC = (comp.competitors || []).find(c => c.homeAway === 'home');
      const awayC = (comp.competitors || []).find(c => c.homeAway === 'away');
      if (!homeC || !awayC) continue;
      const hN = espnTeam(homeC.team?.displayName || homeC.team?.name);
      const aN = espnTeam(awayC.team?.displayName || awayC.team?.name);

      let jogoId = JOGOS_MAP[`${hN}|${aN}`], invert = false;
      if (!jogoId) { jogoId = JOGOS_MAP[`${aN}|${hN}`]; invert = true; }

      // Não encontrou no mapa estático — pode ser jogo do mata-mata
      if (!jogoId) {
        invert = false;
        if (mataByEspnId[espnId]) {
          jogoId = mataByEspnId[espnId];
        } else if (espnId && dt >= '20260627') {
          // Novo jogo de mata-mata detectado — registra no banco
          const gameDate = ev.date ? ev.date.slice(0, 10) : `${dt.slice(0,4)}-${dt.slice(4,6)}-${dt.slice(6,8)}`;
          const fase = faseMataMata(gameDate);
          const diaMes = `${parseInt(gameDate.slice(8,10))}/${['jan','fev','mar','abr','mai','jun','jul'][parseInt(gameDate.slice(5,7))-1]}`;
          // Hora em BRT (UTC-3): pega do ESPN ou usa '—'
          let hora = '—';
          if (ev.date) {
            const utcH = new Date(ev.date).getUTCHours();
            const brtH = (utcH - 3 + 24) % 24;
            hora = `${brtH}h`;
          }
          const newId = (await pool.query(`SELECT nextval('mata_jogos_seq') AS id`)).rows[0].id;
          await pool.query(
            'INSERT INTO mata_jogos (id, espn_id, fase, data, hora, time1, time2) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (espn_id) DO NOTHING',
            [newId, espnId, fase, diaMes, hora, hN, aN]
          );
          jogoId = newId;
          mataByEspnId[espnId] = newId;
          delete mataJogosCache[newId];
          updated++;
        }
        if (!jogoId) continue;
      }

      const status = state === 'in' ? 'IN_PLAY' : state === 'post' ? 'FINISHED' : 'TIMED';
      await pool.query(
        "INSERT INTO live_status (jogo_id, status) VALUES ($1, $2) ON CONFLICT (jogo_id) DO UPDATE SET status = $2 WHERE live_status.status IS DISTINCT FROM 'FINISHED'",
        [jogoId, status]
      );
      if (state === 'pre') continue;

      let g1 = parseInt(homeC.score), g2 = parseInt(awayC.score);
      if (invert) { const t = g1; g1 = g2; g2 = t; }
      if (isNaN(g1) || isNaN(g2)) continue;
      const r = await pool.query(
        `INSERT INTO resultados (jogo_id, g1, g2, overtime, penalties, source) VALUES ($1, $2, $3, false, false, 'api')
         ON CONFLICT (jogo_id) DO UPDATE SET g1 = $2, g2 = $3, source = 'api'
         WHERE resultados.source IS DISTINCT FROM 'manual' AND (resultados.g1 <> $2 OR resultados.g2 <> $3)`,
        [jogoId, g1, g2]
      );
      if (r.rowCount) updated++;
    }
  }
  if (updated > 0) broadcast();
  return updated;
}

// ===== AUTO-SYNC =====
async function autoSync() {
  try {
    let fd = 0;
    try { fd = await doSync(); } catch (_) { /* football-data opcional */ }
    let espn = 0;
    try { espn = await syncEspn(); } catch (_) { /* fonte principal (tempo real) */ }
    console.log(`[auto-sync] ${new Date().toISOString()} — football-data: ${fd} | espn: ${espn}`);
  } catch (e) {
    console.error('[auto-sync] erro:', e.message);
  }
}

// ===== START =====
const PORT = process.env.PORT || 3000;
// 2 min para acompanhar jogos ao vivo de perto
const SYNC_INTERVAL_MS = parseInt(process.env.SYNC_INTERVAL_MS) || 2 * 60 * 1000;

initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`✅ Bolão rodando em http://localhost:${PORT}`);
      autoSync();
      setInterval(autoSync, SYNC_INTERVAL_MS);
      console.log(`🔄 Auto-sync a cada ${SYNC_INTERVAL_MS / 60000} min`);
    });
  })
  .catch(e => {
    console.error('❌ Falha ao conectar ao banco de dados:', e.message);
    process.exit(1);
  });
