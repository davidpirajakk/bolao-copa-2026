const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

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
  const [playersR, palpitesR, resultadosR, liveR, settingsR, campeaoRealR] = await Promise.all([
    pool.query('SELECT id, nome FROM players ORDER BY id'),
    pool.query('SELECT player_id, jogo_id, g1, g2 FROM palpites'),
    pool.query('SELECT jogo_id, g1, g2, overtime, penalties FROM resultados'),
    pool.query('SELECT jogo_id, status FROM live_status'),
    pool.query("SELECT value FROM settings WHERE key = 'api_key'"),
    pool.query("SELECT value FROM settings WHERE key = 'campeao_real'"),
  ]);

  const palpites = {};
  for (const row of palpitesR.rows) {
    const pid = String(row.player_id);
    if (!palpites[pid]) palpites[pid] = {};
    palpites[pid][String(row.jogo_id)] = { g1: row.g1, g2: row.g2 };
  }

  const resultados = {};
  for (const row of resultadosR.rows) {
    resultados[String(row.jogo_id)] = { g1: row.g1, g2: row.g2, overtime: row.overtime, penalties: row.penalties };
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

  if (isGameLocked(jogoId)) return res.status(400).json({ error: 'Palpites encerrados (menos de 1h para o jogo)' });

  const hasResult = await pool.query('SELECT 1 FROM resultados WHERE jogo_id = $1', [jogoId]);
  if (hasResult.rows.length) return res.status(400).json({ error: 'Jogo já encerrado' });

  await pool.query(
    `INSERT INTO palpites (player_id, jogo_id, g1, g2) VALUES ($1, $2, $3, $4)
     ON CONFLICT (player_id, jogo_id) DO UPDATE SET g1 = $3, g2 = $4`,
    [playerId, jogoId, g1, g2]
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

  if (isNaN(g1) || isNaN(g2) || g1 < 0 || g2 < 0 || g1 > 20 || g2 > 20)
    return res.status(400).json({ error: 'Placar inválido' });

  await pool.query(
    `INSERT INTO resultados (jogo_id, g1, g2, overtime, penalties, source) VALUES ($1, $2, $3, $4, $5, 'manual')
     ON CONFLICT (jogo_id) DO UPDATE SET g1 = $2, g2 = $3, overtime = $4, penalties = $5, source = 'manual'`,
    [jogoId, g1, g2, overtime, penalties]
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
const JOGOS_TIMES = {
  1:['11/jun','16h'],2:['11/jun','23h'],3:['12/jun','16h'],4:['12/jun','22h'],
  5:['13/jun','01h'],6:['13/jun','16h'],7:['13/jun','19h'],8:['13/jun','22h'],
  9:['14/jun','14h'],10:['14/jun','17h'],11:['14/jun','20h'],12:['14/jun','23h'],
  13:['15/jun','13h'],14:['15/jun','16h'],15:['15/jun','19h'],16:['15/jun','22h'],
  17:['16/jun','01h'],18:['16/jun','16h'],19:['16/jun','19h'],20:['16/jun','22h'],
  21:['17/jun','14h'],22:['17/jun','17h'],23:['17/jun','20h'],24:['17/jun','23h'],
  25:['18/jun','13h'],26:['18/jun','16h'],27:['18/jun','19h'],28:['18/jun','22h'],
  29:['19/jun','01h'],30:['19/jun','16h'],31:['19/jun','19h'],32:['19/jun','21h30'],
  33:['20/jun','01h'],34:['20/jun','14h'],35:['20/jun','17h'],36:['20/jun','21h'],
  37:['21/jun','13h'],38:['21/jun','16h'],39:['21/jun','19h'],40:['21/jun','22h'],
  41:['22/jun','00h'],42:['22/jun','14h'],43:['22/jun','18h'],44:['22/jun','21h'],
  45:['23/jun','14h'],46:['23/jun','17h'],47:['23/jun','20h'],48:['23/jun','23h'],
  49:['24/jun','16h'],50:['24/jun','16h'],51:['24/jun','19h'],52:['24/jun','19h'],
  53:['24/jun','22h'],54:['24/jun','22h'],55:['25/jun','17h'],56:['25/jun','17h'],
  57:['25/jun','20h'],58:['25/jun','20h'],59:['25/jun','23h'],60:['25/jun','23h'],
  61:['26/jun','16h'],62:['26/jun','16h'],63:['26/jun','21h'],64:['26/jun','21h'],
  65:['27/jun','00h'],66:['27/jun','00h'],67:['27/jun','18h'],68:['27/jun','18h'],
  69:['27/jun','20h30'],70:['27/jun','20h30'],71:['27/jun','23h'],72:['27/jun','23h'],
  77:['18/jul','18h'],78:['19/jul','16h'],
};

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

function isGameLocked(jogoId) {
  const times = JOGOS_TIMES[jogoId];
  if (!times) return false; // knockout TBD games (73-76) are never locked by time
  const gameTime = parseGameTime(times[0], times[1]);
  if (!gameTime) return false;
  return Date.now() >= gameTime.getTime() - 60 * 60 * 1000; // 1h before
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

const JOGOS_MAP = {
  'México|África do Sul':1,'Coreia do Sul|Rep. Tcheca':2,'Canadá|Bósnia-Herz.':3,
  'Estados Unidos|Paraguai':4,'Austrália|Turquia':5,'Catar|Suíça':6,'Brasil|Marrocos':7,
  'Haiti|Escócia':8,'Alemanha|Curaçao':9,'Holanda|Japão':10,'Costa do Marfim|Equador':11,
  'Suécia|Tunísia':12,'Espanha|Cabo Verde':13,'Bélgica|Egito':14,'Arábia Saudita|Uruguai':15,
  'Irã|Nova Zelândia':16,'Áustria|Jordânia':17,'França|Senegal':18,'Iraque|Noruega':19,
  'Argentina|Argélia':20,'Portugal|Congo (RD)':21,'Inglaterra|Croácia':22,'Gana|Panamá':23,
  'Uzbequistão|Colômbia':24,'Rep. Tcheca|África do Sul':25,'Suíça|Bósnia-Herz.':26,
  'Canadá|Catar':27,'México|Coreia do Sul':28,'Turquia|Paraguai':29,'Estados Unidos|Austrália':30,
  'Escócia|Marrocos':31,'Brasil|Haiti':32,'Tunísia|Japão':33,'Holanda|Suécia':34,
  'Alemanha|Costa do Marfim':35,'Equador|Curaçao':36,'Espanha|Arábia Saudita':37,
  'Bélgica|Irã':38,'Uruguai|Cabo Verde':39,'Nova Zelândia|Egito':40,'Jordânia|Argélia':41,
  'Argentina|Áustria':42,'França|Iraque':43,'Noruega|Senegal':44,'Portugal|Uzbequistão':45,
  'Inglaterra|Gana':46,'Panamá|Croácia':47,'Colômbia|Congo (RD)':48,'Suíça|Canadá':49,
  'Bósnia-Herz.|Catar':50,'Escócia|Brasil':51,'Marrocos|Haiti':52,'Rep. Tcheca|México':53,
  'África do Sul|Coreia do Sul':54,'Curaçao|Costa do Marfim':55,'Equador|Alemanha':56,
  'Japão|Suécia':57,'Tunísia|Holanda':58,'Turquia|Estados Unidos':59,'Paraguai|Austrália':60,
  'Noruega|França':61,'Senegal|Iraque':62,'Cabo Verde|Arábia Saudita':63,'Uruguai|Espanha':64,
  'Egito|Irã':65,'Nova Zelândia|Bélgica':66,'Panamá|Inglaterra':67,'Croácia|Gana':68,
  'Colômbia|Portugal':69,'Congo (RD)|Uzbequistão':70,'Argélia|Áustria':71,'Jordânia|Argentina':72,
};

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
      'INSERT INTO live_status (jogo_id, status) VALUES ($1, $2) ON CONFLICT (jogo_id) DO UPDATE SET status = $2 WHERE live_status.status IS DISTINCT FROM 'FINISHED'',
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
  if (!apiKey) return res.status(400).json({ error: 'API key não configurada' });
  try {
    const apiRes = await fetch('https://api.football-data.org/v4/competitions/WC/matches?season=2026', {
      headers: { 'X-Auth-Token': apiKey }
    });
    if (!apiRes.ok) {
      const msg = apiRes.status === 403 || apiRes.status === 401
        ? 'Chave inválida ou sem permissão para Copa do Mundo'
        : `Erro da API: ${apiRes.status}`;
      return res.status(apiRes.status).json({ error: msg });
    }
    const data = await apiRes.json();
    let updated = 0;
    for (const m of (data.matches || [])) {
      const t1 = API_NAME_MAP[m.homeTeam?.name] || m.homeTeam?.name;
      const t2 = API_NAME_MAP[m.awayTeam?.name] || m.awayTeam?.name;
      const jogoId = JOGOS_MAP[`${t1}|${t2}`];
      if (!jogoId) continue;

      await pool.query(
        'INSERT INTO live_status (jogo_id, status) VALUES ($1, $2) ON CONFLICT (jogo_id) DO UPDATE SET status = $2 WHERE live_status.status IS DISTINCT FROM 'FINISHED'',
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
    // Fonte secundária (best-effort): placar + status ao vivo mais rápido
    let sdb = 0;
    try { sdb = await syncSportsDB(); } catch (_) {}
    broadcast();
    res.json({ ok: true, updated: updated + sdb });
  } catch (e) {
    res.status(500).json({ error: 'Erro de conexão: ' + e.message });
  }
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
      'INSERT INTO live_status (jogo_id, status) VALUES ($1, $2) ON CONFLICT (jogo_id) DO UPDATE SET status = $2 WHERE live_status.status IS DISTINCT FROM 'FINISHED'',
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

// ===== AUTO-SYNC =====
async function autoSync() {
  try {
    const updated = await doSync();
    let sdb = 0;
    try { sdb = await syncSportsDB(); } catch (e) { /* fonte secundária: ignora */ }
    console.log(`[auto-sync] ${new Date().toISOString()} — football-data: ${updated} | thesportsdb: ${sdb}`);
  } catch (e) {
    console.error('[auto-sync] erro:', e.message);
  }
}

// ===== START =====
const PORT = process.env.PORT || 3000;
const SYNC_INTERVAL_MS = parseInt(process.env.SYNC_INTERVAL_MS) || 5 * 60 * 1000;

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
