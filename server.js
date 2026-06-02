const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===== STORAGE =====
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'bolao.json');

function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    return { players: [], nextId: 1, palpites: {}, resultados: {}, liveStatus: {}, apiKey: '' };
  }
}

function saveDB() {
  fs.writeFileSync(DB_PATH, JSON.stringify(db), 'utf8');
}

let db = loadDB();

// ===== SSE =====
const clients = new Set();

function getState() {
  return {
    players: db.players,
    palpites: db.palpites,
    resultados: db.resultados,
    liveStatus: db.liveStatus,
    hasApiKey: !!db.apiKey,
  };
}

function broadcast() {
  const msg = `data: ${JSON.stringify(getState())}\n\n`;
  clients.forEach(res => {
    try { res.write(msg); } catch (_) { clients.delete(res); }
  });
}

// ===== ROUTES =====

app.get('/api/state', (req, res) => res.json(getState()));

app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  clients.add(res);
  try { res.write(`data: ${JSON.stringify(getState())}\n\n`); } catch (_) {}

  const hb = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (_) { clearInterval(hb); clients.delete(res); }
  }, 25000);

  req.on('close', () => { clearInterval(hb); clients.delete(res); });
});

app.post('/api/players', (req, res) => {
  const nome = (req.body.nome || '').trim().substring(0, 30);
  if (!nome) return res.status(400).json({ error: 'Nome obrigatório' });
  const player = { id: db.nextId++, nome };
  db.players.push(player);
  saveDB();
  broadcast();
  res.json(player);
});

app.put('/api/palpites/:playerId/:jogoId', (req, res) => {
  const playerId = String(req.params.playerId);
  const jogoId = String(req.params.jogoId);
  const g1 = parseInt(req.body.g1);
  const g2 = parseInt(req.body.g2);

  if (isNaN(g1) || isNaN(g2) || g1 < 0 || g2 < 0 || g1 > 20 || g2 > 20) {
    return res.status(400).json({ error: 'Placar inválido' });
  }
  if (db.resultados[jogoId]) {
    return res.status(400).json({ error: 'Jogo já encerrado' });
  }

  if (!db.palpites[playerId]) db.palpites[playerId] = {};
  db.palpites[playerId][jogoId] = { g1, g2 };
  saveDB();
  broadcast();
  res.json({ ok: true });
});

app.put('/api/results/:jogoId', (req, res) => {
  const jogoId = String(req.params.jogoId);
  const g1 = parseInt(req.body.g1);
  const g2 = parseInt(req.body.g2);
  const overtime = !!req.body.overtime;
  const penalties = !!req.body.penalties;

  if (isNaN(g1) || isNaN(g2) || g1 < 0 || g2 < 0 || g1 > 20 || g2 > 20) {
    return res.status(400).json({ error: 'Placar inválido' });
  }

  db.resultados[jogoId] = { g1, g2, overtime, penalties };
  saveDB();
  broadcast();
  res.json({ ok: true });
});

app.delete('/api/results/:jogoId', (req, res) => {
  delete db.resultados[String(req.params.jogoId)];
  saveDB();
  broadcast();
  res.json({ ok: true });
});

app.put('/api/settings/apikey', (req, res) => {
  const key = (req.body.key || '').trim();
  if (!key) return res.status(400).json({ error: 'Chave inválida' });
  db.apiKey = key;
  saveDB();
  res.json({ ok: true });
});

// Mapeamento nome football-data.org → nome no bolão
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

app.post('/api/sync', async (req, res) => {
  if (!db.apiKey) return res.status(400).json({ error: 'API key não configurada' });

  try {
    const apiRes = await fetch('https://api.football-data.org/v4/competitions/WC/matches?season=2026', {
      headers: { 'X-Auth-Token': db.apiKey }
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
      const jogoId = String(JOGOS_MAP[`${t1}|${t2}`]);
      if (!jogoId || jogoId === 'undefined') continue;

      const status = m.status;
      db.liveStatus[jogoId] = status;

      if ((status === 'FINISHED' || status === 'IN_PLAY' || status === 'PAUSED') && m.score?.fullTime) {
        const g1 = m.score.fullTime.home;
        const g2 = m.score.fullTime.away;
        if (g1 != null && g2 != null) {
          const overtime = m.score.extraTime != null;
          const penalties = m.score.penalties != null;
          db.resultados[jogoId] = { g1, g2, overtime, penalties };
          updated++;
        }
      }
    }

    saveDB();
    broadcast();
    res.json({ ok: true, updated });
  } catch (e) {
    res.status(500).json({ error: 'Erro de conexão: ' + e.message });
  }
});

// ===== AUTO-SYNC =====
// Busca placares automaticamente a cada 5 min se tiver API key
async function autoSync() {
  if (!db.apiKey) return;
  try {
    const apiRes = await fetch('https://api.football-data.org/v4/competitions/WC/matches?season=2026', {
      headers: { 'X-Auth-Token': db.apiKey }
    });
    if (!apiRes.ok) return;
    const data = await apiRes.json();
    let updated = 0;
    for (const m of (data.matches || [])) {
      const t1 = API_NAME_MAP[m.homeTeam?.name] || m.homeTeam?.name;
      const t2 = API_NAME_MAP[m.awayTeam?.name] || m.awayTeam?.name;
      const jogoId = String(JOGOS_MAP[`${t1}|${t2}`]);
      if (!jogoId || jogoId === 'undefined') continue;
      db.liveStatus[jogoId] = m.status;
      if ((['FINISHED','IN_PLAY','PAUSED'].includes(m.status)) && m.score?.fullTime) {
        const g1 = m.score.fullTime.home;
        const g2 = m.score.fullTime.away;
        if (g1 != null && g2 != null) {
          db.resultados[jogoId] = { g1, g2, overtime: m.score.extraTime != null, penalties: m.score.penalties != null };
          updated++;
        }
      }
    }
    if (updated > 0) { saveDB(); broadcast(); }
    console.log(`[auto-sync] ${new Date().toISOString()} — ${updated} resultado(s) atualizado(s)`);
  } catch (e) {
    console.error('[auto-sync] erro:', e.message);
  }
}

// ===== START =====
const PORT = process.env.PORT || 3000;
const SYNC_INTERVAL_MS = parseInt(process.env.SYNC_INTERVAL_MS) || 5 * 60 * 1000; // padrão: 5 min

app.listen(PORT, () => {
  console.log(`✅ Bolão rodando em http://localhost:${PORT}`);
  // Primeira sync ao iniciar (se tiver chave)
  autoSync();
  // Sync automática em loop
  setInterval(autoSync, SYNC_INTERVAL_MS);
  console.log(`🔄 Auto-sync configurado a cada ${SYNC_INTERVAL_MS / 60000} min`);
});
