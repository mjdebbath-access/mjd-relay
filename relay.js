// Relais MJD : boîtes aux lettres en mémoire, aucune dépendance.
// Lancer : node relay.js   (variable PORT optionnelle)
const http = require('http');
const crypto = require('crypto');
const PORT = process.env.PORT || 8080;
const TTL = 24 * 3600 * 1000, MAX = 60, MAXBODY = 4 * 1024 * 1024, MAXBYTES = 24 * 1024 * 1024;
const boxes = new Map();

// Licences (phase de test sur invitation) : clés signées, sans base de données.
// LICENSE_SECRET vide = accès libre. REVOKED_KEYS = identifiants de clés révoquées, séparés par des virgules.
const SECRET = process.env.LICENSE_SECRET || '';
const REVOKED = new Set((process.env.REVOKED_KEYS || '').split(',').map(s => s.trim()).filter(Boolean));
function checkKey(k) {
  if (!SECRET) return { ok: true, open: true };
  const m = /^MJDK1\.([A-Za-z0-9_-]{8,400})\.([A-Za-z0-9_-]{22})$/.exec(k || '');
  if (!m) return { ok: false, why: 'cle' };
  const sig = crypto.createHmac('sha256', SECRET).update(m[1]).digest('base64url').slice(0, 22);
  const a = Buffer.from(sig), b = Buffer.from(m[2]);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, why: 'cle' };
  let p;
  try { p = JSON.parse(Buffer.from(m[1], 'base64url').toString()); } catch (e) { return { ok: false, why: 'cle' }; }
  if (REVOKED.has(p.i)) return { ok: false, why: 'revoquee' };
  if (!p.e || Date.now() > p.e) return { ok: false, why: 'expiree', plan: p.p, exp: p.e };
  return { ok: true, plan: p.p, exp: p.e, label: p.l };
}

// TURN Cloudflare : l'identifiant et le jeton restent dans les variables d'environnement de Render
let turnCache = null;
async function getTurn() {
  const id = process.env.CF_TURN_KEY_ID, tok = process.env.CF_TURN_API_TOKEN;
  if (!id || !tok) return [];
  if (turnCache && Date.now() < turnCache.exp) return turnCache.servers;
  const r = await fetch('https://rtc.live.cloudflare.com/v1/turn/keys/' + id + '/credentials/generate-ice-servers', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ttl: 3600 })
  });
  if (!r.ok) return [];
  const j = await r.json();
  const servers = (Array.isArray(j.iceServers) ? j.iceServers : [j.iceServers]).filter(Boolean);
  turnCache = { servers, exp: Date.now() + 25 * 60 * 1000 };
  return servers;
}
let seq = Date.now();

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Key',
  'Access-Control-Max-Age': '86400'
};
const box = id => {
  if (!boxes.has(id)) boxes.set(id, { msgs: [], waiters: [], pres: new Map() });
  return boxes.get(id);
};
const reply = (res, code, data) => {
  if (res.writableEnded) return;
  res.writeHead(code, { ...cors, 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
};
const pending = (b, since) => b.msgs.filter(m => m.id > since);

// Sauvegarde sur disque (facultative) : définir DATA_DIR sur un disque persistant (ex. /var/data sur Render)
const fs = require('fs');
const DATA_FILE = process.env.DATA_DIR ? process.env.DATA_DIR + '/mjd-data.json' : '';
let dirty = false;
function save() {
  if (!DATA_FILE || !dirty) return;
  dirty = false;
  try {
    const o = { seq, boxes: [...boxes].map(([k, b]) => [k, { msgs: b.msgs, pres: [...b.pres] }]) };
    fs.writeFileSync(DATA_FILE + '.tmp', JSON.stringify(o));
    fs.renameSync(DATA_FILE + '.tmp', DATA_FILE);
  } catch (e) { console.error('Sauvegarde impossible :', e.message); }
}
function load() {
  if (!DATA_FILE) return;
  try {
    const o = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    seq = Math.max(seq, o.seq || 0);
    for (const [k, b] of o.boxes) boxes.set(k, { msgs: b.msgs, waiters: [], pres: new Map(b.pres) });
    console.log('Données rechargées :', boxes.size, 'salons');
  } catch (e) { /* premier démarrage */ }
}
load();
setInterval(save, 5000);
process.on('SIGTERM', () => { save(); process.exit(0); });

// Limite simple : 300 requêtes par minute et par adresse IP
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  let h = hits.get(ip);
  if (!h || now - h.t > 60000) h = { t: now, n: 0 };
  h.n++; hits.set(ip, h);
  return h.n > 300;
}
setInterval(() => { const now = Date.now(); for (const [k, h] of hits) if (now - h.t > 60000) hits.delete(k); }, 60000);

http.createServer((req, res) => {
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (limited(ip)) return reply(res, 429, { error: 'trop de requetes' });
  const u = new URL(req.url, 'http://x');
  const [, action, id] = u.pathname.split('/');
  const lic = checkKey(req.headers['x-key']);
  if (action === 'license') return reply(res, lic.ok ? 200 : 401, lic);
  if (!lic.ok) return reply(res, 401, { error: 'licence', why: lic.why });
  if (!id || !/^[A-Za-z0-9_-]{16,64}$/.test(id)) return reply(res, 400, { error: 'boite invalide' });

  if (action === 'send' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > MAXBODY) req.destroy(); });
    req.on('end', () => {
      const b = box(id);
      b.msgs.push({ id: ++seq, t: Date.now(), data: body });
      dirty = true;
      let tot = b.msgs.reduce((n, m) => n + m.data.length, 0);
      while (b.msgs.length > MAX || (tot > MAXBYTES && b.msgs.length > 1)) tot -= b.msgs.shift().data.length;
      b.waiters.splice(0).forEach(w => { clearTimeout(w.timer); reply(w.res, 200, pending(b, w.since)); });
      reply(res, 200, { ok: true });
    });
  } else if (action === 'poll' && req.method === 'GET') {
    const since = Number(u.searchParams.get('since')) || 0;
    const b = box(id);
    const p = pending(b, since);
    if (p.length) return reply(res, 200, p);
    const w = { res, since, timer: setTimeout(() => {
      b.waiters = b.waiters.filter(x => x !== w);
      reply(res, 200, []);
    }, 25000) };
    b.waiters.push(w);
    res.on('close', () => { clearTimeout(w.timer); b.waiters = b.waiters.filter(x => x !== w); });
  } else if (action === 'turn' && req.method === 'GET') {
    const b = boxes.get(id);
    if (!b || (!b.pres.size && !b.msgs.length)) return reply(res, 403, { error: 'salon inconnu' });
    getTurn().then(s => reply(res, 200, { iceServers: s })).catch(() => reply(res, 200, { iceServers: [] }));
  } else if (action === 'clear' && req.method === 'POST') {
    const b = boxes.get(id);
    if (b) { b.msgs = []; dirty = true; }
    reply(res, 200, { ok: true });
  } else if (action === 'ping' && req.method === 'POST') {
    const tok = u.searchParams.get('tok') || '';
    if (!/^[A-Za-z0-9_-]{8,48}$/.test(tok)) return reply(res, 400, { error: 'jeton invalide' });
    let body = '';
    req.on('data', c => { body += c; if (body.length > 2048) req.destroy(); });
    req.on('end', () => {
      const b = box(id);
      b.pres.delete(tok);
      b.pres.set(tok, { blob: body, t: Date.now() });
      dirty = true;
      if (b.pres.size > 20) b.pres.delete(b.pres.keys().next().value);
      reply(res, 200, { ok: true });
    });
  } else if (action === 'who' && req.method === 'GET') {
    const b = box(id), now = Date.now();
    reply(res, 200, [...b.pres.values()].map(p => ({ b: p.blob, a: Math.round((now - p.t) / 1000) })));
  } else {
    reply(res, 404, { error: 'introuvable' });
  }
}).listen(PORT, () => console.log('Relais MJD sur le port ' + PORT));

// Nettoyage horaire des messages de plus de 24 h
setInterval(() => {
  const now = Date.now();
  dirty = true;
  for (const [k, b] of boxes) {
    b.msgs = b.msgs.filter(m => now - m.t < TTL);
    for (const [t, p] of b.pres) if (now - p.t > TTL) b.pres.delete(t);
    if (!b.msgs.length && !b.waiters.length && !b.pres.size) boxes.delete(k);
  }
}, 3600e3);
