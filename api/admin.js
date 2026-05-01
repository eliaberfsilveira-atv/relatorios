const jwt    = require('jsonwebtoken');
const crypto = require('crypto');

function getKV() {
  try { return require('@vercel/kv').kv; } catch (_) { return null; }
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Password');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const body     = req.method === 'POST' ? (req.body || {}) : (req.query || {});
  const password = body.adminPassword || req.headers['x-admin-password'];
  const action   = req.query.action;

  if (password !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Senha incorreta' });
  }

  const kv = getKV();

  if (action === 'generate') {
    const { name, days = 7 } = body;
    if (!name) return res.status(400).json({ error: 'Nome é obrigatório' });
    const jti   = crypto.randomBytes(10).toString('hex');
    const token = jwt.sign(
      { name, jti, type: 'access' },
      process.env.ADMIN_SECRET,
      { expiresIn: `${days}d` }
    );
    const host    = req.headers.host || '';
    const baseUrl = host.includes('localhost') ? `http://${host}` : `https://${host}`;
    const url     = `${baseUrl}/?t=${token}`;
    if (kv) {
      await kv.hset(`token:${jti}`, {
        name, jti,
        created:  new Date().toISOString(),
        expires:  new Date(Date.now() + days * 86400000).toISOString(),
        revoked:  'false', lastUsed: ''
      });
      await kv.sadd('token_ids', jti);
    }
    return res.status(200).json({ ok: true, url, jti, token });
  }

  if (action === 'tokens') {
    if (!kv) return res.status(200).json({ tokens: [], kvMissing: true });
    const ids    = await kv.smembers('token_ids') || [];
    const tokens = (await Promise.all(ids.map(id => kv.hgetall(`token:${id}`)))).filter(Boolean);
    return res.status(200).json({ tokens });
  }

  if (action === 'revoke') {
    const { jti } = body;
    if (!jti) return res.status(400).json({ error: 'JTI obrigatório' });
    if (kv) {
      await kv.set(`revoked:${jti}`, '1', { ex: 90 * 86400 });
      await kv.hset(`token:${jti}`, { revoked: 'true' });
    }
    return res.status(200).json({ ok: true });
  }

  if (action === 'logs') {
    if (!kv) return res.status(200).json({ logs: [], kvMissing: true });
    const raw  = await kv.lrange('logs', 0, 99) || [];
    const logs = raw.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    return res.status(200).json({ logs });
  }

  return res.status(400).json({ error: 'Ação desconhecida' });
};
