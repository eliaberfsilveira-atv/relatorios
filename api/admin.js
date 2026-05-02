const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { withSecurity } = require('./_security');

function getKV() { try { return require('@vercel/kv').kv; } catch (_) { return null; } }

async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Password');
    if (req.method === 'OPTIONS') return res.status(200).end();

  const body     = req.method === 'POST' ? (req.body || {}) : {};
    const qPassword= req.query.adminPassword;
    const password = body.adminPassword || qPassword || req.headers['x-admin-password'];
    const action   = req.query.action;

  // Constant-time compare para evitar timing attacks
  const expected = process.env.ADMIN_PASSWORD || '';
    const provided = password || '';
    const match = crypto.timingSafeEqual(
          Buffer.from(provided.padEnd(64, '\0').slice(0,64)),
          Buffer.from(expected.padEnd(64, '\0').slice(0,64))
        ) && provided === expected;

    if (!match) return res.status(403).json({ error: 'Senha incorreta' });

  const kv = getKV();

  if (action === 'generate') {
        const { name, days = 7 } = body;
        if (!name || typeof name !== 'string' || name.length > 100) {
                return res.status(400).json({ error: 'Nome inválido' });
        }
        const daysNum = Math.min(Math.max(parseInt(days) || 7, 1), 30);
        const jti = crypto.randomBytes(12).toString('hex');
        const token = jwt.sign(
          { name: name.trim(), jti, type: 'access' },
                process.env.ADMIN_SECRET,
          { expiresIn: `${daysNum}d` }
              );
        const host = req.headers.host || '';
        const baseUrl = host.includes('localhost') ? `http://${host}` : `https://${host}`;
        const url = `${baseUrl}/?t=${token}`;
        if (kv) {
                await kv.hset(`token:${jti}`, {
                          name: name.trim(), jti,
                          created: new Date().toISOString(),
                          expires: new Date(Date.now() + daysNum * 86400000).toISOString(),
                          revoked: 'false', lastUsed: ''
                });
                await kv.sadd('token_ids', jti);
        }
        return res.status(200).json({ ok: true, url, jti });
  }

  if (action === 'tokens') {
        if (!kv) return res.status(200).json({ tokens: [], kvMissing: true });
        const ids = await kv.smembers('token_ids') || [];
        const tokens = (await Promise.all(ids.map(id => kv.hgetall(`token:${id}`)))).filter(Boolean);
        return res.status(200).json({ tokens });
  }

  if (action === 'revoke') {
        const { jti } = body;
        if (!jti || !/^[a-f0-9]{24}$/.test(jti)) return res.status(400).json({ error: 'JTI inválido' });
        if (kv) {
                await kv.set(`revoked:${jti}`, '1', { ex: 90 * 86400 });
                await kv.hset(`token:${jti}`, { revoked: 'true' });
        }
        return res.status(200).json({ ok: true });
  }

  if (action === 'logs') {
        if (!kv) return res.status(200).json({ logs: [], kvMissing: true });
        const raw = await kv.lrange('logs', 0, 99) || [];
        const logs = raw.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
        return res.status(200).json({ logs });
  }

  return res.status(400).json({ error: 'Ação desconhecida' });
}

module.exports = withSecurity('admin', handler);
