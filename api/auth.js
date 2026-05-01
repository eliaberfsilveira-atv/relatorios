const jwt = require('jsonwebtoken');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método não permitido' });

  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Token necessário' });

  try {
    const payload = jwt.verify(token, process.env.ADMIN_SECRET);

    try {
      const { kv } = require('@vercel/kv');
      const revoked = await kv.get(`revoked:${payload.jti}`);
      if (revoked) {
        return res.status(401).json({ error: 'Este link foi revogado pelo administrador.' });
      }
      await kv.lpush('logs', JSON.stringify({
        name: payload.name,
        jti:  payload.jti,
        ip:   req.headers['x-forwarded-for'] || 'desconhecido',
        at:   new Date().toISOString()
      }));
      await kv.ltrim('logs', 0, 499);
      await kv.hset(`token:${payload.jti}`, { lastUsed: new Date().toISOString() });
    } catch (_) {}

    const session = jwt.sign(
      { name: payload.name, type: 'session' },
      process.env.ADMIN_SECRET,
      { expiresIn: '2h' }
    );

    res.setHeader('Set-Cookie',
      `pf_session=${session}; HttpOnly; Secure; SameSite=Strict; Max-Age=7200; Path=/`
    );
    return res.status(200).json({ ok: true, name: payload.name });

  } catch (e) {
    if (e.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Link expirado. Solicite um novo acesso.' });
    }
    return res.status(401).json({ error: 'Link inválido.' });
  }
};
