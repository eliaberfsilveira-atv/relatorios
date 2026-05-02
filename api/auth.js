const jwt = require('jsonwebtoken');
const { withSecurity } = require('./_security');

async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { token } = req.body || {};
  if (!token || typeof token !== 'string' || token.length > 2048) {
    return res.status(400).json({ error: 'Token inválido' });
  }

  try {
    const payload = jwt.verify(token, process.env.ADMIN_SECRET);
    if (payload.type !== 'access') {
      return res.status(401).json({ error: 'Tipo de token inválido' });
    }

    try {
      const { kv } = require('@vercel/kv');
      const revoked = await kv.get(`revoked:${payload.jti}`);
      if (revoked) return res.status(401).json({ error: 'Este link foi revogado pelo administrador.' });
      await kv.lpush('logs', JSON.stringify({
        name: payload.name,
        jti: payload.jti,
        ip: req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'desconhecido',
        ua: req.headers['user-agent']?.substring(0, 80) || '',
        at: new Date().toISOString()
      }));
      await kv.ltrim('logs', 0, 499);
      await kv.hset(`token:${payload.jti}`, { lastUsed: new Date().toISOString() });
    } catch (_) {}

    const session = jwt.sign(
      { name: payload.name, type: 'session', jti: payload.jti },
      process.env.ADMIN_SECRET,
      { expiresIn: '2h' }
    );
    res.setHeader('Set-Cookie',
      `pf_session=${session}; HttpOnly; Secure; SameSite=Strict; Max-Age=7200; Path=/`
    );
    return res.status(200).json({ ok: true, name: payload.name });
  } catch (e) {
    if (e.name === 'TokenExpiredError') return res.status(401).json({ error: 'Link expirado. Solicite um novo acesso.' });
    if (e.name === 'JsonWebTokenError') return res.status(401).json({ error: 'Link inválido.' });
    return res.status(401).json({ error: 'Erro na validação.' });
  }
}

module.exports = withSecurity('auth', handler);
