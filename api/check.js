const jwt = require('jsonwebtoken');
const { withSecurity } = require('./_security');

function handler(req, res) {
  const cookie = req.headers.cookie || '';
  const match  = cookie.match(/pf_session=([^;]+)/);
  if (!match) return res.status(401).json({ ok: false });
  try {
    const payload = jwt.verify(match[1], process.env.ADMIN_SECRET);
    if (payload.type !== 'session') return res.status(401).json({ ok: false });
    return res.status(200).json({ ok: true, name: payload.name });
  } catch (_) {
    return res.status(401).json({ ok: false });
  }
}

module.exports = withSecurity('check', handler);
