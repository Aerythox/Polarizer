import jwt from 'jsonwebtoken';

export function signToken(user, config) {
  return jwt.sign({ sub: String(user._id), role: user.role }, config.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: '1h',
  });
}

// Authentication: who is this caller? It says nothing about what they may do.
export function authenticate(config) {
  return (req, res, next) => {
    const [scheme, token] = (req.headers.authorization ?? '').split(' ');
    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ error: 'Missing bearer token' });
    }

    try {
      const claims = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
      // The role comes straight from the token, so the signing secret is what
      // stops a caller from simply claiming to be an admin.
      req.user = { id: claims.sub, role: claims.role };
      return next();
    } catch {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
}

// Authorization at the function level: may this role use this route?
export function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return next();
  };
}
