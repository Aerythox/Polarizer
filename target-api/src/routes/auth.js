import bcrypt from 'bcryptjs';
import { Router } from 'express';
import { signToken } from '../middleware/auth.js';
import { User } from '../models/user.js';

export function authRoutes(config) {
  const router = Router();

  router.post('/login', async (req, res) => {
    const { email, password } = req.body ?? {};
    // Strings only, so a body like {"email": {"$ne": null}} cannot reach the
    // query. This lab's flaws are the four listed in the README, nothing else.
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    const passwordOk = user && (await bcrypt.compare(password, user.passwordHash));
    if (!passwordOk) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    return res.json({ token: signToken(user, config) });
  });

  return router;
}
