import { Router } from 'express';
import { authenticate, requireRole } from '../middleware/auth.js';
import { Invoice } from '../models/invoice.js';
import { User } from '../models/user.js';

export function adminRoutes(config) {
  const router = Router();
  router.use(authenticate(config));

  // API5, BFLA. Vulnerable mode: the route only checks that you are logged in,
  // so any user can list every account. Fixed mode: only admins may use it.
  // 403 is fine here, because everyone already knows this route exists.
  const usersGuard = config.isFixed
    ? requireRole('admin')
    : (_req, _res, next) => next();

  router.get('/users', usersGuard, async (_req, res) => {
    const users = await User.find().sort('email');
    res.json(users);
  });

  // Protected in both modes. This is also how the attack chain proves it
  // reached admin, and it gives the scanner a route it must not flag.
  router.get('/stats', requireRole('admin'), async (_req, res) => {
    const [userCount, invoiceCount] = await Promise.all([
      User.countDocuments(),
      Invoice.countDocuments(),
    ]);
    res.json({ userCount, invoiceCount });
  });

  return router;
}
