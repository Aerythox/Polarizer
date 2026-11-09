import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { User } from '../models/user.js';

// An allowlist: name the fields users may change, rather than trying to list
// every field they may not.
const EDITABLE_FIELDS = ['name', 'email'];

function pickEditableFields(body) {
  const updates = {};
  for (const field of EDITABLE_FIELDS) {
    if (typeof body?.[field] === 'string') {
      updates[field] = body[field];
    }
  }
  return updates;
}

export function profileRoutes(config) {
  const router = Router();
  router.use(authenticate(config));

  router.get('/me', async (req, res) => {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json(user);
  });

  router.patch('/me', async (req, res) => {
    // API3, mass assignment. Vulnerable mode: the whole body goes into the
    // update, so a user can set role or passwordHash. Fixed mode: only the
    // allowed fields are copied, and anything else is ignored.
    const updates = config.isFixed ? pickEditableFields(req.body) : (req.body ?? {});

    const user = await User.findByIdAndUpdate(req.user.id, updates, {
      returnDocument: 'after',
      runValidators: true,
    });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json(user);
  });

  return router;
}
