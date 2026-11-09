import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { Invoice } from '../models/invoice.js';

export function invoiceRoutes(config) {
  const router = Router();
  router.use(authenticate(config));

  // Safe in both modes: the query only ever matches the caller's invoices.
  router.get('/', async (req, res) => {
    const invoices = await Invoice.find({ ownerId: req.user.id }).sort('number');
    res.json(invoices);
  });

  router.get('/:number', async (req, res) => {
    const number = Number(req.params.number);
    if (!Number.isInteger(number)) {
      return res.status(400).json({ error: 'Invoice number must be an integer' });
    }

    // API1, BOLA. Vulnerable mode: the lookup uses the number alone, so any
    // logged-in user can read any invoice. Fixed mode: the invoice must also
    // belong to the caller, whose ID comes from the signed token. Someone
    // else's invoice gets 404, the same as one that does not exist, so callers
    // cannot learn which invoice numbers are in use.
    const filter = config.isFixed
      ? { number, ownerId: req.user.id }
      : { number };
    const invoice = await Invoice.findOne(filter);

    if (!invoice) {
      return res.status(404).json({ error: 'Invoice not found' });
    }
    return res.json(invoice);
  });

  return router;
}
