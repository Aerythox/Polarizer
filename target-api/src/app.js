import express from 'express';
import { adminRoutes } from './routes/admin.js';
import { authRoutes } from './routes/auth.js';
import { invoiceRoutes } from './routes/invoices.js';
import { profileRoutes } from './routes/profile.js';

export function createApp(config) {
  const app = express();
  app.use(express.json());

  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', mode: config.mode });
  });

  app.use('/auth', authRoutes(config));
  app.use('/invoices', invoiceRoutes(config));
  app.use('/profile', profileRoutes(config));
  app.use('/admin', adminRoutes(config));

  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  // Keep stack traces out of responses.
  app.use((err, _req, res, _next) => {
    if (err.status && err.status < 500) {
      return res.status(err.status).json({ error: 'Bad request' });
    }
    if (err.name === 'ValidationError' || err.name === 'CastError' || err.code === 11000) {
      return res.status(400).json({ error: 'Invalid update' });
    }
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
