// Proves each flaw is closed in fixed mode. A passing test here means the
// attack was blocked.
import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { loadConfig } from '../src/config.js';
import { appFor, bearer, login, seed, startDatabase, stopDatabase } from './helpers.js';

const STRONG_SECRET = 'test-only-'.repeat(5);

describe('flaws closed in fixed mode', () => {
  const app = appFor(loadConfig({ APP_MODE: 'fixed', JWT_SECRET: STRONG_SECRET }));

  before(startDatabase);
  after(stopDatabase);
  beforeEach(seed);

  it('Fix 1, BOLA: Bob gets 404 on Alice\'s invoice', async () => {
    const token = await login(app, 'bob');
    const res = await request(app).get('/invoices/1001').set(bearer(token));
    assert.equal(res.status, 404);
  });

  it('Fix 2, BFLA: a normal user gets 403 on /admin/users', async () => {
    const token = await login(app, 'bob');
    const res = await request(app).get('/admin/users').set(bearer(token));
    assert.equal(res.status, 403);
  });

  it('Fix 2, BFLA: an admin can still use /admin/users', async () => {
    const token = await login(app, 'admin');
    const res = await request(app).get('/admin/users').set(bearer(token));
    assert.equal(res.status, 200);
  });

  it('Fix 3, mass assignment: role is ignored but name still updates', async () => {
    const token = await login(app, 'bob');
    const res = await request(app)
      .patch('/profile/me')
      .set(bearer(token))
      .send({ name: 'Robert Example', role: 'admin' });
    assert.equal(res.status, 200);
    assert.equal(res.body.name, 'Robert Example');
    assert.equal(res.body.role, 'user');
  });

  it('Fix 3, mass assignment: passwordHash cannot be overwritten', async () => {
    const token = await login(app, 'bob');
    await request(app).patch('/profile/me').set(bearer(token)).send({ passwordHash: 'x' });
    await login(app, 'bob'); // Throws if the old password stopped working.
  });

  it('Fix 4, JWT: refuses to start with a missing or short secret', () => {
    assert.throws(() => loadConfig({ APP_MODE: 'fixed' }), /JWT_SECRET/);
    assert.throws(() => loadConfig({ APP_MODE: 'fixed', JWT_SECRET: 'secret123' }), /JWT_SECRET/);
  });

  it('Fix 4, JWT: rejects a token forged with the weak secret', async () => {
    const forged = jwt.sign({ sub: '000000000000000000000000', role: 'admin' }, 'secret123', {
      algorithm: 'HS256',
    });
    const res = await request(app).get('/admin/stats').set(bearer(forged));
    assert.equal(res.status, 401);
  });
});
