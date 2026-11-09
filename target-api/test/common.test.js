// Behavior that must hold in both modes. These are the controls: if any of them
// fail, the app is broken in a way that has nothing to do with the planned flaws.
import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import request from 'supertest';
import { loadConfig } from '../src/config.js';
import { appFor, bearer, login, seed, startDatabase, stopDatabase } from './helpers.js';

const STRONG_SECRET = 'test-only-'.repeat(5);

describe('config', () => {
  it('refuses to load without a valid APP_MODE', () => {
    assert.throws(() => loadConfig({}), /APP_MODE/);
    assert.throws(() => loadConfig({ APP_MODE: 'typo' }), /APP_MODE/);
  });

  it('binds to 127.0.0.1 by default', () => {
    assert.equal(loadConfig({ APP_MODE: 'vulnerable' }).host, '127.0.0.1');
  });
});

for (const mode of ['vulnerable', 'fixed']) {
  describe(`controls in ${mode} mode`, () => {
    const app = appFor(loadConfig({ APP_MODE: mode, JWT_SECRET: STRONG_SECRET }));

    before(startDatabase);
    after(stopDatabase);
    beforeEach(seed);

    it('reports its mode on /health', async () => {
      const res = await request(app).get('/health');
      assert.equal(res.status, 200);
      assert.equal(res.body.mode, mode);
    });

    it('rejects a wrong password', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: 'alice@example.test', password: 'wrong' });
      assert.equal(res.status, 401);
    });

    it('rejects a login body with query operators', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: { $ne: null }, password: { $ne: null } });
      assert.equal(res.status, 400);
    });

    for (const path of ['/invoices', '/invoices/1001', '/profile/me', '/admin/users', '/admin/stats']) {
      it(`returns 401 on ${path} without a token`, async () => {
        const res = await request(app).get(path);
        assert.equal(res.status, 401);
      });
    }

    it('lets a user read their own invoice', async () => {
      const token = await login(app, 'alice');
      const res = await request(app).get('/invoices/1001').set(bearer(token));
      assert.equal(res.status, 200);
      assert.equal(res.body.number, 1001);
    });

    it('lists only the caller\'s invoices', async () => {
      const token = await login(app, 'alice');
      const res = await request(app).get('/invoices').set(bearer(token));
      assert.deepEqual(res.body.map((invoice) => invoice.number), [1001, 1002]);
    });

    it('blocks a normal user from /admin/stats', async () => {
      const token = await login(app, 'alice');
      const res = await request(app).get('/admin/stats').set(bearer(token));
      assert.equal(res.status, 403);
    });

    it('lets an admin use /admin/stats', async () => {
      const token = await login(app, 'admin');
      const res = await request(app).get('/admin/stats').set(bearer(token));
      assert.equal(res.status, 200);
      assert.deepEqual(res.body, { userCount: 3, invoiceCount: 4 });
    });

    it('never returns a password hash', async () => {
      const token = await login(app, 'admin');
      const me = await request(app).get('/profile/me').set(bearer(token));
      const users = await request(app).get('/admin/users').set(bearer(token));
      assert.equal(me.body.passwordHash, undefined);
      assert.ok(users.body.every((user) => user.passwordHash === undefined));
    });
  });
}
