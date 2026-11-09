import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { seed, SEED_USERS } from '../src/seed.js';

let mongo;

export async function startDatabase() {
  mongo = await MongoMemoryServer.create();
  await mongoose.connect(mongo.getUri('invoice_lab_test'));
}

export async function stopDatabase() {
  await mongoose.disconnect();
  await mongo.stop();
}

export { seed };

export function appFor(config) {
  return createApp(config);
}

export async function login(app, name) {
  const { email, password } = SEED_USERS[name];
  const res = await request(app).post('/auth/login').send({ email, password });
  if (res.status !== 200) {
    throw new Error(`Login failed for ${name}: ${res.status}`);
  }
  return res.body.token;
}

export function bearer(token) {
  return { Authorization: `Bearer ${token}` };
}
