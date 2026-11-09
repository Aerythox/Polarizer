import bcrypt from 'bcryptjs';
import { Invoice } from './models/invoice.js';
import { User } from './models/user.js';

// Fake lab accounts only. These passwords protect nothing real.
export const SEED_USERS = {
  alice: { name: 'Alice Example', email: 'alice@example.test', password: 'alice-lab-password', role: 'user' },
  bob: { name: 'Bob Example', email: 'bob@example.test', password: 'bob-lab-password', role: 'user' },
  admin: { name: 'Admin Example', email: 'admin@example.test', password: 'admin-lab-password', role: 'admin' },
};

// Wipes the lab database and recreates it, so every run starts the same.
export async function seed() {
  await Promise.all([User.deleteMany({}), Invoice.deleteMany({})]);

  const [alice, bob] = await Promise.all(
    [SEED_USERS.alice, SEED_USERS.bob, SEED_USERS.admin].map(async ({ password, ...user }) =>
      User.create({ ...user, passwordHash: await bcrypt.hash(password, 10) }),
    ),
  );

  await Invoice.insertMany([
    { number: 1001, ownerId: alice._id, customer: 'Fictional Bakery Co', amountCents: 125000, status: 'paid' },
    { number: 1002, ownerId: alice._id, customer: 'Sample Print Shop', amountCents: 48000, status: 'sent' },
    { number: 1003, ownerId: bob._id, customer: 'Placeholder Logistics', amountCents: 990000, status: 'sent' },
    { number: 1004, ownerId: bob._id, customer: 'Demo Coffee Roasters', amountCents: 37500, status: 'draft' },
  ]);
}
