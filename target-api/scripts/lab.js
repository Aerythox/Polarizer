// Runs the API with a temporary in-memory database, so no Docker is needed.
// Usage: npm run lab -- vulnerable
//        npm run lab -- fixed
import { randomBytes } from 'node:crypto';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { loadConfig } from '../src/config.js';
import { start } from '../src/server.js';

const mode = process.argv[2];

// Fixed mode needs a strong secret. If none is set, make a random one that
// lasts only as long as this lab run.
const env = {
  ...process.env,
  APP_MODE: mode,
  JWT_SECRET: process.env.JWT_SECRET || randomBytes(48).toString('hex'),
};

try {
  // Check the settings first, so a typo fails before the database starts.
  loadConfig(env);

  const mongo = await MongoMemoryServer.create();
  await start(
    loadConfig({
      ...env,
      MONGO_URI: mongo.getUri('invoice_lab'),
      SEED_ON_START: 'true',
    }),
  );
} catch (err) {
  console.error(err.message);
  process.exit(1);
}
