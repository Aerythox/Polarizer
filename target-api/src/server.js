import mongoose from 'mongoose';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { seed } from './seed.js';

function printBanner(config) {
  console.log(`Invoice lab API running in ${config.mode.toUpperCase()} mode`);
  if (!config.isFixed) {
    console.warn('WARNING: this mode is DELIBERATELY INSECURE. Keep it on your own machine. Never deploy it.');
  }
}

export async function start(config) {
  await mongoose.connect(config.mongoUri);
  if (config.seedOnStart) {
    await seed();
  }

  const app = createApp(config);
  app.listen(config.port, config.host, () => {
    printBanner(config);
    console.log(`Listening on ${config.host}:${config.port}`);
  });
}

// Runs only when started directly, such as `node src/server.js`.
if (import.meta.main ?? process.argv[1]?.endsWith('server.js')) {
  try {
    await start(loadConfig());
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
