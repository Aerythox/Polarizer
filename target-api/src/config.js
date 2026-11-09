// Deliberately weak and public. It is the JWT flaw in this lab, not a real secret.
const WEAK_LAB_SECRET = 'secret123';

const MIN_SECRET_LENGTH = 32;

// API2. Vulnerable mode: tokens are signed with a short, guessable secret, so
// anyone who guesses it can forge a token claiming any role. Fixed mode: the
// secret comes from the environment, and the app refuses to start if it is
// missing or too short.
function resolveJwtSecret(mode, env) {
  if (mode === 'vulnerable') {
    return WEAK_LAB_SECRET;
  }

  const secret = env.JWT_SECRET ?? '';
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `JWT_SECRET must be set to at least ${MIN_SECRET_LENGTH} characters in fixed mode. See .env.example`,
    );
  }
  return secret;
}

export function loadConfig(env = process.env) {
  const mode = env.APP_MODE;
  if (mode !== 'vulnerable' && mode !== 'fixed') {
    throw new Error('APP_MODE must be set to "vulnerable" or "fixed".');
  }

  return {
    mode,
    isFixed: mode === 'fixed',
    host: env.HOST ?? '127.0.0.1',
    port: Number(env.PORT ?? 3000),
    mongoUri: env.MONGO_URI ?? 'mongodb://127.0.0.1:27017/invoice_lab',
    seedOnStart: env.SEED_ON_START === 'true',
    jwtSecret: resolveJwtSecret(mode, env),
  };
}
