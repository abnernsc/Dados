module.exports = {
  MASTER_EMAIL: process.env.MASTER_EMAIL || 'abner.vnascimento@gmail.com',
  MASTER_PASSWORD: process.env.MASTER_PASSWORD || 'naumT3interec4',
  JWT_SECRET: process.env.JWT_SECRET || 'chave-jwt-padrao',
  ENCRYPTION_KEY: process.env.ENCRYPTION_KEY || 'chave-criptografia-padrao',
  PORT: process.env.PORT || 3000,
  
  RATE_LIMIT: {
    windowMs: 15 * 60 * 1000,
    max: 100
  },
  
  DATABASE_PATH: './database/syncmaster.db',
  
  CORS_ORIGINS: [
    'chrome-extension://*',
    'moz-extension://*',
    process.env.FRONTEND_URL || 'bancodados-production.up.railway.app',
  ]
};