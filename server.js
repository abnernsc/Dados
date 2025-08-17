// server.js - Servidor principal SyncMaster (Versão JSON Database)
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { JsonDB, Config } = require('node-json-db');
const config = require('./config');
const fs = require('fs');
const path = require('path');

const app = express();

// Criar pasta do banco se não existir
const dbDir = path.dirname(config.DATABASE_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}
const backupDir = path.join(dbDir, 'backups');
if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir, { recursive: true });
  console.log('📁 Pasta de backups criada:', backupDir);
}
// Inicializar banco JSON
const dbPath = config.DATABASE_PATH.replace('.db', '.json');
const db = new JsonDB(new Config(dbPath, true, false, '/'));

console.log('🗄️ Banco JSON inicializado:', dbPath);

// Middlewares de segurança
app.use(helmet());
app.use(cors({
  origin: config.CORS_ORIGINS,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit(config.RATE_LIMIT);
app.use('/api/', limiter);

app.use(express.json({ limit: '10mb' }));

const performBackup = () => {
  try {
    const data = fs.readFileSync(dbPath, 'utf8');
    const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/\..+/, '');
    const backupPath = path.join(backupDir, `backup-${timestamp}.json`);
    
    fs.writeFileSync(backupPath, data);
    console.log(`💾 Backup realizado com sucesso: ${backupPath}`);
    return { success: true, path: backupPath };
  } catch (error) {
    console.error('❌ Erro ao realizar backup:', error);
    return { success: false, error: error.message };
  }
};

// =================== BANCO DE DADOS ===================

// Inicializar estrutura do banco
const initDB = async () => {
  console.log('🗄️ Inicializando banco de dados JSON...');
  
  try {
    // Criar estrutura inicial se não existir
    try {
      await db.getData('/users');
    } catch (error) {
      await db.push('/users', []);
      await db.push('/passwords', []);
      await db.push('/forms', []);
      console.log('📋 Estrutura inicial criada');
    }
    
    // Verificar se seu usuário existe
    const users = await db.getData('/users');
    const userExists = users.find(user => user.email === config.MASTER_EMAIL);
    
    if (!userExists) {
      const hashedPassword = bcrypt.hashSync(config.MASTER_PASSWORD, 12);
      const newUser = {
        id: 1,
        email: config.MASTER_EMAIL,
        password_hash: hashedPassword,
        created_at: new Date().toISOString(),
        last_login: null
      };
      
      await db.push('/users[]', newUser);
      console.log('👤 Usuário master criado:', config.MASTER_EMAIL);
    } else {
      console.log('👤 Usuário master já existe:', config.MASTER_EMAIL);
    }
    
    console.log('✅ Banco de dados inicializado!');
    
  } catch (error) {
    console.error('❌ Erro ao inicializar banco:', error);
  }
};

// =================== CRIPTOGRAFIA ===================

// Criptografar dados sensíveis
// =================== CRIPTOGRAFIA (VERSÃO MODERNA E ROBUSTA) ===================

const ALGORITHM = 'aes-256-cbc';
// Garante que a chave de criptografia tenha sempre 32 bytes, independentemente do que você colocar nas variáveis de ambiente.
const key = crypto.createHash('sha256').update(String(config.ENCRYPTION_KEY)).digest('base64').substr(0, 32);

// Criptografar dados sensíveis
const encrypt = (text) => {
  const iv = crypto.randomBytes(16); // Gera um "sal" aleatório para cada criptografia
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  // Retorna o "sal" + o texto criptografado, para que possamos descriptografar depois
  return iv.toString('hex') + ':' + encrypted;
};

// Descriptografar dados
const decrypt = (encryptedText) => {
  try {
    const parts = encryptedText.split(':');
    const iv = Buffer.from(parts.shift(), 'hex'); // Pega o "sal"
    const encryptedData = parts.join(':'); // Pega o texto criptografado
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error("Erro ao descriptografar:", error);
    return encryptedText; // Retorna o texto original se a descriptografia falhar
  }
};

// =================== MIDDLEWARE DE AUTH ===================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token de acesso requerido' });
  }
  
  jwt.verify(token, config.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// =================== ROTAS DA API ===================

// Rota de teste
app.get('/api/test', (req, res) => {
  res.json({ 
    status: 'online', 
    message: 'SyncMaster API funcionando!',
    timestamp: new Date().toISOString(),
    server: 'JSON Database'
  });
});

// Login (apenas para você!)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Verificar se é seu email
    if (email !== config.MASTER_EMAIL) {
      return res.status(401).json({ error: 'Acesso não autorizado' });
    }
    
    // Buscar usuário no banco
    const users = await db.getData('/users');
    const user = users.find(u => u.email === email);
    
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Email ou senha incorretos' });
    }
    
    // Atualizar último login
    const userIndex = users.findIndex(u => u.id === user.id);
    await db.push(`/users[${userIndex}]/last_login`, new Date().toISOString());
    
    // Gerar token JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email }, 
      config.JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    console.log('🔑 Login realizado:', email, 'em', new Date().toLocaleString());
    
    res.json({
      success: true,
      token: token,
      user: {
        id: user.id,
        email: user.email,
        name: user.email.split('@')[0]
      }
    });
    
  } catch (error) {
    console.error('❌ Erro no login:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Sincronizar senhas
app.post('/api/sync/passwords', authenticateToken, async (req, res) => {
  try {
    const { passwords } = req.body;
    const userId = req.user.userId;
    
    if (!passwords || passwords.length === 0) {
      return res.json({ success: true, message: '0 senhas sincronizadas' });
    }
    
    // Obter senhas existentes
    let existingPasswords = [];
    try {
      existingPasswords = await db.getData('/passwords');
    } catch (error) {
      // Se não existir, criar array vazio
      await db.push('/passwords', []);
      existingPasswords = [];
    }
    
    // Processar cada senha
    passwords.forEach(pwd => {
      const encryptedPassword = encrypt(pwd.password);
      
      // Verificar se já existe
      const existingIndex = existingPasswords.findIndex(p => 
        p.user_id === userId && p.site === pwd.site && p.email === pwd.email
      );
      
      const passwordData = {
        user_id: userId,
        site: pwd.site,
        email: pwd.email,
        password_encrypted: encryptedPassword,
        url: pwd.url || '',
        timestamp: pwd.timestamp,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      
      if (existingIndex >= 0) {
        // Atualizar existente
        existingPasswords[existingIndex] = { ...existingPasswords[existingIndex], ...passwordData };
      } else {
        // Adicionar novo
        passwordData.id = existingPasswords.length + 1;
        existingPasswords.push(passwordData);
      }
    });
    
    // Salvar no banco
    await db.push('/passwords', existingPasswords);
    
    console.log(`🔑 ${passwords.length} senhas sincronizadas para usuário ${req.user.email}`);
    
    res.json({ 
      success: true, 
      message: `${passwords.length} senhas sincronizadas` 
    });
    
  } catch (error) {
    console.error('❌ Erro ao sincronizar senhas:', error);
    res.status(500).json({ error: 'Erro ao sincronizar senhas' });
  }
});

// Sincronizar dados de formulários
app.post('/api/sync/forms', authenticateToken, async (req, res) => {
  try {
    const { forms } = req.body;
    const userId = req.user.userId;
    
    if (!forms || forms.length === 0) {
      return res.json({ success: true, message: '0 formulários sincronizados' });
    }
    
    // Obter formulários existentes
    let existingForms = [];
    try {
      existingForms = await db.getData('/forms');
    } catch (error) {
      await db.push('/forms', []);
      existingForms = [];
    }
    
    // Processar cada formulário
    forms.forEach(form => {
      const encryptedValue = encrypt(form.value);
      
      // Verificar se já existe
      const existingIndex = existingForms.findIndex(f => 
        f.user_id === userId && 
        f.site === form.site && 
        f.type === form.type && 
        f.field === form.field
      );
      
      const formData = {
        user_id: userId,
        site: form.site,
        type: form.type,
        field: form.field,
        value_encrypted: encryptedValue,
        timestamp: form.timestamp,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      
      if (existingIndex >= 0) {
        // Atualizar existente
        existingForms[existingIndex] = { ...existingForms[existingIndex], ...formData };
      } else {
        // Adicionar novo
        formData.id = existingForms.length + 1;
        existingForms.push(formData);
      }
    });
    
    // Salvar no banco
    await db.push('/forms', existingForms);
    
    console.log(`📝 ${forms.length} formulários sincronizados para usuário ${req.user.email}`);
    
    res.json({ 
      success: true, 
      message: `${forms.length} formulários sincronizados` 
    });
    
  } catch (error) {
    console.error('❌ Erro ao sincronizar formulários:', error);
    res.status(500).json({ error: 'Erro ao sincronizar formulários' });
  }
});

// Baixar todos os dados
app.get('/api/sync/download', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Buscar todas as senhas do usuário
    let passwordRows = [];
    try {
      const allPasswords = await db.getData('/passwords');
      passwordRows = allPasswords.filter(p => p.user_id === userId);
    } catch (error) {
      passwordRows = [];
    }
    
    // Buscar todos os formulários do usuário
    let formRows = [];
    try {
      const allForms = await db.getData('/forms');
      formRows = allForms.filter(f => f.user_id === userId);
    } catch (error) {
      formRows = [];
    }
    
    // Descriptografar senhas
    const passwords = passwordRows.map(row => ({
      site: row.site,
      email: row.email,
      password: decrypt(row.password_encrypted),
      url: row.url,
      timestamp: row.timestamp
    }));
    
    // Descriptografar formulários
    const forms = formRows.map(row => ({
      site: row.site,
      type: row.type,
      field: row.field,
      value: decrypt(row.value_encrypted),
      timestamp: row.timestamp
    }));
    
    console.log(`⬇️ Download: ${passwords.length} senhas, ${forms.length} formulários`);
    
    res.json({
      success: true,
      passwords: passwords,
      forms: forms
    });
    
  } catch (error) {
    console.error('❌ Erro ao baixar dados:', error);
    res.status(500).json({ error: 'Erro ao baixar dados' });
  }
});

// Estatísticas
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Contar senhas
    let passwordCount = 0;
    try {
      const allPasswords = await db.getData('/passwords');
      passwordCount = allPasswords.filter(p => p.user_id === userId).length;
    } catch (error) {
      passwordCount = 0;
    }
    
    // Contar formulários
    let formCount = 0;
    try {
      const allForms = await db.getData('/forms');
      formCount = allForms.filter(f => f.user_id === userId).length;
    } catch (error) {
      formCount = 0;
    }
    
    res.json({
      passwords: passwordCount,
      forms: formCount,
      lastSync: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Erro ao obter estatísticas:', error);
    res.status(500).json({ error: 'Erro ao obter estatísticas' });
  }
});
app.get('/api/backup/now', authenticateToken, (req, res) => {
  const result = performBackup();
  if (result.success) {
    res.json({ success: true, message: 'Backup realizado com sucesso!' });
  } else {
    res.status(500).json({ error: 'Falha ao realizar backup', details: result.error });
  }
});

// =================== INICIALIZAÇÃO ===================

// Inicializar servidor
const startServer = async () => {
  await initDB();
  
  const PORT = config.PORT;
  app.listen(PORT, () => {
    // ... (console.logs existentes)
    console.log('   GET  /api/stats          - Estatísticas');
    
    // ADICIONE ESTA LINHA
    console.log('   GET  /api/backup/now     - Fazer backup manual');
    
    console.log('');
    console.log('✅ Tudo funcionando! Sem problemas de compilação 🎉');

    // ADICIONE ESTE BLOCO DE CÓDIGO
    // Backup automático a cada 24 horas
    const twentyFourHours = 24 * 60 * 60 * 1000;
    setInterval(() => {
      console.log('⏰ Executando backup automático agendado...');
      performBackup();
    }, twentyFourHours);
    console.log('🗓️ Backup automático agendado para a cada 24 horas.');
  });
};

startServer().catch(console.error);

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n⏹️ Parando servidor...');
  process.exit(0);
});
