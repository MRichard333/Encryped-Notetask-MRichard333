const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const fs = require('fs');
const argon2 = require('argon2');
const os = require('os');
const { promisify } = require('util');
const EncryptionService = require('./cryptoUtils');
const bcrypt = require('bcryptjs');
const path = require('path');
const port = 3001;
const host = '127.0.0.1';


let encryption = null;
let isAccountSetup = false;
let db = null;

// Helper function to detect hash type
function detectHashType(hash) {
  if (hash.startsWith('$argon2')) {
    return 'argon2';
  } else if (hash.startsWith('$2a$') || hash.startsWith('$2b$') || hash.startsWith('$2y$')) {
    return 'bcrypt';
  }
  return 'unknown';
}
// Environment-based configuration
const isDevelopment = process.env.NODE_ENV !== 'production';

// Database path functions
function getDbPath() {
  const isDev = process.env.NODE_ENV === 'development';
  let dbPath;
  
  if (isDev) {
    dbPath = path.resolve(__dirname, 'MRichard333Todo.sqlite');
  } else {
    const userDataPath = path.join(os.homedir(), '.encrypted-todo');
    try {
      if (!fs.existsSync(userDataPath)) {
        fs.mkdirSync(userDataPath, { recursive: true });
      }
      // Verify directory is writable
      fs.accessSync(userDataPath, fs.constants.W_OK);
      dbPath = path.join(userDataPath, 'MRichard333Todo.sqlite');
    } catch (error) {
      console.error(`[${new Date().toISOString()}] Error with user data directory: ${error.message}`);
      throw error; // Let the calling code handle this
    }
  }
  
  console.log(`[${new Date().toISOString()}] Using database at: ${dbPath}`);
  return dbPath;
}

// Optional: Add a function to validate database path
function validateDbPath(dbPath) {
  const dbDir = path.dirname(dbPath);
  try {
    // Check if directory exists and is writable
    if (!fs.existsSync(dbDir)) {
      throw new Error(`Database directory does not exist: ${dbDir}`);
    }
    fs.accessSync(dbDir, fs.constants.W_OK);
    // If database file exists, check if it's readable/writable
    if (fs.existsSync(dbPath)) {
      fs.accessSync(dbPath, fs.constants.R_OK | fs.constants.W_OK);
    }
    return true;
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Database path validation failed: ${error.message}`);
    return false;
  }
}

// Optional: Add a function to get backup database path
function getBackupDbPath() {
  const mainDbPath = getDbPath();
  const dbDir = path.dirname(mainDbPath);
  const dbName = path.basename(mainDbPath, '.sqlite');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  return path.join(dbDir, `${dbName}_backup_${timestamp}.sqlite`);
}

const app = express();

// Enhanced CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3001',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:3001'
    ];
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
    },
  },
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Initialize SQLite database
async function initializeDatabase() {
  try {
    const dbPath = getDbPath();
    console.log('Attempting to open database at:', dbPath);

    // Validate the database path before proceeding
    if (!validateDbPath(dbPath)) {
      throw new Error('Database path validation failed');
    }

    const dbDir = path.dirname(dbPath);
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }

    return new Promise((resolve, reject) => {
      const database = new sqlite3.Database(dbPath, (err) => {
        if (err) {
          console.error('Database initialization error:', err.message);
          reject(err);
          return;
        }

        db = promisifyDb(database);

        // SQLite optimizations
        database.serialize(() => {
          database.run("PRAGMA journal_mode = WAL");
          database.run("PRAGMA synchronous = NORMAL");
          database.run("PRAGMA cache_size = 1000");
          database.run("PRAGMA temp_store = memory");
        });

        resolve(true);
      });
    });
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  }
}

// SQLite promisify helper
function promisifyDb(database) {
  return {
    run: function(sql, params = []) {
      return new Promise((resolve, reject) => {
        database.run(sql, params, function(err) {
          if (err) reject(err);
          else resolve({ lastID: this.lastID, changes: this.changes });
        });
      });
    },
    get: promisify(database.get.bind(database)),
    all: promisify(database.all.bind(database)),
    exec: promisify(database.exec.bind(database)),
    close: promisify(database.close.bind(database)),
    raw: database
  };
}

// Set up tables if they don't exist
async function setupTables() {
  try {
    // Updated todos table with completion status
    await db.exec(`
      CREATE TABLE IF NOT EXISTS todos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        urgency TEXT DEFAULT 'medium' CHECK (urgency IN ('low', 'medium', 'high', 'urgent')),
        reminder TEXT,
        completed BOOLEAN DEFAULT 0,
        completed_at DATETIME NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Add completion columns to existing todos table if they don't exist
    try {
      await db.exec(`ALTER TABLE todos ADD COLUMN completed BOOLEAN DEFAULT 0;`);
    } catch (err) {
      // Column already exists, ignore error
    }

    try {
      await db.exec(`ALTER TABLE todos ADD COLUMN completed_at DATETIME NULL;`);
    } catch (err) {
      // Column already exists, ignore error
    }

    await db.exec(`
      CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        passphrase TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await db.exec(`CREATE INDEX IF NOT EXISTS idx_todos_created_at ON todos(created_at);`);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_todos_urgency ON todos(urgency);`);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_todos_completed ON todos(completed);`);

    const userRow = await db.get('SELECT passphrase FROM user LIMIT 1');
    isAccountSetup = !!userRow;

    return true;
  } catch (err) {
    console.error('Error setting up database:', err);
    throw err;
  }
}

// Helper for sending server errors
function sendServerError(res, err) {
  console.error('Server Error:', err);
  if (!res.headersSent) {
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Rate limiting for authentication attempts
const authAttempts = new Map();

function checkAuthRateLimit(clientIp) {
  const now = Date.now();
  const attempts = authAttempts.get(clientIp) || [];
  
  // Remove attempts older than 15 minutes
  const validAttempts = attempts.filter(time => now - time < 15 * 60 * 1000);
  
  // Allow max 5 attempts per 15 minutes
  if (validAttempts.length >= 5) {
    return false;
  }
  
  return true;
}

function recordAuthAttempt(clientIp, success) {
  const now = Date.now();
  const attempts = authAttempts.get(clientIp) || [];
  
  if (!success) {
    attempts.push(now);
    authAttempts.set(clientIp, attempts);
  } else {
    // Clear attempts on successful auth
    authAttempts.delete(clientIp);
  }
}

// Middleware to require encryption (auth)
function requireAuth(req, res, next) {
  if (!encryption) {
    return res.status(401).json({ error: 'Not authenticated. Please unlock first.' });
  }
  next();
}

// Input validation middleware for passphrase
function validatePassphrase(req, res, next) {
  const { passphrase } = req.body;

  if (!passphrase) {
    return res.status(400).json({ error: 'Passphrase is required' });
  }
  if (typeof passphrase !== 'string') {
    return res.status(400).json({ error: 'Passphrase must be a string' });
  }
  if (passphrase.length < 6) {
    return res.status(400).json({ error: 'Passphrase must be at least 6 characters' });
  }
  if (passphrase.length > 1000) {
    return res.status(400).json({ error: 'Passphrase is too long' });
  }
  next();
}

// Validation middleware for change password
function validateChangePassword(req, res, next) {
  const { oldPassphrase, newPassphrase } = req.body;

  if (!oldPassphrase || !newPassphrase) {
    return res.status(400).json({ error: 'Both old and new passphrases are required' });
  }
  
  if (typeof oldPassphrase !== 'string' || typeof newPassphrase !== 'string') {
    return res.status(400).json({ error: 'Passphrases must be strings' });
  }
  
  if (newPassphrase.length < 6) {
    return res.status(400).json({ error: 'New passphrase must be at least 6 characters' });
  }
  
  if (newPassphrase.length > 1000) {
    return res.status(400).json({ error: 'New passphrase is too long' });
  }
  
  next();
}

// Safe decryption function
function safeDecrypt(encryptedData, todoId = 'unknown') {
  try {
    if (!encryptedData) {
      console.log(`No encrypted data for todo ${todoId}`);
      return null;
    }

    if (!encryption) {
      console.error('Encryption service not initialized');
      return null;
    }

    let parsedData;
    if (typeof encryptedData === 'string') {
      try {
        parsedData = JSON.parse(encryptedData);
      } catch (parseError) {
        console.error(`Failed to parse encrypted data for todo ${todoId}:`, parseError);
        return null;
      }
    } else if (typeof encryptedData === 'object') {
      parsedData = encryptedData;
    } else {
      console.error(`Invalid encrypted data type for todo ${todoId}:`, typeof encryptedData);
      return null;
    }

    // Validate the structure of the encrypted data
    if (!parsedData.salt || !parsedData.iv || !parsedData.tag || !parsedData.encrypted) {
      console.error(`Invalid encryption format for todo ${todoId}:`, parsedData);
      return null;
    }

    const decryptedData = encryption.decrypt(parsedData, encryption.key.toString('hex'));
    if (!decryptedData) {
      console.error(`Failed to decrypt data for todo ${todoId}`);
      return null;
    }

    return decryptedData;
  } catch (error) {
    console.error(`Failed to decrypt data for todo ${todoId}:`, error);
    return null;
  }
}

// API Routes

app.get('/api/setup-status', (req, res) => {
  res.json({ isSetup: isAccountSetup });
});

// Updated create-account route to use argon2
app.post('/api/create-account', validatePassphrase, async (req, res) => {
  const { passphrase } = req.body;
  
  if (isAccountSetup) {
    return res.status(400).json({ error: 'Account already exists' });
  }

  try {
    const salt = crypto.randomBytes(32).toString('hex');
    const hashedPassphrase = await argon2.hash(passphrase); // Now using argon2
    
    await db.run('INSERT INTO user (passphrase, salt) VALUES (?, ?)', [hashedPassphrase, salt]);
    
    encryption = new EncryptionService(passphrase, Buffer.from(salt, 'hex'));
    isAccountSetup = true;
    
    res.json({ success: true });
  } catch (err) {
    sendServerError(res, err);
  }
});

// Updated auth route with hybrid support
app.post('/api/auth', validatePassphrase, async (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress || '127.0.0.1';

  if (!checkAuthRateLimit(clientIp)) {
    return res.status(429).json({ error: 'Too many authentication attempts. Please try again later.' });
  }

  const { passphrase } = req.body;

  try {
    const row = await db.get('SELECT passphrase, salt FROM user LIMIT 1');
    
    if (!row) {
      recordAuthAttempt(clientIp, false);
      return res.status(401).json({ error: 'No account found. Please set up your account first.' });
    }

    const hashType = detectHashType(row.passphrase);
    let result = false;

    if (hashType === 'bcrypt') {
      result = await bcrypt.compare(passphrase, row.passphrase);
      
      // If bcrypt auth succeeds, migrate to argon2
      if (result) {
        console.log('Migrating password hash from bcrypt to argon2');
        const newHash = await argon2.hash(passphrase);
        await db.run('UPDATE user SET passphrase = ? WHERE id = (SELECT id FROM user LIMIT 1)', [newHash]);
      }
    } else if (hashType === 'argon2') {
      result = await argon2.verify(row.passphrase, passphrase);
    } else {
      console.error('Unknown hash type:', hashType);
      recordAuthAttempt(clientIp, false);
      return res.status(500).json({ error: 'Invalid password format' });
    }

    if (!result) {
      recordAuthAttempt(clientIp, false);
      return res.status(401).json({ error: 'Incorrect passphrase' });
    }

    encryption = new EncryptionService(passphrase, Buffer.from(row.salt, 'hex'));
    recordAuthAttempt(clientIp, true);
    
    res.json({ success: true });
  } catch (err) {
    recordAuthAttempt(clientIp, false);
    sendServerError(res, err);
  }
});

// Updated change-password route to use argon2
app.post('/api/change-password', requireAuth, validateChangePassword, async (req, res) => {
  const { oldPassphrase, newPassphrase } = req.body;

  try {
    const row = await db.get('SELECT passphrase, salt FROM user LIMIT 1');
    if (!row) {
      return res.status(404).json({ error: 'User not found' });
    }

    const hashType = detectHashType(row.passphrase);
    let isOldValid = false;

    if (hashType === 'bcrypt') {
      isOldValid = await bcrypt.compare(oldPassphrase, row.passphrase);
    } else if (hashType === 'argon2') {
      isOldValid = await argon2.verify(row.passphrase, oldPassphrase);
    }

    if (!isOldValid) {
      return res.status(401).json({ error: 'Current passphrase is incorrect' });
    }

    const hashedNewPassphrase = await argon2.hash(newPassphrase); // New password always uses argon2
    await db.run('UPDATE user SET passphrase = ? WHERE id = (SELECT id FROM user LIMIT 1)', [hashedNewPassphrase]);
    
    encryption = new EncryptionService(newPassphrase, Buffer.from(row.salt, 'hex'));
    
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (err) {
    sendServerError(res, err);
  }
});

app.post('/api/lock', (req, res) => {
  encryption = null;
  res.json({ success: true, message: 'Application locked successfully' });
});

app.post('/api/reset-account', requireAuth, async (req, res) => {
  try {
    if (!isAccountSetup) {
      return res.status(403).json({ error: 'No account exists to reset' });
    }

    await db.run('BEGIN TRANSACTION');
    await db.run('DELETE FROM user');
    await db.run('DELETE FROM todos');
    await db.run('COMMIT');

    isAccountSetup = false;
    encryption = null;
    
    res.json({ 
      success: true, 
      message: 'Account and todos have been completely reset' 
    });
  } catch (err) {
    await db.run('ROLLBACK');
    console.error('Account reset error:', err);
    sendServerError(res, err);
  }
});

app.get('/api/todos', requireAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 100); // Cap at 100
    const offset = (page - 1) * limit;

    const countQuery = await db.get('SELECT COUNT(*) as count FROM todos');
    const totalTodos = countQuery.count;

    const rows = await db.all(
      'SELECT * FROM todos ORDER BY created_at DESC LIMIT ? OFFSET ?', 
      [limit, offset]
    );

    if (rows.length === 0) {
      return res.json({
        todos: [],
        page,
        limit,
        total: totalTodos
      });
    }

    const decryptedTodos = [];
    for (const todo of rows) {
      try {
        const decryptedContent = todo.content 
          ? safeDecrypt(todo.content, todo.id) 
          : null;
        
        const decryptedReminder = todo.reminder 
          ? safeDecrypt(todo.reminder, `${todo.id}-reminder`) 
          : null;

        // Only include todos that were successfully decrypted
        if (decryptedContent !== null) {
          decryptedTodos.push({
            id: todo.id,
            content: decryptedContent,
            urgency: todo.urgency,
            reminder: decryptedReminder,
            completed: !!todo.completed,
            completed_at: todo.completed_at,
            created_at: todo.created_at,
            updated_at: todo.updated_at
          });
        }
      } catch (decryptError) {
        console.error(`Failed to process todo ${todo.id}:`, decryptError);
      }
    }

    res.json({
      todos: decryptedTodos,
      page,
      limit,
      total: totalTodos
    });
  } catch (err) {
    console.error("Error in /api/todos:", err);
    sendServerError(res, err);
  }
});

app.post('/api/todos', requireAuth, async (req, res) => {
  if (!req.body) {
    return res.status(400).json({ error: 'No request body provided' });
  }

  const { content = '', urgency = 'medium', reminder = null } = req.body;

  // Input validation
  const validationErrors = [];
  
  if (typeof content !== 'string') {
    validationErrors.push('Content must be a string');
  }

  if (content.trim().length === 0) {
    validationErrors.push('Content cannot be empty');
  }

  if (content.length > 10000) {
    validationErrors.push('Content is too long (max 10000 characters)');
  }

  const validUrgencies = ['low', 'medium', 'high', 'urgent'];
  if (!validUrgencies.includes(urgency)) {
    validationErrors.push('Invalid urgency level');
  }

  if (validationErrors.length > 0) {
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: validationErrors 
    });
  }

  try {
    const cleanContent = content.trim();
    const encryptedContent = encryption.encrypt(cleanContent);
    const encryptedReminder = reminder ? encryption.encrypt(reminder.toString().trim()) : null;

    const result = await db.run(
      'INSERT INTO todos (content, urgency, reminder, completed, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)',
      [
        JSON.stringify(encryptedContent),
        urgency,
        encryptedReminder ? JSON.stringify(encryptedReminder) : null,
        0 // New todos are not completed by default
      ]
    );

    if (!result.lastID) {
      return res.status(500).json({ error: 'Failed to create todo' });
    }

    res.status(201).json({
      id: result.lastID,
      content: cleanContent,
      urgency: urgency,
      reminder: reminder,
      completed: false,
      completed_at: null,
      created_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('Todo creation error:', err);
    sendServerError(res, err);
  }
});

app.put('/api/todos/:todoId', requireAuth, async (req, res) => {
  const id = parseInt(req.params.todoId);
  
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid todo ID' });
  }

  // Log the request for debugging
  console.log(`PUT /api/todos/${id} - Request body:`, req.body);

  // Check if the todo exists first
  try {
    const existingTodo = await db.get('SELECT * FROM todos WHERE id = ?', [id]);
    if (!existingTodo) {
      return res.status(404).json({ error: 'Todo not found' });
    }
  } catch (err) {
    console.error('Error checking todo existence:', err);
    return sendServerError(res, err);
  }

  const { content, urgency, reminder } = req.body;

  // More flexible validation - allow partial updates
  const validationErrors = [];
  
  if (content !== undefined) {
    if (typeof content !== 'string') {
      validationErrors.push('Content must be a string');
    } else if (content.trim().length === 0) {
      validationErrors.push('Content cannot be empty');
    } else if (content.length > 10000) {
      validationErrors.push('Content is too long (max 10000 characters)');
    }
  }

  if (urgency !== undefined) {
    const validUrgencies = ['low', 'medium', 'high', 'urgent'];
    if (!validUrgencies.includes(urgency)) {
      validationErrors.push('Invalid urgency level');
    }
  }

  if (validationErrors.length > 0) {
    return res.status(400).json({ 
      error: 'Validation failed', 
      details: validationErrors 
    });
  }

  try {
    // Build update query dynamically based on provided fields
    const updateFields = [];
    const updateValues = [];

    if (content !== undefined) {
      const encryptedContent = encryption.encrypt(content.trim());
      updateFields.push('content = ?');
      updateValues.push(JSON.stringify(encryptedContent));
    }

    if (urgency !== undefined) {
      updateFields.push('urgency = ?');
      updateValues.push(urgency);
    }

    if (reminder !== undefined) {
      const encryptedReminder = reminder ? encryption.encrypt(reminder.toString().trim()) : null;
      updateFields.push('reminder = ?');
      updateValues.push(encryptedReminder ? JSON.stringify(encryptedReminder) : null);
    }

    // Always update the timestamp
    updateFields.push('updated_at = CURRENT_TIMESTAMP');
    updateValues.push(id);

    if (updateFields.length === 1) { // Only timestamp update
      return res.status(400).json({ error: 'No fields to update' });
    }

    const updateQuery = `UPDATE todos SET ${updateFields.join(', ')} WHERE id = ?`;
    
    console.log('Update query:', updateQuery);
    console.log('Update values:', updateValues);

    const result = await db.run(updateQuery, updateValues);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Todo not found or no changes made' });
    }

    // Return the updated todo
    res.json({
      id: id,
      content: content !== undefined ? content.trim() : undefined,
      urgency: urgency || undefined,
      reminder: reminder !== undefined ? reminder : undefined,
    });
  } catch (err) {
    console.error('Todo update error:', err);
    sendServerError(res, err);
  }
});

// NEW: Toggle todo completion status
app.patch('/api/todos/:todoId/toggle', requireAuth, async (req, res) => {
  const id = parseInt(req.params.todoId);
  
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid todo ID' });
  }

  try {
    // Get current todo state
    const existingTodo = await db.get('SELECT * FROM todos WHERE id = ?', [id]);
    if (!existingTodo) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    const newCompletedStatus = !existingTodo.completed;
    const completedAt = newCompletedStatus ? new Date().toISOString() : null;

    // Update the completion status
    const result = await db.run(
      'UPDATE todos SET completed = ?, completed_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [newCompletedStatus ? 1 : 0, completedAt, id]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Todo not found or no changes made' });
    }

    // Decrypt and return the updated todo
    const decryptedContent = existingTodo.content 
      ? safeDecrypt(existingTodo.content, existingTodo.id) 
      : null;
    
    const decryptedReminder = existingTodo.reminder 
      ? safeDecrypt(existingTodo.reminder, `${existingTodo.id}-reminder`) 
      : null;

    res.json({
      id: id,
      content: decryptedContent,
      urgency: existingTodo.urgency,
      reminder: decryptedReminder,
      completed: newCompletedStatus,
      completed_at: completedAt,
      created_at: existingTodo.created_at,
      updated_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('Todo toggle error:', err);
    sendServerError(res, err);
  }
});

// NEW: Mark todo as completed
app.patch('/api/todos/:todoId/complete', requireAuth, async (req, res) => {
  const id = parseInt(req.params.todoId);
  
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid todo ID' });
  }

  try {
    const completedAt = new Date().toISOString();

    const result = await db.run(
      'UPDATE todos SET completed = 1, completed_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [completedAt, id]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    res.json({
      id: id,
      completed: true,
      completed_at: completedAt,
      message: 'Todo marked as completed'
    });
  } catch (err) {
    console.error('Todo completion error:', err);
    sendServerError(res, err);
  }
});

// NEW: Mark todo as uncompleted
app.patch('/api/todos/:todoId/uncomplete', requireAuth, async (req, res) => {
  const id = parseInt(req.params.todoId);
  
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid todo ID' });
  }

  try {
    const result = await db.run(
      'UPDATE todos SET completed = 0, completed_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [id]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    res.json({
      id: id,
      completed: false,
      completed_at: null,
      message: 'Todo marked as uncompleted'
    });
  } catch (err) {
    console.error('Todo uncompletion error:', err);
    sendServerError(res, err);
  }
});

app.delete('/api/todos/:todoId', requireAuth, async (req, res) => {
  const todoId = parseInt(req.params.todoId);

  if (isNaN(todoId) || todoId <= 0) {
    return res.status(400).json({ error: 'Invalid todo ID' });
  }

  try {
    const result = await db.run('DELETE FROM todos WHERE id = ?', [todoId]);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Todo not found' });
    }

    res.status(200).json({ success: true, message: 'Todo deleted successfully' });
  } catch (err) {
    sendServerError(res, err);
  }
});

app.post('/api/logout', (req, res) => {
  encryption = null;
  res.json({ success: true, message: 'Logged out successfully' });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    service: 'encrypted-todo-backend'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (!res.headersSent) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown function
async function gracefulShutdown(signal) {
  console.log(`\n[Shutdown] Received ${signal}. Starting graceful shutdown...`);

  const shutdownTimeout = setTimeout(() => {
    console.error('[Shutdown] Force quitting after timeout.');
    process.exit(1);
  }, 5000); // 5 seconds timeout

  try {
    // Close HTTP server
    if (server && typeof server.close === 'function') {
      await new Promise((resolve, reject) => {
        server.close((err) => {
          if (err) {
            console.error('[Shutdown] Error closing HTTP server:', err);
            reject(err);
          } else {
            console.log('[Shutdown] HTTP server closed.');
            resolve();
          }
        });
      });
    }

    // Close DB connection
    if (db && typeof db.close === 'function') {
      try {
        await db.close();
        console.log('[Shutdown] Database connection closed.');
      } catch (dbErr) {
        console.error('[Shutdown] Error closing database:', dbErr);
      }
    }
  } catch (err) {
    console.error('[Shutdown] Error during shutdown:', err);
  } finally {
    clearTimeout(shutdownTimeout);
    console.log('[Shutdown] Completed. Exiting now.');
    process.exit(0);
  }
}

// Attach signal handlers
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Initialize database and start server
async function startServer() {
  try {
    await initializeDatabase();
    await setupTables();
    console.log('Database initialized successfully');

    const server = app.listen(port, host, () => {
      console.log(`🔐 Encrypted ToDo API running on ${host}:${port}`);
    });

    server.on('error', (err) => {
      console.error('Server error:', err);
      process.exit(1);
    });

    // Make server available for graceful shutdown
    global.server = server;
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
startServer();

module.exports = app;
