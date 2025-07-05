require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');

const EncryptionService = require('./cryptoUtils');
let encryption = null;

const app = express();
const port = 3001;

app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
}));

app.use(express.json());

// Serve React production build
app.use(express.static(path.join(__dirname, '../client/dist')));

const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    urgency TEXT DEFAULT 'medium',
    reminder TEXT
  )`);
});

function sendServerError(res, err) {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
}

// --- Auth Route to unlock encryption ---
app.post('/api/auth', (req, res) => {
  const { passphrase } = req.body;
  if (!passphrase || passphrase.length < 6) {
    return res.status(400).json({ error: 'Passphrase must be at least 6 characters' });
  }

  try {
    const tempEnc = new EncryptionService(passphrase);

    // Test decrypt one row if exists
    db.get('SELECT content FROM todos LIMIT 1', [], (err, row) => {
      if (err) return sendServerError(res, err);

      if (row) {
        try {
          tempEnc.decrypt(row.content); // test decryption
        } catch (e) {
          return res.status(401).json({ error: 'Incorrect passphrase' });
        }
      }
      encryption = tempEnc;
      res.json({ success: true });
    });
  } catch (e) {
    sendServerError(res, e);
  }
});

// --- Change password ---
app.post('/api/change-passphrase', (req, res) => {
  if (!encryption) return res.status(401).json({ error: 'Unauthorized: Passphrase required' });

  const { currentPassphrase, newPassphrase } = req.body;
  if (!currentPassphrase || !newPassphrase) {
    return res.status(400).json({ error: 'Current and new passphrase required' });
  }
  if (newPassphrase.length < 6) {
    return res.status(400).json({ error: 'New passphrase must be at least 6 characters' });
  }

  try {
    const currentEnc = new EncryptionService(currentPassphrase);

    db.all('SELECT id, content FROM todos', [], (err, rows) => {
      if (err) return sendServerError(res, err);

      try {
        // Decrypt all todos with current key
        const decryptedTodos = rows.map(row => ({
          id: row.id,
          content: currentEnc.decrypt(row.content),
        }));

        const newEnc = new EncryptionService(newPassphrase);

        // Re-encrypt all todos with new key
        const updateStmts = decryptedTodos.map(todo => {
          const encrypted = newEnc.encrypt(todo.content);
          return new Promise((resolve, reject) => {
            db.run('UPDATE todos SET content = ? WHERE id = ?', [encrypted, todo.id], (e) => {
              if (e) reject(e);
              else resolve();
            });
          });
        });

        Promise.all(updateStmts)
          .then(() => {
            encryption = newEnc; // Update to new encryption instance
            res.json({ success: true });
          })
          .catch(updateErr => sendServerError(res, updateErr));

      } catch (decryptErr) {
        return res.status(401).json({ error: 'Incorrect current passphrase' });
      }
    });
  } catch (e) {
    sendServerError(res, e);
  }
});

// --- Lock (clear encryption key) ---
app.post('/api/lock', (req, res) => {
  encryption = null;
  res.json({ success: true });
});

// --- TODOS API ---

app.get('/api/todos', (req, res) => {
  if (!encryption) return res.status(401).json({ error: 'Unauthorized: Passphrase required' });

  db.all('SELECT * FROM todos', [], (err, rows) => {
    if (err) return sendServerError(res, err);
    try {
      const decrypted = rows.map(row => ({
        id: row.id,
        content: encryption.decrypt(row.content),
        urgency: row.urgency,
        reminder: row.reminder
      }));
      res.json(decrypted);
    } catch (e) {
      console.error('Decryption failed:', e);
      res.status(500).json({ error: 'Decryption failed' });
    }
  });
});

app.post('/api/todos', (req, res) => {
  if (!encryption) return res.status(401).json({ error: 'Unauthorized: Passphrase required' });

  const { content, urgency = 'medium', reminder = null } = req.body;
  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'Valid content required' });
  }

  try {
    const encrypted = encryption.encrypt(content.trim());
    db.run(
      'INSERT INTO todos (content, urgency, reminder) VALUES (?, ?, ?)',
      [encrypted, urgency, reminder],
      function (err) {
        if (err) return sendServerError(res, err);
        res.json({ id: this.lastID, content: content.trim(), urgency, reminder });
      }
    );
  } catch (e) {
    sendServerError(res, e);
  }
});

app.put('/api/todos/:id', (req, res) => {
  if (!encryption) return res.status(401).json({ error: 'Unauthorized: Passphrase required' });

  const id = req.params.id;
  const { content, urgency = 'medium', reminder = null } = req.body;

  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'Valid content required' });
  }

  try {
    const encrypted = encryption.encrypt(content.trim());
    db.run(
      'UPDATE todos SET content = ?, urgency = ?, reminder = ? WHERE id = ?',
      [encrypted, urgency, reminder, id],
      function (err) {
        if (err) return sendServerError(res, err);
        if (this.changes === 0) {
          return res.status(404).json({ error: 'Todo not found' });
        }
        res.json({ id, content: content.trim(), urgency, reminder });
      }
    );
  } catch (e) {
    sendServerError(res, e);
  }
});

app.delete('/api/todos/:id', (req, res) => {
  if (!encryption) return res.status(401).json({ error: 'Unauthorized: Passphrase required' });

  const id = req.params.id;
  db.run('DELETE FROM todos WHERE id = ?', [id], function (err) {
    if (err) return sendServerError(res, err);
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Todo not found' });
    }
    res.json({ success: true });
  });
});

// Fallback to frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/dist/index.html'));
});

app.listen(port, () => {
  console.log(`🔐 Encrypted ToDo API running at http://localhost:${port}`);
});
