require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// UPLOADS
const uploadsRoot = path.join(__dirname, 'uploads');

const speakingUploadsDir = path.join(uploadsRoot, 'speaking-tests');
fs.mkdirSync(speakingUploadsDir, { recursive: true });

const writingUploadsDir = path.join(uploadsRoot, 'writing-tests');
fs.mkdirSync(writingUploadsDir, { recursive: true });

const speakingStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, speakingUploadsDir),
  filename: (req, file, cb) => {
    const safeName = Date.now() + '-' + Math.round(Math.random() * 1e9) + '.webm';
    cb(null, safeName);
  }
});

const upload = multer({
  storage: speakingStorage,
  limits: { fileSize: 50 * 1024 * 1024 }
});

const writingStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, writingUploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '') || '.jpg';
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1e9) + ext);
  }
});

const writingUpload = multer({
  storage: writingStorage,
  limits: { fileSize: 20 * 1024 * 1024 }
});

// DATABASE
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'));

const run = (sql, params = []) =>
  new Promise((resolve, reject) => db.run(sql, params, function (err) {
    err ? reject(err) : resolve(this);
  }));

const get = (sql, params = []) =>
  new Promise((resolve, reject) => db.get(sql, params, (err, row) => {
    err ? reject(err) : resolve(row);
  }));

const all = (sql, params = []) =>
  new Promise((resolve, reject) => db.all(sql, params, (err, rows) => {
    err ? reject(err) : resolve(rows);
  }));

function safeUser(user) {
  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    role: user.role,
    balance: user.balance || 0,
    gmail: user.gmail || '',
    telegram: user.telegram || ''
  };
}

function makeToken(user) {
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const userToken = header.startsWith('Bearer ') ? header.slice(7) : null;

    if (!userToken) return res.status(401).json({ message: 'No token provided.' });

    const decoded = jwt.verify(userToken, JWT_SECRET);
    const user = await get('SELECT * FROM users WHERE id=?', [decoded.id]);

    if (!user) return res.status(401).json({ message: 'User not found.' });

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token.' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only.' });
  next();
}

async function addColumnIfMissing(table, column, definition) {
  const columns = await all(`PRAGMA table_info(${table})`);
  const exists = columns.some(c => c.name === column);
  if (!exists) await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

async function init() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      balance INTEGER NOT NULL DEFAULT 0,
      gmail TEXT DEFAULT '',
      telegram TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS deposits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      method TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'progress',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS purchases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      service_id INTEGER NOT NULL,
      service_name TEXT DEFAULT '',
      price INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      admin_message TEXT DEFAULT '',
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT ''
    )
  `);

  await addColumnIfMissing('purchases', 'service_name', "TEXT DEFAULT ''");
  await addColumnIfMissing('purchases', 'status', "TEXT NOT NULL DEFAULT 'pending'");
  await addColumnIfMissing('purchases', 'admin_message', "TEXT DEFAULT ''");
  await addColumnIfMissing('purchases', 'is_read', "INTEGER NOT NULL DEFAULT 0");
  await addColumnIfMissing('purchases', 'updated_at', "TEXT DEFAULT ''");

  await run(`
    CREATE TABLE IF NOT EXISTS speaking_tests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      full_name TEXT NOT NULL,
      video_name TEXT NOT NULL,
      audio_path TEXT NOT NULL,
      audio_url TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      result_message TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT ''
    )
  `);

  await addColumnIfMissing('speaking_tests', 'status', "TEXT NOT NULL DEFAULT 'pending'");
  await addColumnIfMissing('speaking_tests', 'result_message', "TEXT DEFAULT ''");
  await addColumnIfMissing('speaking_tests', 'updated_at', "TEXT DEFAULT ''");

  await run(`
    CREATE TABLE IF NOT EXISTS writing_tests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      full_name TEXT NOT NULL,

      formal_letter_question_text TEXT DEFAULT '',
      formal_letter_question_files TEXT DEFAULT '[]',
      formal_letter_answer_text TEXT DEFAULT '',
      formal_letter_answer_files TEXT DEFAULT '[]',

      informal_letter_question_text TEXT DEFAULT '',
      informal_letter_question_files TEXT DEFAULT '[]',
      informal_letter_answer_text TEXT DEFAULT '',
      informal_letter_answer_files TEXT DEFAULT '[]',

      essay_question_text TEXT DEFAULT '',
      essay_question_files TEXT DEFAULT '[]',
      essay_answer_text TEXT DEFAULT '',
      essay_answer_files TEXT DEFAULT '[]',

      status TEXT NOT NULL DEFAULT 'pending',
      result_message TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT ''
    )
  `);

  const adminPhone = process.env.ADMIN_PHONE || '+998949903424';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Soha1212';

  const admin = await get('SELECT id FROM users WHERE phone=?', [adminPhone]);

  if (!admin) {
    await run(
      'INSERT INTO users(name,phone,password_hash,role,balance) VALUES(?,?,?,?,?)',
      ['Admin', adminPhone, await bcrypt.hash(adminPassword, 10), 'admin', 1000000]
    );
    console.log(`Admin created: ${adminPhone} / ${adminPassword}`);
  }
}

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone, password } = req.body;

    if (!name || !phone || !password) {
      return res.status(400).json({ message: 'Name, phone and password are required.' });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters.' });
    }

    if (!/^\+998\d{9}$/.test(phone)) {
      return res.status(400).json({ message: 'Invalid Uzbekistan phone number.' });
    }

    const exists = await get('SELECT id FROM users WHERE phone=?', [phone]);

    if (exists) {
      return res.status(409).json({ message: 'This phone number is already registered.' });
    }

    await run(
      'INSERT INTO users(name,phone,password_hash) VALUES(?,?,?)',
      [name.trim(), phone, await bcrypt.hash(password, 10)]
    );

    res.status(201).json({ message: 'Registered successfully.' });
  } catch (err) {
    console.error('REGISTER ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = await get('SELECT * FROM users WHERE phone=?', [phone]);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ message: 'Wrong phone or password.' });
    }

    res.json({ token: makeToken(user), user: safeUser(user) });
  } catch (err) {
    console.error('LOGIN ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// PROFILE
app.get('/api/profile/me', auth, (req, res) => {
  res.json(safeUser(req.user));
});

app.put('/api/profile/update', auth, async (req, res) => {
  try {
    const name = (req.body.name || req.user.name).trim();
    const gmail = (req.body.gmail || '').trim();
    const telegram = (req.body.telegram || '').trim();

    if (name.length < 2) {
      return res.status(400).json({ message: 'Name must be at least 2 characters.' });
    }

    if (gmail && !gmail.includes('@')) {
      return res.status(400).json({ message: 'Invalid Gmail.' });
    }

    if (telegram && !telegram.startsWith('@')) {
      return res.status(400).json({ message: 'Telegram username must start with @.' });
    }

    await run(
      'UPDATE users SET name=?, gmail=?, telegram=? WHERE id=?',
      [name, gmail, telegram, req.user.id]
    );

    const updated = await get('SELECT * FROM users WHERE id=?', [req.user.id]);
    res.json(safeUser(updated));
  } catch (err) {
    console.error('PROFILE UPDATE ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// DEPOSIT
app.post('/api/deposit/create', auth, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const method = String(req.body.method || 'Admin').trim();

    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid amount.' });
    }

    const result = await run(
      'INSERT INTO deposits(user_id, amount, method, status) VALUES(?,?,?,?)',
      [req.user.id, amount, method, 'progress']
    );

    res.status(201).json({ message: 'Deposit request created.', id: result.lastID });
  } catch (err) {
    console.error('DEPOSIT CREATE ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/deposit/history', auth, async (req, res) => {
  try {
    const rows = await all(
      'SELECT id, amount, method, status, created_at FROM deposits WHERE user_id=? ORDER BY id DESC',
      [req.user.id]
    );

    res.json(rows);
  } catch (err) {
    console.error('DEPOSIT HISTORY ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// SERVICES
const services = {
  1: { name: 'Certificate Speaking Real Test', price: 10000, redirect: 'service1.html' },
  2: { name: 'Certificate Writing Real Test', price: 5000, redirect: 'service2.html' },
  3: { name: 'Service 3', price: 50000, redirect: 'service3.html' }
};

app.post('/api/services/buy', auth, async (req, res) => {
  try {
    const serviceId = Number(req.body.serviceId);
    const service = services[serviceId];

    if (!service) {
      return res.status(400).json({ message: 'Invalid service.' });
    }

    if (Number(req.user.balance) < service.price) {
      return res.status(400).json({ message: 'Not enough balance.' });
    }

    await run('UPDATE users SET balance = balance - ? WHERE id=?', [service.price, req.user.id]);

    await run(
      `INSERT INTO purchases(user_id, service_id, service_name, price, status, admin_message, is_read)
       VALUES(?,?,?,?,?,?,?)`,
      [
        req.user.id,
        serviceId,
        service.name,
        service.price,
        'pending',
        'Your service request was received. Please wait for admin result.',
        0
      ]
    );

    res.json({ message: 'Service bought successfully.', redirect: service.redirect });
  } catch (err) {
    console.error('BUY ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});// ================= ORDERS =================
app.get('/api/services/my-orders', auth, async (req, res) => {
  try {
    const rows = await all(
      `SELECT id, service_id, service_name, price, status, admin_message, is_read, created_at, updated_at
       FROM purchases
       WHERE user_id=?
       ORDER BY id DESC`,
      [req.user.id]
    );

    res.json(rows);
  } catch (err) {
    console.error('MY ORDERS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/services/my-orders/read', auth, async (req, res) => {
  try {
    await run(
      `UPDATE purchases SET is_read=1
       WHERE user_id=?
       AND (status IN ('completed','cancelled','declined') OR admin_message IS NOT NULL)`,
      [req.user.id]
    );

    res.json({ message: 'Notifications marked as read.' });
  } catch (err) {
    console.error('READ ORDERS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ================= SPEAKING =================
app.post('/api/speaking-tests', auth, upload.single('audio'), async (req, res) => {
  try {
    const fullName = (req.body.full_name || req.user.name || '').trim();
    const videoName = (req.body.video_name || '').trim();
    const file = req.file;

    if (!fullName) return res.status(400).json({ message: 'Full name is required.' });
    if (!videoName) return res.status(400).json({ message: 'Video link is required.' });
    if (!file) return res.status(400).json({ message: 'Audio file is required.' });

    const audioPath = file.path;
    const audioUrl = `/uploads/speaking-tests/${file.filename}`;

    const result = await run(
      `INSERT INTO speaking_tests(user_id, full_name, video_name, audio_path, audio_url, status, result_message)
       VALUES(?,?,?,?,?,?,?)`,
      [req.user.id, fullName, videoName, audioPath, audioUrl, 'pending', '']
    );

    res.status(201).json({
      message: 'Speaking test uploaded.',
      id: result.lastID,
      audio_url: audioUrl
    });
  } catch (err) {
    console.error('SPEAKING TEST ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/speaking-tests/my', auth, async (req, res) => {
  try {
    const rows = await all(
      `SELECT id, full_name, video_name, audio_url, status, result_message, created_at, updated_at
       FROM speaking_tests
       WHERE user_id=?
       ORDER BY id DESC`,
      [req.user.id]
    );

    res.json(rows);
  } catch (err) {
    console.error('MY SPEAKING TESTS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/speaking-tests', auth, adminOnly, async (req, res) => {
  try {
    const rows = await all(
      `SELECT s.*, u.name AS user_name, u.phone, u.gmail, u.telegram
       FROM speaking_tests s
       JOIN users u ON u.id = s.user_id
       ORDER BY s.id DESC`
    );

    res.json(rows);
  } catch (err) {
    console.error('ADMIN SPEAKING TESTS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/speaking-test/:id', auth, adminOnly, async (req, res) => {
  try {
    const status = req.body.status || 'pending';
    const resultMessage = (req.body.result_message || '').trim();

    const test = await get('SELECT * FROM speaking_tests WHERE id=?', [req.params.id]);
    if (!test) return res.status(404).json({ message: 'Speaking test not found.' });

    await run(
      'UPDATE speaking_tests SET status=?, result_message=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
      [status, resultMessage, req.params.id]
    );

    await run(
      `UPDATE purchases
       SET status=?, admin_message=?, is_read=0, updated_at=CURRENT_TIMESTAMP
       WHERE id = (
         SELECT id FROM purchases
         WHERE user_id=? AND service_id=1
         ORDER BY id DESC LIMIT 1
       )`,
      [status, resultMessage, test.user_id]
    );

    res.json({ message: 'Speaking updated.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ================= WRITING =================
const writingUploadFields = writingUpload.fields([
  { name: 'formal_letter_question_file', maxCount: 1 },
  { name: 'formal_letter_answer_files', maxCount: 5 },
  { name: 'informal_letter_question_file', maxCount: 1 },
  { name: 'informal_letter_answer_files', maxCount: 5 },
  { name: 'essay_question_file', maxCount: 1 },
  { name: 'essay_answer_files', maxCount: 5 }
]);

function uploadedUrls(files, field) {
  return JSON.stringify((files[field] || []).map(file => `/uploads/writing-tests/${file.filename}`));
}

app.post('/api/writing-tests', auth, writingUploadFields, async (req, res) => {
  try {
    const files = req.files || {};

    const result = await run(
      `INSERT INTO writing_tests(
        user_id, full_name,
        formal_letter_question_text, formal_letter_question_files,
        formal_letter_answer_text, formal_letter_answer_files,
        informal_letter_question_text, informal_letter_question_files,
        informal_letter_answer_text, informal_letter_answer_files,
        essay_question_text, essay_question_files,
        essay_answer_text, essay_answer_files,
        status, result_message
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        req.user.id,
        req.user.name || 'User',

        req.body.formal_letter_question_text || '',
        uploadedUrls(files, 'formal_letter_question_file'),
        req.body.formal_letter_answer_text || '',
        uploadedUrls(files, 'formal_letter_answer_files'),

        req.body.informal_letter_question_text || '',
        uploadedUrls(files, 'informal_letter_question_file'),
        req.body.informal_letter_answer_text || '',
        uploadedUrls(files, 'informal_letter_answer_files'),

        req.body.essay_question_text || '',
        uploadedUrls(files, 'essay_question_file'),
        req.body.essay_answer_text || '',
        uploadedUrls(files, 'essay_answer_files'),

        'pending',
        ''
      ]
    );

    res.status(201).json({ message: 'Writing test submitted.', id: result.lastID });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/writing-tests', auth, adminOnly, async (req, res) => {
  const rows = await all(
    `SELECT w.*, u.name AS user_name, u.phone, u.gmail, u.telegram
     FROM writing_tests w
     JOIN users u ON u.id = w.user_id
     ORDER BY w.id DESC`
  );

  res.json(rows);
});

app.put('/api/admin/writing-test/:id', auth, adminOnly, async (req, res) => {
  const status = req.body.status || 'pending';
  const resultMessage = (req.body.result_message || '').trim();

  const test = await get('SELECT * FROM writing_tests WHERE id=?', [req.params.id]);
  if (!test) return res.status(404).json({ message: 'Writing test not found.' });

  await run(
    'UPDATE writing_tests SET status=?, result_message=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
    [status, resultMessage, req.params.id]
  );

  await run(
    `UPDATE purchases
     SET status=?, admin_message=?, is_read=0, updated_at=CURRENT_TIMESTAMP
     WHERE id = (
       SELECT id FROM purchases
       WHERE user_id=? AND service_id=2
       ORDER BY id DESC LIMIT 1
     )`,
    [status, resultMessage, test.user_id]
  );

  res.json({ message: 'Writing updated.' });
});

// ================= FALLBACK =================
app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ================= START =================
init()
  .then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
  .catch(err => {
    console.error('INIT ERROR:', err);
    process.exit(1);
  });
