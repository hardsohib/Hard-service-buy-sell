require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL environment variable.');
  process.exit(1);
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const uploadsDir = path.join(__dirname, 'uploads', 'speaking-tests');
const writingUploadsDir = path.join(__dirname, 'uploads', 'writing-tests');

fs.mkdirSync(uploadsDir, { recursive: true });
fs.mkdirSync(writingUploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const safeName = Date.now() + '-' + Math.round(Math.random() * 1e9) + '.webm';
    cb(null, safeName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }
});

const writingStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, writingUploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '') || '.jpg';
    const safeName = Date.now() + '-' + Math.round(Math.random() * 1e9) + ext;
    cb(null, safeName);
  }
});

const writingUpload = multer({
  storage: writingStorage,
  limits: { fileSize: 20 * 1024 * 1024 }
});

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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false }
});

function toPostgres(sql) {
  let index = 0;
  let converted = sql.replace(/\?/g, () => `$${++index}`);

  converted = converted
    .replace(/INTEGER PRIMARY KEY AUTOINCREMENT/g, 'SERIAL PRIMARY KEY')
    .replace(/created_at TEXT DEFAULT CURRENT_TIMESTAMP/g, 'created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
    .replace(/used_at TEXT DEFAULT NULL/g, 'used_at TIMESTAMP DEFAULT NULL');

  return converted;
}

async function run(sql, params = []) {
  let query = toPostgres(sql).trim();

  if (/^INSERT\s+/i.test(query) && !/\bRETURNING\b/i.test(query)) {
    query += ' RETURNING id';
  }

  const result = await pool.query(query, params);
  return {
    lastID: result.rows && result.rows[0] ? result.rows[0].id : undefined,
    rowCount: result.rowCount
  };
}

async function get(sql, params = []) {
  const result = await pool.query(toPostgres(sql), params);
  return result.rows[0];
}

async function all(sql, params = []) {
  const result = await pool.query(toPostgres(sql), params);
  return result.rows;
}

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
  return jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '365d' });
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
  const exists = await get(
    `SELECT column_name
     FROM information_schema.columns
     WHERE table_name = $1 AND column_name = $2`,
    [table, column]
  );

  if (!exists) {
    await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
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

  await addColumnIfMissing('writing_tests', 'status', "TEXT NOT NULL DEFAULT 'pending'");
  await addColumnIfMissing('writing_tests', 'result_message', "TEXT DEFAULT ''");
  await addColumnIfMissing('writing_tests', 'updated_at', "TEXT DEFAULT ''");


  await run(`
    CREATE TABLE IF NOT EXISTS promo_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      amount INTEGER NOT NULL,
      used_by INTEGER DEFAULT NULL,
      used_at TEXT DEFAULT NULL,
      created_by INTEGER DEFAULT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const adminPhone = process.env.ADMIN_PHONE || '+998949903424';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Soha1212';
await run(
  `DELETE FROM users WHERE role='admin'`
);

await run(
  `INSERT INTO users(name, phone, password_hash, role, balance)
   VALUES(?,?,?,?,?)`,
  ['Admin', adminPhone, await bcrypt.hash(adminPassword, 10), 'admin', 1000000]
);

console.log('Admin reset:', adminPhone);
 

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
});

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

app.post('/api/speaking-tests', auth, upload.single('audio'), async (req, res) => {
  try {
    const fullName = (req.body.full_name || req.user.name || '').trim();
    const videoName = (req.body.video_name || '').trim();
    const file = req.file;

    if (!fullName) {
      return res.status(400).json({ message: 'Full name is required.' });
    }

    if (!videoName) {
      return res.status(400).json({ message: 'Video link is required.' });
    }

    if (!file) {
      return res.status(400).json({ message: 'Audio file is required.' });
    }

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
    console.error('SPEAKING TEST UPLOAD ERROR:', err.message);
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
      `SELECT
        s.id,
        s.user_id,
        s.full_name,
        s.video_name,
        s.audio_url,
        s.status,
        s.result_message,
        s.created_at,
        s.updated_at,
        u.name AS user_name,
        u.phone,
        u.gmail,
        u.telegram
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

    if (!['pending', 'checking', 'completed', 'declined'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status.' });
    }

    const test = await get(
      'SELECT * FROM speaking_tests WHERE id=?',
      [req.params.id]
    );

    if (!test) {
      return res.status(404).json({ message: 'Speaking test not found.' });
    }

    await run(
      'UPDATE speaking_tests SET status=?, result_message=?, updated_at=CURRENT_TIMESTAMP::text WHERE id=?',
      [status, resultMessage, req.params.id]
    );

    await run(
      `UPDATE purchases
       SET status=?, admin_message=?, is_read=0, updated_at=CURRENT_TIMESTAMP::text
       WHERE id = (
         SELECT id FROM purchases
         WHERE user_id=? AND service_id=1
         ORDER BY id DESC
         LIMIT 1
       )`,
      [status, resultMessage, test.user_id]
    );

    res.json({ message: 'Speaking test and service box updated.' });
  } catch (err) {
    console.error('UPDATE SPEAKING TEST ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/admin/speaking-test/:id', auth, adminOnly, async (req, res) => {
  try {
    const test = await get('SELECT id, audio_path FROM speaking_tests WHERE id=?', [req.params.id]);

    if (!test) {
      return res.status(404).json({ message: 'Speaking test not found.' });
    }

    await run('DELETE FROM speaking_tests WHERE id=?', [req.params.id]);

    if (test.audio_path && fs.existsSync(test.audio_path)) {
      fs.unlinkSync(test.audio_path);
    }

    res.json({ message: 'Speaking test deleted.' });
  } catch (err) {
    console.error('DELETE SPEAKING TEST ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});


app.post('/api/writing-tests', auth, writingUploadFields, async (req, res) => {
  try {
    const files = req.files || {};
    const fullName = (req.user.name || 'User').trim();

    const hasAnyText =
      (req.body.formal_letter_question_text || '').trim() ||
      (req.body.formal_letter_answer_text || '').trim() ||
      (req.body.informal_letter_question_text || '').trim() ||
      (req.body.informal_letter_answer_text || '').trim() ||
      (req.body.essay_question_text || '').trim() ||
      (req.body.essay_answer_text || '').trim();

    const hasAnyFile = Object.values(files).some(arr => Array.isArray(arr) && arr.length > 0);

    if (!hasAnyText && !hasAnyFile) {
      return res.status(400).json({ message: 'Please write or upload at least one section.' });
    }

    const result = await run(
      `INSERT INTO writing_tests(
        user_id, full_name,
        formal_letter_question_text, formal_letter_question_files, formal_letter_answer_text, formal_letter_answer_files,
        informal_letter_question_text, informal_letter_question_files, informal_letter_answer_text, informal_letter_answer_files,
        essay_question_text, essay_question_files, essay_answer_text, essay_answer_files,
        status, result_message
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        req.user.id,
        fullName,
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

    res.status(201).json({
      message: 'Writing test submitted.',
      id: result.lastID
    });
  } catch (err) {
    console.error('WRITING TEST UPLOAD ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/writing-tests/my', auth, async (req, res) => {
  try {
    const rows = await all(
      `SELECT id, full_name, status, result_message, created_at, updated_at
       FROM writing_tests
       WHERE user_id=?
       ORDER BY id DESC`,
      [req.user.id]
    );

    res.json(rows);
  } catch (err) {
    console.error('MY WRITING TESTS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/writing-tests', auth, adminOnly, async (req, res) => {
  try {
    const rows = await all(
      `SELECT
        w.*,
        u.name AS user_name,
        u.phone,
        u.gmail,
        u.telegram
       FROM writing_tests w
       JOIN users u ON u.id = w.user_id
       ORDER BY w.id DESC`
    );

    res.json(rows);
  } catch (err) {
    console.error('ADMIN WRITING TESTS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/writing-test/:id', auth, adminOnly, async (req, res) => {
  try {
    const status = req.body.status || 'pending';
    const resultMessage = (req.body.result_message || '').trim();

    if (!['pending', 'checking', 'completed', 'declined'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status.' });
    }

    const test = await get('SELECT * FROM writing_tests WHERE id=?', [req.params.id]);

    if (!test) {
      return res.status(404).json({ message: 'Writing test not found.' });
    }

    await run(
      'UPDATE writing_tests SET status=?, result_message=?, updated_at=CURRENT_TIMESTAMP::text WHERE id=?',
      [status, resultMessage, req.params.id]
    );

    await run(
      `UPDATE purchases
       SET status=?, admin_message=?, is_read=0, updated_at=CURRENT_TIMESTAMP::text
       WHERE id = (
         SELECT id FROM purchases
         WHERE user_id=? AND service_id=2
         ORDER BY id DESC
         LIMIT 1
       )`,
      [status, resultMessage, test.user_id]
    );

    res.json({ message: 'Writing test and service box updated.' });
  } catch (err) {
    console.error('UPDATE WRITING TEST ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/admin/writing-test/:id', auth, adminOnly, async (req, res) => {
  try {
    const test = await get('SELECT * FROM writing_tests WHERE id=?', [req.params.id]);

    if (!test) {
      return res.status(404).json({ message: 'Writing test not found.' });
    }

    const fields = [
      'formal_letter_question_files',
      'formal_letter_answer_files',
      'informal_letter_question_files',
      'informal_letter_answer_files',
      'essay_question_files',
      'essay_answer_files'
    ];

    for (const field of fields) {
      let urls = [];
      try {
        urls = JSON.parse(test[field] || '[]');
      } catch {
        urls = [];
      }

      for (const url of urls) {
        const filePath = path.join(__dirname, url.replace(/^\/+/, ''));
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      }
    }

    await run('DELETE FROM writing_tests WHERE id=?', [req.params.id]);

    res.json({ message: 'Writing test deleted.' });
  } catch (err) {
    console.error('DELETE WRITING TEST ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});



app.post('/api/admin/promo-codes', auth, adminOnly, async (req, res) => {
  try {
    let code = String(req.body.code || '').trim().toUpperCase();
    const amount = Number(req.body.amount);

    if (!code) {
      code = 'PROMO-' + Math.random().toString(36).slice(2, 8).toUpperCase();
    }

    if (!/^[A-Z0-9_-]{4,30}$/.test(code)) {
      return res.status(400).json({ message: 'Promo code must be 4-30 characters: A-Z, 0-9, _ or - only.' });
    }

    if (!amount || amount < 5000) {
      return res.status(400).json({ message: 'Promo amount must be at least 5000 UZS.' });
    }

    const exists = await get('SELECT id FROM promo_codes WHERE code=?', [code]);
    if (exists) {
      return res.status(409).json({ message: 'This promo code already exists.' });
    }

    const result = await run(
      'INSERT INTO promo_codes(code, amount, created_by) VALUES(?,?,?)',
      [code, amount, req.user.id]
    );

    res.status(201).json({
      message: 'Promo code created.',
      id: result.lastID,
      code,
      amount
    });
  } catch (err) {
    console.error('CREATE PROMO ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/promo-codes', auth, adminOnly, async (req, res) => {
  try {
    const rows = await all(
      `SELECT
        p.id,
        p.code,
        p.amount,
        p.used_by,
        p.used_at,
        p.created_at,
        u.name AS used_by_name,
        u.phone AS used_by_phone
       FROM promo_codes p
       LEFT JOIN users u ON u.id = p.used_by
       ORDER BY p.id DESC`
    );

    res.json(rows);
  } catch (err) {
    console.error('ADMIN PROMO LIST ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/admin/promo-code/:id', auth, adminOnly, async (req, res) => {
  try {
    const promo = await get('SELECT * FROM promo_codes WHERE id=?', [req.params.id]);
    if (!promo) return res.status(404).json({ message: 'Promo code not found.' });

    if (promo.used_by) {
      return res.status(400).json({ message: 'Used promo code cannot be deleted.' });
    }

    await run('DELETE FROM promo_codes WHERE id=?', [req.params.id]);
    res.json({ message: 'Promo code deleted.' });
  } catch (err) {
    console.error('DELETE PROMO ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/promo/redeem', auth, async (req, res) => {
  try {
    const code = String(req.body.code || '').trim().toUpperCase();

    if (!code) {
      return res.status(400).json({ message: 'Promo code is required.' });
    }

    const promo = await get('SELECT * FROM promo_codes WHERE code=?', [code]);

    if (!promo) {
      return res.status(404).json({ message: 'Invalid promo code.' });
    }

    if (promo.used_by) {
      return res.status(400).json({ message: 'This promo code was already used.' });
    }

    await run(
      'UPDATE promo_codes SET used_by=?, used_at=CURRENT_TIMESTAMP WHERE id=? AND used_by IS NULL',
      [req.user.id, promo.id]
    );

    await run(
      'UPDATE users SET balance = balance + ? WHERE id=?',
      [promo.amount, req.user.id]
    );

    const updatedUser = await get('SELECT * FROM users WHERE id=?', [req.user.id]);

    res.json({
      message: `Promo applied. ${Number(promo.amount).toLocaleString('en-US')} UZS added to your balance.`,
      amount: promo.amount,
      balance: updatedUser.balance,
      user: safeUser(updatedUser)
    });
  } catch (err) {
    console.error('REDEEM PROMO ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});


app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const rows = await all(
      'SELECT id, name, phone, role, balance, gmail, telegram, created_at FROM users ORDER BY id DESC'
    );

    res.json(rows);
  } catch (err) {
    console.error('ADMIN USERS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/deposits', auth, adminOnly, async (req, res) => {
  try {
    const rows = await all(
      `SELECT d.id, d.amount, d.method, d.status, d.created_at, u.name, u.phone
       FROM deposits d
       JOIN users u ON u.id = d.user_id
       ORDER BY d.id DESC`
    );

    res.json(rows);
  } catch (err) {
    console.error('ADMIN DEPOSITS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/admin/orders', auth, adminOnly, async (req, res) => {
  try {
    const rows = await all(
      `SELECT 
        p.id, p.user_id, p.service_id, p.service_name, p.price, p.status,
        p.admin_message, p.is_read, p.created_at, p.updated_at,
        u.name, u.phone, u.gmail, u.telegram
       FROM purchases p
       JOIN users u ON u.id = p.user_id
       ORDER BY p.id DESC`
    );

    res.json(rows);
  } catch (err) {
    console.error('ADMIN ORDERS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/order/:id', auth, adminOnly, async (req, res) => {
  try {
    const status = req.body.status || 'pending';
    const adminMessage = (req.body.admin_message || req.body.message || '').trim();

    if (!['pending', 'checking', 'in_progress', 'completed', 'cancelled', 'declined'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status.' });
    }

    const order = await get('SELECT * FROM purchases WHERE id=?', [req.params.id]);

    if (!order) {
      return res.status(404).json({ message: 'Order not found.' });
    }

    const shouldRefund =
      order.status !== 'cancelled' &&
      order.status !== 'declined' &&
      (status === 'cancelled' || status === 'declined');

    if (shouldRefund) {
      await run(
        'UPDATE users SET balance = balance + ? WHERE id=?',
        [order.price, order.user_id]
      );
    }

    await run(
      'UPDATE purchases SET status=?, admin_message=?, is_read=0, updated_at=CURRENT_TIMESTAMP::text WHERE id=?',
      [status, adminMessage, req.params.id]
    );

    res.json({
      message: shouldRefund ? 'Order updated and money refunded.' : 'Order updated.',
      refunded: shouldRefund,
      refund_amount: shouldRefund ? order.price : 0
    });
  } catch (err) {
    console.error('UPDATE ORDER ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/admin/order/:id', auth, adminOnly, async (req, res) => {
  try {
    const order = await get('SELECT id FROM purchases WHERE id=?', [req.params.id]);

    if (!order) {
      return res.status(404).json({ message: 'Order not found.' });
    }

    await run('DELETE FROM purchases WHERE id=?', [req.params.id]);

    res.json({ message: 'Order deleted.' });
  } catch (err) {
    console.error('DELETE ORDER ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/user/:id/balance', auth, adminOnly, async (req, res) => {
  try {
    const balance = Number(req.body.balance);

    if (isNaN(balance) || balance < 0) {
      return res.status(400).json({ message: 'Invalid balance.' });
    }

    await run('UPDATE users SET balance=? WHERE id=?', [balance, req.params.id]);

    res.json({ message: 'Balance updated.' });
  } catch (err) {
    console.error('BALANCE UPDATE ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/user/:id/password', auth, adminOnly, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password || password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters.' });
    }

    await run(
      'UPDATE users SET password_hash=? WHERE id=?',
      [await bcrypt.hash(password, 10), req.params.id]
    );

    res.json({ message: 'Password updated.' });
  } catch (err) {
    console.error('PASSWORD UPDATE ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/user/:id/info', auth, adminOnly, async (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    const phone = (req.body.phone || '').trim();
    const gmail = (req.body.gmail || '').trim();
    const telegram = (req.body.telegram || '').trim();

    if (!name || !phone) {
      return res.status(400).json({ message: 'Name and phone are required.' });
    }

    await run(
      'UPDATE users SET name=?, phone=?, gmail=?, telegram=? WHERE id=?',
      [name, phone, gmail, telegram, req.params.id]
    );

    res.json({ message: 'User info updated.' });
  } catch (err) {
    console.error('USER INFO UPDATE ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/deposit/:id/status', auth, adminOnly, async (req, res) => {
  try {
    const status = req.body.status;

    if (!['completed', 'declined', 'progress'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status.' });
    }

    const deposit = await get('SELECT * FROM deposits WHERE id=?', [req.params.id]);

    if (!deposit) {
      return res.status(404).json({ message: 'Deposit not found.' });
    }

    if (deposit.status === 'completed' && status !== 'completed') {
      await run('UPDATE users SET balance = balance - ? WHERE id=?', [deposit.amount, deposit.user_id]);
    }

    if (deposit.status !== 'completed' && status === 'completed') {
      await run('UPDATE users SET balance = balance + ? WHERE id=?', [deposit.amount, deposit.user_id]);
    }

    await run('UPDATE deposits SET status=? WHERE id=?', [status, req.params.id]);

    res.json({ message: 'Deposit updated.' });
  } catch (err) {
    console.error('DEPOSIT STATUS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

init()
  .then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
  .catch(err => {
    console.error('INIT ERROR:', err);
    process.exit(1);
  });
