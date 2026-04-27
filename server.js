require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
  return jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;

    if (!token) {
      return res.status(401).json({ message: 'No token provided.' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await get('SELECT * FROM users WHERE id=?', [decoded.id]);

    if (!user) {
      return res.status(401).json({ message: 'User not found.' });
    }

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token.' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin only.' });
  }
  next();
}

async function addColumnIfMissing(table, column, definition) {
  const columns = await all(`PRAGMA table_info(${table})`);
  const exists = columns.some(c => c.name === column);

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
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await addColumnIfMissing('purchases', 'service_name', "TEXT DEFAULT ''");
  await addColumnIfMissing('purchases', 'status', "TEXT NOT NULL DEFAULT 'pending'");
  await addColumnIfMissing('purchases', 'admin_message', "TEXT DEFAULT ''");
  await addColumnIfMissing('purchases', 'updated_at', "TEXT DEFAULT ''");

  const adminPhone = process.env.ADMIN_PHONE || '+998949903424';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Soha1212';

  const admin = await get('SELECT id FROM users WHERE phone=?', [adminPhone]);

  if (!admin) {
    await run(
      'INSERT INTO users(name,phone,password_hash,role,balance) VALUES(?,?,?,?,?)',
      [
        'Admin',
        adminPhone,
        await bcrypt.hash(adminPassword, 10),
        'admin',
        1000000
      ]
    );

    console.log(`Admin created: ${adminPhone} / ${adminPassword}`);
  }
}

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

    if (!user || !await bcrypt.compare(password, user.password_hash)) {
      return res.status(401).json({ message: 'Wrong phone or password.' });
    }

    res.json({
      token: makeToken(user),
      user: safeUser(user)
    });
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

    res.status(201).json({
      message: 'Deposit request created.',
      id: result.lastID
    });
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
  1: {
    name: 'Certificate Speaking Real Test',
    price: 10000,
    redirect: 'service1.html'
  },
  2: {
    name: 'Certificate Writing Real Test',
    price: 5000,
    redirect: 'service2.html'
  },
  3: {
    name: 'Service 3',
    price: 50000,
    redirect: 'service3.html'
  }
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

    await run(
      'UPDATE users SET balance = balance - ? WHERE id=?',
      [service.price, req.user.id]
    );

    await run(
      `INSERT INTO purchases(user_id, service_id, service_name, price, status, admin_message)
       VALUES(?,?,?,?,?,?)`,
      [
        req.user.id,
        serviceId,
        service.name,
        service.price,
        'pending',
        'Your service request was received. Please wait for admin result.'
      ]
    );

    res.json({
      message: 'Service bought successfully.',
      redirect: service.redirect
    });
  } catch (err) {
    console.error('BUY ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/services/my-orders', auth, async (req, res) => {
  try {
    const rows = await all(
      `SELECT id, service_id, service_name, price, status, admin_message, created_at, updated_at
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
        p.id,
        p.user_id,
        p.service_id,
        p.service_name,
        p.price,
        p.status,
        p.admin_message,
        p.created_at,
        p.updated_at,
        u.name,
        u.phone,
        u.gmail,
        u.telegram
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

    if (!['pending', 'in_progress', 'completed', 'declined'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status.' });
    }

    const order = await get('SELECT id FROM purchases WHERE id=?', [req.params.id]);

    if (!order) {
      return res.status(404).json({ message: 'Order not found.' });
    }

    await run(
      'UPDATE purchases SET status=?, admin_message=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
      [status, adminMessage, req.params.id]
    );

    res.json({ message: 'Order updated.' });
  } catch (err) {
    console.error('UPDATE ORDER ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.put('/api/admin/user/:id/balance', auth, adminOnly, async (req, res) => {
  try {
    const balance = Number(req.body.balance);

    if (isNaN(balance) || balance < 0) {
      return res.status(400).json({ message: 'Invalid balance.' });
    }

    await run(
      'UPDATE users SET balance=? WHERE id=?',
      [balance, req.params.id]
    );

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

    const deposit = await get(
      'SELECT * FROM deposits WHERE id=?',
      [req.params.id]
    );

    if (!deposit) {
      return res.status(404).json({ message: 'Deposit not found.' });
    }

    if (deposit.status === 'completed' && status !== 'completed') {
      await run(
        'UPDATE users SET balance = balance - ? WHERE id=?',
        [deposit.amount, deposit.user_id]
      );
    }

    if (deposit.status !== 'completed' && status === 'completed') {
      await run(
        'UPDATE users SET balance = balance + ? WHERE id=?',
        [deposit.amount, deposit.user_id]
      );
    }

    await run(
      'UPDATE deposits SET status=? WHERE id=?',
      [status, req.params.id]
    );

    res.json({ message: 'Deposit updated.' });
  } catch (err) {
    console.error('DEPOSIT STATUS ERROR:', err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('INIT ERROR:', err);
    process.exit(1);
  });
