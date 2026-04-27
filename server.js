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

const run = (s, p = []) =>
  new Promise((ok, no) => db.run(s, p, function (e) { e ? no(e) : ok(this); }));

const get = (s, p = []) =>
  new Promise((ok, no) => db.get(s, p, (e, r) => e ? no(e) : ok(r)));

const all = (s, p = []) =>
  new Promise((ok, no) => db.all(s, p, (e, r) => e ? no(e) : ok(r)));

const safe = u => ({
  id: u.id,
  name: u.name,
  phone: u.phone,
  role: u.role,
  balance: u.balance || 0,
  gmail: u.gmail || '',
  telegram: u.telegram || ''
});

const token = u =>
  jwt.sign({ id: u.id, role: u.role }, JWT_SECRET, { expiresIn: '7d' });

async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const t = h.startsWith('Bearer ') ? h.slice(7) : null;

    if (!t) return res.status(401).json({ message: 'No token' });

    const d = jwt.verify(t, JWT_SECRET);
    const u = await get('SELECT * FROM users WHERE id=?', [d.id]);

    if (!u) return res.status(401).json({ message: 'User not found' });

    req.user = u;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ message: 'Admin only' });

async function init() {
  await run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    phone TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'user',
    balance INTEGER DEFAULT 0,
    gmail TEXT DEFAULT '',
    telegram TEXT DEFAULT ''
  )`);

  await run(`CREATE TABLE IF NOT EXISTS purchases(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    service_id INTEGER,
    service_name TEXT,
    price INTEGER,
    status TEXT DEFAULT 'pending',
    admin_message TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  const p = process.env.ADMIN_PHONE || '+998949903424';
  const pass = process.env.ADMIN_PASSWORD || 'Soha1212';

  if (!await get('SELECT id FROM users WHERE phone=?', [p])) {
    await run(
      'INSERT INTO users(name,phone,password_hash,role,balance) VALUES(?,?,?,?,?)',
      ['Admin', p, await bcrypt.hash(pass, 10), 'admin', 1000000]
    );
  }
}

const services = {
  1: { name: 'Speaking Test', price: 10000 },
  2: { name: 'Writing Test', price: 5000 }
};

app.post('/api/services/buy', auth, async (req, res) => {
  try {
    const s = services[req.body.serviceId];

    if (!s) return res.status(400).json({ message: 'Invalid service' });
    if (req.user.balance < s.price) return res.status(400).json({ message: 'No balance' });

    await run('UPDATE users SET balance=balance-? WHERE id=?', [s.price, req.user.id]);

    await run(
      'INSERT INTO purchases(user_id,service_id,service_name,price) VALUES(?,?,?,?)',
      [req.user.id, req.body.serviceId, s.name, s.price]
    );

    res.json({ message: 'Bought' });
  } catch (e) {
    console.log(e);
    res.status(500).json({ message: 'Error' });
  }
});

app.get('/api/services/my-orders', auth, async (req, res) => {
  const rows = await all(
    'SELECT * FROM purchases WHERE user_id=? ORDER BY id DESC',
    [req.user.id]
  );
  res.json(rows);
});

app.get('/api/admin/orders', auth, adminOnly, async (req, res) => {
  const rows = await all(
    `SELECT p.*,u.name,u.phone 
     FROM purchases p 
     JOIN users u ON u.id=p.user_id 
     ORDER BY p.id DESC`
  );
  res.json(rows);
});

app.put('/api/admin/order/:id', auth, adminOnly, async (req, res) => {
  await run(
    'UPDATE purchases SET status=?, admin_message=? WHERE id=?',
    [req.body.status, req.body.admin_message, req.params.id]
  );
  res.json({ message: 'Updated' });
});

init().then(() => {
  app.listen(PORT, () => console.log('Server running'));
});
