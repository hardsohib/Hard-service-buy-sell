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
const run=(s,p=[])=>new Promise((ok,no)=>db.run(s,p,function(e){e?no(e):ok(this)}));
const get=(s,p=[])=>new Promise((ok,no)=>db.get(s,p,(e,r)=>e?no(e):ok(r)));
const all=(s,p=[])=>new Promise((ok,no)=>db.all(s,p,(e,r)=>e?no(e):ok(r)));
const safe=u=>({id:u.id,name:u.name,phone:u.phone,role:u.role,balance:u.balance||0,gmail:u.gmail||'',telegram:u.telegram||''});
const token=u=>jwt.sign({id:u.id,role:u.role},JWT_SECRET,{expiresIn:'7d'});
async function auth(req,res,next){try{const h=req.headers.authorization||'';const t=h.startsWith('Bearer ')?h.slice(7):null;if(!t)return res.status(401).json({message:'No token provided.'});const d=jwt.verify(t,JWT_SECRET);const u=await get('SELECT * FROM users WHERE id=?',[d.id]);if(!u)return res.status(401).json({message:'User not found.'});req.user=u;next()}catch{return res.status(401).json({message:'Invalid token.'})}}
const adminOnly=(req,res,next)=>req.user.role==='admin'?next():res.status(403).json({message:'Admin only.'});
async function init(){
await run(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,phone TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',balance INTEGER NOT NULL DEFAULT 0,gmail TEXT DEFAULT '',telegram TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
await run(`CREATE TABLE IF NOT EXISTS deposits(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,amount INTEGER NOT NULL,method TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'progress',created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
await run(`CREATE TABLE IF NOT EXISTS purchases(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,service_id INTEGER NOT NULL,price INTEGER NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
const p=process.env.ADMIN_PHONE||'+998901234567', pass=process.env.ADMIN_PASSWORD||'admin12345';
if(!await get('SELECT id FROM users WHERE phone=?',[p])){await run('INSERT INTO users(name,phone,password_hash,role,balance) VALUES(?,?,?,?,?)',['Admin',p,await bcrypt.hash(pass,10),'admin',1000000]);console.log(`Admin created: ${p} / ${pass}`)}
}
app.post('/api/auth/register',async(req,res)=>{try{const{name,phone,password}=req.body;if(!name||!phone||!password)return res.status(400).json({message:'Name, phone and password are required.'});if(password.length<8)return res.status(400).json({message:'Password must be at least 8 characters.'});if(!/^\+998\d{9}$/.test(phone))return res.status(400).json({message:'Invalid Uzbekistan phone number.'});if(await get('SELECT id FROM users WHERE phone=?',[phone]))return res.status(409).json({message:'This phone number is already registered.'});await run('INSERT INTO users(name,phone,password_hash) VALUES(?,?,?)',[name.trim(),phone,await bcrypt.hash(password,10)]);res.status(201).json({message:'Registered successfully.'})}catch{res.status(500).json({message:'Server error.'})}});
app.post('/api/auth/login',async(req,res)=>{try{const{phone,password}=req.body;const u=await get('SELECT * FROM users WHERE phone=?',[phone]);if(!u||!await bcrypt.compare(password,u.password_hash))return res.status(401).json({message:'Wrong phone or password.'});res.json({token:token(u),user:safe(u)})}catch{res.status(500).json({message:'Server error.'})}});
app.get('/api/profile/me',auth,(req,res)=>res.json(safe(req.user)));
app.put('/api/profile/update',auth,async(req,res)=>{try{const name=(req.body.name||req.user.name).trim(),gmail=(req.body.gmail||'').trim(),telegram=(req.body.telegram||'').trim();if(name.length<2)return res.status(400).json({message:'Name must be at least 2 characters.'});if(gmail&&!gmail.includes('@'))return res.status(400).json({message:'Invalid Gmail.'});if(telegram&&!telegram.startsWith('@'))return res.status(400).json({message:'Telegram username must start with @.'});await run('UPDATE users SET name=?,gmail=?,telegram=? WHERE id=?',[name,gmail,telegram,req.user.id]);res.json(safe(await get('SELECT * FROM users WHERE id=?',[req.user.id])))}catch{res.status(500).json({message:'Server error.'})}});
app.post('/api/deposit/create',auth,async(req,res)=>{try{const amount=Number(req.body.amount),method=String(req.body.method||'Admin').trim();if(!amount||amount<=0)return res.status(400).json({message:'Invalid amount.'});const r=await run('INSERT INTO deposits(user_id,amount,method,status) VALUES(?,?,?,?)',[req.user.id,amount,method,'progress']);res.status(201).json({message:'Deposit request created.',id:r.lastID})}catch{res.status(500).json({message:'Server error.'})}});
app.get('/api/deposit/history',auth,async(req,res)=>res.json(await all('SELECT id,amount,method,status,created_at FROM deposits WHERE user_id=? ORDER BY id DESC',[req.user.id])));
const services={1:{price:650000,redirect:'service1.html'},2:{price:520000,redirect:'service2.html'},3:{price:430000,redirect:'service3.html'}};
app.post('/api/services/buy',auth,async(req,res)=>{try{const sid=Number(req.body.serviceId),s=services[sid];if(!s)return res.status(400).json({message:'Invalid service.'});if(Number(req.user.balance)<s.price)return res.status(400).json({message:'Not enough balance.'});await run('UPDATE users SET balance=balance-? WHERE id=?',[s.price,req.user.id]);await run('INSERT INTO purchases(user_id,service_id,price) VALUES(?,?,?)',[req.user.id,sid,s.price]);res.json({message:'Service bought successfully.',redirect:s.redirect})}catch{res.status(500).json({message:'Server error.'})}});
app.get('/api/admin/users',auth,adminOnly,async(req,res)=>res.json(await all('SELECT id,name,phone,role,balance,gmail,telegram,created_at FROM users ORDER BY id DESC')));
app.get('/api/admin/deposits',auth,adminOnly,async(req,res)=>res.json(await all('SELECT d.id,d.amount,d.method,d.status,d.created_at,u.name,u.phone FROM deposits d JOIN users u ON u.id=d.user_id ORDER BY d.id DESC')));
app.put('/api/admin/user/:id/balance',auth,adminOnly,async(req,res)=>{const b=Number(req.body.balance);if(isNaN(b)||b<0)return res.status(400).json({message:'Invalid balance.'});await run('UPDATE users SET balance=? WHERE id=?',[b,req.params.id]);res.json({message:'Balance updated.'})});
app.put('/api/admin/user/:id/password',auth,adminOnly,async(req,res)=>{const{password}=req.body;if(!password||password.length<8)return res.status(400).json({message:'Password must be at least 8 characters.'});await run('UPDATE users SET password_hash=? WHERE id=?',[await bcrypt.hash(password,10),req.params.id]);res.json({message:'Password updated.'})});
app.put('/api/admin/user/:id/info',auth,adminOnly,async(req,res)=>{const name=(req.body.name||'').trim(),phone=(req.body.phone||'').trim(),gmail=(req.body.gmail||'').trim(),telegram=(req.body.telegram||'').trim();if(!name||!phone)return res.status(400).json({message:'Name and phone are required.'});await run('UPDATE users SET name=?,phone=?,gmail=?,telegram=? WHERE id=?',[name,phone,gmail,telegram,req.params.id]);res.json({message:'User info updated.'})});
app.put('/api/admin/deposit/:id/status',auth,adminOnly,async(req,res)=>{try{const status=req.body.status;if(!['completed','declined','progress'].includes(status))return res.status(400).json({message:'Invalid status.'});const d=await get('SELECT * FROM deposits WHERE id=?',[req.params.id]);if(!d)return res.status(404).json({message:'Deposit not found.'});if(d.status==='completed'&&status!=='completed')await run('UPDATE users SET balance=balance-? WHERE id=?',[d.amount,d.user_id]);if(d.status!=='completed'&&status==='completed')await run('UPDATE users SET balance=balance+? WHERE id=?',[d.amount,d.user_id]);await run('UPDATE deposits SET status=? WHERE id=?',[status,req.params.id]);res.json({message:'Deposit updated.'})}catch{res.status(500).json({message:'Server error.'})}});
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
init().then(()=>app.listen(PORT,()=>console.log(`Server running: http://localhost:${PORT}`))).catch(e=>{console.error(e);process.exit(1)});
