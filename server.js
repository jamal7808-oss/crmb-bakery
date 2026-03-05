const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://crmbadmin:HlqPegvUFqbAUglU@cluster0.mvcatum.mongodb.net/?appName=Cluster0';

let db;
async function connectDB() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db('crmb');
  console.log('✅ تم الاتصال بقاعدة البيانات MongoDB');
}

const defaultData = {
  _id: 'main',
  employees: [
    { id: 1, name: "أحمد محمد", role: "خباز رئيسي", salary: 3500, housing: 800 },
    { id: 2, name: "خالد عبدالله", role: "مساعد خباز", salary: 2500, housing: 600 }
  ],
  expenses: [
    { id: 1, category: "كهرباء", amount: 1200, month: "2026-03", note: "" },
    { id: 2, category: "ماء", amount: 300, month: "2026-03", note: "" },
    { id: 3, category: "غاز", amount: 450, month: "2026-03", note: "" }
  ],
  rawMaterials: [
    { id: 1, name: "دقيق", qty: 500, unit: "كيلو", unitCost: 2.5, month: "2026-03" },
    { id: 2, name: "سكر", qty: 100, unit: "كيلو", unitCost: 3.0, month: "2026-03" }
  ],
  rent: { amount: 5000, dueDay: 1, note: "محل الخبازة الرئيسي" },
  revenue: [
    { id: 1, source: "مبيعات خبز", amount: 18000, month: "2026-03" }
  ],
  products: [],
  dailySales: [],
  equipment: [],
  currentMonth: "2026-03"
};

const defaultUsers = [
  { id: 1, username: "admin", password: bcrypt.hashSync("admin123", 10), role: "admin", name: "المدير" },
  { id: 2, username: "user1", password: bcrypt.hashSync("user123", 10), role: "user", name: "موظف 1" }
];

async function loadData() {
  let doc = await db.collection('data').findOne({ _id: 'main' });
  if (!doc) { await db.collection('data').insertOne(defaultData); doc = defaultData; }
  return doc;
}

async function saveData(data) {
  const { _id, ...rest } = data;
  await db.collection('data').updateOne({ _id: 'main' }, { $set: rest }, { upsert: true });
}

async function loadUsers() {
  const users = await db.collection('users').find({}).toArray();
  if (users.length === 0) { await db.collection('users').insertMany(defaultUsers); return defaultUsers; }
  return users;
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));
app.use(session({
  secret: process.env.SESSION_SECRET || 'crmb-secret-2024-bakery',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'غير مصرح' });
  res.redirect('/login');
}

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const users = await loadUsers();
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.json({ ok: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  req.session.user = { id: user.id, username: user.username, role: user.role, name: user.name };
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'غير مصرح' });
  res.json(req.session.user);
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const users = await loadUsers();
  const idx = users.findIndex(u => u.id === req.session.user.id);
  if (idx === -1) return res.json({ ok: false, error: 'المستخدم غير موجود' });
  if (!bcrypt.compareSync(oldPassword, users[idx].password))
    return res.json({ ok: false, error: 'كلمة المرور الحالية غير صحيحة' });
  await db.collection('users').updateOne({ id: users[idx].id }, { $set: { password: bcrypt.hashSync(newPassword, 10) } });
  res.json({ ok: true });
});

app.get('/api/data', requireAuth, async (req, res) => { res.json(await loadData()); });

app.post('/api/data', requireAuth, async (req, res) => {
  await saveData(req.body);
  res.json({ ok: true, savedAt: new Date().toISOString() });
});

app.get('/api/users', requireAuth, async (req, res) => {
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const users = await loadUsers();
  res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role, name: u.name })));
});

app.post('/api/users', requireAuth, async (req, res) => {
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const { username, password, role, name } = req.body;
  if (!username || !password) return res.json({ ok: false, error: 'بيانات ناقصة' });
  const users = await loadUsers();
  if (users.find(u => u.username === username)) return res.json({ ok: false, error: 'المستخدم موجود مسبقاً' });
  await db.collection('users').insertOne({ id: Date.now(), username, password: bcrypt.hashSync(password, 10), role: role || 'user', name: name || username });
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireAuth, async (req, res) => {
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const id = parseInt(req.params.id);
  if (id === req.session.user.id) return res.json({ ok: false, error: 'لا تستطيع حذف نفسك' });
  await db.collection('users').deleteOne({ id });
  res.json({ ok: true });
});

app.get('*', requireAuth, (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

connectDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log('\n====================================');
    console.log('  CRMB Cloud - نظام محاسبة المخابز');
    console.log('====================================');
    console.log(`✅ السيرفر يعمل على المنفذ: ${PORT}`);
    console.log('====================================\n');
  });
}).catch(err => { console.error('❌ خطأ:', err); process.exit(1); });
