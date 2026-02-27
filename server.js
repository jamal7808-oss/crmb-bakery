const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const USERS_FILE = path.join(__dirname, 'users.json');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'crmb-secret-2024-bakery',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// ===== Default Data =====
const defaultData = {
  employees: [
    { id: 1, name: "أحمد محمد", role: "خباز رئيسي", salary: 3500, housing: 800 },
    { id: 2, name: "خالد عبدالله", role: "مساعد خباز", salary: 2500, housing: 600 }
  ],
  expenses: [
    { id: 1, category: "كهرباء", amount: 1200, month: "2026-02", note: "فاتورة فبراير" },
    { id: 2, category: "ماء", amount: 300, month: "2026-02", note: "" },
    { id: 3, category: "غاز", amount: 450, month: "2026-02", note: "" },
    { id: 4, category: "إنترنت", amount: 200, month: "2026-02", note: "" },
    { id: 5, category: "صيانة", amount: 350, month: "2026-02", note: "صيانة فرن" }
  ],
  rawMaterials: [
    { id: 1, name: "دقيق", qty: 500, unit: "كيلو", unitCost: 2.5, month: "2026-02" },
    { id: 2, name: "سكر", qty: 100, unit: "كيلو", unitCost: 3.0, month: "2026-02" },
    { id: 3, name: "زيت", qty: 80, unit: "لتر", unitCost: 8.0, month: "2026-02" },
    { id: 4, name: "خميرة", qty: 20, unit: "كيلو", unitCost: 15.0, month: "2026-02" },
    { id: 5, name: "ملح", qty: 30, unit: "كيلو", unitCost: 1.0, month: "2026-02" }
  ],
  rent: { amount: 5000, dueDay: 1, note: "محل الخبازة الرئيسي" },
  revenue: [
    { id: 1, source: "مبيعات خبز", amount: 18000, month: "2026-02" },
    { id: 2, source: "مبيعات حلويات", amount: 7500, month: "2026-02" },
    { id: 3, source: "طلبات خاصة", amount: 3200, month: "2026-02" }
  ],
  products: [
    { id: 1, name: "خبز أبيض كبير", category: "خبز", price: 1.5, cost: 0.7, unit: "رغيف", barcode: "6281234500011" },
    { id: 2, name: "خبز أسمر", category: "خبز", price: 2.0, cost: 0.9, unit: "رغيف", barcode: "6281234500028" },
    { id: 3, name: "كرواسان سادة", category: "معجنات", price: 3.5, cost: 1.5, unit: "قطعة", barcode: "6281234500035" },
    { id: 4, name: "كيك الشوكولاتة", category: "حلويات", price: 18.0, cost: 8.0, unit: "قطعة", barcode: "6281234500042" }
  ],
  currentMonth: "2026-02"
};

// ===== Default Users =====
const defaultUsers = [
  { id: 1, username: "admin", password: bcrypt.hashSync("admin123", 10), role: "admin", name: "المدير" },
  { id: 2, username: "user1", password: bcrypt.hashSync("user123", 10), role: "user", name: "موظف 1" }
];

// ===== File Helpers =====
function loadJSON(file, fallback) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify(fallback, null, 2));
    return fallback;
  }
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ===== Auth Middleware =====
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'غير مصرح' });
  res.redirect('/login');
}

// ===== AUTH ROUTES =====
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const users = loadJSON(USERS_FILE, defaultUsers);
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.json({ ok: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  }
  req.session.user = { id: user.id, username: user.username, role: user.role, name: user.name };
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'غير مصرح' });
  res.json(req.session.user);
});

// Change password
app.post('/api/change-password', requireAuth, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const users = loadJSON(USERS_FILE, defaultUsers);
  const idx = users.findIndex(u => u.id === req.session.user.id);
  if (idx === -1) return res.json({ ok: false, error: 'المستخدم غير موجود' });
  if (!bcrypt.compareSync(oldPassword, users[idx].password)) {
    return res.json({ ok: false, error: 'كلمة المرور الحالية غير صحيحة' });
  }
  users[idx].password = bcrypt.hashSync(newPassword, 10);
  saveJSON(USERS_FILE, users);
  res.json({ ok: true });
});

// ===== DATA API =====
app.get('/api/data', requireAuth, (req, res) => {
  res.json(loadJSON(DATA_FILE, defaultData));
});

app.post('/api/data', requireAuth, (req, res) => {
  saveJSON(DATA_FILE, req.body);
  res.json({ ok: true, savedAt: new Date().toISOString() });
});

// ===== USERS API (admin only) =====
app.get('/api/users', requireAuth, (req, res) => {
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const users = loadJSON(USERS_FILE, defaultUsers);
  res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role, name: u.name })));
});

app.post('/api/users', requireAuth, (req, res) => {
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const { username, password, role, name } = req.body;
  if (!username || !password) return res.json({ ok: false, error: 'بيانات ناقصة' });
  const users = loadJSON(USERS_FILE, defaultUsers);
  if (users.find(u => u.username === username)) return res.json({ ok: false, error: 'المستخدم موجود مسبقاً' });
  users.push({ id: Date.now(), username, password: bcrypt.hashSync(password, 10), role: role || 'user', name: name || username });
  saveJSON(USERS_FILE, users);
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireAuth, (req, res) => {
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const id = parseInt(req.params.id);
  if (id === req.session.user.id) return res.json({ ok: false, error: 'لا تستطيع حذف نفسك' });
  let users = loadJSON(USERS_FILE, defaultUsers);
  users = users.filter(u => u.id !== id);
  saveJSON(USERS_FILE, users);
  res.json({ ok: true });
});

// ===== SERVE APP =====
app.get('*', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== START =====
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n====================================');
  console.log('  🥖 CRMB Cloud - نظام محاسبة المخابز');
  console.log('====================================');
  console.log(`\n✅ السيرفر يعمل على المنفذ: ${PORT}`);
  console.log(`\n🔐 بيانات الدخول الافتراضية:`);
  console.log(`   المدير:  admin / admin123`);
  console.log(`   موظف:   user1 / user123`);
  console.log(`\n⚠️  غيّر كلمات المرور فور الدخول!`);
  console.log('====================================\n');
});
