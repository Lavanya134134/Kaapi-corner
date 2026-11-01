require('dotenv').config();
const express = require('express'), helmet = require('helmet'), crypto = require('crypto'), { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 10 });
const q = async (sql, p = []) => (await pool.query(sql, p)).rows;
class AppErr extends Error {}

const hash = (p, s = crypto.randomBytes(16).toString('hex')) => s + ':' + crypto.scryptSync(p, s, 32).toString('hex');
const verify = (p, h) => { const [s, k] = h.split(':'); return crypto.timingSafeEqual(Buffer.from(k, 'hex'), crypto.scryptSync(p, s, 32)); };
const SLOTS = ['Morning 9-12', 'Evening 4-8'], PAY = ['COD', 'UPI'], STAT = ['Placed', 'Packed', 'Shipped', 'Delivered'];
const str = s => typeof s === 'string' && s.trim().length > 0 && s.length <= 200;
const idp = r => parseInt(r.params.id, 10) || 0;
const OCOLS = "id,user_id,name,phone,address,slot,payment,coupon,discount,total,status,to_char(created_at,'YYYY-MM-DD HH24:MI') created_at";

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use(express.static('public'));
const h = f => (req, res, next) => f(req, res, next).catch(next);

const hits = new Map(); // simple brute-force protection: 20 login/register tries per 15 min per IP
const limit = (req, res, next) => {
  const n = Date.now(), a = (hits.get(req.ip) || []).filter(t => n - t < 9e5);
  if (a.length >= 20) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  a.push(n); hits.set(req.ip, a); next();
};

// ---- auth (sessions expire after 7 days)
const newSession = async id => {
  const token = crypto.randomBytes(24).toString('hex');
  await q('INSERT INTO sessions(token,user_id) VALUES($1,$2)', [token, id]);
  return { token, user: (await q('SELECT id,name,email,role FROM users WHERE id=$1', [id]))[0] };
};
const auth = h(async (req, res, next) => {
  const t = (req.headers.authorization || '').slice(7) || req.query.t;
  const u = t && (await q('SELECT u.id,u.name,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=$1 AND s.expires_at>now()', [String(t)]))[0];
  if (!u) return res.status(401).json({ error: 'Please login' });
  req.user = u; next();
});
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });

app.post('/api/register', limit, h(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!str(name) || !/^\S+@\S+\.\S+$/.test(email || '') || typeof password !== 'string' || password.length < 6)
    return res.status(400).json({ error: 'Enter name, valid email and 6+ character password' });
  try {
    const r = await q('INSERT INTO users(name,email,pass) VALUES($1,$2,$3) RETURNING id', [name.trim(), email.toLowerCase(), hash(password)]);
    res.json(await newSession(r[0].id));
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'Email already registered' }); throw e; }
}));
app.post('/api/login', limit, h(async (req, res) => {
  const { email, password } = req.body || {};
  const u = (await q('SELECT * FROM users WHERE email=$1', [String(email || '').toLowerCase()]))[0];
  if (!u || typeof password !== 'string' || !verify(password, u.pass)) return res.status(401).json({ error: 'Wrong email or password' });
  q('DELETE FROM sessions WHERE expires_at<now()').catch(() => {});
  res.json(await newSession(u.id));
}));
app.get('/api/me', auth, (req, res) => res.json(req.user));

// ---- catalog, reviews, related, wishlist
app.get('/api/products', h(async (req, res) => res.json(await q(`
  SELECT p.id,p.name,p.category,p.price,p.stock,p.emoji,p.image,
   (SELECT ROUND(AVG(stars),1)::float FROM reviews WHERE product_id=p.id) rating,
   (SELECT COUNT(*)::int FROM reviews WHERE product_id=p.id) rc
  FROM products p WHERE p.active AND ($1='' OR p.category=$1) AND p.name ILIKE $2 ORDER BY p.id`,
  [String(req.query.category || ''), `%${String(req.query.q || '').slice(0, 50)}%`]))));
app.get('/api/products/:id/related', h(async (req, res) => {
  const id = idp(req);
  let r = await q(`SELECT p.id,p.name,p.emoji,p.price FROM order_items a JOIN order_items b ON a.order_id=b.order_id AND b.product_id<>a.product_id
    JOIN products p ON p.id=b.product_id WHERE a.product_id=$1 AND p.active GROUP BY p.id ORDER BY COUNT(*) DESC LIMIT 3`, [id]);
  if (!r.length) r = await q('SELECT id,name,emoji,price FROM products WHERE active AND id<>$1 AND category=(SELECT category FROM products WHERE id=$1) LIMIT 3', [id]);
  res.json(r);
}));
app.get('/api/products/:id/reviews', h(async (req, res) =>
  res.json(await q('SELECT name,stars,text FROM reviews WHERE product_id=$1 ORDER BY id DESC LIMIT 20', [idp(req)]))));
app.post('/api/products/:id/reviews', auth, h(async (req, res) => {
  const { stars, text } = req.body || {};
  if (!Number.isInteger(+stars) || stars < 1 || stars > 5 || !str(text)) return res.status(400).json({ error: 'Give 1-5 stars and a comment' });
  await q(`INSERT INTO reviews(product_id,user_id,name,stars,text) VALUES($1,$2,$3,$4,$5)
    ON CONFLICT(product_id,user_id) DO UPDATE SET stars=EXCLUDED.stars,text=EXCLUDED.text`, [idp(req), req.user.id, req.user.name, +stars, text.trim()]);
  res.json({ ok: 1 });
}));
app.get('/api/wishlist', auth, h(async (req, res) => res.json(await q(
  'SELECT p.id,p.name,p.category,p.price,p.stock,p.emoji,p.image FROM wishlist w JOIN products p ON p.id=w.product_id WHERE w.user_id=$1 AND p.active', [req.user.id]))));
app.post('/api/wishlist/:id', auth, h(async (req, res) => {
  const a = [req.user.id, idp(req)];
  const d = await pool.query('DELETE FROM wishlist WHERE user_id=$1 AND product_id=$2', a);
  if (!d.rowCount) await q('INSERT INTO wishlist VALUES($1,$2)', a);
  res.json({ on: !d.rowCount });
}));
app.get('/api/coupon/:code', h(async (req, res) => {
  const c = (await q('SELECT pct FROM coupons WHERE code=$1', [req.params.code.toUpperCase()]))[0];
  c ? res.json(c) : res.status(404).json({ error: 'Invalid coupon' });
}));

// ---- orders (one DB transaction: coupon + stock + items + total, all or nothing)
async function place(u, c, items) {
  const cl = await pool.connect();
  try {
    await cl.query('BEGIN');
    let cp = null;
    if (c.coupon) {
      cp = (await cl.query('SELECT code,pct FROM coupons WHERE code=$1', [c.coupon.toUpperCase()])).rows[0];
      if (!cp) throw new AppErr('Invalid coupon');
    }
    const oid = (await cl.query('INSERT INTO orders(user_id,name,phone,address,slot,payment,coupon) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [u.id, c.name, c.phone, c.address, c.slot, c.payment, cp && cp.code])).rows[0].id;
    let sub = 0;
    for (const { id, qty } of [...items].sort((a, b) => a.id - b.id)) { // sorted = no deadlocks
      const p = (await cl.query('SELECT name,price FROM products WHERE id=$1 AND active', [id])).rows[0];
      if (!p) throw new AppErr('Product not found');
      const d = await cl.query('UPDATE products SET stock=stock-$1 WHERE id=$2 AND stock>=$1', [qty, id]);
      if (!d.rowCount) throw new AppErr('Not enough stock: ' + p.name);
      await cl.query('INSERT INTO order_items VALUES($1,$2,$3,$4)', [oid, id, qty, p.price]);
      sub += p.price * qty; // price always from DB
    }
    const disc = cp ? Math.floor(sub * cp.pct / 100) : 0;
    await cl.query('UPDATE orders SET total=$1,discount=$2 WHERE id=$3', [sub - disc, disc, oid]);
    await cl.query('COMMIT');
    return { orderId: oid, total: sub - disc, discount: disc };
  } catch (e) { await cl.query('ROLLBACK'); throw e; } finally { cl.release(); }
}
app.post('/api/orders', auth, h(async (req, res) => {
  const { name, phone, address, slot, payment, coupon, items } = req.body || {};
  if (![name, phone, address].every(str) || !/^\d{10}$/.test(phone.trim()) || !SLOTS.includes(slot) || !PAY.includes(payment))
    return res.status(400).json({ error: 'Check name, 10-digit phone, address, slot and payment' });
  if (!Array.isArray(items) || !items.length || items.length > 50 ||
      !items.every(i => Number.isInteger(i.id) && Number.isInteger(i.qty) && i.qty >= 1 && i.qty <= 20))
    return res.status(400).json({ error: 'Cart is empty or invalid' });
  try { res.json(await place(req.user, { name: name.trim(), phone: phone.trim(), address: address.trim(), slot, payment, coupon: str(coupon) ? coupon.trim() : '' }, items)); }
  catch (e) { if (e instanceof AppErr) return res.status(409).json({ error: e.message }); throw e; }
}));
const itemsOf = id => q('SELECT p.name,p.emoji,i.qty,i.price FROM order_items i JOIN products p ON p.id=i.product_id WHERE i.order_id=$1', [id]);
app.get('/api/orders', auth, h(async (req, res) => {
  const os = await q(`SELECT ${OCOLS} FROM orders WHERE user_id=$1 ORDER BY id DESC`, [req.user.id]);
  for (const o of os) o.items = await itemsOf(o.id);
  res.json(os);
}));
app.get('/api/orders/:id/invoice', auth, h(async (req, res) => {
  const o = (await q(`SELECT ${OCOLS} FROM orders WHERE id=$1`, [idp(req)]))[0];
  if (!o || (o.user_id !== req.user.id && req.user.role !== 'admin')) return res.status(404).send('Not found');
  const e = s => String(s ?? '').replace(/[&<>"']/g, c => '&#' + c.charCodeAt(0) + ';');
  const rows = (await itemsOf(o.id)).map(i => `<tr><td>${e(i.name)}<td>${i.qty}<td>₹${i.price}<td>₹${i.qty * i.price}</tr>`).join('');
  res.send(`<!doctype html><meta charset=utf-8><title>Invoice #${o.id}</title><style>body{font:16px system-ui;max-width:640px;margin:30px auto;padding:0 16px}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #ccc;text-align:left}@media print{button{display:none}}</style>
<h1>Kaapi Corner</h1><p>Invoice #${o.id} | ${e(o.created_at)}<br>${e(o.name)}, ${e(o.phone)}<br>${e(o.address)}<br>Slot: ${e(o.slot)}</p>
<table><tr><th>Item<th>Qty<th>Price<th>Amount</tr>${rows}</table>
<p>Discount: ₹${o.discount}<br><b>Total: ₹${o.total}</b> (${e(o.payment)})</p><button onclick="print()">Download / Print PDF</button>`);
}));

// ---- admin
const prod = b => {
  const p = { name: String(b.name || '').trim().slice(0, 100), category: String(b.category || '').trim().slice(0, 40),
    price: +b.price, stock: +b.stock, emoji: String(b.emoji || '🛍️').slice(0, 8), image: String(b.image || '').trim().slice(0, 500) };
  return (!p.name || !p.category || !Number.isInteger(p.price) || p.price < 0 || p.price > 1e7 || !Number.isInteger(p.stock) || p.stock < 0 || p.stock > 1e6 ||
    (p.image && !/^https?:\/\//.test(p.image))) ? null : p;
};
const pv = p => [p.name, p.category, p.price, p.stock, p.emoji, p.image];
app.get('/api/admin/stats', auth, admin, h(async (req, res) => res.json({
  sales: (await q('SELECT COALESCE(SUM(total),0)::int s,COUNT(*)::int n FROM orders'))[0],
  daily: (await q("SELECT * FROM (SELECT to_char(created_at,'YYYY-MM-DD') d,SUM(total)::int t FROM orders GROUP BY 1 ORDER BY 1 DESC LIMIT 7) x ORDER BY d")),
  top: await q('SELECT p.name,SUM(i.qty)::int q FROM order_items i JOIN products p ON p.id=i.product_id GROUP BY p.id ORDER BY q DESC LIMIT 5'),
  low: await q('SELECT id,name,stock FROM products WHERE active AND stock<=5 ORDER BY stock') })));
app.get('/api/admin/orders', auth, admin, h(async (req, res) => res.json(await q(`SELECT ${OCOLS} FROM orders ORDER BY id DESC LIMIT 100`))));
app.put('/api/admin/orders/:id/status', auth, admin, h(async (req, res) => {
  if (!STAT.includes(req.body.status)) return res.status(400).json({ error: 'Bad status' });
  await q('UPDATE orders SET status=$1 WHERE id=$2', [req.body.status, idp(req)]); res.json({ ok: 1 });
}));
app.post('/api/admin/products', auth, admin, h(async (req, res) => {
  const p = prod(req.body || {}); if (!p) return res.status(400).json({ error: 'Check product fields (image must be an http(s) URL)' });
  await q('INSERT INTO products(name,category,price,stock,emoji,image) VALUES($1,$2,$3,$4,$5,$6)', pv(p)); res.json({ ok: 1 });
}));
app.put('/api/admin/products/:id', auth, admin, h(async (req, res) => {
  const p = prod(req.body || {}); if (!p) return res.status(400).json({ error: 'Check product fields' });
  await q('UPDATE products SET name=$1,category=$2,price=$3,stock=$4,emoji=$5,image=$6 WHERE id=$7', [...pv(p), idp(req)]); res.json({ ok: 1 });
}));
app.delete('/api/admin/products/:id', auth, admin, h(async (req, res) => {
  await q('UPDATE products SET active=false WHERE id=$1', [idp(req)]); res.json({ ok: 1 }); // soft delete keeps order history valid
}));
app.post('/api/admin/coupons', auth, admin, h(async (req, res) => {
  const { code, pct } = req.body || {};
  if (!/^[A-Za-z0-9]{3,20}$/.test(code || '') || !Number.isInteger(+pct) || pct < 1 || pct > 90) return res.status(400).json({ error: 'Code 3-20 letters/digits, percent 1-90' });
  await q('INSERT INTO coupons VALUES($1,$2) ON CONFLICT(code) DO UPDATE SET pct=EXCLUDED.pct', [code.toUpperCase(), +pct]); res.json({ ok: 1 });
}));

app.use((err, req, res, next) => {
  if (['23503', '22003', '22P02'].includes(err.code)) return res.status(400).json({ error: 'Invalid input' });
  console.error(err); res.status(500).json({ error: 'Server error' });
});

(async () => {
  try {
    await pool.query('SELECT 1');
    if (!(await q("SELECT 1 FROM users WHERE role='admin'")).length)
      await q("INSERT INTO users(name,email,pass,role) VALUES('Admin',$1,$2,'admin')",
        [(process.env.ADMIN_EMAIL || 'admin@shop.com').toLowerCase(), hash(process.env.ADMIN_PASSWORD || 'ChangeMe123')]);
  } catch (e) { console.error('\nCannot use the database. Did you run schema.sql and set DATABASE_URL in .env?\n', e.message); process.exit(1); }
  app.listen(process.env.PORT || 3000, () => console.log('Shop running at http://localhost:' + (process.env.PORT || 3000)));
})();
