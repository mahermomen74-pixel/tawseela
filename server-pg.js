require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 16) { console.error("حط JWT_SECRET (16 حرف على الأقل)"); process.exit(1); }
if (!process.env.DATABASE_URL) { console.error("حط DATABASE_URL (رابط قاعدة بيانات Neon)"); process.exit(1); }

const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5 });
const q = (text, params) => pool.query(text, params);

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));

const PRICES = { economy: [15, 6], comfort: [25, 8], vip: [40, 12] };
const sign = (u) => jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: "30d" });
const clean = (u) => ({ id: u.id, role: u.role, name: u.name, phone: u.phone, car: u.car });
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch((e) => { console.error(e); bad(res, "خطأ في السيرفر", 500); });

const hits = new Map();
function limit(req, res, next) {
  const now = Date.now();
  const a = (hits.get(req.ip) || []).filter((t) => now - t < 600000);
  if (a.length >= 20) return bad(res, "محاولات كتير، جرّب بعد شوية", 429);
  a.push(now); hits.set(req.ip, a); next();
}

function auth(role) {
  return async (req, res, next) => {
    let user;
    try {
      const p = jwt.verify((req.headers.authorization || "").replace("Bearer ", ""), SECRET);
      if (role && p.role !== role) return bad(res, "مش مسموح", 403);
      const r = await q("SELECT * FROM users WHERE id=$1", [p.id]);
      user = r.rows[0];
      if (!user) throw new Error("no user");
    } catch { return bad(res, "سجّل دخول", 401); }
    req.user = user; next();
  };
}

const idOf = (req) => { const n = Number(req.params.id); return Number.isInteger(n) ? n : null; };

app.get("/api/config", (req, res) => res.json({}));

app.post("/api/register", limit, wrap(async (req, res) => {
  const { role, name, phone, password, car } = req.body || {};
  if (!["customer", "driver"].includes(role)) return bad(res, "نوع الحساب غلط");
  if (!name || String(name).length > 60) return bad(res, "اكتب اسمك");
  if (!/^01[0-9]{9}$/.test(phone || "")) return bad(res, "رقم الموبايل غلط");
  if (!password || password.length < 6) return bad(res, "الباسورد لازم 6 على الأقل");
  if (role === "driver" && !car) return bad(res, "اكتب نوع العربية");
  const hash = await bcrypt.hash(password, 10);
  try {
    const r = await q("INSERT INTO users(role,name,phone,hash,car) VALUES($1,$2,$3,$4,$5) RETURNING *",
      [role, String(name).trim(), phone, hash, role === "driver" ? String(car).slice(0, 60) : null]);
    const u = r.rows[0];
    res.json({ token: sign(u), user: clean(u) });
  } catch (e) {
    if (e.code === "23505") return bad(res, "الرقم مسجل قبل كده", 409);
    throw e;
  }
}));

app.post("/api/login", limit, wrap(async (req, res) => {
  const { role, phone, password } = req.body || {};
  const r = await q("SELECT * FROM users WHERE role=$1 AND phone=$2", [role, phone || ""]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(password || "", u.hash))) return bad(res, "الرقم أو الباسورد غلط", 401);
  res.json({ token: sign(u), user: clean(u) });
}));

app.get("/api/me", auth(), (req, res) => res.json(clean(req.user)));

// ---- العميل ----
app.post("/api/rides", auth("customer"), wrap(async (req, res) => {
  const { from, to, km, mins, type } = req.body || {};
  if (!PRICES[type] || !from || !to || !(km > 0 && km < 500)) return bad(res, "بيانات الرحلة ناقصة");
  const ex = await q("SELECT 1 FROM rides WHERE customer_id=$1 AND status IN('open','accepted')", [req.user.id]);
  if (ex.rowCount) return bad(res, "عندك رحلة شغالة بالفعل", 409);
  const [b, k] = PRICES[type];
  const price = Math.round(b + k * km);
  const r = await q(
    "INSERT INTO rides(customer_id,from_text,to_text,km,mins,type,price,created) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id",
    [req.user.id, String(from).slice(0, 200), String(to).slice(0, 200), km, Math.round(mins) || 0, type, price, Date.now()]);
  res.json({ id: r.rows[0].id, price });
}));

app.get("/api/rides/current", auth("customer"), wrap(async (req, res) => {
  const r = await q(`SELECT r.*, u.name AS driver_name, u.car AS driver_car, u.phone AS driver_phone
    FROM rides r LEFT JOIN users u ON u.id=r.driver_id
    WHERE r.customer_id=$1 AND r.status IN('open','accepted') ORDER BY r.id DESC LIMIT 1`, [req.user.id]);
  res.json(r.rows[0] || null);
}));

app.post("/api/rides/:id/cancel", auth("customer"), wrap(async (req, res) => {
  const id = idOf(req); if (id === null) return bad(res, "رقم غلط");
  const r = await q("UPDATE rides SET status='cancelled' WHERE id=$1 AND customer_id=$2 AND status IN('open','accepted')", [id, req.user.id]);
  res.json({ ok: r.rowCount > 0 });
}));

// ---- السائق ----
app.get("/api/driver/state", auth("driver"), wrap(async (req, res) => {
  const c = await q(`SELECT r.*, u.name AS customer_name, u.phone AS customer_phone
    FROM rides r JOIN users u ON u.id=r.customer_id WHERE r.driver_id=$1 AND r.status='accepted' LIMIT 1`, [req.user.id]);
  const current = c.rows[0] || null;
  const open = current ? [] : (await q(
    "SELECT id,from_text,to_text,km,mins,price,type FROM rides WHERE status='open' ORDER BY id LIMIT 20")).rows;
  const e = await q("SELECT COALESCE(SUM(price),0)::int AS s FROM rides WHERE driver_id=$1 AND status='done'", [req.user.id]);
  res.json({ current, open, earnings: e.rows[0].s });
}));

app.post("/api/rides/:id/accept", auth("driver"), wrap(async (req, res) => {
  const id = idOf(req); if (id === null) return bad(res, "رقم غلط");
  const ex = await q("SELECT 1 FROM rides WHERE driver_id=$1 AND status='accepted'", [req.user.id]);
  if (ex.rowCount) return bad(res, "عندك رحلة شغالة", 409);
  // الشرط status='open' بيمنع سائقين اتنين ياخدوا نفس الرحلة
  const r = await q("UPDATE rides SET status='accepted', driver_id=$1 WHERE id=$2 AND status='open'", [req.user.id, id]);
  res.json({ ok: r.rowCount > 0 });
}));

app.post("/api/rides/:id/finish", auth("driver"), wrap(async (req, res) => {
  const id = idOf(req); if (id === null) return bad(res, "رقم غلط");
  const r = await q("UPDATE rides SET status='done' WHERE id=$1 AND driver_id=$2 AND status='accepted'", [id, req.user.id]);
  res.json({ ok: r.rowCount > 0 });
}));

async function init() {
  await q(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY, role TEXT NOT NULL CHECK(role IN('customer','driver')),
    name TEXT NOT NULL, phone TEXT NOT NULL, hash TEXT NOT NULL, car TEXT,
    UNIQUE(role, phone))`);
  await q(`CREATE TABLE IF NOT EXISTS rides(
    id SERIAL PRIMARY KEY, customer_id INT NOT NULL REFERENCES users(id), driver_id INT REFERENCES users(id),
    from_text TEXT NOT NULL, to_text TEXT NOT NULL, km DOUBLE PRECISION NOT NULL, mins INT NOT NULL,
    type TEXT NOT NULL, price INT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created BIGINT NOT NULL)`);
}

init()
  .then(() => app.listen(process.env.PORT || 3000, () => console.log("شغال، وقاعدة البيانات Neon متوصلة")))
  .catch((e) => { console.error("فشل الاتصال بقاعدة البيانات:", e.message); process.exit(1); });
