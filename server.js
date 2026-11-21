require("dotenv").config();
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 16) {
  console.error("حط JWT_SECRET (16 حرف على الأقل) في ملف .env");
  process.exit(1);
}

const app = express();
const db = new Database(process.env.DB_FILE || "data.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, role TEXT NOT NULL CHECK(role IN('customer','driver')),
  name TEXT NOT NULL, phone TEXT NOT NULL, hash TEXT NOT NULL, car TEXT,
  UNIQUE(role, phone));
CREATE TABLE IF NOT EXISTS rides(
  id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL, driver_id INTEGER,
  from_text TEXT NOT NULL, to_text TEXT NOT NULL, km REAL NOT NULL, mins INTEGER NOT NULL,
  type TEXT NOT NULL, price INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  created INTEGER NOT NULL);
`);

app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));

const PRICES = { economy: [15, 6], comfort: [25, 8], vip: [40, 12] }; // [أساسي, للكم]
const sign = (u) => jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: "30d" });
const clean = (u) => ({ id: u.id, role: u.role, name: u.name, phone: u.phone, car: u.car });
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

// حماية بسيطة من تخمين الباسورد: 20 محاولة كل 10 دقايق لكل IP
const hits = new Map();
function limit(req, res, next) {
  const now = Date.now();
  const a = (hits.get(req.ip) || []).filter((t) => now - t < 600000);
  if (a.length >= 20) return bad(res, "محاولات كتير، جرّب بعد شوية", 429);
  a.push(now);
  hits.set(req.ip, a);
  next();
}

function auth(role) {
  return (req, res, next) => {
    try {
      const p = jwt.verify((req.headers.authorization || "").replace("Bearer ", ""), SECRET);
      if (role && p.role !== role) return bad(res, "مش مسموح", 403);
      req.user = db.prepare("SELECT * FROM users WHERE id=?").get(p.id);
      if (!req.user) throw new Error("no user");
      next();
    } catch {
      bad(res, "سجّل دخول", 401);
    }
  };
}

app.get("/api/config", (q, r) =>
  r.json({ mapsKey: process.env.GOOGLE_MAPS_API_KEY || "", mapId: process.env.MAP_ID || "DEMO_MAP_ID" }));

app.post("/api/register", limit, async (req, res) => {
  const { role, name, phone, password, car } = req.body || {};
  if (!["customer", "driver"].includes(role)) return bad(res, "نوع الحساب غلط");
  if (!name || String(name).length > 60) return bad(res, "اكتب اسمك");
  if (!/^01[0-9]{9}$/.test(phone || "")) return bad(res, "رقم الموبايل غلط");
  if (!password || password.length < 6) return bad(res, "الباسورد لازم 6 على الأقل");
  if (role === "driver" && !car) return bad(res, "اكتب نوع العربية");
  try {
    const hash = await bcrypt.hash(password, 10);
    const id = db.prepare("INSERT INTO users(role,name,phone,hash,car) VALUES(?,?,?,?,?)")
      .run(role, String(name).trim(), phone, hash, role === "driver" ? String(car).slice(0, 60) : null).lastInsertRowid;
    const u = db.prepare("SELECT * FROM users WHERE id=?").get(id);
    res.json({ token: sign(u), user: clean(u) });
  } catch {
    bad(res, "الرقم مسجل قبل كده", 409);
  }
});

app.post("/api/login", limit, async (req, res) => {
  const { role, phone, password } = req.body || {};
  const u = db.prepare("SELECT * FROM users WHERE role=? AND phone=?").get(role, phone || "");
  if (!u || !(await bcrypt.compare(password || "", u.hash))) return bad(res, "الرقم أو الباسورد غلط", 401);
  res.json({ token: sign(u), user: clean(u) });
});

app.get("/api/me", auth(), (req, res) => res.json(clean(req.user)));

// ---- العميل ----
app.post("/api/rides", auth("customer"), (req, res) => {
  const { from, to, km, mins, type } = req.body || {};
  if (!PRICES[type] || !from || !to || !(km > 0 && km < 500)) return bad(res, "بيانات الرحلة ناقصة");
  if (db.prepare("SELECT 1 FROM rides WHERE customer_id=? AND status IN('open','accepted')").get(req.user.id))
    return bad(res, "عندك رحلة شغالة بالفعل", 409);
  const [b, k] = PRICES[type];
  const price = Math.round(b + k * km); // السعر بيتحسب على السيرفر
  const id = db.prepare("INSERT INTO rides(customer_id,from_text,to_text,km,mins,type,price,created) VALUES(?,?,?,?,?,?,?,?)")
    .run(req.user.id, String(from).slice(0, 200), String(to).slice(0, 200), km, Math.round(mins) || 0, type, price, Date.now()).lastInsertRowid;
  res.json({ id, price });
});

app.get("/api/rides/current", auth("customer"), (req, res) =>
  res.json(db.prepare(`SELECT r.*, u.name AS driver_name, u.car AS driver_car, u.phone AS driver_phone
    FROM rides r LEFT JOIN users u ON u.id=r.driver_id
    WHERE r.customer_id=? AND r.status IN('open','accepted') ORDER BY r.id DESC LIMIT 1`).get(req.user.id) || null));

app.post("/api/rides/:id/cancel", auth("customer"), (req, res) => {
  const r = db.prepare("UPDATE rides SET status='cancelled' WHERE id=? AND customer_id=? AND status IN('open','accepted')")
    .run(req.params.id, req.user.id);
  res.json({ ok: r.changes > 0 });
});

// ---- السائق ----
app.get("/api/driver/state", auth("driver"), (req, res) => {
  const current = db.prepare(`SELECT r.*, u.name AS customer_name, u.phone AS customer_phone
    FROM rides r JOIN users u ON u.id=r.customer_id WHERE r.driver_id=? AND r.status='accepted' LIMIT 1`).get(req.user.id) || null;
  const open = current ? [] : db.prepare(
    "SELECT id,from_text,to_text,km,mins,price,type FROM rides WHERE status='open' ORDER BY id LIMIT 20").all();
  const earnings = db.prepare("SELECT COALESCE(SUM(price),0) s FROM rides WHERE driver_id=? AND status='done'").get(req.user.id).s;
  res.json({ current, open, earnings });
});

app.post("/api/rides/:id/accept", auth("driver"), (req, res) => {
  if (db.prepare("SELECT 1 FROM rides WHERE driver_id=? AND status='accepted'").get(req.user.id))
    return bad(res, "عندك رحلة شغالة", 409);
  // الشرط status='open' بيمنع سائقين اتنين ياخدوا نفس الرحلة
  const r = db.prepare("UPDATE rides SET status='accepted', driver_id=? WHERE id=? AND status='open'").run(req.user.id, req.params.id);
  res.json({ ok: r.changes > 0 });
});

app.post("/api/rides/:id/finish", auth("driver"), (req, res) => {
  const r = db.prepare("UPDATE rides SET status='done' WHERE id=? AND driver_id=? AND status='accepted'").run(req.params.id, req.user.id);
  res.json({ ok: r.changes > 0 });
});

app.listen(process.env.PORT || 3000, () => console.log("شغال على http://localhost:" + (process.env.PORT || 3000)));
