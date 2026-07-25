require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const fetch   = require('node-fetch');
const path    = require('path');
const crypto  = require('crypto');
const { createClient } = require('@supabase/supabase-js');

// 🔒 SECURITY HARDENING: เดิมจุดเทียบ ADMIN_API_KEY หลายจุด (requireAdminKey, requirePerm,
// /admin/verify, /messages/:orderId, POST /messages) ใช้ "===" เทียบ string ตรงๆ ซึ่งไม่ใช่
// timing-safe ต่างจากจุดอื่นในระบบเดียวกัน (login password ใช้ timingSafeEqual, webhook
// signature ก็แก้ไปแล้วก่อนหน้า) — ความเสี่ยงจริงต่ำ เพราะมี rate limit + brute-force lockout
// (10 ครั้งก่อนล็อก) กันการยิงหลายพันครั้งเพื่อวัด timing อยู่แล้ว แต่แก้ให้สม่ำเสมอกันทั้งระบบ
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a || ''));
  const bufB = Buffer.from(String(b || ''));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

const app = express();
// 🔒 SECURITY FIX: เดิมไม่เคยตั้ง 'trust proxy' เลย — เวลา deploy จริงบน Railway/Render/Nixpacks
// (ตามที่ nixpacks.toml บ่งบอก) แอปจะรันหลัง reverse proxy เสมอ ถ้าไม่ตั้งค่านี้ req.ip ของ
// Express จะอ่านได้แค่ IP ของตัว proxy เอง (ตัวเดียวกันสำหรับทุกคนที่เข้าเว็บ) ไม่ใช่ IP ลูกค้าจริง
// ผลคือระบบกันสแปม/บรูทฟอร์ซที่ผูกกับ req.ip ทั้งหมด (rateLimit(), adminBruteForceGuard,
// rate limit ของ /validate-coupon /reveal-coupon ที่เพิ่งแก้ไป) จะพังทันที — แย่ที่สุดคือถ้ามีคน
// พยายามเดารหัสแอดมินผิดจนโดนล็อก จะไปล็อกทุกคนที่ใช้เว็บพร้อมกันด้วย (เพราะ IP เดียวกันหมด)
// ตั้งเป็น 1 = เชื่อ X-Forwarded-For จาก reverse proxy ชั้นแรกสุดเท่านั้น (มาตรฐานสำหรับ
// deploy หลัง proxy ชั้นเดียวแบบ Railway/Render/Heroku)
app.set('trust proxy', 1);
// CORS — รองรับ preflight (OPTIONS) จาก GitHub Pages และทุก domain
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-key']
}));
app.options('*', cors()); // preflight สำหรับทุก route

// ─── อนุญาตให้แอปเซล (Sale-Monshin) ฝังหน้าร้านใน iframe ได้ ───
// ค่า default ของเบราว์เซอร์/proxy บางตัวจะบล็อก cross-origin iframe ถ้าไม่ประกาศนโยบาย
// frame-ancestors: อนุญาตเว็บแอปเซลบน GitHub Pages + ตัวเอง + APK webview (https/file)
app.use((req, res, next) => {
  res.removeHeader('X-Frame-Options');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self' https://rueopop-code.github.io https://*.github.io file:");
  next();
});

app.use(express.json({ limit: '15mb', verify: (req, res, buf) => { req.rawBody = buf; } }));         // รับ base64 รูปสลิปขนาดใหญ่ได้ + เก็บ raw body ไว้ตรวจลายเซ็น LINE webhook

// ═══ 🔐 Admin API Key — ป้องกัน endpoint ฝั่งจัดการร้าน ═══════════════
// เปิดใช้เมื่อตั้ง env ADMIN_API_KEY (ตั้งเป็นรหัสลับอะไรก็ได้ยาว ๆ)
// ถ้าไม่ตั้ง → ทำงานเหมือนเดิมทุกอย่าง (backward compatible)
// ฝั่งหน้าเว็บส่ง key มาทาง header 'x-admin-key' หรือ query ?admin_key=
function requireAdminKey(req, res, next) {
  const key = process.env.ADMIN_API_KEY || '';
  if (!key) return next();
  const got = req.headers['x-admin-key'] || req.query.admin_key || '';
  if (safeEqual(got, key)) return next();
  console.warn(`🚫 admin endpoint ถูกปฏิเสธ: ${req.method} ${req.path} จาก ${req.ip}`);
  return res.status(401).json({ error: 'unauthorized — ต้องใส่ Admin API Key' });
}

// ═══ ⏱️ Rate limiter แบบเบา ๆ (in-memory ต่อ IP) ═══════════════════
// ใช้กับ endpoint ที่กินแรงเครื่อง (OCR) กันโดนยิงถล่มจน server ล่ม
const _rateBuckets = new Map(); // key → { count, resetAt }
function rateLimit(maxPerMin) {
  return (req, res, next) => {
    const k = `${req.path}|${req.ip}`;
    const now = Date.now();
    let b = _rateBuckets.get(k);
    if (!b || now > b.resetAt) { b = { count: 0, resetAt: now + 60000 }; _rateBuckets.set(k, b); }
    b.count++;
    if (_rateBuckets.size > 5000) { // กัน map บวม
      for (const [kk, vv] of _rateBuckets) { if (now > vv.resetAt) _rateBuckets.delete(kk); }
    }
    if (b.count > maxPerMin) {
      return res.status(429).json({ error: 'ส่งถี่เกินไป กรุณารอสักครู่แล้วลองใหม่' });
    }
    next();
  };
}

// ═══ 📝 Error log ลง Supabase (fire-and-forget) ══════════════════════
// ต้องมีตาราง error_logs (อยู่ใน supabase-schema.sql) — ถ้ายังไม่มีก็แค่ log ลง console เหมือนเดิม
// 🔔 แจ้งเตือนแอดมินผ่าน LINE อัตโนมัติ (throttle: scope ละไม่เกิน 1 ครั้ง/10 นาที กันสแปม)
//    ปิดได้ด้วย env ERROR_NOTIFY_LINE=0
const _errNotifyLast = new Map(); // `${source}|${scope}` → last notified ms
// ⚙️ เปิด/ปิดแจ้งเตือน + ความถี่ ตั้งได้จากหน้าแอดมิน (settings key 'error_notify')
let _errNotifyCfg = null, _errNotifyCfgAt = 0;
async function _getErrNotifyCfg() {
  if (_errNotifyCfg && Date.now() - _errNotifyCfgAt < 60000) return _errNotifyCfg;
  let cfg = { enabled: (process.env.ERROR_NOTIFY_LINE || '1') !== '0', throttleMin: 10 };
  try {
    const { data } = await supabase.from('settings').select('value').eq('key', 'error_notify').maybeSingle();
    if (data && data.value) cfg = Object.assign(cfg, data.value);
  } catch (_) {}
  _errNotifyCfg = cfg; _errNotifyCfgAt = Date.now();
  return cfg;
}
function logError(scope, err, extra, source) {
  source = source || 'backend';
  const message = (err && err.message) ? err.message : String(err);
  console.error(`❌ [${source}/${scope}]`, message);
  try {
    supabase.from('error_logs').insert([{
      scope, source, message: message.slice(0, 1000),
      extra: extra ? (typeof extra === 'string' ? extra : JSON.stringify(extra)).slice(0, 2000) : null,
      created_at: new Date().toISOString()
    }]).then(({ error }) => { /* เงียบ — ตารางอาจยังไม่ถูกสร้าง */ });
  } catch (_) {}
  // 🔔 LINE แจ้งเตือนแอดมิน (แยก throttle ตาม ระบบ+จุดที่พัง)
  _getErrNotifyCfg().then(cfg => {
    try {
      if (!cfg.enabled || !process.env.LINE_TOKEN) return;
      const key = `${source}|${scope}`;
      const now = Date.now();
      const last = _errNotifyLast.get(key) || 0;
      if (now - last > (cfg.throttleMin || 10) * 60 * 1000) {
        _errNotifyLast.set(key, now);
        if (_errNotifyLast.size > 500) _errNotifyLast.clear();
        const srcTh = { backend:'🖥️ Backend', shop:'🛍️ หน้าร้าน', admin:'🛡️ หน้าแอดมิน', 'sales-app':'💼 แอปเซล' }[source] || source;
        notifyAllAdmins([{
          type: 'text',
          text: `🚨 ระบบแจ้งเตือน Error\n🧩 ระบบ: ${srcTh}\n📍 ส่วน: ${scope}\n💬 ${message.slice(0, 300)}\n🕐 ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}\n\nดูรายละเอียด → หน้าแอดมิน แท็บ "🧾 Log ระบบ"`
        }]).catch(() => {});
      }
    } catch (_) {}
  }).catch(() => {});
}
process.on('unhandledRejection', (e) => logError('unhandledRejection', e));
process.on('uncaughtException',  (e) => logError('uncaughtException', e));

// ═══════════════════════════════════════════════════════════════════
//  👤 ระบบบัญชีผู้ใช้แอดมิน + สิทธิ์การเข้าถึง (RBAC)
//  บทบาท: owner (เจ้าของร้าน — ทำได้ทุกอย่าง) / manager / staff
//  สิทธิ์ (perms): orders, customers, reports, sales, coupons, payments,
//                  products, shop_settings, backup, users, settings
//  รหัสผ่านเก็บแบบ scrypt hash + salt — ไม่มีทางกู้คืนเป็นข้อความได้
//  token มีอายุ 12 ชม. เซ็นด้วย HMAC (secret = env AUTH_SECRET หรือ ADMIN_API_KEY)
// ═══════════════════════════════════════════════════════════════════
const _crypto = require('crypto');
const ALL_PERMS = ['orders','customers','reports','sales','coupons','payments','products','shop_settings','backup','users','settings','system'];

// 🔴 SECURITY FIX: เดิม fallback เป็น string คงที่ 'monshin-no-secret' ที่มองเห็นได้ในซอร์สโค้ด
// นี้เอง (ที่อาจอยู่ใน repo สาธารณะ) — ถ้าร้านไม่ได้ตั้งทั้ง AUTH_SECRET และ ADMIN_API_KEY เลย
// ใครก็ตามที่เคยเห็นโค้ดนี้จะรู้ secret ที่ใช้เซ็น token และปลอม token แอดมิน (เช่น role:'owner')
// ขึ้นมาเองได้ทันที โดยไม่ต้องรู้รหัสผ่านจริงเลย — เปลี่ยนเป็นสุ่ม secret ใหม่ทุกครั้งที่เซิร์ฟเวอร์
// เริ่มทำงาน (ถ้าไม่ได้ตั้ง env ไว้) แทน ผลข้างเคียงที่ยอมรับได้: ถ้าไม่ตั้ง AUTH_SECRET เอง
// token จะหมดอายุทันทีที่เซิร์ฟเวอร์ restart (บังคับให้ต้อง login ใหม่) ปลอดภัยกว่ามากเมื่อเทียบกับ
// การใช้ secret ที่รู้กันทั่วไปแบบเดิม — แนะนำให้ตั้ง AUTH_SECRET เองเพื่อไม่ให้ token หลุดตอน restart
const _fallbackAuthSecret = _crypto.randomBytes(32).toString('hex');
function _authSecret() { return process.env.AUTH_SECRET || process.env.ADMIN_API_KEY || _fallbackAuthSecret; }
function _hashPw(pw, salt) { return _crypto.scryptSync(String(pw), salt, 32).toString('hex'); }
function _b64u(s) { return Buffer.from(s).toString('base64url'); }

function makeAuthToken(user) {
  const payload = _b64u(JSON.stringify({
    uid: user.id, un: user.username, dn: user.display_name,
    role: user.role, perms: user.perms || [],
    exp: Date.now() + 12 * 3600 * 1000
  }));
  const sig = _crypto.createHmac('sha256', _authSecret()).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function verifyAuthToken(token) {
  try {
    const [payload, sig] = String(token || '').split('.');
    if (!payload || !sig) return null;
    const expect = _crypto.createHmac('sha256', _authSecret()).update(payload).digest('base64url');
    if (!_crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!data.exp || Date.now() > data.exp) return null;
    return data;
  } catch (_) { return null; }
}

// middleware: ผ่านได้ถ้า (1) Master Key ถูกต้อง หรือ (2) token ผู้ใช้ที่มีสิทธิ์ perm นั้น
// 🔴 SECURITY FIX (สำคัญมาก): เดิม "ยังไม่ได้ตั้ง ADMIN_API_KEY → ปล่อยผ่านหมด" ใช้เงื่อนไข
// แค่ "ADMIN_API_KEY ว่างไหม" เท่านั้น — ทำให้ถ้าร้านตั้งระบบ username/password ผ่าน /auth/setup
// ไปแล้ว (คิดว่าตัวเองล็อกระบบแล้ว) แต่ลืมตั้ง ADMIN_API_KEY แยกต่างหาก (ซึ่งดูเหมือนไม่จำเป็น
// เพราะมี login แล้ว) จะกลายเป็นว่า**ใครก็เข้าทุก endpoint ที่ควรมีแต่แอดมินได้โดยไม่ต้อง
// login เลย** เพราะโค้ดเช็คแค่ "มี ADMIN_API_KEY ไหม" ไม่ได้เช็คว่า "มีบัญชีแอดมินจริงในระบบ
// หรือยัง" — แก้โดยเพิ่มเช็คว่ามีบัญชี owner ในฐานข้อมูลแล้วหรือยัง ถ้ามีแล้ว (แปลว่าร้าน
// ตั้งใจใช้ระบบ login จริง) ต้องผ่าน token/master key เท่านั้น จะปล่อยผ่านแบบไม่ล็อกได้
// เฉพาะตอนที่ยังไม่มีบัญชีแอดมินเลยจริงๆ (fresh install ก่อนกด setup ครั้งแรก) เท่านั้น
let _ownerExistsCache = null; // cache สั้นๆ กันยิง DB ถี่เกินไปตอนไม่มี token (TTL 30 วิ)
let _ownerExistsCacheAt = 0;
async function _ownerAccountExists() {
  const now = Date.now();
  if (_ownerExistsCache !== null && (now - _ownerExistsCacheAt) < 30000) return _ownerExistsCache;
  try {
    const { count } = await supabase.from('admin_users').select('id', { count: 'exact', head: true }).eq('role', 'owner');
    _ownerExistsCache = (count || 0) > 0;
  } catch (_) {
    _ownerExistsCache = false; // ต่อ DB ไม่ได้ → ปฏิบัติเหมือนยังไม่มีบัญชี (fail-open เท่าพฤติกรรมเดิม เพื่อไม่ให้ระบบใช้งานไม่ได้ตอน DB ล่ม)
  }
  _ownerExistsCacheAt = now;
  return _ownerExistsCache;
}
function requirePerm(perm) {
  return async (req, res, next) => {
    const masterKey = process.env.ADMIN_API_KEY || '';
    const gotKey = req.headers['x-admin-key'] || req.query.admin_key || '';
    if (masterKey && safeEqual(gotKey, masterKey)) {
      req.adminUser = { role: 'owner', username: '__master__', master: true };
      return next();
    }
    const bearer = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
    const u = verifyAuthToken(bearer);
    if (u) {
      req.adminUser = u;
      if (u.role === 'owner') return next();
      if (!perm || (Array.isArray(u.perms) && u.perms.includes(perm))) return next();
      return res.status(403).json({ error: 'ไม่มีสิทธิ์ใช้งานส่วนนี้ (' + perm + ')' });
    }
    // 🐛 BUG FIX: เดิมถ้ายังไม่ได้ตั้ง ADMIN_API_KEY (masterKey ว่าง) จุดนี้จะ next() โดยไม่ตั้ง
    // req.adminUser เลย ทำให้ route ที่อ้างถึง req.adminUser.role/.username (เช่น /auth/users
    // POST/PATCH/DELETE) พังด้วย TypeError แบบไม่สม่ำเสมอ — บาง endpoint (GET /auth/users)
    // เปิดโล่งไม่ต้องล็อกอินเลยด้วย ในขณะที่บาง endpoint ดันพังเพราะ me.role เป็น undefined
    // (ตั้งใจให้ "ทำงานแบบเดิม" เมื่อยังไม่ได้ตั้งระบบล็อก — คงพฤติกรรมเดิมไว้ แต่ตั้ง
    // req.adminUser ให้เป็นค่า placeholder ที่ปลอดภัยเสมอ กันโค้ดส่วนอื่น crash โดยไม่ตั้งใจ)
    if (!masterKey && !(await _ownerAccountExists())) {
      req.adminUser = { role: 'owner', username: '__unauthenticated__', perms: ALL_PERMS };
      return next();
    }
    return res.status(401).json({ error: 'unauthorized — กรุณาเข้าสู่ระบบ' });
  };
}

// ── POST /auth/setup — สร้างบัญชีเจ้าของร้านคนแรก (ต้องใช้ Master Key) ──
app.post('/auth/setup', rateLimit(5), requireAdminKey, async (req, res) => {
  try {
    const { username, password, display_name } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'ต้องมี username และ password' });
    if (String(password).length < 6) return res.status(400).json({ error: 'รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร' });
    const { count } = await supabase.from('admin_users').select('id', { count: 'exact', head: true }).eq('role', 'owner');
    if ((count || 0) > 0) return res.status(400).json({ error: 'มีบัญชีเจ้าของร้านอยู่แล้ว — เข้าสู่ระบบแทน' });
    const salt = _crypto.randomBytes(16).toString('hex');
    const { data, error } = await supabase.from('admin_users').insert([{
      username: String(username).trim().toLowerCase(),
      pass_hash: _hashPw(password, salt), salt,
      display_name: display_name || username, role: 'owner',
      perms: ALL_PERMS, is_active: true, created_by: '__setup__'
    }]).select().maybeSingle();
    if (error) throw error;
    res.json({ success: true, token: makeAuthToken(data), user: { username: data.username, display_name: data.display_name, role: data.role, perms: data.perms } });
  } catch (e) { logError('auth-setup', e); res.status(500).json({ error: e.message }); }
});

// ── GET /auth/status — เช็คว่าระบบมีบัญชีแล้วหรือยัง (ใช้ซ่อน/แสดงปุ่ม setup) ──
app.get('/auth/status', rateLimit(30), async (req, res) => {
  try {
    const { count } = await supabase.from('admin_users').select('id', { count: 'exact', head: true }).eq('role', 'owner');
    res.json({ has_owner: (count || 0) > 0 });
  } catch (_) { res.json({ has_owner: false }); }
});

// ── POST /auth/login ─────────────────────────────────────────────
app.post('/auth/login', rateLimit(10), async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'กรอก username และ password' });
    const { count } = await supabase.from('admin_users').select('id', { count: 'exact', head: true });
    if (!count) return res.status(404).json({ error: 'no_users' }); // ยังไม่มีผู้ใช้ → หน้าเว็บจะพาไป setup
    const { data: u } = await supabase.from('admin_users').select('*')
      .eq('username', String(username).trim().toLowerCase()).maybeSingle();
    if (!u || !u.is_active) return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    const hash = _hashPw(password, u.salt);
    if (!_crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(u.pass_hash)))
      return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    supabase.from('admin_users').update({ last_login: new Date().toISOString() }).eq('id', u.id).then(() => {});
    res.json({ success: true, token: makeAuthToken(u), user: { username: u.username, display_name: u.display_name, role: u.role, perms: u.perms || [] } });
  } catch (e) { logError('auth-login', e); res.status(500).json({ error: e.message }); }
});

// ── GET /auth/me — ตรวจ token + รีเฟรชสิทธิ์ล่าสุดจากฐานข้อมูล ──
app.get('/auth/me', async (req, res) => {
  const bearer = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  const t = verifyAuthToken(bearer);
  if (!t) return res.status(401).json({ error: 'token หมดอายุ — เข้าสู่ระบบใหม่' });
  const { data: u } = await supabase.from('admin_users').select('*').eq('id', t.uid).maybeSingle();
  if (!u || !u.is_active) return res.status(401).json({ error: 'บัญชีถูกปิดใช้งาน' });
  res.json({ success: true, token: makeAuthToken(u), user: { username: u.username, display_name: u.display_name, role: u.role, perms: u.perms || [] } });
});

// ── จัดการผู้ใช้ (ต้องมีสิทธิ์ 'users') ─────────────────────────
// กติกา: manager สร้าง/แก้ได้เฉพาะ manager,staff — ห้ามแตะบัญชี owner
app.get('/auth/users', requirePerm('users'), async (req, res) => {
  const { data, error } = await supabase.from('admin_users')
    .select('id,username,display_name,role,perms,is_active,created_at,last_login')
    .order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ users: data || [] });
});

app.post('/auth/users', requirePerm('users'), async (req, res) => {
  try {
    const me = req.adminUser;
    let { username, password, display_name, role, perms } = req.body || {};
    role = ['owner','manager','staff'].includes(role) ? role : 'staff';
    if (role === 'owner' && me.role !== 'owner') return res.status(403).json({ error: 'เฉพาะเจ้าของร้านเท่านั้นที่สร้างบัญชี owner ได้' });
    if (!username || !password) return res.status(400).json({ error: 'ต้องมี username และ password' });
    if (String(password).length < 6) return res.status(400).json({ error: 'รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร' });
    perms = Array.isArray(perms) ? perms.filter(p => ALL_PERMS.includes(p)) : [];
    if (role === 'owner') perms = ALL_PERMS;
    const salt = _crypto.randomBytes(16).toString('hex');
    const { data, error } = await supabase.from('admin_users').insert([{
      username: String(username).trim().toLowerCase(),
      pass_hash: _hashPw(password, salt), salt,
      display_name: display_name || username, role, perms,
      is_active: true, created_by: me.username
    }]).select('id,username,display_name,role,perms,is_active').maybeSingle();
    if (error) {
      if (/duplicate|unique/i.test(error.message)) return res.status(400).json({ error: 'username นี้ถูกใช้แล้ว' });
      throw error;
    }
    res.json({ success: true, user: data });
  } catch (e) { logError('auth-create-user', e); res.status(500).json({ error: e.message }); }
});

app.patch('/auth/users/:id', requirePerm('users'), async (req, res) => {
  try {
    const me = req.adminUser;
    const { data: target } = await supabase.from('admin_users').select('*').eq('id', req.params.id).maybeSingle();
    if (!target) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
    if (target.role === 'owner' && me.role !== 'owner') return res.status(403).json({ error: 'แก้ไขบัญชี owner ได้เฉพาะเจ้าของร้าน' });
    const upd = {};
    const b = req.body || {};
    if (b.display_name !== undefined) upd.display_name = b.display_name;
    if (b.is_active   !== undefined) upd.is_active = !!b.is_active;
    if (Array.isArray(b.perms)) upd.perms = b.perms.filter(p => ALL_PERMS.includes(p));
    if (b.role && ['owner','manager','staff'].includes(b.role)) {
      if (b.role === 'owner' && me.role !== 'owner') return res.status(403).json({ error: 'เฉพาะเจ้าของร้านเท่านั้น' });
      upd.role = b.role;
      if (b.role === 'owner') upd.perms = ALL_PERMS;
    }
    if (b.new_password) {
      if (String(b.new_password).length < 6) return res.status(400).json({ error: 'รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร' });
      const salt = _crypto.randomBytes(16).toString('hex');
      upd.salt = salt;
      upd.pass_hash = _hashPw(b.new_password, salt);
    }
    // กันปิด/ลดสิทธิ์ owner คนสุดท้าย
    if (target.role === 'owner' && (upd.is_active === false || (upd.role && upd.role !== 'owner'))) {
      const { count } = await supabase.from('admin_users').select('id', { count: 'exact', head: true }).eq('role', 'owner').eq('is_active', true);
      if ((count || 0) <= 1) return res.status(400).json({ error: 'ต้องมีบัญชีเจ้าของร้านที่ใช้งานได้อย่างน้อย 1 บัญชี' });
    }
    const { error } = await supabase.from('admin_users').update(upd).eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { logError('auth-update-user', e); res.status(500).json({ error: e.message }); }
});

app.delete('/auth/users/:id', requirePerm('users'), async (req, res) => {
  try {
    const me = req.adminUser;
    const { data: target } = await supabase.from('admin_users').select('*').eq('id', req.params.id).maybeSingle();
    if (!target) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
    if (target.role === 'owner') {
      if (me.role !== 'owner') return res.status(403).json({ error: 'ลบบัญชี owner ได้เฉพาะเจ้าของร้าน' });
      const { count } = await supabase.from('admin_users').select('id', { count: 'exact', head: true }).eq('role', 'owner');
      if ((count || 0) <= 1) return res.status(400).json({ error: 'ลบเจ้าของร้านคนสุดท้ายไม่ได้' });
    }
    const { error } = await supabase.from('admin_users').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { logError('auth-delete-user', e); res.status(500).json({ error: e.message }); }
});
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// ─── Supabase ──────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ─── LINE (ใช้แค่แจ้งเตือนแอดมิน) ───────────────────────────
const LINE_API = 'https://api.line.me/v2/bot/message';

// อ่าน admin UIDs จาก env — รองรับหลายคนคั่นด้วย comma
// รองรับทั้งชื่อเก่า ADMIN_LINE_UID และชื่อใหม่ ADMIN_LINE_UIDS
function getAdminUids() {
  // รวมทั้ง ADMIN_LINE_UIDS และ ADMIN_LINE_UID เข้าด้วยกัน (ไม่ใช่ OR)
  const fromPlural   = process.env.ADMIN_LINE_UIDS || '';
  const fromSingular = process.env.ADMIN_LINE_UID  || '';
  const combined = [fromPlural, fromSingular].filter(Boolean).join(',');
  // deduplicate — กรณีใส่ UID เดียวกันใน 2 ตัวแปร
  return [...new Set(combined.split(',').map(s => s.trim()).filter(Boolean))];
}

async function linePush(userId, messages) {
  const res = await fetch(`${LINE_API}/push`, {
    method : 'POST',
    headers: {
      'Content-Type' : 'application/json',
      'Authorization': `Bearer ${process.env.LINE_TOKEN}`
    },
    body: JSON.stringify({ to: userId, messages })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || 'LINE push failed');
  }
}

// ส่งให้แอดมินทุกคนพร้อมกัน (ไม่ fail ถ้ามีบางคนล้มเหลว)
async function notifyAllAdmins(messages) {
  const uids = getAdminUids();
  if (!uids.length) {
    console.warn('⚠️ ไม่มี ADMIN_LINE_UIDS / ADMIN_LINE_UID ตั้งไว้');
    return { sent: 0, failed: 0 };
  }
  const results = await Promise.allSettled(uids.map(uid => linePush(uid, messages)));
  const sent   = results.filter(r => r.status === 'fulfilled').length;
  const failed = results.filter(r => r.status === 'rejected').length;
  if (failed) console.warn(`⚠️ ส่งแอดมิน ${sent}/${uids.length} สำเร็จ`);
  return { sent, failed };
}

// ตอบกลับใน LINE webhook (ใช้ replyToken)
// safeReply: ลอง lineReply ก่อน ถ้า token หมดอายุ (Render cold start) → fallback linePush
async function safeReply(replyToken, userId, messages) {
  try {
    await lineReply(replyToken, messages);
  } catch (e) {
    console.warn('lineReply failed → fallback push:', e.message);
    if (userId) {
      await linePush(userId, messages).catch(e2 =>
        console.warn('push fallback failed:', e2.message)
      );
    }
  }
}

async function lineReply(replyToken, messages) {
  const res = await fetch(`${LINE_API}/reply`, {
    method : 'POST',
    headers: {
      'Content-Type' : 'application/json',
      'Authorization': `Bearer ${process.env.LINE_TOKEN}`
    },
    body: JSON.stringify({ replyToken, messages })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    console.warn('LINE reply failed:', err.message || res.status);
  }
}

// ── Shop Hours Message Helper ────────────────────────────────
async function shGetHoursMsg() {
  try {
    const { data } = await supabase.from('settings').select('value').eq('key','shop_hours').maybeSingle();
    if (!data || !data.value || !data.value.enabled) return '';
    const cfg = data.value;
    // แปลงเวลาเป็น Asia/Bangkok เสมอ (server อาจรัน UTC)
    const bkkStr = new Date().toLocaleString('en-US', { timeZone: 'Asia/Bangkok' });
    const now = new Date(bkkStr);
    const day = now.getDay();
    const openDays = cfg.openDays || [];
    const [oh,om] = (cfg.openTime||'09:00').split(':').map(Number);
    const [ch,cm] = (cfg.closeTime||'18:00').split(':').map(Number);
    const nowMins = now.getHours()*60+now.getMinutes();
    const isOpen = openDays.includes(day) && nowMins >= oh*60+om && nowMins < ch*60+cm;
    // ถ้าร้านเปิดปกติ ไม่ต้องส่งข้อความอะไรเลย
    if (isOpen) return '';
    const msg = cfg.msgClosed || '';
    if (!msg) return '';
    return '\n\n🔴 ' + msg;
  } catch(e) { return ''; }
}

// 🔒 SECURITY FIX (สำคัญที่สุดในระบบ): เดิม /send-order เชื่อค่า items[].price และ total
// ที่ส่งมาจาก client (เบราว์เซอร์) ตรงๆ ทั้งหมด — ราคาต่อชิ้น/ราคารวมคำนวณฝั่งหน้าเว็บล้วนๆ
// (ดู cartSubtotal/getCartLinePrice/calcBundleLine ใน index.html) ฝั่ง backend ไม่เคยตรวจสอบ
// กับราคาจริงในตาราง products เลย — ใครก็เรียก POST /send-order ตรงๆ (ข้ามเบราว์เซอร์ เช่นด้วย
// curl/Postman) ส่ง items ของจริงแต่ price/total ต่ำกว่าความเป็นจริงมากๆ ก็สั่งซื้อได้เกือบฟรี
// ฟังก์ชันนี้คำนวณราคาที่ "ถูกต้องตามจริง" ของแต่ละ item ใหม่ฝั่ง server โดยจำลอง logic เดียวกับ
// getCartLinePrice/calcBundleLine ในหน้าเว็บทุกกระเบียดนิ้ว (รวม tier แบบรวม qty ข้ามไซซ์ที่ราคา
// เท่ากันในสินค้าเดียวกัน + โปรชุด) แล้วคืนราคาที่ยืนยันแล้วให้ /send-order ใช้แทนค่าที่ client ส่งมา
async function computeVerifiedItemPricing(items) {
  const productIds = [...new Set(items.map(it => it.productId).filter(id => id !== undefined && id !== null))];
  if (!productIds.length) return { ok: false, reason: 'ไม่มี productId ในรายการสินค้า' };

  const { data: products, error } = await supabase.from('products').select('*').in('id', productIds);
  if (error) return { ok: false, reason: 'ตรวจสอบราคาสินค้าไม่ได้: ' + error.message };
  const productMap = new Map((products || []).map(p => [String(p.id), p]));

  // รวม qty ต่อ (productId + ราคาฐานของไซซ์) เหมือนที่ getEffectiveQty/getCartLinePrice ทำ
  // ข้าม item ที่เป็นส่วนโปรชุด (isBundle) เพราะโปรชุดไม่ใช้ tier
  const qtyByGroup = new Map();
  const resolved = [];

  for (const it of items) {
    const qty = Number(it.qty);
    if (!it.productId || !it.sizeName || !Number.isFinite(qty) || qty <= 0) {
      return { ok: false, reason: `รายการสินค้าไม่ถูกต้อง (productId/sizeName/qty) — ${it.name || ''}` };
    }
    const product = productMap.get(String(it.productId));
    if (!product) return { ok: false, reason: `ไม่พบสินค้า id=${it.productId} ในระบบ (อาจถูกลบไปแล้ว)` };
    const size = (product.sizes || []).find(s => s.n === it.sizeName);
    if (!size) return { ok: false, reason: `ไม่พบไซซ์ "${it.sizeName}" ของสินค้า "${product.name || it.productId}"` };

    resolved.push({ it, qty, size });
    const bundle = (size.bundle && size.bundle.q >= 2 && size.bundle.price > 0 && size.bundle.price < size.p) ? size.bundle : null;
    if (!bundle && !it.isBundle) {
      const key = `${it.productId}::${size.p}`;
      qtyByGroup.set(key, (qtyByGroup.get(key) || 0) + qty);
    }
  }

  let verifiedTotal = 0;
  const verifiedItems = [];
  for (const { it, qty, size } of resolved) {
    const bundle = (size.bundle && size.bundle.q >= 2 && size.bundle.price > 0 && size.bundle.price < size.p) ? size.bundle : null;
    let unitPrice;

    if (bundle && it.isBundle) {
      // ส่วนที่ได้ราคาโปรชุด — ราคาต่อชิ้นต้องเท่ากับ bundle.price เป๊ะ
      unitPrice = bundle.price;
    } else if (bundle && !it.isBundle) {
      // ส่วนเกินโปรชุด (คิดราคาปกติเสมอ ไม่ใช้ tier — ตรงตาม calcBundleLine ฝั่งหน้าเว็บ)
      unitPrice = size.p;
    } else {
      // ไม่มีโปรชุด → ใช้ tier ตาม qty รวมของกลุ่ม (product+ราคาฐานเดียวกัน)
      const tiers = Array.isArray(size.tiers) ? size.tiers : [];
      if (tiers.length) {
        const key = `${it.productId}::${size.p}`;
        const groupQty = qtyByGroup.get(key) || qty;
        const sorted = [...tiers].sort((a, b) => b.minQty - a.minQty);
        const matched = sorted.find(t => groupQty >= t.minQty);
        unitPrice = matched ? matched.price : size.p;
      } else {
        unitPrice = size.p;
      }
    }

    verifiedItems.push({ ...it, price: unitPrice });
    verifiedTotal += unitPrice * qty;
  }

  return { ok: true, items: verifiedItems, verifiedTotal };
}

// normalize เบอร์โทร — เอาเฉพาะตัวเลข
function normalizePhone(p) {
  return String(p || '').replace(/\D/g, '');
}

// 🔒 SECURITY FIX: เดิม /sales/:salesId และ /invite/:refCode เอาค่าจาก URL (req.params) ที่ใครก็
// พิมพ์อะไรก็ได้ไปแปะในหน้า HTML ตรงๆ โดยไม่ escape เลย (เช่น <div>...${salesId}</div>) — ทำให้
// ใครก็สร้างลิงก์แชร์ เช่น /sales/<script>alert(document.cookie)</script> แล้วส่งให้เหยื่อกดได้
// (Reflected XSS) — ฟังก์ชันนี้ escape อักขระพิเศษของ HTML ก่อนแปะลง body เสมอ
function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[m]));
}
// 🔒 ใช้คู่กับ JSON.stringify() ตอนแปะค่าลงใน <script> — JSON.stringify เองไม่ escape "</script>"
// ถ้าค่าที่ได้จาก user มีคำว่า </script> ปนอยู่ เบราว์เซอร์จะปิด <script> ก่อนกำหนดแล้วรันโค้ด
// ที่แปะต่อท้ายมาแทน ฟังก์ชันนี้เปลี่ยน "<" เป็น \u003c กันไม่ให้ปิด tag ก่อนกำหนดได้
function safeJsonForScript(v) {
  return JSON.stringify(v).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
}

// ─── Helpers ──────────────────────────────────────────────
function genOrderId() {
  // ⚠️ ห้ามใช้ slice(-6) เพราะเลขท้าย 6 หลักของ timestamp วนซ้ำทุก ~16.7 นาที → order_id ชนกันได้
  // ใช้เลขท้าย 9 หลัก (วนซ้ำทุก ~11.5 วัน) + สุ่มอีก 2 หลัก → โอกาสชนแทบเป็นศูนย์
  return 'ORD' + Date.now().toString().slice(-9) + String(Math.floor(Math.random() * 90) + 10);
}

function statusLabel(s) {
  return ({
    pending  : '⏳ รอดำเนินการ',
    sent     : '📬 ร้านได้รับออเดอร์แล้ว',
    confirmed: '✅ ยืนยันแล้ว',
    shipped  : '🚚 กำลังจัดส่ง',
    done     : '🎉 เสร็จสิ้น',
    cancelled: '❌ ยกเลิก',
    failed   : '💥 ผิดพลาด'
  })[s] || s;
}

// ─── ผู้แนะนำ (เซล/เพื่อน): แปลง ref_code → ชื่อ ───────────
// เซล (S001, S002, ...) → ดึงชื่อจาก Google Sheet ผ่าน GAS ตัวเดียวกับหน้า Admin (cache 10 นาที)
// เพื่อนชวนเพื่อน (REFxxx) → ดึงชื่อเจ้าของโค้ดจากตาราง referrals + orders
const SALES_GAS_URL = process.env.SALES_GAS_URL || 'https://script.google.com/macros/s/AKfycbw8PT4PBw0AVXiYiyp9LW4mZexvHxkBiohODVoTkq26Tu4YskhyDsbA821E2MBaLJjl/exec';
let _salesStaffCache = { ts: 0, list: [] };

async function getSalesStaffList() {
  if (_salesStaffCache.list.length && (Date.now() - _salesStaffCache.ts) < 10 * 60 * 1000) {
    return _salesStaffCache.list;
  }
  try {
    const r = await fetch(SALES_GAS_URL, {
      method : 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body   : JSON.stringify({ action: 'getSalesStaffList' })
    });
    const d = await r.json();
    if (d && d.ok && Array.isArray(d.staff)) {
      _salesStaffCache = { ts: Date.now(), list: d.staff };
    }
  } catch (e) {
    console.warn('getSalesStaffList failed:', e.message);
  }
  return _salesStaffCache.list;
}

async function resolveRefInfo(refCode) {
  if (!refCode) return null;
  // 💼 รหัสเซล
  if (/^S\d+$/i.test(refCode)) {
    let name = '';
    try {
      const staff = await getSalesStaffList();
      const s = staff.find(x => String(x.salesId || x.id || '').toUpperCase() === String(refCode).toUpperCase());
      if (s) name = s.name || '';
    } catch (e) {}
    return {
      type : 'sales',
      code : refCode,
      name,
      label: name ? `💼 เซลแนะนำ: ${name} (${refCode})` : `💼 เซลแนะนำ: ${refCode}`
    };
  }
  // 🎁 เพื่อนชวนเพื่อน
  let name = '';
  try {
    const { data: ref } = await supabase
      .from('referrals').select('customer_id').eq('ref_code', refCode).maybeSingle();
    if (ref?.customer_id) {
      const { data: anyOrder } = await supabase
        .from('orders').select('customer_name, line_name')
        .eq('customer_id', ref.customer_id)
        .not('customer_name', 'eq', '')
        .order('created_at', { ascending: false })
        .limit(1).maybeSingle();
      name = anyOrder?.line_name || anyOrder?.customer_name || '';
    }
  } catch (e) {}
  return {
    type : 'friend',
    code : refCode,
    name,
    label: name ? `🎁 เพื่อนแนะนำ: ${name} (${refCode})` : `🎁 เพื่อนแนะนำ (${refCode})`
  };
}

async function buildAdminMsg(order) {
  const { customer_name, items, total, order_id, created_at, phone, address, note,
          coupon_code, discount_amount, ref_code, order_type, payment_method, payment_label } = order;
  const date = new Date(created_at).toLocaleString('th-TH', { dateStyle:'short', timeStyle:'short', timeZone:'Asia/Bangkok' });
  const typeLabel = order_type === 'delivery' ? '🚚 จัดส่ง' : '📦 จอง/รับเอง';
  const payLabel  = payment_label || (payment_method === 'cod' ? '🏍️ เก็บปลายทาง' : payment_method === 'transfer' ? '📲 โอน/สแกน QR' : null);
  let msg = `🛒 ออเดอร์ใหม่! #${order_id}\n`;
  msg += `${'─'.repeat(24)}\n`;
  msg += `👤 ${customer_name}\n`;
  // 🤝 แสดงผู้แนะนำใต้ชื่อลูกค้า (เซล: ชื่อ+รหัส / เพื่อน: ชื่อเพื่อน)
  const refInfo = await resolveRefInfo(ref_code);
  if (refInfo) msg += `${refInfo.label}\n`;
  if (phone)   msg += `📞 ${phone}\n`;
  msg += `📋 ประเภท: ${typeLabel}\n`;
  if (payLabel) msg += `💳 ชำระ: ${payLabel}\n`;
  if (address) msg += `📍 ${address}\n`;
  msg += `📅 ${date}\n`;
  msg += `${'─'.repeat(24)}\n`;
  (items || []).forEach(i => {
    msg += `${i.emoji || '•'} ${i.name}\n`;
    msg += `   ${i.qty} × ฿${i.price.toLocaleString()} = ฿${(i.qty * i.price).toLocaleString()}\n`;
  });
  msg += `${'─'.repeat(24)}\n`;
  const disc = Number(discount_amount) || 0;
  if (disc > 0) {
    const subtotal = total + disc;
    msg += `💲 ราคาก่อนลด: ฿${subtotal.toLocaleString()}\n`;
    msg += `🎟️ ${coupon_code ? `คูปอง [${coupon_code}]` : 'ส่วนลด'}: -฿${disc.toLocaleString()}\n`;
  }
  msg += `💰 ยอดสุทธิ: ฿${total.toLocaleString()}\n`;
  if (note) msg += `\n📝 ${note}\n`;
  msg += `\n📲 ติดต่อลูกค้าผ่านหน้า Admin Panel ได้เลยค่ะ`;
  msg += await shGetHoursMsg();
  return msg;
}

// ─── LINE Flex Message Builders ───────────────────────────
const SHOP_URL = process.env.SHOP_URL || 'https://lineoa-u0v2.onrender.com/';

// ─── LINE OA Auto-Reply Keywords ───
// ถ้าลูกค้าพิมพ์ตรงกับ keyword เหล่านี้ → ระบบไม่แจ้งแอดมิน LINE
// (เพราะ LINE OA ตั้ง auto-reply ตอบให้แล้ว — ไม่ต้องรบกวนแอดมิน)
//
// แก้ list ได้ 2 ทาง:
// 1. แก้ตรงนี้แล้ว redeploy
// 2. ตั้ง ENV variable LINE_OA_AUTOREPLY_KEYWORDS ใน Railway (ใช้ , แยก)
//    ตัวอย่าง: วิธีสั่งสินค้า,สั่งยังไง,วิธีใช้,ราคาเท่าไหร่
const DEFAULT_AUTOREPLY_KEYWORDS = [
  'วิธีสั่งสินค้า',
  'สั่งยังไง',
  'วิธีสั่ง',
  'วิธีใช้',
  'วิธีใช้งาน',
  'ราคาเท่าไหร่',
  'มีโปรไหม',
  'โปรโมชั่น',
  'สวัสดี',
  'สวัสดีครับ',
  'สวัสดีค่ะ',
  'hello',
  'hi'
];

const AUTOREPLY_KEYWORDS = (
  process.env.LINE_OA_AUTOREPLY_KEYWORDS
    ? process.env.LINE_OA_AUTOREPLY_KEYWORDS.split(',')
    : DEFAULT_AUTOREPLY_KEYWORDS
).map(k => k.trim().toLowerCase()).filter(Boolean);

function isAutoReplyKeyword(text) {
  if (!text) return false;
  const t = String(text).trim().toLowerCase();
  // exact match
  if (AUTOREPLY_KEYWORDS.includes(t)) return true;
  // เผื่อมี whitespace/symbol เกินมา
  const cleaned = t.replace(/[\s\?\!\.\,]+/g, '');
  return AUTOREPLY_KEYWORDS.some(k => k.replace(/\s+/g, '') === cleaned);
}


// สีตามสถานะ
function statusColor(s) {
  return ({
    pending  : '#F39C12',
    sent     : '#3498DB',
    confirmed: '#27AE60',
    shipped  : '#8E44AD',
    done     : '#16A085',
    cancelled: '#95A5A6',
    failed   : '#E74C3C'
  })[s] || '#7F8C8D';
}

// Flex: สรุปออเดอร์ใหม่ (ส่งหาลูกค้าหลังสั่ง)
// 🎨 Theme: Bright Red × Gold (แดงสด #D62828 / ทอง #FFC94A)
const BRAND_RED       = '#D62828';
const BRAND_RED_DARK  = '#A4161A';
const BRAND_GOLD      = '#FFC94A';
const BRAND_GOLD_SOFT = '#FFD97D';
const BRAND_GOLD_PALE = '#FFE3B3';
const BRAND_CREAM     = '#FFF7E8';
const BRAND_CREAM_BD  = '#F5E1B8';
const BRAND_GOLD_TXT  = '#8a6d1f';

// แถบตราร้าน (โลโก้ดาว + ชื่อร้าน) ใช้ซ้ำบนหัวการ์ดทุกใบ
function brandHeaderRow(small = false) {
  const size = small ? '30px' : '38px';
  return {
    type:'box', layout:'horizontal', alignItems:'center', spacing:'md',
    contents:[
      { type:'box', layout:'vertical', width:size, height:size,
        cornerRadius:'999px', backgroundColor:'#ffffff',
        justifyContent:'center', alignItems:'center',
        contents:[ { type:'text', text:'★', size: small ? 'md' : 'lg', color: BRAND_RED, align:'center' } ]
      },
      { type:'box', layout:'vertical', flex:1,
        contents:[
          { type:'text', text:'MONSHIN SUPPLY', size:'xxs', color: BRAND_GOLD_SOFT, weight:'bold' },
          ...(small ? [] : [{ type:'text', text:'ขอบคุณสำหรับการสั่งซื้อ', size:'sm', color:'#ffffff' }])
        ]
      }
    ]
  };
}

async function buildOrderSummaryFlex(order) {
  // ป้องกันค่า undefined/NaN
  const safe = (v, fallback = '') => (v === undefined || v === null ? fallback : v);
  const safeNum = (v) => {
    const n = Number(v);
    return isNaN(n) ? 0 : n;
  };

  const items = Array.isArray(order.items) ? order.items : [];
  const itemRows = items.slice(0, 6).map(i => {
    const qty   = safeNum(i.qty) || 1;
    const price = safeNum(i.price);
    const lineTotal = qty * price;
    const emoji = String(safe(i.emoji, '•')).trim() || '•';
    const name  = String(safe(i.name, 'สินค้า')).trim() || 'สินค้า';
    return {
      type: 'box', layout: 'horizontal', margin: 'sm',
      contents: [
        { type:'text', text:`${emoji} ${name}`, size:'sm', color:'#3d3428', flex:5, wrap:true },
        { type:'text', text:`×${qty}`, size:'sm', color:'#a89d8c', flex:1, align:'end' },
        { type:'text', text:`฿${lineTotal.toLocaleString()}`, size:'sm', color: BRAND_RED, weight:'bold', flex:2, align:'end' }
      ]
    };
  });

  // ถ้าไม่มี items เลย → ใส่ placeholder
  if (!itemRows.length) {
    itemRows.push({
      type: 'text', text: '— ไม่มีรายการสินค้า —',
      size: 'sm', color: '#a89d8c', align: 'center', margin: 'sm'
    });
  }

  const moreItems = items.length > 6
    ? [{ type:'text', text:`+${items.length - 6} รายการ`, size:'xs', color:'#a89d8c', margin:'sm' }]
    : [];

  const total = safeNum(order.total);
  const orderId = String(safe(order.order_id, '-'));
  const customerName = String(safe(order.customer_name, '-')).trim() || '-';
  // 🤝 ผู้แนะนำ (เซล/เพื่อน) — แสดงใต้ชื่อลูกค้าบนหัวการ์ด
  const refInfo = await resolveRefInfo(order.ref_code);
  const orderTypeLabel = order.order_type === 'delivery' ? '🚚 จัดส่ง' : '📦 จอง/รับเอง';
  const payLabel = order.payment_label || (order.payment_method === 'cod' ? '🏍️ เก็บปลายทาง' : order.payment_method === 'transfer' ? '📲 โอน/สแกน QR' : null);
  const payColor = order.payment_method === 'cod' ? BRAND_RED : '#2980b9';

  // แถวข้อมูลออเดอร์ (ประเภท + ชำระ)
  const orderInfoRows = [
    { type:'box', layout:'horizontal', margin:'sm',
      contents:[
        { type:'text', text:'ประเภท', size:'sm', color:'#8a8378', flex:1 },
        { type:'text', text: orderTypeLabel, size:'sm', color:'#3d3428', weight:'bold', align:'end' }
      ]
    },
    ...(payLabel ? [{
      type:'box', layout:'horizontal', margin:'xs',
      contents:[
        { type:'text', text:'ชำระเงิน', size:'sm', color:'#8a8378', flex:1 },
        { type:'text', text: payLabel, size:'sm', color: payColor, weight:'bold', align:'end' }
      ]
    }] : []),
    { type:'separator', margin:'md', color:'#f5e6e6' }
  ];

  return {
    type: 'flex',
    altText: `ออเดอร์ #${orderId} ของคุณ ฿${total.toLocaleString()}`,
    contents: {
      type: 'bubble',
      header: {
        type: 'box', layout: 'vertical',
        backgroundColor: BRAND_RED,
        paddingAll: '0px',
        contents: [
          // แถบเข้มคาดบนสุด — ให้หัวการ์ดมีมิติ
          { type:'box', layout:'vertical', height:'6px', backgroundColor: BRAND_RED_DARK, contents:[{ type:'filler' }] },
          { type:'box', layout:'vertical', paddingAll:'lg',
            contents: [
              brandHeaderRow(),
              { type:'text', text:`#${orderId}`, color:'#ffffff', size:'xl', weight:'bold', margin:'md' },
              { type:'text', text:`คุณ ${customerName}`, color: BRAND_GOLD_PALE, size:'sm', margin:'xs' },
              ...(refInfo ? [{ type:'text', text: refInfo.label, color: BRAND_GOLD_SOFT, size:'xs', margin:'xs', wrap:true }] : [])
            ]
          },
          // เส้นทองคาดใต้หัว
          { type:'box', layout:'vertical', height:'3px', backgroundColor: BRAND_GOLD, contents:[{ type:'filler' }] }
        ]
      },
      body: {
        type:'box', layout:'vertical', spacing:'md', paddingAll:'lg',
        contents: [
          ...orderInfoRows,
          { type:'text', text:'รายการสินค้า', size:'xs', color:'#C8912A', weight:'bold' },
          ...itemRows,
          ...moreItems,
          { type:'separator', margin:'lg', color:'#f5e6e6' },
          // 🎟️ แสดงส่วนลดคูปอง (ถ้ามี)
          ...(() => {
            const discount = safeNum(order.discount_amount);
            const code     = order.coupon_code;
            if (!code || discount <= 0) return [];
            const subtotal = total + discount;
            return [
              { type:'box', layout:'horizontal', margin:'md',
                contents:[
                  { type:'text', text:'ราคาก่อนลด', size:'sm', color:'#8a8378', flex:1 },
                  { type:'text', text:`฿${subtotal.toLocaleString()}`, size:'sm', color:'#8a8378', align:'end' }
                ]
              },
              { type:'box', layout:'horizontal', margin:'xs',
                contents:[
                  { type:'text', text:`🎟️ คูปอง [${code}]`, size:'sm', color: BRAND_RED, flex:1 },
                  { type:'text', text:`-฿${discount.toLocaleString()}`, size:'sm', color: BRAND_RED, weight:'bold', align:'end' }
                ]
              },
              { type:'separator', margin:'sm', color:'#f5e6e6' }
            ];
          })(),
          // กล่องยอดสุทธิ พื้นครีมทอง ขอบทอง
          { type:'box', layout:'horizontal', margin:'md',
            backgroundColor: BRAND_CREAM, cornerRadius:'8px',
            borderColor: BRAND_CREAM_BD, borderWidth:'1px',
            paddingAll:'md', alignItems:'center',
            contents:[
              { type:'text', text:'ยอดสุทธิ', size:'sm', color: BRAND_GOLD_TXT, flex:1 },
              { type:'text', text:`฿${total.toLocaleString()}`, size:'xl', color: BRAND_RED, weight:'bold', align:'end' }
            ]
          },
          { type:'text', text:'⏳ ร้านกำลังตรวจสอบและจะแจ้งให้ทราบเร็วๆ นี้', size:'xs', color:'#a89d8c', wrap:true, margin:'lg', align:'center' },
          ...await (async () => {
            try {
              const { data } = await supabase.from('settings').select('value').eq('key','shop_hours').maybeSingle();
              if (!data || !data.value || !data.value.enabled) return [];
              const cfg = data.value;
              const bkkStr2 = new Date().toLocaleString('en-US', { timeZone: 'Asia/Bangkok' });
              const now = new Date(bkkStr2);
              const day = now.getDay();
              const openDays = cfg.openDays || [];
              const [oh,om] = (cfg.openTime||'09:00').split(':').map(Number);
              const [ch,cm] = (cfg.closeTime||'18:00').split(':').map(Number);
              const nowMins = now.getHours()*60+now.getMinutes();
              const isOpen = openDays.includes(day) && nowMins >= oh*60+om && nowMins < ch*60+cm;
              // ถ้าร้านเปิดปกติ ไม่ต้องแสดง block แจ้งสถานะ
              if (isOpen) return [];
              const msg = cfg.msgClosed || '';
              if (!msg) return [];
              const openStr = String(oh).padStart(2,'0')+':'+String(om).padStart(2,'0');
              const closeStr = String(ch).padStart(2,'0')+':'+String(cm).padStart(2,'0');
              const daysMap = ['อา.','จ.','อ.','พ.','พฤ.','ศ.','ส.'];
              const daysStr = openDays.map(d=>daysMap[d]).join(' ');
              return [
                { type:'separator', margin:'lg', color:'#f5e6e6' },
                { type:'box', layout:'vertical', margin:'md', backgroundColor: '#fdf2f0', cornerRadius:'8px', paddingAll:'sm',
                  contents:[
                    { type:'text', text: '🔴 ร้านปิดแล้ว', size:'xs', color: BRAND_RED_DARK, weight:'bold' },
                    { type:'text', text: '🕐 '+daysStr+' '+openStr+'–'+closeStr+' น.', size:'xs', color:'#8a8378', margin:'xs' },
                    { type:'text', text: msg, size:'xs', color:'#555555', wrap:true, margin:'xs' }
                  ]
                }
              ];
            } catch(e) { return []; }
          })()
        ]
      },
      footer: {
        type:'box', layout:'vertical', spacing:'sm', paddingAll:'lg', paddingTop:'none',
        contents: [
          { type:'button', style:'primary', color: BRAND_RED, height:'sm',
            action: { type:'postback', label:'📋 ดูสถานะออเดอร์',
                      data:`action=view_order&id=${orderId}`,
                      displayText:`📋 ดูสถานะ #${orderId}` }
          },
          // ปุ่มรอง — กรอบทอง ตัวหนังสือทอง
          { type:'box', layout:'vertical', cornerRadius:'10px',
            borderColor:'#E8B94A', borderWidth:'1px', paddingAll:'md',
            action: { type:'uri', label:'สั่งซื้อเพิ่ม', uri: SHOP_URL },
            contents:[
              { type:'text', text:'🛒 สั่งซื้อเพิ่ม', size:'sm', color:'#B07E1E', align:'center', weight:'bold' }
            ]
          }
        ]
      }
    }
  };
}

// Flex: อัปเดตสถานะออเดอร์
// 🎨 Theme: Bright Red × Gold — หัวการ์ดแดงสดทุกสถานะ + Progress Tracker 4 ขั้น
async function buildStatusUpdateFlex(order, status) {
  const labels = {
    pending  : { emoji:'⏳', text:'รอดำเนินการ', desc:'ร้านกำลังตรวจสอบออเดอร์ของคุณ' },
    sent     : { emoji:'📬', text:'ร้านได้รับแล้ว', desc:'ร้านได้รับออเดอร์ของคุณเรียบร้อยแล้ว' },
    confirmed: { emoji:'✅', text:'ยืนยันแล้ว', desc:'ร้านยืนยันออเดอร์เรียบร้อย กำลังจัดเตรียม' },
    shipped  : { emoji:'🚚', text:'กำลังจัดส่ง', desc:'สินค้าออกจากร้านแล้ว รอรับได้เลย' },
    done     : { emoji:'🎉', text:'เสร็จสิ้น', desc:'ขอบคุณที่อุดหนุนร้านเรา ❤️' },
    cancelled: { emoji:'❌', text:'ยกเลิก', desc:'ออเดอร์ถูกยกเลิก ติดต่อร้านหากมีข้อสงสัย' },
    failed   : { emoji:'💥', text:'ผิดพลาด', desc:'มีข้อผิดพลาดเกิดขึ้น กรุณาติดต่อร้าน' }
  };
  const lbl = labels[status] || { emoji:'📦', text:status, desc:'' };

  // ─── Progress Tracker 4 ขั้น ───
  // สถานะปกติ: รับแล้ว → ยืนยัน → จัดส่ง → สำเร็จ
  // ยกเลิก/ผิดพลาด: ไม่แสดง tracker แต่แสดงกล่องแจ้งเตือนแทน
  const STEP_LABELS = ['รับแล้ว', 'ยืนยัน', 'จัดส่ง', 'สำเร็จ'];
  const STEP_IDX = { pending: 0, sent: 0, confirmed: 1, shipped: 2, done: 3 };
  const isTracked = status in STEP_IDX;
  const curIdx = STEP_IDX[status];

  const COLOR_DONE_STEP = '#2E8B57';   // เขียว = ผ่านแล้ว
  const COLOR_WAIT_STEP = '#f2e8dc';   // เทาครีม = ยังไม่ถึง
  const COLOR_WAIT_TEXT = '#b5ab99';

  function stepCircle(i) {
    const isDone    = status === 'done' ? true : i < curIdx;
    const isCurrent = status !== 'done' && i === curIdx;
    if (isDone) {
      return { type:'box', layout:'vertical', width:'22px', height:'22px',
        cornerRadius:'999px', backgroundColor: COLOR_DONE_STEP,
        justifyContent:'center', alignItems:'center',
        contents:[ { type:'text', text:'✓', size:'xs', color:'#ffffff', align:'center', weight:'bold' } ] };
    }
    if (isCurrent) {
      return { type:'box', layout:'vertical', width:'22px', height:'22px',
        cornerRadius:'999px', backgroundColor: BRAND_RED,
        borderColor: BRAND_GOLD, borderWidth:'2px',
        justifyContent:'center', alignItems:'center',
        contents:[ { type:'text', text:'●', size:'xxs', color:'#ffffff', align:'center' } ] };
    }
    return { type:'box', layout:'vertical', width:'22px', height:'22px',
      cornerRadius:'999px', backgroundColor: COLOR_WAIT_STEP,
      contents:[ { type:'filler' } ] };
  }

  function stepBlock(i) {
    const isDone    = status === 'done' ? true : i < curIdx;
    const isCurrent = status !== 'done' && i === curIdx;
    const txtColor  = isDone ? COLOR_DONE_STEP : isCurrent ? BRAND_RED : COLOR_WAIT_TEXT;
    return {
      type:'box', layout:'vertical', flex:1, alignItems:'center',
      contents:[
        stepCircle(i),
        { type:'text', text: STEP_LABELS[i], size:'xxs', color: txtColor,
          align:'center', margin:'sm', weight: isCurrent ? 'bold' : 'regular' }
      ]
    };
  }

  function stepConnector(i) {
    // เส้นเชื่อมระหว่างขั้น i กับ i+1 — เขียวถ้าผ่านขั้น i แล้ว
    const passed = status === 'done' ? true : i < curIdx;
    return {
      type:'box', layout:'vertical', flex:1, paddingTop:'10px',
      contents:[
        { type:'box', layout:'vertical', height:'2px',
          backgroundColor: passed ? COLOR_DONE_STEP : '#eee0d0',
          contents:[ { type:'filler' } ] }
      ]
    };
  }

  const trackerBox = isTracked ? [
    { type:'box', layout:'horizontal', margin:'lg',
      contents: [
        stepBlock(0), stepConnector(0),
        stepBlock(1), stepConnector(1),
        stepBlock(2), stepConnector(2),
        stepBlock(3)
      ]
    }
  ] : [
    // ยกเลิก/ผิดพลาด — กล่องแจ้งเตือน
    { type:'box', layout:'vertical', margin:'lg',
      backgroundColor: status === 'cancelled' ? '#f4f1ea' : '#fdf2f0',
      cornerRadius:'8px', paddingAll:'md',
      contents:[
        { type:'text', text:`${lbl.emoji} ${lbl.text}`, size:'sm',
          color: status === 'cancelled' ? '#6b6455' : BRAND_RED_DARK, weight:'bold' }
      ]
    }
  ];

  return {
    type:'flex',
    altText: `${lbl.emoji} ออเดอร์ #${order.order_id} — ${lbl.text}`,
    contents: {
      type:'bubble',
      header: {
        type:'box', layout:'vertical',
        backgroundColor: BRAND_RED,
        paddingAll:'0px',
        contents: [
          { type:'box', layout:'vertical', height:'6px', backgroundColor: BRAND_RED_DARK, contents:[{ type:'filler' }] },
          { type:'box', layout:'vertical', paddingAll:'lg',
            contents: [
              { type:'box', layout:'horizontal', alignItems:'center',
                contents:[
                  { type:'box', layout:'horizontal', alignItems:'center', spacing:'md', flex:1,
                    contents:[
                      { type:'box', layout:'vertical', width:'30px', height:'30px',
                        cornerRadius:'999px', backgroundColor:'#ffffff',
                        justifyContent:'center', alignItems:'center',
                        contents:[ { type:'text', text:'★', size:'md', color: BRAND_RED, align:'center' } ]
                      },
                      { type:'text', text:'MONSHIN SUPPLY', size:'xxs', color: BRAND_GOLD_SOFT, weight:'bold', flex:1 }
                    ]
                  },
                  { type:'text', text:`#${order.order_id}`, size:'xxs', color: BRAND_GOLD_PALE, align:'end' }
                ]
              },
              { type:'text', text:'อัปเดตสถานะออเดอร์', color:'#ffffff', size:'sm', margin:'md' },
              // ป้ายสถานะ พื้นขาว ตัวแดง
              { type:'box', layout:'vertical', margin:'sm',
                contents:[
                  { type:'box', layout:'horizontal',
                    backgroundColor:'#ffffff', cornerRadius:'999px',
                    paddingTop:'6px', paddingBottom:'6px', paddingStart:'14px', paddingEnd:'14px',
                    justifyContent:'center',
                    contents:[
                      { type:'text', text:`${lbl.emoji} ${lbl.text}`, size:'md', color: BRAND_RED_DARK, weight:'bold', align:'center' }
                    ]
                  }
                ]
              }
            ]
          },
          { type:'box', layout:'vertical', height:'3px', backgroundColor: BRAND_GOLD, contents:[{ type:'filler' }] }
        ]
      },
      body: {
        type:'box', layout:'vertical', spacing:'md', paddingAll:'lg', paddingTop:'sm',
        contents: [
          ...trackerBox,
          { type:'box', layout:'horizontal', margin:'md',
            contents: [
              { type:'text', text:'ยอดรวม', size:'sm', color:'#8a8378', flex:1 },
              { type:'text', text:`฿${(order.total||0).toLocaleString()}`, size:'sm', color: BRAND_RED, weight:'bold', align:'end', flex:2 }
            ]
          },
          // กล่องคำอธิบายสถานะ พื้นครีมทอง
          { type:'box', layout:'vertical', margin:'sm',
            backgroundColor: BRAND_CREAM, cornerRadius:'8px',
            borderColor: BRAND_CREAM_BD, borderWidth:'1px', paddingAll:'md',
            contents:[
              { type:'text', text:`📦 ${lbl.desc}`, size:'xs', color: BRAND_GOLD_TXT, wrap:true }
            ]
          },
          ...await (async () => {
            const hoursMsg = await shGetHoursMsg();
            if (!hoursMsg) return [];
            const txt = hoursMsg.replace('\n\n🔴 ','');
            return [
              { type:'separator', margin:'md', color:'#f5e6e6' },
              { type:'text', text: '🔴 ร้านปิดแล้ว', size:'xs', color: BRAND_RED_DARK, weight:'bold', margin:'md' },
              { type:'text', text: txt, size:'xs', color:'#555555', wrap:true, margin:'xs' }
            ];
          })()
        ]
      },
      footer: {
        type:'box', layout:'vertical', paddingAll:'lg', paddingTop:'none',
        contents: [
          { type:'button', style:'primary', color: BRAND_RED, height:'sm',
            action:{ type:'postback', label:'📋 ดูรายละเอียด',
                     data:`action=view_order&id=${order.order_id}`,
                     displayText:`📋 ดูรายละเอียด #${order.order_id}` }
          }
        ]
      }
    }
  };
}

// Flex: การชำระเงิน (สลิป/แจ้งยอด) — ใช้ร่วมกันทั้งฝั่งลูกค้าและแอดมิน
// audience: 'customer' | 'admin'
// result  : 'match' (ยอดตรง) | 'under' (โอนขาด) | 'over' (โอนเกิน/รอตรวจ)
function buildPaymentFlex({ audience, result, order_id, customer_name, paid, expected, diff }) {
  const paidStr     = `฿${Number(paid || 0).toLocaleString()}`;
  const expectedStr = `฿${Number(expected || 0).toLocaleString()}`;
  const diffStr     = `฿${Math.abs(Number(diff || 0)).toLocaleString(undefined,{maximumFractionDigits:2})}`;

  // กล่องผลตรวจยอด 3 สี
  const RESULT_BOX = {
    match: { bg:'#E9F5EC', bd:'#bfe0c8', tx:'#1f5c38' },
    under: { bg:'#FFF4E0', bd:'#F0D9A8', tx:'#8a5a12' },
    over : { bg:'#E8F1FA', bd:'#bcd6ee', tx:'#1d5a8f' }
  };
  const ADMIN_RESULT_BOX = {
    match: RESULT_BOX.match,
    under: { bg:'#FDECEC', bd:'#F0C0C0', tx:'#A4161A' },
    over : RESULT_BOX.under
  };

  const isAdmin = audience === 'admin';

  const conf = isAdmin ? {
    match: { title:'💳 ลูกค้าโอนเงินแล้ว!', boxText:'✓ ยอดตรง — ยืนยันอัตโนมัติแล้ว', box: ADMIN_RESULT_BOX.match },
    under: { title:'💳 สลิปยอดไม่ตรง',    boxText:`⚠️ ขาดอีก ${diffStr} — รอยืนยัน manual`, box: ADMIN_RESULT_BOX.under },
    over : { title:'💳 สลิปโอนเกิน',      boxText:`⚠️ โอนเกิน ${diffStr} — กด "ยืนยันชำระแล้ว" ใน Admin Panel`, box: ADMIN_RESULT_BOX.over }
  }[result] : {
    match: { badge:'✅ ชำระเงินสำเร็จ', badgeColor:'#1f7a45',
             boxText:'✓ ยอดตรง — ร้านได้รับชำระเรียบร้อยแล้ว', box: RESULT_BOX.match,
             note:'🎉 ขอบคุณที่อุดหนุนร้านเราค่ะ' },
    under: { badge:'⚠️ ยอดโอนไม่ครบ', badgeColor:'#B07E1E',
             boxText:`⚠️ ขาดอีก ${diffStr}`, box: RESULT_BOX.under,
             desc:'กรุณาโอนเพิ่มแล้วส่งสลิปใหม่ หรือติดต่อร้านเพื่อยืนยันค่ะ' },
    over : { badge:'✅ ได้รับสลิปแล้ว', badgeColor:'#1f7a45',
             boxText:'✓ ได้รับยอดแล้ว', box: RESULT_BOX.over,
             desc:'ทางร้านจะตรวจสอบและยืนยันเร็วๆ นี้ค่ะ' }
  }[result];

  const amountRows = [
    ...(isAdmin && customer_name ? [{
      type:'box', layout:'horizontal',
      contents:[
        { type:'text', text:'ชื่อลูกค้า', size:'sm', color:'#8a8378', flex:1 },
        { type:'text', text:String(customer_name), size:'sm', color:'#3d3428', weight:'bold', align:'end', flex:2 }
      ]
    }] : []),
    { type:'box', layout:'horizontal', margin:'xs',
      contents:[
        { type:'text', text:'ยอดที่โอน', size:'sm', color:'#8a8378', flex:1 },
        { type:'text', text: paidStr, size:'sm', color:'#3d3428', weight:'bold', align:'end', flex:2 }
      ]
    },
    { type:'box', layout:'horizontal', margin:'xs',
      contents:[
        { type:'text', text:'ยอดออเดอร์', size:'sm', color:'#8a8378', flex:1 },
        { type:'text', text: expectedStr, size:'sm', color:'#3d3428', weight:'bold', align:'end', flex:2 }
      ]
    }
  ];

  const resultBox = {
    type:'box', layout:'vertical', margin:'md',
    backgroundColor: conf.box.bg, cornerRadius:'8px',
    borderColor: conf.box.bd, borderWidth:'1px', paddingAll:'md',
    contents:[
      { type:'text', text: conf.boxText, size:'sm', color: conf.box.tx, weight:'bold', wrap:true },
      ...(conf.desc ? [{ type:'text', text: conf.desc, size:'xs', color: conf.box.tx, wrap:true, margin:'xs' }] : [])
    ]
  };

  // ── หัวการ์ด ──
  const header = isAdmin ? {
    type:'box', layout:'vertical', backgroundColor: BRAND_RED, paddingAll:'0px',
    contents:[
      { type:'box', layout:'vertical', height:'6px', backgroundColor: BRAND_RED_DARK, contents:[{ type:'filler' }] },
      { type:'box', layout:'horizontal', paddingAll:'lg', alignItems:'center',
        contents:[
          { type:'text', text: conf.title, size:'md', color:'#ffffff', weight:'bold', flex:1 },
          { type:'box', layout:'vertical', backgroundColor: BRAND_GOLD, cornerRadius:'999px',
            paddingTop:'3px', paddingBottom:'3px', paddingStart:'10px', paddingEnd:'10px',
            contents:[ { type:'text', text:`#${order_id}`, size:'xxs', color:'#3d2c00', weight:'bold' } ]
          }
        ]
      },
      { type:'box', layout:'vertical', height:'3px', backgroundColor: BRAND_GOLD, contents:[{ type:'filler' }] }
    ]
  } : {
    type:'box', layout:'vertical', backgroundColor: BRAND_RED, paddingAll:'0px',
    contents:[
      { type:'box', layout:'vertical', height:'6px', backgroundColor: BRAND_RED_DARK, contents:[{ type:'filler' }] },
      { type:'box', layout:'vertical', paddingAll:'lg',
        contents:[
          { type:'box', layout:'horizontal', alignItems:'center',
            contents:[
              { type:'box', layout:'horizontal', alignItems:'center', spacing:'md', flex:1,
                contents:[
                  { type:'box', layout:'vertical', width:'30px', height:'30px',
                    cornerRadius:'999px', backgroundColor:'#ffffff',
                    justifyContent:'center', alignItems:'center',
                    contents:[ { type:'text', text:'★', size:'md', color: BRAND_RED, align:'center' } ]
                  },
                  { type:'text', text:'MONSHIN SUPPLY', size:'xxs', color: BRAND_GOLD_SOFT, weight:'bold', flex:1 }
                ]
              },
              { type:'text', text:`#${order_id}`, size:'xxs', color: BRAND_GOLD_PALE, align:'end' }
            ]
          },
          { type:'text', text:'การชำระเงิน', color:'#ffffff', size:'sm', margin:'md' },
          { type:'box', layout:'vertical', margin:'sm',
            contents:[
              { type:'box', layout:'horizontal',
                backgroundColor:'#ffffff', cornerRadius:'999px',
                paddingTop:'6px', paddingBottom:'6px', paddingStart:'14px', paddingEnd:'14px',
                justifyContent:'center',
                contents:[
                  { type:'text', text: conf.badge, size:'md', color: conf.badgeColor, weight:'bold', align:'center' }
                ]
              }
            ]
          }
        ]
      },
      { type:'box', layout:'vertical', height:'3px', backgroundColor: BRAND_GOLD, contents:[{ type:'filler' }] }
    ]
  };

  const altText = isAdmin
    ? `${conf.title} #${order_id} — โอน ${paidStr} / ออเดอร์ ${expectedStr}`
    : `${conf.badge} — ออเดอร์ #${order_id}`;

  return {
    type:'flex',
    altText,
    contents:{
      type:'bubble',
      header,
      body:{
        type:'box', layout:'vertical', spacing:'sm', paddingAll:'lg',
        contents:[
          ...amountRows,
          resultBox,
          ...(!isAdmin && conf.note ? [{ type:'text', text: conf.note, size:'xs', color: BRAND_GOLD_TXT, align:'center', margin:'md' }] : [])
        ]
      }
    }
  };
}

// Flex: ข้อความจากร้าน (chat)
function buildChatFlex(order, text) {
  return {
    type:'flex',
    altText: `💬 ข้อความจากร้าน: ${text.slice(0,80)}`,
    contents: {
      type:'bubble',
      header: {
        type:'box', layout:'vertical',
        backgroundColor:'#C0392B',
        paddingAll:'md',
        contents:[
          { type:'text', text:'💬 ข้อความจากร้าน', color:'#ffffff', size:'sm', weight:'bold' },
          ...(order?.order_id && !String(order.order_id).startsWith('LINE-')
              ? [{ type:'text', text:`#${order.order_id}`, color:'#ffffff', size:'xs', margin:'xs' }]
              : [])
        ]
      },
      body: {
        type:'box', layout:'vertical', paddingAll:'lg',
        contents: [
          { type:'text', text: text.slice(0, 1500), size:'sm', color:'#333333', wrap:true }
        ]
      },
      footer: {
        type:'box', layout:'vertical', paddingAll:'lg', paddingTop:'none',
        contents: [
          { type:'button', style:'primary', color:'#C0392B', height:'sm',
            action:{ type:'uri', label:'💬 ตอบในเว็บ', uri: SHOP_URL }
          }
        ]
      }
    }
  };
}

// หา line_user_id ของ customer (จากออเดอร์ใดๆ ของเขาที่ผูกบัญชีแล้ว)
async function findLineUserIdByCustomer(customerId) {
  if (!customerId) return null;
  const { data } = await supabase.from('orders')
    .select('line_user_id')
    .eq('customer_id', customerId)
    .not('line_user_id', 'is', null)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  return data?.line_user_id || null;
}

// ─── LINE Auto-Link System ─────────────────────────────────
// เก็บ token แบบ in-memory (อายุสั้น 30 นาที — กันคนแอบใช้ของคนอื่น)
const linkTokens = new Map(); // token → { lineUserId, expiresAt }

function genLinkToken() {
  // 24-char random string
  return 'L' + Math.random().toString(36).slice(2, 12) +
         Math.random().toString(36).slice(2, 14);
}

function createLinkToken(lineUserId) {
  const token = genLinkToken();
  linkTokens.set(token, {
    lineUserId,
    expiresAt: Date.now() + 30 * 60 * 1000  // 30 นาที
  });
  // cleanup expired tokens (เก็บ map ไม่ให้บวม)
  if (linkTokens.size > 1000) {
    const now = Date.now();
    for (const [k, v] of linkTokens) {
      if (v.expiresAt < now) linkTokens.delete(k);
    }
  }
  return token;
}

function consumeLinkToken(token) {
  const entry = linkTokens.get(token);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    linkTokens.delete(token);
    return null;
  }
  // ใช้ครั้งเดียวแล้วลบ (one-time use)
  linkTokens.delete(token);
  return entry.lineUserId;
}

// ═══════════════════════════════════════════════════════════
//  📍 GPS PIN EXTRACTOR — แกะพิกัดจากข้อความ
// ═══════════════════════════════════════════════════════════

function isValidLatLng(lat, lng) {
  return Number.isFinite(lat) && Number.isFinite(lng)
    && lat >= -90  && lat <= 90
    && lng >= -180 && lng <= 180
    && !(lat === 0 && lng === 0);            // กัน "0,0" กลางมหาสมุทร
}

/**
 * ดึงพิกัด lat/lng จากข้อความ — รองรับฟอร์แมตที่หน้าร้านเดิมส่งมา:
 *   • Google Maps URL: maps.google.com/?q=19.91,99.84
 *   • Google Maps URL: google.com/maps/search/?api=1&query=19.91,99.84
 *   • Google Maps URL: google.com/maps/dir/?api=1&destination=19.91,99.84
 *   • Google Maps path: /@19.91,99.84,17z
 *   • พิกัดดิบ: "19.910500, 99.840600"  หรือ  "พิกัด: 19.91, 99.84"
 *
 * ⚠️ ไม่รองรับ shortened URL (maps.app.goo.gl/xxx, goo.gl/maps/xxx)
 *    เพราะต้อง follow redirect — ให้หน้าร้านส่ง mapLat/mapLng แยกแทน
 */
function extractCoordsFromText(text) {
  if (!text) return null;
  const s = String(text);

  // Pattern 1: Google Maps URL (q=, query=, destination=, /@)
  const urlPatterns = [
    /[?&](?:q|query|destination|ll)=(-?\d{1,3}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)/i,
    /\/@(-?\d{1,3}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)/,
  ];
  for (const re of urlPatterns) {
    const m = s.match(re);
    if (m) {
      const lat = +m[1], lng = +m[2];
      if (isValidLatLng(lat, lng)) return { lat, lng };
    }
  }

  // Pattern 2: พิกัดดิบ "lat, lng" (ต้องมีจุดทศนิยมอย่างน้อย 3 หลัก กันสับสนกับยอดเงิน/เบอร์โทร)
  const plain = s.match(/(-?\d{1,2}\.\d{3,})\s*[,， ]\s*(-?\d{1,3}\.\d{3,})/);
  if (plain) {
    const lat = +plain[1], lng = +plain[2];
    if (isValidLatLng(lat, lng)) return { lat, lng };
  }

  return null;
}

// ═══════════════════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════════════════

app.get('/api', (req, res) => res.json({
  status   : 'ok',
  service  : 'Maejai Shop Backend v3',
  supabase : process.env.SUPABASE_URL ? '✅' : '❌',
  lineToken: process.env.LINE_TOKEN  ? '✅' : '❌'
}));

// ═══════════════════════════════════════════════════════════
//  🔐 LINE LOGIN — สำหรับเปิดเว็บจากภายนอก (Facebook Ad ฯลฯ)
// ═══════════════════════════════════════════════════════════
// ต้องตั้ง env:
//   LINE_LOGIN_CHANNEL_ID     — Channel ID จาก LINE Login Channel
//   LINE_LOGIN_CHANNEL_SECRET — Channel Secret จาก LINE Login Channel
//   BACKEND_URL               — URL ของ backend นี้ เช่น https://xxx.onrender.com

const LINE_LOGIN_CHANNEL_ID     = process.env.LINE_LOGIN_CHANNEL_ID     || '';
const LINE_LOGIN_CHANNEL_SECRET = process.env.LINE_LOGIN_CHANNEL_SECRET || '';

// สร้าง state สำหรับ CSRF — เก็บใน Map (expire 10 นาที)
const loginStateMap = new Map();
function genLoginState() {
  const state = 'S' + Math.random().toString(36).slice(2, 18);
  loginStateMap.set(state, { expiresAt: Date.now() + 10 * 60 * 1000 });
  return state;
}
function verifyLoginState(state) {
  const entry = loginStateMap.get(state);
  if (!entry) return false;
  loginStateMap.delete(state);
  return entry.expiresAt > Date.now();
}

// ── GET /line-login ───────────────────────────────────────
// เริ่ม flow: redirect ไปหน้า LINE ขออนุญาต
app.get('/line-login', (req, res) => {
  if (!LINE_LOGIN_CHANNEL_ID) {
    return res.status(500).send('LINE_LOGIN_CHANNEL_ID ยังไม่ได้ตั้งค่า');
  }
  const backendUrl = (process.env.BACKEND_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
  const redirectUri = encodeURIComponent(`${backendUrl}/line-login/callback`);
  const state       = genLoginState();
  const scope       = 'profile%20openid';
  const botBasicId  = process.env.LINE_OA_ID || process.env.LINE_OA_BASIC_ID || '@monshin';
  const url = `https://access.line.me/oauth2/v2.1/authorize?response_type=code&client_id=${LINE_LOGIN_CHANNEL_ID}&redirect_uri=${redirectUri}&state=${state}&scope=${scope}&bot_prompt=aggressive&bot_basic_id=${encodeURIComponent(botBasicId)}`;
  res.redirect(url);
});

// ── GET /line-login/callback ──────────────────────────────
// LINE redirect กลับมาพร้อม ?code=...&state=...
app.get('/line-login/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(`${SHOP_URL.replace(/\/$/, '')}?login_error=cancelled`);
  }
  if (!verifyLoginState(state)) {
    return res.redirect(`${SHOP_URL.replace(/\/$/, '')}?login_error=invalid_state`);
  }
  if (!code) {
    return res.redirect(`${SHOP_URL.replace(/\/$/, '')}?login_error=no_code`);
  }

  try {
    const backendUrl  = (process.env.BACKEND_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
    const redirectUri = `${backendUrl}/line-login/callback`;

    // แลก code → access token
    const tokenRes = await fetch('https://api.line.me/oauth2/v2.1/token', {
      method : 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body   : new URLSearchParams({
        grant_type   : 'authorization_code',
        code,
        redirect_uri : redirectUri,
        client_id    : LINE_LOGIN_CHANNEL_ID,
        client_secret: LINE_LOGIN_CHANNEL_SECRET,
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('ไม่ได้รับ access_token');

    // ดึง profile
    const profileRes = await fetch('https://api.line.me/v2/profile', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
    });
    const profile = await profileRes.json();
    const lineUserId = profile.userId;
    if (!lineUserId) throw new Error('ไม่ได้รับ userId');

    // upsert ลง Supabase (เหมือนระบบ LIFF เดิม)
    upsertLineUser(lineUserId).catch(() => {});

    // สร้าง link token แล้ว redirect ไปหน้าเพิ่มเพื่อน LINE OA ก่อน แล้วค่อยไปร้าน
    const token    = createLinkToken(lineUserId);
    const shopUrl  = SHOP_URL.replace(/\/$/, '');
    const backendUrl2 = (process.env.BACKEND_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
    const lineOaBasicId = process.env.LINE_OA_ID || process.env.LINE_OA_BASIC_ID || '@monshin';
    const shopTarget = `${shopUrl}?lid=${token}`;

    // ตรวจสอบว่าลูกค้าเป็นเพื่อนกับ LINE OA แล้วหรือยัง
    let isFriend = false;
    try {
      const friendRes = await fetch(`https://api.line.me/v2/bot/profile/${lineUserId}`, {
        headers: { 'Authorization': `Bearer ${process.env.LINE_TOKEN}` }
      });
      isFriend = friendRes.ok; // ถ้าดึงโปรไฟล์ได้ = เป็นเพื่อนแล้ว
    } catch(e) { isFriend = false; }

    if (isFriend) {
      // เป็นเพื่อนแล้ว → ไปร้านเลย
      res.redirect(shopTarget);
    } else {
      // ยังไม่ได้เพิ่มเพื่อน → แสดงหน้ากลางให้เพิ่มเพื่อนก่อน
      const lineAddUrl = `https://line.me/R/ti/p/${encodeURIComponent(lineOaBasicId)}`;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(`<!DOCTYPE html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>เพิ่มเพื่อน LINE OA</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      background: #fff8f0;
      font-family: 'Sarabun', sans-serif;
      padding: 24px;
    }
    .card {
      background: #fff;
      border-radius: 20px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.08);
      padding: 36px 28px;
      max-width: 400px;
      width: 100%;
      text-align: center;
    }
    .icon { font-size: 56px; margin-bottom: 12px; }
    .title {
      font-size: 20px;
      font-weight: 700;
      color: #2C3E50;
      margin-bottom: 8px;
    }
    .desc {
      font-size: 14px;
      color: #666;
      line-height: 1.6;
      margin-bottom: 28px;
    }
    .desc strong { color: #C0392B; }
    .btn-add {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      background: #06C755;
      color: #fff;
      font-size: 16px;
      font-weight: 700;
      border: none;
      border-radius: 12px;
      padding: 14px 24px;
      width: 100%;
      cursor: pointer;
      text-decoration: none;
      margin-bottom: 12px;
    }
    .btn-skip {
      display: block;
      font-size: 13px;
      color: #aaa;
      text-decoration: underline;
      cursor: pointer;
      background: none;
      border: none;
      width: 100%;
      padding: 8px;
    }
    .benefit {
      background: #f0fff4;
      border: 1px solid #c3e6cb;
      border-radius: 10px;
      padding: 14px;
      margin-bottom: 24px;
      text-align: left;
    }
    .benefit p {
      font-size: 13px;
      color: #333;
      margin-bottom: 4px;
    }
    .benefit p:last-child { margin-bottom: 0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">💚</div>
    <div class="title">เพิ่มเพื่อน LINE OA</div>
    <div class="desc">เพื่อรับการแจ้งเตือนออเดอร์และติดต่อกับร้านได้สะดวก</div>

    <div class="benefit">
      <p>✅ รับสรุปออเดอร์ทันทีหลังสั่งซื้อ</p>
      <p>✅ แจ้งเตือนสถานะ จัดส่ง เสร็จสิ้น</p>
      <p>✅ ติดต่อร้านได้โดยตรงผ่าน LINE</p>
      <p>✅ รับโปรโมชั่นและส่วนลดพิเศษ</p>
    </div>

    <a class="btn-add" href="${lineAddUrl}" onclick="addAndGo()">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="white">
        <path d="M19.365 9.863c.349 0 .63.285.63.631 0 .345-.281.63-.63.63H17.61v1.125h1.755c.349 0 .63.283.63.63 0 .344-.281.629-.63.629h-2.386c-.345 0-.627-.285-.627-.629V8.108c0-.345.282-.63.627-.63h2.386c.349 0 .63.285.63.63 0 .349-.281.63-.63.63H17.61v1.125h1.755zm-3.855 3.016c0 .27-.174.51-.432.596-.064.021-.133.031-.199.031-.211 0-.391-.09-.51-.25l-2.443-3.317v2.94c0 .344-.279.629-.631.629-.346 0-.626-.285-.626-.629V8.108c0-.27.173-.51.43-.595.06-.023.136-.033.194-.033.195 0 .375.104.495.254l2.462 3.33V8.108c0-.345.282-.63.63-.63.345 0 .63.285.63.63v4.771zm-5.741 0c0 .344-.282.629-.631.629-.345 0-.627-.285-.627-.629V8.108c0-.345.282-.63.627-.63.349 0 .631.285.631.63v4.771zm-2.466.629H4.917c-.345 0-.63-.285-.63-.629V8.108c0-.345.285-.63.63-.63.348 0 .63.285.63.63v4.141h1.756c.348 0 .629.283.629.63 0 .344-.281.629-.629.629M24 10.314C24 4.943 18.615.572 12 .572S0 4.943 0 10.314c0 4.811 4.27 8.842 10.035 9.608.391.082.923.258 1.058.59.12.301.079.766.038 1.08l-.164 1.02c-.045.301-.24 1.186 1.049.645 1.291-.539 6.916-4.078 9.436-6.975C23.176 14.393 24 12.458 24 10.314"/>
      </svg>
      เพิ่มเพื่อน LINE OA ของร้าน
    </a>


  </div>

  <script>
    function addAndGo() {
      // หลังกดเพิ่มเพื่อน รอ 2 วินาทีแล้วไปร้าน
      setTimeout(() => {
        window.location.href = '${shopTarget}';
      }, 2000);
    }
    // ถ้าผู้ใช้กลับมาจาก LINE แล้วหน้านี้ยังเปิดอยู่ → ไปร้านเลย
    window.addEventListener('focus', () => {
      setTimeout(() => {
        window.location.href = '${shopTarget}';
      }, 500);
    });
  </script>
</body>
</html>`);
    }

  } catch (e) {
    console.error('LINE Login callback error:', e.message);
    res.redirect(`${SHOP_URL.replace(/\/$/, '')}?login_error=server_error`);
  }
});

// ── GET /line-login/page ──────────────────────────────────
// หน้า Landing Page สำหรับยิงแอด Facebook — มีปุ่ม "เข้าสู่ระบบด้วย LINE"
// ── GET /go — 🎯 ลิงก์สำหรับยิงแอด (Facebook/TikTok/IG) แบบเด้งน้อยที่สุด ──
// มือถือ: เด้งเข้าแอป LINE → หน้าเพิ่มเพื่อน OA ทันที (1 jump!)
//   → พอเพิ่มเพื่อน บอทส่งลิงก์ร้าน (พร้อม token ผูกตัวตน) ให้ในแชทอัตโนมัติ
//   → ลูกค้าแตะลิงก์เดียวถึงร้าน แบบระบบจำตัวตนได้เลย ไม่มีหน้า login ใด ๆ
// คอมพิวเตอร์: ไปหน้า /line-login/page ตามเดิม (เพราะเปิดแอป LINE ไม่ได้)
// ตั้งค่า (ถ้ามี): env LINE_ADD_FRIEND_URL = ลิงก์ lin.ee จากหน้าแอดมิน LINE OA
app.get('/go', (req, res) => {
  const backendUrl = (process.env.BACKEND_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
  const oaId = process.env.LINE_OA_ID || process.env.LINE_OA_BASIC_ID || '@monshin';
  const addFriendUrl = process.env.LINE_ADD_FRIEND_URL || `https://line.me/R/ti/p/${encodeURIComponent(oaId)}`;
  const ua = String(req.headers['user-agent'] || '');
  const isMobile = /android|iphone|ipad|ipod|mobile/i.test(ua);
  const isAndroid = /android/i.test(ua);
  // Facebook / Instagram / Messenger in-app browser — เบราว์เซอร์ในตัวของแอปเหล่านี้
  // จงใจบล็อกการ redirect อัตโนมัติออกไปเปิดแอปอื่น (เช่น LINE) ด้วยเหตุผลด้าน tracking/privacy ของตัวเขาเอง
  const isInAppWebview = /FBAN|FBAV|FB_IAB|FBSV|Instagram|Messenger/i.test(ua);

  if (isMobile && isInAppWebview) {
    return res.send(renderInAppEscapePage({ addFriendUrl, isAndroid, inApp: true }));
  }
  // มือถือ (เบราว์เซอร์ปกติ เช่น Safari/Chrome): เสิร์ฟหน้า landing แล้วเด้งเข้า LINE อัตโนมัติ
  // ❌ ไม่ใช้ res.redirect ตรง ๆ อีกต่อไป — เพราะ browser จะค้างที่ line.me (หน้าตาย)
  //    พอลูกค้าสลับแอปกลับมาจะเจอ "ไม่พบเพจ" และกดอะไรต่อไม่ได้เลย
  // ✅ วิธีนี้: หน้าเราค้างอยู่ที่โดเมนเราเสมอ กลับมาเมื่อไหร่ก็กดปุ่มเข้า LINE ซ้ำได้ตลอด
  if (isMobile) {
    return res.send(renderInAppEscapePage({ addFriendUrl, isAndroid, inApp: false }));
  }
  return res.redirect(`${backendUrl}/line-login/page`);
});

// ── หน้าคั่นสำหรับ escape ออกจาก in-app browser ของ Facebook/IG/Messenger ──
// Android: ลองยิง intent:// ให้ระบบ Android เปิด Chrome เอง (หลุดจาก webview ได้จริง เพราะ OS เป็นคนจัดการ ไม่ใช่ตัว webview)
//          ถ้าเปิด Chrome ได้ Chrome จะสานต่อ App Link ไปเปิด LINE ให้เองอัตโนมัติ
// iOS: Apple/FB คุมเข้มกว่ามาก ไม่มีวิธี auto-escape ที่เชื่อถือได้ 100% — แสดงคำแนะนำให้กดเปิดในเบราว์เซอร์ภายนอกแทน
function renderInAppEscapePage({ addFriendUrl, isAndroid, inApp }) {
  let intentUrl = '';
  try {
    const u = new URL(addFriendUrl);
    intentUrl = `intent://${u.host}${u.pathname}${u.search}#Intent;scheme=https;package=com.android.chrome;end`;
  } catch (_) {}
  const title = inApp ? 'กำลังเปิดจาก Facebook/Instagram' : 'เปิดร้านผ่าน LINE';
  const desc  = inApp
    ? 'แอปนี้บล็อกไม่ให้เด้งเข้า LINE อัตโนมัติ — แตะปุ่มด้านล่างเพื่อลองอีกครั้ง หรือทำตามขั้นตอนถ้ายังไม่เข้า'
    : 'แตะปุ่มด้านล่างเพื่อเปิดแอป LINE และเพิ่มเพื่อนร้านเรา';

  return `<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>มนชิน ซัพพลาย — เปิดใน LINE</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    background: #fff8f0; font-family: 'Sarabun', sans-serif; padding: 24px;
  }
  .card {
    background: #fff; border-radius: 20px; box-shadow: 0 4px 24px rgba(0,0,0,0.08);
    padding: 36px 28px; max-width: 400px; width: 100%; text-align: center;
  }
  .logo { font-size: 44px; margin-bottom: 10px; }
  .title { font-size: 19px; font-weight: 700; color: #C0392B; margin-bottom: 8px; }
  .desc { font-size: 14px; color: #666; line-height: 1.7; margin-bottom: 22px; }
  .btn-line {
    display: flex; align-items: center; justify-content: center; gap: 8px;
    background: #06C755; color: #fff; font-size: 15px; font-weight: 700;
    border: none; border-radius: 12px; padding: 14px; text-decoration: none;
    margin-bottom: 18px;
  }
  .steps { text-align: left; font-size: 13px; color: #444; background: #fff8e6;
    border: 1px solid #f0dfa8; border-radius: 10px; padding: 14px 16px; line-height: 1.9; }
  .steps b { color: #7E1610; }
  .menu-dots { display:inline-block; font-weight:900; font-size:16px; background:#eee; border-radius:6px; padding:0 6px; }
</style>
</head>
<body>
  <div class="card">
    <div class="logo">💬</div>
    <div class="title">${title}</div>
    <div class="desc">${desc}</div>
    <div id="afterBox" style="display:none;background:#e8f7ee;border:1px solid #bfe0c8;border-radius:10px;padding:12px 14px;margin-bottom:16px;text-align:left;font-size:13px;color:#1f5c38;line-height:1.8;">
      ✅ <b>ถ้าเพิ่มเพื่อนเรียบร้อยแล้ว</b><br>
      ระบบส่ง<b>ลิงก์เข้าร้าน</b>ให้ในแชท LINE แล้วค่ะ<br>
      เปิดแอป LINE → แชท "มนชิน ซัพพลาย" → แตะลิงก์ได้เลย 🛍️
    </div>
    <a class="btn-line" id="tryBtn" href="${addFriendUrl}" onclick="return handleTryClick(event)">➕ เพิ่มเพื่อน LINE ตอนนี้</a>
    <div class="steps" id="stepsBox" ${inApp ? '' : 'style="display:none;"'}>
      <b>ถ้ากดแล้วไม่เข้า LINE:</b><br>
      1. แตะเมนู <span class="menu-dots">⋮</span> หรือ <span class="menu-dots">•••</span> มุมขวาบนของหน้าจอ<br>
      2. เลือก <b>"เปิดในเบราว์เซอร์"</b> (Open in Browser / Chrome / Safari)<br>
      3. เมื่อเปิดในเบราว์เซอร์แล้ว ลิงก์จะพาไปหน้า LINE ให้อัตโนมัติ
    </div>
  </div>
  <script>
    var _isAndroid = ${JSON.stringify(!!isAndroid)};
    var _intentUrl = ${JSON.stringify(intentUrl)};
    var _inApp     = ${JSON.stringify(!!inApp)};
    var _tapped    = false;
    // สำคัญ: ใน in-app browser ของ Facebook/IG ไม่ auto-redirect ตอนโหลดหน้าโดยเด็ดขาด —
    // Facebook แฟล็ก/บล็อกลิงก์ที่ redirect เองโดยไม่มีการกดของผู้ใช้
    // ต้องรอให้ผู้ใช้แตะปุ่มเองก่อนเสมอ ถึงจะปลอดภัยจากการโดนบล็อก
    function handleTryClick(e) {
      _tapped = true;
      if (_isAndroid && _intentUrl && _inApp) {
        e.preventDefault();
        window.location.href = _intentUrl;
      }
      return true; // เบราว์เซอร์ปกติ/iOS: ปล่อยให้ href ทำงาน (universal link เด้งเข้าแอป LINE เอง)
    }
    // 🔁 ลูกค้าสลับแอปกลับมาที่หน้านี้ (หลังไป LINE) → หน้าเรายังอยู่ ไม่ใช่หน้า error
    //    โชว์กล่องบอกทางต่อ + ปุ่มยังกดซ้ำได้เสมอ
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'visible' && _tapped) {
        var b = document.getElementById('afterBox');
        if (b) b.style.display = 'block';
        var btn = document.getElementById('tryBtn');
        if (btn) btn.textContent = '🔁 เปิด LINE อีกครั้ง';
      }
    });
  </script>
</body>
</html>`;
}

app.get('/line-login/page', (req, res) => {
  const backendUrl = (process.env.BACKEND_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>มนชิน ซัพพลาย — เข้าสู่ระบบ</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      background: #fff8f0;
      font-family: 'Sarabun', sans-serif;
      padding: 24px;
    }
    .card {
      background: #fff;
      border-radius: 20px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.08);
      padding: 40px 32px;
      max-width: 400px;
      width: 100%;
      text-align: center;
    }
    .logo { font-size: 48px; margin-bottom: 12px; }
    .shop-name {
      font-size: 22px;
      font-weight: 700;
      color: #C0392B;
      margin-bottom: 6px;
    }
    .tagline {
      font-size: 14px;
      color: #888;
      margin-bottom: 32px;
    }
    .btn-line {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      background: #06C755;
      color: #fff;
      font-size: 16px;
      font-weight: 600;
      border: none;
      border-radius: 12px;
      padding: 14px 24px;
      width: 100%;
      cursor: pointer;
      text-decoration: none;
      transition: background 0.2s;
    }
    .btn-line:hover { background: #05b04a; }
    .btn-line svg { flex-shrink: 0; }
    .divider {
      display: flex;
      align-items: center;
      gap: 12px;
      margin: 20px 0;
      color: #ccc;
      font-size: 13px;
    }
    .divider::before, .divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: #eee;
    }
    .btn-guest {
      display: block;
      width: 100%;
      padding: 13px;
      border: 1.5px solid #ddd;
      border-radius: 12px;
      background: transparent;
      color: #666;
      font-size: 15px;
      cursor: pointer;
      text-decoration: none;
      transition: border-color 0.2s;
    }
    .btn-guest:hover { border-color: #C0392B; color: #C0392B; }
    .note {
      margin-top: 24px;
      font-size: 12px;
      color: #bbb;
      line-height: 1.6;
    }
    .error-msg {
      background: #fff0f0;
      border: 1px solid #f5c2c2;
      border-radius: 8px;
      color: #C0392B;
      font-size: 13px;
      padding: 10px 14px;
      margin-bottom: 20px;
      display: none;
    }
    .error-msg.show { display: block; }
  </style>
</head>
<body>
  <div class="card">
    <img src="data:image/png;base64,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" alt="logo" style="width:80px;height:80px;object-fit:contain;border-radius:12px;margin-bottom:12px;">
    <div class="shop-name">มนชิน ซัพพลาย</div>
    <div class="tagline">เข้าสู่ระบบเพื่อเริ่มสั่งซื้อสินค้า</div>

    <div class="error-msg" id="errMsg"></div>

    <!-- 🚀 ทางหลัก (มือถือ): เด้งเข้าแอป LINE → เพิ่มเพื่อน → บอทส่งลิงก์ร้านให้ทันที -->
    <a class="btn-line" id="btnAddFriend" href="${process.env.LINE_ADD_FRIEND_URL || `https://line.me/R/ti/p/${encodeURIComponent(process.env.LINE_OA_ID || process.env.LINE_OA_BASIC_ID || '@monshin')}`}">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="white">
        <path d="M19.365 9.863c.349 0 .63.285.63.631 0 .345-.281.63-.63.63H17.61v1.125h1.755c.349 0 .63.283.63.63 0 .344-.281.629-.63.629h-2.386c-.345 0-.627-.285-.627-.629V8.108c0-.345.282-.63.627-.63h2.386c.349 0 .63.285.63.63 0 .349-.281.63-.63.63H17.61v1.125h1.755zm-3.855 3.016c0 .27-.174.51-.432.596-.064.021-.133.031-.199.031-.211 0-.391-.09-.51-.25l-2.443-3.317v2.94c0 .344-.279.629-.631.629-.346 0-.626-.285-.626-.629V8.108c0-.27.173-.51.43-.595.06-.023.136-.033.194-.033.195 0 .375.104.495.254l2.462 3.33V8.108c0-.345.282-.63.63-.63.345 0 .63.285.63.63v4.771zm-5.741 0c0 .344-.282.629-.631.629-.345 0-.627-.285-.627-.629V8.108c0-.345.282-.63.627-.63.349 0 .631.285.631.63v4.771zm-2.466.629H4.917c-.345 0-.63-.285-.63-.629V8.108c0-.345.285-.63.63-.63.348 0 .63.285.63.63v4.141h1.756c.348 0 .629.283.629.63 0 .344-.281.629-.629.629M24 10.314C24 4.943 18.615.572 12 .572S0 4.943 0 10.314c0 4.811 4.27 8.842 10.035 9.608.391.082.923.258 1.058.59.12.301.079.766.038 1.08l-.164 1.02c-.045.301-.24 1.186 1.049.645 1.291-.539 6.916-4.078 9.436-6.975C23.176 14.393 24 12.458 24 10.314"/>
      </svg>
      เปิดร้านผ่าน LINE (แตะเดียว)
    </a>
    <p style="font-size:12px;color:#888;margin-top:8px;line-height:1.6;">
      กด "เพิ่มเพื่อน" ในแอป LINE แล้วระบบจะส่ง<br><b style="color:#C0392B;">ลิงก์เข้าร้าน</b>ให้ในแชททันที ✨
    </p>

    <div class="divider">หรือ (สำหรับคอมพิวเตอร์)</div>

    <a class="btn-line" style="background:#fff;color:#06C755;border:1.5px solid #06C755;" href="${backendUrl}/line-login">
      เข้าสู่ระบบด้วย LINE บนเบราว์เซอร์
    </a>

    <p class="note">
      เมื่อล็อกอินด้วย LINE ระบบจะบันทึกประวัติการสั่งซื้อ<br>และแจ้งเตือนสถานะออเดอร์ผ่าน LINE โดยอัตโนมัติ
    </p>
  </div>

  <script>
    // แสดง error ถ้า redirect กลับมาพร้อม ?login_error=
    const params = new URLSearchParams(window.location.search);
    const err = params.get('login_error');
    if (err) {
      const msgs = {
        cancelled   : 'คุณยกเลิกการเข้าสู่ระบบ',
        invalid_state: 'Session หมดอายุ กรุณาลองใหม่',
        no_code     : 'เกิดข้อผิดพลาด กรุณาลองใหม่',
        server_error: 'เซิร์ฟเวอร์มีปัญหา กรุณาลองใหม่ภายหลัง',
      };
      const el = document.getElementById('errMsg');
      el.textContent = msgs[err] || 'เกิดข้อผิดพลาด: ' + err;
      el.classList.add('show');
    }
  </script>
</body>
</html>`);
});

// ── GET /liff-entry ───────────────────────────────────────
// Endpoint สำหรับ LIFF App — ตั้ง Endpoint URL ใน LINE Developers Console ชี้มาที่นี่
// Rich Menu ตั้ง URL: https://liff.line.me/{LIFF_ID}
// LIFF SDK จะดึง LINE UID ให้อัตโนมัติ แล้วส่งมาที่นี่ผ่าน query string
// → ระบบสร้าง token + redirect ไปหน้าร้านพร้อม ?lid=TOKEN
// → หน้าร้านเรียก /link-line อัตโนมัติ → ผูกบัญชีเสร็จ ไม่ต้องพิมพ์อะไรเลย
app.get('/liff-entry', (req, res) => {
  const shopUrl = SHOP_URL.replace(/\/$/, '');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>กำลังเปิดร้าน...</title>
  <script src="https://static.line-scdn.net/liff/edge/versions/2.22.3/sdk.js"></script>
  <style>
    body { margin:0; display:flex; flex-direction:column; align-items:center;
           justify-content:center; min-height:100vh; font-family:sans-serif;
           background:#fff8f0; color:#333; }
    .spinner { width:48px; height:48px; border:5px solid #eee;
               border-top-color:#c0392b; border-radius:50%;
               animation:spin .8s linear infinite; margin-bottom:16px; }
    @keyframes spin { to { transform:rotate(360deg); } }
    p { font-size:15px; color:#888; }
  </style>
</head>
<body>
  <div class="spinner"></div>
  <p>กำลังเปิดร้าน...</p>
  <script>
    (async () => {
      try {
        await liff.init({ liffId: '${process.env.LIFF_ID || ''}' });

        // ดึง LINE UID ผ่าน LIFF SDK
        const profile  = await liff.getProfile();
        const lineUid  = profile.userId;

        // ส่ง UID ไปที่ backend เพื่อสร้าง token
        const res = await fetch('/liff-token?uid=' + encodeURIComponent(lineUid));
        const data = await res.json();

        if (data.url) {
          // redirect ไปหน้าร้านพร้อม ?lid=TOKEN
          window.location.replace(data.url);
        } else {
          window.location.replace('${shopUrl}');
        }
      } catch (e) {
        console.error('LIFF error:', e);
        // fallback — เปิดร้านปกติ (ไม่ผูก LINE แต่ยังใช้ได้)
        window.location.replace('${shopUrl}');
      }
    })();
  </script>
</body>
</html>`);
});

// ── GET /liff-token ───────────────────────────────────────
// เรียกจาก /liff-entry — รับ LINE UID แล้วคืน shopLink พร้อม ?lid=TOKEN
app.get('/liff-token', async (req, res) => {
  const lineUserId = req.query.uid;
  if (!lineUserId) return res.status(400).json({ error: 'missing uid' });

  const token    = createLinkToken(lineUserId);
  const shopUrl  = SHOP_URL.replace(/\/$/, '');
  const url      = `${shopUrl}?lid=${token}`;

  // บันทึก line_users เผื่อยังไม่มี record
  upsertLineUser(lineUserId).catch(() => {});

  res.json({ url });
});

// ── POST /send-order ──────────────────────────────────────
app.post('/send-order', async (req, res) => {
  const {
    customerId, customerName, lineName, phone, address, note,
    items, total, orderType, extra,
    mapLat, mapLng,             // 📍 พิกัด GPS
    couponId, discountAmount,    // 🎟️ ส่วนลด/คูปอง
    refCode,                       // 🎁 referral code
    paymentMethod, paymentLabel    // 💳 วิธีชำระเงิน
  } = req.body;

  if (!customerId || !customerName || !items?.length || total == null)
    return res.status(400).json({ error: 'ข้อมูลไม่ครบ (customerId/customerName/items/total)' });

  // 🔒 SECURITY FIX: ตรวจ/คำนวณราคาสินค้าใหม่ฝั่ง server จากตาราง products จริง ไม่เชื่อ
  // items[].price / total ที่ client ส่งมาอีกต่อไป (ดูคำอธิบายเต็มที่ computeVerifiedItemPricing)
  const pricing = await computeVerifiedItemPricing(items);
  if (!pricing.ok) {
    logError('send-order-price-verify', new Error(pricing.reason), { customerId });
    return res.status(400).json({ error: pricing.reason });
  }
  const verifiedItems = pricing.items;
  const verifiedTotal = pricing.verifiedTotal;
  if (Math.abs(verifiedTotal - Number(total)) > 1) {
    console.warn(`⚠️ ยอดที่ client ส่งมา (${total}) ไม่ตรงกับยอดที่คำนวณจริง (${verifiedTotal}) customer=${customerId} — ใช้ยอดที่คำนวณจริงแทน`);
  }

  // ── ตรวจสอบและ apply coupon ────────────────────────────
  let appliedCouponId   = null;
  let appliedCouponCode = null;
  let finalDiscount     = 0;

  if (couponId && discountAmount > 0) {
    const { data: coup } = await supabase
      .from('coupons').select('*').eq('id', couponId).eq('is_active', true).maybeSingle();
    if (coup) {
      if (!coup.usage_limit || coup.used_count < coup.usage_limit) {

        // 🔒 ป้องกันใช้คูปองซ้ำ — เช็คว่า LINE UID หรือเบอร์โทรนี้เคยใช้ไปแล้วหรือยัง
        // (กันลูกค้าเคลียร์ localStorage แล้วสร้าง customer_id ใหม่มาใช้ซ้ำ)
        let alreadyUsedCoupon = false;

        // หา LINE UID ของ customer_id นี้ก่อน (ค้นจาก LINK- row หรือ line_users)
        let lineUidForCoupon = null;
        const linkRowId = `LINK-${customerId.slice(0, 20)}`;
        const { data: linkRow } = await supabase.from('orders')
          .select('line_user_id').eq('order_id', linkRowId)
          .not('line_user_id', 'is', null).maybeSingle();
        if (linkRow?.line_user_id) lineUidForCoupon = linkRow.line_user_id;

        if (!lineUidForCoupon) {
          const { data: luRow } = await supabase.from('line_users')
            .select('user_id').eq('customer_id', customerId)
            .order('last_seen', { ascending: false }).limit(1).maybeSingle();
          if (luRow?.user_id) lineUidForCoupon = luRow.user_id;
        }

        // เช็ค coupon_usages ด้วย LINE UID (แม่นที่สุด)
        if (lineUidForCoupon) {
          const { data: usageByUid } = await supabase.from('coupon_usages')
            .select('id').eq('coupon_id', couponId).eq('line_user_id', lineUidForCoupon)
            .limit(1).maybeSingle();
          if (usageByUid) alreadyUsedCoupon = true;
        }

        // เช็ค coupon_usages ด้วยเบอร์โทร (fallback กรณียังไม่ได้ผูก LINE)
        const normPhone = String(phone || '').replace(/\D/g, '');
        if (!alreadyUsedCoupon && normPhone) {
          const { data: usageByPhone } = await supabase.from('coupon_usages')
            .select('id').eq('coupon_id', couponId).eq('phone', normPhone)
            .limit(1).maybeSingle();
          if (usageByPhone) alreadyUsedCoupon = true;
        }

        if (!alreadyUsedCoupon) {
          // 🔒 SECURITY FIX: เดิม finalDiscount = Math.min(discountAmount, total) เชื่อ
          // discountAmount ที่ client ส่งมาตรงๆ (จำกัดแค่ไม่ให้เกิน total ที่ client ก็ส่งมาเอง
          // เหมือนกัน — ไม่ป้องกันอะไรเลยจริงๆ) ตอนนี้คำนวณส่วนลดใหม่จากกฎคูปองจริง +
          // verifiedTotal เท่านั้น ไม่สนใจ discountAmount จาก client อีกต่อไป
          finalDiscount     = Math.min(calcDiscount(coup, verifiedTotal), verifiedTotal);
          appliedCouponId   = coup.id;
          appliedCouponCode = coup.code;
          await supabase.from('coupons')
            .update({ used_count: (coup.used_count || 0) + 1 })
            .eq('id', coup.id);
          // 🔒 บันทึกการใช้คูปอง — ป้องกันใช้ซ้ำแม้เปลี่ยน customer_id
          await supabase.from('coupon_usages').insert([{
            coupon_id    : coup.id,
            line_user_id : lineUidForCoupon || null,
            phone        : normPhone || null,
            customer_id  : customerId
          }]).then(({ error: e }) => {
            if (e) console.warn('coupon_usages insert failed:', e.message);
          });
        } else {
          console.warn(`🚫 coupon ${coup.code} already used by LINE=${lineUidForCoupon?.slice(0,12)} phone=${normPhone}`);
        }
      }
    }
  }

  const finalTotal = Math.max(0, verifiedTotal - finalDiscount);

  // ── parse + validate พิกัด GPS ──
  // 1) ลองรับจาก mapLat/mapLng ก่อน (ทางที่ดีที่สุด — ส่งแยกฟิลด์)
  // 2) ถ้าไม่มี → auto-extract จาก note/extra/address (รองรับฟอร์แมตเดิมที่ฝังใน text)
  let lat = Number(mapLat);
  let lng = Number(mapLng);
  let hasValidPin = isValidLatLng(lat, lng);

  if (!hasValidPin) {
    const haystack = `${note || ''}\n${extra || ''}\n${address || ''}`;
    const found = extractCoordsFromText(haystack);
    if (found) {
      lat = found.lat;
      lng = found.lng;
      hasValidPin = true;
      console.log(`📍 auto-extracted pin from text: ${lat},${lng}`);
    }
  }

  let order_id     = genOrderId();
  const created_at = new Date().toISOString();

  // ถ้าไม่มี refCode ใน request → ดึงจาก LINK ghost row
  let finalRefCode = refCode || null;
  if (!finalRefCode && customerId) {
    const linkRowId = `LINK-${customerId.slice(0, 20)}`;
    const { data: linkRow } = await supabase.from('orders')
      .select('ref_code').eq('order_id', linkRowId).maybeSingle();
    if (linkRow?.ref_code) {
      finalRefCode = linkRow.ref_code;
      console.log(`💼 ref_code from ghost row: ${finalRefCode}`);
    }
  }

  const order      = {
    order_id, customer_id: customerId,
    customer_name: customerName,
    line_name: lineName || customerName,
    phone: phone || null, address: address || null, note: note || extra || null,
    items: verifiedItems, total: finalTotal, status: 'pending', created_at,
    order_type: orderType || 'pickup',
    map_lat: hasValidPin ? lat : null,
    map_lng: hasValidPin ? lng : null,
    coupon_id: appliedCouponId,
    coupon_code: appliedCouponCode,
    discount_amount: finalDiscount,
    ref_code: finalRefCode,          // 💼 รหัสเซลที่แนะนำ
    payment_method: paymentMethod || null,  // 💳 'cod' หรือ 'transfer'
    payment_label:  paymentLabel  || null,   // 💳 ป้ายแสดง เช่น '🏍️ เก็บปลายทาง'
    payment_status: paymentMethod === 'transfer' ? 'pending_slip' : null,  // 🧾 รอสลิป / paid / confirmed
    slip_url      : null,            // 🧾 URL สลิปที่ลูกค้าส่ง
    slip_amount   : null,            // 🧾 ยอดที่ลูกค้าแจ้ง
  };

  let { error: dbErr } = await supabase.from('orders').insert([order]);
  // กันเหนียว: ถ้าเลขออเดอร์ชน (duplicate key) ให้สุ่มเลขใหม่แล้วลองอีกครั้ง
  if (dbErr && /duplicate|unique/i.test(dbErr.message || '')) {
    order_id = genOrderId();
    order.order_id = order_id;
    const retry = await supabase.from('orders').insert([order]);
    dbErr = retry.error;
  }
  if (dbErr) {
    console.error('DB insert error:', dbErr.message);
    logError('send-order', dbErr, { customerId, total });
    return res.status(500).json({ error: 'บันทึกออเดอร์ไม่ได้: ' + dbErr.message });
  }

  // ✂️ ลด stock ของแต่ละ item (ถ้า products มี stock tracking)
  for (const it of verifiedItems) {
    if (!it.productId || !it.sizeName) continue; // skip ถ้า items เก่าไม่มี productId
    try {
      // ใช้ RPC function ที่สร้างไว้
      await supabase.rpc('deduct_stock', {
        p_product_id: it.productId,
        p_size_name : it.sizeName,
        p_qty       : it.qty
      }).then(({ error }) => {
        if (error) console.warn(`deduct_stock ${it.productId}/${it.sizeName}:`, error.message);
      });
    } catch (e) {
      console.warn('stock deduct skipped:', e.message);
    }
  }

  // บันทึก system message ในแชทลูกค้า — สรุปออเดอร์
  const summaryMsg =
    `🎉 ขอบคุณสำหรับการสั่งซื้อ คุณ ${customerName}\n\n` +
    `📦 ออเดอร์ #${order_id}\n` +
    verifiedItems.map(i => `• ${i.emoji||''} ${i.name} ×${i.qty} = ฿${(i.qty*i.price).toLocaleString()}`).join('\n') +
    (finalDiscount > 0 ? `\n🎟️ ส่วนลด: -฿${finalDiscount.toLocaleString()}` : '') +
    `\n\n💰 ยอดรวม: ฿${finalTotal.toLocaleString()}\n` +
    `\nร้านจะยืนยันและแจ้งสถานะให้ทราบเร็วๆ นี้ค่ะ 🙏` +
    await (async () => {
      try {
        const { data } = await supabase.from('settings').select('value').eq('key','shop_hours').maybeSingle();
        if (!data || !data.value || !data.value.enabled) return '';
        const cfg = data.value;
        const bkkStr3 = new Date().toLocaleString('en-US', { timeZone: 'Asia/Bangkok' });
        const now = new Date(bkkStr3);
        const day = now.getDay();
        const openDays = cfg.openDays || [];
        const [oh,om] = (cfg.openTime||'09:00').split(':').map(Number);
        const [ch,cm] = (cfg.closeTime||'18:00').split(':').map(Number);
        const nowMins = now.getHours()*60+now.getMinutes();
        const isOpen = openDays.includes(day) && nowMins >= oh*60+om && nowMins < ch*60+cm;
        // ถ้าร้านเปิดปกติ ไม่ต้องส่งข้อความแจ้ง
        if (isOpen) return '';
        const msg = cfg.msgClosed || '';
        if (!msg) return '';
        return '\n\n🔴 ' + msg;
      } catch(e) { return ''; }
    })();

  await supabase.from('messages').insert([{
    order_id, customer_id: customerId,
    sender: 'system', text: summaryMsg,
    created_at: new Date().toISOString()
  }]).then(({ error }) => {
    if (error) console.warn('insert summary msg:', error.message);
  });

  // ✨ Auto-link: ผูก line_user_id ให้ออเดอร์ใหม่อัตโนมัติ — 3 วิธีเรียงตามความแม่นยำ
  let autoLinkedLineUid = null;
  try {
    const normPhone = (p) => String(p || '').replace(/\D/g, '');
    const norm = (s) => String(s || '').trim().toLowerCase();
    const myPhone = normPhone(phone);

    // ── วิธีที่ 0 (เร็วและแม่นที่สุด): ค้น LINK-{customerId} row โดยตรง ──
    // /link-line สร้าง row นี้ทันทีที่ลูกค้าเปิดร้านผ่านลิงก์ LINE
    // ไม่ต้องเดา ไม่ต้อง match ชื่อ/phone เลย
    if (!autoLinkedLineUid) {
      const linkRowId = `LINK-${customerId.slice(0, 20)}`;
      const { data: linkRow } = await supabase.from('orders')
        .select('line_user_id')
        .eq('order_id', linkRowId)
        .not('line_user_id', 'is', null)
        .maybeSingle();
      if (linkRow?.line_user_id) {
        autoLinkedLineUid = linkRow.line_user_id;
        console.log(`🔗 auto-linked via LINK- row: ${linkRowId}`);
      }
    }

    // ── วิธีที่ 1: ค้นจาก line_users.customer_id ──
    // บันทึกตอนลูกค้าเปิดร้านผ่านลิงก์ LINE → ผูกได้ทันทีโดยไม่ต้องเดา
    if (!autoLinkedLineUid) {
      const { data: luRow } = await supabase.from('line_users')
        .select('user_id')
        .eq('customer_id', customerId)
        .order('last_seen', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (luRow?.user_id) {
        autoLinkedLineUid = luRow.user_id;
        console.log(`🔗 auto-linked via line_users.customer_id: ${customerId}`);
      }
    }

    // ── วิธีที่ 2: ค้นจาก ghost orders (LINE-% / LINK-%) ด้วย phone + ชื่อ ──
    if (!autoLinkedLineUid) {
      const { data: ghostOrders } = await supabase.from('orders')
        .select('order_id, line_user_id, customer_name, line_name, phone')
        .or('order_id.like.LINE-%,order_id.like.LINK-%')
        .not('line_user_id', 'is', null);

      if (ghostOrders?.length) {
        const myLineName = norm(lineName);
        const myCustName = norm(customerName);
        const matched = ghostOrders.find(g => {
          const gLine = norm(g.line_name);
          const gCust = norm(g.customer_name);
          return (myPhone && normPhone(g.phone) === myPhone) ||
                 (myLineName && gLine && gLine === myLineName) ||
                 (myLineName && gCust && gCust === myLineName) ||
                 (myCustName && gCust && gCust === myCustName);
        });
        if (matched?.line_user_id) {
          autoLinkedLineUid = matched.line_user_id;
          console.log(`🔗 auto-linked via ghost order match: ${matched.order_id}`);
        }
      }
    }

    // ── วิธีที่ 3: ค้นจาก line_users ด้วยเบอร์โทร (ถ้ามี phone column) ──
    if (!autoLinkedLineUid && myPhone) {
      const { data: luPhone } = await supabase.from('line_users')
        .select('user_id')
        .eq('phone', myPhone)
        .order('last_seen', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (luPhone?.user_id) {
        autoLinkedLineUid = luPhone.user_id;
        console.log(`🔗 auto-linked via line_users.phone: ${myPhone}`);
      }
    }

    // ── วิธีที่ 4: ค้นจากออเดอร์เก่าของ customer_id เดียวกัน ──
    // กรณีลูกค้าสั่งซ้ำ — ออเดอร์แรกผูก LINE แล้ว ออเดอร์ถัดไปควรได้ใช้ตาม
    if (!autoLinkedLineUid) {
      const { data: prevOrder } = await supabase.from('orders')
        .select('line_user_id')
        .eq('customer_id', customerId)
        .not('line_user_id', 'is', null)
        .not('order_id', 'like', 'LINE-%')
        .not('order_id', 'like', 'LINK-%')
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (prevOrder?.line_user_id) {
        autoLinkedLineUid = prevOrder.line_user_id;
        console.log(`🔗 auto-linked via previous order of customer: ${customerId}`);
      }
    }

    // ── ผูกสำเร็จ → อัปเดต orders + line_users ──
    if (autoLinkedLineUid) {
      await supabase.from('orders')
        .update({ line_user_id: autoLinkedLineUid })
        .eq('customer_id', customerId)
        .then(({ error }) => { if (!error) console.log(`✅ ${customerId} ↔ LINE ${autoLinkedLineUid.slice(0,12)}…`); });

      // อัปเดต line_users ให้มี customer_id (เพื่อ match ได้เร็วขึ้นครั้งถัดไป)
      await supabase.from('line_users')
        .update({ customer_id: customerId })
        .eq('user_id', autoLinkedLineUid)
        .then(null, () => {});
    }
  } catch (e) {
    console.warn('auto-link failed:', e.message);
  }

  // แจ้งแอดมินทุกคนผ่าน LINE OA
  if (process.env.LINE_TOKEN) {
    try {
      const { sent } = await notifyAllAdmins([{ type: 'text', text: await buildAdminMsg(order) }]);
      if (sent > 0) {
        await supabase.from('orders').update({ status: 'sent' }).eq('order_id', order_id);
        console.log(`✅ ${order_id} → admin LINE (${sent} คน)`);
      }
    } catch (e) {
      console.error(`⚠️ ${order_id} LINE notify failed:`, e.message);
    }
  }

  // ✨ ส่ง Flex Message ออเดอร์สรุปหาลูกค้า (ถ้าเคยผูกบัญชีไว้ หรือเพิ่ง auto-link)
  if (process.env.LINE_TOKEN) {
    const customerLineUid = autoLinkedLineUid || await findLineUserIdByCustomer(customerId);
    if (customerLineUid) {
      const flex = await buildOrderSummaryFlex({ ...order, status: 'sent' });
      linePush(customerLineUid, [flex])
        .then(() => console.log(`📤 order summary → ${customerLineUid.slice(0,12)}…`))
        .catch(e => console.warn('LINE flex to customer failed:', e.message));
    } else {
      console.log(`ℹ️ ${order_id} ลูกค้ายังไม่ได้ผูกบัญชี LINE — จะส่ง flex หลังผูกบัญชี`);
    }
  }

  // ✨ ลบ LINK- ghost row — ออเดอร์จริงมี line_user_id แล้ว ไม่ต้องการ mapping row อีกต่อไป
  supabase.from('orders')
    .delete()
    .eq('order_id', `LINK-${customerId.slice(0, 20)}`)
    .then(({ error: e }) => {
      if (!e) console.log(`🗑️ cleaned up LINK-${customerId.slice(0,10)}… ghost`);
    });

  // ── 🎁 Referral Reward ─────────────────────────────────
  // ถ้ามี refCode และนี่คือออเดอร์แรกของลูกค้า → ให้คูปองกับคนชวน
  if (refCode) {
    try {
      // ตรวจว่าเป็นออเดอร์แรกของลูกค้านี้ไหม (ไม่นับ ghost orders)
      const { data: prevOrders } = await supabase
        .from('orders').select('id').eq('customer_id', customerId)
        .not('order_id', 'like', 'LINE-%').not('order_id', 'like', 'LINK-%')
        .neq('order_id', order_id).limit(1);

      const isFirstOrder = !prevOrders?.length;

      if (isFirstOrder) {
        // หา referral owner
        const { data: ref } = await supabase
          .from('referrals').select('id, customer_id').eq('ref_code', refCode).maybeSingle();

        if (ref && ref.customer_id !== customerId) {
          // ตรวจว่าคนชวนนี้เคยได้ reward จากคนนี้ยังไม่ได้ (ป้องกัน duplicate)
          const { data: existingReward } = await supabase
            .from('referral_rewards').select('id')
            .eq('referral_id', ref.id).eq('order_id', order_id).maybeSingle();

          if (!existingReward) {
            // อ่าน referral config
            const { data: cfgRow } = await supabase
              .from('settings').select('value').eq('key', 'referral_config').maybeSingle();
            const cfg = cfgRow?.value || {};
            const rewardType  = cfg.referral_reward_type  || 'fixed';
            const rewardValue = parseFloat(cfg.referral_reward_value) || 50;
            const expireDays  = parseInt(cfg.referral_expire_days)    || 30;
            const maxRewards  = parseInt(cfg.referral_max_rewards)    || 0;

            // ตรวจ max_rewards ต่อคนชวน
            let canReward = true;
            if (maxRewards > 0) {
              const { count } = await supabase
                .from('referral_rewards').select('id', { count: 'exact', head: true })
                .eq('referral_id', ref.id);
              if ((count || 0) >= maxRewards) canReward = false;
            }

            if (canReward) {
              // สร้างคูปองสำหรับคนชวน
              const expireDate = new Date();
              expireDate.setDate(expireDate.getDate() + expireDays);
              const cpnCode = 'RWD-' + Date.now().toString(36).toUpperCase().slice(-6) + '-' +
                              Math.random().toString(36).slice(2,6).toUpperCase();

              const { data: newCoupon } = await supabase
                .from('coupons')
                .insert({
                  name:           'รางวัลชวนเพื่อน',
                  description:    'ขอบคุณที่แนะนำเพื่อนมาซื้อ! ใช้ได้ครั้งเดียว',
                  discount_type:  rewardType,
                  discount_value: rewardValue,
                  apply_type:     'manual',
                  code:           cpnCode,
                  usage_limit:    1,
                  used_count:     0,
                  end_date:       expireDate.toISOString(),
                  is_active:      true,
                  is_secret:      false,
                  condition_type: null,
                  min_order:      0
                })
                .select('id,code').single();

              if (newCoupon) {
                // บันทึก referral_reward
                await supabase.from('referral_rewards').insert({
                  referral_id: ref.id,
                  order_id:    order_id,
                  coupon_id:   newCoupon.id
                });

                // แจ้งเตือนคนชวนผ่าน LINE (ถ้ามี LINE UID)
                if (process.env.LINE_TOKEN) {
                  let refLineUid = null;

                  // [1] ค้นจาก line_users.customer_id (ตรงที่สุด)
                  try {
                    const { data: refUser } = await supabase
                      .from('line_users').select('user_id')
                      .eq('customer_id', ref.customer_id).maybeSingle();
                    refLineUid = refUser?.user_id || null;
                  } catch (_) { refLineUid = null; }
                  console.log(`🔍 [referral] line_users lookup → ${refLineUid || 'ไม่พบ'}`);

                  // [2] fallback: orders.line_user_id ที่ผูกไว้แล้ว
                  if (!refLineUid) {
                    const { data: refOrder } = await supabase
                      .from('orders').select('line_user_id')
                      .eq('customer_id', ref.customer_id)
                      .not('line_user_id', 'is', null).limit(1)
                      .maybeSingle();
                    refLineUid = refOrder?.line_user_id || null;
                    console.log(`🔍 [referral] orders lookup → ${refLineUid || 'ไม่พบ'}`);
                  }

                  // [3] fallback: ค้นจาก line_users ผ่าน customer_name ของ A
                  if (!refLineUid) {
                    const { data: refAnyOrder } = await supabase
                      .from('orders').select('customer_name, line_name')
                      .eq('customer_id', ref.customer_id).limit(1).maybeSingle();
                    const refName = refAnyOrder?.line_name || refAnyOrder?.customer_name;
                    if (refName) {
                      try {
                        const { data: luByName } = await supabase
                          .from('line_users').select('user_id')
                          .eq('display_name', refName).limit(1).maybeSingle();
                        refLineUid = luByName?.user_id || null;
                      } catch (_) { refLineUid = null; }
                      console.log(`🔍 [referral] display_name("${refName}") lookup → ${refLineUid || 'ไม่พบ'}`);
                    }
                  }

                  // [4] fallback: ค้นจาก line_users ผ่าน LINK ghost order
                  if (!refLineUid) {
                    const { data: ghostOrder } = await supabase
                      .from('orders').select('line_user_id')
                      .like('order_id', `LINK-${ref.customer_id.slice(0,20)}%`)
                      .not('line_user_id', 'is', null).limit(1).maybeSingle();
                    refLineUid = ghostOrder?.line_user_id || null;
                    console.log(`🔍 [referral] LINK ghost lookup → ${refLineUid || 'ไม่พบ'}`);
                  }

                  if (!refLineUid) {
                    console.warn(`⚠️ [referral] หา LINE UID ของ A (${ref.customer_id}) ไม่ได้ — คูปองบันทึกไว้แล้ว จะแจ้งเมื่อ A แชทกับ OA ครั้งถัดไป`);
                  }

                  if (refLineUid) {
                    const discStr = rewardType === 'percent'
                      ? `${rewardValue}%` : `฿${rewardValue.toLocaleString()}`;
                    const expireStr = expireDate.toLocaleDateString('th-TH', {
                      day:'numeric', month:'long', year:'numeric', timeZone:'Asia/Bangkok'
                    });
                    await linePush(refLineUid, [{
                      type: 'text',
                      text: `🎁 ยินดีด้วย! เพื่อนของคุณสั่งซื้อครั้งแรกแล้ว\n` +
                            `คุณได้รับคูปองส่วนลด ${discStr}\n` +
                            `📋 โค้ด: ${newCoupon.code}\n` +
                            `⏰ ใช้ได้ถึง: ${expireStr}\n` +
                            `นำโค้ดไปกรอกตอนสั่งซื้อได้เลยค่ะ 🛍️`
                    }]).catch(e => console.warn('referral notify failed:', e.message));
                  }
                }

                console.log(`🎁 referral reward: ${ref.customer_id} ← ${cpnCode} (เพื่อนสั่ง ${order_id})`);
              }
            }
          }
        }
      }
    } catch(e) {
      console.warn('referral reward error (non-fatal):', e.message);
    }
  }

  res.json({
    success: true, orderId: order_id,
    // 🎟️ บอกผลคูปองกลับไปให้หน้าร้าน — จะได้แจ้งลูกค้าถ้าคูปองใช้ไม่ได้ (เช่น ถูกใช้ไปแล้ว)
    couponApplied : !!appliedCouponId,
    couponRejected: !!(couponId && discountAmount > 0 && !appliedCouponId),
    discount      : finalDiscount,
    finalTotal
  });
});

// ── GET /my-orders/:customerId ────────────────────────────
app.get('/my-orders/:customerId', async (req, res) => {
  const { customerId } = req.params;
  if (!customerId) return res.status(400).json({ error: 'missing customerId' });

  // ── 🔗 รวมประวัติของลูกค้าคนเดียวกันที่มีหลาย customer_id ──
  // (เกิดจากเข้าร้านคนละทาง: LIFF vs LINE Login) — ใช้ LINE UID เป็นตัวเชื่อม
  let idList = [customerId];
  try {
    // หา LINE UID ของ customerId นี้
    let uid = null;
    const { data: myLink } = await supabase.from('orders')
      .select('line_user_id').eq('order_id', `LINK-${customerId.slice(0, 20)}`)
      .not('line_user_id', 'is', null).maybeSingle();
    if (myLink?.line_user_id) uid = myLink.line_user_id;
    if (!uid) {
      const { data: lu } = await supabase.from('line_users')
        .select('user_id').eq('customer_id', customerId)
        .order('last_seen', { ascending: false }).limit(1).maybeSingle();
      if (lu?.user_id) uid = lu.user_id;
    }
    // หา customer_id อื่น ๆ ที่ผูกกับ LINE UID เดียวกัน
    if (uid) {
      const { data: siblings } = await supabase.from('orders')
        .select('customer_id').like('order_id', 'LINK-%')
        .eq('line_user_id', uid).limit(10);
      (siblings || []).forEach(r => {
        if (r.customer_id && !idList.includes(r.customer_id)) idList.push(r.customer_id);
      });
      const { data: luSib } = await supabase.from('line_users')
        .select('customer_id').eq('user_id', uid).limit(10);
      (luSib || []).forEach(r => {
        if (r.customer_id && !idList.includes(r.customer_id)) idList.push(r.customer_id);
      });
    }
  } catch (e) { /* ถ้ารวมไม่ได้ ใช้ id เดียวตามเดิม */ }

  const { data, error } = await supabase
    .from('orders')
    .select('*')
    .in('customer_id', idList)
    .not('order_id', 'like', 'LINK-%')
    .order('created_at', { ascending: false })
    .limit(50);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ orders: data || [] });
});

// ── 📥 POST /log-client-error — รับ error จากหน้าเว็บ (หน้าร้าน/แอดมิน/แอปเซล) ──
// ทุกหน้าเว็บมี hook window.onerror ยิงมาที่นี่ → เก็บลง error_logs + แจ้ง LINE
app.post('/log-client-error', rateLimit(15), async (req, res) => {
  try {
    const { source, message, stack, url, line } = req.body || {};
    const src = ['shop','admin','sales'].includes(source) ? source : 'unknown';
    logError('client:' + src, new Error(String(message || 'unknown').slice(0, 500)), {
      url: String(url || '').slice(0, 300),
      line: line || null,
      stack: String(stack || '').slice(0, 800)
    });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false }); }
});

// ── 🧾 GET /admin/errors — ดึง error log ล่าสุด (หน้า Log ระบบ) ──
app.get('/admin/errors', requirePerm('settings'), async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    let q = supabase.from('error_logs').select('*').order('created_at', { ascending: false }).limit(limit);
    if (req.query.scope) q = q.like('scope', `${req.query.scope}%`);
    const { data, error } = await q;
    if (error) throw error;
    res.json({ errors: data || [] });
  } catch (e) {
    res.status(500).json({ error: e.message, hint: 'อาจยังไม่ได้รันตาราง error_logs ใน supabase-schema.sql' });
  }
});

// ── 📈 GET /admin/system-status — สถานะระบบ + คำแนะนำอัพเกรด ──
const _serverStartedAt = Date.now();
app.get('/admin/system-status', requirePerm('system'), async (req, res) => {
  const t0 = Date.now();
  const status = { checkedAt: new Date().toISOString(), services: {}, metrics: {}, recommendations: [] };
  const rec = (level, title, detail) => status.recommendations.push({ level, title, detail });
  try {
    // ── เซิร์ฟเวอร์ (Render) ──
    const mem = process.memoryUsage();
    const memMB = Math.round(mem.rss / 1024 / 1024);
    status.services.backend = { ok: true, uptimeMin: Math.round((Date.now() - _serverStartedAt) / 60000), memoryMB: memMB, node: process.version };
    if (memMB > 400) rec('crit', 'หน่วยความจำใกล้เต็ม', `ใช้ ${memMB}MB จาก 512MB (Render free) — ควรอัพเกรด Render Starter ($7/เดือน) หรือรีสตาร์ท`);
    else if (memMB > 300) rec('warn', 'หน่วยความจำเริ่มสูง', `ใช้ ${memMB}MB จาก 512MB — เฝ้าดูอาการ ถ้าเกิน 400MB บ่อยควรอัพเกรด`);

    // ── ฐานข้อมูล orders (Supabase) ──
    try {
      const _tDb = Date.now();
      const [{ count: totalOrders }, { count: todayOrders }, { count: msgCount }, { count: err24 }] = await Promise.all([
        supabase.from('orders').select('id', { count: 'exact', head: true }),
        supabase.from('orders').select('id', { count: 'exact', head: true }).gte('created_at', new Date(new Date().setHours(0,0,0,0)).toISOString()),
        supabase.from('messages').select('id', { count: 'exact', head: true }),
        supabase.from('error_logs').select('id', { count: 'exact', head: true }).gte('created_at', new Date(Date.now() - 86400000).toISOString()),
      ]);
      status.services.database = { ok: true, totalOrders: totalOrders || 0, todayOrders: todayOrders || 0, messages: msgCount || 0, errors24h: err24 || 0, latencyMs: Date.now() - _tDb };
      if (status.services.database.latencyMs > 2000) rec('crit', 'ฐานข้อมูลตอบช้ามาก', `${status.services.database.latencyMs}ms — ลูกค้าจะรู้สึกว่าเว็บช้า ตรวจสถานะ Supabase`);
      else if (status.services.database.latencyMs > 800) rec('warn', 'ฐานข้อมูลตอบช้า', `${status.services.database.latencyMs}ms — ปกติควรต่ำกว่า 500ms`);
      // 📊 error 24 ชม. แยกตามระบบ (หน้าร้าน/แอดมิน/เซล/backend)
      try {
        const { data: errRows } = await supabase.from('error_logs').select('source').gte('created_at', new Date(Date.now() - 86400000).toISOString()).limit(1000);
        const bySrc = {};
        (errRows || []).forEach(r => { const k = r.source || 'backend'; bySrc[k] = (bySrc[k] || 0) + 1; });
        status.metrics.errorsBySource = bySrc;
      } catch (_) {}
      // Supabase free: 500MB DB — ประเมินหยาบจากจำนวนแถว (ออเดอร์+แชท ~2-5KB/แถว)
      let estMB = Math.round(((totalOrders || 0) * 3 + (msgCount || 0) * 1) / 1024);
      status.metrics.dbSizeIsEstimate = true;
      try {
        const { data: realSize, error: szErr } = await supabase.rpc('db_size');
        if (!szErr && realSize) { estMB = Math.round(realSize / 1048576); status.metrics.dbSizeIsEstimate = false; }
      } catch (_) { /* ยังไม่ได้รัน SQL สร้าง db_size() → ใช้ประมาณการ */ }
      status.metrics.dbEstimatedMB = estMB;
      if (estMB > 400) rec('crit', 'ฐานข้อมูลใกล้เต็ม (ประมาณการ)', `~${estMB}MB จาก 500MB (Supabase free) — ควรอัพเกรด Supabase Pro ($25/เดือน ได้ 8GB + backup อัตโนมัติ) หรือลบข้อมูลเก่า`);
      else if (estMB > 250) rec('warn', 'ฐานข้อมูลโตขึ้นเรื่อย ๆ', `~${estMB}MB จาก 500MB — วางแผนอัพเกรดหรือ archive ข้อมูลเก่าล่วงหน้า`);
      if ((err24 || 0) > 50) rec('crit', 'Error เยอะผิดปกติใน 24 ชม.', `พบ ${err24} รายการ — เปิดแท็บ Log ระบบ ตรวจด่วน`);
      else if ((err24 || 0) > 10) rec('warn', 'มี Error สะสมใน 24 ชม.', `พบ ${err24} รายการ — ควรเข้าไปไล่ดูใน Log ระบบ`);
    } catch (e) {
      status.services.database = { ok: false, error: e.message };
      rec('crit', 'เชื่อมต่อฐานข้อมูลไม่ได้', e.message);
    }

    // ── LINE / ค่าตั้งสำคัญ ──
    status.services.line = { ok: !!process.env.LINE_TOKEN, webhookSecured: !!process.env.LINE_CHANNEL_SECRET };
    status.services.security = { adminKeySet: !!process.env.ADMIN_API_KEY };
    if (!process.env.ADMIN_API_KEY) rec('crit', 'ยังไม่ได้ตั้ง ADMIN_API_KEY', 'endpoint จัดการร้านยังไม่ถูกล็อก — ตั้งใน Render → Environment ด่วน');
    if (!process.env.LINE_CHANNEL_SECRET) rec('warn', 'Webhook ยังไม่ตรวจลายเซ็น', 'ตั้ง LINE_CHANNEL_SECRET เพื่อกันคนยิง webhook ปลอม');
    if (!process.env.LINE_TOKEN) rec('crit', 'ไม่มี LINE_TOKEN', 'บอทตอบลูกค้า/แจ้งเตือนแอดมินไม่ทำงาน');

    // ── คำแนะนำอัพเกรดตามแผนการใช้ (แสดงเสมอเป็นความรู้) ──
    status.upgradeGuide = [
      { service: 'Render (backend)', free: '512MB RAM, sleep เมื่อไม่มีคนใช้ (แก้ด้วย keep-alive แล้ว)', paid: 'Starter $7/เดือน: ไม่ sleep, เร็วขึ้นชัดเจนตอนลูกค้าเปิดร้าน', when: 'เมื่อยอดออเดอร์/วันเกิน ~30 หรือลูกค้าบ่นว่าเว็บโหลดช้าตอนเปิดครั้งแรก' },
      { service: 'Supabase (ฐานข้อมูล)', free: '500MB, ไม่มี backup อัตโนมัติ, pause ถ้าไม่ใช้ 7 วัน', paid: 'Pro $25/เดือน: 8GB + backup รายวัน 7 วัน', when: 'เมื่อ DB ประมาณการเกิน 300MB หรือธุรกิจพึ่งข้อมูลนี้จริงจัง (backup สำคัญมาก)' },
      { service: 'Cloudinary (รูปภาพ)', free: '25 เครดิต/เดือน (~25GB bandwidth)', paid: 'Plus $99/เดือน (แพง — ทางถูกกว่า: ย่อรูปก่อนอัป ซึ่งทำแล้ว)', when: 'เมื่อ dashboard ของ Cloudinary ขึ้นใช้เกิน 80% ติดกัน 2 เดือน' },
    ];

    status.responseMs = Date.now() - t0;
    res.json(status);
  } catch (e) {
    logError('system-status', e);
    res.status(500).json({ error: e.message });
  }
});

// ── POST /log-error — รับ error จากหน้าเว็บ (หน้าร้าน/แอดมิน/แอปเซล) ──
app.post('/log-error', rateLimit(20), (req, res) => {
  try {
    const { source, scope, message, extra } = req.body || {};
    const okSource = ['shop','admin','sales-app'].includes(source) ? source : 'shop';
    if (!message) return res.status(400).json({ error: 'ต้องมี message' });
    logError(String(scope || 'client').slice(0, 100), String(message).slice(0, 800), extra ? String(extra).slice(0, 800) : null, okSource);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /admin/error-logs — ดู log (กรองตามระบบ/ช่วงเวลา) ──────────
app.get('/admin/error-logs', requirePerm('system'), async (req, res) => {
  try {
    const hours  = Math.min(parseInt(req.query.hours) || 72, 24 * 30);
    const source = req.query.source || '';
    let q = supabase.from('error_logs').select('*')
      .gte('created_at', new Date(Date.now() - hours * 3600000).toISOString())
      .order('created_at', { ascending: false }).limit(300);
    if (source && source !== 'all') q = q.eq('source', source);
    const { data, error } = await q;
    if (error) throw error;
    res.json({ logs: data || [] });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET/POST /admin/error-notify-config — เปิด/ปิดแจ้งเตือน LINE ────
app.get('/admin/error-notify-config', requirePerm('system'), async (req, res) => {
  const cfg = await _getErrNotifyCfg();
  res.json({ config: cfg });
});
app.post('/admin/error-notify-config', requirePerm('system'), async (req, res) => {
  try {
    const { enabled, throttleMin } = req.body || {};
    const cfg = { enabled: !!enabled, throttleMin: Math.max(1, Math.min(parseInt(throttleMin) || 10, 1440)) };
    await supabase.from('settings').upsert([{ key: 'error_notify', value: cfg, updated_at: new Date().toISOString() }], { onConflict: 'key' });
    _errNotifyCfg = null; // บังคับโหลดใหม่
    res.json({ success: true, config: cfg });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── 🔒 กันเดารหัส: ผิดครบ 10 ครั้งติดกัน → ล็อค IP นั้นชั่วคราวแล้ว "รีเซ็ท" ตัวนับ ──
// (แยกจาก rateLimit ทั่วไปด้านบน ซึ่งจำกัดจำนวน "ครั้งที่เรียก" — อันนี้จำเฉพาะ "ครั้งที่ผิด"
//  ผิดถูกก็นับ ถ้าถูกจะรีเซ็ทตัวนับทันที ถ้าผิดครบ 10 จะล็อคยาวขึ้นแล้วเริ่มนับใหม่)
const _adminFailBuckets = new Map(); // ip → { fails, lockUntil }
const ADMIN_MAX_FAILS  = 10;
const ADMIN_LOCK_MS    = 5 * 60 * 1000; // ล็อค 5 นาทีเมื่อผิดครบ 10 ครั้ง
function adminBruteForceGuard(req, res, next) {
  const ip  = req.ip;
  const now = Date.now();
  const b = _adminFailBuckets.get(ip);
  if (b && b.lockUntil && now < b.lockUntil) {
    const waitSec = Math.ceil((b.lockUntil - now) / 1000);
    return res.status(429).json({ error: `กรอกรหัสผิดครบ ${ADMIN_MAX_FAILS} ครั้ง — กรุณารออีก ${waitSec} วินาทีแล้วลองใหม่` });
  }
  if (_adminFailBuckets.size > 5000) { // กัน map บวม
    for (const [k, v] of _adminFailBuckets) { if (v.lockUntil && now > v.lockUntil) _adminFailBuckets.delete(k); }
  }
  next();
}

// ── 🔓 GET /admin/verify — เช็คว่า Admin API Key ถูกต้องไหม ─────────
// ใช้เป็นด่านเข้าโหมดตั้งค่าหน้าร้าน (แทน PIN ที่เคยฝังในโค้ดหน้าเว็บ)
// หน้าเว็บจะถามรหัสนี้ "ทุกครั้ง" ที่เข้าโหมดตั้งค่า (ไม่จำรหัสไว้ข้ามการเข้าครั้งใหม่)
// มี rate limit 10 ครั้ง/นาที/IP (กันยิงถล่ม) + ผิดครบ 10 ครั้งติดกัน → ล็อค 5 นาที (กันเดารหัส)
app.get('/admin/verify', rateLimit(10), adminBruteForceGuard, (req, res) => {
  const key = process.env.ADMIN_API_KEY || '';
  const ip  = req.ip;
  // ถ้ายังไม่ได้ตั้ง ADMIN_API_KEY บน server → เปิดผ่านเหมือนเดิม (backward compatible)
  if (!key) return res.json({ ok: true });

  const got = req.headers['x-admin-key'] || req.query.admin_key || '';
  if (safeEqual(got, key)) {
    return res.json({ ok: true });
  }

  // ❌ ผิด → นับเพิ่ม ถ้าครบ 10 ครั้งติดกัน → ล็อคชั่วคราวแล้วรีเซ็ทตัวนับกลับเป็น 0
  const now = Date.now();
  let b = _adminFailBuckets.get(ip) || { fails: 0, lockUntil: 0 };
  b.fails++;
  if (b.fails >= ADMIN_MAX_FAILS) {
    b = { fails: 0, lockUntil: now + ADMIN_LOCK_MS };
    console.warn(`🚫 admin/verify ผิดครบ ${ADMIN_MAX_FAILS} ครั้ง — ล็อค IP ${ip} ${ADMIN_LOCK_MS / 60000} นาที`);
  }
  _adminFailBuckets.set(ip, b);
  console.warn(`🚫 admin endpoint ถูกปฏิเสธ: GET /admin/verify จาก ${ip} (ผิด ${b.fails}/${ADMIN_MAX_FAILS})`);
  return res.status(401).json({ error: 'unauthorized — ต้องใส่ Admin API Key' });
});

// ── 📥 GET /admin/export-orders — สำรองข้อมูลออเดอร์เป็น CSV ─────────
// ใช้: {BACKEND}/admin/export-orders?admin_key=XXX&days=90 (days ไม่ใส่ = ทั้งหมด)
app.get('/admin/export-orders', requirePerm('backup'), async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 0;
    let q = supabase.from('orders').select('*')
      .not('order_id', 'like', 'LINK-%')
      .order('created_at', { ascending: false }).limit(5000);
    if (days > 0) {
      q = q.gte('created_at', new Date(Date.now() - days * 86400000).toISOString());
    }
    const { data, error } = await q;
    if (error) throw error;
    const rows = data || [];
    const cols = ['order_id','created_at','customer_id','customer_name','line_name','phone','address','note','order_type','status','total','discount_amount','coupon_code','payment_method','payment_status','slip_amount','ref_code','items'];
    const esc = v => {
      if (v === null || v === undefined) return '';
      let s = typeof v === 'object' ? JSON.stringify(v) : String(v);
      // 🔒 SECURITY FIX: กัน CSV/Formula Injection — ฟิลด์ที่มาจากลูกค้า (customer_name, note,
      // address, line_name ฯลฯ) เป็นข้อมูลที่ควบคุมไม่ได้ ถ้าลูกค้าพิมพ์ขึ้นต้นด้วย = + - @
      // หรือ tab/CR แล้วแอดมินเปิดไฟล์ CSV นี้ด้วย Excel/Google Sheets โปรแกรมจะตีความเป็นสูตร
      // ทันที (เช่น =HYPERLINK(...) หรือ =cmd|...) เสี่ยงรันคำสั่ง/ขโมยข้อมูลบนเครื่องแอดมิน —
      // ป้องกันโดยเติม ' นำหน้าตามมาตรฐาน OWASP ก่อน escape เครื่องหมายคำพูดตามปกติ
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      if (/[",\n]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
      return s;
    };
    const csv = '\uFEFF' + cols.join(',') + '\n' +
      rows.map(r => cols.map(c => esc(r[c])).join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="orders-backup-${new Date().toISOString().slice(0,10)}.csv"`);
    res.send(csv);
  } catch (e) {
    logError('export-orders', e);
    res.status(500).json({ error: e.message });
  }
});

// ── 📦 จัดการสินค้าผ่าน backend (ทางที่ปลอดภัยกว่าเขียนตรงจากเบราว์เซอร์) ──
// เมื่อเปิด RLS ให้ตาราง products เป็น read-only สำหรับ anon key แล้ว
// หน้าร้าน (โหมดตั้งค่า) จะบันทึก/ลบสินค้าผ่าน 2 endpoint นี้แทน — มี admin key คุ้มกัน
app.post('/admin/products/upsert', requirePerm('products'), async (req, res) => {
  try {
    const rows = Array.isArray(req.body?.rows) ? req.body.rows : (req.body?.row ? [req.body.row] : []);
    if (!rows.length) return res.status(400).json({ error: 'ไม่มีข้อมูลสินค้า (rows)' });
    if (rows.length > 500) return res.status(400).json({ error: 'จำนวนสินค้าเกิน 500 รายการต่อครั้ง' });
    const { error } = await supabase.from('products').upsert(rows, { onConflict: 'id' });
    if (error) throw error;
    res.json({ success: true, count: rows.length });
  } catch (e) {
    logError('products-upsert', e);
    res.status(500).json({ error: e.message });
  }
});
app.post('/admin/products/delete', requirePerm('products'), async (req, res) => {
  try {
    const id = req.body?.id;
    if (!id) return res.status(400).json({ error: 'ต้องระบุ id' });
    const { error } = await supabase.from('products').delete().eq('id', id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    logError('products-delete', e);
    res.status(500).json({ error: e.message });
  }
});

// ── GET /ref-info/:code ───────────────────────────────────
// แปลง ref_code → ชื่อผู้แนะนำ (เซล/เพื่อน) สำหรับ popup ออเดอร์หน้าร้าน
// ส่งเฉพาะ type/code/name/label — ไม่เปิดเผยข้อมูลอื่นของเซล
app.get('/ref-info/:code', async (req, res) => {
  const info = await resolveRefInfo(req.params.code);
  if (!info) return res.status(404).json({ error: 'not found' });
  res.json({ type: info.type, code: info.code, name: info.name, label: info.label });
});

// ── GET /messages/:orderId ────────────────────────────────
app.get('/messages/:orderId', async (req, res) => {
  const { orderId } = req.params;
  const { customer_id } = req.query;

  // 🔒 SECURITY FIX (IDOR): เดิม endpoint นี้ไม่เช็คว่าคนเรียกเป็นเจ้าของออเดอร์หรือไม่เลย —
  // order_id สร้างจาก timestamp + เลขสุ่ม 2 หลัก (ดู genOrderId) ซึ่งเดา/ไล่เดาได้ง่ายกว่า
  // customer_id (random UUID) มาก ทำให้ใครก็ตามที่รู้หรือเดา order_id ได้ อ่านแชท (ที่อยู่/
  // หมายเหตุ/รายละเอียดการจ่ายเงิน) ของออเดอร์คนอื่นได้หมดโดยไม่ต้องพิสูจน์ตัวตนใดๆ
  // ตอนนี้: ถ้ามาจากแอดมิน (admin key ถูกต้อง) ดูได้ทุกออเดอร์เหมือนเดิม — ถ้าไม่ใช่ ต้องส่ง
  // customer_id ของออเดอร์นั้นมาด้วยเสมอ (รองรับ prefix สั้นกว่าเล็กน้อยเหมือนจุด /submit-slip
  // กรณี session ต่างกันนิดหน่อย)
  const masterKey = process.env.ADMIN_API_KEY || '';
  const gotKey = req.headers['x-admin-key'] || req.query.admin_key || '';
  const isAdmin = !!(masterKey && safeEqual(gotKey, masterKey));

  if (!isAdmin) {
    if (!customer_id) return res.status(400).json({ error: 'customer_id required' });
    const { data: ord } = await supabase.from('orders').select('customer_id').eq('order_id', orderId).maybeSingle();
    if (!ord) return res.status(404).json({ error: 'ไม่พบออเดอร์นี้' });
    const ownerId = ord.customer_id || '';
    const sameOwner = ownerId === customer_id || ownerId.startsWith(String(customer_id).slice(0, 8));
    if (!sameOwner) return res.status(403).json({ error: 'ไม่ใช่ออเดอร์ของคุณ' });
  }

  const { data, error } = await supabase
    .from('messages')
    .select('*')
    .eq('order_id', orderId)
    .neq('sender', 'admin_note') // 🚨 BUG FIX: เดิมส่ง note ภายในของแอดมิน (เช่น คำเตือนสงสัยสลิปซ้ำ/ฉ้อโกง) ให้ลูกค้าเห็นด้วย! ต้องกันไว้ตรงนี้เพราะ endpoint นี้เป็นทางเดียวที่หน้าร้านใช้โหลดแชท
    .order('created_at', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ messages: data || [] });
});

// ── POST /link-line ───────────────────────────────────────
// ผูก customer_id (จาก shop browser) ↔ line_user_id อัตโนมัติ
// shop เรียกตอนลูกค้าเปิดด้วย ?lid=TOKEN
app.post('/link-line', async (req, res) => {
  const { customer_id, link_token, refCode } = req.body;
  if (!customer_id || !link_token)
    return res.status(400).json({ error: 'missing customer_id or link_token' });

  const lineUserId = consumeLinkToken(link_token);
  if (!lineUserId)
    return res.status(400).json({ error: 'token invalid or expired' });

  // อัปเดต line_user_id ในออเดอร์ของ customer นี้
  const { error } = await supabase.from('orders')
    .update({ line_user_id: lineUserId })
    .eq('customer_id', customer_id);
  if (error) console.warn('link orders failed:', error.message);

  // ✨ FIX Bug 1: upsert ghost LINK-row เพื่อเก็บ mapping แม้ยังไม่มีออเดอร์จริง
  // เวลา /send-order ทำงาน จะหา line_user_id จาก row นี้ได้เสมอ
  await supabase.from('orders').upsert([{
    order_id    : `LINK-${customer_id.slice(0, 20)}`,
    customer_id,
    line_user_id: lineUserId,
    customer_name: '',
    items       : [],
    total       : 0,
    status      : 'pending',
    created_at  : new Date().toISOString(),
    note        : '🔗 ผูกบัญชี LINE (รอสั่งสินค้า)',
    ref_code    : refCode || null          // 💼 เก็บรหัสเซลไว้ใน ghost row
  }], { onConflict: 'order_id' }).then(({ error: e }) => {
    if (e) console.warn('upsert link-ghost failed:', e.message);
    else console.log(`🔗 stored LINK mapping: customer=${customer_id} ↔ LINE=${lineUserId.slice(0,12)}… ref=${refCode||'-'}`);
  });

  // ดึงโปรไฟล์ LINE มาเพิ่ม customer_name (ถ้าออเดอร์ยังไม่มีชื่อ)
  let displayName = null;
  try {
    const profRes = await fetch(`https://api.line.me/v2/bot/profile/${lineUserId}`, {
      headers: { 'Authorization': `Bearer ${process.env.LINE_TOKEN}` }
    });
    if (profRes.ok) {
      const profile = await profRes.json();
      displayName = profile.displayName || null;
    }
  } catch(e) { /* ignore */ }

  // ✨ อัปเดตชื่อ LINE ใน LINK ghost row
  if (displayName) {
    await supabase.from('orders')
      .update({ customer_name: displayName, line_name: displayName })
      .eq('order_id', `LINK-${customer_id.slice(0, 20)}`)
      .then(null, () => {});
  }

  // ✨ บันทึก customer_id ลง line_users เพื่อให้ auto-link ได้ 100%
  upsertLineUser(lineUserId, { customer_id }).catch(() => {});

  // ✨ FIX: ตรวจหาคูปองชวนเพื่อนที่ค้างอยู่ (ยังไม่ได้แจ้งเพราะไม่มี LINE UID ตอนนั้น)
  //   ทำ async แยกต่างหาก ไม่ block response
  if (process.env.LINE_TOKEN) {
    (async () => {
      try {
        const { data: ref } = await supabase
          .from('referrals').select('id')
          .eq('customer_id', customer_id).maybeSingle();
        if (!ref) return;

        const { data: rewards } = await supabase
          .from('referral_rewards')
          .select('*, coupons(*)')
          .eq('referral_id', ref.id)
          .order('created_at', { ascending: false });
        if (!rewards?.length) return;

        // กรองเฉพาะคูปองที่ยังใช้ได้ (active, ไม่หมดอายุ, ยังไม่ได้ใช้)
        const now = new Date();
        const activeCoupons = rewards.filter(rw => {
          const c = rw.coupons;
          if (!c || !c.is_active) return false;
          if (c.usage_limit !== null && (c.used_count || 0) >= c.usage_limit) return false;
          if (c.end_date && new Date(c.end_date) < now) return false;
          return true;
        });
        if (!activeCoupons.length) return;

        // แจ้งเตือนคูปองที่รอมานาน
        const lines = activeCoupons.map(rw => {
          const c = rw.coupons;
          const discStr = c.discount_type === 'percent'
            ? `${c.discount_value}%` : `฿${Number(c.discount_value).toLocaleString()}`;
          const expStr = c.end_date
            ? new Date(c.end_date).toLocaleDateString('th-TH', { day:'numeric', month:'long', year:'numeric', timeZone:'Asia/Bangkok' })
            : 'ไม่มีวันหมดอายุ';
          return `🎟️ ${c.code}  ลด ${discStr}\n   ใช้ได้ถึง ${expStr}`;
        }).join('\n\n');

        await linePush(lineUserId, [{
          type: 'text',
          text: `🎁 มีคูปองชวนเพื่อนรอคุณอยู่!\n` +
                `เพื่อนของคุณสั่งซื้อครั้งแรกแล้ว แต่ตอนนั้นยังไม่ได้ผูก LINE กับร้าน\n\n` +
                `${lines}\n\n` +
                `นำโค้ดไปกรอกตอนสั่งซื้อได้เลยค่ะ 🛍️`
        }]);
        console.log(`🎁 pending referral notify sent → ${lineUserId.slice(0,12)}… (${activeCoupons.length} coupon)`);
      } catch(e) {
        console.warn('pending referral notify failed:', e.message);
      }
    })();
  }

  console.log(`🔗 linked customer ${customer_id} ↔ LINE ${lineUserId.slice(0,12)}…`);
  res.json({ success: true, lineUserId: lineUserId.slice(0,12) + '…', displayName });
});

// ── POST /backfill-line-links ─────────────────────────────
// แก้ครั้งเดียวสำหรับออเดอร์เก่าที่ยังไม่ผูก line_user_id
// จับคู่ ghost orders (LINE-) กับ ออเดอร์จริง โดยใช้ phone เป็น matching key
app.post('/backfill-line-links', requirePerm('orders'), async (req, res) => {
  const { data: ghosts } = await supabase.from('orders')
    .select('line_user_id, customer_name, phone')
    .like('order_id', 'LINE-%')
    .not('line_user_id', 'is', null);

  if (!ghosts?.length) return res.json({ updated: 0, message: 'no ghost orders' });

  const normPhone = (p) => String(p || '').replace(/\D/g, '');

  let totalUpdated = 0;
  const linked = [];
  for (const g of ghosts) {
    const phone = normPhone(g.phone);
    const name  = (g.customer_name || '').trim().toLowerCase();

    // หาออเดอร์จริงที่ phone หรือ name ตรงกัน แต่ยังไม่มี line_user_id
    const { data: realOrders } = await supabase.from('orders')
      .select('order_id, customer_id, customer_name, phone')
      .not('order_id', 'like', 'LINE-%')
      .is('line_user_id', null);

    const matches = (realOrders || []).filter(o =>
      (phone && normPhone(o.phone) === phone) ||
      (name && (o.customer_name || '').trim().toLowerCase() === name)
    );

    if (matches.length) {
      // get all customer_ids
      const customerIds = [...new Set(matches.map(m => m.customer_id).filter(Boolean))];
      if (customerIds.length) {
        const { count } = await supabase.from('orders')
          .update({ line_user_id: g.line_user_id }, { count: 'exact' })
          .in('customer_id', customerIds);
        totalUpdated += count || 0;
        linked.push({ name: g.customer_name, lineUid: g.line_user_id.slice(0,12)+'…', count });
      }
    }
  }
  res.json({ updated: totalUpdated, linked });
});

// ── POST /resend-order/:orderId ───────────────────────────
// แอดมิน trigger ส่ง Flex สรุปออเดอร์ไปหาลูกค้าใน LINE
// ถ้าลูกค้ายังไม่ผูก → ลอง auto-link ด้วย phone/name ก่อน
app.post('/resend-order/:orderId', requirePerm('orders'), async (req, res) => {
  const { orderId } = req.params;
  if (!process.env.LINE_TOKEN)
    return res.status(500).json({ error: 'LINE_TOKEN not set' });

  // โหลดข้อมูลออเดอร์
  const { data: order, error: orderErr } = await supabase
    .from('orders').select('*').eq('order_id', orderId).maybeSingle();

  if (orderErr) return res.status(500).json({ error: orderErr.message });
  if (!order)   return res.status(404).json({ error: 'order not found' });
  if (String(order.order_id).startsWith('LINE-'))
    return res.status(400).json({ error: 'cannot resend ghost chat thread' });

  // หา line_user_id หลายทาง
  let targetUid = order.line_user_id;
  let linkedHow = targetUid ? 'direct' : null;

  // fallback 1: หาจาก customer_id
  if (!targetUid && order.customer_id) {
    targetUid = await findLineUserIdByCustomer(order.customer_id);
    if (targetUid) linkedHow = 'customer_id';
  }

  // fallback 2: หาจาก phone/name match กับ ghost orders
  if (!targetUid) {
    const normPhone = (p) => String(p || '').replace(/\D/g, '');
    const myPhone = normPhone(order.phone);
    const myName  = (order.customer_name || '').trim().toLowerCase();

    if (myPhone || myName) {
      const { data: ghosts } = await supabase.from('orders')
        .select('line_user_id, customer_name, phone')
        .like('order_id', 'LINE-%')
        .not('line_user_id', 'is', null);

      const matched = (ghosts || []).find(g =>
        (myPhone && normPhone(g.phone) === myPhone) ||
        (myName && (g.customer_name || '').trim().toLowerCase() === myName)
      );

      if (matched?.line_user_id) {
        targetUid = matched.line_user_id;
        linkedHow = matched.phone === order.phone ? 'phone' : 'name';

        // backfill ให้ออเดอร์ของ customer คนนี้ทุกตัว
        if (order.customer_id) {
          await supabase.from('orders')
            .update({ line_user_id: targetUid })
            .eq('customer_id', order.customer_id);
        } else {
          await supabase.from('orders')
            .update({ line_user_id: targetUid })
            .eq('order_id', order.order_id);
        }
      }
    }
  }

  if (!targetUid) {
    return res.status(404).json({
      error: 'no LINE user linked',
      hint: 'ลูกค้ายังไม่ผูกบัญชี LINE — กดปุ่ม 🔗 ที่ ghost chat row เพื่อใส่เบอร์/ชื่อให้ตรงกัน'
    });
  }

  try {
    const flex = await buildOrderSummaryFlex(order);
    await linePush(targetUid, [flex]);
    console.log(`📤 resend order ${orderId} → ${targetUid.slice(0,12)}… (via ${linkedHow})`);
    res.json({
      success: true,
      sentTo: targetUid.slice(0, 12) + '…',
      linkedVia: linkedHow
    });
  } catch (e) {
    console.warn(`❌ resend failed: ${e.message}`);
    res.status(500).json({ error: e.message });
  }
});

// ── POST /messages ────────────────────────────────────────
app.post('/messages', async (req, res) => {
  const { order_id, customer_id, sender, text } = req.body;
  if (!order_id || !sender || !text)
    return res.status(400).json({ error: 'missing fields' });

  // 🔴 SECURITY FIX (สำคัญมาก): เดิม endpoint นี้รับค่า sender จาก client ตรงๆ โดยไม่ตรวจสอบ
  // อะไรเลย — ใครก็ส่ง { order_id, sender:'admin', text:'...' } เข้ามาได้ แล้วโค้ดด้านล่าง
  // (sender === 'admin') จะยิง LINE Push ข้อความนั้นออกไปหาลูกค้าจริงทันที เหมือนเป็นแอดมิน
  // ร้านตอบเอง — เปิดช่องให้ปลอมข้อความแอดมิน (เช่น เลขบัญชีโอนเงินปลอม) ส่งหาลูกค้าได้เลย
  // แก้: อนุญาต sender ที่ไม่ใช่ 'customer' (เช่น 'admin') เฉพาะเมื่อมี admin key/token ถูกต้อง
  const masterKey = process.env.ADMIN_API_KEY || '';
  const gotKey = req.headers['x-admin-key'] || req.query.admin_key || '';
  const bearer = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  const isAdminCaller = !!((masterKey && safeEqual(gotKey, masterKey)) || verifyAuthToken(bearer));
  if (sender !== 'customer' && !isAdminCaller) {
    return res.status(403).json({ error: 'ไม่มีสิทธิ์ส่งข้อความในนามนี้' });
  }
  // ลูกค้าส่งเอง → เช็คว่าเป็นเจ้าของออเดอร์จริง กันสแปม/แกล้งแชทออเดอร์คนอื่น
  // (รองรับ prefix สั้นกว่าเล็กน้อยเหมือนจุดอื่นในระบบ กรณี session ต่างกันนิดหน่อย)
  if (sender === 'customer' && !isAdminCaller) {
    if (!customer_id) return res.status(400).json({ error: 'customer_id required' });
    const { data: ordCheck } = await supabase.from('orders').select('customer_id').eq('order_id', order_id).maybeSingle();
    if (ordCheck) {
      const ownerId = ordCheck.customer_id || '';
      const sameOwner = ownerId === customer_id || ownerId.startsWith(String(customer_id).slice(0, 8));
      if (!sameOwner) return res.status(403).json({ error: 'ไม่ใช่ออเดอร์ของคุณ' });
    }
    // ไม่พบออเดอร์ (เช่น ทักก่อนมีออเดอร์จริง / ghost LINE- row) → ปล่อยผ่านตามพฤติกรรมเดิม
  }

  const { data, error } = await supabase.from('messages').insert([{
    order_id, customer_id, sender, text,
    created_at: new Date().toISOString()
  }]).select().single();

  if (error) return res.status(500).json({ error: error.message });

  // โหลด order มาดู line_user_id และ customer_name
  const { data: order } = await supabase.from('orders')
    .select('customer_name, order_id, line_user_id')
    .eq('order_id', order_id).maybeSingle();

  // ลูกค้าทัก → แจ้งแอดมินทุกคนผ่าน LINE
  if (sender === 'customer' && process.env.LINE_TOKEN) {
    const name = order?.customer_name || 'ลูกค้า';
    const notifyText = `💬 ${name} ส่งข้อความ (#${order_id}):\n\n${text.slice(0,500)}\n\n📲 เปิด Admin Panel เพื่อตอบกลับ`;
    notifyAllAdmins([{ type:'text', text: notifyText }]).catch(console.error);
  }

  // แอดมินตอบ → ส่ง Flex Message LINE หาลูกค้า
  if (sender === 'admin' && process.env.LINE_TOKEN) {
    let targetUserId = order?.line_user_id;
    console.log(`[admin reply] order_id=${order_id}, order.line_user_id=${targetUserId || 'null'}`);

    // ถ้า order_id มาในรูปแบบ "LINE-..." แต่ไม่มี line_user_id
    if (!targetUserId && order_id.startsWith('LINE-')) {
      const { data: ghostOrder } = await supabase.from('orders')
        .select('line_user_id').eq('order_id', order_id).maybeSingle();
      if (ghostOrder?.line_user_id) {
        targetUserId = ghostOrder.line_user_id;
        console.log(`[admin reply] found via ghost lookup: ${targetUserId.slice(0,12)}…`);
      }
    }

    // fallback 1: หาจาก customer_id
    if (!targetUserId && customer_id) {
      targetUserId = await findLineUserIdByCustomer(customer_id);
      if (targetUserId) console.log(`[admin reply] found via customer_id: ${targetUserId.slice(0,12)}…`);
    }

    // fallback 2: ถ้า order_id แบบ "LINE-{prefix16}" — scan หา full userId ใน DB ที่ขึ้นต้นด้วย prefix นี้
    if (!targetUserId && order_id.startsWith('LINE-')) {
      const prefix = order_id.slice(5); // เอาส่วนหลัง "LINE-"
      const { data: scanRows } = await supabase.from('orders')
        .select('line_user_id')
        .not('line_user_id', 'is', null)
        .like('line_user_id', `${prefix}%`)
        .limit(1);
      if (scanRows?.[0]?.line_user_id) {
        targetUserId = scanRows[0].line_user_id;
        console.log(`[admin reply] found via prefix scan: ${targetUserId.slice(0,12)}…`);

        // backfill ghost order ให้มี line_user_id
        await supabase.from('orders')
          .update({ line_user_id: targetUserId })
          .eq('order_id', order_id)
          .then(({ error }) => { if (!error) console.log('[admin reply] backfilled ghost order'); });
      }
    }

    if (targetUserId) {
      try {
        const flex = buildChatFlex(order, text);
        await linePush(targetUserId, [flex]);
        console.log(`📤 admin reply → ${targetUserId.slice(0,12)}…`);
      } catch (e) {
        console.warn(`❌ LINE push failed for ${targetUserId.slice(0,12)}…: ${e.message}`);
      }
    } else {
      console.warn(`❌ no target LINE user found for order ${order_id}`);
    }
  }

  res.json({ success: true, message: data });
});


// ── upsert ข้อมูลลูกค้าลง line_users (เรียกทุกครั้งที่มี event) ──
async function upsertLineUser(userId, extraFields = {}) {
  if (!userId) return null;
  try {
    const profRes = await fetch(`https://api.line.me/v2/bot/profile/${userId}`, {
      headers: { 'Authorization': `Bearer ${process.env.LINE_TOKEN}` }
    });
    const profile = profRes.ok ? await profRes.json() : {};
    const displayName = profile.displayName || null;
    const pictureUrl  = profile.pictureUrl  || null;

    const row = {
      user_id     : userId,
      display_name: displayName,
      picture_url : pictureUrl,
      last_seen   : new Date().toISOString(),
      ...extraFields   // ✨ เผื่อส่ง customer_id มาด้วย
    };
    // ถ้าไม่มี customer_id ใน extraFields → ไม่ทับค่าเดิม (only update if provided)
    if (!extraFields.customer_id) delete row.customer_id;

    await supabase.from('line_users').upsert([row], { onConflict: 'user_id' });
    return displayName;
  } catch (e) {
    console.warn('upsertLineUser failed:', e.message);
    return null;
  }
}

// ── POST /webhook ─────────────────────────────────────────
// LINE bot — ลูกค้าทักมา → ตอบสถานะออเดอร์
app.post('/webhook', async (req, res) => {
  // 🔐 ตรวจลายเซ็น LINE (X-Line-Signature) — เปิดใช้เมื่อตั้ง env LINE_CHANNEL_SECRET
  // กันคนนอกยิง webhook ปลอมมาสั่งบอทตอบ/สร้างข้อมูลมั่ว ถ้าไม่ตั้ง env จะทำงานเหมือนเดิม
  const _lineSecret = process.env.LINE_CHANNEL_SECRET || '';
  if (_lineSecret) {
    try {
      const crypto = require('crypto');
      const sig = req.headers['x-line-signature'] || '';
      const expected = crypto.createHmac('sha256', _lineSecret)
        .update(req.rawBody || Buffer.from(JSON.stringify(req.body || {})))
        .digest('base64');
      // 🔒 SECURITY FIX: เดิมเทียบด้วย sig !== expected (string compare ธรรมดา) ซึ่งไม่ใช่
      // timing-safe เหมือนจุดอื่นในระบบ (เทียบกับ verifyAuthToken ที่ใช้ timingSafeEqual) —
      // เปลี่ยนมาใช้ crypto.timingSafeEqual ให้สม่ำเสมอกัน กันโดนเดาลายเซ็นทีละไบต์ผ่าน timing
      const sigBuf = Buffer.from(sig, 'base64');
      const expBuf = Buffer.from(expected, 'base64');
      const sigValid = sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
      if (!sigValid) {
        console.warn('🚫 webhook: signature ไม่ถูกต้อง — ปฏิเสธ');
        return res.sendStatus(403);
      }
    } catch (e) {
      console.warn('webhook signature check error:', e.message);
    }
  }
  res.sendStatus(200);
  const events = req.body?.events || [];

  for (const ev of events) {
    const userId = ev.source?.userId;
    if (!userId) continue;

    // ✨ บันทึก / อัปเดต line_users อัตโนมัติทุกครั้ง (fire-and-forget)
    upsertLineUser(userId).catch(() => {});

    // ── ครอบทุก event ด้วย try-catch — ป้องกัน crash เงียบ ──
    try {

    // ── FOLLOW EVENT (ลูกค้าเพิ่ม bot เป็นเพื่อน / unblock) ──
    if (ev.type === 'follow') {
      const replyToken = ev.replyToken;
      const token = createLinkToken(userId);
      const shopLink = `${SHOP_URL}?lid=${token}`;

      await safeReply(replyToken, userId, [
        {
          type: 'text',
          text: `🛍 สวัสดีค่ะ! ยินดีต้อนรับสู่ มนชิน ซัพพลาย\n\n` +
                `กดลิงก์ด้านล่างเพื่อเริ่มสั่งซื้อ ระบบจะจดจำคุณอัตโนมัติ ไม่ต้องลงทะเบียน 🚀\n\n` +
                `${shopLink}\n\n` +
                `⏰ ลิงก์มีอายุ 30 นาที\n\n` +
                `📌 ครั้งหน้าพิมพ์คำใดคำหนึ่งด้านล่างเพื่อรับลิงก์ใหม่ได้ตลอดค่ะ:\n` +
                `• "เปิดร้าน"\n` +
                `• "ผูกบัญชี(สั่งสินค้า)"\n` +
                `• "ผูกบัญชี"`
        }
      ]);
      continue;
    }

    // ── POSTBACK EVENTS (กดปุ่มใน Flex Message) ──
    if (ev.type === 'postback') {
      const replyToken = ev.replyToken;
      const data = ev.postback?.data || '';
      const params = new URLSearchParams(data);
      const action = params.get('action');

      if (action === 'view_order') {
        const orderId = params.get('id');
        if (!orderId) { await safeReply(replyToken, userId, [{ type:'text', text:'❌ ไม่พบเลขออเดอร์' }]); continue; }

        const { data: order } = await supabase.from('orders')
          .select('*').eq('order_id', orderId).maybeSingle();

        if (!order) {
          await safeReply(replyToken, userId, [{ type:'text', text:`❌ ไม่พบออเดอร์ #${orderId}` }]);
          continue;
        }

        // ตอบกลับด้วยข้อความสรุป + Flex รายละเอียด
        const st = order.status || 'pending';
        const itemsList = (order.items || []).map(i =>
          `${i.emoji||'•'} ${i.name} ×${i.qty} = ฿${(i.qty*i.price).toLocaleString()}`
        ).join('\n');
        const date = new Date(order.created_at).toLocaleString('th-TH', { dateStyle:'short', timeStyle:'short', timeZone:'Asia/Bangkok' });

        let detailText =
          `📦 ออเดอร์ #${order.order_id}\n` +
          `${'─'.repeat(20)}\n` +
          `${getStatusEmoji(st)} สถานะ: ${STATUS_LABELS_TH[st] || st}\n\n` +
          `👤 ${order.customer_name || '-'}\n`;

        if (order.phone)   detailText += `📞 ${order.phone}\n`;
        if (order.address) detailText += `📍 ${order.address}\n`;
        detailText += `📅 ${date}\n`;
        detailText += `${'─'.repeat(20)}\n`;
        if (itemsList) detailText += `${itemsList}\n${'─'.repeat(20)}\n`;
        detailText += `💰 ยอดรวม: ฿${(order.total||0).toLocaleString()}`;
        if (order.note) detailText += `\n\n📝 ${order.note}`;
        detailText += await shGetHoursMsg();

        // ส่งทั้ง text และ flex update (สถานะปัจจุบัน)
        const messages = [{ type:'text', text: detailText }];
        if (Array.isArray(order.items) && order.items.length > 0) {
          messages.push(await buildStatusUpdateFlex(order, st));
        }
        await safeReply(replyToken, userId, messages);
        continue;
      }

      if (action === 'view_history') {
        // ดึงออเดอร์ที่เสร็จสิ้น/ยกเลิกทั้งหมดของ user นี้
        const { data: histOrders } = await supabase.from('orders')
          .select('*')
          .eq('line_user_id', userId)
          .in('status', ['done', 'cancelled'])
          .not('order_id', 'like', 'LINE-%')
          .not('order_id', 'like', 'LINK-%')
          .order('created_at', { ascending: false })
          .limit(10);

        const realHist = (histOrders || []).filter(o => Array.isArray(o.items) && o.items.length > 0);

        if (!realHist.length) {
          await safeReply(replyToken, userId, [{ type:'text', text:'📭 ยังไม่มีประวัติออเดอร์ค่ะ' }]);
          continue;
        }

        const histBubbles = realHist.slice(0, 10).map(o => ({
          type:'bubble', size:'kilo',
          header:{
            type:'box', layout:'vertical',
            backgroundColor: statusColor(o.status),
            paddingAll:'md',
            contents:[
              { type:'text', text:`${getStatusEmoji(o.status)} ${STATUS_LABELS_TH[o.status]||o.status}`, color:'#ffffff', size:'sm', weight:'bold' },
              { type:'text', text:`#${o.order_id}`, color:'#ffffff', size:'xs', margin:'xs' }
            ]
          },
          body:{
            type:'box', layout:'vertical', spacing:'sm', paddingAll:'md',
            contents:[
              ...((o.items||[]).slice(0,3).map(i => ({
                type:'text', text:`${i.emoji||'•'} ${i.name} ×${i.qty}`,
                size:'xs', color:'#555555', wrap:true
              }))),
              ...((o.items||[]).length > 3 ? [{ type:'text', text:`+${o.items.length-3} รายการ`, size:'xxs', color:'#888888' }] : []),
              { type:'separator', margin:'md' },
              { type:'box', layout:'horizontal', margin:'md',
                contents:[
                  { type:'text', text:'รวม', size:'xs', color:'#888888', flex:1 },
                  { type:'text', text:`฿${(o.total||0).toLocaleString()}`, size:'sm', color:'#C0392B', weight:'bold', align:'end', flex:2 }
                ]
              },
              { type:'text', text: new Date(o.created_at).toLocaleString('th-TH', { dateStyle:'short', timeStyle:'short', timeZone:'Asia/Bangkok' }), size:'xxs', color:'#aaaaaa', margin:'xs' }
            ]
          },
          footer:{
            type:'box', layout:'vertical', paddingAll:'md', paddingTop:'none',
            contents:[
              { type:'button', style:'primary', color:'#C0392B', height:'sm',
                action:{ type:'postback', label:'📋 ดูรายละเอียด',
                         data:`action=view_order&id=${o.order_id}`,
                         displayText:`📋 ดูรายละเอียด #${o.order_id}` }
              }
            ]
          }
        }));

        await safeReply(replyToken, userId, [
          { type:'text', text:`📜 ประวัติออเดอร์ของคุณ (${realHist.length} รายการ)` },
          { type:'flex', altText:`ประวัติออเดอร์ ${realHist.length} รายการ`,
            contents:{ type:'carousel', contents: histBubbles } }
        ]);
        continue;
      }


    }

    if (ev.type !== 'message' || ev.message?.type !== 'text') {
      // ── รับรูปสลิปจาก LINE ลูกค้า ──────────────────────────
      if (ev.type === 'message' && ev.message?.type === 'image') {
        const replyToken = ev.replyToken;
        try {
          const { data: orders } = await supabase
            .from('orders')
            .select('order_id, total, customer_id, customer_name, payment_status, payment_method')
            .eq('line_user_id', userId)
            .eq('payment_method', 'transfer')
            .not('status', 'in', '("done","cancelled")')
            .gt('total', 0)
            .like('order_id', 'ORD%')
            .order('created_at', { ascending: false })
            .limit(1);

          const order = orders?.[0];
          if (!order) {
            // ไม่พบออเดอร์โอนเงิน → ไม่ตอบและไม่ดึงรูป
            continue;
          }

          // ไม่ดึงรูปจาก LINE Content API เพราะจะทำให้รูปหายจาก chat
          // แจ้งลูกค้าให้ส่งสลิปผ่านหน้าร้านแทน
          await safeReply(replyToken, userId, [{
            type: 'text',
            text: `📋 ได้รับรูปแล้วค่ะ #${order.order_id}\n\nกรุณาส่งสลิปผ่านหน้าร้านด้วยนะคะ เพื่อให้ระบบตรวจยอดอัตโนมัติได้ค่ะ 🙏\n\n👉 กดปุ่ม "สั่งสินค้า" ในเมนู → เลือก "ออเดอร์ของฉัน" → แนบสลิป`
          }]);

          // แจ้งแอดมินด้วยว่ามีลูกค้าส่งรูปมา
          notifyAllAdmins([{
            type: 'text',
            text: `📷 ลูกค้าส่งรูปใน LINE #${order.order_id}\nชื่อ: ${order.customer_name}\nกรุณาตรวจสอบในหน้าแอดมินค่ะ`
          }]).catch(() => {});

        } catch(imgErr) {
          console.error('LINE image slip error:', imgErr.message);
          try { await safeReply(ev.replyToken, userId, [{ type:'text', text:'❌ เกิดข้อผิดพลาด กรุณาลองใหม่ค่ะ' }]); } catch(_) {}
        }
      }
      continue;
    }
    const rawText = ev.message.text || '';
    const text = rawText.trim().toLowerCase();
    const replyToken = ev.replyToken;

    // ── รับยอดที่ลูกค้าพิมพ์มาทาง LINE (กรณี OCR อ่านไม่ได้) ─────────
    // 🚨 SECURITY FIX: เดิมโค้ดตรงนี้ auto-confirm ออเดอร์เป็น "ชำระแล้ว" ทันทีถ้าตัวเลข
    // ที่ลูกค้าพิมพ์ (เช่น "500") ตรงกับยอดออเดอร์ — โดยไม่มีการแนบสลิปหรือรูปใด ๆ เลย!
    // เท่ากับใครก็ตามพิมพ์ยอดถูกก็ได้ออเดอร์ฟรีโดยไม่ต้องโอนเงินจริง
    // แก้แล้ว: ข้อความที่พิมพ์มาใช้แค่ "บันทึกยอดที่ลูกค้าแจ้ง" ให้แอดมินเห็น/ตรวจ manual เท่านั้น
    // การ auto-confirm (status: 'confirmed') จะเกิดได้จาก /submit-slip เท่านั้น ซึ่งต้องมีรูปสลิปจริง
    // ให้ server อ่าน OCR ยืนยันอิสระเองก่อนเสมอ
    const amountTyped = parseFloat(rawText.trim().replace(/[฿,\s]/g, ''));
    if (!isNaN(amountTyped) && amountTyped > 0 && amountTyped < 1000000) {
      // หาออเดอร์โอนที่รอสลิปหรืออ่านยอดไม่ได้
      const { data: amtOrders } = await supabase
        .from('orders')
        .select('order_id, total, customer_id, customer_name, payment_status, slip_url')
        .eq('line_user_id', userId)
        .eq('payment_method', 'transfer')
        .in('payment_status', ['pending_slip', 'slip_mismatch'])
        .order('created_at', { ascending: false })
        .limit(1);

      const amtOrder = amtOrders?.[0];
      if (amtOrder) {
        const expectedTotal = Number(amtOrder.total) || 0;
        const diff = expectedTotal - amountTyped;
        const now  = new Date().toISOString();

        // บันทึกแค่ "ยอดที่ลูกค้าแจ้ง" ไว้ให้แอดมินดูประกอบ — ไม่แตะ status/payment_status
        // ให้เป็น 'confirmed'/'paid' อัตโนมัติจากข้อความเปล่า ๆ นี้เด็ดขาด
        await supabase.from('orders').update({
          slip_amount: amountTyped
        }).eq('order_id', amtOrder.order_id);

        try {
          await supabase.from('messages').insert([{
            order_id: amtOrder.order_id, customer_id: amtOrder.customer_id,
            sender: 'system',
            text: `💬 ลูกค้าแจ้งยอดโอน ฿${amountTyped.toLocaleString()} ทาง LINE (ยังไม่มีสลิปแนบ — รอแอดมินตรวจสอบ manual)`,
            created_at: now
          }]);
        } catch(e) { console.warn('insert amount msg:', e.message); }

        // แจ้งลูกค้า: ให้แนบสลิปจริงผ่านหน้าเว็บเพื่อให้ระบบยืนยันอัตโนมัติ (ปลอดภัยกว่า)
        await safeReply(replyToken, userId, [{
          type: 'text',
          text: `📋 รับทราบยอด ฿${amountTyped.toLocaleString()} แล้วค่ะ (ออเดอร์ #${amtOrder.order_id})\n\nกรุณาแนบรูปสลิปตัวจริงผ่านหน้าร้าน เพื่อให้ระบบตรวจสอบและยืนยันอัตโนมัติได้เลยนะคะ 🙏\n\n👉 กดปุ่ม "สั่งสินค้า" ในเมนู → เลือก "ออเดอร์ของฉัน" → แนบสลิป`
        }]);

        // แจ้งแอดมินให้ตรวจสอบเอง (ไม่ auto-confirm จากข้อความพิมพ์)
        notifyAllAdmins([{
          type: 'text',
          text: `💬 ลูกค้าพิมพ์แจ้งยอดทาง LINE (ไม่มีสลิป) #${amtOrder.order_id}\nชื่อ: ${amtOrder.customer_name}\nยอดที่แจ้ง: ฿${amountTyped.toLocaleString()}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}${diff !== 0 ? `\nส่วนต่าง: ฿${Math.abs(diff).toFixed(2)}` : ''}\n⚠️ ยังไม่มีรูปสลิปยืนยัน — กรุณาตรวจสอบก่อนกด "ยืนยันชำระแล้ว" ใน Admin Panel`
        }]).catch(() => {});
        continue;
      }
    }

    // อัปเดต LINE user_id ในออเดอร์ทั้งหมดที่มีเบอร์ตรงกัน (ผูกอัตโนมัติเมื่อพิมพ์เบอร์)
    // ตรวจว่า text เป็นเบอร์โทรไหม (8-12 หลัก)
    // 🐛 FIX: ต้องเช็คว่าข้อความ "หน้าตาเป็นเบอร์โทรจริงๆ" ก่อน
    // เดิม normalizePhone ดึงตัวเลขจากทั้งข้อความ ทำให้ข้อความสั่งสินค้า
    // เช่น "ถ้วย TB45= 1 ถุง 7*15 = 1" มีตัวเลขรวม 8-12 หลัก → หลงเข้าโหมดค้นหาเบอร์
    // เงื่อนไขใหม่: หลังตัดคำนำหน้า (เบอร์/tel) แล้ว ต้องเหลือแต่ ตัวเลข ช่องว่าง - . ( ) + เท่านั้น
    const phoneOnly = normalizePhone(rawText);
    const looksLikePhone = rawText.trim()
      .replace(/^(เบอร์โทรศัพท์|เบอร์โทร|เบอร์|โทร|tel\.?|phone)[\s:：]*/i, '')
      .replace(/[\d\s\-\.\(\)\+]/g, '') === '';
    if (looksLikePhone && phoneOnly.length >= 8 && phoneOnly.length <= 12 && /^\d+$/.test(phoneOnly)) {
      // จับคู่ออเดอร์ที่มีเบอร์นี้ → set line_user_id
      // ไม่ใช้ limit — ป้องกัน miss ออเดอร์เก่า
      const { data: matched, error: phoneQueryErr } = await supabase.from('orders')
        .select('order_id, phone, customer_name, status, total, customer_id')
        .order('created_at', { ascending: false });

      if (phoneQueryErr) {
        console.error('phone lookup DB error:', phoneQueryErr.message);
        await linePush(userId, [{ type:'text', text:'❌ ระบบค้นหาขัดข้อง กรุณาลองใหม่ค่ะ' }]).catch(() => {});
        continue;
      }

      // startsWith/endsWith รองรับทุกกรณี:
      // • ตรงเป๊ะ            : "0812345678" vs "0812345678" ✅
      // • มี/ไม่มี 0 นำหน้า  : "0812345678" vs "812345678"  ✅
      // • จำนวนหลักต่างกัน  : "1234567890" vs "123456789"  ✅
      const matches = (matched || []).filter(o => {
        const stored = normalizePhone(o.phone);
        if (!stored || stored.length < 8) return false;
        if (stored === phoneOnly) return true;
        const shorter = stored.length < phoneOnly.length ? stored : phoneOnly;
        const longer  = stored.length < phoneOnly.length ? phoneOnly : stored;
        return longer.startsWith(shorter) || longer.endsWith(shorter);
      });

      if (matches.length) {
        // อัปเดต line_user_id ให้ทุกออเดอร์ที่เบอร์ตรงกัน
        await supabase.from('orders')
          .update({ line_user_id: userId })
          .in('order_id', matches.map(o => o.order_id))
          .then(({ error }) => { if (error) console.warn('link line_user_id:', error.message); });

        // ดึงออเดอร์ล่าสุดเต็มข้อมูล (มี items) เพื่อส่ง Flex summary
        const { data: fullLatest } = await supabase.from('orders')
          .select('*')
          .eq('order_id', matches[0].order_id)
          .maybeSingle();

        // ตอบลูกค้าด้วย text+flex รวมกัน
        const replyMessages = [
          {
            type: 'text',
            text: `✅ ผูกบัญชีสำเร็จ คุณ ${matches[0].customer_name || ''}\n\n` +
                  `พบออเดอร์ทั้งหมด ${matches.length} รายการ\n\n` +
                  `📲 พิมพ์ "ออเดอร์" เพื่อดูทั้งหมด หรือดูออเดอร์ล่าสุดด้านล่าง 👇`
          }
        ];
        if (fullLatest && fullLatest.items?.length) {
          // ✨ ส่ง order summary + status flex พร้อมกัน (ไม่ต้องกดดูสถานะ)
          replyMessages.push(await buildOrderSummaryFlex(fullLatest));
          if (fullLatest.status && fullLatest.status !== 'pending') {
            replyMessages.push(await buildStatusUpdateFlex(fullLatest, fullLatest.status));
          }
        }

        // ✨ บันทึก customer_id ลง line_users เพื่อ auto-link ครั้งถัดไป
        const matchedCustomerId = matches[0].customer_id;
        if (matchedCustomerId) {
          supabase.from('line_users')
            .update({ customer_id: matchedCustomerId })
            .eq('user_id', userId)
            .then(null, () => {});
        }

        // ส่ง text ก่อนเสมอ (guaranteed) — ลูกค้าได้รับการยืนยันแน่นอน
        await linePush(userId, [replyMessages[0]])
          .catch(e => console.warn('push text failed:', e.message));

        // ส่ง Flex แยก (optional) — ถ้าพังก็ไม่กระทบข้อความหลัก
        if (replyMessages.length > 1) {
          await linePush(userId, replyMessages.slice(1))
            .catch(e => console.warn('push flex failed (non-critical):', e.message));
        }
        continue;
      } else {
        await linePush(userId, [{
          type: 'text',
          text: `🔍 ไม่พบออเดอร์ที่ใช้เบอร์ ${rawText}\n\n📌 กรุณาตรวจสอบ:\n• เบอร์ที่พิมพ์ตรงกับที่กรอกตอนสั่งไหม?\n• ลองพิมพ์เบอร์ให้ครบ 10 หลัก เช่น 0812345678\n\nหากยังไม่พบ กดลิงก์ด้านล่างเพื่อสั่งสินค้าใหม่ได้เลยค่ะ\n${SHOP_URL}`
        }]).catch(e => console.warn('push phone-notfound failed:', e.message));
        continue;
      }
    }

    // คำสั่ง: ออเดอร์ / order / สถานะ → ดูออเดอร์ของตัวเอง
    if (text.includes('ออเดอร์') || text.includes('order') || text.includes('สถานะ') || text.includes('status')) {
      // หาออเดอร์ที่ผูกกับ LINE user นี้ (ตรง)
      const { data: myOrders } = await supabase.from('orders')
        .select('*')
        .eq('line_user_id', userId)
        .not('items', 'is', null)
        .order('created_at', { ascending: false })
        .limit(10);

      // กรอง ghost orders ออก (ที่ items เป็น array ว่าง)
      let realOrders = (myOrders || []).filter(o =>
        Array.isArray(o.items) && o.items.length > 0
      );

      // ✨ FIX: ถ้าไม่พบ — fallback หา customer_id จาก LINK- ghost แล้วดึงออเดอร์
      if (!realOrders.length) {
        const { data: linkGhost } = await supabase.from('orders')
          .select('customer_id')
          .eq('line_user_id', userId)
          .like('order_id', 'LINK-%')
          .limit(1);

        if (linkGhost?.[0]?.customer_id) {
          const { data: cidOrders } = await supabase.from('orders')
            .select('*')
            .eq('customer_id', linkGhost[0].customer_id)
            .not('order_id', 'like', 'LINK-%')
            .not('order_id', 'like', 'LINE-%')
            .order('created_at', { ascending: false })
            .limit(10);

          const filtered = (cidOrders || []).filter(o =>
            Array.isArray(o.items) && o.items.length > 0
          );
          if (filtered.length) {
            // ✨ backfill line_user_id ให้ออเดอร์เหล่านี้ด้วย
            await supabase.from('orders')
              .update({ line_user_id: userId })
              .eq('customer_id', linkGhost[0].customer_id)
              .not('order_id', 'like', 'LINK-%')
              .then(null, () => {});
            realOrders = filtered;
          }
        }
      }

      if (!realOrders.length) {
        await safeReply(replyToken, userId, [{
          type: 'text',
          text: `📭 ยังไม่พบออเดอร์ของคุณในระบบ\n\n` +
                `🔗 วิธีผูกบัญชี: พิมพ์เบอร์โทรที่ใช้ตอนสั่งซื้อมาครับ\n` +
                `เช่น: 0812345678\n\n` +
                `หรือสั่งสินค้าได้ที่:\n${SHOP_URL}`
        }]);
        continue;
      }

      // แยกออเดอร์ใหม่ (กำลังดำเนินการ) vs ออเดอร์เก่า (เสร็จสิ้น/ยกเลิก)
      const DONE_STATUSES = ['done', 'cancelled'];
      const activeOrders = realOrders.filter(o => !DONE_STATUSES.includes(o.status));
      const historyOrders = realOrders.filter(o => DONE_STATUSES.includes(o.status));

      // ถ้าลูกค้าพิมพ์ "ประวัติ" → แสดงออเดอร์เก่าแทน
      const wantHistory = text.includes('ประวัติ') || text.includes('history') || text.includes('เก่า');
      const ordersToShow = wantHistory ? historyOrders : (activeOrders.length ? activeOrders : realOrders);

      // helper สร้าง bubble แต่ละออเดอร์
      const makeBubble = (o) => ({
        type:'bubble', size:'kilo',
        header: {
          type:'box', layout:'vertical',
          backgroundColor: statusColor(o.status),
          paddingAll:'md',
          contents:[
            { type:'text', text:`${getStatusEmoji(o.status)} ${STATUS_LABELS_TH[o.status]||o.status}`, color:'#ffffff', size:'sm', weight:'bold' },
            { type:'text', text:`#${o.order_id}`, color:'#ffffff', size:'xs', margin:'xs' }
          ]
        },
        body: {
          type:'box', layout:'vertical', spacing:'sm', paddingAll:'md',
          contents: [
            ...((o.items||[]).slice(0,3).map(i => ({
              type:'text',
              text:`${i.emoji||'•'} ${i.name} ×${i.qty}`,
              size:'xs', color:'#555555', wrap:true
            }))),
            ...((o.items||[]).length > 3 ? [{ type:'text', text:`+${o.items.length-3} รายการ`, size:'xxs', color:'#888888' }] : []),
            { type:'separator', margin:'md' },
            { type:'box', layout:'horizontal', margin:'md',
              contents:[
                { type:'text', text:'รวม', size:'xs', color:'#888888', flex:1 },
                { type:'text', text:`฿${(o.total||0).toLocaleString()}`, size:'sm', color:'#C0392B', weight:'bold', align:'end', flex:2 }
              ]
            },
            { type:'text', text: new Date(o.created_at).toLocaleString('th-TH', { dateStyle:'short', timeStyle:'short', timeZone:'Asia/Bangkok' }), size:'xxs', color:'#aaaaaa', margin:'xs' }
          ]
        },
        footer: {
          type:'box', layout:'vertical', paddingAll:'md', paddingTop:'none',
          contents:[
            { type:'button', style:'primary', color:'#C0392B', height:'sm',
              action:{ type:'postback', label:'📋 ดูรายละเอียด',
                       data:`action=view_order&id=${o.order_id}`,
                       displayText:`📋 ดูรายละเอียด #${o.order_id}` }
            }
          ]
        }
      });

      const bubbles = ordersToShow.slice(0, 10).map(makeBubble);

      // สร้างข้อความ header
      const customerName = realOrders[0].customer_name || '';
      let headerText = '';
      if (wantHistory) {
        headerText = `📜 ประวัติออเดอร์ของคุณ ${customerName} (${historyOrders.length} รายการ)`;
      } else if (activeOrders.length) {
        const todayTH = new Date().toLocaleDateString('th-TH', { dateStyle:'short', timeZone:'Asia/Bangkok' });
        const todayOrders = activeOrders.filter(o => new Date(o.created_at).toLocaleDateString('th-TH', { dateStyle:'short', timeZone:'Asia/Bangkok' }) === todayTH);
        if (todayOrders.length > 0) {
          headerText = `📋 ออเดอร์ล่าสุดวันนี้ ${customerName} (${todayOrders.length} รายการ)`;
        } else {
          headerText = `📋 ออเดอร์ล่าสุด ${customerName} (${activeOrders.length} รายการ)`;
        }
      } else {
        headerText = `📋 ออเดอร์ของคุณ ${customerName} (${realOrders.length} รายการล่าสุด)`;
      }

      const replyMsgs = [
        { type:'text', text: headerText },
        {
          type:'flex',
          altText: headerText,
          contents:{ type:'carousel', contents: bubbles }
        }
      ];

      // ถ้ามีประวัติออเดอร์เก่า และตอนนี้กำลังดูออเดอร์ปัจจุบัน → แสดงปุ่ม popup ถามว่าอยากดูประวัติไหม
      if (!wantHistory && historyOrders.length > 0) {
        replyMsgs.push({
          type:'flex',
          altText:`มีประวัติออเดอร์เก่า ${historyOrders.length} รายการ — ดูประวัติไหม?`,
          contents:{
            type:'bubble', size:'kilo',
            body:{
              type:'box', layout:'vertical', paddingAll:'lg', spacing:'sm',
              contents:[
                { type:'text', text:'📜 ประวัติออเดอร์', weight:'bold', size:'md', color:'#333333' },
                { type:'text', text:`คุณมีออเดอร์ที่เสร็จสิ้นแล้ว ${historyOrders.length} รายการ`, size:'sm', color:'#888888', wrap:true, margin:'sm' }
              ]
            },
            footer:{
              type:'box', layout:'vertical', paddingAll:'lg', paddingTop:'none',
              contents:[
                { type:'button', style:'secondary', height:'sm',
                  action:{
                    type:'postback',
                    label:'📜 ดูประวัติออเดอร์',
                    data:'action=view_history',
                    displayText:'📜 ดูประวัติออเดอร์'
                  }
                }
              ]
            }
          }
        });
      }

      await safeReply(replyToken, userId, replyMsgs);
      continue;
    }

    // คำสั่ง: id → ส่ง LINE User ID กลับให้ลูกค้า (เพื่อให้แอดมินผูกบัญชีได้)
    if (text === 'id' || text === 'my id' || text === 'userid' || text === 'user id' || text === 'ไอดี') {
      await safeReply(replyToken, userId, [{
        type: 'text',
        text: `🆔 LINE User ID ของคุณ:\n\n${userId}\n\n📋 คัดลอกและส่งให้ร้านค้าเพื่อผูกบัญชีค่ะ`
      }]);
      continue;
    }

        // คำสั่ง: เปิดร้าน / shop / สั่ง / ซื้อ → ส่งลิงก์ shop พร้อม token
    if (text === 'เปิดร้าน' || text === 'shop' || text === 'สั่ง' || text === 'ซื้อ' || text === 'สั่งซื้อ' || text === 'เปิด' || text === 'ร้าน'|| text === 'ผูกบัญชี(สั่งสินค้า)'|| text === 'ผูกบัญชี'|| text === 'สั่งสินค้า') {
      const token = createLinkToken(userId);
      const shopLink = `${SHOP_URL}?lid=${token}`;
      await safeReply(replyToken, userId, [{
        type: 'text',
        text: `🛍 กดลิงก์ด้านล่างเพื่อสั่งสินค้า ระบบจะจดจำคุณอัตโนมัติ\n\n${shopLink}\n\n⏰ ลิงก์มีอายุ 30 นาที`
      }]);
      continue;
    }

    // คำสั่ง: help / ช่วยเหลือ / เริ่มต้น
    if (text.includes('help') || text.includes('ช่วย') || text === 'เริ่ม' || text === 'start' || text === 'menu' || text === 'เมนู') {
      const token = createLinkToken(userId);
      const shopLink = `${SHOP_URL}?lid=${token}`;
      await safeReply(replyToken, userId, [{
        type: 'text',
        text: `🛍 สวัสดีค่ะ! ใช้งานได้ดังนี้:\n\n` +
              `🛒 สั่งสินค้า → ${shopLink}\n` +
              `📦 พิมพ์ "ออเดอร์" → ดูสถานะออเดอร์\n` +
              `🔗 พิมพ์เบอร์โทร → ผูกออเดอร์เก่า\n` +
              `📲 พิมพ์ "เปิดร้าน/ผูกบัญชี(สั่งสินค้า)/ผูกบัญชี/สั่งสินค้า" → รับลิงก์ใหม่\n\n` +
              `ถ้ามีคำถาม พิมพ์มาได้เลย — ร้านจะตอบในแชทค่ะ 💬`
      }]);
      continue;
    }

    // ข้อความอื่นๆ: forward ไปแอดมิน + บันทึกในแชท (ถ้าผูกบัญชีแล้ว)
    // ✨ FIX Bug 3: กรองออกทั้ง LINE-% และ LINK-% ghost — นับเฉพาะออเดอร์จริง
    const { data: linkedOrders } = await supabase.from('orders')
      .select('order_id, customer_id, customer_name')
      .eq('line_user_id', userId)
      .not('order_id', 'like', 'LINE-%')
      .not('order_id', 'like', 'LINK-%')
      .order('created_at', { ascending: false })
      .limit(1);

    const latest = linkedOrders?.[0];

    // ดึงโปรไฟล์ LINE มาดูชื่อ (ถ้าไม่ได้ผูกบัญชี)
    let displayName = latest?.customer_name || 'ลูกค้า LINE';
    if (!latest) {
      try {
        const profRes = await fetch(`https://api.line.me/v2/bot/profile/${userId}`, {
          headers: { 'Authorization': `Bearer ${process.env.LINE_TOKEN}` }
        });
        if (profRes.ok) {
          const profile = await profRes.json();
          if (profile.displayName) displayName = profile.displayName;
        }
      } catch(e) { /* ignore */ }
    }

    // บันทึกข้อความลูกค้าลง messages
    // - ถ้ามีออเดอร์: ผูกกับ order_id ล่าสุด
    // - ถ้าไม่มี: ใช้ thread_id แบบ LINE-{userId} เพื่อให้ admin ยังเห็นได้
    const threadOrderId = latest?.order_id || `LINE-${userId.slice(0,16)}`;
    const threadCustomerId = latest?.customer_id || `LINE-${userId.slice(0,16)}`;

    await supabase.from('messages').insert([{
      order_id   : threadOrderId,
      customer_id: threadCustomerId,
      sender     : 'customer',
      text       : rawText,
      created_at : new Date().toISOString()
    }]).then(({ error }) => { if (error) console.warn('insert msg:', error.message); });

    // ✨ FIX: ถ้ายังไม่มีออเดอร์จริง → สร้าง ghost เฉพาะถ้ายังไม่มี LINK- ghost อยู่แล้ว
    if (!latest) {
      // ตรวจว่ามี LINK- ghost (ผูกบัญชีแล้วแต่ยังไม่สั่ง) ไหม — ถ้ามี ไม่ต้องสร้าง LINE- ซ้ำ
      const { data: linkGhost } = await supabase.from('orders')
        .select('order_id').eq('line_user_id', userId).like('order_id', 'LINK-%').limit(1);

      if (!linkGhost?.length) {
        // ยังไม่ผูกบัญชีเลย → สร้าง LINE- ghost ให้แอดมินเห็นแชท
        await supabase.from('orders').upsert([{
          order_id     : threadOrderId,
          customer_id  : threadCustomerId,
          customer_name: displayName,
          line_user_id : userId,
          items        : [],
          total        : 0,
          status       : 'pending',
          created_at   : new Date().toISOString(),
          note         : '💬 แชทเข้ามาทาง LINE OA (ยังไม่มีออเดอร์)'
        }], { onConflict: 'order_id' }).then(({ error }) => {
          if (error) console.warn('upsert ghost order:', error.message);
        });
      } else {
        // มี LINK- ghost → อัปเดตชื่อ/ข้อความแทน
        await supabase.from('messages').upsert([{
          order_id   : linkGhost[0].order_id,
          customer_id: threadCustomerId,
          sender     : 'customer',
          text       : rawText,
          created_at : new Date().toISOString()
        }]).then(null, () => {});
      }
    }

    // ✨ แจ้งแอดมินเฉพาะลูกค้าที่มีออเดอร์จริง + ไม่ใช่ keyword auto-reply
    // *** ข้อความแชทธรรมดา (ไม่เกี่ยวกับออเดอร์/ผูกบัญชี) → ไม่แจ้งแอดมิน ***
    if (latest) {
      // ถ้าตรงกับ keyword auto-reply ของ LINE OA → ไม่แจ้ง (LINE OA ตอบให้แล้ว)
      if (isAutoReplyKeyword(rawText)) {
        console.log(`💬 ${displayName} ส่ง "${rawText.slice(0,30)}" ตรงกับ auto-reply keyword — ไม่แจ้งแอดมิน`);
      } else {
        // ไม่แจ้งแอดมินสำหรับข้อความแชทธรรมดา
        // (แอดมินจะเห็นในหน้า Admin Panel เอง ไม่ต้องรบกวน LINE)
        console.log(`💬 ${displayName} ส่งข้อความ (#${latest.order_id}) "${rawText.slice(0,30)}" — บันทึกใน Admin Panel (ไม่แจ้ง LINE)`);
      }
    } else {
      console.log(`💬 ${displayName} ทักเข้ามาใน LINE (ยังไม่มีออเดอร์) — ไม่แจ้งแอดมิน`);
    }

    // ✨ ไม่ตอบ auto-reply — ปล่อยให้แอดมินตอบเอง ลูกค้าจะไม่เห็น "ได้รับข้อความแล้ว..." spam
    // (ถ้าลูกค้าอยากเปิดร้าน/ดูออเดอร์ → กด Rich Menu หรือพิมพ์ keyword)
    } catch (evErr) {
      // ถ้า event ใดๆ crash → log + push error จริงๆ ให้เห็น
      const errMsg = evErr?.message || String(evErr);
      console.error('⚠️ webhook event error:', errMsg, '| userId:', userId, '| type:', ev.type, '| stack:', evErr?.stack);
      logError('webhook', evErr, { userId, evType: ev.type });
      if (userId) {
        linePush(userId, [{ type:'text', text:`❌ Error: ${errMsg.slice(0,200)}` }]).catch(() => {});
      }
      // แจ้ง admin ด้วยเพื่อ debug
      notifyAllAdmins([{ type:'text', text:`⚠️ Webhook error\nUser: ${userId}\nError: ${errMsg.slice(0,300)}` }]).catch(() => {});
    }
  }
});

// helper สำหรับ webhook
const STATUS_LABELS_TH = {
  pending  : '⏳ รอดำเนินการ',
  sent     : '📬 ร้านได้รับแล้ว',
  confirmed: '✅ ยืนยันแล้ว',
  shipped  : '🚚 กำลังจัดส่ง',
  done     : '🎉 เสร็จสิ้น',
  cancelled: '❌ ยกเลิก',
  failed   : '💥 ผิดพลาด'
};
function getStatusEmoji(s) {
  return ({
    pending:'⏳', sent:'📬', confirmed:'✅',
    shipped:'🚚', done:'🎉', cancelled:'❌', failed:'💥'
  })[s] || '📦';
}

// ══════════════════════════════════════════════════════════
//  COUPON / DISCOUNT SYSTEM
// ══════════════════════════════════════════════════════════

// ── helper: คำนวณส่วนลดจาก coupon ──────────────────────────
function calcDiscount(coupon, orderTotal) {
  if (!coupon || !coupon.is_active) return 0;
  if (coupon.min_order && orderTotal < coupon.min_order) return 0;
  if (coupon.discount_type === 'percent') {
    const d = (orderTotal * coupon.discount_value) / 100;
    return coupon.max_discount ? Math.min(d, coupon.max_discount) : d;
  }
  return Math.min(coupon.discount_value, orderTotal); // ไม่ลดจนติดลบ
}

// ── GET /applicable-discounts ─────────────────────────────
// ส่งคืน auto-discounts ที่ลูกค้านี้ใช้ได้ตอนนี้
app.get('/applicable-discounts', async (req, res) => {
  const { customerId, orderTotal } = req.query;
  if (!customerId) return res.status(400).json({ error: 'customerId required' });

  const total = parseFloat(orderTotal) || 0;
  const now   = new Date().toISOString();

  // ดึง auto-coupons ที่ active
  const { data: coupons, error } = await supabase
    .from('coupons')
    .select('*')
    .eq('is_active', true)
    .eq('apply_type', 'auto')
    .or(`start_date.is.null,start_date.lte.${now}`)
    .or(`end_date.is.null,end_date.gte.${now}`)
    .order('discount_value', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });

  // ตรวจ first_order
  let isFirstOrder = false;
  const { data: prevOrders } = await supabase
    .from('orders')
    .select('id')
    .eq('customer_id', customerId)
    .not('order_id', 'like', 'LINE-%')
    .not('order_id', 'like', 'LINK-%')
    .limit(1);
  isFirstOrder = !prevOrders?.length;

  // กรอง coupons ตาม condition + usage_limit
  const eligible = (coupons || []).filter(c => {
    if (c.usage_limit !== null && c.used_count >= c.usage_limit) return false;
    if (c.condition_type === 'first_order') return isFirstOrder;
    return true; // 'always' or null
  });

  // เลือก coupon เดียวที่ให้ส่วนลดมากสุด
  let best = null;
  let bestDiscount = 0;
  for (const c of eligible) {
    const d = calcDiscount(c, total || 1); // ใช้ 1 ถ้ายังไม่รู้ total
    if (d > bestDiscount) { best = c; bestDiscount = d; }
  }

  // ตรวจว่ามี manual coupon active อยู่หรือไม่ (เพื่อให้ frontend แสดง/ซ่อน input field)
  const { data: manualCoupons } = await supabase
    .from('coupons')
    .select('id')
    .eq('is_active', true)
    .eq('apply_type', 'manual')
    .or(`start_date.is.null,start_date.lte.${now}`)
    .or(`end_date.is.null,end_date.gte.${now}`)
    .limit(1);
  const hasManualCoupon = !!(manualCoupons?.length);

  res.json({ isFirstOrder, discount: best, allEligible: eligible, hasManualCoupon });
});

// ── GET /validate-coupon ──────────────────────────────────
// ตรวจสอบ manual coupon code ที่ลูกค้ากรอก
app.get('/validate-coupon', rateLimit(20), async (req, res) => {
  const { code, customerId, orderTotal, phone } = req.query;
  if (!code) return res.status(400).json({ error: 'กรุณากรอกรหัสคูปอง' });

  const total = parseFloat(orderTotal) || 0;
  const now   = new Date().toISOString();

  // 🔒 SECURITY FIX: เดิมใช้ .ilike('code', code.trim()) — ilike ตีความ % และ _ เป็น wildcard
  // เสมอโดยไม่ escape ค่าที่ลูกค้าพิมพ์มาก่อน ทำให้ส่ง code=% เข้ามาแล้วได้คูปอง manual
  // ตัวใดตัวหนึ่งกลับไปโดยไม่ต้องรู้รหัสจริงเลย — เปลี่ยนเป็น .eq() แบบตรงตัว (โค้ดฝั่งหน้าเว็บ
  // แปลงเป็นตัวพิมพ์ใหญ่ก่อนส่งอยู่แล้วเสมอ จึงไม่กระทบการใช้งานปกติ) + ใส่ rate limit กันยิงถล่ม
  const codeNorm = code.trim().toUpperCase();
  // หา coupon ที่ตรงกับ code
  const { data: coupon, error } = await supabase
    .from('coupons')
    .select('*')
    .eq('is_active', true)
    .eq('apply_type', 'manual')
    .eq('code', codeNorm)
    .or(`start_date.is.null,start_date.lte.${now}`)
    .or(`end_date.is.null,end_date.gte.${now}`)
    .maybeSingle();

  if (error) return res.status(500).json({ error: error.message });
  if (!coupon) return res.status(404).json({ error: 'ไม่พบคูปองนี้ หรือคูปองหมดอายุแล้ว' });

  // ตรวจ usage_limit
  if (coupon.usage_limit !== null && coupon.used_count >= coupon.usage_limit)
    return res.status(400).json({ error: 'คูปองนี้ถูกใช้ครบจำนวนแล้ว' });

  // ตรวจ min_order
  if (coupon.min_order > 0 && total < coupon.min_order)
    return res.status(400).json({ error: `ต้องสั่งขั้นต่ำ ฿${coupon.min_order.toLocaleString()} ถึงจะใช้คูปองนี้ได้`, coupon });

  // ตรวจ first_order condition
  if (coupon.condition_type === 'first_order' && customerId) {
    const { data: prev } = await supabase
      .from('orders').select('id').eq('customer_id', customerId)
      .not('order_id', 'like', 'LINE-%').not('order_id', 'like', 'LINK-%').limit(1);
    if (prev?.length)
      return res.status(400).json({ error: 'คูปองนี้สำหรับการสั่งซื้อครั้งแรกเท่านั้น' });
  }

  // 🔒 ตรวจว่า LINE UID หรือเบอร์โทรนี้เคยใช้คูปองนี้ไปแล้วหรือยัง
  if (customerId) {
    // หา LINE UID จาก LINK- row หรือ line_users
    let lineUidForValidate = null;
    const linkRowId = `LINK-${customerId.slice(0, 20)}`;
    const { data: linkRow } = await supabase.from('orders')
      .select('line_user_id').eq('order_id', linkRowId)
      .not('line_user_id', 'is', null).maybeSingle();
    if (linkRow?.line_user_id) lineUidForValidate = linkRow.line_user_id;

    if (!lineUidForValidate) {
      const { data: luRow } = await supabase.from('line_users')
        .select('user_id').eq('customer_id', customerId)
        .order('last_seen', { ascending: false }).limit(1).maybeSingle();
      if (luRow?.user_id) lineUidForValidate = luRow.user_id;
    }

    if (lineUidForValidate) {
      const { data: usageByUid } = await supabase.from('coupon_usages')
        .select('id').eq('coupon_id', coupon.id).eq('line_user_id', lineUidForValidate)
        .limit(1).maybeSingle();
      if (usageByUid)
        return res.status(400).json({ error: 'คูปองนี้ถูกใช้ไปแล้วในบัญชีของคุณ' });
    }

    const normPhone = String(phone || '').replace(/\D/g, '');
    if (normPhone) {
      const { data: usageByPhone } = await supabase.from('coupon_usages')
        .select('id').eq('coupon_id', coupon.id).eq('phone', normPhone)
        .limit(1).maybeSingle();
      if (usageByPhone)
        return res.status(400).json({ error: 'คูปองนี้ถูกใช้ไปแล้วในบัญชีของคุณ' });
    }
  }

  const discount = calcDiscount(coupon, total);
  res.json({ success: true, coupon, discountAmount: discount });
});

// ── GET /coupons (admin) ──────────────────────────────────
// 🔴 SECURITY FIX (สำคัญมาก): เดิม route นี้ไม่มี requirePerm เลย ทั้งที่ POST/PATCH/DELETE
// ของ /coupons ตัวเดียวกันมีครบ — ใครก็ยิง GET เข้ามาได้เลยแล้วได้โค้ดคูปองลับ (secret_code)
// ของคูปองทุกใบออกไปตรงๆ โดยไม่ต้องเดา/ผ่านการตรวจสอบใดๆ เลย
app.get('/coupons', requirePerm('coupons'), async (req, res) => {
  const { data, error } = await supabase
    .from('coupons')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ coupons: data || [] });
});

// ── POST /coupons (admin) ─────────────────────────────────
app.post('/coupons', requirePerm('coupons'), async (req, res) => {
  const {
    name, description, code, discount_type, discount_value,
    max_discount, min_order, apply_type, condition_type,
    start_date, end_date, usage_limit, is_active
  } = req.body;

  if (!name || discount_value == null)
    return res.status(400).json({ error: 'name และ discount_value จำเป็น' });

  const { data, error } = await supabase.from('coupons').insert([{
    name, description: description || null,
    code: code || null,
    discount_type: discount_type || 'fixed',
    discount_value: Number(discount_value),
    max_discount: max_discount ? Number(max_discount) : null,
    min_order: Number(min_order || 0),
    apply_type: apply_type || 'auto',
    condition_type: condition_type || null,
    start_date: start_date || null,
    end_date: end_date || null,
    usage_limit: usage_limit ? Number(usage_limit) : null,
    is_active: is_active !== false
  }]).select().single();

  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, coupon: data });
});

// ── PATCH /coupons/:id (admin) ────────────────────────────
app.patch('/coupons/:id', requirePerm('coupons'), async (req, res) => {
  const id = parseInt(req.params.id);
  const updates = {};
  const fields = [
    'name','description','code','discount_type','discount_value',
    'max_discount','min_order','apply_type','condition_type',
    'start_date','end_date','usage_limit','is_active'
  ];
  fields.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });

  const { data, error } = await supabase
    .from('coupons').update(updates).eq('id', id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, coupon: data });
});

// ── DELETE /coupons/:id (admin) ───────────────────────────
app.delete('/coupons/:id', requirePerm('coupons'), async (req, res) => {
  const id = parseInt(req.params.id);
  const { error } = await supabase.from('coupons').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// ── GET /orders (admin) ──────────────────────────────────
// 🔴 SECURITY FIX (สำคัญมาก): เดิม route นี้ไม่มี requirePerm เลย ทั้งที่ endpoint จัดการ
// ออเดอร์ตัวอื่นๆ (เช่น /orders/:orderId/notify-status, /orders/:orderId/status) มี
// requirePerm('orders') ครบ — ใครก็ยิง GET /orders?limit=5000 เข้ามาได้เลยแล้วได้ฐานข้อมูล
// ลูกค้าทั้งหมด (ชื่อ/เบอร์/ที่อยู่/สถานะจ่ายเงิน) ออกไปตรงๆ โดยไม่ต้องผ่านการตรวจสอบใดๆ เลย
app.get('/orders', requirePerm('orders'), async (req, res) => {
  const limit  = parseInt(req.query.limit)  || 100;
  const offset = parseInt(req.query.offset) || 0;
  const { data, error, count } = await supabase
    .from('orders')
    .select('*', { count: 'exact' })
    // ✨ ซ่อน LINK- rows — mapping record ไม่ใช่ออเดอร์จริง
    .not('order_id', 'like', 'LINK-%')
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ total: count, orders: data });
});

// ── POST /orders/:orderId/notify-status ───────────────────
// Admin กด "📣 ส่งสถานะ" → ส่ง LINE Flex ให้ลูกค้าโดยไม่อัปเดต DB ซ้ำ
app.post('/orders/:orderId/notify-status', requirePerm('orders'), async (req, res) => {
  const { orderId } = req.params;

  const { data: order, error } = await supabase
    .from('orders').select('*').eq('order_id', orderId).maybeSingle();

  if (error) return res.status(500).json({ error: error.message });
  if (!order) return res.status(404).json({ error: 'ไม่พบออเดอร์ ' + orderId });

  if (!process.env.LINE_TOKEN) {
    return res.status(500).json({ error: 'LINE_TOKEN ไม่ได้ตั้งค่า' });
  }

  // หา LINE user ID จาก order หรือ customer
  let targetUid = order.line_user_id;
  if (!targetUid) {
    targetUid = await findLineUserIdByCustomer(order.customer_id);
  }
  if (!targetUid) {
    return res.status(400).json({ error: 'ไม่พบ LINE user ของลูกค้ารายนี้ (ยังไม่ได้ผูกบัญชี)' });
  }

  try {
    const flex = await buildStatusUpdateFlex(order, order.status);
    await linePush(targetUid, [flex]);
    console.log(`📣 notify-status ${order.status} → ${targetUid.slice(0,12)}…`);
    res.json({ success: true, status: order.status, sentTo: targetUid.slice(0,12) + '…' });
  } catch (e) {
    console.warn('notify-status push failed:', e.message);
    res.status(500).json({ error: 'ส่ง LINE ไม่ได้: ' + e.message });
  }
});

// ── PATCH /orders/:orderId/status ─────────────────────────
app.patch('/orders/:orderId/status', requirePerm('orders'), async (req, res) => {
  const { status } = req.body;
  const allowed = ['pending', 'sent', 'confirmed', 'shipped', 'done', 'cancelled', 'failed'];
  if (!allowed.includes(status))
    return res.status(400).json({ error: `status must be: ${allowed.join(', ')}` });

  const { data, error } = await supabase
    .from('orders').update({ status }).eq('order_id', req.params.orderId)
    .select().single();
  if (error) return res.status(500).json({ error: error.message });

  if (data) {
    // 1) บันทึก system message ในแชทเว็บ
    try {
      await supabase.from('messages').insert([{
        order_id   : data.order_id,
        customer_id: data.customer_id,
        sender     : 'system',
        text       : `📦 ออเดอร์ #${data.order_id} อัปเดตสถานะ: ${statusLabel(status)}`,
        created_at : new Date().toISOString()
      }]);
    } catch(e) { console.error(e); }

    // 2) ส่ง LINE Flex Message หาลูกค้า
    if (process.env.LINE_TOKEN) {
      // ใช้ line_user_id โดยตรงจาก order ก่อน — fallback ไปหาจาก customer_id
      let targetUid = data.line_user_id;
      if (!targetUid) {
        targetUid = await findLineUserIdByCustomer(data.customer_id);
      }
      if (targetUid) {
        const flex = await buildStatusUpdateFlex(data, status);
        linePush(targetUid, [flex])
          .then(() => console.log(`📤 status flex → ${targetUid.slice(0,12)}…`))
          .catch(e => console.warn('LINE flex push failed:', e.message));
      }
    }
  }

  res.json({ success: true, order: data });
});

// ═══════════════════════════════════════════════════════════
//  REFERRAL SYSTEM
// ═══════════════════════════════════════════════════════════

// ── GET /referral-config ────────────────────────────────────
// อ่าน config ระบบชวนเพื่อน (แอดมิน)
app.get('/referral-config', async (req, res) => {
  const { data, error } = await supabase
    .from('settings')
    .select('value')
    .eq('key', 'referral_config')
    .maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  const defaults = {
    referral_reward_type : 'fixed',
    referral_reward_value: 50,
    referral_max_rewards : 0,
    referral_expire_days : 30
  };
  res.json(data ? { ...defaults, ...data.value } : defaults);
});

// ── POST /referral-config ───────────────────────────────────
// บันทึก config ระบบชวนเพื่อน (แอดมิน)
app.post('/referral-config', requirePerm('shop_settings'), async (req, res) => {
  const cfg = {
    referral_reward_type : req.body.referral_reward_type  || 'fixed',
    referral_reward_value: parseFloat(req.body.referral_reward_value) || 50,
    referral_max_rewards : parseInt(req.body.referral_max_rewards)    || 0,
    referral_expire_days : parseInt(req.body.referral_expire_days)    || 30,
  };
  const { error } = await supabase
    .from('settings')
    .upsert({ key: 'referral_config', value: cfg }, { onConflict: 'key' });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, config: cfg });
});

// ── GET /shop-hours ──────────────────────────────────────────
// อ่านเวลาทำการร้าน (ลูกค้าและแอดมินใช้)
app.get('/shop-hours', async (req, res) => {
  const { data, error } = await supabase
    .from('settings')
    .select('value')
    .eq('key', 'shop_hours')
    .maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  const defaults = {
    enabled: false,
    openTime: '09:00',
    closeTime: '18:00',
    openDays: [1,2,3,4,5,6],
    msgOpen: 'ยินดีต้อนรับค่ะ! 🎉 ร้านเปิดให้บริการอยู่นะคะ',
    msgClosed: 'ขณะนี้ร้านปิดให้บริการแล้วค่ะ 🌙\nทางร้านจะจัดส่งสินค้าให้วันพรุ่งนี้เช้านะคะ ✨\nขอบคุณที่อุดหนุนร้านเรานะคะ 🙏',
    showBanner: true,
    showPopup: true,
    popupOnce: true
  };
  res.json(data ? { ...defaults, ...data.value } : defaults);
});

// ── POST /shop-hours ─────────────────────────────────────────
// บันทึกเวลาทำการร้าน (แอดมิน)
app.post('/shop-hours', requirePerm('shop_settings'), async (req, res) => {
  const cfg = {
    enabled   : !!req.body.enabled,
    openTime  : req.body.openTime  || '09:00',
    closeTime : req.body.closeTime || '18:00',
    openDays  : Array.isArray(req.body.openDays) ? req.body.openDays : [1,2,3,4,5,6],
    msgOpen   : req.body.msgOpen   || '',
    msgClosed : req.body.msgClosed || '',
    showBanner: !!req.body.showBanner,
    showPopup : !!req.body.showPopup,
    popupOnce : !!req.body.popupOnce
  };
  const { error } = await supabase
    .from('settings')
    .upsert({ key: 'shop_hours', value: cfg }, { onConflict: 'key' });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, config: cfg });
});

// ── GET /qr-config ───────────────────────────────────────────
// อ่านการตั้งค่า QR โอนเงิน (ลูกค้าและแอดมินใช้)
app.get('/qr-config', async (req, res) => {
  const { data, error } = await supabase
    .from('settings')
    .select('value')
    .eq('key', 'qr_config')
    .maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  const defaults = { enabled: false, promptpay_number: '', account_name: '', qr_image_url: '', note: '' };
  res.json(data ? { ...defaults, ...data.value } : defaults);
});

// ── POST /qr-config ──────────────────────────────────────────
// บันทึกการตั้งค่า QR โอนเงิน (แอดมิน)
app.post('/qr-config', requirePerm('shop_settings'), async (req, res) => {
  const cfg = {
    enabled          : !!req.body.enabled,
    promptpay_number : String(req.body.promptpay_number  || '').trim(),
    account_name     : String(req.body.account_name      || '').trim(),
    qr_image_url     : String(req.body.qr_image_url      || '').trim(),
    note             : String(req.body.note              || '').trim(),
  };
  const { error } = await supabase
    .from('settings')
    .upsert({ key: 'qr_config', value: cfg }, { onConflict: 'key' });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, config: cfg });
});

// ── GET /hero-banner ─────────────────────────────────────────
// ป้ายโฆษณาหน้าร้าน (ลูกค้าและแอดมินใช้)
app.get('/hero-banner', async (req, res) => {
  const { data, error } = await supabase
    .from('settings')
    .select('value')
    .eq('key', 'hero_banner')
    .maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  const defaults = { enabled: false, autoplaySec: 5, items: [] };
  res.json(data ? { ...defaults, ...data.value } : defaults);
});

// ── POST /hero-banner ────────────────────────────────────────
// บันทึกป้ายโฆษณาหน้าร้าน (แอดมิน)
app.post('/hero-banner', requirePerm('shop_settings'), async (req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items.slice(0, 10).map(it => ({
    type    : ['image', 'video', 'youtube'].includes(it.type) ? it.type : 'image',
    url     : String(it.url || '').slice(0, 1000),
    caption : String(it.caption || '').slice(0, 200),
    link    : String(it.link || '').slice(0, 1000)
  })).filter(it => it.url) : [];
  const cfg = {
    enabled     : !!req.body.enabled,
    autoplaySec : Math.min(30, Math.max(2, parseInt(req.body.autoplaySec) || 5)),
    items
  };
  const { error } = await supabase
    .from('settings')
    .upsert({ key: 'hero_banner', value: cfg }, { onConflict: 'key' });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, config: cfg });
});

// ── helper: ดึงรูปจาก URL (เช่น Cloudinary) มาเป็น base64 — ใช้ตรวจสลิปซ้ำที่ server ──
// 🔴 SECURITY FIX (SSRF): เดิมฟังก์ชันนี้ fetch() URL อะไรก็ได้ที่ client ส่งมาใน slip_url
// ตรงๆ โดยไม่ตรวจสอบเลย — flow ที่ถูกต้องจริงคือรูปอัปโหลดจากเบราว์เซอร์ไป Cloudinary ก่อน
// แล้วได้ URL บนโดเมน res.cloudinary.com กลับมาเท่านั้น (ดู index.html ตอนอัปโหลดสลิป) แต่
// ถ้าใครเรียก POST /submit-slip ตรงๆ (ข้ามเบราว์เซอร์) ใส่ slip_url เป็น URL ภายในองค์กร/
// cloud metadata endpoint (เช่น http://169.254.169.254/...) หรือ URL ใดๆ ก็ได้ เซิร์ฟเวอร์จะ
// ยิง request ออกไปให้ทันที (Server-Side Request Forgery) — ใช้สอดแนม/โจมตีเครือข่ายภายใน
// ของเซิร์ฟเวอร์เองได้ — แก้โดยอนุญาตเฉพาะ URL ที่เป็น https บนโดเมน res.cloudinary.com เท่านั้น
const ALLOWED_IMAGE_HOSTS = ['res.cloudinary.com'];
function isAllowedImageUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && ALLOWED_IMAGE_HOSTS.includes(u.hostname);
  } catch (_) { return false; }
}
async function fetchImageAsBase64(url) {
  if (!isAllowedImageUrl(url)) throw new Error('slip_url ไม่ได้มาจากแหล่งที่เชื่อถือได้');
  const r = await fetch(url, { timeout: 15000 });
  if (!r.ok) throw new Error(`fetch image failed: ${r.status}`);
  const buf = await r.buffer();
  return buf.toString('base64');
}

// ── shared: รัน OCR สลิป (preprocess ด้วย sharp + tesseract) แล้วดึงยอดเงิน/วันที่-เวลา/
// เลขอ้างอิง/hash ของรูป ออกมาให้ครบในครั้งเดียว ใช้ร่วมกันทั้ง /read-slip (prefill ให้ลูกค้า)
// และ /submit-slip (ตรวจยืนยันอิสระที่ server — ไม่พึ่งยอดที่ client พิมพ์มาอย่างเดียวอีกต่อไป)
async function runSlipOCR(base64) {
  const crypto    = require('crypto');
  const tesseract = require('node-tesseract-ocr');
  const os   = require('os');
  const path = require('path');
  const fs   = require('fs');

  const b64Raw    = base64.replace(/^data:image\/\w+;base64,/, '');
  const imageHash = crypto.createHash('sha256').update(b64Raw, 'base64').digest('hex');
  const rnd       = Math.random().toString(36).slice(2);
  const tmpOrig   = path.join(os.tmpdir(), `slip_orig_${Date.now()}_${rnd}.jpg`);
  const tmpProc   = path.join(os.tmpdir(), `slip_proc_${Date.now()}_${rnd}.png`);

  try {
    fs.writeFileSync(tmpOrig, Buffer.from(b64Raw, 'base64'));

    let processedFile = tmpOrig;
    try {
      const sharp = require('sharp');
      await sharp(tmpOrig)
        .resize({ width: 1200, withoutEnlargement: false })
        .grayscale()
        .normalise()
        .sharpen()
        .threshold(128)
        .png()
        .toFile(tmpProc);
      processedFile = tmpProc;
    } catch (sharpErr) {
      console.warn('sharp preprocess failed, using original:', sharpErr.message);
    }

    const config  = { lang: 'tha+eng', oem: 1, psm: 6 };
    const rawText = await tesseract.recognize(processedFile, config);
    fs.unlink(tmpOrig, () => {});
    fs.unlink(tmpProc, () => {});

    if (!rawText || !rawText.trim()) {
      return { rawText: '', amount: null, datetime: null, dateRaw: null, ref: null, imageHash };
    }

    const amount   = extractAmountFromSlip(rawText);
    const dateInfo = extractSlipDateTime(rawText);
    const ref      = extractSlipRef(rawText);

    return { rawText, amount, datetime: dateInfo.iso, dateRaw: dateInfo.raw, ref, imageHash };
  } catch (e) {
    try { fs.unlinkSync(tmpOrig); } catch (_) {}
    try { fs.unlinkSync(tmpProc); } catch (_) {}
    throw e;
  }
}

// ── POST /submit-slip ────────────────────────────────────────
// ลูกค้าส่งสลิป + ยอดที่โอน → ระบบตรวจสอบ "อิสระจากฝั่ง client" ด้วยการรัน OCR ซ้ำที่
// server จากรูปสลิปจริง (ไม่เชื่อยอดที่พิมพ์มาเฉยๆ อีกต่อไป — กันคนพิมพ์ยอดหลอกทั้งที่ไม่ได้โอนจริง)
// เพิ่มการตรวจ 3 ชั้น:
//   1) ยอดเงิน — อ่านจากรูปจริงที่ server เอง ไม่ใช่ตัวเลขที่ client ส่งมา
//   2) วันที่/เวลาในสลิป — ต้องไม่เก่า/ไม่ล่วงหน้าเกินไป (กันเอาสลิปเก่ามาใช้ซ้ำ)
//   3) สลิปซ้ำ — เทียบ hash ของรูป และเลขอ้างอิงรายการ กับออเดอร์อื่นทั้งหมด
// หมายเหตุสำคัญ: นี่คือการตรวจด้วย OCR (ฟรี ไม่พึ่ง API เสียเงิน) ซึ่งช่วยกันการโกงแบบพิมพ์
// ยอดมั่ว/เอาสลิปเก่า-สลิปคนอื่นมาใช้ซ้ำได้ดีขึ้นมาก แต่ "ไม่ใช่การยืนยันกับธนาคารจริง" —
// สลิปที่ถูกตัดต่อรูปภาพอย่างประณีต (Photoshop) จนตัวเลขในรูปตรงกับยอดจริงเป๊ะ ระบบนี้ตรวจไม่ได้
// 100% ถ้าต้องการความมั่นใจสูงสุดจริงๆ ต้องใช้บริการยืนยันสลิปกับธนาคารโดยตรง (เช่น สลิปOK, บริการ
// ตรวจสลิปของธนาคาร) ซึ่งมีค่าใช้จ่ายต่อครั้ง
const SLIP_MAX_AGE_HOURS   = 24; // สลิปที่วันที่/เวลาเก่ากว่านี้ → ไม่ auto-confirm ให้ ต้องแอดมินตรวจเอง
const SLIP_MAX_FUTURE_MIN  = 15; // เวลาในสลิปล้ำหน้าเวลาปัจจุบันเกินนี้ → น่าสงสัย (นาฬิกาเพี้ยน/สลิปปลอม)

app.post('/submit-slip', rateLimit(20), async (req, res) => {
  const { order_id, customer_id, slip_url, slip_amount, slip_ref_manual } = req.body;
  if (!order_id || !customer_id)
    return res.status(400).json({ error: 'order_id/customer_id required' });
  // 🐛 BUG FIX: หน้าเว็บไม่เคยมีช่องให้ลูกค้ากรอก "รหัสอ้างอิง/เลขที่รายการ" เองเลย (มีแต่ช่องยอดเงิน)
  // ทั้งที่ server อ่านค่านี้จากรูปได้อยู่แล้ว (extractSlipRef) และใช้กันสลิปซ้ำ — ถ้า OCR อ่านรหัส
  // จากรูปไม่ออก (เช่น ลายมือ/มุมกล้อง/ฟอนต์ธนาคารที่ไม่คุ้น) การกันสลิปซ้ำฝั่งนี้ก็ใช้ไม่ได้เลย
  // เพิ่มให้ลูกค้ากรอกเองเป็น fallback ได้ (ใช้ประกอบการกันสลิปซ้ำเท่านั้น ไม่ใช้ตัดสินยอดเงิน —
  // ยอดเงินยังคงต้องอ่านจากรูปจริงที่ server เท่านั้นเหมือนเดิม กันคนพิมพ์มั่ว)
  const manualRef = (typeof slip_ref_manual === 'string' && slip_ref_manual.trim())
    ? slip_ref_manual.trim().slice(0, 25) : null;

  const { data: order, error: oErr } = await supabase
    .from('orders').select('*').eq('order_id', order_id).maybeSingle();
  if (oErr) {
    console.error('submit-slip DB error:', oErr.message);
    return res.status(500).json({ error: 'DB error: ' + oErr.message });
  }
  if (!order)
    return res.status(404).json({ error: `ไม่พบออเดอร์ #${order_id} — กรุณารีเฟรชแล้วลองใหม่` });
  // อนุญาต customer_id ที่ลงท้ายด้วย prefix เดียวกัน (กรณี session ต่างกันเล็กน้อย)
  if (order.customer_id !== customer_id && !order.customer_id?.startsWith(customer_id?.slice(0, 8)))
    return res.status(403).json({ error: 'ไม่ใช่ออเดอร์ของคุณ' });

  const expectedTotal = Number(order.total) || 0;
  const typedAmount   = parseFloat(slip_amount) || 0;

  // ═══ 🔍 ตรวจสลิปอิสระที่ server จากรูปจริง (ไม่พึ่งตัวเลขที่ client พิมพ์มา) ═══
  let ocr = null;
  if (slip_url) {
    try {
      const base64 = await fetchImageAsBase64(slip_url);
      ocr = await runSlipOCR(base64);
    } catch (e) {
      console.warn('submit-slip server OCR failed:', e.message);
    }
  }

  // ═══ 🚫 กันสลิปซ้ำ — รูปเดิม/เลขอ้างอิงเดิมถูกใช้ยืนยันออเดอร์อื่นไปแล้วหรือไม่ ═══
  let dupReason = null;
  try {
    if (ocr?.imageHash) {
      const { data: dupByHash } = await supabase
        .from('orders').select('order_id')
        .eq('slip_image_hash', ocr.imageHash)
        .neq('order_id', order_id)
        .limit(1).maybeSingle();
      if (dupByHash) dupReason = `รูปสลิปนี้เคยถูกใช้ยืนยันออเดอร์ #${dupByHash.order_id} ไปแล้ว`;
    }
    const refForDupCheck = ocr?.ref || manualRef; // ใช้ค่าที่ลูกค้ากรอกเองเป็น fallback ถ้า OCR อ่านไม่ออก
    if (!dupReason && refForDupCheck) {
      const { data: dupByRef } = await supabase
        .from('orders').select('order_id')
        .eq('slip_ref', refForDupCheck)
        .neq('order_id', order_id)
        .limit(1).maybeSingle();
      if (dupByRef) dupReason = `เลขอ้างอิงรายการนี้เคยถูกใช้ยืนยันออเดอร์ #${dupByRef.order_id} ไปแล้ว`;
    }
  } catch (e) {
    // ถ้ายังไม่ได้รัน SQL migration เพิ่มคอลัมน์ slip_image_hash/slip_ref จะเข้ามาที่นี่ — ข้ามการเช็คไปก่อน ไม่ทำให้ทั้ง endpoint ล้ม
    console.warn('dup-slip check skipped (ลองรัน SQL migration เพิ่มคอลัมน์ก่อนหรือยัง?):', e.message);
  }

  // ═══ 📅 ตรวจความสดใหม่ของวันที่/เวลาในสลิป ═══
  let dateFlag = null; // 'stale' | 'future' | null
  if (ocr?.datetime) {
    const ageHr = (Date.now() - new Date(ocr.datetime).getTime()) / 3600000;
    if (ageHr > SLIP_MAX_AGE_HOURS) dateFlag = 'stale';
    else if (ageHr < -(SLIP_MAX_FUTURE_MIN / 60)) dateFlag = 'future';
  }

  // ═══ ✅ ตัดสินผล — verifiedAmount คือยอดที่ server อ่านได้เองจากรูปจริง (ใช้ตัวนี้ตัดสิน) ═══
  const verifiedAmount = ocr?.amount ?? null;
  const paidAmount = verifiedAmount != null ? verifiedAmount : typedAmount; // ใช้แสดงผล/แจ้งเตือนเท่านั้น
  const diff = expectedTotal - paidAmount;

  let isMatch = false;
  let blockReason = null;

  if (dupReason) {
    blockReason = 'duplicate';
  } else if (dateFlag === 'stale') {
    blockReason = 'stale_date';
  } else if (dateFlag === 'future') {
    blockReason = 'future_date';
  } else if (!slip_url) {
    blockReason = 'no_image';
  } else if (verifiedAmount == null) {
    // มีรูป แต่ server อ่านยอดจากรูปเองไม่ได้ (ลายมือ/มุมกล้อง/OCR พลาด ฯลฯ) → ไม่เชื่อยอดที่ client พิมพ์เพียงอย่างเดียว
    blockReason = 'ocr_failed';
  } else {
    isMatch = Math.abs(expectedTotal - verifiedAmount) < 1;
  }

  const now = new Date().toISOString();
  const newPayStatus = isMatch ? 'paid' : 'slip_mismatch';

  const updatePayload = {
    slip_url        : slip_url || null,
    slip_amount     : typedAmount || null,
    slip_ocr_amount : verifiedAmount,
    slip_image_hash : ocr?.imageHash || null,
    slip_ref        : ocr?.ref || manualRef || null,
    slip_datetime   : ocr?.datetime || null,
    payment_flag    : blockReason,   // null | 'duplicate' | 'stale_date' | 'future_date' | 'no_image' | 'ocr_failed' — ให้แอดมินพาเนลแยกเคสสงสัยฉ้อโกงจากยอดไม่ตรงธรรมดา
    payment_status  : newPayStatus,
    ...(isMatch ? { status: 'confirmed' } : {})
  };
  const { error: updErr } = await supabase.from('orders').update(updatePayload).eq('order_id', order_id);
  if (updErr) {
    // เผื่อยังไม่ได้รัน SQL migration เพิ่มคอลัมน์ใหม่ — fallback อัปเดตเฉพาะฟิลด์เดิมกันออเดอร์ค้าง
    console.warn('submit-slip update with new columns failed (รัน SQL migration แล้วหรือยัง?):', updErr.message);
    await supabase.from('orders').update({
      slip_url: slip_url || null,
      slip_amount: typedAmount || null,
      payment_status: newPayStatus,
      ...(isMatch ? { status: 'confirmed' } : {})
    }).eq('order_id', order_id);
  }

  // ═══ ข้อความแจ้งลูกค้า/แอดมิน ตามผลตรวจ ═══
  let chatMsg = '';
  let adminMsg = '';

  if (isMatch) {
    chatMsg  = `✅ ยืนยันการโอนเงินสำเร็จ!\n\nยอดที่โอน: ฿${verifiedAmount.toLocaleString()}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}\n\n🎉 ทางร้านได้รับการชำระเรียบร้อยแล้ว ขอบคุณค่ะ`;
    adminMsg = `💳 ลูกค้าโอนเงินแล้ว! #${order_id}\n\nชื่อ: ${order.customer_name}\nยอดที่โอน (ระบบอ่านจากสลิปจริง): ฿${verifiedAmount.toLocaleString()}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}\n✅ ยอดตรง — ยืนยันอัตโนมัติแล้ว (ตรวจสอบอิสระจาก server แล้ว)`;
  } else if (blockReason === 'duplicate') {
    chatMsg  = `⚠️ ระบบตรวจพบว่าสลิปนี้เคยถูกใช้ยืนยันการชำระไปแล้ว กรุณาแนบสลิปที่ถูกต้องของรายการนี้ หรือติดต่อร้านค้าค่ะ`;
    adminMsg = `🚨 สลิปซ้ำ! #${order_id}\n\nชื่อ: ${order.customer_name}\n${dupReason}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}\n⚠️ อาจเป็นการฉ้อโกง — ห้ามกดยืนยันจนกว่าจะตรวจสอบให้แน่ใจก่อนนะครับ`;
  } else if (blockReason === 'stale_date') {
    chatMsg  = `⚠️ วันที่/เวลาในสลิปดูเก่าเกินไป (เกิน ${SLIP_MAX_AGE_HOURS} ชม.) ระบบจึงขอให้ร้านตรวจสอบก่อนค่ะ`;
    adminMsg = `🚨 สลิปวันที่เก่าผิดปกติ #${order_id}\n\nชื่อ: ${order.customer_name}\nวันที่ในสลิป: ${ocr?.dateRaw || '-'}\nยอดที่โอน: ฿${paidAmount.toLocaleString()}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}\n⚠️ อาจเป็นสลิปเก่าที่ถูกนำมาใช้ซ้ำ — กรุณาตรวจสอบก่อนกด "ยืนยันชำระแล้ว"`;
  } else if (blockReason === 'future_date') {
    chatMsg  = `⚠️ วันที่/เวลาในสลิปยังไม่ถึง ระบบจึงขอให้ร้านตรวจสอบก่อนค่ะ`;
    adminMsg = `🚨 สลิปวันที่ล่วงหน้าผิดปกติ #${order_id}\n\nชื่อ: ${order.customer_name}\nวันที่ในสลิป: ${ocr?.dateRaw || '-'}\nยอดที่โอน: ฿${paidAmount.toLocaleString()}\n⚠️ อาจเป็นสลิปตกแต่ง — กรุณาตรวจสอบก่อนกด "ยืนยันชำระแล้ว"`;
  } else if (blockReason === 'no_image' || blockReason === 'ocr_failed') {
    chatMsg = diff > 0
      ? `⚠️ ยอดที่แจ้งไม่ครบ\n\nยอดที่แจ้ง: ฿${paidAmount.toLocaleString()}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}\nขาดอีก: ฿${diff.toFixed(2)}\n\nกรุณาโอนเพิ่มแล้วส่งสลิปใหม่ หรือติดต่อร้านค้าเพื่อยืนยันค่ะ`
      : `✅ ได้รับแจ้งแล้ว!\n\nยอดที่แจ้ง: ฿${paidAmount.toLocaleString()}\n\nทางร้านจะตรวจสอบและยืนยันเร็วๆ นี้ค่ะ`;
    adminMsg = `💳 สลิปรอตรวจสอบ (ระบบยืนยันอัตโนมัติไม่ได้) #${order_id}\n\nชื่อ: ${order.customer_name}\nยอดที่ลูกค้าพิมพ์: ฿${typedAmount.toLocaleString()}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}\nสาเหตุ: ${blockReason === 'no_image' ? 'ไม่มีรูปสลิปให้ตรวจสอบ' : 'ระบบอ่านยอดจากรูปสลิปเองไม่ได้'}\n📲 กรุณาตรวจรูปสลิปด้วยตาก่อนกด "ยืนยันชำระแล้ว" ใน Admin Panel`;
  } else {
    // ยอดไม่ตรงแบบปกติ — มีรูป, server อ่านยอดได้, แต่ยอดไม่เท่ากับที่ต้องชำระ
    if (diff > 0) {
      chatMsg  = `⚠️ ยอดที่โอนไม่ครบ\n\nยอดที่โอน: ฿${verifiedAmount.toLocaleString()}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}\nขาดอีก: ฿${diff.toFixed(2)}\n\nกรุณาโอนเพิ่ม ฿${diff.toFixed(2)} แล้วส่งสลิปใหม่ หรือติดต่อร้านค้าเพื่อยืนยันค่ะ`;
      adminMsg = `💳 สลิปยอดไม่ตรง #${order_id}\n\nชื่อ: ${order.customer_name}\nยอดที่โอน (ระบบอ่านจากสลิปจริง): ฿${verifiedAmount.toLocaleString()}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}\n⚠️ ขาดอีก ฿${diff.toFixed(2)}\n\n📲 กด "ยืนยันชำระแล้ว" ใน Admin เพื่อยืนยัน manual`;
    } else {
      chatMsg  = `✅ ได้รับสลิปแล้ว!\n\nยอดที่โอน: ฿${verifiedAmount.toLocaleString()}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}\n\nทางร้านจะตรวจสอบและยืนยันเร็วๆ นี้ค่ะ`;
      adminMsg = `💳 สลิปโอนเกิน #${order_id}\n\nชื่อ: ${order.customer_name}\nยอดที่โอน (ระบบอ่านจากสลิปจริง): ฿${verifiedAmount.toLocaleString()}\nยอดออเดอร์: ฿${expectedTotal.toLocaleString()}\n\n📲 กด "ยืนยันชำระแล้ว" ใน Admin Panel`;
    }
  }

  try {
    await supabase.from('messages').insert([{
      order_id, customer_id, sender: 'system', text: chatMsg, created_at: now
    }]);
  } catch(e) { console.warn('insert slip msg:', e.message); }

  // 📝 Note ภายในสำหรับแอดมินเท่านั้น (sender: 'admin_note' — ไม่โผล่ในแชทของลูกค้าเด็ดขาด ดู /messages/:orderId)
  // ให้เหตุผลละเอียดแบบเทคนิค (ยอดที่ server อ่านจากรูปจริง / เหตุผลบล็อก ฯลฯ) ไปอยู่ในหน้าแชทของแอดมินพาเนลด้วย
  // ไม่ใช่แค่ผ่าน LINE push อย่างเดียว เผื่อแอดมินพลาดดู LINE ตอนนั้น
  try {
    await supabase.from('messages').insert([{
      order_id, customer_id, sender: 'admin_note', text: adminMsg, created_at: now
    }]);
  } catch(e) { console.warn('insert admin note:', e.message); }

  if (process.env.LINE_TOKEN) {
    const payResult = isMatch ? 'match' : (diff > 0 ? 'under' : 'over');
    // 🐛 BUG FIX: เดิม adminMsg (ข้อความละเอียดที่บอกเหตุผลชัดเจน เช่น "🚨 สลิปซ้ำ!") ถูกสร้างไว้
    // แต่ไม่เคยถูกส่งไปที่ไหนเลย แอดมินได้แค่การ์ด Flex ทั่วไปที่แยกเคสฉ้อโกงกับยอดไม่ตรงธรรมดาไม่ออก
    // ตอนนี้ส่ง adminMsg เป็นข้อความ text ไปด้วยเสมอ ให้แอดมินเห็นเหตุผลตรงๆ ใน LINE OA ทันที
    const msgs = [
      { type: 'text', text: adminMsg },
      buildPaymentFlex({
        audience:'admin', result: payResult, order_id,
        customer_name: order.customer_name,
        paid: paidAmount, expected: expectedTotal, diff
      })
    ];
    if (slip_url) msgs.push({ type:'image', originalContentUrl: slip_url, previewImageUrl: slip_url });
    notifyAllAdmins(msgs).catch(e => console.warn('slip notify:', e.message));
  }

  res.json({
    success: true, status: newPayStatus, isMatch, diff,
    reason: blockReason,           // null | 'duplicate' | 'stale_date' | 'future_date' | 'no_image' | 'ocr_failed'
    verifiedAmount,                // ยอดที่ server อ่านได้เองจากรูป (null ถ้าอ่านไม่ได้/ไม่มีรูป)
    slipDate: ocr?.dateRaw || null
  });
});

// ── POST /read-slip ──────────────────────────────────────────
// อ่านยอด+วันที่/เวลาจากรูปสลิปด้วย Tesseract OCR (ฟรี ไม่ต้อง API key) — ใช้ prefill ให้ลูกค้าเห็นไว ๆ
// (การตัดสินใจ auto-confirm จริง ๆ เกิดที่ /submit-slip ซึ่ง server จะอ่านซ้ำเองอีกครั้งอย่างอิสระ)
app.post('/read-slip', rateLimit(10), async (req, res) => {
  const { image_base64 } = req.body;
  if (!image_base64)
    return res.status(400).json({ error: 'ต้องส่ง image_base64' });

  // ป้องกัน base64 ใหญ่เกิน 10MB
  const b64Raw = image_base64.replace(/^data:image\/\w+;base64,/, '');
  if (b64Raw.length > 10 * 1024 * 1024)
    return res.status(413).json({ success: false, amount: null, message: 'รูปใหญ่เกินไป กรุณากรอกยอดเอง' });

  try {
    const result = await runSlipOCR(image_base64);
    if (!result.rawText) {
      return res.json({ success: false, amount: null, message: 'อ่านตัวอักษรไม่ได้ — กรุณากรอกยอดที่โอนด้วยนะคะ' });
    }
    if (!result.amount) {
      return res.json({ success: false, amount: null, raw: result.rawText, message: 'หายอดไม่เจอ — กรุณากรอกยอดที่โอนด้วยนะคะ' });
    }
    res.json({
      success: true, amount: result.amount, raw: result.rawText,
      slipDate: result.dateRaw, slipRef: result.ref
    });
  } catch (e) {
    const msg = e.message?.includes('tesseract') || e.message?.includes('spawn')
      ? 'Tesseract ยังไม่ได้ติดตั้งบน server'
      : e.message;
    res.status(500).json({ error: msg });
  }
});

// ── helper: แยกยอดเงินจากข้อความ OCR สลิปโอนเงิน ──────────
function extractAmountFromSlip(text) {
  const lines = text.split(/\n/).map(l => l.trim()).filter(Boolean);

  // Pattern 1: ตัวเลขที่ขึ้นต้นบรรทัดเดียวหรือมีแค่ตัวเลข+จุด (ยอดหลักในสลิป PromptPay/KTB)
  // เช่น "2,000.00" หรือ "58.00" อยู่บรรทัดเดียวกัน
  for (const line of lines) {
    const stripped = line.replace(/\s/g, '');
    const soloNum = stripped.match(/^(\d{1,3}(,\d{3})*(\.\d{2})?)$|^(\d+\.\d{2})$/);
    if (soloNum) {
      const val = parseFloat(stripped.replace(/,/g, ''));
      if (val >= 1 && val <= 999999) return val;
    }
  }

  // Pattern 2: keyword ที่มักอยู่ก่อนยอดเงิน (ไทย + Krungthai + KBank + SCB)
  const amountKeywords = /จำนวนเงิน|ยอดโอน|ยอดเงิน|จำนวน|amount|total|โอนเงิน|เงิน|จํานวนเงิน|จํานวน|รายการโอนเงิน|การโอนเงิน/i;
  for (let i = 0; i < lines.length; i++) {
    if (amountKeywords.test(lines[i])) {
      const sameLineNum = parseThaiNumber(lines[i]);
      if (sameLineNum) return sameLineNum;
      if (lines[i + 1]) {
        const nextLineNum = parseThaiNumber(lines[i + 1]);
        if (nextLineNum) return nextLineNum;
      }
      if (lines[i + 2]) {
        const next2LineNum = parseThaiNumber(lines[i + 2]);
        if (next2LineNum) return next2LineNum;
      }
    }
  }

  // Pattern 3: หาตัวเลขที่มี .00 (มักเป็นยอดเงิน เช่น 2,000.00 หรือ 58.00)
  for (const line of lines) {
    const dotZero = line.match(/(\d[\d,]*\.00)/g);
    if (dotZero) {
      for (const n of dotZero) {
        const val = parseFloat(n.replace(/,/g, ''));
        if (val >= 1 && val <= 999999) return val;
      }
    }
  }

  // Pattern 4: fallback — ตัวเลขที่ใหญ่ที่สุดที่สมเหตุ
  const allNumbers = [];
  for (const line of lines) {
    const nums = line.match(/\d[\d,]*\.?\d*/g) || [];
    for (const n of nums) {
      const val = parseFloat(n.replace(/,/g, ''));
      if (val >= 1 && val <= 999999) allNumbers.push(val);
    }
  }

  if (!allNumbers.length) return null;
  const wholeNumbers = allNumbers.filter(n => n === Math.floor(n) || (n * 100) % 1 === 0);
  if (wholeNumbers.length) return Math.max(...wholeNumbers);
  return Math.max(...allNumbers);
}

function parseThaiNumber(str) {
  // แปลงตัวเลขไทย ๐-๙ → 0-9
  const normalized = str.replace(/[๐-๙]/g, d => d.charCodeAt(0) - 3664);
  const match = normalized.match(/(\d[\d,]*\.?\d*)/);
  if (!match) return null;
  const val = parseFloat(match[1].replace(/,/g, ''));
  return (val >= 1 && val <= 999999) ? val : null;
}

// ── ★ ใหม่: helper แยก "วันที่/เวลา" จากข้อความ OCR สลิป ──────────
// รองรับปี พ.ศ. (2 หรือ 4 หลัก, แปลงเป็น ค.ศ. อัตโนมัติ), เดือนไทยแบบย่อ/เต็ม, เวลา HH:MM(:SS)
// ใช้ตรวจว่าสลิปนี้ "สด" พอจะเชื่อได้ไหม (กันเอาสลิปเก่ามาใช้ยืนยันซ้ำ)
const TH_MONTHS = {
  'ม.ค.':1, 'มค':1, 'มกราคม':1,
  'ก.พ.':2, 'กพ':2, 'กุมภาพันธ์':2,
  'มี.ค.':3, 'มีค':3, 'มีนาคม':3,
  'เม.ย.':4, 'เมย':4, 'เมษายน':4,
  'พ.ค.':5, 'พค':5, 'พฤษภาคม':5,
  'มิ.ย.':6, 'มิย':6, 'มิถุนายน':6,
  'ก.ค.':7, 'กค':7, 'กรกฎาคม':7,
  'ส.ค.':8, 'สค':8, 'สิงหาคม':8,
  'ก.ย.':9, 'กย':9, 'กันยายน':9,
  'ต.ค.':10, 'ตค':10, 'ตุลาคม':10,
  'พ.ย.':11, 'พย':11, 'พฤศจิกายน':11,
  'ธ.ค.':12, 'ธค':12, 'ธันวาคม':12
};

function extractSlipDateTime(text) {
  const norm = String(text).replace(/[๐-๙]/g, d => d.charCodeAt(0) - 3664); // เลขไทย → เลขอารบิก

  let day = null, month = null, year = null, hour = null, minute = null;

  // รูปแบบตัวเลขล้วน: 12/01/2568, 12-01-25, 12.01.2025
  const numDate = norm.match(/(\d{1,2})[\/\-\.](\d{1,2})[\/\-\.](\d{2,4})/);
  if (numDate) {
    day = parseInt(numDate[1], 10);
    month = parseInt(numDate[2], 10);
    year = parseInt(numDate[3], 10);
  } else {
    // รูปแบบวันที่ไทย: "12 ม.ค. 68" หรือ "12 มกราคม 2568"
    const monthNames = Object.keys(TH_MONTHS).sort((a, b) => b.length - a.length)
      .map(k => k.replace(/\./g, '\\.'));
    const thDateRe = new RegExp(`(\\d{1,2})\\s*(${monthNames.join('|')})\\s*(\\d{2,4})`, 'i');
    const thDate = thDateRe.exec(norm);
    if (thDate) {
      day = parseInt(thDate[1], 10);
      const mKey = Object.keys(TH_MONTHS).find(k => k.toLowerCase() === thDate[2].toLowerCase());
      month = mKey ? TH_MONTHS[mKey] : null;
      year = parseInt(thDate[3], 10);
    }
  }

  // แปลงปี พ.ศ. → ค.ศ.
  if (year != null) {
    if (year < 100) year += 2500;   // เช่น "68" → 2568
    if (year > 2400) year -= 543;   // พ.ศ. → ค.ศ. (สลิปไทยเกือบทั้งหมดเป็น พ.ศ.)
  }

  // เวลา HH:MM(:SS)
  const timeMatch = norm.match(/(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if (timeMatch) {
    hour   = parseInt(timeMatch[1], 10);
    minute = parseInt(timeMatch[2], 10);
  }

  if (day == null || month == null || year == null) return { iso: null, raw: null };
  if (month < 1 || month > 12 || day < 1 || day > 31) return { iso: null, raw: null };
  if (year < 2000 || year > 2100) return { iso: null, raw: null }; // กันเลขมั่วจาก OCR

  // สลิปไทยเป็นเวลาไทย (UTC+7) — ถ้าไม่เจอเวลา ใช้เที่ยงวันเป็นค่ากลาง กัน freshness check พลาดเพราะ timezone
  const h = hour ?? 12, m = minute ?? 0;
  const d = new Date(Date.UTC(year, month - 1, day, h - 7, m, 0));
  if (isNaN(d.getTime())) return { iso: null, raw: null };

  const raw = `${String(day).padStart(2,'0')}/${String(month).padStart(2,'0')}/${year}` +
    (hour != null ? ` ${String(hour).padStart(2,'0')}:${String(minute).padStart(2,'0')} น.` : '');
  return { iso: d.toISOString(), raw };
}

// ── ★ ใหม่: helper แยก "เลขที่รายการ/เลขอ้างอิง" จากสลิป ──────────
// ใช้กันสลิปเดิมถูกเอามาใช้ซ้ำยืนยันหลายออเดอร์ (ธนาคารแต่ละเจ้าออกเลขนี้ไม่ซ้ำกันต่อ 1 รายการโอนจริง)
function extractSlipRef(text) {
  const lines = text.split(/\n/).map(l => l.trim()).filter(Boolean);
  const refKeywords = /เลขที่รายการ|รหัสอ้างอิง|เลขอ้างอิง|หมายเลขอ้างอิง|เลขที่อ้างอิง|ref(?:erence)?\s*(?:no\.?|number|id)?\b|transaction\s*id/i;
  for (let i = 0; i < lines.length; i++) {
    if (!refKeywords.test(lines[i])) continue;
    const sameLine = lines[i].replace(refKeywords, '').match(/[A-Za-z0-9]{8,25}/);
    if (sameLine) return sameLine[0];
    if (lines[i + 1]) {
      const nextLine = lines[i + 1].match(/[A-Za-z0-9]{8,25}/);
      if (nextLine) return nextLine[0];
    }
  }
  return null;
}


// ── POST /confirm-payment ────────────────────────────────────
// แอดมินยืนยัน manual ว่าชำระแล้ว
app.post('/confirm-payment', requirePerm('payments'), async (req, res) => {
  const { order_id } = req.body;
  if (!order_id) return res.status(400).json({ error: 'order_id required' });

  const { data: order } = await supabase.from('orders')
    .select('customer_name, line_user_id, customer_id, total, payment_method')
    .eq('order_id', order_id).maybeSingle();
  if (!order) return res.status(404).json({ error: 'ไม่พบออเดอร์' });

  const { error: cpErr } = await supabase.from('orders').update({
    payment_status: 'confirmed', status: 'confirmed', payment_flag: null
  }).eq('order_id', order_id);
  if (cpErr) {
    // เผื่อยังไม่ได้รัน SQL migration เพิ่มคอลัมน์ payment_flag
    await supabase.from('orders').update({
      payment_status: 'confirmed', status: 'confirmed'
    }).eq('order_id', order_id);
  }

  const confirmMsg = `✅ แอดมินยืนยันการชำระเงินแล้ว!\n\nออเดอร์ #${order_id}\nยอด: ฿${Number(order.total).toLocaleString()}\n\nขอบคุณที่อุดหนุนร้านค้านะคะ 🙏`;
  try {
    await supabase.from('messages').insert([{
      order_id, customer_id: order.customer_id,
      sender: 'system', text: confirmMsg,
      created_at: new Date().toISOString()
    }]);
  } catch(e) { console.warn('confirm msg:', e.message); }

  if (process.env.LINE_TOKEN && order.line_user_id) {
    linePush(order.line_user_id, [buildPaymentFlex({
      audience:'customer', result:'match', order_id,
      paid: order.total, expected: order.total, diff: 0
    })])
      .catch(e => console.warn('confirm LINE push:', e.message));
  }

  res.json({ success: true });
});

// สร้าง/ดึงลิงก์ referral ของลูกค้า
app.get('/my-referral', async (req, res) => {
  const { customerId } = req.query;
  if (!customerId) return res.status(400).json({ error: 'customerId required' });

  // ดึงหรือสร้าง referral record
  let { data: ref } = await supabase
    .from('referrals')
    .select('ref_code')
    .eq('customer_id', customerId)
    .maybeSingle();

  if (!ref) {
    const ref_code = 'REF' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2,5).toUpperCase();
    const { data: newRef, error } = await supabase
      .from('referrals')
      .insert({ customer_id: customerId, ref_code })
      .select('ref_code')
      .single();
    if (error) return res.status(500).json({ error: error.message });
    ref = newRef;
  }

  const baseUrl = process.env.SHOP_URL || `https://${req.headers.host}`;
  const shareUrl = `${baseUrl.replace(/\/$/, '')}/invite/${ref.ref_code}`;
  res.json({ refCode: ref.ref_code, shareUrl });
});

// ── POST /referral-visit ─────────────────────────────────────
// บันทึกการเยี่ยมชมจากลิงก์ referral
app.post('/referral-visit', async (req, res) => {
  const { customerId, refCode } = req.body;
  if (!refCode) return res.status(400).json({ error: 'refCode required' });

  // ✨ ถ้า refCode เป็น salesId (เช่น S001, S002) → บันทึกลง ghost row ทันที
  // เพื่อให้ /send-order ดึงได้แม้ localStorage หาย
  if (customerId && /^S\d+$/i.test(refCode)) {
    const linkRowId = `LINK-${customerId.slice(0, 20)}`;
    await supabase.from('orders').upsert([{
      order_id    : linkRowId,
      customer_id : customerId,
      customer_name: '',
      items       : [],
      total       : 0,
      status      : 'pending',
      created_at  : new Date().toISOString(),
      note        : '🔗 เยี่ยมชมจากลิงก์เซล',
      ref_code    : refCode
    }], { onConflict: 'order_id' }).then(({ error: e }) => {
      if (e) console.warn('upsert sales-ref ghost failed:', e.message);
      else console.log(`💼 sales ref stored: customer=${customerId} ref=${refCode}`);
    });
    return res.json({ success: true });
  }

  // หา referral owner (ระบบชวนเพื่อนปกติ)
  const { data: ref } = await supabase
    .from('referrals')
    .select('id, customer_id')
    .eq('ref_code', refCode)
    .maybeSingle();

  if (!ref) return res.status(404).json({ error: 'ไม่พบ referral code นี้' });

  // บันทึก visit (ถ้ายังไม่เคยบันทึก customerId นี้)
  if (customerId && customerId !== ref.customer_id) {
    await supabase
      .from('referral_visits')
      .upsert(
        { referral_id: ref.id, visitor_customer_id: customerId },
        { onConflict: 'referral_id,visitor_customer_id', ignoreDuplicates: true }
      );
  }

  res.json({ success: true });
});

// ── GET /my-referral-rewards ─────────────────────────────────
// ดูรายการคูปองที่ได้จากการชวนเพื่อน
app.get('/my-referral-rewards', async (req, res) => {
  const { customerId } = req.query;
  if (!customerId) return res.status(400).json({ error: 'customerId required' });

  const { data: ref } = await supabase
    .from('referrals')
    .select('id')
    .eq('customer_id', customerId)
    .maybeSingle();

  if (!ref) return res.json({ rewards: [] });

  const { data: rewards, error } = await supabase
    .from('referral_rewards')
    .select('*, coupons(*)')
    .eq('referral_id', ref.id)
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json({ rewards: rewards || [] });
});

// ── GET /available-coupons ───────────────────────────────────
// ดึงรายการคูปองทั้งหมด (auto + manual) ที่ลูกค้าใช้ได้ใน picker
app.get('/available-coupons', async (req, res) => {
  const { customerId, orderTotal } = req.query;
  const total = parseFloat(orderTotal) || 0;
  const now   = new Date().toISOString();

  // ดึงทั้ง auto และ manual ที่ active (ยกเว้น secret)
  const { data: coupons, error } = await supabase
    .from('coupons')
    .select('*')
    .eq('is_active', true)
    .neq('is_secret', true)
    .or(`start_date.is.null,start_date.lte.${now}`)
    .or(`end_date.is.null,end_date.gte.${now}`)
    .order('discount_value', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });

  // ตรวจ first_order
  let isFirstOrder = false;
  if (customerId) {
    const { data: prevOrders } = await supabase
      .from('orders').select('id').eq('customer_id', customerId)
      .not('order_id', 'like', 'LINE-%').not('order_id', 'like', 'LINK-%').limit(1);
    isFirstOrder = !prevOrders?.length;
  }

  // กรองตาม condition + usage_limit
  const eligible = (coupons || []).filter(c => {
    if (c.usage_limit !== null && (c.used_count || 0) >= c.usage_limit) return false;
    if (c.condition_type === 'first_order') return isFirstOrder;
    return true;
  });

  // คำนวณ discount ให้แต่ละ coupon
  const result = eligible.map(c => ({
    ...c,
    discountAmount: calcDiscount(c, total)
  }));

  res.json({ coupons: result });
});

// ── POST /reveal-coupon ──────────────────────────────────────
// เปิดเผยคูปองลับด้วย secretCode
app.post('/reveal-coupon', rateLimit(20), async (req, res) => {
  const { secretCode, customerId, orderTotal } = req.body;
  if (!secretCode) return res.status(400).json({ error: 'กรุณากรอกโค้ดลับ' });

  const total = parseFloat(orderTotal) || 0;
  const now   = new Date().toISOString();

  // 🔒 SECURITY FIX: เดิมใช้ .ilike('secret_code', secretCode.trim()) — ilike ตีความ % และ _
  // เป็น wildcard เสมอ ทำให้ส่ง secretCode=% เข้ามาแล้วได้คูปองลับ (is_secret=true) ตัวใดตัวหนึ่ง
  // กลับไปทันที โดยไม่ต้องรู้โค้ดลับจริงเลย — ทำลายจุดประสงค์ของ "โค้ดลับ" ทั้งระบบ
  // เปลี่ยนเป็น .eq() แบบตรงตัว (ฝั่งหน้าเว็บแปลงเป็นตัวพิมพ์ใหญ่ก่อนส่งอยู่แล้วเสมอ
  // จึงไม่กระทบการใช้งานปกติ) + ใส่ rate limit กันเดาโค้ดแบบยิงถล่ม
  const secretCodeNorm = secretCode.trim().toUpperCase();

  const { data: coupon, error } = await supabase
    .from('coupons')
    .select('*')
    .eq('is_active', true)
    .eq('is_secret', true)
    .eq('secret_code', secretCodeNorm)
    .or(`start_date.is.null,start_date.lte.${now}`)
    .or(`end_date.is.null,end_date.gte.${now}`)
    .maybeSingle();

  if (error) return res.status(500).json({ error: error.message });
  if (!coupon) return res.status(404).json({ error: 'ไม่พบโค้ดลับนี้ หรือหมดอายุแล้ว' });

  if (coupon.usage_limit !== null && (coupon.used_count || 0) >= coupon.usage_limit)
    return res.status(400).json({ error: 'คูปองนี้ถูกใช้ครบจำนวนแล้ว' });

  if (coupon.min_order > 0 && total < coupon.min_order)
    return res.status(400).json({ error: `ต้องสั่งขั้นต่ำ ฿${coupon.min_order.toLocaleString()} ถึงจะใช้คูปองนี้ได้` });

  const discountAmount = calcDiscount(coupon, total);
  res.json({ success: true, coupon, discountAmount });
});

// ═══════════════════════════════════════════════════════════
//  STATIC FILES
// ═══════════════════════════════════════════════════════════
//  หน้าร้านลูกค้า อยู่ที่ index.html (อยู่บน Railway/GitHub)
//  หน้าแอดมิน admin.html เก็บไว้ในเครื่องเจ้าของร้าน — เปิดจาก browser ตรงๆ
//  (admin.html จะเรียก API ของ backend ที่นี่ผ่าน CORS)

// ── GET /sales/:salesId ──────────────────────────────────────
// หน้า Landing สำหรับเซล — แยกจากระบบเชิญเพื่อน
app.get('/sales/:salesId', (req, res) => {
  const salesId  = req.params.salesId;
  const baseUrl  = (process.env.SHOP_URL || `https://${req.headers.host}`).replace(/\/$/, '');
  const shopUrl  = `${baseUrl}/?ref=${salesId}`;
  const lineOaId = process.env.LINE_OA_ID || '';
  const lineAddUrl = lineOaId ? `https://line.me/R/ti/p/${encodeURIComponent(lineOaId)}` : null;
  const shopName = process.env.SHOP_NAME || 'ร้านของเรา';

  if (!lineAddUrl) return res.redirect(302, shopUrl);

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.send(`<!DOCTYPE html>
<html lang="th">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>สั่งสินค้าผ่านเซล — ${shopName}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Helvetica Neue',Arial,'Noto Sans Thai',sans-serif;
         background:linear-gradient(135deg,#fff5f5 0%,#ffe0e0 100%);
         min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{background:#fff;border-radius:20px;padding:36px 28px 32px;
          max-width:380px;width:100%;text-align:center;
          box-shadow:0 8px 40px rgba(192,57,43,.15)}
    .logo{font-size:48px;margin-bottom:8px}
    .shop{font-size:20px;font-weight:700;color:#2C3E50;margin-bottom:4px}
    .tagline{font-size:13px;color:#888;margin-bottom:8px}
    .sales-badge{display:inline-block;background:linear-gradient(120deg,#96281B,#C0392B);
                 color:#fff;border-radius:20px;padding:6px 18px;font-size:13px;
                 font-weight:700;margin-bottom:24px;letter-spacing:.5px}
    .step{display:flex;align-items:flex-start;gap:12px;text-align:left;margin-bottom:16px}
    .step-num{min-width:26px;height:26px;border-radius:50%;
              background:#C0392B;color:#fff;font-size:12px;font-weight:700;
              display:flex;align-items:center;justify-content:center;margin-top:2px}
    .step-txt{font-size:14px;color:#444;line-height:1.5}
    .step-txt strong{color:#2C3E50}
    .btn-line{display:block;background:#06C755;color:#fff;border:none;
              border-radius:12px;padding:16px;font-size:16px;font-weight:700;
              text-decoration:none;cursor:pointer;margin-top:24px;
              font-family:inherit;width:100%;
              box-shadow:0 4px 14px rgba(6,199,85,.35)}
    .btn-skip{display:block;margin-top:12px;font-size:13px;color:#aaa;
              text-decoration:underline;cursor:pointer;background:none;
              border:none;font-family:inherit;width:100%;padding:6px}
    #status{font-size:13px;color:#C0392B;min-height:20px;margin-top:14px;display:none}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">🛍️</div>
    <div class="shop">${shopName}</div>
    <div class="tagline">พนักงานขายแนะนำสินค้าให้คุณ</div>
    <div class="sales-badge">💼 รหัสเซล: ${escapeHtml(salesId)}</div>

    <div class="step">
      <div class="step-num">1</div>
      <div class="step-txt"><strong>แอด LINE OA ของเรา</strong><br>เพื่อรับการแจ้งเตือนออเดอร์</div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div class="step-txt"><strong>ช้อปสินค้าได้เลย</strong><br>ออเดอร์จะอ้างอิงถึงเซลคนนี้อัตโนมัติ</div>
    </div>

    <button class="btn-line" onclick="goAddAndShop()">
      ➕ แอด LINE OA + ไปช้อปเลย
    </button>
    <button class="btn-skip" onclick="goShopOnly()">ข้ามขั้นตอนนี้ ไปช้อปเลย →</button>
    <div id="status">✅ กำลังพาไปหน้าร้าน...</div>
  </div>

  <script>
    const SHOP_WITH_REF = ${safeJsonForScript(shopUrl)};
    const LINE_ADD      = ${safeJsonForScript(lineAddUrl)};

    function goAddAndShop() {
      window.open(LINE_ADD, '_blank');
      document.getElementById('status').style.display = 'block';
      setTimeout(() => { window.location.href = SHOP_WITH_REF; }, 1200);
    }
    function goShopOnly() {
      window.location.href = SHOP_WITH_REF;
    }
  </script>
</body>
</html>`);
});

// ── GET /invite/:refCode ─────────────────────────────────────
// หน้า Landing Page กลาง — ให้ B แอด LINE OA แล้ว redirect ไปร้านพร้อม ref code
app.get('/invite/:refCode', (req, res) => {
  const refCode  = req.params.refCode;
  const baseUrl  = (process.env.SHOP_URL || `https://${req.headers.host}`).replace(/\/$/, '');
  const shopUrl  = `${baseUrl}/?ref=${refCode}`;
  const lineOaId = process.env.LINE_OA_ID || '';                 // เช่น @menshop หรือ @Uxxxxxxxx
  const lineAddUrl = lineOaId
    ? `https://line.me/R/ti/p/${encodeURIComponent(lineOaId)}`
    : null;
  const shopName = process.env.SHOP_NAME || 'ร้านของเรา';

  // ถ้าไม่มี LINE_OA_ID → redirect ตรงไปร้านเลย
  if (!lineAddUrl) {
    return res.redirect(302, shopUrl);
  }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="th">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>เชิญมาช้อปด้วยกัน — ${shopName}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Helvetica Neue',Arial,'Noto Sans Thai',sans-serif;
         background:linear-gradient(135deg,#f8f9fa 0%,#e8f5e9 100%);
         min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{background:#fff;border-radius:20px;padding:36px 28px 32px;
          max-width:380px;width:100%;text-align:center;
          box-shadow:0 8px 40px rgba(0,0,0,.10)}
    .logo{font-size:48px;margin-bottom:8px}
    .shop{font-size:20px;font-weight:700;color:#2C3E50;margin-bottom:4px}
    .tagline{font-size:13px;color:#888;margin-bottom:28px}
    .divider{border:none;border-top:1px solid #f0f0f0;margin:20px 0}
    .step{display:flex;align-items:flex-start;gap:12px;text-align:left;margin-bottom:16px}
    .step-num{min-width:26px;height:26px;border-radius:50%;
              background:#06C755;color:#fff;font-size:12px;font-weight:700;
              display:flex;align-items:center;justify-content:center;margin-top:2px}
    .step-txt{font-size:14px;color:#444;line-height:1.5}
    .step-txt strong{color:#2C3E50}
    .btn-line{display:block;background:#06C755;color:#fff;border:none;
              border-radius:12px;padding:16px;font-size:16px;font-weight:700;
              text-decoration:none;cursor:pointer;margin-top:24px;
              font-family:inherit;width:100%;
              box-shadow:0 4px 14px rgba(6,199,85,.35);
              transition:transform .15s,box-shadow .15s}
    .btn-line:active{transform:scale(.97);box-shadow:0 2px 8px rgba(6,199,85,.3)}
    .btn-skip{display:block;margin-top:12px;font-size:13px;color:#aaa;
              text-decoration:underline;cursor:pointer;background:none;
              border:none;font-family:inherit;width:100%;padding:6px}
    .gift{font-size:13px;color:#e8593c;font-weight:600;
          background:#fff5f2;border-radius:8px;padding:10px 14px;
          margin-bottom:20px;border:1px solid #ffd5cc}
    #status{font-size:13px;color:#06C755;min-height:20px;margin-top:14px;display:none}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">🛍️</div>
    <div class="shop">${shopName}</div>
    <div class="tagline">เพื่อนของคุณชวนมาช้อปด้วยกัน!</div>

    <div class="gift">🎁 ช้อปครั้งแรกแล้วเพื่อนของคุณ<br>จะได้รับคูปองส่วนลดทันที!</div>

    <div class="step">
      <div class="step-num">1</div>
      <div class="step-txt"><strong>แอด LINE OA ของเรา</strong><br>เพื่อรับการแจ้งเตือนออเดอร์และโปรโมชั่น</div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div class="step-txt"><strong>ช้อปสินค้าได้เลย</strong><br>ระบบบันทึกว่าคุณมาจากลิงก์เพื่อนอัตโนมัติ</div>
    </div>

    <button class="btn-line" onclick="goAddAndShop()">
      ➕ แอด LINE OA + ไปช้อปเลย
    </button>
    <button class="btn-skip" onclick="goShopOnly()">ข้ามขั้นตอนนี้ ไปช้อปเลย →</button>
    <div id="status">✅ กำลังพาไปหน้าร้าน...</div>
  </div>

  <script>
    const SHOP_URL   = ${safeJsonForScript(shopUrl)};
    const LINE_ADD   = ${safeJsonForScript(lineAddUrl)};
    const REF_CODE   = ${safeJsonForScript(refCode)};
    const SHOP_WITH_REF = SHOP_URL + (SHOP_URL.includes('?') ? '&' : '?') + 'ref=' + encodeURIComponent(REF_CODE);

    function goAddAndShop() {
      // เปิด LINE เพื่อแอด OA
      window.open(LINE_ADD, '_blank');
      // redirect ไปร้านพร้อม ref code
      document.getElementById('status').style.display = 'block';
      setTimeout(() => { window.location.href = SHOP_WITH_REF; }, 1200);
    }

    function goShopOnly() {
      window.location.href = SHOP_WITH_REF;
    }
  </script>
</body>
</html>`);
});


// fallback: ทุก URL ที่ไม่ match route ข้างบน → ส่งหน้าร้าน
app.use(express.static(__dirname));

app.get('/shop', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── Health Check (ป้องกัน Render Sleep) ───────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── Start ─────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  const adminCount = getAdminUids().length;
  console.log(`\n🚀 Maejai Shop Backend v3 — port ${PORT}`);
  console.log(`🗄  Supabase  : ${process.env.SUPABASE_URL  ? '✅' : '❌'}`);
  console.log(`💬 LINE      : ${process.env.LINE_TOKEN     ? '✅' : '❌'}`);
  console.log(`👥 Admins    : ${adminCount} คน`);
  console.log(`📍 Routes    : /shop, /admin, /api`);

  // ── Keep-alive: ping ตัวเองทุก 10 นาที ป้องกัน Render หลับ ──
  const SELF_URL = process.env.RENDER_EXTERNAL_URL
    || process.env.BACKEND_URL
    || process.env.SHOP_URL
    || ('http://localhost:' + PORT);
  const PING_INTERVAL = 10 * 60 * 1000; // 10 นาที (ต่ำกว่า 15 นาที ที่ Render sleep)

  setInterval(async () => {
    try {
      const r = await fetch(SELF_URL.replace(/\/+$/, '') + '/health');
      console.log('🏓 keep-alive ping →', r.status === 200 ? '✅ OK' : '⚠️ ' + r.status);
    } catch (e) {
      console.warn('🏓 keep-alive ping failed:', e.message);
    }
  }, PING_INTERVAL);

  console.log('🏓 Keep-alive เปิดแล้ว (ping ทุก 10 นาที →', SELF_URL, ')');
});
