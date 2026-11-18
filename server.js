require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');
const { v2: cloudinary } = require('cloudinary');
const multer = require('multer');
const cors = require('cors');
const crypto = require('crypto');
const { promisify } = require('util');
const { ObjectId } = require('mongodb');
const scrypt = promisify(crypto.scrypt);
const defaults = require('./content-default.json');

const app = express();
const port = Number(process.env.PORT || 3002);
const cookieName = 'pallabi_admin';
const sessionSecret = process.env.SESSION_SECRET;
let db;
app.disable('x-powered-by');
const allowedOrigins = new Set([
  'https://pallavi-tau.vercel.app',
  'http://localhost:5173',
  ...String(process.env.CLIENT_ORIGIN || '')
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean)
]);
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    callback(new Error('Origin is not allowed.'));
  },
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use('/api/admin/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false }));

function requireSession(req, res, next) {
  if (!sessionSecret) return res.status(503).json({ error: 'Admin session is not configured.' });
  try {
    req.session = jwt.verify(req.cookies[cookieName], sessionSecret, { algorithms: ['HS256'] });
    if (!['admin', 'editor'].includes(req.session.role)) throw new Error('Invalid role');
    next();
  } catch {
    res.status(401).json({ error: 'Please sign in to continue.' });
  }
}
function requireAdmin(req, res, next) {
  requireSession(req, res, () => req.session.role === 'admin' ? next() : res.status(403).json({ error: 'Administrator access is required.' }));
}
const normalizeEmail = value => String(value || '').trim().toLowerCase();
async function makePasswordHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await scrypt(password, salt, 64);
  return `${salt}:${hash.toString('hex')}`;
}
async function checkPassword(password, stored) {
  if (typeof stored !== 'string' || !stored.includes(':')) return false;
  const [salt, expectedHex] = stored.split(':');
  const expected = Buffer.from(expectedHex, 'hex');
  const actual = await scrypt(password, salt, expected.length);
  return expected.length > 0 && crypto.timingSafeEqual(actual, expected);
}

app.get('/api/health', (_req, res) => res.json({ ok: true, database: Boolean(db) }));
app.get('/api/admin/session', requireSession, (req, res) => res.json({ ok: true, role: req.session.role, email: req.session.email }));
app.get('/api/content', async (_req, res) => {
  if (!db) return res.json(defaults);
  try {
    const content = await db.collection('site_content').findOne({ _id: 'published' });
    res.json(content?.data ? { ...defaults, ...content.data } : defaults);
  } catch { res.status(503).json({ error: 'Content database is unavailable.' }); }
});
app.post('/api/admin/login', async (req, res) => {
  const email = normalizeEmail(req.body?.username);
  const password = String(req.body?.password || '');
  if (!sessionSecret) return res.status(503).json({ error: 'Admin session is not configured.' });
  try {
    let account = null;
    if (db) account = await db.collection('admin_users').findOne({ email });
    // Local emergency access remains available during a database outage; normal accounts are verified from MongoDB.
    const envMatch = !db && process.env.NODE_ENV !== 'production' && email === normalizeEmail(process.env.ADMIN_USERNAME) && password === process.env.ADMIN_PASSWORD;
    if (!envMatch && (!account || !(await checkPassword(password, account.passwordHash)))) return res.status(401).json({ error: 'Email or password is incorrect.' });
    const role = envMatch ? 'admin' : account.role;
    const token = jwt.sign({ sub: envMatch ? 'env-admin' : account._id.toString(), role, email }, sessionSecret, { algorithm: 'HS256', expiresIn: '8h' });
    const production = process.env.NODE_ENV === 'production';
    res.cookie(cookieName, token, { httpOnly: true, secure: production, sameSite: production ? 'none' : 'lax', maxAge: 8 * 60 * 60 * 1000, path: '/' });
    res.json({ ok: true, role, email });
  } catch { res.status(503).json({ error: 'Could not verify the account. Please try again.' }); }
});
app.get('/api/admin/users', requireAdmin, async (_req, res) => {
  if (!db) return res.status(503).json({ error: 'User database is unavailable.' });
  try {
    const users = await db.collection('admin_users').find({}, { projection: { passwordHash: 0 } }).sort({ createdAt: 1 }).toArray();
    res.json(users.map(({ _id, email, role, createdAt }) => ({ id: _id.toString(), email, role, createdAt })));
  } catch { res.status(503).json({ error: 'Could not load admin accounts.' }); }
});
app.post('/api/admin/users', requireAdmin, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'User database is unavailable.' });
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');
  const role = req.body?.role === 'editor' ? 'editor' : 'admin';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 10) return res.status(400).json({ error: 'Use a password with at least 10 characters.' });
  try {
    const result = await db.collection('admin_users').insertOne({ email, passwordHash: await makePasswordHash(password), role, createdAt: new Date() });
    res.status(201).json({ id: result.insertedId.toString(), email, role });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ error: 'An account with this email already exists.' });
    res.status(503).json({ error: 'Could not create the account.' });
  }
});
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  if (!db) return res.status(503).json({ error: 'User database is unavailable.' });
  if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'Invalid account id.' });
  try {
    const collection = db.collection('admin_users');
    const targetId = new ObjectId(req.params.id);
    const target = await collection.findOne({ _id: targetId });
    if (!target) return res.status(404).json({ error: 'Account not found.' });
    if (req.session.sub === targetId.toString() || req.session.email === target.email) return res.status(400).json({ error: 'You cannot remove your own account.' });
    if (target.role === 'admin' && await collection.countDocuments({ role: 'admin' }) <= 1) return res.status(400).json({ error: 'Keep at least one administrator account.' });
    await collection.deleteOne({ _id: targetId });
    res.json({ ok: true });
  } catch { res.status(503).json({ error: 'Could not remove the account.' }); }
});
app.post('/api/admin/logout', requireSession, (_req, res) => {
  const production = process.env.NODE_ENV === 'production';
  res.clearCookie(cookieName, { httpOnly: true, secure: production, sameSite: production ? 'none' : 'lax', path: '/' });
  res.json({ ok: true });
});
app.put('/api/admin/content', requireSession, async (req, res) => {
  try {
    if (!db) return res.status(503).json({ error: 'Content database is unavailable.' });
    const data = req.body;
    if (!data || typeof data !== 'object' || Array.isArray(data)) return res.status(400).json({ error: 'Expected a content object.' });
    await db.collection('site_content').updateOne({ _id: 'published' }, { $set: { data, updatedAt: new Date() } }, { upsert: true });
    res.json({ ok: true });
  } catch { res.status(503).json({ error: 'Could not save content.' }); }
});
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 }, fileFilter: (_req, file, cb) => cb(null, /^image\/(jpeg|png|webp)$/.test(file.mimetype) || file.mimetype === 'application/pdf') });
app.post('/api/admin/media', requireSession, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Upload a JPG, PNG or WebP image (up to 8 MB).' });
  const cloudConfigured = process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET;
  if (!cloudConfigured) return res.status(503).json({ error: 'Cloudinary is not configured yet.' });
  cloudinary.config({ cloud_name: process.env.CLOUDINARY_CLOUD_NAME, api_key: process.env.CLOUDINARY_API_KEY, api_secret: process.env.CLOUDINARY_API_SECRET, secure: true });
  try {
    const dataUri = `data:${req.file.mimetype};base64,${req.file.buffer.toString('base64')}`;
    const isPdf = req.file.mimetype === 'application/pdf';
    const result = await cloudinary.uploader.upload(dataUri, { folder: 'pallabi-cooperative', resource_type: isPdf ? 'raw' : 'image' });
    res.json({ url: result.secure_url, publicId: result.public_id });
  } catch { res.status(502).json({ error: 'Image upload failed.' }); }
});

async function connectDatabase() {
  const client = new MongoClient(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  try {
    await client.connect();
    const database = client.db(process.env.MONGODB_DB || undefined);
    await database.collection('site_content').updateOne(
      { _id: 'published' },
      { $setOnInsert: { data: defaults, createdAt: new Date() } },
      { upsert: true }
    );
    const users = database.collection('admin_users');
    await users.createIndex({ email: 1 }, { unique: true });
    if (await users.countDocuments() === 0 && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
      await users.insertOne({ email: normalizeEmail(process.env.ADMIN_USERNAME), passwordHash: await makePasswordHash(process.env.ADMIN_PASSWORD), role: 'admin', createdAt: new Date() });
    }
    db = database;
    console.log('MongoDB connected.');
  } catch (error) {
    await client.close().catch(() => {});
    console.error('MongoDB unavailable; retrying in 30 seconds:', error.message);
    const retry = setTimeout(connectDatabase, 30000);
    retry.unref();
  }
}

if (!process.env.MONGODB_URI) {
  console.error('MONGODB_URI is required. Copy .env.example to .env and configure it.');
  process.exit(1);
}
app.listen(port, () => console.log(`Pallabi site listening on http://localhost:${port}`));
connectDatabase();
