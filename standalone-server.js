'use strict';

require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Pool } = require('pg');
const { createClient } = require('redis');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { randomUUID } = require('crypto');

// ─── Validate env ─────────────────────────────────────────────────────────────

const REQUIRED_ENV = ['DATABASE_URL', 'JWT_SECRET'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`Missing required env var: ${key}`);
    process.exit(1);
  }
}

// ─── PostgreSQL ────────────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('sslmode=require')
    ? { rejectUnauthorized: false }
    : false,
});

pool.on('error', (err) => {
  console.error('Unexpected pg pool error:', err);
});

// ─── Redis ─────────────────────────────────────────────────────────────────────

let redisClient = null;

function parseRedisUrl(raw) {
  if (!raw) return null;
  const hasTls = raw.includes('--tls');
  const match = raw.match(/redis[s]?:\/\/\S+/);
  const url = match ? match[0] : raw.trim();
  if (hasTls && url.startsWith('redis://')) {
    return url.replace('redis://', 'rediss://');
  }
  return url;
}

async function connectRedis() {
  const rawUrl = process.env.REDIS_URL;
  if (!rawUrl) {
    console.warn('REDIS_URL not set — rate limiting disabled');
    return;
  }
  const url = parseRedisUrl(rawUrl);
  redisClient = createClient({ url });
  redisClient.on('error', (err) => console.error('Redis error:', err));
  try {
    await redisClient.connect();
    console.log('Redis connected');
  } catch (err) {
    console.error('Redis connection failed — rate limiting disabled:', err.message);
    redisClient = null;
  }
}

// ─── Middleware: requireTenant (JWT auth) ──────────────────────────────────────

function requireTenant(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }
  const token = authHeader.slice(7);
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return res.status(500).json({ error: 'JWT_SECRET is not configured' });
  }
  try {
    const payload = jwt.verify(token, secret);
    if (!payload.tenant_id) {
      return res.status(401).json({ error: 'Token missing tenant_id claim' });
    }
    req.tenant_id = payload.tenant_id;
    req.user_id = payload.user_id;
    req.user_email = payload.email;
    req.user_display_name = payload.display_name;
    req.user_role = payload.role;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── Middleware: rateLimiter ───────────────────────────────────────────────────

function rateLimiter(maxRequests, windowSecs, keyPrefix) {
  return async (req, res, next) => {
    if (!redisClient) return next();
    const ip =
      (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
      req.socket.remoteAddress ||
      'unknown';
    const key = `${keyPrefix}:${ip}`;
    try {
      const current = await redisClient.incr(key);
      if (current === 1) await redisClient.expire(key, windowSecs);
      if (current > maxRequests) {
        const ttl = await redisClient.ttl(key);
        return res.status(429).json({
          error: 'Too many requests — please try again later.',
          retryAfterSeconds: ttl > 0 ? ttl : windowSecs,
        });
      }
      next();
    } catch (err) {
      console.error('Rate limiter error:', err);
      next();
    }
  };
}

// ─── JWT helper ───────────────────────────────────────────────────────────────

function signToken(user) {
  return jwt.sign(
    {
      user_id: user.user_id,
      tenant_id: user.tenant_id,
      email: user.email,
      display_name: user.display_name,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' },
  );
}

// ─── Express app ──────────────────────────────────────────────────────────────

const app = express();

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Sync-Secret'],
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Routes: health ───────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── Routes: auth ─────────────────────────────────────────────────────────────

const loginRateLimit = rateLimiter(5, 60, 'rl:login');

// POST /api/auth/login
app.post('/api/auth/login', loginRateLimit, async (req, res) => {
  const { email, password, tenant_id } = req.body;
  if (!email || !password || !tenant_id) {
    return res.status(400).json({ error: 'email, password, and tenant_id are required' });
  }
  try {
    const result = await pool.query(
      `SELECT user_id, tenant_id, email, display_name, role, password_hash
       FROM users
       WHERE email = $1 AND tenant_id = $2 AND is_active = true
       LIMIT 1`,
      [email, tenant_id],
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken(user);
    res.json({
      token,
      user: {
        user_id: user.user_id,
        tenant_id: user.tenant_id,
        email: user.email,
        display_name: user.display_name,
        role: user.role,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/refresh
app.post('/api/auth/refresh', requireTenant, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT user_id, tenant_id, email, display_name, role
       FROM users
       WHERE user_id = $1 AND tenant_id = $2 AND is_active = true
       LIMIT 1`,
      [req.user_id, req.tenant_id],
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'User not found or deactivated' });
    res.json({ token: signToken(user), user });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', requireTenant, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT user_id, tenant_id, email, display_name, role,
              source_product, avatar_url, status, custom_status,
              last_active_at, is_active, created_at
       FROM users
       WHERE user_id = $1 AND tenant_id = $2 AND is_active = true
       LIMIT 1`,
      [req.user_id, req.tenant_id],
    );
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error('Me error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', requireTenant, (_req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// ─── Routes: channels ─────────────────────────────────────────────────────────

// GET /api/channels
app.get('/api/channels', requireTenant, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.channel_id, c.name, c.type, c.description, c.topic,
              c.created_by, c.is_archived, c.created_at,
              cm.role AS member_role, cm.last_read_at
       FROM channels c
       JOIN channel_members cm ON cm.channel_id = c.channel_id AND cm.tenant_id = c.tenant_id
       WHERE c.tenant_id = $1 AND cm.user_id = $2 AND c.is_archived = false
       ORDER BY c.name ASC`,
      [req.tenant_id, req.user_id],
    );
    res.json({ channels: result.rows });
  } catch (err) {
    console.error('GET /channels error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/channels
app.post('/api/channels', requireTenant, async (req, res) => {
  const { name, type, description } = req.body;
  if (!name || !type) return res.status(400).json({ error: 'name and type are required' });
  if (!['public', 'private'].includes(type)) {
    return res.status(400).json({ error: 'type must be public or private' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const channelId = randomUUID();
    const channelResult = await client.query(
      `INSERT INTO channels (channel_id, tenant_id, name, type, description, created_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [channelId, req.tenant_id, name, type, description || null, req.user_id],
    );
    await client.query(
      `INSERT INTO channel_members (channel_id, user_id, tenant_id, role) VALUES ($1, $2, $3, 'admin')`,
      [channelId, req.user_id, req.tenant_id],
    );
    await client.query('COMMIT');
    res.status(201).json({ channel: channelResult.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('POST /channels error:', err);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

// POST /api/channels/:id/join
app.post('/api/channels/:id/join', requireTenant, async (req, res) => {
  const { id } = req.params;
  try {
    const channelResult = await pool.query(
      `SELECT channel_id, type, is_archived FROM channels WHERE channel_id = $1 AND tenant_id = $2`,
      [id, req.tenant_id],
    );
    const channel = channelResult.rows[0];
    if (!channel) return res.status(404).json({ error: 'Channel not found' });
    if (channel.is_archived) return res.status(400).json({ error: 'Channel is archived' });
    if (channel.type !== 'public') return res.status(403).json({ error: 'Cannot self-join a private channel' });
    await pool.query(
      `INSERT INTO channel_members (channel_id, user_id, tenant_id, role) VALUES ($1, $2, $3, 'member') ON CONFLICT (channel_id, user_id) DO NOTHING`,
      [id, req.user_id, req.tenant_id],
    );
    res.json({ status: 'ok' });
  } catch (err) {
    console.error('POST /channels/:id/join error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/channels/:id/invite
app.post('/api/channels/:id/invite', requireTenant, async (req, res) => {
  const { id } = req.params;
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id is required' });
  try {
    const channelResult = await pool.query(
      `SELECT channel_id, type, is_archived FROM channels WHERE channel_id = $1 AND tenant_id = $2`,
      [id, req.tenant_id],
    );
    const channel = channelResult.rows[0];
    if (!channel) return res.status(404).json({ error: 'Channel not found' });
    if (channel.is_archived) return res.status(400).json({ error: 'Channel is archived' });
    if (channel.type === 'private') {
      const memberResult = await pool.query(
        `SELECT role FROM channel_members WHERE channel_id = $1 AND user_id = $2 AND tenant_id = $3`,
        [id, req.user_id, req.tenant_id],
      );
      const callerRole = memberResult.rows[0] && memberResult.rows[0].role;
      if (!callerRole || !['admin', 'moderator'].includes(callerRole)) {
        return res.status(403).json({ error: 'Only admins or moderators can invite to private channels' });
      }
    }
    const userResult = await pool.query(
      `SELECT user_id FROM users WHERE user_id = $1 AND tenant_id = $2 AND is_active = true`,
      [user_id, req.tenant_id],
    );
    if (!userResult.rows[0]) return res.status(404).json({ error: 'User not found in this tenant' });
    await pool.query(
      `INSERT INTO channel_members (channel_id, user_id, tenant_id, role) VALUES ($1, $2, $3, 'member') ON CONFLICT (channel_id, user_id) DO NOTHING`,
      [id, user_id, req.tenant_id],
    );
    res.json({ status: 'ok' });
  } catch (err) {
    console.error('POST /channels/:id/invite error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/channels/:id/members
app.get('/api/channels/:id/members', requireTenant, async (req, res) => {
  const { id } = req.params;
  try {
    const memberCheck = await pool.query(
      `SELECT 1 FROM channel_members WHERE channel_id = $1 AND user_id = $2 AND tenant_id = $3`,
      [id, req.user_id, req.tenant_id],
    );
    if (!memberCheck.rows[0]) return res.status(403).json({ error: 'You are not a member of this channel' });
    const result = await pool.query(
      `SELECT u.user_id, u.email, u.display_name, u.avatar_url, u.status,
              cm.role AS channel_role, cm.joined_at, cm.last_read_at
       FROM channel_members cm
       JOIN users u ON u.user_id = cm.user_id AND u.tenant_id = cm.tenant_id
       WHERE cm.channel_id = $1 AND cm.tenant_id = $2
       ORDER BY cm.joined_at ASC`,
      [id, req.tenant_id],
    );
    res.json({ members: result.rows });
  } catch (err) {
    console.error('GET /channels/:id/members error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PATCH /api/channels/:id
app.patch('/api/channels/:id', requireTenant, async (req, res) => {
  const { id } = req.params;
  const { name, description, topic } = req.body;
  const setClauses = [];
  const values = [];
  if (name !== undefined) { values.push(name); setClauses.push(`name = $${values.length}`); }
  if (description !== undefined) { values.push(description); setClauses.push(`description = $${values.length}`); }
  if (topic !== undefined) { values.push(topic); setClauses.push(`topic = $${values.length}`); }
  if (setClauses.length === 0) {
    return res.status(400).json({ error: 'At least one of name, description, or topic is required' });
  }
  try {
    const memberCheck = await pool.query(
      `SELECT 1 FROM channel_members WHERE channel_id = $1 AND user_id = $2 AND tenant_id = $3`,
      [id, req.user_id, req.tenant_id],
    );
    if (!memberCheck.rows[0]) return res.status(403).json({ error: 'You are not a member of this channel' });
    values.push(id);
    const idParam = `$${values.length}`;
    values.push(req.tenant_id);
    const tenantParam = `$${values.length}`;
    const result = await pool.query(
      `UPDATE channels SET ${setClauses.join(', ')} WHERE channel_id = ${idParam} AND tenant_id = ${tenantParam} AND is_archived = false RETURNING *`,
      values,
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Channel not found or is archived' });
    res.json({ channel: result.rows[0] });
  } catch (err) {
    console.error('PATCH /channels/:id error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/channels/:id (archive)
app.delete('/api/channels/:id', requireTenant, async (req, res) => {
  const { id } = req.params;
  try {
    const memberResult = await pool.query(
      `SELECT role FROM channel_members WHERE channel_id = $1 AND user_id = $2 AND tenant_id = $3`,
      [id, req.user_id, req.tenant_id],
    );
    const callerRole = memberResult.rows[0] && memberResult.rows[0].role;
    if (!callerRole) return res.status(403).json({ error: 'You are not a member of this channel' });
    if (callerRole !== 'admin') return res.status(403).json({ error: 'Only channel admins can archive a channel' });
    const result = await pool.query(
      `UPDATE channels SET is_archived = true WHERE channel_id = $1 AND tenant_id = $2 AND is_archived = false RETURNING channel_id, name`,
      [id, req.tenant_id],
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Channel not found or already archived' });
    res.json({ status: 'ok', archived: result.rows[0] });
  } catch (err) {
    console.error('DELETE /channels/:id error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Routes: users ────────────────────────────────────────────────────────────

const USER_PUBLIC_FIELDS = `user_id, tenant_id, email, display_name, role,
  source_product, avatar_url, status, custom_status, last_active_at, created_at`;

// GET /api/users
app.get('/api/users', requireTenant, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ${USER_PUBLIC_FIELDS} FROM users WHERE tenant_id = $1 AND is_active = true ORDER BY display_name ASC`,
      [req.tenant_id],
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error('GET /users error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/users/:id
app.get('/api/users/:id', requireTenant, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `SELECT ${USER_PUBLIC_FIELDS} FROM users WHERE user_id = $1 AND tenant_id = $2 AND is_active = true`,
      [id, req.tenant_id],
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('GET /users/:id error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PATCH /api/users/me/status
app.patch('/api/users/me/status', requireTenant, async (req, res) => {
  const { status, custom_status } = req.body;
  const VALID_STATUSES = ['online', 'away', 'dnd', 'offline'];
  if (status !== undefined && !VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${VALID_STATUSES.join(', ')}` });
  }
  if (status === undefined && custom_status === undefined) {
    return res.status(400).json({ error: 'At least one of status or custom_status is required' });
  }
  const setClauses = ['last_active_at = NOW()'];
  const values = [];
  if (status !== undefined) { values.push(status); setClauses.push(`status = $${values.length}`); }
  if (custom_status !== undefined) { values.push(custom_status); setClauses.push(`custom_status = $${values.length}`); }
  values.push(req.user_id);
  values.push(req.tenant_id);
  try {
    const result = await pool.query(
      `UPDATE users SET ${setClauses.join(', ')} WHERE user_id = $${values.length - 1} AND tenant_id = $${values.length} RETURNING user_id, status, custom_status, last_active_at`,
      values,
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('PATCH /users/me/status error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PATCH /api/users/me/pinned-channels
app.patch('/api/users/me/pinned-channels', requireTenant, async (req, res) => {
  const { channel_id, action } = req.body;
  if (!channel_id || !action) return res.status(400).json({ error: 'channel_id and action are required' });
  if (!['pin', 'unpin'].includes(action)) return res.status(400).json({ error: 'action must be pin or unpin' });
  try {
    const memberCheck = await pool.query(
      `SELECT 1 FROM channel_members WHERE channel_id = $1 AND user_id = $2 AND tenant_id = $3`,
      [channel_id, req.user_id, req.tenant_id],
    );
    if (!memberCheck.rows[0]) return res.status(403).json({ error: 'You are not a member of this channel' });
    if (action === 'pin') {
      await pool.query(
        `INSERT INTO pinned_channels (user_id, channel_id, tenant_id) VALUES ($1, $2, $3) ON CONFLICT (user_id, channel_id) DO NOTHING`,
        [req.user_id, channel_id, req.tenant_id],
      );
    } else {
      await pool.query(
        `DELETE FROM pinned_channels WHERE user_id = $1 AND channel_id = $2 AND tenant_id = $3`,
        [req.user_id, channel_id, req.tenant_id],
      );
    }
    const pinned = await pool.query(
      `SELECT pc.channel_id, c.name, c.type, pc.pinned_at FROM pinned_channels pc JOIN channels c ON c.channel_id = pc.channel_id WHERE pc.user_id = $1 AND pc.tenant_id = $2 ORDER BY pc.pinned_at ASC`,
      [req.user_id, req.tenant_id],
    );
    res.json({ pinned_channels: pinned.rows });
  } catch (err) {
    console.error('PATCH /users/me/pinned-channels error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Routes: sync ─────────────────────────────────────────────────────────────

// POST /api/sync/users
app.post('/api/sync/users', async (req, res) => {
  const secret = process.env.SYNC_SECRET;
  if (!secret) return res.status(500).json({ error: 'SYNC_SECRET is not configured' });
  const provided = req.headers['x-sync-secret'];
  if (!provided || provided !== secret) return res.status(401).json({ error: 'Invalid or missing X-Sync-Secret header' });

  const { tenant_id, action, email, display_name, role, source_product } = req.body;
  if (!tenant_id || !action) return res.status(400).json({ error: 'tenant_id and action are required' });
  if (!['create', 'update', 'deactivate'].includes(action)) {
    return res.status(400).json({ error: 'action must be one of: create, update, deactivate' });
  }

  try {
    if (action === 'create') {
      if (!email || !display_name) return res.status(400).json({ error: 'email and display_name are required for create' });
      await pool.query(
        `INSERT INTO users (user_id, tenant_id, email, display_name, role, source_product, is_active)
         VALUES ($1, $2, $3, $4, $5, $6, true)
         ON CONFLICT (tenant_id, email) DO NOTHING`,
        [randomUUID(), tenant_id, email, display_name, role || 'member', source_product || null],
      );
      return res.json({ status: 'ok', action: 'created' });
    }
    if (action === 'update') {
      if (!email) return res.status(400).json({ error: 'email is required for update' });
      const setClauses = [];
      const values = [];
      if (display_name !== undefined) { values.push(display_name); setClauses.push(`display_name = $${values.length}`); }
      if (role !== undefined) { values.push(role); setClauses.push(`role = $${values.length}`); }
      if (source_product !== undefined) { values.push(source_product); setClauses.push(`source_product = $${values.length}`); }
      if (setClauses.length === 0) return res.status(400).json({ error: 'At least one field to update is required' });
      values.push(email);
      values.push(tenant_id);
      const result = await pool.query(
        `UPDATE users SET ${setClauses.join(', ')} WHERE email = $${values.length - 1} AND tenant_id = $${values.length}`,
        values,
      );
      if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
      return res.json({ status: 'ok', action: 'updated' });
    }
    if (action === 'deactivate') {
      if (!email) return res.status(400).json({ error: 'email is required for deactivate' });
      const result = await pool.query(
        `UPDATE users SET is_active = false WHERE email = $1 AND tenant_id = $2`,
        [email, tenant_id],
      );
      if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
      return res.json({ status: 'ok', action: 'deactivated' });
    }
  } catch (err) {
    console.error('Sync error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Routes: messages ─────────────────────────────────────────────────────────

// GET /api/messages?channel_id=:id[&before_id=:cursor]
// Cursor-based pagination — 50 messages per page, joined with sender info.
//
// Without before_id: returns the latest 50 messages ordered ASC.
// With    before_id: returns up to 50 messages strictly older than the cursor
//                    using (created_at, message_id) for deterministic tie-breaking,
//                    then re-ordered ASC for display.
//
// Response: { messages, has_more, oldest_message_id }
//   has_more          — true when older messages exist beyond this page
//   oldest_message_id — message_id of the earliest message in the page (use as next cursor)

const MSG_SELECT = `
  m.message_id,
  m.channel_id,
  m.tenant_id,
  m.sender_id,
  m.content,
  m.is_edited,
  m.is_deleted,
  m.created_at,
  m.updated_at,
  u.display_name AS sender_display_name,
  u.avatar_url   AS sender_avatar_url`;

app.get('/api/messages', requireTenant, async (req, res) => {
  const { channel_id, before_id } = req.query;

  if (!channel_id) {
    return res.status(400).json({ error: 'channel_id query parameter is required' });
  }

  try {
    // Caller must be a channel member (tenant-scoped gate)
    const memberCheck = await pool.query(
      `SELECT 1 FROM channel_members WHERE channel_id = $1 AND user_id = $2 AND tenant_id = $3`,
      [channel_id, req.user_id, req.tenant_id],
    );
    if (!memberCheck.rows[0]) {
      return res.status(403).json({ error: 'You are not a member of this channel' });
    }

    let rows;

    if (before_id) {
      // ── Cursor mode ─────────────────────────────────────────────────────────
      // Resolve the cursor message's created_at (needed for tie-breaking)
      const cursorRes = await pool.query(
        `SELECT created_at FROM messages WHERE message_id = $1 AND tenant_id = $2`,
        [before_id, req.tenant_id],
      );
      if (!cursorRes.rows[0]) {
        return res.status(404).json({ error: 'before_id message not found' });
      }
      const cursorTime = cursorRes.rows[0].created_at;

      // Fetch up to 50 messages strictly older than the cursor
      const result = await pool.query(
        `SELECT ${MSG_SELECT}
         FROM (
           SELECT * FROM messages
           WHERE channel_id = $1
             AND tenant_id  = $2
             AND is_deleted = false
             AND (
               created_at < $3
               OR (created_at = $3 AND message_id < $4)
             )
           ORDER BY created_at DESC, message_id DESC
           LIMIT 50
         ) m
         JOIN users u
           ON u.user_id   = m.sender_id
          AND u.tenant_id = m.tenant_id
         ORDER BY m.created_at ASC, m.message_id ASC`,
        [channel_id, req.tenant_id, cursorTime, before_id],
      );
      rows = result.rows;
    } else {
      // ── Initial load: latest 50 ──────────────────────────────────────────────
      const result = await pool.query(
        `SELECT ${MSG_SELECT}
         FROM (
           SELECT * FROM messages
           WHERE channel_id = $1
             AND tenant_id  = $2
             AND is_deleted = false
           ORDER BY created_at DESC
           LIMIT 50
         ) m
         JOIN users u
           ON u.user_id   = m.sender_id
          AND u.tenant_id = m.tenant_id
         ORDER BY m.created_at ASC`,
        [channel_id, req.tenant_id],
      );
      rows = result.rows;
    }

    // ── has_more ─────────────────────────────────────────────────────────────
    // After ASC re-ordering, rows[0] is the oldest message on this page.
    // has_more = true when at least one non-deleted message is older than it.
    const oldest = rows[0];
    let has_more = false;

    if (oldest) {
      const moreCheck = await pool.query(
        `SELECT 1 FROM messages
         WHERE channel_id = $1
           AND tenant_id  = $2
           AND is_deleted = false
           AND (
             created_at < $3
             OR (created_at = $3 AND message_id < $4)
           )
         LIMIT 1`,
        [channel_id, req.tenant_id, oldest.created_at, oldest.message_id],
      );
      has_more = moreCheck.rows.length > 0;
    }

    res.json({
      messages: rows,
      has_more,
      oldest_message_id: oldest?.message_id ?? null,
    });
  } catch (err) {
    console.error('GET /messages error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Routes: DMs ──────────────────────────────────────────────────────────────

// POST /api/dm/find-or-create
// Find or create a private DM channel between the caller and target_user_id
app.post('/api/dm/find-or-create', requireTenant, async (req, res) => {
  const { target_user_id } = req.body;

  if (!target_user_id) {
    return res.status(400).json({ error: 'target_user_id is required' });
  }
  if (target_user_id === req.user_id) {
    return res.status(400).json({ error: 'Cannot create a DM with yourself' });
  }

  try {
    // Verify target user exists and is active in this tenant
    const targetCheck = await pool.query(
      `SELECT user_id FROM users WHERE user_id = $1 AND tenant_id = $2 AND is_active = true`,
      [target_user_id, req.tenant_id],
    );
    if (!targetCheck.rows[0]) {
      return res.status(404).json({ error: 'Target user not found in this tenant' });
    }

    // Check for an existing DM channel between both users in this tenant
    const existing = await pool.query(
      `SELECT c.*
       FROM channels c
       JOIN channel_members cm1 ON cm1.channel_id = c.channel_id AND cm1.user_id = $1
       JOIN channel_members cm2 ON cm2.channel_id = c.channel_id AND cm2.user_id = $2
       WHERE c.tenant_id = $3 AND c.type = 'dm' AND c.is_archived = false
       LIMIT 1`,
      [req.user_id, target_user_id, req.tenant_id],
    );

    if (existing.rows[0]) {
      return res.json({ channel: existing.rows[0], created: false });
    }

    // Create new DM channel in a transaction
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const channelId = randomUUID();
      const channelResult = await client.query(
        `INSERT INTO channels (channel_id, tenant_id, name, type, created_by)
         VALUES ($1, $2, $3, 'dm', $4) RETURNING *`,
        [channelId, req.tenant_id, `dm:${req.user_id}:${target_user_id}`, req.user_id],
      );

      await client.query(
        `INSERT INTO channel_members (channel_id, user_id, tenant_id, role)
         VALUES ($1, $2, $3, 'member'), ($1, $4, $3, 'member')`,
        [channelId, req.user_id, req.tenant_id, target_user_id],
      );

      await client.query('COMMIT');
      res.status(201).json({ channel: channelResult.rows[0], created: true });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('POST /dm/find-or-create error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Routes: read receipts ────────────────────────────────────────────────────

// GET /api/messages/:id/reads
// Returns users who have read this message.
// Only the message sender or an admin may access this endpoint (tenant-scoped).
app.get('/api/messages/:id/reads', requireTenant, async (req, res) => {
  const { id: message_id } = req.params;

  try {
    // Verify the message exists in this tenant
    const msgCheck = await pool.query(
      `SELECT sender_id FROM messages WHERE message_id = $1 AND tenant_id = $2`,
      [message_id, req.tenant_id],
    );
    if (!msgCheck.rows[0]) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Only sender or admins can inspect reads
    const { sender_id } = msgCheck.rows[0];
    if (req.user_id !== sender_id && req.user_role !== 'admin') {
      return res.status(403).json({ error: 'Only the message sender or an admin can view read receipts' });
    }

    // Fetch read records joined with user profile
    const result = await pool.query(
      `SELECT
         mr.user_id,
         u.display_name,
         u.avatar_url,
         mr.read_at
       FROM message_reads mr
       JOIN users u
         ON u.user_id   = mr.user_id
        AND u.tenant_id = mr.tenant_id
       WHERE mr.message_id = $1
         AND mr.tenant_id  = $2
       ORDER BY mr.read_at ASC`,
      [message_id, req.tenant_id],
    );

    res.json({ reads: result.rows });
  } catch (err) {
    console.error('GET /messages/:id/reads error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/messages/:id/readers
// Returns every user who has read this message.
// Accessible to: the message sender, admins, and moderators. 403 otherwise.
// Returns an empty readers array when nobody has read the message yet.
app.get('/api/messages/:id/readers', requireTenant, async (req, res) => {
  const { id: message_id } = req.params;

  try {
    // Verify the message exists in this tenant
    const msgCheck = await pool.query(
      `SELECT sender_id FROM messages WHERE message_id = $1 AND tenant_id = $2`,
      [message_id, req.tenant_id],
    );
    if (!msgCheck.rows[0]) {
      return res.status(404).json({ error: 'Message not found' });
    }

    // Only the sender, admins, or moderators may view reader details
    const { sender_id } = msgCheck.rows[0];
    const isPrivileged = req.user_role === 'admin' || req.user_role === 'moderator';
    if (req.user_id !== sender_id && !isPrivileged) {
      return res.status(403).json({
        error: 'Only the message sender, admins, or moderators can view readers',
      });
    }

    // Join message_reads with users to get profile info, ordered oldest-read first
    const result = await pool.query(
      `SELECT
         mr.user_id,
         u.display_name,
         u.avatar_url,
         mr.read_at
       FROM message_reads mr
       JOIN users u
         ON u.user_id   = mr.user_id
        AND u.tenant_id = mr.tenant_id
       WHERE mr.message_id = $1
         AND mr.tenant_id  = $2
       ORDER BY mr.read_at ASC`,
      [message_id, req.tenant_id],
    );

    res.json({ readers: result.rows });
  } catch (err) {
    console.error('GET /messages/:id/readers error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── HTTP server + Socket.io ──────────────────────────────────────────────────

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
    credentials: false,
  },
  transports: ['websocket'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000,
});

// Keyed by user_id → Set of socket IDs (multiple tabs supported)
const connectedUsers = new Map();

// ── Auth middleware ──────────────────────────────────────────────────────────
// Token is optional: unauthenticated connections are allowed but marked as such.
// Authenticated sockets get user_id / tenant_id / role attached.
io.use((socket, next) => {
  console.log('Socket connection attempt, auth:', socket.handshake.auth);

  const token = socket.handshake.auth && socket.handshake.auth.token;

  if (!token) {
    socket.authenticated = false;
    return next();
  }

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    console.log('JWT validation error: JWT_SECRET is not configured');
    socket.authenticated = false;
    return next();
  }

  try {
    const payload = jwt.verify(token, secret);
    if (!payload.user_id || !payload.tenant_id) {
      console.log('JWT validation error: invalid token claims (missing user_id or tenant_id)');
      socket.authenticated = false;
      return next();
    }
    socket.authenticated = true;
    socket.user_id      = payload.user_id;
    socket.tenant_id    = payload.tenant_id;
    socket.email        = payload.email;
    socket.display_name = payload.display_name;
    socket.role         = payload.role;
    next();
  } catch (err) {
    console.log('JWT validation error:', err.message);
    socket.authenticated = false;
    next();
  }
});

// ── Connection handler ───────────────────────────────────────────────────────
io.on('connection', async (socket) => {
  // Unauthenticated sockets are permitted to connect but get no tenant access
  if (!socket.authenticated) {
    console.log(`⚠ Socket connected (unauthenticated)  id=${socket.id}`);
    return;
  }

  const { user_id, tenant_id, display_name } = socket;
  console.log(`✓ Socket connected  user=${user_id}  tenant=${tenant_id}  id=${socket.id}`);

  // Track connected sockets
  if (!connectedUsers.has(user_id)) connectedUsers.set(user_id, new Set());
  connectedUsers.get(user_id).add(socket.id);

  // Join tenant-scoped rooms for all the user's channels
  try {
    const result = await pool.query(
      `SELECT channel_id FROM channel_members WHERE user_id = $1 AND tenant_id = $2`,
      [user_id, tenant_id],
    );

    const rooms = [];
    for (const row of result.rows) {
      const room = `${tenant_id}:${row.channel_id}`;
      socket.join(room);
      rooms.push(room);
    }

    // Personal room for DMs / notifications
    const personalRoom = `${tenant_id}:user:${user_id}`;
    socket.join(personalRoom);

    // Tenant-wide room for presence broadcasts
    const tenantRoom = `tenant:${tenant_id}`;
    socket.join(tenantRoom);

    console.log(`  → Joined ${rooms.length} channel room(s) + personal + tenant room  user=${user_id}`);

    socket.emit('connection_ready', {
      user_id,
      tenant_id,
      display_name,
      rooms,
      personal_room: personalRoom,
    });
  } catch (err) {
    console.error(`  ✗ Failed to load channels for user=${user_id}:`, err.message);
    socket.emit('auth_error', { message: 'Failed to load channel memberships' });
    socket.disconnect(true);
    return;
  }

  // ── Presence ───────────────────────────────────────────────────────────────
  const tenantRoom  = `tenant:${tenant_id}`;
  const presenceKey = `presence:${tenant_id}:${user_id}`;
  let presenceTimer = null;

  if (redisClient) {
    (async () => {
      try {
        // 1. Mark online with 60 s TTL
        await redisClient.set(presenceKey, 'online', { EX: 60 });

        // 2. Refresh TTL every 30 s — re-SET so the expiry always resets
        presenceTimer = setInterval(async () => {
          try { await redisClient.set(presenceKey, 'online', { EX: 60 }); } catch { /* swallow */ }
        }, 30_000);

        // 3. Broadcast presence_update to ALL sockets in the tenant room
        io.to(tenantRoom).emit('presence_update', { user_id, status: 'online' });

        // 4. Collect all current presence keys for this tenant
        //    Use KEYS (fine at tenant scale; avoids scanIterator API changes in v5)
        const keys = await redisClient.keys(`presence:${tenant_id}:*`);

        // 5. Emit initial_presence snapshot to the connecting socket only
        let presences = [];
        if (keys.length > 0) {
          const values = await redisClient.mGet(keys);
          presences = keys.map((key, i) => ({
            user_id: key.split(':')[2],
            status:  values[i] ?? 'offline',
          }));
        }
        socket.emit('initial_presence', { presences });

        console.log(`  → Presence: online  user=${user_id}  tenantRoom=${tenantRoom}`);
      } catch (err) {
        console.error(`  ✗ Presence setup error user=${user_id}:`, err.message);
      }
    })();
  }

  // ── Per-socket middleware: update last_active_at on every event ──────────
  // Fire-and-forget — never blocks event handling
  socket.use(([_event], next) => {
    pool
      .query(
        `UPDATE users SET last_active_at = NOW() WHERE user_id = $1 AND tenant_id = $2`,
        [user_id, tenant_id],
      )
      .catch((err) => console.error('last_active_at update error:', err.message));
    next();
  });

  // ── send_message ─────────────────────────────────────────────────────────
  socket.on('send_message', async (payload) => {
    const channel_id = payload && payload.channel_id;
    const content    = payload && payload.content;

    if (!channel_id || !content || !content.trim()) {
      socket.emit('message_error', { error: 'channel_id and content are required' });
      return;
    }

    try {
      // Verify sender is a member of this channel (tenant-scoped)
      const memberCheck = await pool.query(
        `SELECT 1 FROM channel_members WHERE channel_id = $1 AND user_id = $2 AND tenant_id = $3`,
        [channel_id, user_id, tenant_id],
      );
      if (!memberCheck.rows[0]) {
        socket.emit('message_error', { error: 'Not a member of this channel' });
        return;
      }

      // Persist to DB
      const result = await pool.query(
        `INSERT INTO messages (message_id, tenant_id, channel_id, sender_id, content)
         VALUES (gen_random_uuid(), $1, $2, $3, $4)
         RETURNING message_id, channel_id, sender_id, content,
                   is_edited, is_deleted, created_at, updated_at`,
        [tenant_id, channel_id, user_id, content.trim()],
      );

      const message = { ...result.rows[0], display_name, tenant_id };
      const room = `${tenant_id}:${channel_id}`;

      // Broadcast to ALL sockets in the room including sender
      io.to(room).emit('new_message', message);

      // Acknowledge to sender with persisted record
      socket.emit('message_confirmed', message);

      // Delivery confirmation — message safely persisted in DB
      socket.emit('message_delivered', {
        message_id: message.message_id,
        status: 'delivered',
      });

      console.log(`  ✉ message  channel=${channel_id}  user=${user_id}  id=${message.message_id}`);
    } catch (err) {
      console.error(`  ✗ send_message error:`, err.message);
      socket.emit('message_error', { error: 'Failed to save message' });
    }
  });

  // ── mark_read ─────────────────────────────────────────────────────────────
  // Client emits when user opens a channel.
  // Upserts read records for every unread message in that channel.
  socket.on('mark_read', async (payload) => {
    const channel_id = payload && payload.channel_id;
    if (!channel_id) return;

    try {
      // Upsert read records for all unread messages in the channel.
      // RETURNING lets us know which rows were newly inserted.
      const inserted = await pool.query(
        `INSERT INTO message_reads (message_id, user_id, tenant_id, read_at)
         SELECT m.message_id, $1::varchar, $2::varchar, NOW()
         FROM messages m
         WHERE m.channel_id = $3::varchar
           AND m.tenant_id  = $2::varchar
           AND m.is_deleted = false
         ON CONFLICT (message_id, user_id) DO NOTHING
         RETURNING message_id`,
        [user_id, tenant_id, channel_id],
      );

      // Ack back to the reader immediately
      socket.emit('messages_marked_read', { channel_id, user_id });
      console.log(`  ✓ mark_read  channel=${channel_id}  user=${user_id}  newly_read=${inserted.rows.length}`);

      // For each newly-read message, notify its sender via their personal room
      if (inserted.rows.length > 0) {
        const messageIds = inserted.rows.map(r => r.message_id);

        const senders = await pool.query(
          `SELECT message_id, sender_id FROM messages
           WHERE message_id = ANY($1)
             AND sender_id != $2`,    // skip self-reads
          [messageIds, user_id],
        );

        for (const { message_id, sender_id } of senders.rows) {
          const senderRoom = `${tenant_id}:user:${sender_id}`;
          io.to(senderRoom).emit('message_read', {
            message_id,
            reader_user_id: user_id,
            status: 'read',
          });
        }
      }
    } catch (err) {
      console.error(`  ✗ mark_read error:`, err.message);
    }
  });

  // ── typing_start ──────────────────────────────────────────────────────────
  socket.on('typing_start', async (payload) => {
    const channel_id = payload && payload.channel_id;
    if (!channel_id) return;

    const room     = `${tenant_id}:${channel_id}`;
    const redisKey = `typing:${tenant_id}:${channel_id}:${user_id}`;

    if (redisClient) {
      try { await redisClient.set(redisKey, '1', { EX: 5 }); } catch { /* optional */ }
    }

    socket.to(room).emit('user_typing', { user_id, display_name, channel_id });
  });

  // ── typing_stop ───────────────────────────────────────────────────────────
  socket.on('typing_stop', async (payload) => {
    const channel_id = payload && payload.channel_id;
    if (!channel_id) return;

    const room     = `${tenant_id}:${channel_id}`;
    const redisKey = `typing:${tenant_id}:${channel_id}:${user_id}`;

    if (redisClient) {
      try { await redisClient.del(redisKey); } catch { /* optional */ }
    }

    socket.to(room).emit('user_stopped_typing', { user_id, display_name, channel_id });
  });

  // ── Disconnect cleanup ───────────────────────────────────────────────────
  socket.on('disconnect', async (reason) => {
    // Stop TTL refresh immediately
    if (presenceTimer) {
      clearInterval(presenceTimer);
      presenceTimer = null;
    }

    const userSockets = connectedUsers.get(user_id);
    if (userSockets) {
      userSockets.delete(socket.id);
      // Only mark offline when the LAST socket for this user is gone
      if (userSockets.size === 0) {
        connectedUsers.delete(user_id);
        if (redisClient) {
          try {
            await redisClient.del(presenceKey);
            io.to(tenantRoom).emit('presence_update', { user_id, status: 'offline' });
            console.log(`  → Presence: offline  user=${user_id}`);
          } catch { /* non-fatal */ }
        }
      }
    }
    console.log(`✗ Socket disconnected  user=${user_id}  id=${socket.id}  reason=${reason}`);
  });
});

// ─── Routes: message edit and delete ─────────────────────────────────────────

// PATCH /api/messages/:id — edit a message (sender only)
// Emits "message_updated" to the channel room.
app.patch('/api/messages/:id', requireTenant, async (req, res) => {
  const { id: message_id } = req.params;
  const { content } = req.body;

  if (!content || !content.trim()) {
    return res.status(400).json({ error: 'content is required' });
  }

  try {
    // Verify message exists, is not deleted, and caller is the sender
    const msgCheck = await pool.query(
      `SELECT sender_id, channel_id FROM messages
       WHERE message_id = $1 AND tenant_id = $2 AND is_deleted = false`,
      [message_id, req.tenant_id],
    );
    if (!msgCheck.rows[0]) {
      return res.status(404).json({ error: 'Message not found' });
    }

    const { sender_id, channel_id } = msgCheck.rows[0];
    if (sender_id !== req.user_id) {
      return res.status(403).json({ error: 'Only the message sender can edit this message' });
    }

    // Apply the edit
    const updated = await pool.query(
      `UPDATE messages
       SET content    = $1,
           is_edited  = true,
           updated_at = NOW()
       WHERE message_id = $2 AND tenant_id = $3
       RETURNING message_id, channel_id, tenant_id, sender_id,
                 content, is_edited, is_deleted, created_at, updated_at`,
      [content.trim(), message_id, req.tenant_id],
    );

    const message = updated.rows[0];

    // Broadcast to channel room so all clients update in real time
    const room = `${req.tenant_id}:${channel_id}`;
    io.to(room).emit('message_updated', message);

    res.json({ message });
  } catch (err) {
    console.error('PATCH /messages/:id error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/messages/:id — soft-delete a message
// Allowed: admin/moderator always; sender if channel.members_can_delete_messages=true.
// Emits "message_deleted" to the channel room.
app.delete('/api/messages/:id', requireTenant, async (req, res) => {
  const { id: message_id } = req.params;

  try {
    // Fetch message + channel permission flag in one query
    const msgCheck = await pool.query(
      `SELECT m.sender_id, m.channel_id, c.members_can_delete_messages
       FROM messages m
       JOIN channels c
         ON c.channel_id = m.channel_id
        AND c.tenant_id  = m.tenant_id
       WHERE m.message_id = $1
         AND m.tenant_id  = $2
         AND m.is_deleted = false`,
      [message_id, req.tenant_id],
    );
    if (!msgCheck.rows[0]) {
      return res.status(404).json({ error: 'Message not found' });
    }

    const { sender_id, channel_id, members_can_delete_messages } = msgCheck.rows[0];
    const isPrivileged  = req.user_role === 'admin' || req.user_role === 'moderator';
    const isSenderAllow = req.user_id === sender_id && members_can_delete_messages;

    if (!isPrivileged && !isSenderAllow) {
      return res.status(403).json({ error: 'You do not have permission to delete this message' });
    }

    // Soft-delete — preserve row for audit/read-receipt history
    await pool.query(
      `UPDATE messages
       SET is_deleted = true,
           content    = '',
           updated_at = NOW()
       WHERE message_id = $1 AND tenant_id = $2`,
      [message_id, req.tenant_id],
    );

    // Notify all clients in the channel room
    const room = `${req.tenant_id}:${channel_id}`;
    io.to(room).emit('message_deleted', { message_id, channel_id });

    res.json({ success: true, message_id, channel_id });
  } catch (err) {
    console.error('DELETE /messages/:id error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || '3001', 10);

// Idempotent migration: ensure members_can_delete_messages column exists
async function migrateDb() {
  try {
    await pool.query(
      `ALTER TABLE channels
       ADD COLUMN IF NOT EXISTS members_can_delete_messages BOOLEAN DEFAULT false`,
    );
    console.log('DB migration: channels.members_can_delete_messages ensured');
  } catch (err) {
    console.error('DB migration warning:', err.message);
  }
}

connectRedis()
  .then(() => migrateDb())
  .then(() => {
    server.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Startup error:', err.message);
    process.exit(1);
  });
