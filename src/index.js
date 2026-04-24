// aurora-chat — Cloudflare Worker
// Handles: POST /auth/register, POST /auth/login, GET /ws (WebSocket upgrade)

import { ChatRoom } from './chatroom.js';
export { ChatRoom };

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

// ── PBKDF2 password hashing ──────────────────────────────────────────────────
async function hashPassword(password) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 },
    keyMaterial, 256
  );
  const hashArr = Array.from(new Uint8Array(bits));
  const saltArr = Array.from(salt);
  return JSON.stringify({ hash: hashArr, salt: saltArr });
}

async function verifyPassword(password, stored) {
  const enc = new TextEncoder();
  const { hash, salt } = JSON.parse(stored);
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: new Uint8Array(salt), iterations: 100000 },
    keyMaterial, 256
  );
  const attempt = Array.from(new Uint8Array(bits));
  return attempt.length === hash.length && attempt.every((b, i) => b === hash[i]);
}

// ── JWT (HS256 via crypto.subtle) ────────────────────────────────────────────
function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signJWT(payload, secret) {
  const enc = new TextEncoder();
  const header = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`));
  return `${header}.${body}.${b64url(sig)}`;
}

async function verifyJWT(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBuf = Uint8Array.from(atob(sig.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, enc.encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body.replace(/-/g,'+').replace(/_/g,'/')));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch { return null; }
}

// ── Rate limiting via KV ─────────────────────────────────────────────────────
async function checkRateLimit(kv, ip) {
  const key = `ratelimit:${ip}`;
  const raw = await kv.get(key);
  const data = raw ? JSON.parse(raw) : { count: 0, reset: Date.now() + 15 * 60 * 1000 };
  if (Date.now() > data.reset) { data.count = 0; data.reset = Date.now() + 15 * 60 * 1000; }
  if (data.count >= 5) return false;
  data.count++;
  await kv.put(key, JSON.stringify(data), { expirationTtl: 900 });
  return true;
}

// ── Main handler ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // Normalize path — strip trailing slash
    const path = url.pathname.replace(/\/$/, '') || '/';

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    if (path === '/auth/register' && request.method === 'POST') {
      const { username, password } = await request.json();
      if (!username || !password) return json({ error: 'Username and password required' }, 400);
      if (username.length < 2 || username.length > 24) return json({ error: 'Username must be 2–24 characters' }, 400);
      if (!/^[a-zA-Z0-9_]+$/.test(username)) return json({ error: 'Username: letters, numbers, underscores only' }, 400);
      if (password.length < 6) return json({ error: 'Password must be at least 6 characters' }, 400);
      const existing = await env.USERS.get(`user:${username.toLowerCase()}`);
      if (existing) return json({ error: 'Username already taken' }, 409);
      const passwordHash = await hashPassword(password);
      await env.USERS.put(`user:${username.toLowerCase()}`, JSON.stringify({
        username, passwordHash, createdAt: Date.now()
      }));
      const token = await signJWT(
        { sub: username, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 86400 },
        env.JWT_SECRET
      );
      return json({ token, username });
    }

    if (path === '/auth/login' && request.method === 'POST') {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const allowed = await checkRateLimit(env.USERS, ip);
      if (!allowed) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);
      const { username, password } = await request.json();
      if (!username || !password) return json({ error: 'Username and password required' }, 400);
      const raw = await env.USERS.get(`user:${username.toLowerCase()}`);
      if (!raw) return json({ error: 'Invalid username or password' }, 401);
      const user = JSON.parse(raw);
      const valid = await verifyPassword(password, user.passwordHash);
      if (!valid) return json({ error: 'Invalid username or password' }, 401);
      const token = await signJWT(
        { sub: user.username, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 86400 },
        env.JWT_SECRET
      );
      return json({ token, username: user.username });
    }

    if (path === '/ws') {
      const token = url.searchParams.get('token');
      if (!token) return json({ error: 'Token required' }, 401);
      const payload = await verifyJWT(token, env.JWT_SECRET);
      if (!payload) return json({ error: 'Invalid or expired token' }, 401);
      // Route all connections to the single ChatRoom Durable Object
      const id = env.CHATROOM.idFromName('main');
      const room = env.CHATROOM.get(id);
      // Pass username via header to the DO
      const modifiedRequest = new Request(request, {
        headers: { ...Object.fromEntries(request.headers), 'X-Username': payload.sub }
      });
      return room.fetch(modifiedRequest);
    }

    return json({ error: 'Not found' }, 404);
  }
};
