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

    // POST /auth/register
    if (path === '/auth/register' && request.method === 'POST') {
      const { username, password, turnstileToken } = await request.json();
      if (!username || !password) return json({ error: 'Username and password required' }, 400);

      // Verify Turnstile token
      if (!turnstileToken) return json({ error: 'Please complete the captcha' }, 400);
      const tsRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: env.TURNSTILE_SECRET, response: turnstileToken }),
      });
      const tsData = await tsRes.json();
      if (!tsData.success) return json({ error: 'Captcha verification failed. Please try again.' }, 400);

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

    if (path === '/igdb' && request.method === 'GET') {
      const genre = url.searchParams.get('genre');
      if (!genre) return json({ error: 'genre required' }, 400);

      if (!env.IGDB_CLIENT_ID || !env.IGDB_CLIENT_SECRET) {
        return json({ error: 'IGDB not configured' }, 503);
      }

      // Cache results for 6 hours
      const cacheKey = `igdb_genre:${genre.toLowerCase()}`;
      const cached = await env.USERS.get(cacheKey);
      if (cached) {
        return new Response(cached, {
          headers: { 'Content-Type': 'application/json', ...CORS }
        });
      }

      // Get/refresh OAuth token (cached in KV)
      let token = await env.USERS.get('igdb_token');
      if (!token) {
        const tokenRes = await fetch(
          `https://id.twitch.tv/oauth2/token?client_id=${env.IGDB_CLIENT_ID}&client_secret=${env.IGDB_CLIENT_SECRET}&grant_type=client_credentials`,
          { method: 'POST' }
        );
        if (!tokenRes.ok) return json({ error: 'IGDB auth failed' }, 502);
        const tokenData = await tokenRes.json();
        token = tokenData.access_token;
        // Cache token for slightly less than its expiry (~55 days)
        await env.USERS.put('igdb_token', token, { expirationTtl: 4700000 });
      }

      // IGDB genre IDs (verified): https://api.igdb.com/v4/genres
      // IGDB theme IDs: https://api.igdb.com/v4/themes
      const GENRE_MAP = {
        'relaxing':   { type: 'theme',  id: 21,   label: 'Sandbox' },  // use Sandbox theme + filter for peaceful games
        'rpg':        { type: 'genre',  id: 12  },
        'indie':      { type: 'genre',  id: 32  },
        'puzzle':     { type: 'genre',  id: 9   },
        'horror':     { type: 'theme',  id: 19  },
        'strategy':   { type: 'genre',  id: 15  },
        'simulation': { type: 'genre',  id: 13  },
        'platformer': { type: 'genre',  id: 8   },
        'roguelike':  { type: 'theme',  id: 23  },  // Survival theme — closest
        'open world': { type: 'theme',  id: 33  },  // Open world theme
      };

      const genreInfo = GENRE_MAP[genre.toLowerCase()] || { type: 'genre', id: 12 };
      const filterField = genreInfo.type === 'theme' ? 'themes' : 'genres';

      // Query IGDB — top rated games with Steam links
      const eightYearsAgo = Math.floor(Date.now() / 1000) - (8 * 365 * 24 * 3600);
      const offset = Math.floor(Math.random() * 8) * 10;
      const igdbRes = await fetch('https://api.igdb.com/v4/games', {
        method: 'POST',
        headers: {
          'Client-ID': env.IGDB_CLIENT_ID,
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'text/plain',
        },
        body: `
          fields name, summary, rating, rating_count, cover.url, websites.url, websites.category, genres.name, themes.name;
          where ${filterField} = (${genreInfo.id})
            & rating >= 65
            & rating_count >= 10
            & category = 0
            & version_parent = null;
          sort rating_count desc;
          limit 50;
          offset ${offset};
        `
      });

      if (!igdbRes.ok) {
        // Token may have expired, clear it and retry once
        await env.USERS.delete('igdb_token');
        return json({ error: 'IGDB request failed, try again' }, 502);
      }

      const games = await igdbRes.json();
      if (!games.length) return json({ error: 'No games found' }, 404);

      // Extract Steam URL (category 13 = Steam)
      const results = games
        .map(g => {
          const steamSite = g.websites?.find(w => w.category === 13 || (w.url && w.url.includes('store.steampowered.com')));
          const steamUrl = steamSite?.url || null;
          const appid = steamUrl ? steamUrl.match(/app\/(\d+)/)?.[1] : null;
          return {
            name: g.name,
            summary: g.summary ? g.summary.slice(0, 200) + (g.summary.length > 200 ? '…' : '') : null,
            score: Math.round(g.rating),
            rating_count: g.rating_count,
            cover: g.cover?.url ? 'https:' + g.cover.url.replace('t_thumb', 't_cover_big') : null,
            steamUrl,
            appid,
            genres: (g.genres?.map(ge => ge.name) || []).concat(g.themes?.map(t => t.name) || []).slice(0,3).join(', ') || null,
          };
        })
        .filter(g => g.steamUrl);

      // Fall back to all games if none have Steam links
      const finalResults = results.length > 0 ? results : games.map(g => ({
        name: g.name,
        summary: g.summary ? g.summary.slice(0, 200) + (g.summary.length > 200 ? '…' : '') : null,
        score: Math.round(g.rating || 0),
        rating_count: g.rating_count || 0,
        cover: g.cover?.url ? 'https:' + g.cover.url.replace('t_thumb', 't_cover_big') : null,
        steamUrl: `https://www.igdb.com/games/${g.name.toLowerCase().replace(/[^a-z0-9]/g,'-')}`,
        appid: null,
        genres: (g.genres?.map(ge => ge.name) || []).slice(0,3).join(', ') || null,
      }));

      if (!finalResults.length) return json({ error: 'No games found for this genre' }, 404);

      const result = JSON.stringify(finalResults);
      await env.USERS.put(cacheKey, result, { expirationTtl: 21600 });
      return new Response(result, {
        headers: { 'Content-Type': 'application/json', ...CORS }
      });
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
