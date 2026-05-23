// functions/api/waitlist.js
// Cloudflare Pages Function — POST /api/waitlist
//
// Stores waitlist email signups in a D1 database.
// Runs on Cloudflare's edge (V8 isolate, no cold start).
//
// Required binding in Cloudflare dashboard (Pages > Settings > Functions > D1 bindings):
//   variable name: DB
//   database: pakketradar-waitlist

// Simple email validator — RFC 5322 is ridiculous, this catches real mistakes
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// JSON response helper with CORS and no-cache headers
function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}

// Handle CORS preflight
export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    },
  });
}

// Block anything that isn't POST
export async function onRequestGet() {
  return json({ error: 'Method not allowed' }, 405);
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. Parse input — accept both JSON (preferred) and form-encoded
  let email = '';
  let honeypot = '';
  const contentType = request.headers.get('content-type') || '';

  try {
    if (contentType.includes('application/json')) {
      const body = await request.json();
      email = String(body.email || '').trim().toLowerCase();
      honeypot = String(body.website || '').trim();
    } else if (contentType.includes('form')) {
      const form = await request.formData();
      email = String(form.get('email') || '').trim().toLowerCase();
      honeypot = String(form.get('website') || '').trim();
    } else {
      return json({ error: 'Unsupported content type' }, 415);
    }
  } catch (err) {
    return json({ error: 'Invalid request body' }, 400);
  }

  // 2. Honeypot: real humans leave it empty; bots fill it.
  //    We pretend-accept spam (200 OK) so bots don't learn.
  if (honeypot) {
    return json({ ok: true, message: 'Bedankt!' });
  }

  // 3. Validate email
  if (!email || email.length > 254 || !EMAIL_RE.test(email)) {
    return json({ error: 'Ongeldig e-mailadres' }, 400);
  }

  // 4. Rate-limit by IP using Cloudflare's built-in cf-connecting-ip.
  //    We keep it simple: one signup per IP per 60 seconds.
  //    For production at scale, swap this for Cloudflare Rate Limiting rules.
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';

  try {
    // Check recent submissions from this IP
    const recent = await env.DB.prepare(
      `SELECT COUNT(*) as n FROM waitlist
       WHERE ip_hash = ?
         AND created_at > strftime('%s', 'now') - 60`
    )
      .bind(await hashIp(ip))
      .first();

    if (recent && recent.n > 0) {
      return json({ error: 'Even geduld — probeer over een minuut opnieuw' }, 429);
    }
  } catch (err) {
    // If D1 is unavailable, log and continue. Rate-limit is nice-to-have.
    console.error('Rate-limit check failed:', err);
  }

  // 5. Insert — uses UNIQUE constraint on email so duplicates fail gracefully
  try {
    const ipHash = await hashIp(ip);
    const userAgent = (request.headers.get('user-agent') || '').slice(0, 255);
    const country = request.headers.get('cf-ipcountry') || 'XX';
    const referer = (request.headers.get('referer') || '').slice(0, 255);

    await env.DB.prepare(
      `INSERT INTO waitlist (email, ip_hash, user_agent, country, referer, created_at)
       VALUES (?, ?, ?, ?, ?, strftime('%s', 'now'))`
    )
      .bind(email, ipHash, userAgent, country, referer)
      .run();

    return json({ ok: true, message: 'Bedankt! We sturen je bericht zodra we live gaan.' });
  } catch (err) {
    // SQLite UNIQUE constraint error → already on the list. Treat as success.
    if (err && err.message && err.message.includes('UNIQUE')) {
      return json({ ok: true, message: 'Je staat al op de wachtlijst.' });
    }
    console.error('Waitlist insert failed:', err);
    return json({ error: 'Er ging iets mis. Probeer het later opnieuw.' }, 500);
  }
}

// Hash IP address with SHA-256 so we never store raw IPs (GDPR-friendlier).
async function hashIp(ip) {
  const encoder = new TextEncoder();
  // Add a static salt so rainbow-table attacks on common IPs don't work
  const data = encoder.encode('pakketradar-v1:' + ip);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
