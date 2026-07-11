'use strict';

/*
 * CedarCrypt - WAICT workshop demo server (Exercise 1: the vulnerable app)
 * ------------------------------------------------------------------------
 * A tiny web app that shows a cat and has an "admin console" for swapping the
 * displayed image. It is DELIBERATELY insecure so we can attack it.
 *
 * No dependencies -- uses only Node's built-in modules.
 *
 * Run:   node server.js
 * Open:  http://localhost:3000
 * Admin: http://localhost:3000/admin
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const STATE_FILE = path.join(__dirname, 'state.json');

/* ------------------------------------------------------------------ *
 * "User database"
 *
 * There is exactly one user: admin. The password is stored as a plain
 * SHA-256 hash (no salt, no slow KDF). This is the WRONG way to store a
 * password -- SHA-256 is fast and unsalted, so a weak password falls to a
 * tool like hashcat in seconds. That is the whole point of Exercise 1.
 *
 *   admin password  ->  SHA-256  ->  the hex string below
 * ------------------------------------------------------------------ */
const ADMIN_USER = 'admin';
// FIXME(dev): temporary creds for local testing -> admin / sunshine
//             rotate this and move it to a secret store before shipping!!
const ADMIN_PASSWORD_SHA256 =
  'a941a4c4fd0c01cddef61b8be963bf4c1e2b0811c037ce3f1835fddf6ef6c223';

function sha256hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/* ------------------------------------------------------------------ *
 * App state: which image is currently shown on the home page.
 * Persisted to state.json so a "defacement" survives a page reload
 * (and a server restart), just like a real compromised server would.
 * ------------------------------------------------------------------ */
const DEFAULT_IMAGE = 'cat.jpg';
const AVAILABLE_IMAGES = ['cat.jpg', 'evil.jpg'];

function readState() {
  try {
    const state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    if (AVAILABLE_IMAGES.includes(state.image)) return state;
  } catch (_) {
    /* no state yet -> fall through to default */
  }
  return { image: DEFAULT_IMAGE };
}

function writeState(state) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

/* ------------------------------------------------------------------ *
 * Super-simple in-memory sessions.
 * A random token in a cookie -> "you are logged in as admin".
 * (Do not do this in production. It is fine for a workshop.)
 * ------------------------------------------------------------------ */
const sessions = new Set();

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const jar = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    jar[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return jar;
}

function isAdmin(req) {
  const jar = parseCookies(req);
  return jar.session && sessions.has(jar.session);
}

/* ------------------------------------------------------------------ *
 * Tiny helpers for reading the request body and sending responses.
 * ------------------------------------------------------------------ */
function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e6) req.destroy(); // basic flood guard
    });
    req.on('end', () => resolve(new URLSearchParams(data)));
  });
}

function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function serveStatic(req, res) {
  // Map the URL path to a file under public/, safely.
  const urlPath = decodeURIComponent(req.url.split('?')[0]);
  const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
  const filePath = path.join(PUBLIC_DIR, rel);

  // Prevent path traversal outside public/.
  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendHtml(res, 403, '<h1>403 Forbidden</h1>');
    return;
  }

  fs.readFile(filePath, (err, buf) => {
    if (err) {
      sendHtml(res, 404, '<h1>404 Not Found</h1>');
      return;
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(buf);
  });
}

/* ------------------------------------------------------------------ *
 * Admin console (server-rendered so you can read the auth logic here)
 * ------------------------------------------------------------------ */
function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body class="admin">
  <main class="card">
    <h1>${title}</h1>
    ${body}
    <p><a href="/">&larr; Back to the site</a></p>
  </main>
</body>
</html>`;
}

function adminPage(req, res) {
  if (!isAdmin(req)) {
    sendHtml(
      res,
      200,
      page(
        'CedarCrypt Admin - Login',
        `<form method="POST" action="/admin/login" class="stack">
           <label>Username <input name="username" autocomplete="username" value="admin"></label>
           <label>Password <input name="password" type="password" autocomplete="current-password"></label>
           <button type="submit">Log in</button>
         </form>
         <aside class="hint">
           <p><strong>Workshop hint.</strong> The admin password is stored as a SHA-256 hash:</p>
           <code>${ADMIN_PASSWORD_SHA256}</code>
           <p>Crack it (e.g. with hashcat, mode <code>-m 1400</code>) to recover the password, then log in.</p>
         </aside>`
      )
    );
    return;
  }

  const current = readState().image;
  const options = AVAILABLE_IMAGES.map(
    (img) => `<label class="pick">
        <input type="radio" name="image" value="${img}" ${img === current ? 'checked' : ''}>
        <img src="/resources/${img}" alt="${img}" width="120" height="120">
        <span>${img}</span>
      </label>`
  ).join('\n');

  sendHtml(
    res,
    200,
    page(
      'CedarCrypt Admin - Console',
      `<p>Logged in as <strong>admin</strong>. Choose the image shown on the home page:</p>
       <form method="POST" action="/admin/set-image" class="stack">
         <div class="picker">${options}</div>
         <button type="submit">Update image</button>
       </form>
       <form method="POST" action="/admin/logout"><button type="submit" class="link">Log out</button></form>`
    )
  );
}

/* ------------------------------------------------------------------ *
 * Router
 * ------------------------------------------------------------------ */
const server = http.createServer(async (req, res) => {
  const urlPath = req.url.split('?')[0];

  if (req.method === 'GET' && urlPath === '/api/image') {
    sendJson(res, 200, { image: readState().image });
    return;
  }

  if (req.method === 'GET' && urlPath === '/admin') {
    adminPage(req, res);
    return;
  }

  if (req.method === 'POST' && urlPath === '/admin/login') {
    const body = await readBody(req);
    const ok =
      body.get('username') === ADMIN_USER &&
      sha256hex(body.get('password') || '') === ADMIN_PASSWORD_SHA256;
    if (!ok) {
      sendHtml(res, 401, page('Login failed', `<p class="error">Wrong username or password.</p>`));
      return;
    }
    const token = crypto.randomBytes(16).toString('hex');
    sessions.add(token);
    res.setHeader('Set-Cookie', `session=${token}; HttpOnly; Path=/; SameSite=Lax`);
    redirect(res, '/admin');
    return;
  }

  if (req.method === 'POST' && urlPath === '/admin/set-image') {
    if (!isAdmin(req)) {
      sendHtml(res, 403, page('Forbidden', `<p class="error">Log in first.</p>`));
      return;
    }
    const body = await readBody(req);
    const image = body.get('image');
    if (AVAILABLE_IMAGES.includes(image)) writeState({ image });
    redirect(res, '/admin');
    return;
  }

  if (req.method === 'POST' && urlPath === '/admin/logout') {
    const jar = parseCookies(req);
    if (jar.session) sessions.delete(jar.session);
    res.setHeader('Set-Cookie', 'session=; Path=/; Max-Age=0');
    redirect(res, '/admin');
    return;
  }

  if (req.method === 'GET') {
    serveStatic(req, res);
    return;
  }

  sendHtml(res, 405, '<h1>405 Method Not Allowed</h1>');
});

server.listen(PORT, () => {
  console.log(`CedarCrypt running at http://localhost:${PORT}`);
  console.log(`Admin console:        http://localhost:${PORT}/admin`);
});
