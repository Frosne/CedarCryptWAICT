'use strict';

/*
 * CedarCrypt - WAICT workshop (SOLUTION: integrity implemented)
 * ----------------------------------------------------------------
 * A minimal static site: index.html, app.js, style.css, cat.jpg.
 *
 * This is the completed reference for Exercise 2 -- look here if you get stuck.
 * Compared with the exercise-2 starter, it has:
 *   1. public/waict-manifest.json  (SHA-256 of every file, base64-encoded)
 *   2. the Integrity-Policy-WAICT-v1 header set on every response (below)
 *
 * To see the browser reject tampering: edit a hash in waict-manifest.json,
 * restart, and reload in a WAICT-aware browser.
 *
 * No dependencies -- uses only Node's built-in modules.
 *
 * Run:   node server.js
 * Open:  http://localhost:3000
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

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

const server = http.createServer((req, res) => {
  // Map the URL path to a file under public/, safely.
  const urlPath = decodeURIComponent(req.url.split('?')[0]);
  const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
  const filePath = path.join(PUBLIC_DIR, rel);

  // Prevent path traversal outside public/.
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<h1>403 Forbidden</h1>');
    return;
  }

  fs.readFile(filePath, (err, buf) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<h1>404 Not Found</h1>');
      return;
    }
    const headers = {
      'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream',
    };

    // WAICT integrity header: the browser checks every script and image it
    // loads against the hashes in the manifest. If a served resource no longer
    // matches, the browser refuses to use it -- catching a tampered/compromised
    // server (including the image-swap attack from Exercise 1).
    headers['Integrity-Policy-WAICT-v1'] =
      'manifest="/waict-manifest.json", blocked-destinations=(script image), mode=enforce, max-age=0';

    res.writeHead(200, headers);
    res.end(buf);
  });
});

server.listen(PORT, () => {
  console.log(`CedarCrypt running at http://localhost:${PORT}`);
});
