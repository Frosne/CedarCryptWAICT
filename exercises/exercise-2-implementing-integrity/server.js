'use strict';

/*
 * CedarCrypt - WAICT workshop (Exercise 2: implementing integrity)
 * ----------------------------------------------------------------
 * A minimal static site: index.html, app.js, style.css, cat.jpg.
 *
 * Your task in this exercise:
 *   1. Compute the SHA-256 of each file in public/ and write them into a new
 *      manifest, public/waict-manifest.json (see the README for the format).
 *   2. Add the WAICT integrity header (see the TODO below).
 *   3. Load the page in a WAICT-aware browser and confirm it still works.
 *   4. Corrupt a hash in the manifest, reload, and watch the browser reject it.
 *
 * No dependencies -- uses only Node's built-in modules.
 *
 * Run:   node server.js
 * Open:  http://localhost:3001
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3001;
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

    // ================================================================
    // TODO (Exercise 2): add the WAICT integrity header.
    //
    // WAICT asks the browser to check every script it loads against a
    // manifest of hashes you publish. To turn it on, set a response header:
    //
    //   name:  Integrity-Policy-WAICT-v1
    //   value: max-age=0; mode=enforce; blocked-destinations=(script image); manifest="/waict-manifest.json"
    //
    // e.g.  headers['Integrity-Policy-WAICT-v1'] = '...';
    //
    // Then create public/waict-manifest.json (the manifest you build by
    // hashing each file), restart the server, and verify with:
    //   curl -I http://localhost:3001
    // ================================================================

    res.writeHead(200, headers);
    res.end(buf);
  });
});

server.listen(PORT, () => {
  console.log(`CedarCrypt running at http://localhost:${PORT}`);
});
