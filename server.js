const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const session = require('express-session');
const db = require('./db'); // Assumes db.js above
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for Render
app.set('trust proxy', 1);

// Middleware
app.use(cors({
  origin: ['https://toolkit.mintlink.co', 'http://localhost:3000'], // Allow Hostinger domain and localhost
  credentials: true
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: 'super-secure-secret', // CHANGE THIS for production!
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // True in production
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // None for cross-site in production
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));


function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).send('Login required');
  next();
}

// Registration endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || password.length < 4)
    return res.status(400).send('User/pass required');
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function (err) {
      if (err) return res.status(409).send('Username taken');
      req.session.userId = this.lastID;
      res.send('Registration complete');
    });
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT id, password FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) return res.status(401).send('Invalid user/pass');
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).send('Invalid user/pass');
    req.session.userId = user.id;
    res.send('Login successful');
  });
});

// Logout endpoint
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.send('Logged out'));
});

// Shortlink creation (no login required)
app.post('/shorten', (req, res) => {
  const originalUrl = req.body.url;
  let code = req.body.code?.trim();
  const userId = req.session.userId || null;
  if (!originalUrl || !/^https?:\/\/.+/.test(originalUrl)) {
    return res.status(400).send('Invalid URL.');
  }
  if (!code) {
    code = crypto.randomBytes(4).toString('hex').slice(0, 6);
  } else {
    code = code.replace(/^\/+|\/+$/g, '').replace(/\s+/g, '-');
  }
  db.get('SELECT id FROM links WHERE code = ?', [code], (err, row) => {
    if (row) return res.status(409).send('Shortlink already exists. Pick a different code.');
    db.run('INSERT INTO links (code, url, user_id) VALUES (?, ?, ?)', [code, originalUrl, userId], function (err) {
      if (err) return res.status(500).send('Error saving link.');
      res.send(`https://toolkit.mintlink.co/${code}`);
    });
  });
});
// List logged-in user's links (dashboard)
app.get('/api/links', requireAuth, (req, res) => {
  db.all('SELECT code, url, created_at FROM links WHERE user_id = ? ORDER BY created_at DESC',
    [req.session.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Error fetching links' });
      res.json(rows);
    }
  );
});

// List logged-in user's links (dashboard)
app.get('/api/stats/:code', (req, res) => {
  const code = req.params.code;
  db.all('SELECT referrer, country, timestamp FROM analytics WHERE code = ? ORDER BY timestamp DESC', [code], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Stats error' });
    res.json(rows);
  });
});


// Delete link (only links owned by logged-in user)
app.post('/api/delete', requireAuth, (req, res) => {
  const { code } = req.body;
  db.run('DELETE FROM links WHERE code = ? AND user_id = ?', [code, req.session.userId], function (err) {
    if (err) return res.status(500).send('Error deleting');
    if (this.changes === 0) return res.status(404).send('Not found');
    res.send('Deleted');
  });
});

// Admin delete ANY link (for testing -- use with care!)
app.post('/admin/delete', (req, res) => {
  const { code } = req.body;
  db.run('DELETE FROM links WHERE code = ?', [code], function (err) {
    if (err) return res.status(500).send('Error deleting');
    if (this.changes === 0) return res.status(404).send('Not found');
    res.send('Deleted');
  });
});

// Admin delete ALL links (database wipe -- for testing only)
app.post('/admin/delete-all', (req, res) => {
  db.run('DELETE FROM links', function (err) {
    if (err) return res.status(500).send('Error deleting all');
    res.send('All links deleted');
  });
});

// Update link (only by owner)
app.post('/api/update', requireAuth, (req, res) => {
  const { code, url } = req.body;
  if (!/^https?:\/\/.+/.test(url)) return res.status(400).send('Invalid URL');
  db.run('UPDATE links SET url=? WHERE code=? AND user_id=?', [url, code, req.session.userId], function (err) {
    if (err) return res.status(500).send('Error updating');
    if (this.changes === 0) return res.status(404).send('Not found');
    res.send('Updated');
  });
});

// Redirect handler (catch-all, must be last!)
// Redirect handler (catch-all, must be last!)
app.get(/^\/(.+)$/, (req, res) => {
  const code = req.params[0];
  db.get('SELECT url FROM links WHERE code = ?', [code], (err, row) => {
    if (err) return res.status(500).send('Server error.');
    if (row) {
      const ref = req.get('Referer') || '';
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

      // Check if localhost
      if (ip === '::1' || ip === '127.0.0.1' || ip?.includes('127.0.0.1')) {
        db.run('INSERT INTO analytics (code, referrer, country) VALUES (?, ?, ?)',
          [code, ref, "Local"]
        );
        return res.redirect(row.url);
      }

      // Try to get country, but don't block the redirect
      fetch(`http://ip-api.com/json/${ip}?fields=country`)
        .then(resp => resp.json())
        .then(data => {
          db.run('INSERT INTO analytics (code, referrer, country) VALUES (?, ?, ?)',
            [code, ref, data.country || "Unknown"]
          );
        })
        .catch(() => {
          db.run('INSERT INTO analytics (code, referrer, country) VALUES (?, ?, ?)',
            [code, ref, "Unknown"]
          );
        });

      // Redirect immediately, don't wait for analytics
      res.redirect(row.url);
    } else {
      res.status(404).send('Shortlink not found.');
    }
  });
});


app.listen(PORT, '0.0.0.0', () => {
  console.log(`URL Shortener running on port ${PORT}`);
});
