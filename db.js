const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./links.db');

db.run(`CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE,
  url TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  user_id INTEGER
);`);

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
);`);

db.run(`CREATE TABLE IF NOT EXISTS analytics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT,
  referrer TEXT,
  country TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);`);


module.exports = db;
