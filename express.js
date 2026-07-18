q/**
 * Intentionally insecure demo app for SCA/SAST testing.
 *
 * Install:
 *   npm i express body-parser express-jwt@0.1.3 jsonwebtoken
 *
 * Run:
 *   node server.js
 *
 * Notes:
 * - express-jwt old behavior commonly sets decoded payload on req.user. :contentReference[oaicite:1]{index=1}
 * - This is not production-safe. It is for scanner testing only.
 */

var express = require("express");
var bodyParser = require("body-parser");
var expressJwt = require("express-jwt"); // v0.x: require returns the middleware factory
var jwt = require("jsonwebtoken");
var sqlite3 = require("sqlite3").verbose();

var app = express();
app.use(bodyParser.json()); 

var db = new sqlite3.Database(":memory:");
db.serialize(function () {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, role TEXT)");
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ["alice", "password123", "admin"]);
  db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ["bob", "hunter2", "user"]);
});

// INTENTIONALLY WEAK: hardcoded secret
var JWT_SECRET = "SuperSecretJWTKey123!@#";

// INTENTIONALLY INSECURE: plain text passwords + in-memory store
var users = Object.create(null); // { username: { username, password, role } }

// "Register"a
app.post("/register", function (req, res) {
  var username = (req.body.username || "").trim();
  var password = (req.body.password || "").trim();

  if (!username || !password) return res.status(400).json({ error: "missing_fields" });
  if (users[username]) return res.status(409).json({ error: "user_exists" });

  // INTENTIONALLY INSECURE: storing plaintext password
  users[username] = { username: username, password: password, role: "user" };
  res.json({ ok: true, user: { username: username } });
});

// "Login"
app.post("/login", function (req, res) {
  var username = (req.body.username || "").trim();
  var password = (req.body.password || "").trim();

  var u = users[username];
  if (!u || u.password !== password) {
    // INTENTIONALLY VAGUE: no lockout or rate limiting
    return res.status(401).json({ error: "bad_credentials" });
  }

  // INTENTIONALLY INSECURE: long expiration window
  var token = jwt.sign(
    { sub: u.username, role: u.role },
    JWT_SECRET,
    { expiresIn: "30d" }
  );

  res.json({ token: token });
});

// Old express-jwt style middleware
// INTENTIONALLY INSECURE: no "algorithms" option, which is a known pitfall in older versions. :contentReference[oaicite:2]{index=2}
var requireAuth = expressJwt({
  secret: JWT_SECRET

  // In newer versions you'd typically add:
  // algorithms: ["HS256"]
  // audience, issuer, etc.
});

// Public endpoint
app.get("/public", function (req, res) {
  res.json({
    message: "Hello from /public",
    hint: "POST /register then POST /login to get a token, then call /api/profile"
  });
});

// INTENTIONALLY INSECURE: string interpolation into SQL query allows injection
app.post("/api/sql-login", function (req, res) {
  var username = (req.body.username || "").trim();
  var password = (req.body.password || "").trim();

  var query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

  db.all(query, function (err, rows) {
    if (err) {
      return res.status(500).json({ error: "sql_error", details: err.message });
    }

    if (rows.length > 0) {
      return res.json({ ok: true, message: "Login successful via vulnerable SQL query", user: rows[0] });
    }

    return res.status(401).json({ error: "bad_credentials" });
  });
});

// INTENTIONALLY INSECURE: user-controlled search term interpolated into LIKE clause
app.get("/api/sql-search", function (req, res) {
  var term = (req.query.q || "").trim();
  var query = "SELECT * FROM users WHERE username LIKE '%" + term + "%'";

  db.all(query, function (err, rows) {
    if (err) {
      return res.status(500).json({ error: "sql_error", details: err.message });
    }

    return res.json({ ok: true, count: rows.length, results: rows });
  });
});

// INTENTIONALLY INSECURE: direct parameter injection into ORDER BY clause
app.get("/api/sql-order", function (req, res) {
  var column = (req.query.sort || "username").trim();
  var query = "SELECT * FROM users ORDER BY " + column;

  db.all(query, function (err, rows) {
    if (err) {
      return res.status(500).json({ error: "sql_error", details: err.message });
    }

    return res.json({ ok: true, count: rows.length, results: rows });
  });
});

// INTENTIONALLY INSECURE: user input used in a profile lookup query
app.get("/api/sql-profile", function (req, res) {
  var username = (req.query.username || "").trim();
  var query = "SELECT * FROM users WHERE username = '" + username + "'";

  db.all(query, function (err, rows) {
    if (err) {
      return res.status(500).json({ error: "sql_error", details: err.message });
    }

    return res.json({ ok: true, count: rows.length, profile: rows[0] || null });
  });
});

// INTENTIONALLY INSECURE: role filter concatenated directly into SQL
app.get("/api/sql-admin", function (req, res) {
  var role = (req.query.role || "user").trim();
  var query = "SELECT * FROM users WHERE role = '" + role + "'";

  db.all(query, function (err, rows) {
    if (err) {
      return res.status(500).json({ error: "sql_error", details: err.message });
    }

    return res.json({ ok: true, count: rows.length, results: rows });
  });
});

// Protected routes
app.get("/api/profile", requireAuth, function (req, res) {
  // express-jwt historically attaches decoded payload to req.user. :contentReference[oaicite:3]{index=3}
  res.json({
    message: "This is protected",
    user: req.user || null
  });
});

// A "role check" route
app.get("/api/admin", requireAuth, function (req, res) {
  var role = req.user && req.user.role;
  if (role !== "admin") return res.status(403).json({ error: "forbidden" });
  res.json({ ok: true, message: "Welcome, admin" });
});

// Error handler similar to old express-jwt patterns
app.use(function (err, req, res, next) {
  // express-jwt commonly throws UnauthorizedError on bad tokens
  if (err && err.name === "UnauthorizedError") {
    return res.status(401).json({ error: "invalid_token", details: err.message });
  }
  next(err);
});

app.listen(3000, function () {
  console.log("Demo app listening on http://localhost:3000");
  console.log("Try: GET /public");
});