/**
 * Intentionally insecure demo app for SCA/SAST testing.
 *
 * Install:
 *   npm i express body-parser express-jwt@0.1.3 jsonwebtoken sqlite3
 *
 * Run:
 *   node server.js
 *
 * This application is intentionally vulnerable and is not production-safe.
 */

var express = require("express");
var bodyParser = require("body-parser");
var expressJwt = require("express-jwt");
var jwt = require("jsonwebtoken");
var sqlite3 = require("sqlite3").verbose();
var path = require("path");

var app = express();

app.use(bodyParser.json());

var db = new sqlite3.Database(":memory:");

db.serialize(function () {
  db.run(
    "CREATE TABLE users (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
      "username TEXT, " +
      "password TEXT, " +
      "role TEXT" +
    ")"
  );

  db.run(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    ["alice", "password123", "admin"]
  );

  db.run(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    ["bob", "hunter2", "user"]
  );
});

var User = {
  find: function (query, callback) {
    var username = (query.username || "").trim();
    var password = (query.password || "").trim();
    var role = (query.role || "").trim();

    // INTENTIONALLY INSECURE: user input is concatenated into SQL.
    var sql =
      "SELECT * FROM users WHERE username = '" +
      username +
      "'";

    if (password) {
      sql += " AND password = '" + password + "'";
    }

    if (role) {
      sql += " AND role = '" + role + "'";
    }

    db.all(sql, function (err, rows) {
      if (err) {
        return callback(err, null);
      }

      return callback(null, rows);
    });
  }
};

// INTENTIONALLY INSECURE: hardcoded signing secret.
var JWT_SECRET = "SuperSecretJWTKey123!@#";

// INTENTIONALLY INSECURE: plaintext passwords in an in-memory object.
var users = Object.create(null);

app.post("/register", function (req, res) {
  var username = (req.body.username || "").trim();
  var password = (req.body.password || "").trim();

  if (!username || !password) {
    return res.status(400).json({
      error: "missing_fields"
    });
  }

  if (users[username]) {
    return res.status(409).json({
      error: "user_exists"
    });
  }

  users[username] = {
    username: username,
    password: password,
    role: "user"
  };

  return res.json({
    ok: true,
    user: {
      username: username
    }
  });
});

app.post("/login", function (req, res) {
  var username = (req.body.username || "").trim();
  var password = (req.body.password || "").trim();

  var user = users[username];

  if (!user || user.password !== password) {
    // INTENTIONALLY INSECURE: no rate limiting or account lockout.
    return res.status(401).json({
      error: "bad_credentials"
    });
  }

  // INTENTIONALLY INSECURE: long token expiration.
  var token = jwt.sign(
    {
      sub: user.username,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );

  return res.json({
    token: token
  });
});

// Old express-jwt middleware style.
var requireAuth = expressJwt({
  secret: JWT_SECRET
});

// Public endpoint.
app.get("/public", function (req, res) {
  return res.json({
    message: "Hello from /public",
    hint: "POST /register, then POST /login, then call /api/profile"
  });
});

// INTENTIONALLY INSECURE: username and password are concatenated into SQL.
app.post("/api/user-login", function (req, res, next) {
  User.find(
    {
      username: req.body.username,
      password: req.body.password
    },
    function (err, matchingUsers) {
      if (err) {
        return next(err);
      }

      if (matchingUsers.length > 0) {
        return res.json({
          ok: true,
          message: "Login successful via vulnerable database query",
          user: matchingUsers[0]
        });
      }

      return res.status(401).json({
        error: "bad_credentials"
      });
    }
  );
});

// INTENTIONALLY INSECURE: query-object values flow into vulnerable SQL.
app.post("/api/user-profile", function (req, res, next) {
  User.find(
    {
      username: req.body.username
    },
    function (err, matchingUsers) {
      if (err) {
        return next(err);
      }

      return res.json({
        ok: true,
        count: matchingUsers.length,
        profile: matchingUsers[0] || null
      });
    }
  );
});

// INTENTIONALLY INSECURE: role and username flow into vulnerable SQL.
app.post("/api/user-admin", function (req, res, next) {
  User.find(
    {
      username: req.body.username,
      role: req.body.role
    },
    function (err, matchingUsers) {
      if (err) {
        return next(err);
      }

      return res.json({
        ok: true,
        count: matchingUsers.length,
        results: matchingUsers
      });
    }
  );
});

// INTENTIONALLY INSECURE: query-string input flows into vulnerable SQL.
app.get("/api/user-search", function (req, res, next) {
  User.find(
    {
      username: req.query.username
    },
    function (err, matchingUsers) {
      if (err) {
        return next(err);
      }

      return res.json({
        ok: true,
        count: matchingUsers.length,
        results: matchingUsers
      });
    }
  );
});

// INTENTIONALLY INSECURE: user-controlled path permits path traversal.
app.get("/api/download", function (req, res, next) {
  var filename = req.query.filename;

  if (!filename) {
    return res.status(400).json({
      error: "missing_filename"
    });
  }

  var filePath = path.join(
    __dirname,
    "downloads",
    filename
  );

  res.download(filePath, function (err) {
    if (err) {
      return next(err);
    }
  });
});

// Protected endpoint.
app.get("/api/profile", requireAuth, function (req, res) {
  return res.json({
    message: "This is protected",
    user: req.user || null
  });
});

// Protected admin endpoint.
app.get("/api/admin", requireAuth, function (req, res) {
  var role = req.user && req.user.role;

  if (role !== "admin") {
    return res.status(403).json({
      error: "forbidden"
    });
  }

  return res.json({
    ok: true,
    message: "Welcome, admin"
  });
});

// Authentication error handler.
app.use(function (err, req, res, next) {
  if (err && err.name === "UnauthorizedError") {
    return res.status(401).json({
      error: "invalid_token",
      details: err.message
    });
  }

  return next(err);
});

// General error handler.
app.use(function (err, req, res, next) {
  console.error(err);

  return res.status(500).json({
    error: "internal_server_error",
    details: err.message
  });
});

app.listen(3000, function () {
  console.log("Demo app listening on http://localhost:3000");
  console.log("Public endpoint: GET /public");
  console.log("Database login: POST /api/user-login");
  console.log("File download: GET /api/download?filename=example.txt");
});