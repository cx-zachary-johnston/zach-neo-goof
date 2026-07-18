const express = require("express");
const mysql = require("mysql2");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password",
  database: "demo"
});

// 1. Find user by username
app.get("/users/by-username", (req, res) => {
  const username = req.query.username;

  const query =
    "SELECT * FROM users WHERE username = '" + username + "'";

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).send(err.message);
    }

    res.json(results);
  });
});

// 2. Find user by email
app.get("/users/by-email", (req, res) => {
  const email = req.query.email;

  const query =
    "SELECT * FROM users WHERE email = '" + email + "'";

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).send(err.message);
    }

    res.json(results);
  });
});

// 3. Find users by city
app.get("/users/by-city", (req, res) => {
  const city = req.query.city;

  const query =
    "SELECT * FROM users WHERE city = '" + city + "'";

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).send(err.message);
    }

    res.json(results);
  });
});

// 4. Search users by name
app.get("/users/search", (req, res) => {
  const name = req.query.name;

  const query =
    "SELECT * FROM users WHERE name LIKE '%" + name + "%'";

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).send(err.message);
    }

    res.json(results);
  });
});

// 5. Find user from route parameter
app.get("/users/:id", (req, res) => {
  const id = req.params.id;

  const query =
    "SELECT * FROM users WHERE id = " + id;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).send(err.message);
    }

    res.json(results);
  });
});

// 6. Authenticate user
app.post("/users/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const query =
    "SELECT * FROM users WHERE username = '" +
    username +
    "' AND password = '" +
    password +
    "'";

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).send(err.message);
    }

    res.json(results);
  });
});

// 7. Delete user
app.delete("/users/:id", (req, res) => {
  const id = req.params.id;

  const query =
    "DELETE FROM users WHERE id = " + id;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).send(err.message);
    }

    res.json(results);
  });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});