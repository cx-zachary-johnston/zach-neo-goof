const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database(':memory:');
function vulnerableLogin(username, password) {
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  console.log("Executing query: " + query);

  db.all(query, [], (err, rows) => { 
    if (err) {
      throw err;
    }

    if (rows.length > 0) {
      console.log("Login successful for user: " + username);
    } else {
      console.log("Login failed for user: " + username);
    }   
  });
}