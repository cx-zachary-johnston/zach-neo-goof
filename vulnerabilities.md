# vulnerable packages

"adm-zip": "^0.4.7",
"express-jwt": "0.1.3",


# malicious packages

"node-ipc": "9.2.2",
"momnet": "2.29.1",


# sql injection pattern
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