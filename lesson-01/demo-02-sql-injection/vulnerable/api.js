/**
 * SQL Injection Vulnerable API
 * ============================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * WARNING: This code contains intentional SQL injection vulnerabilities.
 * DO NOT use in production environments.
 *
 * OWASP Category: A03:2021 - Injection
 * CWE: CWE-89 (SQL Injection)
 */

const express = require('express');
const mysql = require('mysql2');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD || 'demo',
  database: process.env.DB_NAME || 'testdb'
});

// Connect to database
db.connect((err) => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// =============================================================================
// VULNERABILITY 1: SQL Injection in GET parameter
// =============================================================================
//
// Attack Vector: /user/1 OR 1=1
// Attack Vector: /user/1 UNION SELECT username, password FROM users--
//
// Copilot Chat Prompt:
// "Analyze this Express API endpoint for SQL injection vulnerabilities.
//  Show me:
//  1. The vulnerable line
//  2. How an attacker would exploit it
//  3. Example malicious payloads
//  4. Why string concatenation is dangerous"
//
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // VULNERABLE: String template literal with user input
  const query = `SELECT * FROM users WHERE id = ${userId}`;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Query error:', err);
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// =============================================================================
// VULNERABILITY 2: SQL Injection in Login (Authentication Bypass)
// =============================================================================
//
// Attack Vector: username = "admin'--" (bypasses password check)
// Attack Vector: username = "' OR '1'='1" (returns all users)
//
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABLE: String concatenation in authentication query
  const query = "SELECT * FROM users WHERE username = '" + username +
                "' AND password = '" + password + "'";

  db.query(query, (err, results) => {
    if (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Login failed' });
    }

    if (results.length > 0) {
      res.json({
        success: true,
        message: 'Login successful',
        user: results[0]
      });
    } else {
      res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }
  });
});

// =============================================================================
// VULNERABILITY 3: SQL Injection in Search Function
// =============================================================================
//
// Attack Vector: q=' UNION SELECT table_name, column_name, 3, 4 FROM information_schema.columns--
// Attack Vector: q=' OR 1=1--
//
app.get('/search', (req, res) => {
  const searchTerm = req.query.q || '';
  const category = req.query.category || '';

  // VULNERABLE: Multiple user inputs concatenated into query
  const query = `SELECT * FROM products
                 WHERE name LIKE '%${searchTerm}%'
                 AND category = '${category}'`;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Search error:', err);
      return res.status(500).json({ error: err.message });
    }
    res.json({ results });
  });
});

// =============================================================================
// VULNERABILITY 4: SQL Injection in ORDER BY clause
// =============================================================================
//
// Attack Vector: sort=id; DROP TABLE users;--
// Attack Vector: sort=(SELECT password FROM users WHERE username='admin')
//
app.get('/products', (req, res) => {
  const sortBy = req.query.sort || 'name';
  const order = req.query.order || 'ASC';

  // VULNERABLE: ORDER BY and sort direction from user input
  const query = `SELECT * FROM products ORDER BY ${sortBy} ${order}`;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Products error:', err);
      return res.status(500).json({ error: err.message });
    }
    res.json({ products: results });
  });
});

// =============================================================================
// VULNERABILITY 5: SQL Injection in INSERT statement
// =============================================================================
//
// Attack Vector: email = "test@test.com', 'admin'); DROP TABLE users;--"
//
app.post('/register', (req, res) => {
  const { username, email, password } = req.body;

  // VULNERABLE: User input in INSERT statement
  const query = `INSERT INTO users (username, email, password, role)
                 VALUES ('${username}', '${email}', '${password}', 'user')`;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Registration error:', err);
      return res.status(500).json({ error: err.message });
    }
    res.json({
      success: true,
      message: 'User registered',
      userId: result.insertId
    });
  });
});

// =============================================================================
// VULNERABILITY 6: SQL Injection in UPDATE statement
// =============================================================================
//
// Attack Vector: userId = "1; UPDATE users SET role='admin' WHERE username='attacker'--"
//
app.put('/user/:id', (req, res) => {
  const userId = req.params.id;
  const { email, displayName } = req.body;

  // VULNERABLE: User input in UPDATE statement
  const query = `UPDATE users
                 SET email = '${email}', display_name = '${displayName}'
                 WHERE id = ${userId}`;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Update error:', err);
      return res.status(500).json({ error: err.message });
    }
    res.json({
      success: true,
      message: 'User updated',
      affectedRows: result.affectedRows
    });
  });
});

// =============================================================================
// VULNERABILITY 7: SQL Injection in DELETE statement
// =============================================================================
//
// Attack Vector: id = "1 OR 1=1" (deletes all records)
//
app.delete('/product/:id', (req, res) => {
  const productId = req.params.id;

  // VULNERABLE: User input in DELETE statement
  const query = `DELETE FROM products WHERE id = ${productId}`;

  db.query(query, (err, result) => {
    if (err) {
      console.error('Delete error:', err);
      return res.status(500).json({ error: err.message });
    }
    res.json({
      success: true,
      message: 'Product deleted',
      affectedRows: result.affectedRows
    });
  });
});

// =============================================================================
// VULNERABILITY 8: Blind SQL Injection (Boolean-based)
// =============================================================================
//
// Attack Vector: username = "admin' AND SUBSTRING(password,1,1)='a'--"
// Attacker extracts data character-by-character based on true/false response
//
app.get('/check-user', (req, res) => {
  const username = req.query.username || '';

  // VULNERABLE: Response differs based on query result
  const query = `SELECT COUNT(*) as count FROM users WHERE username = '${username}'`;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    // Different response enables blind injection attacks
    if (results[0].count > 0) {
      res.json({ exists: true, message: 'Username taken' });
    } else {
      res.json({ exists: false, message: 'Username available' });
    }
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`⚠️  VULNERABLE API running on port ${PORT}`);
  console.log('This API contains intentional SQL injection vulnerabilities.');
  console.log('For educational purposes only - DO NOT deploy to production!');
});

module.exports = app;
