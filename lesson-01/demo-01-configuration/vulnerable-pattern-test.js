/**
 * Vulnerable Pattern Test File
 * ============================
 * This file contains intentionally vulnerable code patterns
 * to test your GitHub Copilot security configuration.
 *
 * INSTRUCTIONS:
 * 1. Open this file in VS Code with Copilot enabled
 * 2. Highlight vulnerable code sections
 * 3. Ask Copilot Chat: "Is this code secure?"
 * 4. Copilot should identify the vulnerabilities
 *
 * WARNING: This code is for educational purposes only.
 * DO NOT use in production environments.
 */

const express = require('express');
const mysql = require('mysql2');

const app = express();

// Database connection (demo purposes)
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD || 'demo',
  database: process.env.DB_NAME || 'testdb'
});

// =============================================================================
// VULNERABILITY 1: SQL Injection via String Concatenation
// =============================================================================
//
// Copilot Chat Prompt: "Is this getUserById function vulnerable?"
// Expected: Copilot identifies SQL injection risk
//
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // VULNERABLE: String concatenation allows SQL injection
  const query = "SELECT * FROM users WHERE id = " + userId;

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// =============================================================================
// VULNERABILITY 2: Command Injection via exec()
// =============================================================================
//
// Copilot Chat Prompt: "What's wrong with this ping function?"
// Expected: Copilot identifies command injection risk
//
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
  const host = req.query.host;

  // VULNERABLE: User input passed directly to shell command
  exec(`ping -c 3 ${host}`, (error, stdout, stderr) => {
    if (error) return res.status(500).json({ error: error.message });
    res.json({ output: stdout });
  });
});

// =============================================================================
// VULNERABILITY 3: Path Traversal
// =============================================================================
//
// Copilot Chat Prompt: "Can an attacker read arbitrary files with this endpoint?"
// Expected: Copilot identifies directory traversal vulnerability
//
const fs = require('fs');
const path = require('path');

app.get('/files/:filename', (req, res) => {
  const filename = req.params.filename;

  // VULNERABLE: No path sanitization - allows ../../../etc/passwd
  const filePath = path.join(__dirname, 'uploads', filename);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'File not found' });
    res.send(data);
  });
});

// =============================================================================
// VULNERABILITY 4: Hardcoded Credentials
// =============================================================================
//
// Copilot Chat Prompt: "Are there any security issues with this configuration?"
// Expected: Copilot identifies hardcoded secrets
//
const config = {
  apiKey: 'sk-live-abc123xyz789secret',  // VULNERABLE: Hardcoded API key
  dbPassword: 'SuperSecretPassword123!',   // VULNERABLE: Hardcoded password
  jwtSecret: 'my-super-secret-jwt-key'     // VULNERABLE: Hardcoded JWT secret
};

// =============================================================================
// VULNERABILITY 5: Insecure JWT Verification
// =============================================================================
//
// Copilot Chat Prompt: "Is this JWT verification secure?"
// Expected: Copilot identifies algorithm confusion vulnerability
//
const jwt = require('jsonwebtoken');

app.get('/protected', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  // VULNERABLE: No algorithm specified - allows "none" algorithm attack
  try {
    const decoded = jwt.decode(token);  // VULNERABLE: decode() doesn't verify!
    res.json({ user: decoded });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Start server (demo only)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`⚠️  VULNERABLE test server running on port ${PORT}`);
  console.log('This server contains intentional vulnerabilities for testing.');
});

module.exports = app;
