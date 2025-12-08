/**
 * DELIBERATELY VULNERABLE EXPRESS API FOR SECURITY TRAINING
 *
 * This API contains INTENTIONAL security vulnerabilities for educational purposes.
 * DO NOT use this code in production environments.
 *
 * Vulnerabilities demonstrated:
 * - CWE-798: Hardcoded JWT secret
 * - CWE-327: JWT algorithm confusion (HS256/RS256)
 * - CWE-613: Missing token expiration enforcement
 * - CWE-639: Authorization bypass via JWT payload manipulation
 * - CWE-209: Information disclosure in error messages
 * - CWE-89: SQL injection in search endpoint
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');
const authMiddleware = require('./middleware/auth');

const app = express();
app.use(express.json());

// VULNERABILITY 1: Hardcoded JWT secret (CWE-798)
// vuln-code-snippet start hardcodedSecret
const JWT_SECRET = 'super-secret-key-12345';  // NEVER hardcode secrets!
// vuln-code-snippet end hardcodedSecret

// Database connection string (simulated)
const MONGO_URI = 'mongodb://localhost:27017/authapi';
let db;

// Initialize database connection
async function connectDB() {
  try {
    const client = await MongoClient.connect(MONGO_URI);
    db = client.db();
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('Database connection failed:', error);
  }
}

/**
 * Login endpoint
 * POST /api/login
 * Body: { username, password }
 */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // VULNERABILITY 2: SQL Injection in user lookup (CWE-89)
    // vuln-code-snippet start sqlInjection
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    // This is vulnerable to SQL injection: ' OR '1'='1
    // vuln-code-snippet end sqlInjection

    // Simulated user lookup (in real code, this would query the database)
    const user = {
      id: 1,
      username: username,
      email: 'user@example.com',
      role: 'user'
    };

    // VULNERABILITY 3: JWT created without expiration and with user-controlled role (CWE-613, CWE-639)
    // vuln-code-snippet start jwtNoExpiry
    const token = jwt.sign(
      {
        userId: user.id,
        username: user.username,
        role: user.role  // User can manipulate this in the token!
      },
      JWT_SECRET
      // Missing: expiresIn option - tokens never expire!
    );
    // vuln-code-snippet end jwtNoExpiry

    res.json({
      success: true,
      token: token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });

  } catch (error) {
    // VULNERABILITY 4: Information disclosure in error messages (CWE-209)
    // vuln-code-snippet start errorDisclosure
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack,  // Exposes internal implementation details!
      query: req.body      // Leaks sensitive request data!
    });
    // vuln-code-snippet end errorDisclosure
  }
});

/**
 * User profile endpoint
 * GET /api/profile
 * Requires authentication
 */
app.get('/api/profile', authMiddleware.authenticate, async (req, res) => {
  try {
    // User data comes from JWT payload (already validated by middleware)
    const userId = req.user.userId;

    // Simulated user lookup
    const user = {
      id: userId,
      username: req.user.username,
      email: 'user@example.com',
      role: req.user.role,
      profile: {
        firstName: 'John',
        lastName: 'Doe',
        phone: '555-0123'
      }
    };

    res.json({
      success: true,
      user: user
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

/**
 * Admin endpoint - should only be accessible to admin users
 * GET /api/admin/users
 * Requires admin role
 */
app.get('/api/admin/users', authMiddleware.authenticate, authMiddleware.requireAdmin, async (req, res) => {
  try {
    // VULNERABILITY 5: Authorization bypass - role comes from JWT payload
    // vuln-code-snippet start authzBypass
    // An attacker can create a JWT with role='admin' and bypass authorization!
    // The middleware only checks if req.user.role === 'admin'
    // but doesn't verify the role against the database
    // vuln-code-snippet end authzBypass

    // Simulated admin data
    const users = [
      { id: 1, username: 'admin', role: 'admin', email: 'admin@example.com' },
      { id: 2, username: 'user1', role: 'user', email: 'user1@example.com' },
      { id: 3, username: 'user2', role: 'user', email: 'user2@example.com' }
    ];

    res.json({
      success: true,
      users: users
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

/**
 * Search endpoint - vulnerable to SQL injection
 * GET /api/search?q=searchterm
 */
app.get('/api/search', authMiddleware.authenticate, async (req, res) => {
  try {
    const searchQuery = req.query.q;

    // VULNERABILITY 6: SQL Injection in search (CWE-89)
    // vuln-code-snippet start searchSQLi
    const query = `SELECT * FROM products WHERE name LIKE '%${searchQuery}%' OR description LIKE '%${searchQuery}%'`;
    // Vulnerable to: ' OR 1=1--
    // vuln-code-snippet end searchSQLi

    // Simulated search results
    const results = [
      { id: 1, name: 'Product 1', description: 'Description 1' },
      { id: 2, name: 'Product 2', description: 'Description 2' }
    ];

    res.json({
      success: true,
      query: searchQuery,
      results: results
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      stack: error.stack,
      query: req.query.q
    });
  }
});

/**
 * Health check endpoint
 * GET /health
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    // VULNERABILITY 7: Information disclosure - version info
    version: '1.0.0',
    nodeVersion: process.version,
    platform: process.platform
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[VULNERABLE] Auth API server running on port ${PORT}`);
  console.log('WARNING: This API contains intentional security vulnerabilities for training purposes');
  console.log('DO NOT deploy to production!');
});

// Export for testing
module.exports = { app, JWT_SECRET };
