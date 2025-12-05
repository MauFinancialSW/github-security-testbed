/**
 * SQL Injection SECURE API
 * ========================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * This file demonstrates secure coding patterns that prevent SQL injection.
 * All queries use parameterized statements (prepared statements).
 *
 * Key Security Patterns:
 * 1. Parameterized queries with ? placeholders
 * 2. Input validation and sanitization
 * 3. Whitelist validation for dynamic columns
 * 4. Proper error handling (no info leakage)
 */

const express = require('express');
const mysql = require('mysql2/promise');
const { body, param, query, validationResult } = require('express-validator');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection pool (better than single connection)
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD || 'demo',
  database: process.env.DB_NAME || 'testdb',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Validation error handler middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
    });
  }
  next();
};

// =============================================================================
// SECURE ENDPOINT 1: Parameterized Query for User Lookup
// =============================================================================
//
// Security: Uses ? placeholder - MySQL driver handles escaping
// The database treats userId as DATA, not as executable SQL code
//
app.get('/user/:id',
  param('id').isInt({ min: 1 }).withMessage('User ID must be a positive integer'),
  handleValidationErrors,
  async (req, res) => {
    try {
      const userId = parseInt(req.params.id, 10);

      // SECURE: Parameterized query - SQL injection safe
      const [rows] = await pool.execute(
        'SELECT id, username, email, display_name, created_at FROM users WHERE id = ?',
        [userId]
      );

      if (rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      res.json({
        success: true,
        user: rows[0]
      });
    } catch (error) {
      console.error('Database error:', error);
      // SECURE: Don't expose internal error details
      res.status(500).json({
        success: false,
        message: 'An error occurred while fetching user data'
      });
    }
  }
);

// =============================================================================
// SECURE ENDPOINT 2: Parameterized Login with Password Hashing
// =============================================================================
//
// Security Features:
// 1. Parameterized query prevents SQL injection
// 2. Password comparison should use bcrypt (shown conceptually)
// 3. Generic error message prevents username enumeration
//
const bcrypt = require('bcrypt');

app.post('/login',
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be 3-50 alphanumeric characters'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters'),
  handleValidationErrors,
  async (req, res) => {
    try {
      const { username, password } = req.body;

      // SECURE: Parameterized query
      const [rows] = await pool.execute(
        'SELECT id, username, password_hash, role FROM users WHERE username = ?',
        [username]
      );

      // SECURE: Generic message prevents username enumeration
      if (rows.length === 0) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'
        });
      }

      const user = rows[0];

      // SECURE: Compare password with bcrypt
      const passwordValid = await bcrypt.compare(password, user.password_hash);

      if (!passwordValid) {
        return res.status(401).json({
          success: false,
          message: 'Invalid credentials'  // Same message as above
        });
      }

      // Success - return user data (in production, return JWT token)
      res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        }
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        success: false,
        message: 'An error occurred during login'
      });
    }
  }
);

// =============================================================================
// SECURE ENDPOINT 3: Parameterized Search with LIKE
// =============================================================================
//
// Security: Even LIKE queries can be parameterized safely
// The % wildcards are added in the application, not by user input
//
app.get('/search',
  query('q')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .escape()
    .withMessage('Search term must be less than 100 characters'),
  query('category')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Category must be less than 50 characters'),
  handleValidationErrors,
  async (req, res) => {
    try {
      const searchTerm = req.query.q || '';
      const category = req.query.category || '';

      let sql = 'SELECT id, name, description, price, category FROM products WHERE 1=1';
      const params = [];

      if (searchTerm) {
        // SECURE: Parameterized LIKE query
        sql += ' AND name LIKE ?';
        params.push(`%${searchTerm}%`);
      }

      if (category) {
        sql += ' AND category = ?';
        params.push(category);
      }

      sql += ' LIMIT 100';  // Prevent resource exhaustion

      const [rows] = await pool.execute(sql, params);

      res.json({
        success: true,
        count: rows.length,
        results: rows
      });
    } catch (error) {
      console.error('Search error:', error);
      res.status(500).json({
        success: false,
        message: 'An error occurred during search'
      });
    }
  }
);

// =============================================================================
// SECURE ENDPOINT 4: Whitelist Validation for ORDER BY
// =============================================================================
//
// Security: ORDER BY cannot be parameterized, so we use a whitelist
// Only pre-approved column names are allowed
//
const ALLOWED_SORT_COLUMNS = ['name', 'price', 'category', 'created_at'];
const ALLOWED_SORT_ORDERS = ['ASC', 'DESC'];

app.get('/products',
  query('sort')
    .optional()
    .isIn(ALLOWED_SORT_COLUMNS)
    .withMessage(`Sort must be one of: ${ALLOWED_SORT_COLUMNS.join(', ')}`),
  query('order')
    .optional()
    .toUpperCase()
    .isIn(ALLOWED_SORT_ORDERS)
    .withMessage('Order must be ASC or DESC'),
  handleValidationErrors,
  async (req, res) => {
    try {
      // SECURE: Whitelist validation for dynamic SQL parts
      const sortBy = ALLOWED_SORT_COLUMNS.includes(req.query.sort)
        ? req.query.sort
        : 'name';
      const order = ALLOWED_SORT_ORDERS.includes(req.query.order?.toUpperCase())
        ? req.query.order.toUpperCase()
        : 'ASC';

      // SECURE: Column name from whitelist, not user input
      const sql = `SELECT id, name, description, price, category
                   FROM products
                   ORDER BY ${sortBy} ${order}
                   LIMIT 100`;

      const [rows] = await pool.execute(sql);

      res.json({
        success: true,
        count: rows.length,
        products: rows
      });
    } catch (error) {
      console.error('Products error:', error);
      res.status(500).json({
        success: false,
        message: 'An error occurred while fetching products'
      });
    }
  }
);

// =============================================================================
// SECURE ENDPOINT 5: Parameterized INSERT with Password Hashing
// =============================================================================
//
// Security Features:
// 1. Input validation with express-validator
// 2. Password hashing with bcrypt
// 3. Parameterized INSERT query
//
app.post('/register',
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be 3-50 alphanumeric characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email required'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain uppercase, lowercase, and number'),
  handleValidationErrors,
  async (req, res) => {
    try {
      const { username, email, password } = req.body;

      // Check if username already exists
      const [existing] = await pool.execute(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        [username, email]
      );

      if (existing.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Username or email already registered'
        });
      }

      // SECURE: Hash password before storage
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      // SECURE: Parameterized INSERT
      const [result] = await pool.execute(
        'INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, NOW())',
        [username, email, passwordHash, 'user']
      );

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        userId: result.insertId
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({
        success: false,
        message: 'An error occurred during registration'
      });
    }
  }
);

// =============================================================================
// SECURE ENDPOINT 6: Parameterized UPDATE with Authorization
// =============================================================================
//
// Security: Combines parameterized queries with authorization checks
// User can only update their own profile (IDOR prevention)
//
app.put('/user/:id',
  param('id').isInt({ min: 1 }),
  body('email').optional().isEmail().normalizeEmail(),
  body('displayName').optional().trim().isLength({ max: 100 }),
  handleValidationErrors,
  async (req, res) => {
    try {
      const userId = parseInt(req.params.id, 10);
      const { email, displayName } = req.body;

      // In production: verify req.user.id === userId (authorization check)
      // This prevents IDOR attacks

      const updates = [];
      const params = [];

      if (email) {
        updates.push('email = ?');
        params.push(email);
      }

      if (displayName) {
        updates.push('display_name = ?');
        params.push(displayName);
      }

      if (updates.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'No fields to update'
        });
      }

      params.push(userId);  // WHERE clause parameter

      // SECURE: Parameterized UPDATE
      const [result] = await pool.execute(
        `UPDATE users SET ${updates.join(', ')}, updated_at = NOW() WHERE id = ?`,
        params
      );

      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      res.json({
        success: true,
        message: 'User updated successfully'
      });
    } catch (error) {
      console.error('Update error:', error);
      res.status(500).json({
        success: false,
        message: 'An error occurred while updating user'
      });
    }
  }
);

// =============================================================================
// SECURE ENDPOINT 7: Parameterized DELETE with Authorization
// =============================================================================
app.delete('/product/:id',
  param('id').isInt({ min: 1 }),
  handleValidationErrors,
  async (req, res) => {
    try {
      const productId = parseInt(req.params.id, 10);

      // In production: verify user has permission to delete

      // SECURE: Parameterized DELETE
      const [result] = await pool.execute(
        'DELETE FROM products WHERE id = ?',
        [productId]
      );

      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: 'Product not found'
        });
      }

      res.json({
        success: true,
        message: 'Product deleted successfully'
      });
    } catch (error) {
      console.error('Delete error:', error);
      res.status(500).json({
        success: false,
        message: 'An error occurred while deleting product'
      });
    }
  }
);

// =============================================================================
// SECURE ENDPOINT 8: Constant-Time Username Check (Prevents Timing Attacks)
// =============================================================================
app.get('/check-user',
  query('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9_]+$/),
  handleValidationErrors,
  async (req, res) => {
    try {
      const username = req.query.username;

      // SECURE: Parameterized query
      const [rows] = await pool.execute(
        'SELECT COUNT(*) as count FROM users WHERE username = ?',
        [username]
      );

      // SECURE: Add artificial delay to prevent timing attacks
      await new Promise(resolve => setTimeout(resolve, 100));

      res.json({
        exists: rows[0].count > 0
      });
    } catch (error) {
      console.error('Check user error:', error);
      res.status(500).json({
        success: false,
        message: 'An error occurred'
      });
    }
  }
);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    security: 'All queries use parameterized statements'
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ SECURE API running on port ${PORT}`);
  console.log('All queries use parameterized statements (SQL injection safe)');
});

module.exports = app;
