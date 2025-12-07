/**
 * SQL Injection Prevention Tests
 * ==============================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * These tests verify that SQL injection attacks are properly blocked.
 * Tests should PASS when the secure API is used (attacks fail).
 *
 * Run with: npm test
 */

const request = require('supertest');
const app = require('../secure/api');

describe('SQL Injection Prevention Tests', () => {

  // =========================================================================
  // Test Category 1: Authentication Bypass Attacks
  // =========================================================================
  describe('Authentication Bypass Prevention', () => {

    test('should reject SQL injection with OR 1=1', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: "' OR '1'='1",
          password: "anything"
        });

      // Should NOT return success - injection should be blocked
      expect(response.body.success).not.toBe(true);
      expect(response.status).toBe(400);  // Validation should reject
    });

    test('should reject SQL injection with comment bypass', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: "admin'--",
          password: "ignored"
        });

      // Comment injection should not bypass authentication
      expect(response.body.success).not.toBe(true);
    });

    test('should reject SQL injection with UNION attack', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: "' UNION SELECT 1,'admin','password','admin'--",
          password: "x"
        });

      expect(response.body.success).not.toBe(true);
    });

    test('should reject always-true condition attack', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: "' OR 1=1 OR '",
          password: "' OR 1=1 OR '"
        });

      expect(response.body.success).not.toBe(true);
    });

  });

  // =========================================================================
  // Test Category 2: UNION-based SQL Injection
  // =========================================================================
  describe('UNION-based Injection Prevention', () => {

    test('should reject UNION SELECT attack on user endpoint', async () => {
      const maliciousId = "1 UNION SELECT username, password, email FROM users--";

      const response = await request(app)
        .get(`/user/${encodeURIComponent(maliciousId)}`);

      // Should return validation error, not query results
      expect(response.status).toBe(400);
    });

    test('should reject information_schema enumeration', async () => {
      const response = await request(app)
        .get('/search')
        .query({
          q: "' UNION SELECT table_name, column_name, 1, 1 FROM information_schema.columns--"
        });

      // Should not leak database schema
      expect(response.body.results).toBeDefined();
      // Results should only contain products, not schema info
      if (response.body.results?.length > 0) {
        response.body.results.forEach(result => {
          expect(result).not.toHaveProperty('table_name');
          expect(result).not.toHaveProperty('column_name');
        });
      }
    });

  });

  // =========================================================================
  // Test Category 3: ORDER BY Injection
  // =========================================================================
  describe('ORDER BY Injection Prevention', () => {

    test('should reject malicious ORDER BY injection', async () => {
      const response = await request(app)
        .get('/products')
        .query({
          sort: '(SELECT password FROM users WHERE username="admin")',
          order: 'ASC'
        });

      // Should return validation error for invalid sort column
      expect(response.status).toBe(400);
    });

    test('should reject stacked query via ORDER BY', async () => {
      const response = await request(app)
        .get('/products')
        .query({
          sort: 'name; DROP TABLE products;--',
          order: 'ASC'
        });

      // Should fail validation, not execute stacked query
      expect(response.status).toBe(400);
    });

    test('should accept valid whitelist sort columns', async () => {
      const response = await request(app)
        .get('/products')
        .query({
          sort: 'price',
          order: 'DESC'
        });

      // Valid sort should work
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

  });

  // =========================================================================
  // Test Category 4: Blind SQL Injection
  // =========================================================================
  describe('Blind SQL Injection Prevention', () => {

    test('should not leak data via boolean-based blind injection', async () => {
      // Attempt to extract first character of admin password
      const injectionPayload = "admin' AND SUBSTRING(password,1,1)='a'--";

      const response = await request(app)
        .get('/check-user')
        .query({ username: injectionPayload });

      // Should fail validation, not return boolean hints
      expect(response.status).toBe(400);
    });

    test('should not be vulnerable to time-based blind injection', async () => {
      const startTime = Date.now();

      // Time-based injection - should NOT cause delay if protected
      const response = await request(app)
        .get('/check-user')
        .query({ username: "admin' AND SLEEP(5)--" });

      const duration = Date.now() - startTime;

      // Should fail validation quickly, not wait 5 seconds
      expect(duration).toBeLessThan(2000);
      expect(response.status).toBe(400);
    });

  });

  // =========================================================================
  // Test Category 5: Stacked Queries (Batched Statements)
  // =========================================================================
  describe('Stacked Query Prevention', () => {

    test('should reject DROP TABLE attack', async () => {
      const response = await request(app)
        .get('/user/1; DROP TABLE users;--');

      // Should fail validation, table should still exist
      expect(response.status).toBe(400);
    });

    test('should reject INSERT into admin role', async () => {
      const response = await request(app)
        .post('/register')
        .send({
          username: "attacker",
          email: "attacker@evil.com",
          password: "password123'); INSERT INTO users VALUES (999,'hacker','h@h.com','hacked','admin')--"
        });

      // Should fail validation
      expect(response.status).toBe(400);
    });

  });

  // =========================================================================
  // Test Category 6: Special Character Handling
  // =========================================================================
  describe('Special Character Handling', () => {

    test('should properly escape single quotes', async () => {
      const response = await request(app)
        .get('/search')
        .query({ q: "O'Reilly" });  // Legitimate apostrophe in search

      // Should handle without error
      expect([200, 400]).toContain(response.status);
      // Should not crash or expose SQL error
      expect(response.body.error).not.toMatch(/SQL|syntax|mysql/i);
    });

    test('should properly handle backslashes', async () => {
      const response = await request(app)
        .get('/search')
        .query({ q: "test\\value" });

      expect([200, 400]).toContain(response.status);
    });

    test('should properly handle null bytes', async () => {
      const response = await request(app)
        .get('/search')
        .query({ q: "test%00value" });

      expect([200, 400]).toContain(response.status);
    });

  });

  // =========================================================================
  // Test Category 7: Error Message Information Leakage
  // =========================================================================
  describe('Error Message Security', () => {

    test('should not expose SQL syntax in error messages', async () => {
      const response = await request(app)
        .get('/user/invalid-id');

      // Error message should be generic
      if (response.body.message) {
        expect(response.body.message).not.toMatch(/SQL|syntax|mysql|query/i);
      }
    });

    test('should not expose database structure in errors', async () => {
      const response = await request(app)
        .get('/search')
        .query({ q: "'" });  // Single quote to try to break query

      if (response.body.error || response.body.message) {
        const errorMsg = response.body.error || response.body.message;
        expect(errorMsg).not.toMatch(/column|table|database|schema/i);
      }
    });

  });

  // =========================================================================
  // Test Category 9: Encoding Bypasses & Case Sensitivity
  // =========================================================================
  describe('Encoding Bypasses & Case Sensitivity', () => {

    test('should reject case-variation OR injection', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: "' oR '1'='1",
          password: "x"
        });

      expect(response.body.success).not.toBe(true);
      expect([400, 401]).toContain(response.status);
    });

    test('should reject mixed case OR with different variations', async () => {
      const variations = ["' Or '1'='1", "' OR '1'='1", "' Or '1'='1"];

      for (const payload of variations) {
        const response = await request(app)
          .post('/login')
          .send({ username: payload, password: "x" });
        expect(response.body.success).not.toBe(true);
      }
    });

    test('should reject URL-encoded SQL injection in path parameters', async () => {
      // %27 = ', %20 = space, %4F%52 = OR
      const response = await request(app)
        .get('/user/1%27%20OR%201%3D1');

      expect(response.status).toBe(400);
    });

    test('should reject double URL-encoded payloads', async () => {
      // Double encoded: %2527 = %27 (encoded quote)
      const response = await request(app)
        .get('/user/1%2527%20OR%201%3D1');

      expect([400, 404]).toContain(response.status);
    });

    test('should reject Unicode-encoded SQL injection', async () => {
      // Using Unicode escape sequences
      const response = await request(app)
        .post('/login')
        .send({
          username: "' \u004f\u0052 '1'='1",  // OR in Unicode
          password: "x"
        });

      expect(response.body.success).not.toBe(true);
    });

    test('should reject hex-encoded SQL keywords', async () => {
      // 0x4f52 = OR in hex
      const response = await request(app)
        .get('/search')
        .query({ q: "' 0x4f52 1=1--" });

      expect(response.status).toBe(400);
    });

  });

  // =========================================================================
  // Test Category 10: MySQL Comment Syntax Variations
  // =========================================================================
  describe('MySQL Comment Syntax Variations', () => {

    test('should reject MySQL version-specific comments', async () => {
      // /*!50000 */ syntax is MySQL-specific version comment
      const response = await request(app)
        .post('/login')
        .send({
          username: "' /*!50000 OR */ '1'='1",
          password: "x"
        });

      expect(response.body.success).not.toBe(true);
    });

    test('should reject C-style block comments', async () => {
      const response = await request(app)
        .get('/search')
        .query({ q: "' OR 1=1 /*! malicious */" });

      expect(response.status).toBe(400);
    });

    test('should reject nested comment bypass', async () => {
      const response = await request(app)
        .get('/search')
        .query({ q: "' OR '1'='1' /**/" });

      expect(response.status).toBe(400);
    });

    test('should reject semicolon with null byte terminator', async () => {
      const response = await request(app)
        .get('/user/1; DROP TABLE users%00');

      expect(response.status).toBe(400);
    });

  });

  // =========================================================================
  // Test Category 11: Type Juggling & Numeric Parameter Bypass
  // =========================================================================
  describe('Type Juggling & Numeric Parameter Bypass', () => {

    test('should reject string injection in numeric parameter', async () => {
      const response = await request(app)
        .get('/user/1\' OR \'a\'=\'a');

      expect(response.status).toBe(400);
    });

    test('should reject float notation in numeric field', async () => {
      const response = await request(app)
        .get('/user/1.0 OR 1=1');

      expect(response.status).toBe(400);
    });

    test('should reject scientific notation with injection', async () => {
      const response = await request(app)
        .get('/user/1e0 OR 1=1');

      expect(response.status).toBe(400);
    });

    test('should reject negative number with OR clause', async () => {
      const response = await request(app)
        .get('/user/-1 OR 1=1');

      expect(response.status).toBe(400);
    });

  });

  // =========================================================================
  // Test Category 12: LIKE Clause Specific Injection
  // =========================================================================
  describe('LIKE Clause Specific Injection', () => {

    test('should reject LIKE-based injection with % wildcard', async () => {
      const response = await request(app)
        .get('/search')
        .query({ q: "%' UNION SELECT * FROM users--" });

      expect(response.status).toBe(400);
    });

    test('should reject LIKE-based injection with _ wildcard', async () => {
      const response = await request(app)
        .get('/search')
        .query({ q: "_' OR 1=1--" });

      expect(response.status).toBe(400);
    });

    test('should reject LIKE injection with time-based blind SQL', async () => {
      const startTime = Date.now();

      const response = await request(app)
        .get('/search')
        .query({ q: "' AND SLEEP(2)--" });

      const duration = Date.now() - startTime;

      // Should fail quickly, not wait for SLEEP
      expect(duration).toBeLessThan(1500);
    });

  });

  // =========================================================================
  // Test Category 13: Multiple Parameter Interaction
  // =========================================================================
  describe('Multiple Parameter Interaction', () => {

    test('should reject injection in secondary parameter', async () => {
      const response = await request(app)
        .get('/search')
        .query({ q: "normal", category: "' OR 1=1--" });

      expect(response.status).toBe(400);
    });

    test('should reject injection in primary parameter', async () => {
      const response = await request(app)
        .get('/search')
        .query({ q: "' OR 1=1--", category: "normal" });

      expect(response.status).toBe(400);
    });

    test('should reject simultaneous injection in both parameters', async () => {
      const response = await request(app)
        .get('/search')
        .query({
          q: "' OR 1=1--",
          category: "' OR 1=1--"
        });

      expect(response.status).toBe(400);
    });

    test('should reject cross-parameter injection attempts', async () => {
      // Attempt to break out via first param and continue in second
      const response = await request(app)
        .get('/search')
        .query({
          q: "test' UNION SELECT",
          category: "* FROM users--"
        });

      expect(response.status).toBe(400);
    });

  });

  // =========================================================================
  // Test Category 14: Nested Quote & Escape Variations
  // =========================================================================
  describe('Nested Quote & Escape Variations', () => {

    test('should reject backslash-escaped quote bypass', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: "\\' OR '1'='1",
          password: "x"
        });

      expect(response.body.success).not.toBe(true);
    });

    test('should reject triple-quote confusion attack', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: "''' OR '1'='",
          password: "x"
        });

      expect(response.body.success).not.toBe(true);
    });

    test('should reject mixed single/double quote injection', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: '" OR "1"="1',
          password: "x"
        });

      // Response depends on parameterization, but shouldn't authenticate
      expect(response.body.success).not.toBe(true);
    });

    test('should reject parenthesis manipulation with quotes', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: "' OR (1=1 AND '1'='1",
          password: "x"
        });

      expect(response.body.success).not.toBe(true);
    });

  });

  // =========================================================================
  // Test Category 15: UPDATE/DELETE/INSERT Field-Specific Injection
  // =========================================================================
  describe('UPDATE/DELETE/INSERT Field-Specific Injection', () => {

    test('should reject UPDATE injection in email field', async () => {
      const response = await request(app)
        .put('/user/1')
        .send({
          email: "' OR 1=1; DROP TABLE users--",
          displayName: "Normal Name"
        });

      expect(response.status).toBe(400);
    });

    test('should reject UPDATE injection in displayName field', async () => {
      const response = await request(app)
        .put('/user/1')
        .send({
          email: "test@test.com",
          displayName: "admin', role='admin"
        });

      expect(response.status).toBe(400);
    });

    test('should reject UPDATE injection in URL path parameter', async () => {
      const response = await request(app)
        .put('/user/1\' OR \'1\'=\'1')
        .send({
          email: "test@test.com",
          displayName: "Name"
        });

      expect(response.status).toBe(400);
    });

    test('should reject DELETE with OR condition in path', async () => {
      const response = await request(app)
        .delete('/product/1 OR 1=1');

      expect(response.status).toBe(400);
    });

    test('should reject INSERT with column-count mismatch injection', async () => {
      const response = await request(app)
        .post('/register')
        .send({
          username: "hacker",
          email: "h@h.com', 999, 'admin'); DELETE FROM users WHERE 'x'='x",
          password: "pass123"
        });

      expect(response.status).toBe(400);
    });

  });

  // =========================================================================
  // Test Category 16: ORDER BY Numeric & Boundary Cases
  // =========================================================================
  describe('ORDER BY Numeric & Boundary Cases', () => {

    test('should reject ORDER BY with negative number injection', async () => {
      const response = await request(app)
        .get('/products')
        .query({
          sort: "-1 UNION SELECT * FROM users--",
          order: "ASC"
        });

      expect(response.status).toBe(400);
    });

    test('should reject ORDER BY with out-of-range column index', async () => {
      const response = await request(app)
        .get('/products')
        .query({
          sort: "999999",
          order: "ASC"
        });

      expect(response.status).toBe(400);
    });

    test('should reject ORDER BY with invalid sort direction case', async () => {
      const response = await request(app)
        .get('/products')
        .query({
          sort: "price",
          order: "desc; DROP--"  // lowercase + injection
        });

      expect(response.status).toBe(400);
    });

    test('should reject ORDER BY with expression injection', async () => {
      const response = await request(app)
        .get('/products')
        .query({
          sort: "CASE WHEN 1=1 THEN id ELSE name END",
          order: "ASC"
        });

      expect(response.status).toBe(400);
    });

  });

  // =========================================================================
  // Test Category 17: Comment Escape Sequences
  // =========================================================================
  describe('Comment Escape Sequences', () => {

    test('should reject hash comment with injection', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: "admin'#",
          password: "anything"
        });

      expect(response.body.success).not.toBe(true);
    });

    test('should reject inline comment with conditional logic', async () => {
      const response = await request(app)
        .get('/search')
        .query({
          q: "' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--"
        });

      expect(response.status).toBe(400);
    });

  });

  // =========================================================================
  // Test Category 8: Input Validation
  // =========================================================================
  describe('Input Validation', () => {

    test('should validate user ID is numeric', async () => {
      const response = await request(app)
        .get('/user/abc');

      expect(response.status).toBe(400);
      expect(response.body.errors).toBeDefined();
    });

    test('should validate email format', async () => {
      const response = await request(app)
        .post('/register')
        .send({
          username: 'validuser',
          email: 'not-an-email',
          password: 'SecurePass123'
        });

      expect(response.status).toBe(400);
    });

    test('should enforce password complexity', async () => {
      const response = await request(app)
        .post('/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'weak'  // Too short, no complexity
        });

      expect(response.status).toBe(400);
    });

  });

});

// =========================================================================
// Common SQL Injection Payloads Reference
// =========================================================================
const COMMON_PAYLOADS = {
  authentication_bypass: [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "admin'--",
    "' OR 1=1#",
    "') OR ('1'='1",
    "' OR 1=1/*",
    "' oR '1'='1",  // Case variation
    "' Or '1'='1",  // Case variation
  ],
  union_based: [
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password FROM users--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
  ],
  error_based: [
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
  ],
  blind_boolean: [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND SUBSTRING(username,1,1)='a'--",
  ],
  blind_time: [
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(5000000,SHA1('test'))--",
  ],
  stacked_queries: [
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES('hacker','hacker')--",
    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
  ],
  encoding_bypasses: [
    "' %4f%52 '1'='1",                    // URL-encoded OR
    "%27%20OR%201%3D1",                   // URL-encoded ' OR 1=1
    "' /*!50000 OR */ '1'='1",            // MySQL version comment
    "' UNION /*! SELECT */ * FROM users", // MySQL version comment UNION
    "' OR 0x31=0x31",                     // Hex-encoded 1=1
  ],
  like_clause_specific: [
    "%' UNION SELECT * FROM users--",
    "_' OR 1=1--",
    "' OR 1=1 LIKE '",
    "%' AND SLEEP(5)--",
  ],
  comment_variations: [
    "' OR 1=1 /**/",
    "' OR 1=1 #",
    "' OR 1=1 -- -",
    "'; WAITFOR DELAY '0:0:5'--",
    "' /*!50000 OR */ '1'='1",  // MySQL version-specific comment
  ],
  type_juggling: [
    "1' OR '1'='1",        // String in numeric context
    "1.0 OR 1=1",          // Float notation
    "1e0 OR 1=1",          // Scientific notation
    "-1 OR 1=1",           // Negative number
  ],
  escape_bypass: [
    "\\' OR '1'='1",       // Backslash escape
    "''' OR '1'='",        // Triple quotes
    '\" OR \"1\"=\"1',     // Double quotes
    "' OR (1=1 AND '1'='1", // Parenthesis confusion
  ]
};

module.exports = { COMMON_PAYLOADS };
