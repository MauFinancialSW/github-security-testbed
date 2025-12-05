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
  ]
};

module.exports = { COMMON_PAYLOADS };
