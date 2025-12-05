/**
 * IDOR Vulnerable API - Documents Endpoint
 * ========================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * WARNING: This code contains intentional IDOR vulnerabilities.
 * DO NOT use in production environments.
 *
 * OWASP Category: A01:2021 - Broken Access Control
 * CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
 *
 * Copilot Chat Prompt:
 * "Analyze this multi-tenant API for authorization vulnerabilities.
 *  This is a SaaS app where users should only access their tenant's data.
 *  Check for:
 *  1. Insecure Direct Object Reference (IDOR)
 *  2. Missing tenant isolation
 *  3. Authorization bypasses
 *  4. Horizontal privilege escalation"
 */

const express = require('express');
const router = express.Router();
const db = require('../db');

// Middleware to extract user info from JWT (simplified)
const authenticate = (req, res, next) => {
  // In a real app, this would decode a JWT token
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Mock user extraction (in production, decode JWT)
  req.user = {
    id: req.headers['x-user-id'] || 1,
    tenantId: req.headers['x-tenant-id'] || 'tenant_a',
    role: req.headers['x-user-role'] || 'user'
  };

  next();
};

// =============================================================================
// VULNERABILITY 1: IDOR - No tenant isolation in document retrieval
// =============================================================================
//
// Attack: User from Tenant A accesses Tenant B's document by ID
// Example: GET /documents/123 (where doc 123 belongs to different tenant)
//
router.get('/documents/:docId', authenticate, async (req, res) => {
  const { docId } = req.params;

  try {
    // VULNERABLE: Missing tenant check - any authenticated user can access any document
    const document = await db.query(
      'SELECT * FROM documents WHERE id = ?',
      [docId]
    );

    if (!document || document.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    // Returns document regardless of tenant ownership
    res.json(document[0]);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// VULNERABILITY 2: IDOR - No ownership check in document update
// =============================================================================
//
// Attack: User modifies another tenant's document
//
router.put('/documents/:docId', authenticate, async (req, res) => {
  const { docId } = req.params;
  const { title, content } = req.body;

  try {
    // VULNERABLE: No verification that user owns this document
    const result = await db.query(
      'UPDATE documents SET title = ?, content = ?, updated_at = NOW() WHERE id = ?',
      [title, content, docId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    res.json({ success: true, message: 'Document updated' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// VULNERABILITY 3: IDOR - No ownership check in document deletion
// =============================================================================
//
// Attack: User deletes another tenant's document
//
router.delete('/documents/:docId', authenticate, async (req, res) => {
  const { docId } = req.params;

  try {
    // VULNERABLE: No verification that user's tenant owns this document
    const result = await db.query(
      'DELETE FROM documents WHERE id = ?',
      [docId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    res.json({ success: true, message: 'Document deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// VULNERABILITY 4: IDOR - User profile access without ownership check
// =============================================================================
//
// Attack: User views another user's profile including sensitive data
//
router.get('/users/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;

  try {
    // VULNERABLE: Any user can view any other user's profile
    const user = await db.query(
      'SELECT id, email, name, phone, address, ssn_last_four FROM users WHERE id = ?',
      [userId]
    );

    if (!user || user.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user[0]);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// VULNERABILITY 5: IDOR - Invoice access without authorization
// =============================================================================
//
// Attack: User downloads another tenant's invoice
//
router.get('/invoices/:invoiceId/download', authenticate, async (req, res) => {
  const { invoiceId } = req.params;

  try {
    // VULNERABLE: No tenant check on invoice access
    const invoice = await db.query(
      'SELECT * FROM invoices WHERE id = ?',
      [invoiceId]
    );

    if (!invoice || invoice.length === 0) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    // Returns invoice PDF URL without ownership verification
    res.json({
      downloadUrl: `/files/invoices/${invoiceId}.pdf`,
      invoice: invoice[0]
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// VULNERABILITY 6: Predictable ID enumeration
// =============================================================================
//
// Attack: Sequential IDs allow enumeration of all resources
//
router.get('/orders', authenticate, async (req, res) => {
  // Note: This endpoint IS tenant-filtered, but IDs are predictable
  const { tenantId } = req.user;

  try {
    const orders = await db.query(
      'SELECT * FROM orders WHERE tenant_id = ?',
      [tenantId]
    );

    // VULNERABLE: Exposing internal sequential IDs enables guessing
    // Attacker can try GET /orders/1, /orders/2, etc.
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// VULNERABILITY 7: Mass assignment leading to privilege escalation
// =============================================================================
//
// Attack: User modifies their role by including it in update payload
//
router.put('/users/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;

  try {
    // VULNERABLE: Mass assignment - user can set any field including 'role'
    // Attacker sends: { "name": "Hacker", "role": "admin" }
    const result = await db.query(
      'UPDATE users SET ? WHERE id = ?',
      [req.body, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, message: 'User updated' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// VULNERABILITY 8: Batch operations without per-item authorization
// =============================================================================
//
// Attack: User includes IDs from other tenants in batch request
//
router.post('/documents/batch-export', authenticate, async (req, res) => {
  const { documentIds } = req.body;  // Array of document IDs

  try {
    // VULNERABLE: No verification that user owns ALL requested documents
    const documents = await db.query(
      'SELECT * FROM documents WHERE id IN (?)',
      [documentIds]
    );

    // Returns all requested documents, including ones from other tenants
    res.json({
      count: documents.length,
      documents: documents
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

/**
 * IDOR Attack Scenarios:
 * ======================
 *
 * 1. Horizontal Privilege Escalation:
 *    - User A accesses User B's resources (same role, different identity)
 *    - Example: GET /documents/123 where doc belongs to different user
 *
 * 2. Vertical Privilege Escalation:
 *    - Regular user accesses admin resources
 *    - Example: GET /admin/users or modifying role field
 *
 * 3. Cross-Tenant Access:
 *    - User from Tenant A accesses Tenant B's data
 *    - Critical in multi-tenant SaaS applications
 *
 * 4. Parameter Manipulation:
 *    - Changing IDs in URL or request body
 *    - Modifying tenant_id in requests
 *
 * 5. ID Enumeration:
 *    - Sequential IDs allow guessing valid resources
 *    - Should use UUIDs or other unpredictable identifiers
 */
