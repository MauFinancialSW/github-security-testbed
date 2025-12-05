/**
 * Race Condition Vulnerability Scanner
 * =====================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * Custom scanner to detect race condition vulnerabilities in web applications.
 * Focuses on TOCTOU (Time-of-check to time-of-use) and concurrent request issues.
 *
 * Copilot Chat Prompt:
 * "Generate a race condition scanner for e-commerce coupon redemption.
 *  The scanner should:
 *  1. Send 50 concurrent requests with same coupon code
 *  2. Detect if coupon is reused (race condition)
 *  3. Report vulnerability if more than 1 request succeeds
 *  4. Suggest database locking as remediation"
 */

const axios = require('axios');

class RaceConditionScanner {
  constructor(baseUrl, authToken) {
    this.baseUrl = baseUrl;
    this.authToken = authToken;
    this.findings = [];
  }

  /**
   * Get authorization headers
   */
  getHeaders() {
    return {
      'Authorization': `Bearer ${this.authToken}`,
      'Content-Type': 'application/json'
    };
  }

  /**
   * Test coupon redemption race condition
   */
  async testCouponRedemption(couponCode, iterations = 50) {
    console.log(`\nTesting coupon race condition with ${iterations} concurrent requests...`);
    console.log(`Coupon code: ${couponCode}`);

    const endpoint = `${this.baseUrl}/api/apply-coupon`;
    const headers = this.getHeaders();

    // Create array of concurrent requests
    const requests = Array(iterations).fill().map((_, index) => {
      return axios.post(
        endpoint,
        { code: couponCode, orderId: `order-${Date.now()}-${index}` },
        {
          headers,
          validateStatus: () => true,
          timeout: 10000
        }
      ).then(response => ({
        index,
        status: response.status,
        success: response.status === 200 && response.data?.success,
        data: response.data
      })).catch(error => ({
        index,
        status: 0,
        success: false,
        error: error.message
      }));
    });

    // Execute all requests simultaneously
    console.log('Sending concurrent requests...');
    const startTime = Date.now();
    const results = await Promise.all(requests);
    const duration = Date.now() - startTime;

    // Analyze results
    const successCount = results.filter(r => r.success).length;
    const failCount = results.filter(r => !r.success && r.status !== 0).length;
    const errorCount = results.filter(r => r.status === 0).length;

    console.log(`\nResults (${duration}ms):`);
    console.log(`  Successful redemptions: ${successCount}`);
    console.log(`  Failed (expected): ${failCount}`);
    console.log(`  Errors: ${errorCount}`);

    if (successCount > 1) {
      const finding = {
        severity: 'HIGH',
        type: 'RACE_CONDITION',
        subtype: 'COUPON_REUSE',
        endpoint: endpoint,
        description: `Coupon code "${couponCode}" was reused ${successCount} times due to race condition`,
        evidence: {
          iterations: iterations,
          successfulRedemptions: successCount,
          duration: `${duration}ms`,
          successfulResponses: results.filter(r => r.success).map(r => ({
            index: r.index,
            data: r.data
          }))
        },
        impact: 'Financial loss - users can apply single-use coupons multiple times',
        businessImpact: `Potential loss: ${successCount - 1} x coupon value`,
        cwe: 'CWE-362',
        owasp: 'A04:2021 - Insecure Design'
      };

      this.findings.push(finding);
      console.log(`  ❌ VULNERABLE: Race condition detected`);

      return { vulnerable: true, finding };
    }

    console.log(`  ✅ PROTECTED: Coupon could only be redeemed once`);
    return { vulnerable: false };
  }

  /**
   * Test account balance withdrawal race condition
   */
  async testBalanceWithdrawal(amount, iterations = 20) {
    console.log(`\nTesting balance withdrawal race condition...`);
    console.log(`Withdrawal amount: $${amount} x ${iterations} requests`);

    const endpoint = `${this.baseUrl}/api/withdraw`;
    const headers = this.getHeaders();

    // Check initial balance
    let initialBalance = 0;
    try {
      const balanceResponse = await axios.get(
        `${this.baseUrl}/api/balance`,
        { headers, validateStatus: () => true }
      );
      initialBalance = balanceResponse.data?.balance || 0;
      console.log(`Initial balance: $${initialBalance}`);
    } catch (error) {
      console.log('Could not fetch initial balance');
    }

    // Create concurrent withdrawal requests
    const requests = Array(iterations).fill().map((_, index) => {
      return axios.post(
        endpoint,
        { amount: amount },
        { headers, validateStatus: () => true }
      ).then(response => ({
        index,
        status: response.status,
        success: response.status === 200,
        newBalance: response.data?.newBalance
      })).catch(error => ({
        index,
        status: 0,
        success: false,
        error: error.message
      }));
    });

    // Execute concurrently
    const results = await Promise.all(requests);

    const successCount = results.filter(r => r.success).length;
    const totalWithdrawn = successCount * amount;

    console.log(`\nResults:`);
    console.log(`  Successful withdrawals: ${successCount}`);
    console.log(`  Total withdrawn: $${totalWithdrawn}`);

    // Check if more money was withdrawn than should be possible
    if (totalWithdrawn > initialBalance && successCount > 1) {
      const finding = {
        severity: 'CRITICAL',
        type: 'RACE_CONDITION',
        subtype: 'BALANCE_OVERDRAW',
        endpoint: endpoint,
        description: `Balance overdraw via race condition: withdrew $${totalWithdrawn} from $${initialBalance} balance`,
        evidence: {
          initialBalance: initialBalance,
          successfulWithdrawals: successCount,
          totalWithdrawn: totalWithdrawn,
          overdraw: totalWithdrawn - initialBalance
        },
        impact: 'Critical financial loss - users can withdraw more than their balance',
        cwe: 'CWE-362',
        owasp: 'A04:2021 - Insecure Design'
      };

      this.findings.push(finding);
      console.log(`  ❌ VULNERABLE: Balance overdraw detected`);

      return { vulnerable: true, finding };
    }

    console.log(`  ✅ PROTECTED: Balance checks appear atomic`);
    return { vulnerable: false };
  }

  /**
   * Test inventory purchase race condition
   */
  async testInventoryRace(productId, quantity, iterations = 30) {
    console.log(`\nTesting inventory race condition...`);
    console.log(`Product: ${productId}, Quantity: ${quantity}`);

    const endpoint = `${this.baseUrl}/api/purchase`;
    const headers = this.getHeaders();

    // Check initial inventory
    let initialStock = 0;
    try {
      const inventoryResponse = await axios.get(
        `${this.baseUrl}/api/products/${productId}`,
        { headers, validateStatus: () => true }
      );
      initialStock = inventoryResponse.data?.stock || 0;
      console.log(`Initial stock: ${initialStock}`);
    } catch (error) {
      console.log('Could not fetch initial inventory');
    }

    // Create concurrent purchase requests
    const requests = Array(iterations).fill().map((_, index) => {
      return axios.post(
        endpoint,
        { productId: productId, quantity: quantity },
        { headers, validateStatus: () => true }
      ).then(response => ({
        index,
        status: response.status,
        success: response.status === 200,
        remainingStock: response.data?.remainingStock
      })).catch(error => ({
        index,
        status: 0,
        success: false,
        error: error.message
      }));
    });

    const results = await Promise.all(requests);
    const successCount = results.filter(r => r.success).length;
    const totalPurchased = successCount * quantity;

    console.log(`\nResults:`);
    console.log(`  Successful purchases: ${successCount}`);
    console.log(`  Total items purchased: ${totalPurchased}`);

    if (totalPurchased > initialStock && successCount > 1) {
      const finding = {
        severity: 'HIGH',
        type: 'RACE_CONDITION',
        subtype: 'INVENTORY_OVERSELL',
        endpoint: endpoint,
        description: `Inventory oversold via race condition: sold ${totalPurchased} items from ${initialStock} stock`,
        evidence: {
          initialStock: initialStock,
          successfulPurchases: successCount,
          totalSold: totalPurchased,
          oversold: totalPurchased - initialStock
        },
        impact: 'Inventory management failure - selling more items than available',
        cwe: 'CWE-362',
        owasp: 'A04:2021 - Insecure Design'
      };

      this.findings.push(finding);
      console.log(`  ❌ VULNERABLE: Inventory oversell detected`);

      return { vulnerable: true, finding };
    }

    console.log(`  ✅ PROTECTED: Inventory checks appear atomic`);
    return { vulnerable: false };
  }

  /**
   * Test file upload race condition (double write)
   */
  async testFileUploadRace(filename, iterations = 10) {
    console.log(`\nTesting file upload race condition...`);

    const endpoint = `${this.baseUrl}/api/upload`;
    const headers = {
      ...this.getHeaders(),
      'Content-Type': 'application/json'
    };

    const requests = Array(iterations).fill().map((_, index) => {
      return axios.post(
        endpoint,
        {
          filename: filename,
          content: `Content from request ${index} - ${Date.now()}`
        },
        { headers, validateStatus: () => true }
      ).then(response => ({
        index,
        status: response.status,
        success: response.status === 200,
        path: response.data?.path
      })).catch(error => ({
        index,
        success: false,
        error: error.message
      }));
    });

    const results = await Promise.all(requests);
    const successCount = results.filter(r => r.success).length;
    const uniquePaths = new Set(results.filter(r => r.path).map(r => r.path));

    console.log(`\nResults:`);
    console.log(`  Successful uploads: ${successCount}`);
    console.log(`  Unique paths created: ${uniquePaths.size}`);

    if (successCount > 1 && uniquePaths.size === 1) {
      const finding = {
        severity: 'MEDIUM',
        type: 'RACE_CONDITION',
        subtype: 'FILE_OVERWRITE',
        endpoint: endpoint,
        description: 'File upload race condition allows content overwrite',
        evidence: {
          successfulUploads: successCount,
          uniqueFiles: uniquePaths.size
        },
        impact: 'Data integrity issue - file content can be overwritten unpredictably',
        cwe: 'CWE-362',
        owasp: 'A04:2021 - Insecure Design'
      };

      this.findings.push(finding);
      console.log(`  ❌ VULNERABLE: File overwrite race condition`);

      return { vulnerable: true, finding };
    }

    return { vulnerable: false };
  }

  /**
   * Get remediation steps for race condition findings
   */
  getRemediationSteps(finding) {
    const remediations = {
      'COUPON_REUSE': [
        'Use database locking (SELECT ... FOR UPDATE)',
        'Implement atomic coupon redemption with transactions',
        'Use optimistic locking with version numbers',
        'Add unique constraint on (coupon_id, order_id)',
        'Consider using Redis SETNX for distributed locking'
      ],
      'BALANCE_OVERDRAW': [
        'Use database transactions with row-level locking',
        'Implement pessimistic locking on balance updates',
        'Use CHECK constraint: balance >= 0',
        'Consider event sourcing for financial transactions',
        'Add idempotency keys to prevent duplicate withdrawals'
      ],
      'INVENTORY_OVERSELL': [
        'Use database-level stock decrement with CHECK',
        'Implement optimistic locking with version field',
        'Use queued purchase processing',
        'Consider reservation system with timeout',
        'Add database constraint: stock >= 0'
      ],
      'FILE_OVERWRITE': [
        'Generate unique filenames server-side',
        'Use atomic file operations (rename after write)',
        'Implement file locking during write',
        'Add versioning to file uploads'
      ]
    };

    return remediations[finding.subtype] || [
      'Implement proper locking mechanism',
      'Use database transactions',
      'Add idempotency keys to prevent duplicate operations'
    ];
  }

  /**
   * Generate vulnerability report
   */
  generateReport() {
    return {
      metadata: {
        scanDate: new Date().toISOString(),
        targetUrl: this.baseUrl,
        scanner: 'Race Condition Scanner v1.0'
      },
      summary: {
        totalFindings: this.findings.length,
        critical: this.findings.filter(f => f.severity === 'CRITICAL').length,
        high: this.findings.filter(f => f.severity === 'HIGH').length,
        medium: this.findings.filter(f => f.severity === 'MEDIUM').length
      },
      findings: this.findings.map(f => ({
        ...f,
        remediation: {
          steps: this.getRemediationSteps(f),
          priority: f.severity === 'CRITICAL' ? 'Immediate' : 'High',
          secureCodeExample: this.getSecureCodeExample(f.subtype)
        }
      }))
    };
  }

  /**
   * Get secure code example for remediation
   */
  getSecureCodeExample(subtype) {
    const examples = {
      'COUPON_REUSE': `
// Secure coupon redemption with database transaction
async function redeemCoupon(couponCode, orderId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Lock the coupon row
    const coupon = await client.query(
      'SELECT * FROM coupons WHERE code = $1 AND used = false FOR UPDATE',
      [couponCode]
    );

    if (coupon.rows.length === 0) {
      throw new Error('Coupon not available');
    }

    // Mark as used
    await client.query(
      'UPDATE coupons SET used = true, used_at = NOW(), order_id = $1 WHERE code = $2',
      [orderId, couponCode]
    );

    await client.query('COMMIT');
    return { success: true };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}`,
      'BALANCE_OVERDRAW': `
// Secure balance withdrawal with optimistic locking
async function withdraw(userId, amount) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Get current balance with lock
    const result = await client.query(
      'UPDATE accounts SET balance = balance - $1 WHERE user_id = $2 AND balance >= $1 RETURNING balance',
      [amount, userId]
    );

    if (result.rows.length === 0) {
      throw new Error('Insufficient funds');
    }

    await client.query('COMMIT');
    return { success: true, newBalance: result.rows[0].balance };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}`
    };

    return examples[subtype] || '// Implement atomic operations with proper locking';
  }
}

module.exports = RaceConditionScanner;

// CLI execution
if (require.main === module) {
  const scanner = new RaceConditionScanner(
    'http://localhost:3002',
    'test-auth-token'
  );

  async function runScan() {
    console.log('Starting Race Condition vulnerability scan...');
    console.log('='.repeat(50));

    await scanner.testCouponRedemption('SAVE20', 50);
    await scanner.testBalanceWithdrawal(100, 20);
    await scanner.testInventoryRace('product-123', 1, 30);

    const report = scanner.generateReport();

    console.log('\n' + '='.repeat(50));
    console.log('SCAN REPORT');
    console.log('='.repeat(50));
    console.log(JSON.stringify(report, null, 2));
  }

  runScan().catch(console.error);
}
