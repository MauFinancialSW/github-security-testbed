/**
 * IDOR Vulnerability Scanner
 * ==========================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * Custom scanner to detect Insecure Direct Object Reference vulnerabilities
 * in multi-tenant SaaS applications.
 *
 * Copilot Chat Prompt:
 * "Build a custom vulnerability scanner for IDOR in a multi-tenant SaaS API.
 *  The scanner should:
 *  1. Take auth tokens for multiple tenants
 *  2. Attempt cross-tenant resource access
 *  3. Detect successful IDOR exploits
 *  4. Generate findings with severity ratings
 *  5. Include remediation steps in report"
 */

const axios = require('axios');

class IDORScanner {
  constructor(baseUrl, authTokens) {
    this.baseUrl = baseUrl;
    this.authTokens = authTokens;  // { tenantA: {...}, tenantB: {...} }
    this.findings = [];
    this.scannedEndpoints = [];
  }

  /**
   * Get authorization headers for a specific tenant
   */
  getAuthHeaders(tenant) {
    const auth = this.authTokens[tenant];
    return {
      'Authorization': `Bearer ${auth.token}`,
      'X-User-Id': auth.userId,
      'X-Tenant-Id': auth.tenantId,
      'X-User-Role': auth.role || 'user',
      'Content-Type': 'application/json'
    };
  }

  /**
   * Scan a single endpoint for IDOR vulnerability
   */
  async scanEndpoint(endpoint, resourceIds, method = 'GET') {
    console.log(`\nScanning endpoint: ${method} ${endpoint}`);
    const endpointFindings = [];

    // Get Tenant A credentials
    const tenantAHeaders = this.getAuthHeaders('tenantA');

    // Test access to resources that belong to Tenant B
    for (const resourceId of resourceIds.tenantB) {
      const url = `${this.baseUrl}${endpoint}/${resourceId}`;

      try {
        let response;

        if (method === 'GET') {
          response = await axios.get(url, {
            headers: tenantAHeaders,
            validateStatus: () => true  // Don't throw on error status
          });
        } else if (method === 'PUT') {
          response = await axios.put(url, { title: 'IDOR Test' }, {
            headers: tenantAHeaders,
            validateStatus: () => true
          });
        } else if (method === 'DELETE') {
          // Don't actually delete, just test
          response = await axios.get(url, {
            headers: tenantAHeaders,
            validateStatus: () => true
          });
        }

        // If we got 200 and data back, IDOR vulnerability exists
        if (response.status === 200 && response.data) {
          const finding = {
            severity: 'CRITICAL',
            type: 'IDOR',
            method: method,
            endpoint: endpoint,
            resourceId: resourceId,
            description: `Tenant A successfully accessed Tenant B's resource (ID: ${resourceId})`,
            evidence: {
              statusCode: response.status,
              dataReturned: true,
              responsePreview: JSON.stringify(response.data).substring(0, 200)
            },
            impact: 'Unauthorized cross-tenant data access',
            cwe: 'CWE-639',
            owasp: 'A01:2021 - Broken Access Control'
          };

          endpointFindings.push(finding);
          console.log(`  ❌ VULNERABLE: Resource ${resourceId} accessible cross-tenant`);
        } else if (response.status === 403 || response.status === 404) {
          console.log(`  ✅ PROTECTED: Resource ${resourceId} properly restricted (${response.status})`);
        }

      } catch (error) {
        console.log(`  ⚠️  ERROR testing resource ${resourceId}: ${error.message}`);
      }
    }

    this.scannedEndpoints.push({ endpoint, method, findings: endpointFindings.length });
    this.findings.push(...endpointFindings);

    return endpointFindings;
  }

  /**
   * Scan for predictable ID enumeration
   */
  async scanIdEnumeration(endpoint, startId = 1, count = 10) {
    console.log(`\nScanning for ID enumeration: ${endpoint}`);
    const findings = [];
    let accessibleCount = 0;

    const headers = this.getAuthHeaders('tenantA');

    for (let id = startId; id < startId + count; id++) {
      try {
        const response = await axios.get(
          `${this.baseUrl}${endpoint}/${id}`,
          { headers, validateStatus: () => true }
        );

        if (response.status === 200) {
          accessibleCount++;
        }
      } catch (error) {
        // Continue scanning
      }
    }

    // If more than expected resources are accessible, enumeration is possible
    if (accessibleCount > 2) {  // Assuming tenant should only have ~2 resources
      findings.push({
        severity: 'HIGH',
        type: 'ID_ENUMERATION',
        endpoint: endpoint,
        description: `Sequential ID enumeration possible. Accessed ${accessibleCount}/${count} resources.`,
        impact: 'Attacker can discover and access resources by guessing IDs',
        recommendation: 'Use UUIDs instead of sequential integers for resource IDs',
        cwe: 'CWE-639',
        owasp: 'A01:2021 - Broken Access Control'
      });

      console.log(`  ❌ VULNERABLE: ${accessibleCount} resources accessible via enumeration`);
    } else {
      console.log(`  ✅ LIMITED: Only ${accessibleCount} resources accessible`);
    }

    this.findings.push(...findings);
    return findings;
  }

  /**
   * Scan for mass assignment vulnerabilities
   */
  async scanMassAssignment(endpoint, userId) {
    console.log(`\nScanning for mass assignment: ${endpoint}`);
    const findings = [];

    const headers = this.getAuthHeaders('tenantA');

    try {
      // Attempt to update role field
      const response = await axios.put(
        `${this.baseUrl}${endpoint}/${userId}`,
        {
          name: 'Test User',
          role: 'admin'  // Attempting privilege escalation
        },
        { headers, validateStatus: () => true }
      );

      if (response.status === 200) {
        // Check if role was actually updated
        const checkResponse = await axios.get(
          `${this.baseUrl}${endpoint}/${userId}`,
          { headers, validateStatus: () => true }
        );

        if (checkResponse.data?.role === 'admin') {
          findings.push({
            severity: 'CRITICAL',
            type: 'MASS_ASSIGNMENT',
            endpoint: endpoint,
            description: 'Mass assignment allows role escalation to admin',
            evidence: {
              payload: { role: 'admin' },
              result: 'Role successfully changed'
            },
            impact: 'Attacker can escalate privileges to admin',
            recommendation: 'Whitelist allowed fields in update operations',
            cwe: 'CWE-915',
            owasp: 'A01:2021 - Broken Access Control'
          });

          console.log(`  ❌ VULNERABLE: Role escalation via mass assignment`);
        }
      }
    } catch (error) {
      console.log(`  ⚠️  ERROR: ${error.message}`);
    }

    this.findings.push(...findings);
    return findings;
  }

  /**
   * Scan batch endpoints for authorization bypass
   */
  async scanBatchOperations(endpoint, mixedIds) {
    console.log(`\nScanning batch endpoint: ${endpoint}`);
    const findings = [];

    const headers = this.getAuthHeaders('tenantA');

    try {
      const response = await axios.post(
        `${this.baseUrl}${endpoint}`,
        { documentIds: mixedIds },  // Mix of Tenant A and B IDs
        { headers, validateStatus: () => true }
      );

      if (response.status === 200 && response.data.documents) {
        const returnedIds = response.data.documents.map(d => d.id);
        const unauthorizedIds = mixedIds.filter(id =>
          returnedIds.includes(id) && !this.authTokens.tenantA.ownedResourceIds?.includes(id)
        );

        if (unauthorizedIds.length > 0) {
          findings.push({
            severity: 'HIGH',
            type: 'BATCH_AUTHORIZATION_BYPASS',
            endpoint: endpoint,
            description: `Batch operation returned ${unauthorizedIds.length} unauthorized resources`,
            evidence: {
              requestedIds: mixedIds,
              unauthorizedIds: unauthorizedIds
            },
            impact: 'Cross-tenant data exposure via batch operations',
            recommendation: 'Validate authorization for each item in batch requests',
            cwe: 'CWE-639',
            owasp: 'A01:2021 - Broken Access Control'
          });

          console.log(`  ❌ VULNERABLE: Batch returned unauthorized resources`);
        }
      }
    } catch (error) {
      console.log(`  ⚠️  ERROR: ${error.message}`);
    }

    this.findings.push(...findings);
    return findings;
  }

  /**
   * Get remediation steps for a finding
   */
  getRemediationSteps(finding) {
    const remediations = {
      'IDOR': [
        'Add tenant_id to all database queries',
        'Verify current user belongs to resource\'s tenant',
        'Implement row-level security in database',
        'Return 403 Forbidden for cross-tenant access attempts',
        'Log and alert on IDOR attempts'
      ],
      'ID_ENUMERATION': [
        'Replace sequential IDs with UUIDs',
        'Implement rate limiting on resource endpoints',
        'Add additional authorization checks',
        'Consider using signed tokens for resource access'
      ],
      'MASS_ASSIGNMENT': [
        'Whitelist allowed fields in update operations',
        'Use DTOs to explicitly map allowed fields',
        'Never trust client-provided role/permission fields',
        'Implement field-level authorization'
      ],
      'BATCH_AUTHORIZATION_BYPASS': [
        'Validate authorization for each item in batch',
        'Filter batch results by tenant',
        'Implement per-item access checks before returning data',
        'Consider pagination with authorization per page'
      ]
    };

    return remediations[finding.type] || ['Implement proper authorization checks'];
  }

  /**
   * Generate comprehensive vulnerability report
   */
  generateReport() {
    const criticalCount = this.findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = this.findings.filter(f => f.severity === 'HIGH').length;
    const mediumCount = this.findings.filter(f => f.severity === 'MEDIUM').length;

    const report = {
      metadata: {
        scanDate: new Date().toISOString(),
        targetUrl: this.baseUrl,
        scanner: 'IDOR Scanner v1.0',
        endpointsScanned: this.scannedEndpoints.length
      },
      summary: {
        totalFindings: this.findings.length,
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        riskLevel: criticalCount > 0 ? 'CRITICAL' : (highCount > 0 ? 'HIGH' : 'MEDIUM')
      },
      findings: this.findings.map(f => ({
        ...f,
        remediation: {
          steps: this.getRemediationSteps(f),
          priority: f.severity === 'CRITICAL' ? 'Immediate' : 'High',
          estimatedEffort: f.severity === 'CRITICAL' ? '2-4 hours' : '4-8 hours'
        },
        references: [
          `OWASP: ${f.owasp}`,
          `CWE: ${f.cwe}`,
          'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'
        ]
      })),
      scannedEndpoints: this.scannedEndpoints
    };

    return report;
  }

  /**
   * Run full IDOR scan
   */
  async runFullScan(config) {
    console.log('Starting IDOR vulnerability scan...');
    console.log(`Target: ${this.baseUrl}`);
    console.log('='.repeat(50));

    // Scan document endpoints
    await this.scanEndpoint('/api/documents', config.resourceIds, 'GET');

    // Scan user profile endpoint
    await this.scanEndpoint('/api/users', config.userIds, 'GET');

    // Scan invoice endpoint
    await this.scanEndpoint('/api/invoices', config.invoiceIds, 'GET');

    // Scan for ID enumeration
    await this.scanIdEnumeration('/api/documents', 1, 10);

    // Scan for mass assignment
    if (config.testMassAssignment) {
      await this.scanMassAssignment('/api/users', config.ownUserId);
    }

    // Scan batch operations
    if (config.batchEndpoint) {
      await this.scanBatchOperations(config.batchEndpoint, config.mixedResourceIds);
    }

    console.log('\n' + '='.repeat(50));
    console.log('Scan complete. Generating report...');

    return this.generateReport();
  }
}

// Export for use as module
module.exports = IDORScanner;

// CLI execution
if (require.main === module) {
  const scanner = new IDORScanner('http://localhost:3001', {
    tenantA: {
      token: 'tenant-a-jwt-token',
      userId: '1',
      tenantId: 'tenant_a',
      role: 'user',
      ownedResourceIds: [1, 2]
    },
    tenantB: {
      token: 'tenant-b-jwt-token',
      userId: '3',
      tenantId: 'tenant_b',
      role: 'user',
      ownedResourceIds: [3, 4]
    }
  });

  const config = {
    resourceIds: {
      tenantA: [1, 2],
      tenantB: [3, 4]  // Resources owned by Tenant B
    },
    userIds: {
      tenantA: [1, 2],
      tenantB: [3, 4]
    },
    invoiceIds: {
      tenantA: [1],
      tenantB: [2]
    },
    testMassAssignment: true,
    ownUserId: 1,
    batchEndpoint: '/api/documents/batch-export',
    mixedResourceIds: [1, 2, 3, 4]  // Mix of both tenants
  };

  scanner.runFullScan(config).then(report => {
    console.log('\n' + '='.repeat(50));
    console.log('SCAN REPORT');
    console.log('='.repeat(50));
    console.log(JSON.stringify(report, null, 2));
  }).catch(err => {
    console.error('Scan failed:', err);
  });
}
