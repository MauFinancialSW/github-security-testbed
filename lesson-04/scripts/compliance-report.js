/**
 * Security Compliance Report Generator
 * =====================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 04 - Security Code Review, Threat Modeling, Auditing
 *
 * Copilot Prompt Used:
 * "Generate compliance report for OWASP Top 10 and PCI-DSS requirements"
 *
 * Features:
 * - OWASP Top 10 coverage analysis
 * - PCI-DSS requirement mapping
 * - CWE categorization
 * - Remediation tracking
 */

const fs = require('fs');
const path = require('path');

// =============================================================================
// Compliance Frameworks
// =============================================================================

const owaspTop10_2021 = {
  'A01:2021': {
    name: 'Broken Access Control',
    description: 'Restrictions on authenticated users are not properly enforced',
    cwes: ['CWE-22', 'CWE-23', 'CWE-35', 'CWE-59', 'CWE-200', 'CWE-201', 'CWE-219', 'CWE-264', 'CWE-275', 'CWE-276', 'CWE-284', 'CWE-285', 'CWE-352', 'CWE-359', 'CWE-377', 'CWE-402', 'CWE-425', 'CWE-441', 'CWE-497', 'CWE-538', 'CWE-540', 'CWE-548', 'CWE-552', 'CWE-566', 'CWE-601', 'CWE-639', 'CWE-651', 'CWE-668', 'CWE-706', 'CWE-862', 'CWE-863', 'CWE-913', 'CWE-922', 'CWE-1275'],
    controls: [
      'Implement access control mechanisms',
      'Deny access by default',
      'Log access control failures',
      'Rate limit API access',
      'Invalidate JWT tokens on logout'
    ]
  },
  'A02:2021': {
    name: 'Cryptographic Failures',
    description: 'Failures related to cryptography which lead to sensitive data exposure',
    cwes: ['CWE-261', 'CWE-296', 'CWE-310', 'CWE-319', 'CWE-321', 'CWE-322', 'CWE-323', 'CWE-324', 'CWE-325', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-329', 'CWE-330', 'CWE-331', 'CWE-335', 'CWE-336', 'CWE-337', 'CWE-338', 'CWE-340', 'CWE-347', 'CWE-523', 'CWE-720', 'CWE-757', 'CWE-759', 'CWE-760', 'CWE-780', 'CWE-818', 'CWE-916'],
    controls: [
      'Classify data by sensitivity',
      'Use strong encryption algorithms',
      'Encrypt data in transit',
      'Encrypt data at rest',
      'Use proper key management'
    ]
  },
  'A03:2021': {
    name: 'Injection',
    description: 'Hostile data sent to interpreter as part of command or query',
    cwes: ['CWE-20', 'CWE-74', 'CWE-75', 'CWE-77', 'CWE-78', 'CWE-79', 'CWE-80', 'CWE-83', 'CWE-87', 'CWE-88', 'CWE-89', 'CWE-90', 'CWE-91', 'CWE-93', 'CWE-94', 'CWE-95', 'CWE-96', 'CWE-97', 'CWE-98', 'CWE-99', 'CWE-100', 'CWE-113', 'CWE-116', 'CWE-138', 'CWE-184', 'CWE-470', 'CWE-471', 'CWE-564', 'CWE-610', 'CWE-643', 'CWE-644', 'CWE-652', 'CWE-917'],
    controls: [
      'Use parameterized queries',
      'Validate and sanitize input',
      'Use safe APIs',
      'Escape special characters',
      'Limit query permissions'
    ]
  },
  'A04:2021': {
    name: 'Insecure Design',
    description: 'Missing or ineffective security controls',
    cwes: ['CWE-73', 'CWE-183', 'CWE-209', 'CWE-213', 'CWE-235', 'CWE-256', 'CWE-257', 'CWE-266', 'CWE-269', 'CWE-280', 'CWE-311', 'CWE-312', 'CWE-313', 'CWE-316', 'CWE-419', 'CWE-430', 'CWE-434', 'CWE-444', 'CWE-451', 'CWE-472', 'CWE-501', 'CWE-522', 'CWE-525', 'CWE-539', 'CWE-579', 'CWE-598', 'CWE-602', 'CWE-642', 'CWE-646', 'CWE-650', 'CWE-653', 'CWE-656', 'CWE-657', 'CWE-799', 'CWE-807', 'CWE-840', 'CWE-841', 'CWE-927', 'CWE-1021', 'CWE-1173'],
    controls: [
      'Establish secure development lifecycle',
      'Use threat modeling',
      'Integrate security in design',
      'Implement security patterns',
      'Perform design reviews'
    ]
  },
  'A05:2021': {
    name: 'Security Misconfiguration',
    description: 'Missing or misconfigured security controls',
    cwes: ['CWE-2', 'CWE-11', 'CWE-13', 'CWE-15', 'CWE-16', 'CWE-260', 'CWE-315', 'CWE-520', 'CWE-526', 'CWE-537', 'CWE-541', 'CWE-547', 'CWE-611', 'CWE-614', 'CWE-756', 'CWE-776', 'CWE-942', 'CWE-1004', 'CWE-1032', 'CWE-1174'],
    controls: [
      'Implement hardening procedures',
      'Remove unused features',
      'Review configurations regularly',
      'Automate configuration management',
      'Implement proper error handling'
    ]
  },
  'A06:2021': {
    name: 'Vulnerable and Outdated Components',
    description: 'Using components with known vulnerabilities',
    cwes: ['CWE-937', 'CWE-1035', 'CWE-1104'],
    controls: [
      'Maintain software inventory',
      'Monitor for vulnerabilities',
      'Update components regularly',
      'Use only trusted sources',
      'Remove unused dependencies'
    ]
  },
  'A07:2021': {
    name: 'Identification and Authentication Failures',
    description: 'Weak authentication or session management',
    cwes: ['CWE-255', 'CWE-259', 'CWE-287', 'CWE-288', 'CWE-290', 'CWE-294', 'CWE-295', 'CWE-297', 'CWE-300', 'CWE-302', 'CWE-304', 'CWE-306', 'CWE-307', 'CWE-346', 'CWE-384', 'CWE-521', 'CWE-613', 'CWE-620', 'CWE-640', 'CWE-798', 'CWE-940', 'CWE-1216'],
    controls: [
      'Implement MFA',
      'Use secure password policies',
      'Protect against brute force',
      'Use secure session management',
      'Implement account lockout'
    ]
  },
  'A08:2021': {
    name: 'Software and Data Integrity Failures',
    description: 'Code and infrastructure without integrity verification',
    cwes: ['CWE-345', 'CWE-353', 'CWE-426', 'CWE-494', 'CWE-502', 'CWE-565', 'CWE-784', 'CWE-829', 'CWE-830', 'CWE-913'],
    controls: [
      'Verify software integrity',
      'Use signed packages',
      'Secure CI/CD pipelines',
      'Review code changes',
      'Validate serialized data'
    ]
  },
  'A09:2021': {
    name: 'Security Logging and Monitoring Failures',
    description: 'Insufficient logging, detection, and response',
    cwes: ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778'],
    controls: [
      'Log security events',
      'Monitor for anomalies',
      'Implement alerting',
      'Retain logs appropriately',
      'Protect log integrity'
    ]
  },
  'A10:2021': {
    name: 'Server-Side Request Forgery (SSRF)',
    description: 'Fetching remote resources without validating user-supplied URL',
    cwes: ['CWE-918'],
    controls: [
      'Validate and sanitize URLs',
      'Use allowlists for destinations',
      'Disable HTTP redirects',
      'Block private IP ranges',
      'Use network segmentation'
    ]
  }
};

const pciDss4 = {
  'Requirement 1': {
    name: 'Install and Maintain Network Security Controls',
    controls: ['1.1', '1.2', '1.3', '1.4', '1.5']
  },
  'Requirement 2': {
    name: 'Apply Secure Configurations',
    controls: ['2.1', '2.2', '2.3']
  },
  'Requirement 3': {
    name: 'Protect Stored Account Data',
    controls: ['3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7']
  },
  'Requirement 4': {
    name: 'Protect Cardholder Data with Strong Cryptography',
    controls: ['4.1', '4.2']
  },
  'Requirement 5': {
    name: 'Protect All Systems Against Malware',
    controls: ['5.1', '5.2', '5.3', '5.4']
  },
  'Requirement 6': {
    name: 'Develop and Maintain Secure Systems',
    controls: ['6.1', '6.2', '6.3', '6.4', '6.5']
  },
  'Requirement 7': {
    name: 'Restrict Access to System Components',
    controls: ['7.1', '7.2', '7.3']
  },
  'Requirement 8': {
    name: 'Identify Users and Authenticate Access',
    controls: ['8.1', '8.2', '8.3', '8.4', '8.5', '8.6']
  },
  'Requirement 9': {
    name: 'Restrict Physical Access',
    controls: ['9.1', '9.2', '9.3', '9.4', '9.5']
  },
  'Requirement 10': {
    name: 'Log and Monitor All Access',
    controls: ['10.1', '10.2', '10.3', '10.4', '10.5', '10.6', '10.7']
  },
  'Requirement 11': {
    name: 'Test Security of Systems Regularly',
    controls: ['11.1', '11.2', '11.3', '11.4', '11.5', '11.6']
  },
  'Requirement 12': {
    name: 'Support Information Security with Policies',
    controls: ['12.1', '12.2', '12.3', '12.4', '12.5', '12.6', '12.7', '12.8', '12.9', '12.10']
  }
};

// =============================================================================
// Compliance Report Generator
// =============================================================================

class ComplianceReportGenerator {
  constructor() {
    this.findings = [];
    this.controls = new Map();
    this.remediation = new Map();
  }

  /**
   * Add security finding from scan results
   */
  addFinding(finding) {
    this.findings.push({
      id: finding.id || `FINDING-${Date.now()}`,
      severity: finding.severity,
      cwe: finding.cwe,
      title: finding.title,
      description: finding.description,
      location: finding.location,
      remediation: finding.remediation,
      status: finding.status || 'open',
      discoveredAt: finding.discoveredAt || new Date().toISOString()
    });

    return this;
  }

  /**
   * Import findings from SARIF format
   */
  importSarif(sarifPath) {
    const sarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));

    for (const run of sarif.runs || []) {
      const tool = run.tool?.driver?.name || 'Unknown';

      for (const result of run.results || []) {
        this.addFinding({
          id: result.ruleId,
          severity: this.mapSarifSeverity(result.level),
          cwe: this.extractCwe(result),
          title: result.message?.text,
          description: result.message?.text,
          location: this.formatLocation(result.locations),
          remediation: result.fixes?.[0]?.description?.text,
          tool
        });
      }
    }

    return this;
  }

  mapSarifSeverity(level) {
    const mapping = {
      'error': 'critical',
      'warning': 'high',
      'note': 'medium',
      'none': 'low'
    };
    return mapping[level] || 'medium';
  }

  extractCwe(result) {
    const tags = result.properties?.tags || [];
    const cweTag = tags.find(t => t.startsWith('CWE-'));
    return cweTag || null;
  }

  formatLocation(locations) {
    if (!locations || locations.length === 0) return 'Unknown';

    const loc = locations[0];
    const file = loc.physicalLocation?.artifactLocation?.uri || 'Unknown file';
    const line = loc.physicalLocation?.region?.startLine || '?';

    return `${file}:${line}`;
  }

  /**
   * Map findings to OWASP Top 10
   */
  mapToOwasp() {
    const mapping = {};

    for (const [id, category] of Object.entries(owaspTop10_2021)) {
      mapping[id] = {
        ...category,
        findings: [],
        status: 'compliant'
      };
    }

    for (const finding of this.findings) {
      if (!finding.cwe) continue;

      for (const [id, category] of Object.entries(owaspTop10_2021)) {
        if (category.cwes.includes(finding.cwe)) {
          mapping[id].findings.push(finding);
          if (finding.status === 'open') {
            mapping[id].status = 'non-compliant';
          }
        }
      }
    }

    return mapping;
  }

  /**
   * Generate compliance score
   */
  calculateScore() {
    const owaspMapping = this.mapToOwasp();
    const totalCategories = Object.keys(owaspMapping).length;
    const compliantCategories = Object.values(owaspMapping)
      .filter(c => c.status === 'compliant').length;

    const openFindings = this.findings.filter(f => f.status === 'open');
    const severityScores = {
      'critical': 10,
      'high': 7,
      'medium': 4,
      'low': 1
    };

    const riskScore = openFindings.reduce((sum, f) =>
      sum + (severityScores[f.severity] || 0), 0);

    return {
      owaspCompliance: Math.round((compliantCategories / totalCategories) * 100),
      totalFindings: this.findings.length,
      openFindings: openFindings.length,
      riskScore,
      riskLevel: riskScore > 50 ? 'Critical' :
                 riskScore > 30 ? 'High' :
                 riskScore > 10 ? 'Medium' : 'Low'
    };
  }

  /**
   * Generate HTML report
   */
  generateHtmlReport() {
    const owaspMapping = this.mapToOwasp();
    const score = this.calculateScore();

    const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Security Compliance Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; }
    .header { background: #1a1a2e; color: white; padding: 20px; margin: -40px -40px 20px; }
    .summary { display: flex; gap: 20px; margin-bottom: 20px; }
    .card { border: 1px solid #ddd; padding: 15px; border-radius: 8px; flex: 1; }
    .critical { color: #dc3545; }
    .high { color: #fd7e14; }
    .medium { color: #ffc107; }
    .low { color: #28a745; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
    th { background: #f5f5f5; }
    .compliant { background: #d4edda; }
    .non-compliant { background: #f8d7da; }
    .finding { margin: 10px 0; padding: 10px; border-left: 4px solid; }
    .finding.critical { border-color: #dc3545; background: #f8d7da; }
    .finding.high { border-color: #fd7e14; background: #fff3cd; }
    .finding.medium { border-color: #ffc107; background: #fff8e1; }
    .finding.low { border-color: #28a745; background: #d4edda; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Compliance Report</h1>
    <p>Generated: ${new Date().toISOString()}</p>
  </div>

  <div class="summary">
    <div class="card">
      <h3>OWASP Compliance</h3>
      <h2>${score.owaspCompliance}%</h2>
    </div>
    <div class="card">
      <h3>Total Findings</h3>
      <h2>${score.totalFindings}</h2>
    </div>
    <div class="card">
      <h3>Open Findings</h3>
      <h2 class="${score.openFindings > 0 ? 'critical' : 'low'}">${score.openFindings}</h2>
    </div>
    <div class="card">
      <h3>Risk Level</h3>
      <h2 class="${score.riskLevel.toLowerCase()}">${score.riskLevel}</h2>
    </div>
  </div>

  <h2>OWASP Top 10 Coverage</h2>
  <table>
    <tr>
      <th>ID</th>
      <th>Category</th>
      <th>Findings</th>
      <th>Status</th>
    </tr>
    ${Object.entries(owaspMapping).map(([id, cat]) => `
    <tr class="${cat.status}">
      <td>${id}</td>
      <td>${cat.name}</td>
      <td>${cat.findings.length}</td>
      <td>${cat.status.toUpperCase()}</td>
    </tr>
    `).join('')}
  </table>

  <h2>Findings Detail</h2>
  ${this.findings.map(f => `
  <div class="finding ${f.severity}">
    <strong>${f.id}</strong> - ${f.title}
    <br><small>Severity: ${f.severity} | CWE: ${f.cwe || 'N/A'} | Location: ${f.location}</small>
    <p>${f.description}</p>
    ${f.remediation ? `<p><strong>Remediation:</strong> ${f.remediation}</p>` : ''}
  </div>
  `).join('')}

</body>
</html>`;

    return html;
  }

  /**
   * Generate JSON report
   */
  generateJsonReport() {
    return {
      metadata: {
        generatedAt: new Date().toISOString(),
        version: '1.0.0',
        frameworks: ['OWASP Top 10 2021', 'PCI-DSS 4.0']
      },
      score: this.calculateScore(),
      owasp: this.mapToOwasp(),
      findings: this.findings,
      remediation: Object.fromEntries(this.remediation)
    };
  }

  /**
   * Save reports to files
   */
  saveReports(outputDir) {
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // HTML Report
    fs.writeFileSync(
      path.join(outputDir, 'compliance-report.html'),
      this.generateHtmlReport()
    );

    // JSON Report
    fs.writeFileSync(
      path.join(outputDir, 'compliance-report.json'),
      JSON.stringify(this.generateJsonReport(), null, 2)
    );

    console.log(`Reports saved to ${outputDir}`);
  }
}

// =============================================================================
// Export
// =============================================================================

module.exports = {
  ComplianceReportGenerator,
  owaspTop10_2021,
  pciDss4
};

// =============================================================================
// Demo
// =============================================================================

if (require.main === module) {
  console.log('=== Compliance Report Generator Demo ===\n');

  const generator = new ComplianceReportGenerator();

  // Add sample findings
  generator.addFinding({
    id: 'SQL-001',
    severity: 'critical',
    cwe: 'CWE-89',
    title: 'SQL Injection in user search',
    description: 'User input is concatenated directly into SQL query',
    location: 'src/api/users.js:45',
    remediation: 'Use parameterized queries'
  });

  generator.addFinding({
    id: 'XSS-001',
    severity: 'high',
    cwe: 'CWE-79',
    title: 'Reflected XSS in search results',
    description: 'Search term is reflected without encoding',
    location: 'src/views/search.jsx:23',
    remediation: 'Use React JSX escaping or DOMPurify'
  });

  generator.addFinding({
    id: 'CRYPTO-001',
    severity: 'medium',
    cwe: 'CWE-327',
    title: 'Weak hashing algorithm',
    description: 'MD5 used for password hashing',
    location: 'src/auth/hash.js:12',
    remediation: 'Use Argon2id or bcrypt'
  });

  // Generate reports
  const score = generator.calculateScore();
  console.log('Compliance Score:', score);

  generator.saveReports('./reports');
}
