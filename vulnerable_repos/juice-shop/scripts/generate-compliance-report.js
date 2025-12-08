#!/usr/bin/env node
/**
 * Generate OWASP Top 10 Compliance Report from GHAS Data
 *
 * Used in Lesson 04, Demo 2 for automated compliance reporting.
 *
 * Usage:
 *   cat alerts.json | node generate-compliance-report.js
 *   node generate-compliance-report.js < alerts.json
 *   node generate-compliance-report.js --format markdown
 */

const fs = require('fs');

const format = process.argv.includes('--format')
  ? process.argv[process.argv.indexOf('--format') + 1]
  : 'markdown';

// OWASP Top 10 2021 categories
const owaspCategories = {
  'A01:2021': 'Broken Access Control',
  'A02:2021': 'Cryptographic Failures',
  'A03:2021': 'Injection',
  'A04:2021': 'Insecure Design',
  'A05:2021': 'Security Misconfiguration',
  'A06:2021': 'Vulnerable and Outdated Components',
  'A07:2021': 'Identification and Authentication Failures',
  'A08:2021': 'Software and Data Integrity Failures',
  'A09:2021': 'Security Logging and Monitoring Failures',
  'A10:2021': 'Server-Side Request Forgery'
};

// CWE to OWASP mapping
const cweMapping = {
  'CWE-79': 'A03:2021',   // XSS
  'CWE-89': 'A03:2021',   // SQL Injection
  'CWE-78': 'A03:2021',   // Command Injection
  'CWE-94': 'A03:2021',   // Code Injection
  'CWE-22': 'A01:2021',   // Path Traversal
  'CWE-284': 'A01:2021',  // Access Control
  'CWE-639': 'A01:2021',  // IDOR
  'CWE-798': 'A07:2021',  // Hardcoded Credentials
  'CWE-287': 'A07:2021',  // Auth Bypass
  'CWE-327': 'A02:2021',  // Weak Crypto
  'CWE-328': 'A02:2021',  // Weak Hash
  'CWE-502': 'A08:2021',  // Deserialization
  'CWE-918': 'A10:2021',  // SSRF
  'CWE-611': 'A05:2021',  // XXE
  'CWE-1035': 'A06:2021'  // Vulnerable Components
};

/**
 * Read GHAS alerts from stdin or file
 */
async function readAlerts() {
  return new Promise((resolve) => {
    let data = '';

    if (process.stdin.isTTY) {
      // No piped input, try reading from file
      const sampleData = {
        scan_date: new Date().toISOString(),
        repository: 'demo/juice-shop',
        alerts: [
          { type: 'CodeQL', severity: 'critical', owasp: 'A03:2021 Injection', rule: 'sql-injection' },
          { type: 'CodeQL', severity: 'high', owasp: 'A03:2021 Injection', rule: 'xss' },
          { type: 'Dependabot', severity: 'high', owasp: 'A06:2021 Vulnerable Components', package: 'lodash' }
        ]
      };
      resolve(sampleData);
    } else {
      process.stdin.on('data', chunk => data += chunk);
      process.stdin.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          console.error('Error parsing JSON input');
          process.exit(1);
        }
      });
    }
  });
}

/**
 * Generate compliance summary by OWASP category
 */
function generateComplianceSummary(alerts) {
  const summary = {};

  // Initialize all categories
  Object.keys(owaspCategories).forEach(cat => {
    summary[cat] = {
      name: owaspCategories[cat],
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      findings: []
    };
  });

  // Categorize alerts
  alerts.forEach(alert => {
    const category = alert.owasp?.split(' ')[0] || 'A06:2021';
    if (summary[category]) {
      summary[category].total++;
      summary[category][alert.severity]++;
      summary[category].findings.push(alert);
    }
  });

  return summary;
}

/**
 * Calculate compliance score
 */
function calculateScore(summary) {
  let totalCategories = Object.keys(summary).length;
  let compliantCategories = Object.values(summary).filter(
    cat => cat.critical === 0 && cat.high === 0
  ).length;

  return Math.round((compliantCategories / totalCategories) * 100);
}

/**
 * Generate Markdown report
 */
function generateMarkdownReport(data, summary) {
  const score = calculateScore(summary);
  const scoreEmoji = score >= 80 ? '🟢' : score >= 50 ? '🟡' : '🔴';

  let report = `# OWASP Top 10 Compliance Report

**Repository:** ${data.repository}
**Generated:** ${new Date().toISOString()}
**Compliance Score:** ${scoreEmoji} ${score}%

## Executive Summary

`;

  // Summary table
  report += `| OWASP Category | Status | Critical | High | Medium | Low |
|----------------|--------|----------|------|--------|-----|
`;

  Object.entries(summary).forEach(([code, cat]) => {
    const status = cat.critical === 0 && cat.high === 0 ? '✅' : '❌';
    report += `| ${code} ${cat.name} | ${status} | ${cat.critical} | ${cat.high} | ${cat.medium} | ${cat.low} |\n`;
  });

  // Detailed findings
  report += `\n## Detailed Findings\n\n`;

  Object.entries(summary).forEach(([code, cat]) => {
    if (cat.total > 0) {
      report += `### ${code}: ${cat.name}\n\n`;
      report += `**Findings:** ${cat.total} (${cat.critical} critical, ${cat.high} high)\n\n`;

      cat.findings.forEach(finding => {
        const icon = finding.severity === 'critical' ? '🔴' :
                     finding.severity === 'high' ? '🟠' : '🟡';
        report += `- ${icon} **${finding.rule || finding.package || finding.secret_type}**\n`;
        report += `  - Severity: ${finding.severity?.toUpperCase()}\n`;
        report += `  - Type: ${finding.type}\n`;
        if (finding.file) report += `  - Location: \`${finding.file}:${finding.line}\`\n`;
        if (finding.cve) report += `  - CVE: ${finding.cve}\n`;
        report += '\n';
      });
    }
  });

  // Remediation priorities
  report += `## Remediation Priorities

### Immediate (Critical)
`;

  const critical = data.alerts.filter(a => a.severity === 'critical');
  if (critical.length > 0) {
    critical.forEach(a => {
      report += `1. **${a.rule || a.package}** - ${a.owasp}\n`;
    });
  } else {
    report += `No critical findings.\n`;
  }

  report += `
### This Sprint (High)
`;

  const high = data.alerts.filter(a => a.severity === 'high');
  if (high.length > 0) {
    high.forEach(a => {
      report += `1. **${a.rule || a.package}** - ${a.owasp}\n`;
    });
  } else {
    report += `No high-severity findings.\n`;
  }

  report += `
---

*Generated by GHAS Compliance Reporter for MS Press GitHub Copilot for Cybersecurity course*
`;

  return report;
}

/**
 * Generate JSON report
 */
function generateJSONReport(data, summary) {
  return JSON.stringify({
    report_type: 'OWASP Top 10 Compliance',
    generated_at: new Date().toISOString(),
    repository: data.repository,
    compliance_score: calculateScore(summary),
    summary: Object.entries(summary).map(([code, cat]) => ({
      category: code,
      name: cat.name,
      compliant: cat.critical === 0 && cat.high === 0,
      findings: {
        total: cat.total,
        critical: cat.critical,
        high: cat.high,
        medium: cat.medium,
        low: cat.low
      }
    })),
    remediation_priorities: {
      immediate: data.alerts.filter(a => a.severity === 'critical'),
      this_sprint: data.alerts.filter(a => a.severity === 'high'),
      next_sprint: data.alerts.filter(a => a.severity === 'medium')
    }
  }, null, 2);
}

/**
 * Main
 */
async function main() {
  const data = await readAlerts();
  const summary = generateComplianceSummary(data.alerts || []);

  if (format === 'json') {
    console.log(generateJSONReport(data, summary));
  } else {
    console.log(generateMarkdownReport(data, summary));
  }
}

main().catch(console.error);
