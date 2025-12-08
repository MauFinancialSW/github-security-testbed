#!/usr/bin/env node
/**
 * Fetch GitHub Advanced Security (GHAS) Alerts
 *
 * Used in Lesson 04 demos for compliance reporting and vulnerability analysis.
 *
 * Usage:
 *   GITHUB_TOKEN=xxx node fetch-ghas-alerts.js
 *   node fetch-ghas-alerts.js --output json > alerts.json
 *   node fetch-ghas-alerts.js --severity critical,high
 */

const https = require('https');

// Configuration
const config = {
  token: process.env.GITHUB_TOKEN,
  owner: process.env.GITHUB_OWNER || 'YOUR_ORG',
  repo: process.env.GITHUB_REPO || 'juice-shop',
  severity: process.argv.includes('--severity')
    ? process.argv[process.argv.indexOf('--severity') + 1]?.split(',')
    : ['critical', 'high', 'medium', 'low'],
  outputFormat: process.argv.includes('--output')
    ? process.argv[process.argv.indexOf('--output') + 1]
    : 'table'
};

if (!config.token) {
  console.error('Error: GITHUB_TOKEN environment variable required');
  console.error('Usage: GITHUB_TOKEN=ghp_xxx node fetch-ghas-alerts.js');
  process.exit(1);
}

/**
 * Make GitHub API request
 */
function githubApi(path) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.github.com',
      path: path,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${config.token}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'GHAS-Alert-Fetcher',
        'X-GitHub-Api-Version': '2022-11-28'
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          reject(new Error(`API Error ${res.statusCode}: ${data}`));
        } else {
          resolve(JSON.parse(data));
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
}

/**
 * Fetch CodeQL SAST alerts
 */
async function fetchCodeQLAlerts() {
  try {
    const alerts = await githubApi(
      `/repos/${config.owner}/${config.repo}/code-scanning/alerts?state=open`
    );

    return alerts.map(alert => ({
      type: 'CodeQL',
      number: alert.number,
      rule: alert.rule.id,
      severity: alert.rule.security_severity_level || alert.rule.severity,
      description: alert.rule.description,
      file: alert.most_recent_instance?.location?.path,
      line: alert.most_recent_instance?.location?.start_line,
      state: alert.state,
      created: alert.created_at,
      url: alert.html_url
    }));
  } catch (error) {
    console.error('CodeQL fetch error:', error.message);
    return [];
  }
}

/**
 * Fetch Dependabot alerts
 */
async function fetchDependabotAlerts() {
  try {
    const alerts = await githubApi(
      `/repos/${config.owner}/${config.repo}/dependabot/alerts?state=open`
    );

    return alerts.map(alert => ({
      type: 'Dependabot',
      number: alert.number,
      package: alert.security_advisory?.package?.name || alert.dependency?.package?.name,
      severity: alert.security_advisory?.severity,
      cve: alert.security_advisory?.cve_id,
      cvss: alert.security_advisory?.cvss?.score,
      description: alert.security_advisory?.summary,
      vulnerable_version: alert.security_vulnerability?.vulnerable_version_range,
      patched_version: alert.security_vulnerability?.first_patched_version?.identifier,
      state: alert.state,
      created: alert.created_at,
      url: alert.html_url
    }));
  } catch (error) {
    console.error('Dependabot fetch error:', error.message);
    return [];
  }
}

/**
 * Fetch secret scanning alerts
 */
async function fetchSecretAlerts() {
  try {
    const alerts = await githubApi(
      `/repos/${config.owner}/${config.repo}/secret-scanning/alerts?state=open`
    );

    return alerts.map(alert => ({
      type: 'Secret',
      number: alert.number,
      secret_type: alert.secret_type_display_name,
      severity: 'critical',
      state: alert.state,
      created: alert.created_at,
      url: alert.html_url
    }));
  } catch (error) {
    console.error('Secret scanning fetch error:', error.message);
    return [];
  }
}

/**
 * Map to OWASP Top 10 category
 */
function mapToOWASP(alert) {
  const mappings = {
    'sql-injection': 'A03:2021 Injection',
    'xss': 'A03:2021 Injection',
    'command-injection': 'A03:2021 Injection',
    'path-traversal': 'A01:2021 Broken Access Control',
    'idor': 'A01:2021 Broken Access Control',
    'auth': 'A07:2021 Auth Failures',
    'crypto': 'A02:2021 Crypto Failures',
    'deserialization': 'A08:2021 Software Integrity',
    'ssrf': 'A10:2021 SSRF',
    'xxe': 'A05:2021 Security Misconfiguration'
  };

  const ruleLower = (alert.rule || alert.package || '').toLowerCase();
  for (const [key, value] of Object.entries(mappings)) {
    if (ruleLower.includes(key)) return value;
  }

  if (alert.type === 'Dependabot') return 'A06:2021 Vulnerable Components';
  if (alert.type === 'Secret') return 'A07:2021 Auth Failures';

  return 'Unmapped';
}

/**
 * Output results
 */
function outputResults(alerts) {
  // Filter by severity
  const filtered = alerts.filter(a =>
    config.severity.includes(a.severity?.toLowerCase())
  );

  // Add OWASP mapping
  filtered.forEach(a => a.owasp = mapToOWASP(a));

  if (config.outputFormat === 'json') {
    console.log(JSON.stringify({
      scan_date: new Date().toISOString(),
      repository: `${config.owner}/${config.repo}`,
      summary: {
        total: filtered.length,
        critical: filtered.filter(a => a.severity === 'critical').length,
        high: filtered.filter(a => a.severity === 'high').length,
        medium: filtered.filter(a => a.severity === 'medium').length,
        low: filtered.filter(a => a.severity === 'low').length,
        by_type: {
          codeql: filtered.filter(a => a.type === 'CodeQL').length,
          dependabot: filtered.filter(a => a.type === 'Dependabot').length,
          secrets: filtered.filter(a => a.type === 'Secret').length
        }
      },
      alerts: filtered
    }, null, 2));
  } else {
    // Table format
    console.log('\n=== GHAS Security Alerts ===\n');
    console.log(`Repository: ${config.owner}/${config.repo}`);
    console.log(`Scan Date: ${new Date().toISOString()}\n`);

    console.log('SUMMARY:');
    console.log(`  Total: ${filtered.length}`);
    console.log(`  Critical: ${filtered.filter(a => a.severity === 'critical').length}`);
    console.log(`  High: ${filtered.filter(a => a.severity === 'high').length}`);
    console.log(`  Medium: ${filtered.filter(a => a.severity === 'medium').length}`);
    console.log(`  Low: ${filtered.filter(a => a.severity === 'low').length}\n`);

    console.log('ALERTS:');
    filtered.forEach(alert => {
      const icon = alert.severity === 'critical' ? '🔴' :
                   alert.severity === 'high' ? '🟠' :
                   alert.severity === 'medium' ? '🟡' : '🟢';
      console.log(`  ${icon} [${alert.type}] ${alert.rule || alert.package || alert.secret_type}`);
      console.log(`     Severity: ${alert.severity?.toUpperCase()}`);
      console.log(`     OWASP: ${alert.owasp}`);
      if (alert.file) console.log(`     File: ${alert.file}:${alert.line}`);
      if (alert.cve) console.log(`     CVE: ${alert.cve} (CVSS: ${alert.cvss})`);
      console.log(`     URL: ${alert.url}\n`);
    });
  }
}

/**
 * Main
 */
async function main() {
  console.error(`Fetching GHAS alerts for ${config.owner}/${config.repo}...\n`);

  const [codeql, dependabot, secrets] = await Promise.all([
    fetchCodeQLAlerts(),
    fetchDependabotAlerts(),
    fetchSecretAlerts()
  ]);

  const allAlerts = [...codeql, ...dependabot, ...secrets];
  outputResults(allAlerts);
}

main().catch(console.error);
