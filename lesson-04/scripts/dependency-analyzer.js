/**
 * Dependency Security Analyzer
 * =============================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 04 - Security Code Review, Threat Modeling, Auditing
 *
 * Copilot Prompt Used:
 * "Create dependency analyzer that checks for security vulnerabilities"
 *
 * Features:
 * - Parses package.json and package-lock.json
 * - Checks against known vulnerabilities
 * - Identifies outdated packages
 * - Generates dependency tree
 * - License compliance checking
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

// =============================================================================
// Vulnerability Database (Sample - use npm audit API in production)
// =============================================================================

const knownVulnerabilities = {
  'lodash': {
    '<4.17.21': {
      severity: 'critical',
      cve: 'CVE-2021-23337',
      title: 'Command Injection',
      description: 'Prototype pollution vulnerability in lodash',
      fix: 'Upgrade to 4.17.21 or later'
    }
  },
  'axios': {
    '<0.21.1': {
      severity: 'high',
      cve: 'CVE-2021-3749',
      title: 'Server-Side Request Forgery',
      description: 'SSRF vulnerability in axios',
      fix: 'Upgrade to 0.21.1 or later'
    }
  },
  'minimist': {
    '<1.2.6': {
      severity: 'critical',
      cve: 'CVE-2021-44906',
      title: 'Prototype Pollution',
      description: 'Prototype pollution in minimist',
      fix: 'Upgrade to 1.2.6 or later'
    }
  },
  'express': {
    '<4.17.3': {
      severity: 'medium',
      cve: 'CVE-2022-24999',
      title: 'Open Redirect',
      description: 'qs prototype pollution',
      fix: 'Upgrade to 4.17.3 or later'
    }
  },
  'jsonwebtoken': {
    '<9.0.0': {
      severity: 'high',
      cve: 'CVE-2022-23529',
      title: 'Insecure Defaults',
      description: 'Allows algorithm switching attacks',
      fix: 'Upgrade to 9.0.0 or later'
    }
  }
};

// Problematic licenses for commercial use
const problematicLicenses = [
  'GPL-2.0',
  'GPL-3.0',
  'AGPL-3.0',
  'LGPL-2.1',
  'LGPL-3.0',
  'SSPL-1.0'
];

// =============================================================================
// Version Comparison
// =============================================================================

/**
 * Parse semver version string
 */
function parseVersion(version) {
  const clean = version.replace(/^[^0-9]*/, '');
  const parts = clean.split('.').map(p => parseInt(p) || 0);
  return {
    major: parts[0] || 0,
    minor: parts[1] || 0,
    patch: parts[2] || 0
  };
}

/**
 * Compare two versions
 * @returns -1 if a < b, 0 if equal, 1 if a > b
 */
function compareVersions(a, b) {
  const va = parseVersion(a);
  const vb = parseVersion(b);

  if (va.major !== vb.major) return va.major < vb.major ? -1 : 1;
  if (va.minor !== vb.minor) return va.minor < vb.minor ? -1 : 1;
  if (va.patch !== vb.patch) return va.patch < vb.patch ? -1 : 1;
  return 0;
}

/**
 * Check if version matches constraint
 */
function matchesConstraint(version, constraint) {
  const v = parseVersion(version);

  if (constraint.startsWith('<')) {
    const target = parseVersion(constraint.substring(1));
    return compareVersions(version, constraint.substring(1)) < 0;
  }

  if (constraint.startsWith('>=')) {
    return compareVersions(version, constraint.substring(2)) >= 0;
  }

  if (constraint.startsWith('<=')) {
    return compareVersions(version, constraint.substring(2)) <= 0;
  }

  if (constraint.startsWith('>')) {
    return compareVersions(version, constraint.substring(1)) > 0;
  }

  return version === constraint;
}

// =============================================================================
// Dependency Analyzer Class
// =============================================================================

class DependencyAnalyzer {
  constructor(projectPath) {
    this.projectPath = projectPath;
    this.packageJson = null;
    this.lockFile = null;
    this.dependencies = new Map();
    this.vulnerabilities = [];
    this.licenseIssues = [];
    this.outdated = [];
  }

  /**
   * Load package.json and lock file
   */
  load() {
    // Load package.json
    const packagePath = path.join(this.projectPath, 'package.json');
    if (!fs.existsSync(packagePath)) {
      throw new Error('package.json not found');
    }
    this.packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));

    // Try to load lock file
    const npmLockPath = path.join(this.projectPath, 'package-lock.json');
    const yarnLockPath = path.join(this.projectPath, 'yarn.lock');

    if (fs.existsSync(npmLockPath)) {
      this.lockFile = JSON.parse(fs.readFileSync(npmLockPath, 'utf8'));
      this.lockType = 'npm';
    } else if (fs.existsSync(yarnLockPath)) {
      // Parse yarn.lock (simplified)
      this.lockFile = fs.readFileSync(yarnLockPath, 'utf8');
      this.lockType = 'yarn';
    }

    return this;
  }

  /**
   * Build dependency tree
   */
  buildDependencyTree() {
    const allDeps = {
      ...this.packageJson.dependencies,
      ...this.packageJson.devDependencies
    };

    for (const [name, version] of Object.entries(allDeps)) {
      this.dependencies.set(name, {
        name,
        requestedVersion: version,
        resolvedVersion: this.getResolvedVersion(name),
        isDev: !!this.packageJson.devDependencies?.[name],
        directDependency: true
      });
    }

    // Add transitive dependencies from lock file
    if (this.lockType === 'npm' && this.lockFile?.packages) {
      for (const [pkgPath, pkgInfo] of Object.entries(this.lockFile.packages)) {
        if (!pkgPath || pkgPath === '') continue;

        const name = pkgPath.replace('node_modules/', '').split('node_modules/').pop();
        if (!this.dependencies.has(name)) {
          this.dependencies.set(name, {
            name,
            requestedVersion: pkgInfo.version,
            resolvedVersion: pkgInfo.version,
            isDev: pkgInfo.dev || false,
            directDependency: false
          });
        }
      }
    }

    return this;
  }

  /**
   * Get resolved version from lock file
   */
  getResolvedVersion(name) {
    if (this.lockType === 'npm' && this.lockFile?.packages) {
      const pkg = this.lockFile.packages[`node_modules/${name}`];
      return pkg?.version || 'unknown';
    }
    return 'unknown';
  }

  /**
   * Check for known vulnerabilities
   */
  checkVulnerabilities() {
    for (const [name, dep] of this.dependencies) {
      const vulnDb = knownVulnerabilities[name];
      if (!vulnDb) continue;

      for (const [constraint, vuln] of Object.entries(vulnDb)) {
        if (matchesConstraint(dep.resolvedVersion, constraint)) {
          this.vulnerabilities.push({
            package: name,
            version: dep.resolvedVersion,
            ...vuln,
            isDev: dep.isDev,
            directDependency: dep.directDependency
          });
        }
      }
    }

    return this;
  }

  /**
   * Check for license issues
   */
  async checkLicenses() {
    // In production, fetch license info from npm registry
    // Here we simulate with common packages

    const licenseMap = {
      'react': 'MIT',
      'express': 'MIT',
      'lodash': 'MIT',
      'moment': 'MIT',
      'axios': 'MIT',
      'mysql': 'MIT',
      'pg': 'MIT'
    };

    for (const [name] of this.dependencies) {
      const license = licenseMap[name] || 'Unknown';

      if (problematicLicenses.includes(license)) {
        this.licenseIssues.push({
          package: name,
          license,
          issue: 'Copyleft license may have viral effect on your code'
        });
      }
    }

    return this;
  }

  /**
   * Check for outdated packages
   */
  async checkOutdated() {
    // In production, fetch latest versions from npm registry
    // Here we simulate with sample data

    const latestVersions = {
      'lodash': '4.17.21',
      'express': '4.18.2',
      'axios': '1.6.0',
      'react': '18.2.0'
    };

    for (const [name, dep] of this.dependencies) {
      const latest = latestVersions[name];
      if (!latest) continue;

      if (compareVersions(dep.resolvedVersion, latest) < 0) {
        const majorDiff = parseVersion(latest).major - parseVersion(dep.resolvedVersion).major;

        this.outdated.push({
          package: name,
          currentVersion: dep.resolvedVersion,
          latestVersion: latest,
          severity: majorDiff >= 2 ? 'high' : majorDiff >= 1 ? 'medium' : 'low'
        });
      }
    }

    return this;
  }

  /**
   * Run full analysis
   */
  async analyze() {
    this.load();
    this.buildDependencyTree();
    this.checkVulnerabilities();
    await this.checkLicenses();
    await this.checkOutdated();

    return this.generateReport();
  }

  /**
   * Generate analysis report
   */
  generateReport() {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };

    return {
      metadata: {
        projectName: this.packageJson.name,
        projectVersion: this.packageJson.version,
        analyzedAt: new Date().toISOString(),
        totalDependencies: this.dependencies.size,
        directDependencies: [...this.dependencies.values()].filter(d => d.directDependency).length,
        devDependencies: [...this.dependencies.values()].filter(d => d.isDev).length
      },
      summary: {
        vulnerabilities: {
          total: this.vulnerabilities.length,
          critical: this.vulnerabilities.filter(v => v.severity === 'critical').length,
          high: this.vulnerabilities.filter(v => v.severity === 'high').length,
          medium: this.vulnerabilities.filter(v => v.severity === 'medium').length,
          low: this.vulnerabilities.filter(v => v.severity === 'low').length
        },
        licenseIssues: this.licenseIssues.length,
        outdatedPackages: this.outdated.length
      },
      vulnerabilities: this.vulnerabilities
        .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]),
      licenseIssues: this.licenseIssues,
      outdatedPackages: this.outdated
        .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]),
      dependencies: Object.fromEntries(this.dependencies)
    };
  }

  /**
   * Generate text report
   */
  generateTextReport(report) {
    const lines = [];
    lines.push('='.repeat(60));
    lines.push('Dependency Security Analysis Report');
    lines.push('='.repeat(60));
    lines.push(`Project: ${report.metadata.projectName}@${report.metadata.projectVersion}`);
    lines.push(`Analyzed: ${report.metadata.analyzedAt}`);
    lines.push(`Total dependencies: ${report.metadata.totalDependencies}`);
    lines.push('');

    // Vulnerabilities
    lines.push('VULNERABILITIES');
    lines.push('-'.repeat(40));
    lines.push(`Critical: ${report.summary.vulnerabilities.critical}`);
    lines.push(`High:     ${report.summary.vulnerabilities.high}`);
    lines.push(`Medium:   ${report.summary.vulnerabilities.medium}`);
    lines.push(`Low:      ${report.summary.vulnerabilities.low}`);
    lines.push('');

    if (report.vulnerabilities.length > 0) {
      for (const vuln of report.vulnerabilities) {
        const severity = vuln.severity.toUpperCase().padEnd(8);
        lines.push(`[${severity}] ${vuln.package}@${vuln.version}`);
        lines.push(`           ${vuln.title} (${vuln.cve})`);
        lines.push(`           Fix: ${vuln.fix}`);
        lines.push('');
      }
    } else {
      lines.push('No known vulnerabilities found.');
      lines.push('');
    }

    // License Issues
    lines.push('LICENSE ISSUES');
    lines.push('-'.repeat(40));
    if (report.licenseIssues.length > 0) {
      for (const issue of report.licenseIssues) {
        lines.push(`${issue.package}: ${issue.license}`);
        lines.push(`  ${issue.issue}`);
      }
    } else {
      lines.push('No license issues found.');
    }
    lines.push('');

    // Outdated
    lines.push('OUTDATED PACKAGES');
    lines.push('-'.repeat(40));
    if (report.outdated.length > 0) {
      for (const pkg of report.outdatedPackages) {
        lines.push(`${pkg.package}: ${pkg.currentVersion} → ${pkg.latestVersion}`);
      }
    } else {
      lines.push('All packages are up to date.');
    }
    lines.push('');

    lines.push('='.repeat(60));

    return lines.join('\n');
  }
}

// =============================================================================
// Export
// =============================================================================

module.exports = { DependencyAnalyzer };

// =============================================================================
// CLI
// =============================================================================

if (require.main === module) {
  const projectPath = process.argv[2] || '.';
  const outputFormat = process.argv.includes('--json') ? 'json' : 'text';

  console.log('Dependency Security Analyzer');
  console.log('Analyzing:', path.resolve(projectPath));
  console.log('');

  const analyzer = new DependencyAnalyzer(projectPath);

  analyzer.analyze()
    .then(report => {
      if (outputFormat === 'json') {
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log(analyzer.generateTextReport(report));
      }

      // Exit with error if critical vulnerabilities found
      if (report.summary.vulnerabilities.critical > 0) {
        process.exit(1);
      }
    })
    .catch(error => {
      console.error('Error:', error.message);
      process.exit(1);
    });
}
