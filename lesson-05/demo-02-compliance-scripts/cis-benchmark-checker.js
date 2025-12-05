/**
 * CIS Benchmark Compliance Checker
 * ==================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 05 - Compliance, IR, Configuration Management
 *
 * Copilot Prompt Used:
 * "Create CIS benchmark compliance checker for AWS resources"
 *
 * Features:
 * - AWS CIS Benchmark 1.4 controls
 * - Automated compliance checking
 * - Remediation recommendations
 * - Compliance scoring
 */

const AWS = require('aws-sdk');

// =============================================================================
// CIS AWS Foundations Benchmark 1.4 Controls
// =============================================================================

const cisBenchmarks = {
  // Section 1: Identity and Access Management
  '1.1': {
    title: 'Avoid the use of the root account',
    section: 'IAM',
    severity: 'critical',
    check: async (credentials) => {
      const iam = new AWS.IAM(credentials);

      // Check root account last used
      const summary = await iam.getAccountSummary().promise();
      const rootMFAEnabled = summary.SummaryMap.AccountMFAEnabled === 1;

      // Get credential report
      await iam.generateCredentialReport().promise();
      await new Promise(resolve => setTimeout(resolve, 2000));
      const report = await iam.getCredentialReport().promise();

      const csvData = Buffer.from(report.Content, 'base64').toString('utf8');
      const lines = csvData.split('\n');
      const rootLine = lines.find(l => l.startsWith('<root_account>'));

      if (rootLine) {
        const fields = rootLine.split(',');
        const passwordLastUsed = fields[4];
        const accessKeyLastUsed = fields[10] !== 'N/A' ? new Date(fields[10]) : null;

        const recentUsage = accessKeyLastUsed &&
          (Date.now() - accessKeyLastUsed.getTime()) < 90 * 24 * 60 * 60 * 1000;

        return {
          compliant: !recentUsage,
          message: recentUsage ?
            'Root account access keys used within last 90 days' :
            'Root account not recently used',
          remediation: 'Remove root access keys and use IAM users'
        };
      }

      return { compliant: true, message: 'Unable to determine root usage' };
    }
  },

  '1.2': {
    title: 'Ensure MFA is enabled for the root account',
    section: 'IAM',
    severity: 'critical',
    check: async (credentials) => {
      const iam = new AWS.IAM(credentials);
      const summary = await iam.getAccountSummary().promise();

      const mfaEnabled = summary.SummaryMap.AccountMFAEnabled === 1;

      return {
        compliant: mfaEnabled,
        message: mfaEnabled ? 'Root MFA enabled' : 'Root MFA not enabled',
        remediation: 'Enable MFA for root account using hardware or virtual MFA device'
      };
    }
  },

  '1.4': {
    title: 'Ensure access keys are rotated every 90 days or less',
    section: 'IAM',
    severity: 'high',
    check: async (credentials) => {
      const iam = new AWS.IAM(credentials);
      const users = await iam.listUsers().promise();
      const staleKeys = [];

      for (const user of users.Users) {
        const keys = await iam.listAccessKeys({ UserName: user.UserName }).promise();

        for (const key of keys.AccessKeyMetadata) {
          const ageInDays = Math.floor(
            (Date.now() - new Date(key.CreateDate).getTime()) / (1000 * 60 * 60 * 24)
          );

          if (ageInDays > 90) {
            staleKeys.push({
              user: user.UserName,
              keyId: key.AccessKeyId,
              ageInDays
            });
          }
        }
      }

      return {
        compliant: staleKeys.length === 0,
        message: staleKeys.length === 0 ?
          'All access keys rotated within 90 days' :
          `${staleKeys.length} stale access keys found`,
        findings: staleKeys,
        remediation: 'Rotate access keys older than 90 days'
      };
    }
  },

  '1.5': {
    title: 'Ensure IAM password policy requires at least one uppercase letter',
    section: 'IAM',
    severity: 'medium',
    check: async (credentials) => {
      const iam = new AWS.IAM(credentials);

      try {
        const policy = await iam.getAccountPasswordPolicy().promise();

        const checks = {
          uppercase: policy.PasswordPolicy.RequireUppercaseCharacters,
          lowercase: policy.PasswordPolicy.RequireLowercaseCharacters,
          numbers: policy.PasswordPolicy.RequireNumbers,
          symbols: policy.PasswordPolicy.RequireSymbols,
          minLength: policy.PasswordPolicy.MinimumPasswordLength >= 14,
          expiration: policy.PasswordPolicy.MaxPasswordAge <= 90,
          reuse: policy.PasswordPolicy.PasswordReusePrevention >= 24
        };

        const allCompliant = Object.values(checks).every(v => v);

        return {
          compliant: allCompliant,
          message: allCompliant ? 'Password policy meets requirements' : 'Password policy needs updates',
          findings: checks,
          remediation: 'Update IAM password policy to meet CIS requirements'
        };
      } catch (error) {
        return {
          compliant: false,
          message: 'No password policy configured',
          remediation: 'Configure IAM password policy'
        };
      }
    }
  },

  // Section 2: Storage
  '2.1.1': {
    title: 'Ensure all S3 buckets employ encryption-at-rest',
    section: 'S3',
    severity: 'high',
    check: async (credentials) => {
      const s3 = new AWS.S3(credentials);
      const buckets = await s3.listBuckets().promise();
      const unencrypted = [];

      for (const bucket of buckets.Buckets) {
        try {
          await s3.getBucketEncryption({ Bucket: bucket.Name }).promise();
        } catch (error) {
          if (error.code === 'ServerSideEncryptionConfigurationNotFoundError') {
            unencrypted.push(bucket.Name);
          }
        }
      }

      return {
        compliant: unencrypted.length === 0,
        message: unencrypted.length === 0 ?
          'All S3 buckets have encryption enabled' :
          `${unencrypted.length} buckets without encryption`,
        findings: unencrypted,
        remediation: 'Enable default encryption on all S3 buckets'
      };
    }
  },

  '2.1.2': {
    title: 'Ensure S3 Bucket Policy is set to deny HTTP requests',
    section: 'S3',
    severity: 'medium',
    check: async (credentials) => {
      const s3 = new AWS.S3(credentials);
      const buckets = await s3.listBuckets().promise();
      const insecure = [];

      for (const bucket of buckets.Buckets) {
        try {
          const policy = await s3.getBucketPolicy({ Bucket: bucket.Name }).promise();
          const policyDoc = JSON.parse(policy.Policy);

          const hasSecureTransport = policyDoc.Statement.some(stmt =>
            stmt.Effect === 'Deny' &&
            stmt.Condition?.Bool?.['aws:SecureTransport'] === 'false'
          );

          if (!hasSecureTransport) {
            insecure.push(bucket.Name);
          }
        } catch (error) {
          if (error.code === 'NoSuchBucketPolicy') {
            insecure.push(bucket.Name);
          }
        }
      }

      return {
        compliant: insecure.length === 0,
        message: insecure.length === 0 ?
          'All buckets deny HTTP requests' :
          `${insecure.length} buckets allow HTTP`,
        findings: insecure,
        remediation: 'Add bucket policy to deny non-HTTPS requests'
      };
    }
  },

  // Section 3: Logging
  '3.1': {
    title: 'Ensure CloudTrail is enabled in all regions',
    section: 'Logging',
    severity: 'critical',
    check: async (credentials) => {
      const cloudtrail = new AWS.CloudTrail(credentials);
      const trails = await cloudtrail.describeTrails().promise();

      const multiRegionTrail = trails.trailList.find(t =>
        t.IsMultiRegionTrail && t.IsLogging
      );

      if (multiRegionTrail) {
        const status = await cloudtrail.getTrailStatus({
          Name: multiRegionTrail.Name
        }).promise();

        return {
          compliant: status.IsLogging,
          message: status.IsLogging ?
            'CloudTrail enabled in all regions' :
            'CloudTrail not logging',
          findings: { trailName: multiRegionTrail.Name },
          remediation: 'Enable multi-region CloudTrail with logging'
        };
      }

      return {
        compliant: false,
        message: 'No multi-region CloudTrail found',
        remediation: 'Create multi-region CloudTrail'
      };
    }
  },

  '3.3': {
    title: 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs',
    section: 'Logging',
    severity: 'high',
    check: async (credentials) => {
      const cloudtrail = new AWS.CloudTrail(credentials);
      const trails = await cloudtrail.describeTrails().promise();

      const unencrypted = trails.trailList.filter(t => !t.KMSKeyId);

      return {
        compliant: unencrypted.length === 0,
        message: unencrypted.length === 0 ?
          'All CloudTrail logs encrypted with KMS' :
          `${unencrypted.length} trails not using KMS encryption`,
        findings: unencrypted.map(t => t.Name),
        remediation: 'Enable KMS encryption for CloudTrail logs'
      };
    }
  },

  // Section 4: Monitoring
  '4.3': {
    title: 'Ensure a log metric filter and alarm exist for root account usage',
    section: 'Monitoring',
    severity: 'high',
    check: async (credentials) => {
      const logs = new AWS.CloudWatchLogs(credentials);
      const cloudwatch = new AWS.CloudWatch(credentials);

      // Get metric filters
      const filters = await logs.describeMetricFilters().promise();

      const rootLoginFilter = filters.metricFilters.find(f =>
        f.filterPattern.includes('Root') ||
        f.filterPattern.includes('root')
      );

      if (!rootLoginFilter) {
        return {
          compliant: false,
          message: 'No metric filter for root account usage',
          remediation: 'Create CloudWatch metric filter and alarm for root logins'
        };
      }

      // Check for alarm
      const alarms = await cloudwatch.describeAlarms({
        AlarmNamePrefix: rootLoginFilter.metricTransformations[0].metricName
      }).promise();

      return {
        compliant: alarms.MetricAlarms.length > 0,
        message: alarms.MetricAlarms.length > 0 ?
          'Root account usage alarm configured' :
          'Metric filter exists but no alarm',
        remediation: 'Create CloudWatch alarm for root account metric'
      };
    }
  },

  // Section 5: Networking
  '5.1': {
    title: 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote admin ports',
    section: 'Networking',
    severity: 'critical',
    check: async (credentials) => {
      const ec2 = new AWS.EC2(credentials);
      const nacls = await ec2.describeNetworkAcls().promise();
      const violations = [];

      const adminPorts = [22, 3389];

      for (const nacl of nacls.NetworkAcls) {
        for (const entry of nacl.Entries) {
          if (!entry.Egress && entry.RuleAction === 'allow') {
            const fromPort = entry.PortRange?.From;
            const toPort = entry.PortRange?.To;
            const cidr = entry.CidrBlock;

            if (cidr === '0.0.0.0/0' || cidr === '::/0') {
              for (const port of adminPorts) {
                if (fromPort <= port && toPort >= port) {
                  violations.push({
                    naclId: nacl.NetworkAclId,
                    port,
                    ruleNumber: entry.RuleNumber
                  });
                }
              }
            }
          }
        }
      }

      return {
        compliant: violations.length === 0,
        message: violations.length === 0 ?
          'No NACLs allow public admin access' :
          `${violations.length} NACL rules allow public admin access`,
        findings: violations,
        remediation: 'Remove NACL rules allowing 0.0.0.0/0 to ports 22 and 3389'
      };
    }
  },

  '5.3': {
    title: 'Ensure the default security group of every VPC restricts all traffic',
    section: 'Networking',
    severity: 'high',
    check: async (credentials) => {
      const ec2 = new AWS.EC2(credentials);
      const vpcs = await ec2.describeVpcs().promise();
      const violations = [];

      for (const vpc of vpcs.Vpcs) {
        const sgs = await ec2.describeSecurityGroups({
          Filters: [
            { Name: 'vpc-id', Values: [vpc.VpcId] },
            { Name: 'group-name', Values: ['default'] }
          ]
        }).promise();

        for (const sg of sgs.SecurityGroups) {
          if (sg.IpPermissions.length > 0 || sg.IpPermissionsEgress.length > 0) {
            violations.push({
              vpcId: vpc.VpcId,
              sgId: sg.GroupId,
              ingressRules: sg.IpPermissions.length,
              egressRules: sg.IpPermissionsEgress.length
            });
          }
        }
      }

      return {
        compliant: violations.length === 0,
        message: violations.length === 0 ?
          'All default security groups are empty' :
          `${violations.length} default SGs have rules`,
        findings: violations,
        remediation: 'Remove all rules from default security groups'
      };
    }
  }
};

// =============================================================================
// CIS Benchmark Checker Class
// =============================================================================

class CISBenchmarkChecker {
  constructor(credentials = {}) {
    this.credentials = credentials;
    this.results = [];
    this.startTime = null;
  }

  /**
   * Run all CIS benchmark checks
   */
  async runAllChecks() {
    console.log('=== CIS AWS Foundations Benchmark 1.4 Compliance Check ===\n');
    this.startTime = Date.now();

    for (const [controlId, control] of Object.entries(cisBenchmarks)) {
      console.log(`Checking ${controlId}: ${control.title}...`);

      try {
        const result = await control.check(this.credentials);
        this.results.push({
          controlId,
          title: control.title,
          section: control.section,
          severity: control.severity,
          ...result
        });

        const status = result.compliant ? '✓ PASS' : '✗ FAIL';
        console.log(`  ${status}: ${result.message}\n`);
      } catch (error) {
        this.results.push({
          controlId,
          title: control.title,
          section: control.section,
          severity: control.severity,
          compliant: false,
          message: `Error: ${error.message}`,
          error: true
        });
        console.log(`  ⚠ ERROR: ${error.message}\n`);
      }
    }

    return this.generateReport();
  }

  /**
   * Run specific section checks
   */
  async runSectionChecks(section) {
    const sectionControls = Object.entries(cisBenchmarks)
      .filter(([, control]) => control.section === section);

    for (const [controlId, control] of sectionControls) {
      const result = await control.check(this.credentials);
      this.results.push({
        controlId,
        title: control.title,
        section: control.section,
        severity: control.severity,
        ...result
      });
    }

    return this.generateReport();
  }

  /**
   * Generate compliance report
   */
  generateReport() {
    const passed = this.results.filter(r => r.compliant).length;
    const failed = this.results.filter(r => !r.compliant).length;
    const score = Math.round((passed / this.results.length) * 100);

    const bySeverity = {
      critical: this.results.filter(r => !r.compliant && r.severity === 'critical').length,
      high: this.results.filter(r => !r.compliant && r.severity === 'high').length,
      medium: this.results.filter(r => !r.compliant && r.severity === 'medium').length,
      low: this.results.filter(r => !r.compliant && r.severity === 'low').length
    };

    const bySection = {};
    for (const result of this.results) {
      if (!bySection[result.section]) {
        bySection[result.section] = { passed: 0, failed: 0 };
      }
      if (result.compliant) {
        bySection[result.section].passed++;
      } else {
        bySection[result.section].failed++;
      }
    }

    return {
      metadata: {
        framework: 'CIS AWS Foundations Benchmark 1.4',
        checkedAt: new Date().toISOString(),
        duration: `${(Date.now() - this.startTime) / 1000}s`,
        totalControls: this.results.length
      },
      summary: {
        passed,
        failed,
        score: `${score}%`,
        failedBySeverity: bySeverity,
        bySection
      },
      results: this.results,
      remediationPriority: this.results
        .filter(r => !r.compliant)
        .sort((a, b) => {
          const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
          return severityOrder[a.severity] - severityOrder[b.severity];
        })
    };
  }

  /**
   * Generate text report
   */
  generateTextReport(report) {
    const lines = [];
    lines.push('='.repeat(60));
    lines.push('CIS AWS Foundations Benchmark 1.4 Compliance Report');
    lines.push('='.repeat(60));
    lines.push(`Checked: ${report.metadata.checkedAt}`);
    lines.push(`Duration: ${report.metadata.duration}`);
    lines.push('');
    lines.push(`Score: ${report.summary.score}`);
    lines.push(`Passed: ${report.summary.passed} | Failed: ${report.summary.failed}`);
    lines.push('');
    lines.push('Failed by Severity:');
    lines.push(`  Critical: ${report.summary.failedBySeverity.critical}`);
    lines.push(`  High:     ${report.summary.failedBySeverity.high}`);
    lines.push(`  Medium:   ${report.summary.failedBySeverity.medium}`);
    lines.push(`  Low:      ${report.summary.failedBySeverity.low}`);
    lines.push('');
    lines.push('Remediation Priority:');

    for (const result of report.remediationPriority.slice(0, 10)) {
      lines.push(`  [${result.severity.toUpperCase()}] ${result.controlId}: ${result.title}`);
      if (result.remediation) {
        lines.push(`    → ${result.remediation}`);
      }
    }

    lines.push('');
    lines.push('='.repeat(60));

    return lines.join('\n');
  }
}

// =============================================================================
// Export
// =============================================================================

module.exports = {
  CISBenchmarkChecker,
  cisBenchmarks
};

// =============================================================================
// CLI
// =============================================================================

if (require.main === module) {
  const checker = new CISBenchmarkChecker();

  checker.runAllChecks()
    .then(report => {
      console.log('\n' + checker.generateTextReport(report));
    })
    .catch(error => {
      console.error('Error running checks:', error.message);
      process.exit(1);
    });
}
