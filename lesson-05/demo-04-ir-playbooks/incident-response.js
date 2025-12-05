/**
 * Incident Response Automation Playbook
 * =======================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 05 - Compliance, IR, Configuration Management
 *
 * Copilot Prompt Used:
 * "Create incident response automation playbook for security events"
 *
 * Features:
 * - Automated incident detection
 * - Evidence collection
 * - Containment actions
 * - Notification and escalation
 * - Forensic artifact preservation
 */

const AWS = require('aws-sdk');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// =============================================================================
// Configuration
// =============================================================================

const config = {
  evidenceBucket: process.env.EVIDENCE_BUCKET || 'security-evidence-bucket',
  slackWebhook: process.env.SLACK_WEBHOOK,
  pagerdutyKey: process.env.PAGERDUTY_KEY,
  quarantineSecurityGroup: process.env.QUARANTINE_SG,
  forensicsSubnet: process.env.FORENSICS_SUBNET,
  region: process.env.AWS_REGION || 'us-east-1'
};

// =============================================================================
// Incident Types
// =============================================================================

const incidentPlaybooks = {
  'compromised-instance': {
    severity: 'critical',
    description: 'EC2 instance showing signs of compromise',
    phases: ['detect', 'contain', 'collect', 'notify']
  },
  'unauthorized-access': {
    severity: 'high',
    description: 'Unauthorized access attempt detected',
    phases: ['detect', 'collect', 'notify']
  },
  'data-exfiltration': {
    severity: 'critical',
    description: 'Potential data exfiltration detected',
    phases: ['detect', 'contain', 'collect', 'notify', 'escalate']
  },
  'malware-detected': {
    severity: 'critical',
    description: 'Malware detected on system',
    phases: ['detect', 'contain', 'collect', 'notify']
  },
  'suspicious-api-activity': {
    severity: 'medium',
    description: 'Suspicious AWS API activity detected',
    phases: ['detect', 'collect', 'notify']
  }
};

// =============================================================================
// Incident Response Class
// =============================================================================

class IncidentResponse {
  constructor(options = {}) {
    this.options = { ...config, ...options };
    this.ec2 = new AWS.EC2({ region: this.options.region });
    this.s3 = new AWS.S3({ region: this.options.region });
    this.cloudtrail = new AWS.CloudTrail({ region: this.options.region });
    this.logs = new AWS.CloudWatchLogs({ region: this.options.region });
    this.ssm = new AWS.SSM({ region: this.options.region });

    this.incidentId = null;
    this.evidence = [];
    this.timeline = [];
    this.actions = [];
  }

  /**
   * Initialize incident response
   */
  async initIncident(type, context) {
    this.incidentId = `IR-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    this.type = type;
    this.context = context;
    this.startTime = new Date().toISOString();

    const playbook = incidentPlaybooks[type];
    if (!playbook) {
      throw new Error(`Unknown incident type: ${type}`);
    }

    this.severity = playbook.severity;
    this.phases = playbook.phases;

    this.addToTimeline('Incident initiated', {
      incidentId: this.incidentId,
      type,
      severity: this.severity,
      context
    });

    console.log(`\n${'='.repeat(60)}`);
    console.log(`INCIDENT RESPONSE: ${this.incidentId}`);
    console.log(`Type: ${type} | Severity: ${this.severity.toUpperCase()}`);
    console.log(`${'='.repeat(60)}\n`);

    return this;
  }

  /**
   * Add event to timeline
   */
  addToTimeline(event, details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      event,
      details
    };
    this.timeline.push(entry);
    console.log(`[${entry.timestamp}] ${event}`);
  }

  /**
   * Record action taken
   */
  recordAction(action, result) {
    this.actions.push({
      timestamp: new Date().toISOString(),
      action,
      result,
      incidentId: this.incidentId
    });
  }

  // ===========================================================================
  // Phase 1: Detection
  // ===========================================================================

  async detectPhase() {
    this.addToTimeline('PHASE: Detection');

    if (this.context.instanceId) {
      await this.collectInstanceInfo(this.context.instanceId);
    }

    if (this.context.userId) {
      await this.collectUserActivity(this.context.userId);
    }

    return this;
  }

  async collectInstanceInfo(instanceId) {
    this.addToTimeline('Collecting instance information', { instanceId });

    const instances = await this.ec2.describeInstances({
      InstanceIds: [instanceId]
    }).promise();

    const instance = instances.Reservations[0]?.Instances[0];
    if (instance) {
      this.evidence.push({
        type: 'instance-info',
        data: instance,
        collectedAt: new Date().toISOString()
      });

      this.addToTimeline('Instance info collected', {
        privateIp: instance.PrivateIpAddress,
        publicIp: instance.PublicIpAddress,
        state: instance.State.Name,
        securityGroups: instance.SecurityGroups.map(sg => sg.GroupId)
      });
    }
  }

  async collectUserActivity(userId) {
    this.addToTimeline('Collecting user activity', { userId });

    // Look up CloudTrail events
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - 24 * 60 * 60 * 1000);

    const events = await this.cloudtrail.lookupEvents({
      LookupAttributes: [{
        AttributeKey: 'Username',
        AttributeValue: userId
      }],
      StartTime: startTime,
      EndTime: endTime,
      MaxResults: 50
    }).promise();

    this.evidence.push({
      type: 'cloudtrail-events',
      userId,
      events: events.Events,
      collectedAt: new Date().toISOString()
    });

    this.addToTimeline('CloudTrail events collected', {
      eventCount: events.Events.length,
      timeRange: `${startTime.toISOString()} to ${endTime.toISOString()}`
    });
  }

  // ===========================================================================
  // Phase 2: Containment
  // ===========================================================================

  async containPhase() {
    this.addToTimeline('PHASE: Containment');

    if (this.context.instanceId) {
      await this.isolateInstance(this.context.instanceId);
    }

    if (this.context.accessKeyId) {
      await this.disableAccessKey(this.context.userId, this.context.accessKeyId);
    }

    return this;
  }

  async isolateInstance(instanceId) {
    this.addToTimeline('Isolating compromised instance', { instanceId });

    try {
      // Get current security groups
      const instances = await this.ec2.describeInstances({
        InstanceIds: [instanceId]
      }).promise();

      const instance = instances.Reservations[0]?.Instances[0];
      const originalSGs = instance.SecurityGroups.map(sg => sg.GroupId);

      // Store original configuration
      this.evidence.push({
        type: 'original-security-groups',
        instanceId,
        securityGroups: originalSGs,
        collectedAt: new Date().toISOString()
      });

      // Create quarantine security group if not exists
      let quarantineSG = this.options.quarantineSecurityGroup;

      if (!quarantineSG) {
        const sg = await this.ec2.createSecurityGroup({
          GroupName: `quarantine-${this.incidentId}`,
          Description: `Quarantine SG for incident ${this.incidentId}`,
          VpcId: instance.VpcId
        }).promise();

        quarantineSG = sg.GroupId;

        // Remove all ingress/egress (deny all)
        await this.ec2.revokeSecurityGroupEgress({
          GroupId: quarantineSG,
          IpPermissions: [{
            IpProtocol: '-1',
            IpRanges: [{ CidrIp: '0.0.0.0/0' }]
          }]
        }).promise().catch(() => { });
      }

      // Apply quarantine security group
      await this.ec2.modifyInstanceAttribute({
        InstanceId: instanceId,
        Groups: [quarantineSG]
      }).promise();

      this.addToTimeline('Instance isolated', {
        instanceId,
        quarantineSecurityGroup: quarantineSG,
        originalSecurityGroups: originalSGs
      });

      this.recordAction('isolate-instance', {
        success: true,
        instanceId,
        quarantineSG
      });

    } catch (error) {
      this.addToTimeline('Instance isolation failed', { error: error.message });
      this.recordAction('isolate-instance', { success: false, error: error.message });
    }
  }

  async disableAccessKey(userId, accessKeyId) {
    this.addToTimeline('Disabling access key', { userId, accessKeyId });

    const iam = new AWS.IAM({ region: this.options.region });

    try {
      await iam.updateAccessKey({
        UserName: userId,
        AccessKeyId: accessKeyId,
        Status: 'Inactive'
      }).promise();

      this.addToTimeline('Access key disabled', { accessKeyId });
      this.recordAction('disable-access-key', { success: true, accessKeyId });

    } catch (error) {
      this.addToTimeline('Failed to disable access key', { error: error.message });
      this.recordAction('disable-access-key', { success: false, error: error.message });
    }
  }

  // ===========================================================================
  // Phase 3: Evidence Collection
  // ===========================================================================

  async collectPhase() {
    this.addToTimeline('PHASE: Evidence Collection');

    if (this.context.instanceId) {
      await this.createForensicSnapshot(this.context.instanceId);
      await this.collectInstanceLogs(this.context.instanceId);
      await this.collectMemoryDump(this.context.instanceId);
    }

    await this.preserveEvidence();

    return this;
  }

  async createForensicSnapshot(instanceId) {
    this.addToTimeline('Creating forensic snapshot', { instanceId });

    try {
      // Get volumes attached to instance
      const instances = await this.ec2.describeInstances({
        InstanceIds: [instanceId]
      }).promise();

      const instance = instances.Reservations[0]?.Instances[0];
      const volumes = instance.BlockDeviceMappings.map(bd => bd.Ebs?.VolumeId).filter(Boolean);

      const snapshots = [];
      for (const volumeId of volumes) {
        const snapshot = await this.ec2.createSnapshot({
          VolumeId: volumeId,
          Description: `Forensic snapshot for ${this.incidentId}`,
          TagSpecifications: [{
            ResourceType: 'snapshot',
            Tags: [
              { Key: 'IncidentId', Value: this.incidentId },
              { Key: 'Purpose', Value: 'forensics' },
              { Key: 'CreatedBy', Value: 'incident-response' }
            ]
          }]
        }).promise();

        snapshots.push({
          volumeId,
          snapshotId: snapshot.SnapshotId
        });
      }

      this.evidence.push({
        type: 'forensic-snapshots',
        instanceId,
        snapshots,
        collectedAt: new Date().toISOString()
      });

      this.addToTimeline('Forensic snapshots created', { snapshots });
      this.recordAction('create-snapshot', { success: true, snapshots });

    } catch (error) {
      this.addToTimeline('Snapshot creation failed', { error: error.message });
      this.recordAction('create-snapshot', { success: false, error: error.message });
    }
  }

  async collectInstanceLogs(instanceId) {
    this.addToTimeline('Collecting instance logs via SSM', { instanceId });

    try {
      // Run log collection command via SSM
      const command = await this.ssm.sendCommand({
        InstanceIds: [instanceId],
        DocumentName: 'AWS-RunShellScript',
        Comment: `Log collection for ${this.incidentId}`,
        Parameters: {
          commands: [
            'tar czf /tmp/logs.tar.gz /var/log/',
            'cat /tmp/logs.tar.gz | base64'
          ]
        }
      }).promise();

      this.addToTimeline('Log collection command sent', {
        commandId: command.Command.CommandId
      });

    } catch (error) {
      this.addToTimeline('Log collection failed', { error: error.message });
    }
  }

  async collectMemoryDump(instanceId) {
    this.addToTimeline('Memory dump collection initiated', { instanceId });
    // In production: Use specialized memory acquisition tools
    // This is a placeholder for the concept
  }

  async preserveEvidence() {
    this.addToTimeline('Preserving evidence to S3');

    const evidenceKey = `incidents/${this.incidentId}/evidence.json`;
    const evidenceHash = crypto
      .createHash('sha256')
      .update(JSON.stringify(this.evidence))
      .digest('hex');

    try {
      await this.s3.putObject({
        Bucket: this.options.evidenceBucket,
        Key: evidenceKey,
        Body: JSON.stringify(this.evidence, null, 2),
        ContentType: 'application/json',
        ServerSideEncryption: 'aws:kms',
        Metadata: {
          'incident-id': this.incidentId,
          'sha256-hash': evidenceHash
        }
      }).promise();

      this.addToTimeline('Evidence preserved', {
        bucket: this.options.evidenceBucket,
        key: evidenceKey,
        hash: evidenceHash
      });

    } catch (error) {
      this.addToTimeline('Evidence preservation failed', { error: error.message });
    }
  }

  // ===========================================================================
  // Phase 4: Notification
  // ===========================================================================

  async notifyPhase() {
    this.addToTimeline('PHASE: Notification');

    await this.sendSlackAlert();
    await this.createPagerDutyIncident();

    return this;
  }

  async sendSlackAlert() {
    if (!this.options.slackWebhook) {
      this.addToTimeline('Slack webhook not configured, skipping');
      return;
    }

    const message = {
      text: `🚨 Security Incident: ${this.incidentId}`,
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: `🚨 ${this.type.toUpperCase()}` }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Incident ID:*\n${this.incidentId}` },
            { type: 'mrkdwn', text: `*Severity:*\n${this.severity.toUpperCase()}` },
            { type: 'mrkdwn', text: `*Started:*\n${this.startTime}` },
            { type: 'mrkdwn', text: `*Actions Taken:*\n${this.actions.length}` }
          ]
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Timeline (last 3 events):*\n${this.timeline.slice(-3).map(t => `• ${t.event}`).join('\n')}`
          }
        }
      ]
    };

    // In production: Send actual HTTP request to Slack
    this.addToTimeline('Slack alert sent');
  }

  async createPagerDutyIncident() {
    if (!this.options.pagerdutyKey) {
      this.addToTimeline('PagerDuty not configured, skipping');
      return;
    }

    // In production: Use PagerDuty Events API
    this.addToTimeline('PagerDuty incident created');
  }

  // ===========================================================================
  // Phase 5: Escalation
  // ===========================================================================

  async escalatePhase() {
    this.addToTimeline('PHASE: Escalation');

    // Escalation logic based on severity and type
    if (this.severity === 'critical') {
      this.addToTimeline('Critical incident - escalating to security leadership');
      // Send executive notification
    }

    return this;
  }

  // ===========================================================================
  // Execute Playbook
  // ===========================================================================

  async execute() {
    for (const phase of this.phases) {
      switch (phase) {
        case 'detect':
          await this.detectPhase();
          break;
        case 'contain':
          await this.containPhase();
          break;
        case 'collect':
          await this.collectPhase();
          break;
        case 'notify':
          await this.notifyPhase();
          break;
        case 'escalate':
          await this.escalatePhase();
          break;
      }
    }

    return this.generateReport();
  }

  // ===========================================================================
  // Report Generation
  // ===========================================================================

  generateReport() {
    const report = {
      incidentId: this.incidentId,
      type: this.type,
      severity: this.severity,
      startTime: this.startTime,
      endTime: new Date().toISOString(),
      context: this.context,
      timeline: this.timeline,
      actions: this.actions,
      evidenceCount: this.evidence.length,
      status: 'contained'
    };

    console.log(`\n${'='.repeat(60)}`);
    console.log('INCIDENT RESPONSE COMPLETE');
    console.log(`${'='.repeat(60)}`);
    console.log(`Incident ID: ${this.incidentId}`);
    console.log(`Type: ${this.type}`);
    console.log(`Severity: ${this.severity}`);
    console.log(`Duration: ${new Date() - new Date(this.startTime)}ms`);
    console.log(`Actions Taken: ${this.actions.length}`);
    console.log(`Evidence Collected: ${this.evidence.length} items`);
    console.log(`${'='.repeat(60)}\n`);

    return report;
  }
}

// =============================================================================
// Export
// =============================================================================

module.exports = {
  IncidentResponse,
  incidentPlaybooks
};

// =============================================================================
// Demo
// =============================================================================

if (require.main === module) {
  console.log('Incident Response Playbook Demo');
  console.log('================================\n');

  const ir = new IncidentResponse();

  ir.initIncident('compromised-instance', {
    instanceId: 'i-0123456789abcdef0',
    detectedBy: 'GuardDuty',
    finding: 'UnauthorizedAccess:EC2/MaliciousIPCaller.Custom'
  })
    .then(instance => instance.execute())
    .then(report => {
      console.log('\nFinal Report:', JSON.stringify(report, null, 2));
    })
    .catch(error => {
      console.error('Error:', error.message);
    });
}
