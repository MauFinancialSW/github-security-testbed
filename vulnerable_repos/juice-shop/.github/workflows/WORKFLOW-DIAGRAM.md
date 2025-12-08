# Security Workflows Architecture

## Workflow Trigger Matrix

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GitHub Events & Schedules                        │
└─────────────────────────────────────────────────────────────────────────┘
          │                    │                    │
          │                    │                    │
    Pull Request          Push (master)      Weekly Schedule
          │                    │                    │
          ▼                    ▼                    ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ security-scan    │  │ deploy-secure    │  │ weekly-          │
│ + custom-linting │  │                  │  │ compliance       │
└──────────────────┘  └──────────────────┘  └──────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
```

## Security Scan Workflow (security-scan.yml)

```
┌─────────────────────────────────────────────────────────────┐
│                    security-scan.yml                        │
│                 (PR, Weekly, Manual)                        │
└─────────────────────────────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┬─────────────────┐
           │               │               │                 │
           ▼               ▼               ▼                 ▼
    ┌──────────┐    ┌──────────┐   ┌──────────┐      ┌──────────┐
    │ CodeQL   │    │   npm    │   │  Secret  │      │ Generate │
    │  SAST    │    │  Audit   │   │ Scanning │      │  SARIF   │
    └──────────┘    └──────────┘   └──────────┘      └──────────┘
           │               │               │                 │
           └───────────────┴───────────────┴─────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Security Gate   │
                  │   Validation    │
                  └─────────────────┘
                           │
            ┌──────────────┴──────────────┐
            │                             │
            ▼                             ▼
       ✅ PASS                        ❌ FAIL
    (No action)                  (Block deployment)
```

## Deploy Secure Pipeline (deploy-secure.yml)

```
┌─────────────────────────────────────────────────────────────┐
│                   deploy-secure.yml                         │
│                  (Push to master)                           │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Stage 1: TEST  │
                  │  Coverage >= 85%│
                  └─────────────────┘
                           │
                ┌──────────┴──────────┐
                │                     │
                ▼                     ▼
         ┌────────────┐        ┌────────────┐
         │ Stage 2:   │        │ Stage 3:   │
         │    SAST    │        │ Dependency │
         │  (CodeQL)  │        │    Scan    │
         └────────────┘        └────────────┘
                │                     │
                └──────────┬──────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Stage 4:       │
                  │  Compliance     │
                  │     Check       │
                  └─────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Stage 5:       │
                  │ Security Gate   │
                  │   Decision      │
                  └─────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
  ┌──────────┐      ┌──────────┐      ┌──────────┐
  │ APPROVED │      │ REQUIRES │      │ BLOCKED  │
  │          │      │ APPROVAL │      │          │
  └──────────┘      └──────────┘      └──────────┘
        │                  │                  │
        ▼                  ▼                  ▼
  ┌──────────┐      ┌──────────┐      ┌──────────┐
  │ Deploy   │      │  Create  │      │  Create  │
  │ to Azure │      │  Issue   │      │  Issue   │
  └──────────┘      └──────────┘      └──────────┘
        │
        ▼
  ┌──────────┐
  │ Stage 6: │
  │ Deploy   │
  └──────────┘
        │
        ├─────► Staging Slot
        │
        ├─────► Smoke Tests
        │
        └─────► Swap to Production
```

## Custom Security Linting (custom-security-linting.yml)

```
┌─────────────────────────────────────────────────────────────┐
│              custom-security-linting.yml                    │
│                    (PR, Push)                               │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Create Custom   │
                  │ Semgrep Rules   │
                  └─────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   ┌─────────┐      ┌─────────┐       ┌─────────┐
   │   SQL   │      │Hardcoded│       │  Path   │
   │Injection│      │ Secrets │       │Traversal│
   └─────────┘      └─────────┘       └─────────┘
        │                  │                  │
        │           ┌──────┴──────┬───────────┘
        │           │             │
        ▼           ▼             ▼
   ┌─────────┐  ┌─────────┐  ┌─────────┐
   │  Weak   │  │   XSS   │  │ Semgrep │
   │ Crypto  │  │ in EJS  │  │  Scan   │
   └─────────┘  └─────────┘  └─────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
              ┌──────────┐   ┌──────────┐  ┌──────────┐
              │  Upload  │   │ Generate │  │   Post   │
              │  SARIF   │   │ Summary  │  │PR Comment│
              └──────────┘   └──────────┘  └──────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                    ▼                             ▼
            ✅ No ERRORs                    ❌ ERRORs Found
         (Build passes)                   (Build fails)
```

## Weekly Compliance Digest (weekly-compliance-digest.yml)

```
┌─────────────────────────────────────────────────────────────┐
│           weekly-compliance-digest.yml                      │
│              (Monday 9 AM UTC)                              │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ Fetch GHAS      │
                  │    Alerts       │
                  └─────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   ┌─────────┐      ┌─────────┐       ┌─────────┐
   │ CodeQL  │      │Dependabot│      │ Secret  │
   │ Alerts  │      │ Alerts  │       │Scanning │
   └─────────┘      └─────────┘       └─────────┘
        │                  │                  │
        └──────────────────┴──────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │   Parse and     │
                  │  Categorize     │
                  └─────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   ┌─────────┐      ┌─────────┐       ┌─────────┐
   │  Count  │      │  OWASP  │       │Generate │
   │   by    │      │Top 10   │       │ Report  │
   │Severity │      │ Mapping │       │  (MD)   │
   └─────────┘      └─────────┘       └─────────┘
                                             │
                    ┌────────────────────────┴────────────────────────┐
                    │                                                 │
                    ▼                                                 ▼
            Findings > 0                                      Findings = 0
                    │                                                 │
                    ▼                                                 ▼
          ┌──────────────────┐                              ┌──────────────────┐
          │ Create GitHub    │                              │ Post Success     │
          │ Issue with       │                              │ Summary          │
          │ Full Report      │                              │                  │
          └──────────────────┘                              └──────────────────┘
                    │
                    │
          Labels: security,
                 compliance,
                 weekly-digest
```

## Security Gate Decision Matrix

```
┌────────────────────────────────────────────────────────────────────┐
│                    Security Gate Decision Tree                    │
└────────────────────────────────────────────────────────────────────┘

                        Start Security Gate
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Tests Passed?         │
                    │ Coverage >= 85%?      │
                    └───────────────────────┘
                         │              │
                      YES│              │NO
                         │              ▼
                         │      ┌─────────────────┐
                         │      │ GATE: BLOCKED   │
                         │      │ Action: FAIL    │
                         │      └─────────────────┘
                         ▼
              ┌───────────────────────┐
              │ Critical/High CVEs?   │
              └───────────────────────┘
                    │              │
                  NO│              │YES
                    │              ▼
                    │      ┌─────────────────────┐
                    │      │ GATE: REQUIRES      │
                    │      │       APPROVAL      │
                    │      │ Action: CREATE      │
                    │      │         ISSUE       │
                    │      └─────────────────────┘
                    ▼
         ┌───────────────────────┐
         │ Critical/High SAST?   │
         └───────────────────────┘
               │              │
             NO│              │YES
               │              ▼
               │      ┌─────────────────────┐
               │      │ GATE: REQUIRES      │
               │      │       APPROVAL      │
               │      │ Action: CREATE      │
               │      │         ISSUE       │
               │      └─────────────────────┘
               ▼
      ┌─────────────────┐
      │ GATE: APPROVED  │
      │ Action: DEPLOY  │
      └─────────────────┘
```

## Integration Points

```
┌─────────────────────────────────────────────────────────────────┐
│                  GitHub Security Features                       │
└─────────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
    ┌──────────┐         ┌──────────┐        ┌──────────┐
    │ Security │         │  GitHub  │        │ Dependabot│
    │   Tab    │         │  Issues  │        │  Alerts  │
    └──────────┘         └──────────┘        └──────────┘
           ▲                    ▲                    ▲
           │                    │                    │
    ┌──────┴──────┐      ┌──────┴──────┐     ┌──────┴──────┐
    │ SARIF Upload│      │Issue Creation│    │ npm audit   │
    │ (CodeQL +   │      │ (auto on    │     │ API queries │
    │  Semgrep)   │      │  failures)  │     │             │
    └─────────────┘      └─────────────┘     └─────────────┘
           ▲                    ▲                    ▲
           │                    │                    │
    ┌──────┴────────────────────┴────────────────────┴──────┐
    │           Security Workflows (4 workflows)            │
    └───────────────────────────────────────────────────────┘
```

## Notification Flow

```
Security Event Detected
         │
         ▼
┌─────────────────┐
│ Workflow Runs   │
└─────────────────┘
         │
         ├────► Step Summary (always)
         │
         ├────► SARIF Upload → Security Tab
         │
         ├────► Artifacts Upload
         │
         └────► GitHub Issue (on failure)
                     │
                     └────► Labels: security, compliance
                             Assignees: security team
```

## File Artifacts Generated

```
Workflow: security-scan.yml
  └── Artifacts:
      ├── npm-audit-results/
      │   ├── npm-audit-backend.json
      │   └── npm-audit-frontend.json
      └── SARIF/
          └── codeql-results.sarif

Workflow: deploy-secure.yml
  └── Artifacts:
      ├── coverage-reports/
      │   ├── frontend-lcov.info
      │   └── server-lcov.info
      ├── dependency-audit/
      │   └── audit-results.json
      └── compliance-report/
          └── compliance-report.md

Workflow: custom-security-linting.yml
  └── Artifacts:
      └── SARIF/
          └── semgrep-results.sarif

Workflow: weekly-compliance-digest.yml
  └── Artifacts:
      ├── ghas-alerts/
      │   └── ghas-alerts.json
      └── compliance-report/
          └── compliance-report.md
```

---

**Legend:**
- ┌─┐ : Process/Job
- ──► : Data flow
- ✅  : Success path
- ❌  : Failure path
- │   : Sequential flow
- ├   : Parallel branches

**Generated with [Claude Code](https://claude.com/claude-code)**
