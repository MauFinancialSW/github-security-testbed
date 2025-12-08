# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

This is OWASP Juice Shop - a deliberately insecure e-commerce web application for security training. This fork is the demo codebase for the **MS Press GitHub Copilot for Cybersecurity Professionals** course. Demo runbooks are in `/demos/`.

## Build & Run Commands

```bash
# Install all dependencies (backend + frontend)
npm install

# Development with auto-reload
npm run serve:dev

# Production build and run
npm run build:frontend && npm run build:server
npm start

# Linting
npm run lint          # Check ESLint + SCSS
npm run lint:fix      # Auto-fix issues
npm run lint:config   # Validate config schema
```

## Testing Commands

```bash
npm test              # Angular + server tests combined
npm run test:server   # Mocha server tests only
npm run test:api      # Frisby/Jest API tests
npm run cypress:open  # E2E interactive
npm run cypress:run   # E2E headless
```

## Architecture Overview

**Full-stack application:**
- **Backend:** Node.js/Express (TypeScript) with Sequelize ORM → SQLite
- **Frontend:** Angular 20+ (separate build in `/frontend/`)
- **Database:** SQLite at `data/juiceshop.sqlite`

**Key directories:**
- `/routes/` - 62 Express route handlers (export functions returning middleware)
- `/models/` - 22 Sequelize ORM models with relations in `models/relations.ts`
- `/lib/` - Core utilities: `insecurity.ts` (JWT/hashing), `challengeUtils.ts` (challenge solving)
- `/data/` - Data seeding (`datacreator.ts`), runtime cache (`datacache.ts`)
- `/config/` - YAML configuration profiles (default.yml, test.yml, ctf.yml, etc.)

**Main orchestrator:** `server.ts` (755 lines) - middleware chain, 109+ routes, Finale REST API

## Course Structure (MS Press)

```
juice-shop/
├── demos/                    # Lesson runbooks (01-05)
├── labs/                     # Lab exercises by lesson
│   ├── lesson-01/           # Vulnerability Detection
│   ├── lesson-02/           # Security Protocols
│   ├── lesson-03/           # Automated Testing
│   ├── lesson-04/           # Code Review & Auditing
│   └── lesson-05/           # Compliance & IR
├── iac/                      # Infrastructure as Code
│   ├── juice-shop-insecure/ # Deliberately vulnerable Terraform
│   └── juice-shop-hardened/ # Secure baseline Terraform
├── scripts/                  # GHAS and compliance tools
│   ├── fetch-ghas-alerts.js
│   └── generate-compliance-report.js
└── juice-shop-security-course.code-workspace
```

### Lesson Topics

1. **Lesson 01:** Vulnerability Detection (SQL injection, XSS, IDOR, custom scanners)
2. **Lesson 02:** Security Protocols (OAuth 2.0, JWT, encryption, Azure Key Vault, zero-trust IaC)
3. **Lesson 03:** Automated Testing (security tests, fuzzing, SAST/DAST, CI/CD gates)
4. **Lesson 04:** Code Review & Auditing (STRIDE, Semgrep linters, compliance reporting)
5. **Lesson 05:** Compliance & IR (CIS/NIST benchmarks, STIG, incident response playbooks)

### IaC for Demos

The `iac/` directory contains Terraform configurations for Azure:

- **`juice-shop-insecure/`** - Intentionally vulnerable:
  - Public IPs, permissive NSGs (0.0.0.0/0)
  - TLS 1.0 allowed, no encryption at rest
  - Hardcoded credentials, no audit logging
  - Used as "before" state in Lesson 02 Demo 4 and Lesson 05 Demo 1

- **`juice-shop-hardened/`** - Security best practices:
  - Private endpoints, network segmentation
  - TLS 1.2+, TDE with CMK, Azure AD auth
  - Managed identities, comprehensive logging
  - Used as "after" state demonstrating zero-trust

## Critical Patterns

### Route Pattern
```typescript
// Routes export a function returning Express handler
export function routeName() {
  return (req: Request, res: Response, next: NextFunction) => { ... }
}
```

### Challenge Verification
```typescript
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'

challengeUtils.solveIf(challenges.someChallenge, () => exploitCondition)
```

### Security Middleware Chain
- `security.isAuthorized()` - JWT validation
- `security.appendUserId()` - Attaches user ID from JWT
- `security.denyAll()` - Returns 403
- Runs BEFORE Finale REST API

### Intentional Vulnerabilities
- Raw SQL via `models.sequelize.query()` enables SQL injection
- `vuln-code-snippet` comments mark vulnerable code sections
- Config-driven vulnerability enabling via `/config/*.yml`
- MD5 password hashing (deliberately weak) via `security.hash()`

## Configuration

- Load values: `config.get<Type>('path.to.value')`
- Schema validation: `config.schema.yml`
- Profiles: default.yml, test.yml, unsafe.yml, ctf.yml, tutorial.yml

## Testing Structure

- **Server tests:** Mocha in `test/server/**/*.ts`
- **API tests:** Frisby/Jest in `test/api/**/*Spec.ts`
- **Frontend tests:** Jasmine/Karma in `frontend/src/**/*.spec.ts`
- **E2E tests:** Cypress in `cypress/e2e/**/*.cy.ts`

## Useful References

- Companion Guide: https://pwning.owasp-juice.shop
- Course Setup: See `COURSE-SETUP.md`
- VS Code Workspace: `juice-shop-security-course.code-workspace`
- Application runs on port 3000 by default
- Docker: `docker run -p 3000:3000 bkimminich/juice-shop`
