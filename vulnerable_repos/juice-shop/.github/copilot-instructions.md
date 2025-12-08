# OWASP Juice Shop - Copilot Instructions

## Project Overview

OWASP Juice Shop is a deliberately insecure e-commerce web application designed to teach security vulnerabilities. It comprises:
- **Backend**: Node.js/Express TypeScript server with Sequelize ORM (SQLite database)
- **Frontend**: Angular application
- **Testing**: Mocha (server), Jasmine/Karma (frontend), Cypress (E2E), Frisby (API)
- **Database**: SQLite with Sequelize models for data persistence

## Architecture

### Backend Structure (`server.ts` is the core orchestrator)
- **Models** (`/models`): Sequelize ORM definitions for Users, Products, Challenges, Baskets, etc. Models use MySQL-style naming (`UserModel`, `ProductModel`)
- **Routes** (`/routes`): REST API endpoints organized by feature (login, basket, orders, payment, etc.). Each route exports handler functions
- **Lib** (`/lib`): Core utilities including security (`insecurity.ts`), challenge tracking (`challengeUtils.ts`), utilities (`utils.ts`), logging
- **Data** (`/data`): Data creation (`datacreator.ts`), static seed data (`staticData.ts`), MongoDB collections for reviews/orders

### Frontend (`/frontend` - separate Angular app)
- Angular 20+ CLI project with Material Design
- Compiled to `frontend/dist/frontend` at build time
- Served from backend as static files under `/` route

### Challenge System (Core to Architecture)
- Challenges are database records with metadata (difficulty, category, hints, key, description)
- **Challenge solving pattern**: Routes use `challengeUtils.solveIf()` to verify exploit conditions and mark challenges as solved
- Challenges have `enabled` status controlled by config and environment (`getChallengeEnablementStatus()`)
- Uses `vuln-code-snippet` comments to mark vulnerable code sections for exercises
- **Hint system**: Related `HintModel` records with progressive content
- **Challenge verification**: Happens in routes BEFORE `finale` REST API (see middleware chain in `server.ts` lines ~100-300)

### Key Design Patterns

#### 1. **Security Middleware Chain** (`server.ts`)
- `security.isAuthorized()`: JWT token validation - adds user to request
- `security.appendUserId()`: Attaches `req.userId` from JWT
- `security.denyAll()`: Returns 403 - used to control API access
- `security.isAccounting()`: Role-based access for specific users
- Middleware runs BEFORE Sequelize REST API (finale)

#### 2. **Authorization Model** (`lib/insecurity.ts`)
- JWT tokens created with `security.authorize()` - used for authentication
- `security.authenticatedUsers` map caches active sessions (token → user data)
- Hash function: MD5 for passwords (deliberately weak for training) via `security.hash()`
- Signed tokens with embedded user data: `{ userId, type?, email }`

#### 3. **Route Pattern** (see `/routes/login.ts`)
- Routes export a single function returning Express handler
- Common signature: `export function routeName() { return (req, res, next) => { ... } }`
- Use `models.sequelize.query()` for raw SQL (enables SQL injection vulns), `Model.findAll()` for ORM
- Error handling: catch and call `next(error)` for middleware error handler

#### 4. **Challenge Verification Pattern**
```typescript
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'

// In route handler:
challengeUtils.solveIf(challenges.someChallenge, () => {
  return exploitDetected // boolean condition
})
```
- `challenges` object is a singleton datacache loaded at startup
- `solveIf()` verifies condition is true AND challenge not already solved
- Challenge name = `*Challenge` suffix on exported object key

#### 5. **Data Creation** (`data/datacreator.ts`)
- Runs async on startup before server listens
- Loads static data via `loadStaticUserData()`, `loadStaticChallengeData()`, etc.
- Creates test users, products, challenges sequentially
- Populates MongoDB collections for reviews/orders (NoSQL alongside SQL)

### Database Design
- **SQLite** primary datastore (file: `data/juiceshop.sqlite`)
- **Sequelize models** (18 total) with relationships defined in `models/relations.ts`
- Key models: User, Product, Basket, BasketItem, Challenge, Feedback, Complaint, etc.
- **Model conventions**: Use DataTypes from Sequelize; custom setters for validation/sanitization
- Example sanitization pattern in `models/user.ts`: setters apply `security.sanitizeLegacy()` or `security.sanitizeSecure()` based on challenge enablement

## Developer Workflows

### Build & Run
```bash
npm install              # Backend + frontend install
npm run build:frontend   # Compile Angular
npm run build:server     # Compile TypeScript to build/
npm start               # Run compiled backend (node build/app)
npm run serve           # Dev: ts-node + ng serve concurrently
npm run serve:dev       # Dev with ts-node-dev (auto-reload)
```

### Testing
```bash
npm test                # Angular tests + server tests (combined)
npm run test:server     # Server tests only (Mocha with ts-node)
npm run test:api        # API tests (Frisby/Jest)
npm run cypress:open    # E2E tests (interactive)
npm run cypress:run     # E2E tests (headless)
```

### Linting
```bash
npm run lint            # Check style (ESLint backend + frontend)
npm run lint:fix        # Auto-fix ESLint/SCSS issues
npm run lint:config     # Validate config schema
```

### Configuration
- Config files: `/config/*.yml` (e.g., `default.yml`, `test.yml`)
- Load with `config.get<Type>('path.to.value')`
- Schema validation: `config.schema.yml` validated on startup
- Common config paths: `application.domain`, `server.port`, `challenges.showHints`

## Code Patterns & Conventions

### TypeScript Strict Mode
- `tsconfig.json` enforces `strict: true`
- Use explicit types on function parameters/returns
- Import types: `import type { SomeType } from '...'`

### Testing Conventions
- **Server tests**: Mocha in `test/server/**/*.ts`
- **API tests**: Frisby in `test/api/**/*Spec.ts` - use `frisby.get/post/put()` chains
- **Frontend tests**: Jasmine in `frontend/src/**/*.spec.ts`
- **E2E tests**: Cypress in `cypress/e2e/**/*.cy.ts`

### File Upload Handling
- Multer middleware: in-memory (`uploadToMemory`) or disk (`uploadToDisk`)
- Middleware chain: `upload.single('file')` → `ensureFileIsPassed` → validation → handler
- Sensitive file types restricted by MIME type map defined in `server.ts` bottom

### Logging
- Use `logger.info()`, `logger.error()` from `lib/logger.ts`
- Production: logs stream to `logs/access.log.%DATE%` via Morgan
- Include status messages with `colors` package (colors.cyan(), colors.green(), etc.)

### REST API Auto-Generation
- **Finale** (formerly Epilogue): auto-generates CRUD endpoints for models
- Registered in `server.ts` lines 380+: models list with exclude fields
- Hooks allow pre/post processing on create/read/list operations
- Format: `/api/{ModelName}s` and `/api/{ModelName}s/:id`
- Translates challenge descriptions, security questions on-the-fly

## Critical Files & Directories

| File/Directory | Purpose |
|---|---|
| `server.ts` | Main application setup: middleware, routes, finale init |
| `models/index.ts` | Sequelize initialization and model import |
| `data/datacreator.ts` | Startup data seed logic (users, challenges, products) |
| `lib/insecurity.ts` | Security utilities (JWT, hashing, sanitization) |
| `lib/challengeUtils.ts` | Challenge solving mechanism |
| `routes/verify.ts` | Challenge verification functions (access control, SSTI, XSS checks) |
| `data/datacache.ts` | Runtime singleton objects (challenges, users, notifications) |
| `cypress/e2e/` | E2E test scenarios for challenge validation |
| `config/default.yml` | Default configuration (application name, domain, challenge settings) |

## Common Tasks

### Adding a New Challenge
1. Add challenge metadata to `data/challenges.yml` or `staticData.ts`
2. Create verification logic in route handler using `challengeUtils.solveIf()`
3. Add vulnerable code with `// vuln-code-snippet` comments
4. Create Cypress E2E test in `cypress/e2e/` to demonstrate exploit
5. Add hint text in `HintModel` creation in `datacreator.ts`

### Adding a New Route
1. Create file in `/routes/{feature}.ts` exporting handler function
2. Import in `server.ts` and add to route chain: `app.get('/path', handler())`
3. Apply security middleware (`isAuthorized()`, `appendUserId()`) as needed
4. Use Sequelize queries or Models for data access
5. Add error handling via `next(error)`

### Modifying Data Model
1. Edit Sequelize model in `/models/{entity}.ts`
2. Add DataTypes fields, setters, validations
3. Update relationships if needed in `models/relations.ts`
4. Regenerate seed data creation in `data/datacreator.ts`
5. Update API tests in `test/api/` to match new schema

### Frontend Component Changes
1. Components in `frontend/src/app/`
2. Services in `frontend/src/app/Services/` (API calls via HttpClient)
3. Use TypeScript strict mode, match ESLint style
4. Import shared Material modules from Material Design library
5. Test with `ng test` (Karma) before E2E

## Notable Quirks & Special Patterns

- **Raw SQL queries**: `models.sequelize.query()` used intentionally to enable SQL injection vulnerabilities (see `login.ts`)
- **Challenge snapshots**: `vuln-code-snippet` comments with nested tags mark code sections for code-snippet challenges
- **Config-driven enabling**: Many vulnerabilities conditionally enabled via `config` and environment checks (`isChallengeEnabled()`)
- **WebSocket events**: `registerWebsocketEvents(server)` handles real-time challenge notifications
- **Anti-cheating**: `lib/antiCheat.ts` detects pre-solve API interactions to mark exploits as cheating
- **Metrics/Prometheus**: Endpoints expose metrics at `/metrics` for monitoring (Grafana dashboard in `monitoring/`)
- **i18n**: Backend and frontend both support multi-language via i18n files in `/i18n/`

## Links & References
- Companion Guide: https://pwning.owasp-juice.shop
- Issues & Help: Use GitHub issues for bugs; avoid support questions
- Code Style: JavaScript Standard with ESLint (`http://standardjs.com`)
- Dependencies require signed Git commits (Developer Certificate of Origin)
