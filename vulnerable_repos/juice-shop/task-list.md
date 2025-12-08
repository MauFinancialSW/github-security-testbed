# Task List for Adapting OWASP Juice Shop for Copilot Cybersecurity Course

## 0. Fork & Workspace Setup

1. **Fork OWASP Juice Shop into your GitHub org**

   * Fork `https://github.com/juice-shop/juice-shop`.
   * Name it something like `juice-shop-copilot-course`.
   * Ensure the destination org has **GitHub Advanced Security (GHAS)** enabled.

2. **Clone locally into a course root**

   ```bash
   mkdir C:\Labs\copilot-juice
   cd C:\Labs\copilot-juice
   git clone https://github.com/<you>/juice-shop-copilot-course.git juice-shop
   cd juice-shop
   git checkout -b course-labs
   ```

3. **Create a VS Code workspace**

   * Add `juice-shop-course.code-workspace` at the root:

     * Folders: `.` (the app), `labs/`, `iac/` (we’ll make those in a sec).
     * Recommended extensions: Copilot, Copilot Chat, YAML, Terraform, PowerShell, Docker.

4. **Document course usage**

   * In `README.md`, add a short “Course Edition” section:

     * This fork is used for **GitHub Copilot for Cybersecurity Specialists**.
     * List the 5 lessons and which folders they touch.


## 1. Add a Lab & IaC Structure Around Juice Shop

5. **Create a `labs/` directory for all demo-specific assets**

   ```text
   juice-shop/
     labs/
       lesson-01/
       lesson-02/
       lesson-03/
       lesson-04/
       lesson-05/
   ```

   * Each `lesson-0x` gets a `README.md` and any helper scripts, test harnesses, or additional microservices you need.

6. **Create an `iac/` directory for Terraform and infra**

   ```text
   juice-shop/
     iac/
       juice-shop/   # TF for deploying Juice Shop itself
       waap/         # optional WAAP / WAF patterns
       hacking-lab/  # optional multi-target lab (Juice Shop + others)
   ```

   * You can reuse existing Terraform examples that deploy Juice Shop to cloud providers as reference, e.g.:

     * **GCE + Juice Shop + OWASP ZAP** example.
     * Terraform hacking lab with Juice Shop as a target.
     * Google Cloud WAAP module example for Juice Shop.

7. **Add a `COURSE-SETUP.md`**

   * Explain:

     * How to clone your fork.
     * How to start Juice Shop locally (Docker, Node, or Heroku mode).
     * How to initialize Terraform examples.

---

## 2. Make Juice Shop “Copilot + GHAS-ready”

Juice Shop already has CodeQL workflows in its upstream repo.

8. **Confirm/enable CodeQL in your fork**

   * Ensure `.github/workflows/codeql-analysis.yml` is present and enabled in your fork.
   * If you want a separate *course* workflow, add `.github/workflows/codeql-course.yml` with comments like:

     ```yaml
     # COURSE: Lesson 3 – CodeQL SAST demo against Juice Shop
     ```

9. **Enable GHAS features**

   * On your repo:

     * Turn on **code scanning**, **secret scanning**, and **Dependabot** alerts following the GHAS “Juice Shop trial” docs.

10. **Add helper scripts for GHAS data**

    * Under `scripts/`:

      * `fetch-ghas-alerts.js` – uses GitHub REST API to pull GHAS alerts as JSON.
      * `fetch-dependabot-alerts.js` – pulls Dependabot alerts.
      * `ghas-to-owasp10.js` – optional mapping script; you can borrow approach from GHAS + Juice Shop docs where they map alerts to OWASP Top 10.

11. **Add a minimal SECURITY.md**


      * This is an intentionally insecure training fork.
      * Do not deploy to production.
      * GHAS alerts are expected and used for demos.

---

## 3. Vulnerability Mapping for Lesson 1 (Detection & Review)

You already have Lesson 1 demo runbook; now you want those demos to operate on Juice Shop instead of a made-up app.

12. **Study Juice Shop’s vuln categories and challenge mapping**

    * Use the official “Pwning Juice Shop” guide and vulnerability categories to see where OWASP Top 10 issues live in the codebase.

13. **Map each Lesson 1 demo to specific Juice Shop files & routes**

    In `labs/lesson-01/MAPPING.md`:

    * **SQL injection / injection demo**

      * Pick a challenge involving injection (e.g., search or login functionality).
      * Map to specific controllers/services in the TypeScript/Node backend (e.g., `server.ts`, `routes/*`, `dataAccess/*` – exact files after you browse the repo).

    * **XSS demo**

      * Choose a reflected or stored XSS challenge (e.g., in reviews, feedback, or search).
      * Map to template + route + Angular component.

    * **IDOR / broken access control**

      * Pick a challenge where a user can access someone else’s data (account data, orders, etc.).
      * Map to API endpoints and route guards.

14. **Add in-code markers for course demos**

    * In each target file, add tiny comments like:

      ```ts
      // COURSE: Lesson 1 Demo – SQL Injection vulnerability here for Copilot analysis
      ```

    * These anchor your Copilot Chat prompts: “Scroll to the COURSE comment.”

15. **Prepare secure variants / refactor stubs**

    * For each vulnerability:

      * Add a new function or branch representing the "secure" version:

        * Parameterized queries, escaped output, proper access checks.
      * Your Lesson 1 flow:
        "Show vuln code → use Copilot Chat to explain + exploit → use Copilot to help refactor into secure variant stub."

16. **Add data-reset helper script (optional but nice)**

    * In `labs/lesson-01/reset-state.js`:

      * Use the Juice Shop API or direct DB seeding to reset orders/users to known lab state.

---

## 4. Lesson 2 – Protocols & Crypto (Still Juice Shop-aware)

Lesson 2 is your “build secure protocols” lesson (OAuth2, JWT, crypto, zero trust).

17. **Create a mini “secure services” layer under `labs/lesson-02/`**

    * `labs/lesson-02/oauth-server/` – Node/Express or Nest microservice implementing OAuth2 + PKCE.
    * `labs/lesson-02/api-gateway/` – simple gateway enforcing JWT + RBAC and proxying to Juice Shop endpoints.
    * `labs/lesson-02/crypto-service/` – library or service for AES-GCM, PBKDF2, Key Vault integration patterns.

18. **Document how these would front Juice Shop**

    * In `labs/lesson-02/README.md`:

      * Sketch architecture: **Client → OAuth Server → API Gateway → Juice Shop**.
      * Map existing Juice Shop routes that would sit “behind” the gateway.

19. **Add explicit Copilot prompts into comments or docs**

    * For each service, embed “prompt anchors”:

      // COURSE: Ask Copilot to implement OAuth2 + PKCE handler here.
      ```

    * Your runbook will then say “Place cursor here, open Copilot Chat, paste this prompt.”

20. **Zero-trust & network policy narrative**

    * Link to IaC pieces under `iac/juice-shop/` (see next section) showing:

      * Private endpoints
      * TLS enforcement
      * WAF/wAF/WAAP in front of Juice Shop.

---

## 5. Lesson 3 – Automated Testing on Juice Shop

Lesson 3 is unit tests, fuzzing, SAST, CI/CD.

21. **Create a `labs/lesson-03/tests/` directory**

    * Add baseline test files for:

      * Authentication routes
      * Vulnerable endpoints identified in Lesson 1

    * Keep them intentionally thin so Copilot can "fill in the rest."

22. **Wire tests into Juice Shop’s test harness**

    * Juice Shop already has tests (for build/CI).
    * Add your security tests under `test/security/` or similar.
    * Update `package.json` scripts:

      ```json
      "test:security": "mocha test/security/**/*.spec.ts"
      ```

      or adapt to the existing test runner.

23. **Align CodeQL to your lesson**

    * Add comments like:

      ```yaml
      # COURSE: Lesson 3 – run CodeQL on Juice Shop + show alerts in Security tab
      ```

24. **Keep fuzzing separate, but in this repo**

    * Under `labs/lesson-03/fuzzing/`:

      * Your C fuzz targets and harness.
      * Or, if you want to fuzz Juice Shop APIs:

        * A Node-based fuzz client that hits specific Juice Shop endpoints.

    * Juice Shop itself doesn't need modification; this is "client-side" fuzz harness.
 **Create a CI pipeline example for Juice Shop**

    * Under `labs/lesson-03/workflows/`:

      * `ci-security.yml` that:

        * Builds Juice Shop.
        * Runs tests.
        * Runs CodeQL & `npm audit`.
        * Uploads SARIF.

      * This is where Copilot helps you author & refine the workflow in the demos.

---

## 6. Lesson 4 – Governance, Reporting, Linters, Dependency Workflow

Lesson 4 is code review, STRIDE, GHAS reporting, Semgrep/custom linters, and dependency triage.

26. **Mark a “review target” module in Juice Shop**

    * Choose a meaty file (auth handling, JWT, profile updates).
    * Add:

      ```ts
      // COURSE: Lesson 4 Demo – Use Copilot Chat for security code review & STRIDE modeling here.
      ```

27. **Set up GHAS → report tooling**
    * In `labs/lesson-04/reporting/`:

      * Place `fetch-ghas-alerts.js` and `ghas-to-owasp10.js`.
      * Include a markdown template for “Executive Security Summary” Copilot should fill.

28. **Create Semgrep rule packs**

    * Under `labs/lesson-04/semgrep/`:

      * YAML rules targeting:

        * Hardcoded secrets.
        * Insecure crypto.
        * Insecure request patterns specific to Juice Shop's stack.

      * Add a `semgrep.yml` CI workflow that:

        * Runs Semgrep.
        * Emits SARIF (`--sarif --output semgrep-results.sarif`).
        * Uploads via `github/codeql-action/upload-sarif`. (You fixed this pattern in L4 already.)

29. **Dependency triage scripts**

    * Under `labs/lesson-04/dependency-triage/`:

      * Scripts to:

        * Fetch Dependabot alerts.
        * Group by package + CVE.
        * Generate a triage summary (this is where Copilot's summarization shines).

    * Make sure Juice Shop's `package.json` still has some vulnerable or outdated deps (which is usually true).

---

## 7. Lesson 5 – Compliance, IaC & IR (Juice Shop + Terraform)

Now the Terraform/IaC “shit with TF”.

30. **Create Terraform for a basic Juice Shop deployment**

    * Under `iac/juice-shop/`:

      * A minimal config that:

        * Deploys Juice Shop container or Node app on your cloud of choice (Azure, GCP, AWS – pick one).
        * Uses existing community examples as reference (e.g., TF labs that deploy Juice Shop EC2/GCE).
      * Add intentionally insecure baseline:

        * Open security group.
        * No TLS.
        * Public bucket/logging gaps.

31. **Add a hardened variant / WAAP example**

    * Either:

      * Harden the TF using "OWASP Top 10 mitigation for Juice Shop on GCP" style guidance.
      * Or use a WAAP module that shows Juice Shop behind WAF/WAAP (e.g., GCP WAAP example for Juice Shop).

    * These align with your "zero trust / segmentation / compliance" story in Lessons 2 & 5.

32. **Wire IaC into GHAS & Copilot**

    * Add `.github/workflows/iac-scan.yml`:

      * Runs `terraform validate` / `tfsec` / built-in GHAS IaC scanning (if enabled).
      * This is where Copilot generates/remediates scanning workflows.

    * In `iac/juice-shop/README.md`, explain:

      * Harden security groups.
      * Add logging and monitoring.
      * Map findings to CIS / NIST controls.

33. **IR playbooks referencing a Juice Shop deployment**

    * Under `labs/lesson-05/ir-playbooks/`:

      * IR scripts for an Azure/GCP VM or container hosting Juice Shop.
      * KQL queries hitting logs for a Juice Shop app.

    * Even if the IR demo isn't *literally* hitting Juice Shop logs live, tie the narrative to "a compromised Juice Shop instance in the cloud."

---

## 8. MCP & Copilot Integration Tasks

You want to show MCP as part of the “whole fucking deal” with Copilot.

34. **Add `.vscode/mcp.json` to the repo**
    * Configure at least:

      * The **GitHub MCP server** so Copilot can:

        * List GHAS alerts.
        * Open issues/PRs.

      * Optionally an **Azure or logging MCP server** (for IR demos).

35. **Design one GHAS-focused MCP tool flow**

    * In your runbooks, plan a segment where:

      * Copilot Chat uses MCP to:

        * Query GHAS alerts for the Juice Shop repo.
        * Group them by OWASP category.
        * Generate a remediation plan.

    * That uses:

      * GitHub MCP server → GHAS APIs → Copilot summarization.

36. **Design one IR/logs-focused MCP tool flow**

    * If you have logs in Log Analytics / other store:

      * Build or configure an MCP server that surfaces KQL queries / log search.
      * Copilot Chat uses it to:

        * Pull logs for a hypothetical Juice Shop attack.
        * Build/update the IR playbook.

37. **Tag MCP use points in code/comments**

    * In `scripts/` and `labs/` add:

      ```js
      // COURSE: Ask Copilot via MCP to run this script and summarize results.
      ```

---

## 9. Final Sanity Checks Before You LLM-Refactor

38. **Dry-run each lesson path manually**

    * For each lesson:

      * Follow your current MD runbook.
      * Replace "demo app X" with the Juice Shop paths you just defined.

      * Check:

        * `npm install` works.
        * Tests run.
        * GHAS alerts show up.
        * TF plans apply in a test environment.

39. **Mark all “LLM refactor hotspots”**

    * Anywhere you expect Copilot/LLM to generate big chunks (OAuth server, gateways, workflows), add explicit comments:

      ```ts
      // LLM-GENERATED: Keep this area open for Copilot during demo.
      ```

    * That makes it easy to prompt against the right regions when you paste your MD runbook into an LLM later.

40. **Tag a baseline “course-labs-v1”**

    * Once it all works:

      ```bash
      git commit -am "Course labs baseline for Copilot cyber course"
      git tag course-labs-v1
      git push origin course-labs-v1
      ```

Now you’ve got a Juice Shop fork that’s:

* **GHAS-native** (as GitHub’s own training docs already recommend).
* Structured around your 5 lessons.
* IaC-ready with Terraform for hardened deployments.
* MCP-capable as a Copilot playground.

**Next best step:**
Create `labs/` and `iac/` with stub READMEs, then we can take **Lesson 1’s MD** and rewrite it line-by-line against `juice-shop` so your first module is fully Juice-Shop-native.
