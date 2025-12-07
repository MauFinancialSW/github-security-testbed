---
agent: agent
---
# prompts/sql-detection.md

## SQL Injection Detection Prompt

Scan this codebase for SQL injection vulnerabilities. Focus on:

1. String concatenation in SQL queries
2. Unsanitized user input in WHERE clauses
3. Dynamic query building without parameterization
4. ORM queries using raw SQL

For each finding:
- Show the vulnerable code
- Explain the attack vector
- Provide parameterized query alternative
- Rate severity (Critical/High/Medium/Low)

Output as JSON for automated processing.
