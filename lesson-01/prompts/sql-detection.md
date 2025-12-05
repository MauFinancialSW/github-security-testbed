# SQL Injection Detection Prompt

## Purpose
Use this prompt with GitHub Copilot Chat to scan codebases for SQL injection vulnerabilities.

## Prompt Template

```
Scan this codebase for SQL injection vulnerabilities. Focus on:

1. String concatenation in SQL queries
2. Unsanitized user input in WHERE clauses
3. Dynamic query building without parameterization
4. ORM queries using raw SQL
5. Stored procedures with dynamic SQL
6. ORDER BY and LIMIT clauses with user input

For each finding:
- Show the vulnerable code snippet
- Explain the attack vector with example payload
- Provide parameterized query alternative
- Rate severity (Critical/High/Medium/Low)
- Include CWE reference

Output as JSON for automated processing.
```

## Usage Examples

### Basic Scan
```
@workspace Analyze all JavaScript files for SQL injection. Show vulnerable lines and fixes.
```

### Targeted Scan
```
Review this function for SQL injection:
[paste code]

Identify:
1. Input sources (params, query, body)
2. How input flows to database query
3. Missing sanitization points
4. Secure alternative using prepared statements
```

### Comprehensive Audit
```
Perform a SQL injection security audit on this repository:

1. Find all database query patterns
2. Trace user input to query construction
3. Identify injection points
4. Prioritize by risk (auth bypass > data leak > DoS)
5. Generate fix recommendations with code examples
```

## Expected Copilot Response Format

```json
{
  "findings": [
    {
      "file": "api/users.js",
      "line": 45,
      "severity": "CRITICAL",
      "type": "SQL_INJECTION",
      "vulnerableCode": "const query = `SELECT * FROM users WHERE id = ${userId}`;",
      "attackVector": "User can inject: 1 OR 1=1 to bypass authentication",
      "examplePayload": "1' OR '1'='1",
      "secureAlternative": "const query = 'SELECT * FROM users WHERE id = ?'; db.query(query, [userId]);",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection"
    }
  ]
}
```

## Common SQL Injection Patterns to Detect

### Pattern 1: String Concatenation
```javascript
// VULNERABLE
const query = "SELECT * FROM users WHERE id = " + userId;
const query = `SELECT * FROM users WHERE id = ${userId}`;
const query = "SELECT * FROM users WHERE name = '" + name + "'";
```

### Pattern 2: Format String
```python
# VULNERABLE
query = "SELECT * FROM users WHERE id = %s" % user_id
query = "SELECT * FROM users WHERE id = {}".format(user_id)
query = f"SELECT * FROM users WHERE id = {user_id}"
```

### Pattern 3: ORDER BY Injection
```javascript
// VULNERABLE - ORDER BY cannot be parameterized
const query = `SELECT * FROM products ORDER BY ${sortColumn} ${sortDirection}`;
```

### Pattern 4: IN Clause
```javascript
// VULNERABLE
const ids = req.query.ids.join(',');
const query = `SELECT * FROM items WHERE id IN (${ids})`;
```

## Remediation Templates

### Node.js with mysql2
```javascript
// SECURE: Parameterized query
const [rows] = await pool.execute(
  'SELECT * FROM users WHERE id = ?',
  [userId]
);
```

### Python with psycopg2
```python
# SECURE: Parameterized query
cursor.execute(
    "SELECT * FROM users WHERE id = %s",
    (user_id,)
)
```

### Java with PreparedStatement
```java
// SECURE: Prepared statement
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?"
);
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
```

## Testing Commands

After fixes are applied, verify with these tests:

```bash
# Test for SQL injection in login
curl -X POST http://localhost:3000/login \
  -d "username=admin'--&password=anything"

# Test UNION injection
curl "http://localhost:3000/user/1%20UNION%20SELECT%20*%20FROM%20passwords"

# Test boolean blind injection
curl "http://localhost:3000/user/1%20AND%201=1"
curl "http://localhost:3000/user/1%20AND%201=2"
```
