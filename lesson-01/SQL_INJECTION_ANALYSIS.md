# SQL Injection Vulnerability Analysis
## Lesson 01 - Demo 02: Vulnerable API

### Executive Summary
The Express API in `demo-02-sql-injection/vulnerable/api.js` contains **8 critical SQL injection vulnerabilities** (OWASP A03:2021, CWE-89) that allow attackers to bypass authentication, exfiltrate data, and modify/delete records.

---

## Critical Vulnerabilities

### Vulnerability 1: GET Parameter Injection
**Location:** `/user/:id` endpoint (line 58)

**Vulnerable Code:**
```javascript
const query = `SELECT * FROM users WHERE id = ${userId}`;
```

**Attack Vectors:**
- `/user/1 OR 1=1` → Returns all users
- `/user/1 UNION SELECT username, password FROM users--` → Data exfiltration

---

### Vulnerability 2: Authentication Bypass
**Location:** `/login` endpoint (line 75)

**Vulnerable Code:**
```javascript
const query = "SELECT * FROM users WHERE username = '" + username +
              "' AND password = '" + password + "'";
```

**Attack Vectors:**
- `username: "admin'--"` → Bypasses password check
- `username: "' OR '1'='1"` → Returns all users

---

### Vulnerability 3: Search Function Injection
**Location:** `/search` endpoint (line 118)

**Vulnerable Code:**
```javascript
const query = `SELECT * FROM products
               WHERE name LIKE '%${searchTerm}%'
               AND category = '${category}'`;
```

**Attack Vectors:**
- `q=' UNION SELECT table_name, column_name, 3, 4 FROM information_schema.columns--`
- `q=' OR 1=1--`

---

### Vulnerability 4: ORDER BY Clause Injection
**Location:** `/products` endpoint (line 143)

**Vulnerable Code:**
```javascript
const query = `SELECT * FROM products ORDER BY ${sortBy} ${order}`;
```

**Attack Vectors:**
- `sort=id; DROP TABLE users;--` → Stacked queries
- `sort=(SELECT password FROM users WHERE username='admin')`

---

### Vulnerability 5: INSERT Statement Injection
**Location:** `/register` endpoint (line 167)

**Vulnerable Code:**
```javascript
const query = `INSERT INTO users (username, email, password, role)
               VALUES ('${username}', '${email}', '${password}', 'user')`;
```

**Attack Vector:**
- `email: "test@test.com', 'admin'); DROP TABLE users;--"`

---

### Vulnerability 6: UPDATE Statement Injection
**Location:** `/user/:id` PUT endpoint (line 194)

**Vulnerable Code:**
```javascript
const query = `UPDATE users
               SET email = '${email}', display_name = '${displayName}'
               WHERE id = ${userId}`;
```

**Attack Vector:**
- Privilege escalation by injecting role updates

---

### Vulnerability 7: DELETE Statement Injection
**Location:** `/product/:id` endpoint (line 217)

**Vulnerable Code:**
```javascript
const query = `DELETE FROM products WHERE id = ${productId}`;
```

**Attack Vector:**
- `id=1 OR 1=1` → Deletes all records

---

### Vulnerability 8: Blind SQL Injection
**Location:** `/check-user` endpoint (line 241)

**Vulnerable Code:**
```javascript
const query = `SELECT COUNT(*) as count FROM users WHERE username = '${username}'`;
// Different responses based on result
if (results[0].count > 0) {
  res.json({ exists: true, message: 'Username taken' });
}
```

**Attack Vector:**
- `username: "admin' AND SUBSTRING(password,1,1)='a'--"`
- Attacker extracts data character-by-character via response timing

---

## Secure Alternative: Parameterized Queries

All vulnerabilities are fixed by using **parameterized queries** with placeholders:

```javascript
// SECURE PATTERN
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Use ? placeholders and pass values separately
  const query = 'SELECT * FROM users WHERE id = ?';

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Query error:', err);
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});
```

### Key Benefits
- ✅ SQL structure is locked and cannot be altered by user input
- ✅ Database driver automatically escapes values
- ✅ Works for all SQL statement types (SELECT, INSERT, UPDATE, DELETE)

### Fix Template
Replace all endpoints following this pattern:

```javascript
// Before (VULNERABLE)
const query = `SELECT * FROM users WHERE id = ${userId}`;
db.query(query, callback);

// After (SECURE)
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId], callback);
```

---

## Recommendations
1. **Immediate:** Replace all dynamic queries with parameterized queries
2. **Input Validation:** Validate type and format (e.g., IDs should be integers)
3. **Least Privilege:** Database user should have minimal required permissions
4. **WAF:** Deploy Web Application Firewall to detect injection attempts
5. **Testing:** Run SAST tools (Semgrep, SonarQube) in CI/CD pipeline
6. **Education:** Train developers on secure coding practices

---

## References
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
- mysql2 Documentation: https://github.com/sidorares/node-mysql2
