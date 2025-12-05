/**
 * @name SQL Injection Detection
 * @description Detects SQL injection vulnerabilities in JavaScript/TypeScript
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id js/sql-injection
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/a03-2021
 */

import javascript
import DataFlow::PathGraph
import semmle.javascript.security.dataflow.SqlInjectionQuery

/**
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 03 - Automated Security Testing
 *
 * Copilot Prompt Used:
 * "Create CodeQL query to detect SQL injection in Node.js applications"
 */

// Source: HTTP request parameters
class HttpRequestSource extends DataFlow::SourceNode {
  HttpRequestSource() {
    // Express.js request parameters
    exists(DataFlow::Node req |
      req = DataFlow::globalVarRef("req") or
      req.asExpr().(Parameter).getName() = "req"
    |
      // req.params, req.query, req.body
      this = req.getAPropertyRead(["params", "query", "body"]).getAPropertyRead()
    )
  }
}

// Sink: SQL query methods
class SqlQuerySink extends DataFlow::Node {
  SqlQuerySink() {
    // PostgreSQL (pg)
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = ["query", "execute"] and
      call.getReceiver().getALocalSource().toString().matches("%pool%|%client%")
    |
      this = call.getArgument(0)
    )
    or
    // MySQL
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = ["query", "execute"] and
      call.getReceiver().getALocalSource().toString().matches("%connection%|%mysql%")
    |
      this = call.getArgument(0)
    )
    or
    // SQLite
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = ["run", "get", "all", "exec"] and
      call.getReceiver().getALocalSource().toString().matches("%db%|%sqlite%")
    |
      this = call.getArgument(0)
    )
    or
    // Generic database
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "raw" or
      call.getMethodName() = "rawQuery"
    |
      this = call.getArgument(0)
    )
  }
}

// Sanitizers
class SqlSanitizer extends DataFlow::Node {
  SqlSanitizer() {
    // Parameterized query (array)
    exists(DataFlow::ArrayCreationNode arr | this = arr.getAnElement())
    or
    // Input validation functions
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["escape", "escapeId", "sanitize", "validate", "parseInt"]
    |
      this = call
    )
    or
    // Type coercion
    exists(AddExpr add | add.getAnOperand().getType().toString() = "number" |
      this.asExpr() = add
    )
  }
}

// Main query
from SqlInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection vulnerability: user input from $@ flows to SQL query.",
  source.getNode(), "HTTP request"
