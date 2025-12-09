#!/usr/bin/env bash
set -euo pipefail

# Lists CodeQL code scanning alerts tagged with OWASP Top 10 for the current repository.

gh api \
  repos/:owner/:repo/code-scanning/alerts \
  --paginate \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  | jq -s '
      (add // [])
      | map(select(.rule.tags and any(.rule.tags[]?; (ascii_downcase | contains("owasp")))))
      | map({
          alert_number: .number,
          rule_id: .rule.id,
          security_severity: .security_severity,
          owasp_tags: [ .rule.tags[]? | select((ascii_downcase | contains("owasp"))) ],
          file_path: (.most_recent_instance.location.path? // null)
        })
      | .[]
    '
