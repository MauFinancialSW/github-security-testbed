# Zero Trust Architecture Prompts

## Course: GitHub Copilot for Cybersecurity Specialists
## Lesson: 02 - Security Protocols with Copilot

---

## Network Segmentation with Terraform

### Basic Prompt
```
Create Terraform config for zero trust network segmentation on AWS
```

### Expected Infrastructure
- VPC with private subnets only (no public internet access)
- Network ACLs with explicit deny-all rules
- Security groups following least privilege
- VPC endpoints for AWS service access (no NAT gateway needed)
- VPC Flow Logs for traffic analysis

### Micro-segmentation Prompt
```
Configure security groups for database tier that only accepts connections from application tier on port 5432
```

### Expected Pattern
```hcl
resource "aws_security_group" "db" {
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]  # Only from app tier
  }
  # No egress - databases don't initiate connections
}
```

---

## Service Mesh with Istio

### Basic Prompt
```
Configure Istio service mesh for zero trust mTLS between all services
```

### Key Configurations

#### Strict mTLS
```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
spec:
  mtls:
    mode: STRICT  # Require mTLS for all traffic
```

#### Default Deny Policy
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-all
spec:
  {}  # Empty spec = deny all
```

---

## Service-to-Service Authorization

### Prompt
```
Create Istio authorization policy for payment service that only accepts requests from order service
```

### Expected Implementation
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payment-service-policy
spec:
  selector:
    matchLabels:
      app: payment-service
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/app/sa/order-service"]
      to:
        - operation:
            methods: ["POST"]
            paths: ["/payments/process"]
```

---

## JWT-Based Authentication

### Prompt
```
Configure Istio request authentication with JWT validation from identity provider
```

### Expected Configuration
```yaml
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
spec:
  jwtRules:
    - issuer: "https://auth.example.com"
      jwksUri: "https://auth.example.com/.well-known/jwks.json"
      audiences: ["https://api.example.com"]
      forwardOriginalToken: true
      outputClaimToHeaders:
        - header: "x-user-id"
          claim: "sub"
```

---

## Rate Limiting and Circuit Breaking

### Rate Limiting Prompt
```
Configure Istio rate limiting at 100 requests per second per client
```

### Circuit Breaker Prompt
```
Configure circuit breaker that ejects hosts after 5 consecutive 5xx errors
```

### Expected DestinationRule
```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
spec:
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http2MaxRequests: 1000
    outlierDetection:
      consecutive5xxErrors: 5
      interval: 30s
      baseEjectionTime: 30s
```

---

## Key Vault Integration

### Azure Key Vault Prompt
```
Integrate with Azure Key Vault for secret management using managed identity
```

### HashiCorp Vault Prompt
```
Configure HashiCorp Vault with AppRole authentication and transit engine for encryption-as-a-service
```

---

## Zero Trust Principles for Prompts

1. **Never Trust, Always Verify**: Request authentication at every layer.

2. **Least Privilege Access**: Specify exact paths, methods, and source services.

3. **Micro-segmentation**: Each service has its own authorization policy.

4. **Encryption in Transit**: Always enable mTLS, never use plaintext.

5. **Continuous Verification**: Include rate limiting and circuit breaking.

6. **Audit Everything**: Enable logging for security events and access.
