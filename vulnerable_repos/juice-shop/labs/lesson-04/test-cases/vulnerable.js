/**
 * VULNERABLE CODE SAMPLES
 *
 * These code samples contain hardcoded secrets and should trigger Semgrep rules.
 * DO NOT use patterns like these in production code!
 */

// ========================================
// AZURE STORAGE - Hardcoded Connection Strings
// ========================================

// VULNERABLE: Hardcoded Azure Storage connection string
// Should trigger: azure-hardcoded-storage-connection-string
const { BlobServiceClient } = require('@azure/storage-blob');

const connectionString = "DefaultEndpointsProtocol=https;AccountName=devstorageacct;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;EndpointSuffix=core.windows.net";
const blobServiceClient = BlobServiceClient.fromConnectionString(connectionString);

// VULNERABLE: Another variant with single quotes
const storageConnString = 'DefaultEndpointsProtocol=https;AccountName=prodaccount;AccountKey=ABC123XYZ789verylongsecretkey1234567890abcdefghijklmnopqrstuvwxyz==';
const blobClient = BlobServiceClient.fromConnectionString(storageConnString);

// VULNERABLE: Inline connection string
const client = BlobServiceClient.fromConnectionString(
  "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=myverysecretkey123456789=="
);

// ========================================
// HARDCODED API KEYS
// ========================================

// VULNERABLE: Hardcoded API keys
// Should trigger: hardcoded-api-key
const API_KEY = "sk_live_51234567890abcdefghijklmnopqrstuvwxyz";
const STRIPE_API_KEY = 'pk_test_abcdefghijklmnopqrstuvwxyz1234567890';
const access_key = "AKIAIOSFODNN7EXAMPLE1234567890ABCDEFGHIJ";
const SECRET_API_KEY = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";

// VULNERABLE: API key in configuration object
const config = {
  apiKey: "AIzaSyBCdEfGhIjKlMnOpQrStUvWxYz1234567890",
  authKey: "Bearer_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  accessToken: "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
};

// ========================================
// HARDCODED JWT SECRETS
// ========================================

// VULNERABLE: Hardcoded JWT secret
// Should trigger: hardcoded-jwt-secret
const jwt = require('jsonwebtoken');

const jwtSecret = "my-super-secret-jwt-key-12345";
const token = jwt.sign({ userId: 1, role: 'admin' }, jwtSecret);

// VULNERABLE: JWT verification with hardcoded secret
const decoded = jwt.verify(token, 'another-hardcoded-secret-key');

// VULNERABLE: Inline secret
const userToken = jwt.sign(
  { user: 'admin' },
  "hardcoded-secret-this-is-bad",
  { expiresIn: '1h' }
);

// ========================================
// HARDCODED DATABASE CREDENTIALS
// ========================================

// VULNERABLE: MongoDB connection string with password
// Should trigger: hardcoded-database-password
const mongoUri = "mongodb://admin:MyP@ssw0rd123@localhost:27017/mydb";
const mongoose = require('mongoose');
mongoose.connect('mongodb://user:SecretPassword123!@prod-db.example.com:27017/production');

// VULNERABLE: PostgreSQL connection string
const pgConnection = 'postgresql://dbuser:SuperSecretPass123@database.example.com:5432/appdb';

// ========================================
// AWS CREDENTIALS
// ========================================

// VULNERABLE: Hardcoded AWS credentials
// Should trigger: hardcoded-aws-credentials
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

const AWS = require('aws-sdk');
AWS.config.update({
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  region: 'us-west-2'
});

// ========================================
// GENERIC HIGH-ENTROPY SECRETS
// ========================================

// VULNERABLE: Generic secrets
// Should trigger: generic-high-entropy-secret
const SECRET_TOKEN = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";
const PASSWORD = "VeryLongAndComplexPasswordThatShouldBeInEnvVar12345!@#";
const auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
const encryption_key = "0123456789abcdef0123456789abcdef0123456789abcdef";

// ========================================
// MISSING MANAGED IDENTITY
// ========================================

// VULNERABLE: Using connection string instead of DefaultAzureCredential
// Should trigger: azure-storage-missing-managed-identity
const { QueueServiceClient } = require('@azure/storage-queue');
const queueClient = QueueServiceClient.fromConnectionString(
  "DefaultEndpointsProtocol=https;AccountName=queue;AccountKey=abc123=="
);

// VULNERABLE: Cosmos DB with key
// Should trigger: azure-cosmosdb-missing-managed-identity
const { CosmosClient } = require('@azure/cosmos');
const cosmosClient = new CosmosClient({
  endpoint: "https://mycosmosdb.documents.azure.com:443/",
  key: "C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw=="
});

// VULNERABLE: Service Bus with connection string
// Should trigger: azure-servicebus-missing-managed-identity
const { ServiceBusClient } = require('@azure/service-bus');
const sbClient = new ServiceBusClient(
  "Endpoint=sb://myservicebus.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abc123xyz789=="
);

// ========================================
// REAL-WORLD EXAMPLES
// ========================================

// VULNERABLE: Email service configuration
const emailConfig = {
  service: 'gmail',
  auth: {
    user: 'admin@example.com',
    pass: 'MyEmailPassword123!'  // Hardcoded password
  }
};

// VULNERABLE: Third-party API client
class PaymentService {
  constructor() {
    this.apiKey = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';  // Stripe API key
    this.endpoint = 'https://api.stripe.com/v1';
  }

  processPayment(amount) {
    // Uses hardcoded API key
    return fetch(this.endpoint + '/charges', {
      headers: {
        'Authorization': `Bearer ${this.apiKey}`
      }
    });
  }
}

// VULNERABLE: Encryption key in code
const crypto = require('crypto');
const ENCRYPTION_KEY = 'abcdef0123456789abcdef0123456789';  // 32 bytes
const IV = '0123456789abcdef';  // 16 bytes

function encrypt(text) {
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

// ========================================
// SUMMARY
// ========================================

/*
This file should trigger the following Semgrep rules:
1. azure-hardcoded-storage-connection-string (3+ findings)
2. hardcoded-api-key (4+ findings)
3. hardcoded-jwt-secret (3+ findings)
4. hardcoded-database-password (3+ findings)
5. hardcoded-aws-credentials (2+ findings)
6. generic-high-entropy-secret (4+ findings)
7. azure-storage-missing-managed-identity (1+ findings)
8. azure-cosmosdb-missing-managed-identity (1+ findings)
9. azure-servicebus-missing-managed-identity (1+ findings)

Total expected findings: 20+
*/
