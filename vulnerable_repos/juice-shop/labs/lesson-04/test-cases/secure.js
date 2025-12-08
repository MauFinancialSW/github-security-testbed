/**
 * SECURE CODE SAMPLES
 *
 * These code samples demonstrate secure patterns that should NOT trigger Semgrep rules.
 * These are the recommended approaches for production code.
 */

// ========================================
// AZURE STORAGE - Using DefaultAzureCredential
// ========================================

// SECURE: Using DefaultAzureCredential with managed identity
const { DefaultAzureCredential } = require("@azure/identity");
const { BlobServiceClient } = require("@azure/storage-blob");

// Get account name from environment (not a secret)
const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME;

// Use managed identity - no secrets needed!
const credential = new DefaultAzureCredential();
const blobServiceClient = new BlobServiceClient(
  `https://${accountName}.blob.core.windows.net`,
  credential
);

// SECURE: Queue service with managed identity
const { QueueServiceClient } = require('@azure/storage-queue');
const queueServiceClient = new QueueServiceClient(
  `https://${accountName}.queue.core.windows.net`,
  credential
);

// ========================================
// API KEYS FROM ENVIRONMENT
// ========================================

// SECURE: Load API keys from environment variables
const apiKey = process.env.API_KEY;
const stripeApiKey = process.env.STRIPE_API_KEY;
const accessToken = process.env.ACCESS_TOKEN;

// SECURE: Configuration from environment
const config = {
  apiKey: process.env.EXTERNAL_API_KEY,
  apiEndpoint: process.env.API_ENDPOINT,
  timeout: 5000
};

// SECURE: Validate that required environment variables are set
if (!apiKey || !stripeApiKey) {
  throw new Error('Required environment variables not set');
}

// ========================================
// JWT WITH ENVIRONMENT VARIABLES
// ========================================

// SECURE: JWT secret from environment
const jwt = require('jsonwebtoken');
const jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
  throw new Error('JWT_SECRET environment variable must be set');
}

// Create token with secure options
const token = jwt.sign(
  { userId: 1, role: 'user' },
  jwtSecret,
  {
    algorithm: 'HS256',      // Explicitly specify algorithm
    expiresIn: '1h',         // Token expires after 1 hour
    issuer: 'myapp',         // Identify token issuer
    audience: 'myapp-api'    // Identify intended recipient
  }
);

// Verify token with secure options
const decoded = jwt.verify(token, jwtSecret, {
  algorithms: ['HS256'],   // Only allow specific algorithm
  issuer: 'myapp',
  audience: 'myapp-api'
});

// ========================================
// AZURE KEY VAULT FOR SECRETS
// ========================================

// SECURE: Load secrets from Azure Key Vault
const { SecretClient } = require("@azure/keyvault-secrets");

async function getSecrets() {
  const keyVaultName = process.env.KEY_VAULT_NAME;
  const vaultUrl = `https://${keyVaultName}.vault.azure.net`;

  const credential = new DefaultAzureCredential();
  const secretClient = new SecretClient(vaultUrl, credential);

  // Retrieve secrets from Key Vault
  const apiKeySecret = await secretClient.getSecret('api-key');
  const dbPasswordSecret = await secretClient.getSecret('db-password');

  return {
    apiKey: apiKeySecret.value,
    dbPassword: dbPasswordSecret.value
  };
}

// ========================================
// DATABASE CONNECTIONS
// ========================================

// SECURE: MongoDB connection from environment
const mongoose = require('mongoose');
const mongoUri = process.env.MONGODB_URI;

if (!mongoUri) {
  throw new Error('MONGODB_URI environment variable not set');
}

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// SECURE: Build connection string from separate env vars
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 27017,
  database: process.env.DB_NAME,
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD
};

const connectionString = `mongodb://${dbConfig.username}:${dbConfig.password}@${dbConfig.host}:${dbConfig.port}/${dbConfig.database}`;

// SECURE: Azure Cosmos DB with managed identity
const { CosmosClient } = require("@azure/cosmos");

async function createCosmosClient() {
  const endpoint = process.env.COSMOS_ENDPOINT;
  const credential = new DefaultAzureCredential();

  const client = new CosmosClient({
    endpoint: endpoint,
    aadCredentials: credential  // Use AAD authentication
  });

  return client;
}

// ========================================
// AWS SDK WITH IAM ROLES
// ========================================

// SECURE: AWS SDK uses IAM role automatically (no credentials needed)
const AWS = require('aws-sdk');

// When running in AWS (EC2, ECS, Lambda), the SDK automatically uses
// the IAM role attached to the resource. No credentials needed!
const s3 = new AWS.S3();
const dynamodb = new AWS.DynamoDB();

// SECURE: For local development, use AWS profiles
AWS.config.credentials = new AWS.SharedIniFileCredentials({
  profile: process.env.AWS_PROFILE || 'default'
});

// ========================================
// SERVICE BUS WITH MANAGED IDENTITY
// ========================================

// SECURE: Azure Service Bus with DefaultAzureCredential
const { ServiceBusClient } = require("@azure/service-bus");

const fullyQualifiedNamespace = process.env.SERVICE_BUS_FQDN;
const credential = new DefaultAzureCredential();

const serviceBusClient = new ServiceBusClient(
  fullyQualifiedNamespace,
  credential
);

// ========================================
// EMAIL SERVICE WITH ENVIRONMENT CONFIG
// ========================================

// SECURE: Email configuration from environment
const nodemailer = require('nodemailer');

const emailTransporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD  // From environment, not hardcoded
  }
});

// ========================================
// ENCRYPTION WITH SECURE KEY MANAGEMENT
// ========================================

// SECURE: Encryption key from Azure Key Vault or environment
const crypto = require('crypto');

async function getEncryptionKey() {
  // Option 1: From environment (base64 encoded)
  if (process.env.ENCRYPTION_KEY) {
    return Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
  }

  // Option 2: From Azure Key Vault
  const keyVaultName = process.env.KEY_VAULT_NAME;
  const vaultUrl = `https://${keyVaultName}.vault.azure.net`;
  const credential = new DefaultAzureCredential();
  const secretClient = new SecretClient(vaultUrl, credential);
  const secret = await secretClient.getSecret('encryption-key');

  return Buffer.from(secret.value, 'base64');
}

async function encrypt(text) {
  const key = await getEncryptionKey();
  const iv = crypto.randomBytes(16);  // Generate random IV for each encryption

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(text, 'utf8'),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  // Return IV + authTag + encrypted data (all needed for decryption)
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

// ========================================
// PAYMENT SERVICE WITH SECURE CONFIG
// ========================================

// SECURE: Payment service using environment variables
class SecurePaymentService {
  constructor() {
    this.apiKey = process.env.STRIPE_SECRET_KEY;
    this.endpoint = process.env.STRIPE_API_ENDPOINT || 'https://api.stripe.com/v1';

    if (!this.apiKey) {
      throw new Error('STRIPE_SECRET_KEY environment variable not set');
    }
  }

  async processPayment(amount) {
    return fetch(this.endpoint + '/charges', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ amount })
    });
  }
}

// ========================================
// DEVELOPMENT VS PRODUCTION
// ========================================

// SECURE: Different configurations for dev vs prod
const isDevelopment = process.env.NODE_ENV === 'development';

const appConfig = {
  // For development, can use .env file (not committed to git)
  apiKey: process.env.API_KEY,

  // For production, use managed identity
  useManagedIdentity: !isDevelopment,

  // Security headers
  helmet: {
    contentSecurityPolicy: true,
    hsts: true
  }
};

// ========================================
// EXAMPLE: COMPLETE SECURE SETUP
// ========================================

// SECURE: Complete example with all best practices
async function initializeApp() {
  // 1. Validate required environment variables
  const requiredEnvVars = [
    'AZURE_STORAGE_ACCOUNT_NAME',
    'KEY_VAULT_NAME',
    'COSMOS_ENDPOINT',
    'SERVICE_BUS_FQDN'
  ];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      throw new Error(`Required environment variable ${envVar} is not set`);
    }
  }

  // 2. Initialize DefaultAzureCredential once
  const credential = new DefaultAzureCredential();

  // 3. Initialize all Azure clients with managed identity
  const storageClient = new BlobServiceClient(
    `https://${process.env.AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net`,
    credential
  );

  const cosmosClient = new CosmosClient({
    endpoint: process.env.COSMOS_ENDPOINT,
    aadCredentials: credential
  });

  const serviceBusClient = new ServiceBusClient(
    process.env.SERVICE_BUS_FQDN,
    credential
  );

  // 4. Load secrets from Key Vault
  const keyVaultUrl = `https://${process.env.KEY_VAULT_NAME}.vault.azure.net`;
  const secretClient = new SecretClient(keyVaultUrl, credential);

  const jwtSecret = await secretClient.getSecret('jwt-secret');
  const encryptionKey = await secretClient.getSecret('encryption-key');

  return {
    storage: storageClient,
    database: cosmosClient,
    messaging: serviceBusClient,
    secrets: {
      jwtSecret: jwtSecret.value,
      encryptionKey: encryptionKey.value
    }
  };
}

// ========================================
// TEST FIXTURES (FALSE POSITIVES)
// ========================================

// These look like secrets but are actually test fixtures
// Use clear naming or comments to indicate they're not real

const TEST_JWT_SECRET = 'test-secret-for-unit-tests-only';  // OK: Clearly labeled as test
const EXAMPLE_API_KEY = 'example_key_1234567890';  // OK: "example" indicates not real
const MOCK_CONNECTION_STRING = 'Server=localhost;Database=test;';  // OK: Clearly for testing

// For test files, you can also disable Semgrep rules:
// nosemgrep: hardcoded-jwt-secret
const UNIT_TEST_SECRET = 'unit-test-secret-12345';

// ========================================
// SUMMARY
// ========================================

/*
This file demonstrates secure patterns:

1. AZURE STORAGE: Use DefaultAzureCredential with managed identity
2. API KEYS: Load from environment variables, never hardcode
3. JWT: Secret from environment, specify algorithm, set expiration
4. DATABASES: Connection strings from environment, use managed identity when possible
5. AWS: Use IAM roles, never hardcode credentials
6. SECRETS: Use Azure Key Vault or equivalent secret management service
7. ENCRYPTION: Keys from secure storage, random IVs, authenticated encryption

DEPLOYMENT CHECKLIST:
- [ ] All secrets in environment variables or Key Vault
- [ ] Managed identity enabled for Azure resources
- [ ] IAM roles configured for AWS resources
- [ ] .env file in .gitignore (never commit)
- [ ] Validation for required environment variables
- [ ] Different configurations for dev/staging/prod
- [ ] Secrets rotated regularly
- [ ] Audit logging enabled for secret access

This file should produce ZERO Semgrep findings!
*/

module.exports = {
  initializeApp,
  SecurePaymentService,
  encrypt
};
