/**
 * IDOR Vulnerable Application Server
 * ===================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * This server demonstrates IDOR vulnerabilities in a multi-tenant application.
 * Use the scanner in ../scanner/ to detect these vulnerabilities.
 */

const express = require('express');
const documentsRouter = require('./api/documents');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Mount API routes
app.use('/api', documentsRouter);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    warning: 'This application contains intentional IDOR vulnerabilities'
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`IDOR Demo App running on port ${PORT}`);
  console.log('WARNING: Contains intentional security vulnerabilities');
});

module.exports = app;
