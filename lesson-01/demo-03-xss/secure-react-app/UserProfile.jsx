/**
 * XSS SECURE React Component
 * ==========================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * This component demonstrates secure coding patterns to prevent XSS.
 *
 * Key Security Patterns:
 * 1. DOMPurify for HTML sanitization
 * 2. URL validation for href attributes
 * 3. Input validation and encoding
 * 4. No eval() or document.write()
 * 5. CSS property whitelisting
 */

import React, { useState, useEffect, useMemo } from 'react';
import DOMPurify from 'dompurify';

// Configure DOMPurify
const DOMPURIFY_CONFIG = {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
  ALLOWED_ATTR: ['href', 'title'],
  ALLOW_DATA_ATTR: false,
  ADD_ATTR: ['target'],  // Allow target attribute
  FORBID_TAGS: ['script', 'style', 'iframe', 'form', 'input'],
  FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover']
};

// URL validation helper
const isValidUrl = (urlString) => {
  try {
    const url = new URL(urlString);
    // SECURE: Only allow http and https protocols
    return ['http:', 'https:'].includes(url.protocol);
  } catch {
    return false;
  }
};

// CSS property whitelist
const ALLOWED_CSS_COLORS = /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$|^rgb\(\d{1,3},\s*\d{1,3},\s*\d{1,3}\)$/;

function UserProfile() {
  const [username, setUsername] = useState('');
  const [bio, setBio] = useState('');
  const [website, setWebsite] = useState('');
  const [comment, setComment] = useState('');
  const [comments, setComments] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [backgroundColor, setBackgroundColor] = useState('#ffffff');

  // ==========================================================================
  // SECURE: Sanitize bio HTML with DOMPurify
  // ==========================================================================
  const sanitizedBio = useMemo(() => {
    return DOMPurify.sanitize(bio, DOMPURIFY_CONFIG);
  }, [bio]);

  const renderBio = () => {
    return (
      <div className="bio-section">
        <h3>About Me</h3>
        {/* SECURE: HTML sanitized with DOMPurify before rendering */}
        <div dangerouslySetInnerHTML={{ __html: sanitizedBio }} />
      </div>
    );
  };

  // ==========================================================================
  // SECURE: Validate URL before rendering as link
  // ==========================================================================
  const renderWebsiteLink = () => {
    // SECURE: Validate URL protocol
    if (!website || !isValidUrl(website)) {
      return website ? (
        <div className="website-link error">
          Invalid URL format. Please use https://
        </div>
      ) : null;
    }

    return (
      <div className="website-link">
        {/* SECURE: URL validated, rel="noopener noreferrer" added */}
        <a
          href={website}
          target="_blank"
          rel="noopener noreferrer"
        >
          Visit my website
        </a>
      </div>
    );
  };

  // ==========================================================================
  // SECURE: Sanitize comments before storing and displaying
  // ==========================================================================
  const handleAddComment = () => {
    const trimmedComment = comment.trim();
    if (trimmedComment) {
      // SECURE: Sanitize comment text before storing
      const sanitizedComment = DOMPurify.sanitize(trimmedComment, {
        ALLOWED_TAGS: [],  // Strip all HTML tags from comments
        ALLOWED_ATTR: []
      });

      setComments([...comments, {
        id: Date.now(),
        text: sanitizedComment,
        author: DOMPurify.sanitize(username || 'Anonymous', { ALLOWED_TAGS: [] }),
        timestamp: new Date().toISOString()
      }]);
      setComment('');
    }
  };

  const renderComments = () => {
    return (
      <div className="comments-section">
        <h3>Comments</h3>
        {comments.map(c => (
          <div key={c.id} className="comment">
            {/* SECURE: Text rendered with React's automatic escaping */}
            <strong>{c.author}:</strong>
            <span>{c.text}</span>
            <small>{new Date(c.timestamp).toLocaleString()}</small>
          </div>
        ))}
      </div>
    );
  };

  // ==========================================================================
  // SECURE: URL parameter handling with sanitization
  // ==========================================================================
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const searchParam = urlParams.get('search');

    if (searchParam) {
      // SECURE: Sanitize URL parameter
      const sanitizedSearch = DOMPurify.sanitize(searchParam, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: []
      });
      setSearchQuery(sanitizedSearch);
    }
  }, []);

  // ==========================================================================
  // SECURE: Error messages with proper encoding
  // ==========================================================================
  const handleFormSubmit = () => {
    if (!username || username.length < 3) {
      // SECURE: Error message uses React's automatic encoding
      setErrorMessage('Username must be at least 3 characters long.');
      return;
    }

    if (username.length > 50) {
      setErrorMessage('Username must be less than 50 characters.');
      return;
    }

    // Validate username format
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      setErrorMessage('Username can only contain letters, numbers, and underscores.');
      return;
    }

    setErrorMessage('');
    // Process valid form...
    console.log('Profile saved:', { username, bio: sanitizedBio, website });
  };

  // ==========================================================================
  // SECURE: Calculate age without eval()
  // ==========================================================================
  const calculateAge = (birthYear) => {
    // SECURE: Parse integer, no eval()
    const year = parseInt(birthYear, 10);
    if (isNaN(year) || year < 1900 || year > new Date().getFullYear()) {
      return null;
    }
    return new Date().getFullYear() - year;
  };

  // ==========================================================================
  // SECURE: CSS property validation
  // ==========================================================================
  const validatedBackgroundColor = useMemo(() => {
    // SECURE: Only allow valid hex colors or rgb values
    if (ALLOWED_CSS_COLORS.test(backgroundColor)) {
      return backgroundColor;
    }
    return '#ffffff';  // Default to white if invalid
  }, [backgroundColor]);

  const containerStyle = {
    // SECURE: Validated CSS property
    backgroundColor: validatedBackgroundColor,
    padding: '20px',
    borderRadius: '8px'
  };

  return (
    <div style={containerStyle} className="user-profile">
      <h1>User Profile (Secure)</h1>

      {/* SECURE: Error message with React's automatic encoding */}
      {errorMessage && (
        <div className="error" role="alert">
          {errorMessage}
        </div>
      )}

      {/* SECURE: Search query displayed safely */}
      {searchQuery && (
        <div id="search-results">
          Search results for: {searchQuery}
        </div>
      )}

      {/* Form inputs with validation */}
      <div className="form-group">
        <label htmlFor="username">Username:</label>
        <input
          id="username"
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Enter username"
          maxLength={50}
          pattern="[a-zA-Z0-9_]+"
        />
      </div>

      <div className="form-group">
        <label htmlFor="bio">Bio (limited HTML allowed):</label>
        <textarea
          id="bio"
          value={bio}
          onChange={(e) => setBio(e.target.value)}
          placeholder="Tell us about yourself... (limited HTML: b, i, em, strong, a, p, br, ul, ol, li)"
          rows={4}
        />
        <small>Allowed tags: b, i, em, strong, a, p, br, ul, ol, li</small>
      </div>

      <div className="form-group">
        <label htmlFor="website">Website URL:</label>
        <input
          id="website"
          type="url"
          value={website}
          onChange={(e) => setWebsite(e.target.value)}
          placeholder="https://your-website.com"
        />
        {website && !isValidUrl(website) && (
          <small className="error">Please enter a valid https:// URL</small>
        )}
      </div>

      <div className="form-group">
        <label htmlFor="bgColor">Background Color:</label>
        <input
          id="bgColor"
          type="text"
          value={backgroundColor}
          onChange={(e) => setBackgroundColor(e.target.value)}
          placeholder="#ffffff"
          pattern="^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$"
        />
        <small>Format: #fff or #ffffff</small>
      </div>

      <button onClick={handleFormSubmit}>Save Profile</button>

      {/* Bio display - SECURE */}
      {renderBio()}

      {/* Website link - SECURE */}
      {renderWebsiteLink()}

      {/* Comments section - SECURE */}
      <div className="add-comment">
        <h3>Add Comment</h3>
        <textarea
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          placeholder="Write a comment... (HTML will be stripped)"
        />
        <button onClick={handleAddComment}>Post Comment</button>
      </div>

      {renderComments()}
    </div>
  );
}

export default UserProfile;

/**
 * Security Measures Implemented:
 * ==============================
 *
 * 1. DOMPurify Sanitization
 *    - All user HTML input sanitized before rendering
 *    - Strict whitelist of allowed tags and attributes
 *    - Dangerous tags (script, style, iframe) explicitly forbidden
 *
 * 2. URL Validation
 *    - Only http/https protocols allowed for links
 *    - javascript: and data: URLs blocked
 *    - rel="noopener noreferrer" on external links
 *
 * 3. Input Validation
 *    - Username pattern validation
 *    - Maximum length limits
 *    - Input type hints (url, text)
 *
 * 4. Output Encoding
 *    - React's automatic JSX encoding for text content
 *    - No direct innerHTML without sanitization
 *
 * 5. CSS Validation
 *    - Color values validated against whitelist pattern
 *    - Invalid values fall back to safe default
 *
 * 6. No Dangerous Functions
 *    - No eval() with user input
 *    - No document.write()
 *    - No innerHTML without sanitization
 */
