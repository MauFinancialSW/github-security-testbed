/**
 * Vulnerable React Application - Main App Component
 * =================================================
 * Course: GitHub Copilot for Cybersecurity Specialists
 * Lesson: 01 - Vulnerability Detection
 *
 * WARNING: This application contains intentional security vulnerabilities.
 * DO NOT use in production environments.
 */

import React from 'react';
import UserProfile from './UserProfile';

function App() {
  return (
    <div className="app">
      <header className="app-header">
        <h1>Vulnerable React Demo</h1>
        <p className="warning">
          This application contains intentional XSS vulnerabilities
          for educational purposes.
        </p>
      </header>

      <main>
        <UserProfile />
      </main>

      <footer>
        <p>GitHub Copilot for Cybersecurity Specialists - Lesson 01</p>
      </footer>
    </div>
  );
}

export default App;
