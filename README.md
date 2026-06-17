# Sentinel™ Security Code Sandbox & Attack Simulation Tree (ADST)

A comprehensive application security training platform featuring an interactive code sandbox, vulnerability analysis, and attack simulation tree visualization.

## Overview

Sentinel is an educational security tool designed to help developers and security professionals understand common application vulnerabilities through hands-on analysis and interactive attack simulations. The platform combines a modern web interface with a powerful Python CLI tool for vulnerability detection and remediation guidance.

## Features

- **Interactive Web Dashboard**: Real-time vulnerability analysis and visualization
- **Attack Simulation Tree (ADST)**: Visual representation of attack paths and exploitation techniques
- **Python CLI Tool**: Standalone terminal interface for security analysis
- **Vulnerable Code Samples**: Training files with intentional security flaws
- **Remediation Guidance**: Detailed fix recommendations for each vulnerability
- **Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices
- **Offline Support**: All analysis runs locally without internet dependency

## Architecture

### System Components

```
Sentinel/
├── frontend/              # React web interface
│   └── index.html        # Single-page application
├── backend/              # Express.js API server
│   └── server.js         # REST API endpoints
├── python_cli/           # Python security analyzer
│   └── sentinel.py       # Interactive TUI tool
├── target_code/          # Vulnerable training code
│   ├── auth.ts          # Authentication vulnerabilities
│   └── payments.ts      # Payment processing vulnerabilities
└── package.json         # Node.js dependencies
```

### Technology Stack

- **Frontend**: Vanilla JavaScript (responsive, no framework dependencies)
- **Backend**: Node.js with Express.js
- **CLI Tool**: Python 3 with Rich library for TUI
- **Styling**: CSS3 with modern gradients and animations
- **Compatibility**: All modern browsers, Python 3.6+

## Installation

### Prerequisites

- Node.js 16+ and npm/yarn
- Python 3.6+
- Git

### Quick Start

1. **Clone or extract the repository**
   ```bash
   cd sentinel-security-adst
   ```

2. **Install Node.js dependencies**
   ```bash
   npm install
   ```

3. **Install Python dependencies**
   ```bash
   pip install rich requests
   ```

4. **Start the backend server**
   ```bash
   npm start
   ```
   The server will run on `http://localhost:3000`

5. **Access the web interface**
   Open your browser and navigate to `http://localhost:3000`

## Usage

### Web Dashboard

The web interface provides:

1. **Vulnerabilities Panel**: Lists all detected security issues with severity ratings
2. **Target Files Panel**: Shows available training code files
3. **Code Viewer**: Displays source code with syntax highlighting
4. **Attack Simulation Tree**: Interactive visualization of attack paths and remediations

**Navigation**:
- Click on any vulnerability to view detailed attack paths
- Click on any file to view its source code
- All panels are responsive and mobile-friendly

### Python CLI Tool

Run the interactive security analyzer:

```bash
cd python_cli
python sentinel.py
```

**Menu Options**:
1. **Refresh vulnerability analysis** - Scan and display all detected vulnerabilities
2. **Download external file** - Fetch remote code files into the sandbox
3. **View source code** - Display syntax-highlighted code in terminal
4. **Exit** - Close the application

**Example Session**:
```
Select option [1-4]: 1
[Displays vulnerability tree with attack paths]

Select option [1-4]: 3
Select file:
  [0] auth.ts
  [1] payments.ts
Enter index: 0
[Displays auth.ts source code with syntax highlighting]
```

## Vulnerabilities Covered

### 1. Insecure Direct Object Reference (IDOR)

**File**: `auth.ts`
**Severity**: CRITICAL (9.1/10)
**CWE**: CWE-639

**Description**: User profile queries based on unvalidated client input without session verification.

**Attack Path**:
1. Attacker logs in as user_1002
2. Attacker modifies URL parameter from user_1002 to admin_9999
3. System returns admin profile without authorization check
4. Attacker gains full administrative access

**Remediation**:
```typescript
// VULNERABLE
const profile = USER_DATABASE[userId];

// FIXED
if (req.session.userId !== userId) {
  return res.status(403).json({ error: "Unauthorized" });
}
const profile = USER_DATABASE[userId];
```

### 2. Open Redirection Vulnerability

**File**: `auth.ts`
**Severity**: HIGH (7.4/10)
**CWE**: CWE-601

**Description**: Server redirects to user-supplied URLs without domain validation.

**Attack Path**:
1. Attacker crafts phishing email with redirect link
2. Link redirects victim to malicious domain clone
3. User enters credentials on fake login page
4. Attacker captures credentials

**Remediation**:
```typescript
// VULNERABLE
if (redirectTo) {
  return res.redirect(redirectTo);
}

// FIXED
const ALLOWED_DOMAINS = ["example.com", "www.example.com"];
const redirectUrl = new URL(redirectTo);
if (!ALLOWED_DOMAINS.includes(redirectUrl.hostname)) {
  return res.status(403).json({ error: "Invalid redirect" });
}
return res.redirect(redirectTo);
```

### 3. Parameter Tampering - Price Manipulation

**File**: `payments.ts`
**Severity**: CRITICAL (9.3/10)
**CWE**: CWE-434

**Description**: System trusts client-side price values without server-side verification.

**Attack Path**:
1. Attacker modifies HTML form price field to $0.01
2. System processes tampered price on checkout
3. Payment gateway charges minimal amount
4. Attacker completes fraud transaction

**Remediation**:
```typescript
// VULNERABLE
const totalAmount = quantity * singleUnitPrice;

// FIXED
const actualPrice = await getProductPriceFromDatabase(itemId);
if (actualPrice !== singleUnitPrice) {
  return res.status(400).json({ error: "Price mismatch" });
}
const totalAmount = quantity * actualPrice;
```

## API Endpoints

### GET `/api/vulnerabilities`
Returns list of all detected vulnerabilities.

**Response**:
```json
{
  "vulnerabilities": [
    {
      "id": "idor",
      "name": "Insecure Direct Object Reference",
      "severity": "CRITICAL",
      "score": "9.1/10",
      "description": "User profile queries based on unvalidated client input",
      "file": "auth.ts"
    }
  ]
}
```

### GET `/api/vulnerability/:id`
Returns detailed information about a specific vulnerability.

**Response**:
```json
{
  "id": "idor",
  "name": "Insecure Direct Object Reference",
  "severity": "CRITICAL",
  "score": "9.1/10",
  "cwe": "CWE-639",
  "description": "...",
  "attackSteps": ["step1", "step2", ...],
  "remediation": "...",
  "codeExample": "..."
}
```

### GET `/api/files`
Returns list of available training code files.

**Response**:
```json
{
  "files": [
    {
      "name": "auth.ts",
      "size": "2.5 KB",
      "vulnerabilities": ["idor", "open_redirect"]
    }
  ]
}
```

## Responsive Design

Sentinel is fully responsive and optimized for:

- **Desktop** (1920x1080 and above): Full dashboard with side-by-side panels
- **Tablet** (768px - 1024px): Stacked layout with touch-friendly controls
- **Mobile** (320px - 767px): Single-column layout with optimized spacing

**Responsive Features**:
- Flexible grid layout that adapts to screen size
- Touch-friendly button sizes and spacing
- Readable font sizes across all devices
- Optimized code viewer for small screens
- Sticky header for easy navigation

## Development

### Project Structure

```
.
├── frontend/
│   └── index.html          # Web UI (vanilla JS)
├── backend/
│   └── server.js           # Express API server
├── python_cli/
│   └── sentinel.py         # Python CLI tool
├── target_code/
│   ├── auth.ts            # Training vulnerability files
│   └── payments.ts
├── package.json           # Node dependencies
└── README.md             # This file
```

### Running in Development

```bash
# Terminal 1: Start backend server
npm start

# Terminal 2: Open browser to http://localhost:3000
# Terminal 3: Run Python CLI
cd python_cli && python sentinel.py
```

### Code Guidelines

- All code is in English
- Comments explain vulnerability concepts
- Consistent indentation (2 spaces for JS, 4 spaces for Python)
- No external UI frameworks (vanilla JavaScript)
- Responsive CSS without media query breakpoints

## Security Considerations

**Important**: Sentinel is designed for **educational purposes only**. The vulnerable code samples are intentionally flawed to demonstrate security concepts. Never use this code in production environments.

### Best Practices

1. Always validate user input on the server side
2. Never trust client-side data for security decisions
3. Use parameterized queries to prevent injection attacks
4. Implement proper session management
5. Use HTTPS in production
6. Keep dependencies updated
7. Conduct regular security audits

## Contributing

Contributions are welcome! Please ensure:
- All code is in English
- Changes maintain responsive design
- New vulnerabilities include attack paths and remediations
- Code follows existing style guidelines

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or suggestions:
1. Check existing documentation
2. Review vulnerability details in the web interface
3. Run the Python CLI for detailed analysis
4. Consult OWASP resources for additional context

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## Changelog

### Version 1.0.0
- Initial release
- Web dashboard with vulnerability analysis
- Python CLI tool with TUI interface
- Three training vulnerabilities (IDOR, Open Redirect, Price Tampering)
- Fully responsive design
- Complete API documentation

---

**Sentinel™** - Secure Coding Through Simulation
