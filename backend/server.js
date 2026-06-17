import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());
app.use(express.json());

// Serve static files from frontend
app.use(express.static(path.join(__dirname, '../frontend/dist')));

// API Routes
app.get('/api/vulnerabilities', (req, res) => {
  res.json({
    vulnerabilities: [
      {
        id: 'idor',
        name: 'Insecure Direct Object Reference',
        severity: 'CRITICAL',
        score: '9.1/10',
        description: 'User profile queries based on unvalidated client input',
        file: 'auth.ts'
      },
      {
        id: 'open_redirect',
        name: 'Open Redirection Vulnerability',
        severity: 'HIGH',
        score: '7.4/10',
        description: 'Server redirects to user-supplied URLs without validation',
        file: 'auth.ts'
      },
      {
        id: 'price_tampering',
        name: 'Parameter Tampering - Price Manipulation',
        severity: 'CRITICAL',
        score: '9.3/10',
        description: 'System trusts client-side price values without verification',
        file: 'payments.ts'
      }
    ]
  });
});

app.get('/api/vulnerability/:id', (req, res) => {
  const vulnerabilityDetails = {
    idor: {
      id: 'idor',
      name: 'Insecure Direct Object Reference',
      severity: 'CRITICAL',
      score: '9.1/10',
      cwe: 'CWE-639',
      description: 'User profile queries based on unvalidated client input without session verification',
      attackSteps: [
        'Attacker logs in as user_1002',
        'Attacker modifies URL parameter from user_1002 to admin_9999',
        'System returns admin profile without authorization check',
        'Attacker gains full administrative access'
      ],
      remediation: 'Validate userId against req.session.userId before database queries',
      codeExample: 'const profile = USER_DATABASE[userId]; // VULNERABLE\n// FIX: if (req.session.userId !== userId) return 403;'
    },
    open_redirect: {
      id: 'open_redirect',
      name: 'Open Redirection Vulnerability',
      severity: 'HIGH',
      score: '7.4/10',
      cwe: 'CWE-601',
      description: 'Server redirects to user-supplied URLs without domain validation',
      attackSteps: [
        'Attacker crafts phishing email with redirect link',
        'Link redirects victim to malicious domain clone',
        'User enters credentials on fake login page',
        'Attacker captures credentials'
      ],
      remediation: 'Implement whitelist of allowed redirect domains',
      codeExample: 'if (redirectTo) return res.redirect(redirectTo); // VULNERABLE\n// FIX: const allowedDomains = ["example.com"]; if (!allowedDomains.includes(new URL(redirectTo).hostname)) return 403;'
    },
    price_tampering: {
      id: 'price_tampering',
      name: 'Parameter Tampering - Price Manipulation',
      severity: 'CRITICAL',
      score: '9.3/10',
      cwe: 'CWE-434',
      description: 'System trusts client-side price values without server-side verification',
      attackSteps: [
        'Attacker modifies HTML form price field to $0.01',
        'System processes tampered price on checkout',
        'Payment gateway charges minimal amount',
        'Attacker completes fraud transaction'
      ],
      remediation: 'Fetch actual prices from server-side database, never trust client input',
      codeExample: 'const totalAmount = quantity * singleUnitPrice; // VULNERABLE\n// FIX: const actualPrice = await getProductPrice(itemId); const totalAmount = quantity * actualPrice;'
    }
  };

  const vuln = vulnerabilityDetails[req.params.id];
  if (vuln) {
    res.json(vuln);
  } else {
    res.status(404).json({ error: 'Vulnerability not found' });
  }
});

app.get('/api/files', (req, res) => {
  res.json({
    files: [
      { name: 'auth.ts', size: '2.5 KB', vulnerabilities: ['idor', 'open_redirect'] },
      { name: 'payments.ts', size: '1.8 KB', vulnerabilities: ['price_tampering'] }
    ]
  });
});

// Fallback to index.html for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/dist/index.html'));
});

app.listen(PORT, () => {
  console.log(`Sentinel server running on http://localhost:${PORT}`);
});
