// Sentinel™ Tactical Test Suite
const express = require('express');
const app = express();

// 1. ES6 Destructuring + Open Redirect (CWE-601)
app.post('/goto', (req, res) => {
    const { targetDest, nonce } = req.body;
    // VULNERABLE: targetDest is user-controlled
    res.redirect(targetDest);
});

// 2. Variable Alias + IDOR (CWE-639)
app.get('/api/user', (req, res) => {
    const uid = req.query.id;
    // VULNERABLE: No ownership check for uid
    db.query("SELECT * FROM profiles WHERE user_id = " + uid);
});

// 3. Parameter Tampering (CWE-472)
app.post('/checkout', (req, res) => {
    const { amt } = req.body;
    // VULNERABLE: amt assigned directly to price
    const order = {
        item: "Premium Armor",
        price: amt
    };
    db.save(order);
});

// 4. SECURE CASE: Should NOT be flagged
app.get('/safe-redirect', (req, res) => {
    const { dest } = req.query;
    const whitelist = ['/dashboard', '/settings'];
    if (whitelist.includes(dest)) {
        res.redirect(dest);
    }
});
