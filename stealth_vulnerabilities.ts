// Sentinel™ Tactical Test: Multi-Hop Taint Tracking
const express = require('express');
const app = express();

// 1. Multi-Hop Open Redirect (CWE-601)
app.post('/redirect-hop', (req, res) => {
    const initialUrl = req.body.target;
    const secondHop = initialUrl;
    const finalUrl = secondHop;
    // VULNERABLE: Taint propagated through 3 variables
    res.redirect(finalUrl);
});

// 2. Multi-Hop IDOR (CWE-639)
app.get('/invoice/:id', (req, res) => {
    const { id: invoiceId } = req.params;
    const lookupId = invoiceId;
    const finalId = lookupId;
    // VULNERABLE: Taint propagated through destructuring and aliases
    db.query("SELECT * FROM invoices WHERE id = " + finalId);
});

// 3. Expanded Semantic Keywords (CWE-472)
app.post('/update-billing', (req, res) => {
    const { unitCost } = req.body;
    const newRate = unitCost;
    // VULNERABLE: 'unitCost' is a sensitive keyword
    const profile = {
        rate: newRate
    };
    db.save(profile);
});
