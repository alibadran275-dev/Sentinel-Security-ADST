// Sentinel™ Tactical Test: Trust Boundaries & False Positives
const express = require('express');
const app = express();

// 1. Trust Boundary: Server-side Price Fetching
app.post('/purchase', async (req, res) => {
    const { productId, quantity } = req.body;
    
    // SECURE: price is fetched from DB, not from request
    const price = await db.lookup('products', productId).price;
    
    const total = price * quantity;
    
    const order = {
        item: productId,
        cost: total // SHOULD NOT BE FLAGGED: price is trusted
    };
    db.save(order);
});

// 2. Multi-line Validation (CWE-601)
app.get('/safe-goto', (req, res) => {
    const { dest } = req.query;
    
    // VALIDATION BLOCK
    const allowed = ['/home', '/about'];
    if (allowed.includes(dest)) {
        res.redirect(dest); // SHOULD NOT BE FLAGGED
    }
});
