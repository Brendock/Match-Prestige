const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse JSON bodies
app.use(bodyParser.json({ verify: (req, res, buf) => {
  // Store raw body for HMAC calculation
  req.rawBody = buf;
}}));

// Utility to calculate HMAC using Shopify API secret
function verifyHmac(rawBody, hmacHeader, secret) {
  if (!hmacHeader || !secret) return false;
  try {
    const digest = crypto
      .createHmac('sha256', secret)
      .update(rawBody, 'utf8')
      .digest('base64');
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader));
  } catch (err) {
    return false;
  }
}

// Health check / GET endpoint
app.get('/sync', (req, res) => {
  res.json({ status: 'ok', message: 'Match Prestige sync service is running', timestamp: new Date().toISOString() });
});

// POST endpoint for sync
app.post('/sync', (req, res) => {
  const hmacHeader = req.get('x-shopify-hmac-sha256') || req.get('X-Shopify-Hmac-Sha256');
  const secret = process.env.SHOPIFY_API_SECRET;
  const isValid = verifyHmac(req.rawBody, hmacHeader, secret);
  if (!isValid) {
    return res.status(401).json({ status: 'error', message: 'Invalid HMAC signature' });
  }
  // Example processing: echo back the received payload
  res.json({ status: 'success', received: req.body });
});
app.listen(port, () => {
  console.log(`Match Prestige sync service listening at http://localhost:${port}`);
});
