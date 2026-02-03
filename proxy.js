const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const querystring = require('querystring');

const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

/**
 * Verify Shopify App Proxy signature.
 *
 * Shopify app proxies include a `signature` query parameter that is used to
 * verify the authenticity of the request. The signature is calculated by
 * concatenating all other query parameters (sorted lexicographically) without
 * any separators, then computing an HMAC using the app's API secret and
 * encoding the result as a hex string. See Shopify documentation for details:
 * https://shopify.dev/docs/apps/build/online-store/app-proxies/authenticate-app-proxies
 *
 * @param {object} req Express request object
 * @param {string} secret Shared secret for the app
 * @returns {boolean} True if signature is valid, false otherwise
 */
function verifyAppProxySignature(req, secret) {
  if (!secret) return false;
  const rawQuery = (req.originalUrl.split('?')[1] || '');
  const params = querystring.parse(rawQuery);

  const signature = params.signature;
  if (!signature || typeof signature !== 'string') {
    return false;
  }
  delete params.signature;

  const message = Object.keys(params)
    .map((key) => {
      const value = params[key];
      const valueString = Array.isArray(value) ? value.join(',') : (value ?? '');
      return `${key}=${valueString}`;
    })
    .sort()
    .join('');

  const digest = crypto
    .createHmac('sha256', secret)
    .update(message)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
  } catch {
    return false;
  }
}

// Health check / GET endpoint
app.get('/sync', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Match Prestige sync service is running',
    timestamp: new Date().toISOString(),
  });
});

// POST endpoint for sync via App Proxy
app.post('/sync', (req, res) => {
  const secret = process.env.SHOPIFY_API_SECRET;
  const isValid = verifyAppProxySignature(req, secret);
  if (!isValid) {
    return res.status(401).json({ status: 'error', message: 'Invalid App Proxy signature' });
  }
  // Example processing: echo back the received payload
  res.json({ status: 'success', received: req.body });
});

app.listen(port, () => {
  console.log(`Match Prestige sync service listening at http://localhost:${port}`);
});
