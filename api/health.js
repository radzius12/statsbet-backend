// api/health.js
const { publicEndpoint } = require('../lib/auth');

async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  res.json({ 
    status: 'OK', 
    message: 'StatsBet API is running on Vercel WITHOUT email verification',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
}

module.exports = publicEndpoint(handler);