// lib/auth.js - Authentication middleware
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// CORS headers
function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://statsbet.pl');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}

// Handle CORS preflight
function handleCors(req, res, next) {
  setCorsHeaders(res);
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
}

// Auth middleware
function authenticateToken(handler) {
  return async (req, res) => {
    // Handle CORS first
    setCorsHeaders(res);
    
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    try {
      const user = jwt.verify(token, JWT_SECRET);
      req.user = user;
      return handler(req, res);
    } catch (error) {
      return res.status(403).json({ error: 'Invalid token' });
    }
  };
}

// Public endpoint wrapper
function publicEndpoint(handler) {
  return async (req, res) => {
    setCorsHeaders(res);
    
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }
    
    return handler(req, res);
  };
}

module.exports = {
  authenticateToken,
  publicEndpoint,
  setCorsHeaders,
  handleCors,
  JWT_SECRET
};