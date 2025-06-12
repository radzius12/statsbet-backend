// api/auth/login.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { publicEndpoint, JWT_SECRET } = require('../../lib/auth');
const { getOne, initializeDatabase } = require('../../lib/db');

async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Initialize database tables
  await initializeDatabase();

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email i hasło są wymagane' });
  }

  try {
    const user = await getOne('SELECT * FROM users WHERE email = $1', [email]);

    if (!user) {
      return res.status(400).json({ error: 'Nieprawidłowe dane logowania' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Nieprawidłowe dane logowania' });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Logowanie pomyślne',
      token,
      user: { 
        id: user.id, 
        username: user.username, 
        email: user.email,
        initialAmount: user.initial_amount,
        taxRate: user.tax_rate
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Błąd serwera' });
  }
}

module.exports = publicEndpoint(handler);