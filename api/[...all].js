// SUPER PROSTY API Handler - na pewno zadziała
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';
const db = new sqlite3.Database('/tmp/statsbet.db');

// Initialize tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    initial_amount REAL DEFAULT 1000,
    tax_rate REAL DEFAULT 12,
    verified INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS bets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    bet_type TEXT NOT NULL,
    bet_category TEXT NOT NULL,
    odds REAL NOT NULL,
    stake REAL NOT NULL,
    potential_win REAL NOT NULL,
    result TEXT,
    profile_id TEXT DEFAULT 'default',
    sport TEXT,
    note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const path = req.query.all ? req.query.all.join('/') : '';
  
  try {
    // HEALTH CHECK - ZAWSZE PIERWSZY!
    if (path === 'health' && req.method === 'GET') {
      return res.status(200).json({
        status: 'OK',
        message: 'StatsBet API is running WITHOUT email verification',
        timestamp: new Date().toISOString(),
        method: req.method,
        path: path
      });
    }

    // REGISTER
    if (path === 'register' && req.method === 'POST') {
      const { username, email, password } = req.body;

      if (!username || !email || !password) {
        return res.status(400).json({ error: 'Wszystkie pola są wymagane' });
      }

      if (password.length < 6) {
        return res.status(400).json({ error: 'Hasło musi mieć minimum 6 znaków' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      
      return new Promise((resolve) => {
        db.run(
          'INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, ?)',
          [username.trim(), email.trim().toLowerCase(), hashedPassword, 1],
          function(err) {
            if (err) {
              if (err.message.includes('UNIQUE constraint failed')) {
                res.status(400).json({ error: 'Użytkownik o tym emailu już istnieje' });
              } else {
                res.status(500).json({ error: 'Błąd bazy danych' });
              }
            } else {
              res.status(200).json({
                message: 'Konto zostało utworzone pomyślnie! Możesz się teraz zalogować.',
                autoVerified: true
              });
            }
            resolve();
          }
        );
      });
    }

    // LOGIN
    if (path === 'login' && req.method === 'POST') {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email i hasło są wymagane' });
      }

      return new Promise((resolve) => {
        db.get('SELECT * FROM users WHERE email = ?', [email.trim().toLowerCase()], async (err, user) => {
          if (err || !user) {
            res.status(400).json({ error: 'Nieprawidłowe dane logowania' });
            resolve();
            return;
          }

          const validPassword = await bcrypt.compare(password, user.password);
          if (!validPassword) {
            res.status(400).json({ error: 'Nieprawidłowe dane logowania' });
            resolve();
            return;
          }

          const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '7d' }
          );

          res.status(200).json({
            message: 'Logowanie pomyślne',
            token,
            user: {
              id: user.id,
              username: user.username,
              email: user.email
            }
          });
          resolve();
        });
      });
    }

    // AUTH REQUIRED ENDPOINTS
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    let user;
    try {
      user = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(403).json({ error: 'Invalid token' });
    }

    // GET BETS
    if (path === 'bets' && req.method === 'GET') {
      return new Promise((resolve) => {
        db.all('SELECT * FROM bets WHERE user_id = ? ORDER BY date DESC', [user.userId], (err, rows) => {
          res.json(rows || []);
          resolve();
        });
      });
    }

    // ADD BET
    if (path === 'bets' && req.method === 'POST') {
      const { date, betType, betCategory, odds, stake, potentialWin, result, sport, note } = req.body;

      if (!date || !betType || !betCategory || !odds || !stake) {
        return res.status(400).json({ error: 'Required fields missing' });
      }

      return new Promise((resolve) => {
        db.run(
          `INSERT INTO bets (user_id, date, bet_type, bet_category, odds, stake, potential_win, result, sport, note) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [user.userId, date, betType, betCategory, odds, stake, potentialWin || (odds * stake), result || null, sport || null, note || null],
          function(err) {
            if (err) {
              res.status(500).json({ error: 'Database error' });
            } else {
              res.json({ message: 'Bet added successfully' });
            }
            resolve();
          }
        );
      });
    }

    // GET STATS
    if (path === 'stats' && req.method === 'GET') {
      return new Promise((resolve) => {
        db.all('SELECT * FROM bets WHERE user_id = ?', [user.userId], (err, bets) => {
          if (err) {
            res.status(500).json({ error: 'Database error' });
            resolve();
            return;
          }

          bets = bets || [];
          const totalStake = bets.reduce((sum, bet) => sum + parseFloat(bet.stake || 0), 0);
          const wins = bets.filter(bet => bet.result === 'WYGRANA').length;
          const losses = bets.filter(bet => bet.result === 'PRZEGRANA').length;
          const returns = bets.filter(bet => bet.result === 'ZWROT').length;

          let profit = 0;
          bets.forEach(bet => {
            if (bet.result === 'WYGRANA') {
              profit += parseFloat(bet.potential_win || 0) - parseFloat(bet.stake || 0);
            } else if (bet.result === 'PRZEGRANA') {
              profit -= parseFloat(bet.stake || 0);
            }
          });

          const initialAmount = 1000;
          const currentAmount = initialAmount + profit;
          const yieldPercentage = totalStake > 0 ? (profit / totalStake) * 100 : 0;
          const winRate = wins + losses > 0 ? (wins / (wins + losses)) * 100 : 0;
          const averageOdds = bets.length > 0 ? bets.reduce((sum, bet) => sum + parseFloat(bet.odds || 0), 0) / bets.length : 0;

          res.json({
            initialAmount: initialAmount.toFixed(2),
            totalStake: totalStake.toFixed(2),
            currentAmount: currentAmount.toFixed(2),
            profit: profit.toFixed(2),
            yieldPercentage: yieldPercentage.toFixed(2),
            winLossRatio: `${wins} / ${losses} / ${returns}`,
            winRate: winRate.toFixed(1),
            averageOdds: averageOdds.toFixed(2),
            totalBets: bets.length,
            totalWinnings: '0.00'
          });
          resolve();
        });
      });
    }

    // 404
    return res.status(404).json({ error: 'Endpoint not found: ' + path });

  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
}
