// api/[...all].js - Vercel Serverless Function Handler
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Constants
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Initialize database in /tmp for Vercel
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
    verification_token TEXT,
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS saved_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    period_start TEXT,
    period_end TEXT,
    total_bets INTEGER,
    total_stake REAL,
    profit REAL,
    yield_percentage REAL,
    win_rate REAL,
    average_odds REAL,
    wins INTEGER,
    losses INTEGER,
    returns INTEGER,
    saved_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);
});

// Auth middleware
const authenticateToken = (token) => {
  return new Promise((resolve, reject) => {
    if (!token) {
      reject(new Error('Access token required'));
      return;
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        reject(new Error('Invalid token'));
      } else {
        resolve(user);
      }
    });
  });
};

// Database helpers
const dbGet = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

const dbAll = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows || []);
    });
  });
};

const dbRun = (query, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(query, params, function(err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
};

// Main handler
export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  try {
    const { query, method } = req;
    const path = query.all ? query.all.join('/') : '';

    console.log(`${method} /api/${path}`);

    // Health check
    if (path === 'health') {
      return res.json({
        status: 'OK',
        message: 'StatsBet API is running WITHOUT email verification',
        timestamp: new Date().toISOString(),
        cors: 'enabled',
        database: 'sqlite3'
      });
    }

    // Register
    if (path === 'register' && method === 'POST') {
      const { username, email, password } = req.body;

      if (!username || !email || !password) {
        return res.status(400).json({ error: 'Wszystkie pola są wymagane' });
      }

      if (password.length < 6) {
        return res.status(400).json({ error: 'Hasło musi mieć minimum 6 znaków' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      
      try {
        await dbRun(
          'INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, ?)',
          [username.trim(), email.trim().toLowerCase(), hashedPassword, 1]
        );

        return res.json({
          message: 'Konto zostało utworzone pomyślnie! Możesz się teraz zalogować.',
          emailSent: false,
          email: email,
          autoVerified: true
        });
      } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'Użytkownik o tym emailu już istnieje' });
        }
        throw error;
      }
    }

    // Login
    if (path === 'login' && method === 'POST') {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email i hasło są wymagane' });
      }

      const user = await dbGet('SELECT * FROM users WHERE email = ?', [email.trim().toLowerCase()]);

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

      return res.json({
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
    }

    // Protected routes - require authentication
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    const user = await authenticateToken(token);

    // Get bets
    if (path === 'bets' && method === 'GET') {
      const bets = await dbAll(
        'SELECT * FROM bets WHERE user_id = ? ORDER BY date DESC, id DESC',
        [user.userId]
      );
      return res.json(bets);
    }

    // Add bet
    if (path === 'bets' && method === 'POST') {
      const { date, betType, betCategory, odds, stake, potentialWin, result, profileId, sport, note } = req.body;

      if (!date || !betType || !betCategory || !odds || !stake) {
        return res.status(400).json({ error: 'Required fields missing' });
      }

      const result_data = await dbRun(
        `INSERT INTO bets (user_id, date, bet_type, bet_category, odds, stake, potential_win, result, profile_id, sport, note) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [user.userId, date, betType, betCategory, odds, stake, potentialWin || (odds * stake), result || null, profileId || 'default', sport || null, note || null]
      );

      const newBet = await dbGet('SELECT * FROM bets WHERE id = ?', [result_data.id]);
      return res.json({ message: 'Bet added successfully', bet: newBet });
    }

    // Update bet
    if (path.startsWith('bets/') && method === 'PUT') {
      const betId = path.split('/')[1];
      const { date, betType, betCategory, odds, stake, potentialWin, result, profileId, sport, note } = req.body;

      await dbRun(
        `UPDATE bets SET date = ?, bet_type = ?, bet_category = ?, odds = ?, 
         stake = ?, potential_win = ?, result = ?, profile_id = ?, sport = ?, note = ?
         WHERE id = ? AND user_id = ?`,
        [date, betType, betCategory, odds, stake, potentialWin, result, profileId || 'default', sport || null, note || null, betId, user.userId]
      );

      const updatedBet = await dbGet('SELECT * FROM bets WHERE id = ?', [betId]);
      return res.json({ message: 'Bet updated successfully', bet: updatedBet });
    }

    // Delete bet
    if (path.startsWith('bets/') && method === 'DELETE') {
      const betId = path.split('/')[1];
      await dbRun('DELETE FROM bets WHERE id = ? AND user_id = ?', [betId, user.userId]);
      return res.json({ message: 'Bet deleted successfully' });
    }

    // Get stats
    if (path === 'stats' && method === 'GET') {
      const bets = await dbAll('SELECT * FROM bets WHERE user_id = ?', [user.userId]);
      
      const totalStake = bets.reduce((sum, bet) => sum + parseFloat(bet.stake || 0), 0);
      const wins = bets.filter(bet => bet.result === 'WYGRANA').length;
      const losses = bets.filter(bet => bet.result === 'PRZEGRANA').length;
      const returns = bets.filter(bet => bet.result === 'ZWROT').length;

      let profit = 0;
      let totalWinnings = 0;
      bets.forEach(bet => {
        if (bet.result === 'WYGRANA') {
          const winAmount = parseFloat(bet.potential_win || 0) - parseFloat(bet.stake || 0);
          profit += winAmount;
          totalWinnings += parseFloat(bet.potential_win || 0);
        } else if (bet.result === 'PRZEGRANA') {
          profit -= parseFloat(bet.stake || 0);
        }
      });

      const userSettings = await dbGet('SELECT initial_amount FROM users WHERE id = ?', [user.userId]);
      const initialAmount = userSettings ? userSettings.initial_amount : 1000;
      const currentAmount = initialAmount + profit;
      const yieldPercentage = totalStake > 0 ? (profit / totalStake) * 100 : 0;
      const winRate = wins + losses > 0 ? (wins / (wins + losses)) * 100 : 0;
      const averageOdds = bets.length > 0 ? bets.reduce((sum, bet) => sum + parseFloat(bet.odds || 0), 0) / bets.length : 0;

      return res.json({
        initialAmount: initialAmount.toFixed(2),
        totalStake: totalStake.toFixed(2),
        currentAmount: currentAmount.toFixed(2),
        profit: profit.toFixed(2),
        yieldPercentage: yieldPercentage.toFixed(2),
        winLossRatio: `${wins} / ${losses} / ${returns}`,
        winRate: winRate.toFixed(1),
        averageOdds: averageOdds.toFixed(2),
        totalBets: bets.length,
        totalWinnings: totalWinnings.toFixed(2)
      });
    }

    // Get settings
    if (path === 'settings' && method === 'GET') {
      const settings = await dbGet('SELECT initial_amount, tax_rate FROM users WHERE id = ?', [user.userId]);
      return res.json({
        initialAmount: settings ? settings.initial_amount : 1000,
        taxRate: settings ? settings.tax_rate : 12
      });
    }

    // Update settings
    if (path === 'settings' && method === 'PUT') {
      const { initialAmount, taxRate } = req.body;
      await dbRun('UPDATE users SET initial_amount = ?, tax_rate = ? WHERE id = ?', [initialAmount, taxRate, user.userId]);
      return res.json({ message: 'Settings updated successfully' });
    }

    // Get saved stats
    if (path === 'saved-stats' && method === 'GET') {
      const savedStats = await dbAll('SELECT * FROM saved_stats WHERE user_id = ? ORDER BY saved_at DESC', [user.userId]);
      return res.json(savedStats);
    }

    // Reset stats
    if (path === 'reset-stats' && method === 'POST') {
      const bets = await dbAll('SELECT * FROM bets WHERE user_id = ? ORDER BY date ASC', [user.userId]);
      
      if (bets.length === 0) {
        return res.status(400).json({ error: 'No bets to archive' });
      }

      // Calculate stats
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

      const yieldPercentage = totalStake > 0 ? (profit / totalStake) * 100 : 0;
      const winRate = wins + losses > 0 ? (wins / (wins + losses)) * 100 : 0;
      const averageOdds = bets.length > 0 ? bets.reduce((sum, bet) => sum + parseFloat(bet.odds || 0), 0) / bets.length : 0;

      // Save stats
      await dbRun(
        `INSERT INTO saved_stats 
         (user_id, period_start, period_end, total_bets, total_stake, profit, 
          yield_percentage, win_rate, average_odds, wins, losses, returns) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [user.userId, bets[0].date, bets[bets.length - 1].date, bets.length, totalStake, profit,
         yieldPercentage, winRate, averageOdds, wins, losses, returns]
      );

      // Delete all bets
      await dbRun('DELETE FROM bets WHERE user_id = ?', [user.userId]);

      return res.json({ message: 'Stats saved and reset successfully' });
    }

    // 404 for unmatched routes
    return res.status(404).json({ error: 'Not found' });

  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ error: error.message || 'Internal server error' });
  }
}
