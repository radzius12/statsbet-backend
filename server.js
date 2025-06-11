// StatsBet Backend - NAPRAWIONY (CORS + błędy) ✅
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// Middleware
app.use(express.json());

// NAPRAWIONY CORS - dodano http://statsbet.pl ✅
app.use(cors({
  origin: [
    'https://statsbet.pl', 
    'http://statsbet.pl',     // ✅ DODANE
    'http://localhost:8080',
    'http://localhost:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.static('public'));

// Email transporter - WYŁĄCZONY (ale bez błędów)
let transporter = null;
try {
  if (process.env.SMTP_HOST && process.env.SMTP_USER) {
    transporter = nodemailer.createTransporter({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
      }
    });
  }
} catch (error) {
  console.log('📧 Email transporter disabled:', error.message);
}

// Database initialization - NAPRAWIONY
const db = new sqlite3.Database('./statsbet.db');

// Create tables - UPROSZCZONY (bez błędów migracji)
db.serialize(() => {
  // Users table
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
  )`, (err) => {
    if (err) console.error('Users table error:', err);
    else console.log('✅ Users table ready');
  });

  // Bets table
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
  )`, (err) => {
    if (err) console.error('Bets table error:', err);
    else console.log('✅ Bets table ready');
  });

  // Saved stats table
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
  )`, (err) => {
    if (err) console.error('Saved stats table error:', err);
    else console.log('✅ Saved stats table ready');
  });
  
  console.log('✅ Database initialization complete');
});

// Email sending function - BEZPIECZNA
const sendVerificationEmail = (email, username, token) => {
  console.log(`📧 Email verification DISABLED for: ${email} (auto-verified)`);
  return Promise.resolve();
};

// Auth middleware - NAPRAWIONY
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// === HEALTH CHECK - PIERWSZY ENDPOINT ===
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'StatsBet API is running WITHOUT email verification',
    timestamp: new Date().toISOString(),
    cors: 'enabled',
    database: 'sqlite3'
  });
});

// === AUTH ROUTES ===

// Register - BEZ WERYFIKACJI EMAIL ✅
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Walidacja - NAPRAWIONA
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Wszystkie pola są wymagane' });
    }

    if (typeof username !== 'string' || username.length < 3) {
      return res.status(400).json({ error: 'Nazwa użytkownika musi mieć minimum 3 znaki' });
    }

    if (typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Hasło musi mieć minimum 6 znaków' });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Nieprawidłowy format email' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert user - AUTOMATYCZNA WERYFIKACJA
    db.run(
      'INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, ?)',
      [username.trim(), email.trim().toLowerCase(), hashedPassword, 1],
      function(err) {
        if (err) {
          console.error('Database error:', err);
          if (err.message.includes('UNIQUE constraint failed')) {
            if (err.message.includes('email')) {
              return res.status(400).json({ error: 'Użytkownik o tym emailu już istnieje' });
            } else {
              return res.status(400).json({ error: 'Nazwa użytkownika już zajęta' });
            }
          }
          return res.status(500).json({ error: 'Błąd bazy danych' });
        }
        
        console.log(`✅ User created: ${email} (ID: ${this.lastID})`);
        
        res.json({ 
          message: 'Konto zostało utworzone pomyślnie! Możesz się teraz zalogować.',
          emailSent: false,
          email: email,
          autoVerified: true
        });
      }
    );
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

// Login - BEZ SPRAWDZANIA WERYFIKACJI ✅
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email i hasło są wymagane' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email.trim().toLowerCase()], async (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Błąd bazy danych' });
      }

      if (!user) {
        return res.status(400).json({ error: 'Nieprawidłowe dane logowania' });
      }

      try {
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
          return res.status(400).json({ error: 'Nieprawidłowe dane logowania' });
        }

        const token = jwt.sign(
          { userId: user.id, username: user.username }, 
          JWT_SECRET, 
          { expiresIn: '7d' }
        );

        console.log(`✅ User logged in: ${user.email}`);

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
        console.error('Password comparison error:', error);
        res.status(500).json({ error: 'Błąd serwera' });
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

// Verify email - WYŁĄCZONE
app.get('/api/verify/:token', (req, res) => {
  res.json({ message: 'Weryfikacja email wyłączona - wszystkie konta są automatycznie aktywne' });
});

// Resend verification - WYŁĄCZONE
app.post('/api/resend-verification', (req, res) => {
  res.json({ message: 'Weryfikacja email wyłączona - wszystkie konta są automatycznie aktywne' });
});

// === BETS ROUTES ===

// Get all bets for user
app.get('/api/bets', authenticateToken, (req, res) => {
  const { profile } = req.query;
  
  let query = 'SELECT * FROM bets WHERE user_id = ?';
  let params = [req.user.userId];
  
  if (profile && profile !== 'ALL') {
    query += ' AND profile_id = ?';
    params.push(profile);
  }
  
  query += ' ORDER BY date DESC, id DESC';
  
  db.all(query, params, (err, rows) => {
    if (err) {
      console.error('Get bets error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows || []);
  });
});

// Add new bet
app.post('/api/bets', authenticateToken, (req, res) => {
  try {
    const { date, betType, betCategory, odds, stake, potentialWin, result, profileId, sport, note } = req.body;

    if (!date || !betType || !betCategory || !odds || !stake) {
      return res.status(400).json({ error: 'Required fields missing' });
    }

    // Validation
    if (isNaN(odds) || odds < 1) {
      return res.status(400).json({ error: 'Invalid odds value' });
    }
    
    if (isNaN(stake) || stake <= 0) {
      return res.status(400).json({ error: 'Invalid stake value' });
    }

    const calculatedPotentialWin = potentialWin || (odds * stake);

    db.run(
      `INSERT INTO bets (user_id, date, bet_type, bet_category, odds, stake, potential_win, result, profile_id, sport, note) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.userId, date, betType, betCategory, odds, stake, calculatedPotentialWin, result || null, profileId || 'default', sport || null, note || null],
      function(err) {
        if (err) {
          console.error('Add bet error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        db.get('SELECT * FROM bets WHERE id = ?', [this.lastID], (err, row) => {
          if (err) {
            console.error('Get new bet error:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          res.json({ message: 'Bet added successfully', bet: row });
        });
      }
    );
  } catch (error) {
    console.error('Add bet error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update bet
app.put('/api/bets/:id', authenticateToken, (req, res) => {
  try {
    const betId = req.params.id;
    const { date, betType, betCategory, odds, stake, potentialWin, result, profileId, sport, note } = req.body;

    db.run(
      `UPDATE bets SET date = ?, bet_type = ?, bet_category = ?, odds = ?, 
       stake = ?, potential_win = ?, result = ?, profile_id = ?, sport = ?, note = ?
       WHERE id = ? AND user_id = ?`,
      [date, betType, betCategory, odds, stake, potentialWin, result, profileId || 'default', sport || null, note || null, betId, req.user.userId],
      function(err) {
        if (err) {
          console.error('Update bet error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (this.changes === 0) {
          return res.status(404).json({ error: 'Bet not found' });
        }
        
        db.get('SELECT * FROM bets WHERE id = ?', [betId], (err, row) => {
          if (err) {
            console.error('Get updated bet error:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          res.json({ message: 'Bet updated successfully', bet: row });
        });
      }
    );
  } catch (error) {
    console.error('Update bet error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete bet
app.delete('/api/bets/:id', authenticateToken, (req, res) => {
  const betId = req.params.id;

  db.run(
    'DELETE FROM bets WHERE id = ? AND user_id = ?',
    [betId, req.user.userId],
    function(err) {
      if (err) {
        console.error('Delete bet error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Bet not found' });
      }
      
      res.json({ message: 'Bet deleted successfully' });
    }
  );
});

// === STATS ROUTES ===

// Get user stats
app.get('/api/stats', authenticateToken, (req, res) => {
  const { profile } = req.query;
  
  let query = 'SELECT * FROM bets WHERE user_id = ?';
  let params = [req.user.userId];
  
  if (profile && profile !== 'ALL') {
    query += ' AND profile_id = ?';
    params.push(profile);
  }
  
  db.all(query, params, (err, bets) => {
    if (err) {
      console.error('Get stats error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    bets = bets || [];

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

    db.get('SELECT initial_amount FROM users WHERE id = ?', [req.user.userId], (err, user) => {
      if (err) {
        console.error('Get user settings error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      const initialAmount = user ? user.initial_amount : 1000;
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
        totalWinnings: totalWinnings.toFixed(2)
      });
    });
  });
});

// === SETTINGS ROUTES ===

// Get user settings
app.get('/api/settings', authenticateToken, (req, res) => {
  db.get(
    'SELECT initial_amount, tax_rate FROM users WHERE id = ?',
    [req.user.userId],
    (err, row) => {
      if (err) {
        console.error('Get settings error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({
        initialAmount: row ? row.initial_amount : 1000,
        taxRate: row ? row.tax_rate : 12
      });
    }
  );
});

// Update user settings
app.put('/api/settings', authenticateToken, (req, res) => {
  const { initialAmount, taxRate } = req.body;

  db.run(
    'UPDATE users SET initial_amount = ?, tax_rate = ? WHERE id = ?',
    [initialAmount, taxRate, req.user.userId],
    function(err) {
      if (err) {
        console.error('Update settings error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ message: 'Settings updated successfully' });
    }
  );
});

// === RESET STATS ROUTES ===

// Save current stats and reset
app.post('/api/reset-stats', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM bets WHERE user_id = ? ORDER BY date ASC',
    [req.user.userId],
    (err, bets) => {
      if (err) {
        console.error('Reset stats error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (!bets || bets.length === 0) {
        return res.status(400).json({ error: 'No bets to archive' });
      }

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

      const periodStart = bets[0].date;
      const periodEnd = bets[bets.length - 1].date;

      db.run(
        `INSERT INTO saved_stats 
         (user_id, period_start, period_end, total_bets, total_stake, profit, 
          yield_percentage, win_rate, average_odds, wins, losses, returns) 
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.user.userId, periodStart, periodEnd, bets.length, totalStake, profit,
         yieldPercentage, winRate, averageOdds, wins, losses, returns],
        function(err) {
          if (err) {
            console.error('Save stats error:', err);
            return res.status(500).json({ error: 'Error saving stats' });
          }

          db.run('DELETE FROM bets WHERE user_id = ?', [req.user.userId], (err) => {
            if (err) {
              console.error('Reset bets error:', err);
              return res.status(500).json({ error: 'Error resetting bets' });
            }
            res.json({ message: 'Stats saved and reset successfully' });
          });
        }
      );
    }
  );
});

// Get saved stats
app.get('/api/saved-stats', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM saved_stats WHERE user_id = ? ORDER BY saved_at DESC',
    [req.user.userId],
    (err, rows) => {
      if (err) {
        console.error('Get saved stats error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows || []);
    }
  );
});

// Delete saved stats
app.delete('/api/saved-stats/:id', authenticateToken, (req, res) => {
  const statsId = req.params.id;

  db.run(
    'DELETE FROM saved_stats WHERE id = ? AND user_id = ?',
    [statsId, req.user.userId],
    function(err) {
      if (err) {
        console.error('Delete saved stats error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Stats not found' });
      }
      
      res.json({ message: 'Saved stats deleted successfully' });
    }
  );
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ StatsBet Backend running on port ${PORT}`);
  console.log(`📡 API available at: http://localhost:${PORT}/api`);
  console.log(`🚫 Email verification DISABLED - automatic account activation`);
  console.log(`🌐 CORS enabled for: http://statsbet.pl, https://statsbet.pl`);
});
