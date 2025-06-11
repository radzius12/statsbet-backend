// StatsBet Backend with Email Verification - MINIMALNA POPRAWKA CORS
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

// ⭐ JEDYNA ZMIANA - POPRAWIONA LISTA ORIGINS
app.use(cors({
  origin: [
    'http://statsbet.pl',        // ⭐ DODANO
    'https://statsbet.pl', 
    'http://localhost:8080'
  ],
  credentials: true
}));

app.use(express.static('public'));

// Email transporter - BEZ ZMIAN
const transporter = nodemailer.createTransporter({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD
  }
});

// Database initialization - BEZ ZMIAN
const db = new sqlite3.Database(':memory:');

// Create tables - BEZ ZMIAN
db.serialize(() => {
  // Users table with email verification
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    initial_amount REAL DEFAULT 1000,
    tax_rate REAL DEFAULT 12,
    verified INTEGER DEFAULT 0,
    verification_token TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Bets table with profile_id, sport, note
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
  )`);

  // Add missing columns if they don't exist (migracje)
  db.run(`ALTER TABLE bets ADD COLUMN sport TEXT`, () => {});
  db.run(`ALTER TABLE bets ADD COLUMN note TEXT`, () => {});
  db.run(`ALTER TABLE bets ADD COLUMN profile_id TEXT DEFAULT 'default'`, () => {});
  
  console.log('✅ Database tables initialized');
});

// Email sending function - BEZ ZMIAN
const sendVerificationEmail = (email, username, token) => {
  const verificationUrl = `${process.env.FRONTEND_URL || 'https://statsbet.pl'}?token=${token}`;
  
  const mailOptions = {
    from: process.env.SMTP_USER,
    to: email,
    subject: 'StatsBet Pro - Potwierdź swoje konto',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #2563eb; margin: 0;">📊 StatsBet Pro</h1>
        </div>
        
        <h2 style="color: #2563eb;">Witaj ${username}!</h2>
        <p style="font-size: 16px; line-height: 1.5;">Dziękujemy za rejestrację w StatsBet Pro - najlepszej aplikacji do śledzenia statystyk bukmacherskich.</p>
        
        <p style="font-size: 16px; line-height: 1.5;">Aby aktywować swoje konto i rozpocząć korzystanie z aplikacji, kliknij w poniższy przycisk:</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verificationUrl}" 
             style="background: #2563eb; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: bold; font-size: 16px;">
            ✅ Potwierdź konto
          </a>
        </div>
        
        <p style="font-size: 14px; color: #666;">Jeśli przycisk nie działa, skopiuj i wklej ten link do przeglądarki:</p>
        <p style="word-break: break-all; color: #2563eb; background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 12px;">${verificationUrl}</p>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
          <p style="font-size: 12px; color: #666; margin: 0;">
            <strong>Ważne:</strong> Link jest ważny przez 24 godziny.<br>
            Jeśli nie rejestrowałeś się w StatsBet Pro, zignoruj tego emaila.
          </p>
        </div>
      </div>
    `
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Błąd wysyłania emaila:', error);
    } else {
      console.log('Email weryfikacyjny wysłany do:', email);
    }
  });
};

// RESZTA KODU IDENTYCZNA JAK WCZEŚNIEJ...
// Auth middleware
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

// === AUTH ROUTES ===

// Register
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Wszystkie pola są wymagane' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Hasło musi mieć minimum 6 znaków' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    db.run(
      'INSERT INTO users (username, email, password, verification_token) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, verificationToken],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Użytkownik o tym emailu lub nazwie już istnieje' });
          }
          return res.status(500).json({ error: 'Błąd bazy danych' });
        }
        
        // Wyślij email weryfikacyjny
        sendVerificationEmail(email, username, verificationToken);
        
        res.json({ 
          message: 'Konto zostało utworzone! Sprawdź email i kliknij w link weryfikacyjny aby aktywować konto.',
          emailSent: true,
          email: email
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Błąd serwera' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email i hasło są wymagane' });
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Błąd bazy danych' });
    }

    if (!user) {
      return res.status(400).json({ error: 'Nieprawidłowe dane logowania' });
    }

    if (!user.verified) {
      return res.status(400).json({ 
        error: 'Konto nie zostało zweryfikowane. Sprawdź email i kliknij w link weryfikacyjny.',
        needsVerification: true,
        email: user.email
      });
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
      res.status(500).json({ error: 'Błąd serwera' });
    }
  });
});

// Verify email
app.get('/api/verify/:token', (req, res) => {
  const token = req.params.token;
  
  db.run(
    'UPDATE users SET verified = 1, verification_token = NULL WHERE verification_token = ?',
    [token],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Błąd weryfikacji' });
      }
      
      if (this.changes === 0) {
        return res.status(400).json({ error: 'Nieprawidłowy lub wygasły token weryfikacji' });
      }
      
      res.json({ message: 'Email zweryfikowany pomyślnie! Możesz się teraz zalogować.' });
    }
  );
});

// Resend verification
app.post('/api/resend-verification', (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email jest wymagany' });
  }
  
  db.get('SELECT * FROM users WHERE email = ? AND verified = 0', [email], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Błąd bazy danych' });
    }
    
    if (!user) {
      return res.status(400).json({ error: 'Użytkownik nie znaleziony lub konto już zweryfikowane' });
    }
    
    const token = crypto.randomBytes(32).toString('hex');
    
    db.run(
      'UPDATE users SET verification_token = ? WHERE id = ?',
      [token, user.id],
      (err) => {
        if (err) {
          return res.status(500).json({ error: 'Błąd bazy danych' });
        }
        
        sendVerificationEmail(user.email, user.username, token);
        res.json({ message: 'Email weryfikacyjny wysłany ponownie' });
      }
    );
  });
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
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

// Add new bet
app.post('/api/bets', authenticateToken, (req, res) => {
  const { date, betType, betCategory, odds, stake, potentialWin, result, profileId, sport, note } = req.body;

  if (!date || !betType || !betCategory || !odds || !stake) {
    return res.status(400).json({ error: 'Required fields missing' });
  }

  db.run(
    `INSERT INTO bets (user_id, date, bet_type, bet_category, odds, stake, potential_win, result, profile_id, sport, note) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [req.user.userId, date, betType, betCategory, odds, stake, potentialWin, result || null, profileId || 'default', sport || null, note || null],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      db.get('SELECT * FROM bets WHERE id = ?', [this.lastID], (err, row) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        res.json({ message: 'Bet added successfully', bet: row });
      });
    }
  );
});

// Update bet
app.put('/api/bets/:id', authenticateToken, (req, res) => {
  const betId = req.params.id;
  const { date, betType, betCategory, odds, stake, potentialWin, result, profileId, sport, note } = req.body;

  db.run(
    `UPDATE bets SET date = ?, bet_type = ?, bet_category = ?, odds = ?, 
     stake = ?, potential_win = ?, result = ?, profile_id = ?, sport = ?, note = ?
     WHERE id = ? AND user_id = ?`,
    [date, betType, betCategory, odds, stake, potentialWin, result, profileId || 'default', sport || null, note || null, betId, req.user.userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Bet not found' });
      }
      
      db.get('SELECT * FROM bets WHERE id = ?', [betId], (err, row) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        res.json({ message: 'Bet updated successfully', bet: row });
      });
    }
  );
});

// Delete bet
app.delete('/api/bets/:id', authenticateToken, (req, res) => {
  const betId = req.params.id;

  db.run(
    'DELETE FROM bets WHERE id = ? AND user_id = ?',
    [betId, req.user.userId],
    function(err) {
      if (err) {
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
  
  db.all(query, params,
    (err, bets) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

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
    }
  );
});

// === SETTINGS ROUTES ===

// Get user settings
app.get('/api/settings', authenticateToken, (req, res) => {
  db.get(
    'SELECT initial_amount, tax_rate FROM users WHERE id = ?',
    [req.user.userId],
    (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({
        initialAmount: row.initial_amount,
        taxRate: row.tax_rate
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
        return res.status(500).json({ error: 'Database error' });
      }

      if (bets.length === 0) {
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
            return res.status(500).json({ error: 'Error saving stats' });
          }

          db.run('DELETE FROM bets WHERE user_id = ?', [req.user.userId], (err) => {
            if (err) {
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
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
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
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Stats not found' });
      }
      
      res.json({ message: 'Saved stats deleted successfully' });
    }
  );
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'StatsBet API is running with email verification' });
});

// Export for Vercel
module.exports = app;
