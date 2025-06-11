// Ultra Simple API - BEZ SQLite (na pewno zadziała)
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';

// In-memory storage (tymczasowo zamiast bazy)
let users = [];
let bets = [];

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
    // HEALTH CHECK
    if (path === 'health' && req.method === 'GET') {
      return res.status(200).json({
        status: 'OK',
        message: 'StatsBet API is running WITHOUT email verification (in-memory)',
        timestamp: new Date().toISOString(),
        method: req.method,
        path: path,
        users: users.length,
        bets: bets.length
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

      // Check if user exists
      const existingUser = users.find(u => u.email === email.toLowerCase());
      if (existingUser) {
        return res.status(400).json({ error: 'Użytkownik o tym emailu już istnieje' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      
      const newUser = {
        id: users.length + 1,
        username: username.trim(),
        email: email.trim().toLowerCase(),
        password: hashedPassword,
        verified: 1,
        initial_amount: 1000,
        tax_rate: 12,
        created_at: new Date().toISOString()
      };

      users.push(newUser);

      return res.status(200).json({
        message: 'Konto zostało utworzone pomyślnie! Możesz się teraz zalogować.',
        autoVerified: true,
        email: email
      });
    }

    // LOGIN
    if (path === 'login' && req.method === 'POST') {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email i hasło są wymagane' });
      }

      const user = users.find(u => u.email === email.toLowerCase());
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

      return res.status(200).json({
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
      const userBets = bets.filter(bet => bet.user_id === user.userId);
      return res.json(userBets);
    }

    // ADD BET
    if (path === 'bets' && req.method === 'POST') {
      const { date, betType, betCategory, odds, stake, potentialWin, result, sport, note } = req.body;

      if (!date || !betType || !betCategory || !odds || !stake) {
        return res.status(400).json({ error: 'Required fields missing' });
      }

      const newBet = {
        id: bets.length + 1,
        user_id: user.userId,
        date,
        bet_type: betType,
        bet_category: betCategory,
        odds: parseFloat(odds),
        stake: parseFloat(stake),
        potential_win: potentialWin || (parseFloat(odds) * parseFloat(stake)),
        result: result || null,
        profile_id: 'default',
        sport: sport || null,
        note: note || null,
        created_at: new Date().toISOString()
      };

      bets.push(newBet);

      return res.json({ 
        message: 'Bet added successfully', 
        bet: newBet 
      });
    }

    // GET STATS
    if (path === 'stats' && req.method === 'GET') {
      const userBets = bets.filter(bet => bet.user_id === user.userId);
      
      const totalStake = userBets.reduce((sum, bet) => sum + parseFloat(bet.stake || 0), 0);
      const wins = userBets.filter(bet => bet.result === 'WYGRANA').length;
      const losses = userBets.filter(bet => bet.result === 'PRZEGRANA').length;
      const returns = userBets.filter(bet => bet.result === 'ZWROT').length;

      let profit = 0;
      let totalWinnings = 0;
      userBets.forEach(bet => {
        if (bet.result === 'WYGRANA') {
          const winAmount = parseFloat(bet.potential_win || 0) - parseFloat(bet.stake || 0);
          profit += winAmount;
          totalWinnings += parseFloat(bet.potential_win || 0);
        } else if (bet.result === 'PRZEGRANA') {
          profit -= parseFloat(bet.stake || 0);
        }
      });

      const initialAmount = 1000;
      const currentAmount = initialAmount + profit;
      const yieldPercentage = totalStake > 0 ? (profit / totalStake) * 100 : 0;
      const winRate = wins + losses > 0 ? (wins / (wins + losses)) * 100 : 0;
      const averageOdds = userBets.length > 0 ? userBets.reduce((sum, bet) => sum + parseFloat(bet.odds || 0), 0) / userBets.length : 0;

      return res.json({
        initialAmount: initialAmount.toFixed(2),
        totalStake: totalStake.toFixed(2),
        currentAmount: currentAmount.toFixed(2),
        profit: profit.toFixed(2),
        yieldPercentage: yieldPercentage.toFixed(2),
        winLossRatio: `${wins} / ${losses} / ${returns}`,
        winRate: winRate.toFixed(1),
        averageOdds: averageOdds.toFixed(2),
        totalBets: userBets.length,
        totalWinnings: totalWinnings.toFixed(2)
      });
    }

    // GET SETTINGS
    if (path === 'settings' && req.method === 'GET') {
      const currentUser = users.find(u => u.id === user.userId);
      return res.json({
        initialAmount: currentUser ? currentUser.initial_amount : 1000,
        taxRate: currentUser ? currentUser.tax_rate : 12
      });
    }

    // UPDATE SETTINGS
    if (path === 'settings' && req.method === 'PUT') {
      const { initialAmount, taxRate } = req.body;
      const userIndex = users.findIndex(u => u.id === user.userId);
      if (userIndex !== -1) {
        users[userIndex].initial_amount = initialAmount;
        users[userIndex].tax_rate = taxRate;
      }
      return res.json({ message: 'Settings updated successfully' });
    }

    // 404
    return res.status(404).json({ 
      error: 'Endpoint not found: ' + path,
      available: ['health', 'register', 'login', 'bets', 'stats', 'settings']
    });

  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ 
      error: 'Internal server error', 
      message: error.message,
      stack: error.stack
    });
  }
}
