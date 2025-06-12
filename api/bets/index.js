// api/bets/index.js
const { authenticateToken } = require('../../lib/auth');
const { getMany, insertOne, initializeDatabase } = require('../../lib/db');

async function handler(req, res) {
  // Initialize database tables
  await initializeDatabase();

  if (req.method === 'GET') {
    // Get all bets for user
    const { profile } = req.query;
    
    let query = 'SELECT * FROM bets WHERE user_id = $1';
    let params = [req.user.userId];
    
    if (profile && profile !== 'ALL') {
      query += ' AND profile_id = $2';
      params.push(profile);
    }
    
    query += ' ORDER BY date DESC, id DESC';
    
    try {
      const bets = await getMany(query, params);
      return res.json(bets);
    } catch (error) {
      console.error('Get bets error:', error);
      return res.status(500).json({ error: 'Database error' });
    }
  }
  
  if (req.method === 'POST') {
    // Add new bet
    const { date, betType, betCategory, odds, stake, potentialWin, result, profileId, sport, note } = req.body;

    if (!date || !betType || !betCategory || !odds || !stake) {
      return res.status(400).json({ error: 'Required fields missing' });
    }

    try {
      const newBet = await insertOne(
        `INSERT INTO bets (user_id, date, bet_type, bet_category, odds, stake, potential_win, result, profile_id, sport, note) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [req.user.userId, date, betType, betCategory, odds, stake, potentialWin, result || null, profileId || 'default', sport || null, note || null]
      );
      
      return res.json({ message: 'Bet added successfully', bet: newBet });
    } catch (error) {
      console.error('Add bet error:', error);
      return res.status(500).json({ error: 'Database error' });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}

module.exports = authenticateToken(handler);