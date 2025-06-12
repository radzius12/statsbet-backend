// api/bets/[id].js
const { authenticateToken } = require('../../lib/auth');
const { updateOne, query, initializeDatabase } = require('../../lib/db');

async function handler(req, res) {
  // Initialize database tables
  await initializeDatabase();

  const { id } = req.query;
  
  if (req.method === 'PUT') {
    // Update bet
    const { date, betType, betCategory, odds, stake, potentialWin, result, profileId, sport, note } = req.body;

    try {
      const updatedBet = await updateOne(
        `UPDATE bets SET date = $1, bet_type = $2, bet_category = $3, odds = $4, 
         stake = $5, potential_win = $6, result = $7, profile_id = $8, sport = $9, note = $10
         WHERE id = $11 AND user_id = $12`,
        [date, betType, betCategory, odds, stake, potentialWin, result, profileId || 'default', sport || null, note || null, id, req.user.userId]
      );
      
      if (!updatedBet) {
        return res.status(404).json({ error: 'Bet not found' });
      }
      
      return res.json({ message: 'Bet updated successfully', bet: updatedBet });
    } catch (error) {
      console.error('Update bet error:', error);
      return res.status(500).json({ error: 'Database error' });
    }
  }
  
  if (req.method === 'DELETE') {
    // Delete bet
    try {
      const result = await query(
        'DELETE FROM bets WHERE id = $1 AND user_id = $2',
        [id, req.user.userId]
      );
      
      if (result.rowCount === 0) {
        return res.status(404).json({ error: 'Bet not found' });
      }
      
      return res.json({ message: 'Bet deleted successfully' });
    } catch (error) {
      console.error('Delete bet error:', error);
      return res.status(500).json({ error: 'Database error' });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}

module.exports = authenticateToken(handler);