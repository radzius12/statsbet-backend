// api/stats/index.js
const { authenticateToken } = require('../../lib/auth');
const { getMany, getOne, initializeDatabase } = require('../../lib/db');

async function handler(req, res) {
  // Initialize database tables
  await initializeDatabase();

  const { profile } = req.query;
  
  let query = 'SELECT * FROM bets WHERE user_id = $1';
  let params = [req.user.userId];
  
  if (profile && profile !== 'ALL') {
    query += ' AND profile_id = $2';
    params.push(profile);
  }
  
  try {
    const bets = await getMany(query, params);

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

    const user = await getOne('SELECT initial_amount FROM users WHERE id = $1', [req.user.userId]);
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
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Database error' });
  }
}

module.exports = authenticateToken(handler);