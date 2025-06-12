// lib/db.js - Database configuration for Vercel
const { Pool } = require('pg');

// Vercel Postgres connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initializeDatabase() {
  const client = await pool.connect();
  
  try {
    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        initial_amount DECIMAL(10,2) DEFAULT 1000,
        tax_rate DECIMAL(5,2) DEFAULT 12,
        verified BOOLEAN DEFAULT true,
        verification_token VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Bets table
    await client.query(`
      CREATE TABLE IF NOT EXISTS bets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        date DATE NOT NULL,
        bet_type VARCHAR(50) NOT NULL,
        bet_category VARCHAR(50) NOT NULL,
        odds DECIMAL(10,2) NOT NULL,
        stake DECIMAL(10,2) NOT NULL,
        potential_win DECIMAL(10,2) NOT NULL,
        result VARCHAR(20),
        profile_id VARCHAR(100) DEFAULT 'default',
        sport VARCHAR(255),
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Saved stats table
    await client.query(`
      CREATE TABLE IF NOT EXISTS saved_stats (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        period_start DATE,
        period_end DATE,
        total_bets INTEGER,
        total_stake DECIMAL(10,2),
        profit DECIMAL(10,2),
        yield_percentage DECIMAL(10,2),
        win_rate DECIMAL(10,2),
        average_odds DECIMAL(10,2),
        wins INTEGER,
        losses INTEGER,
        returns INTEGER,
        saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ Database tables initialized');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  } finally {
    client.release();
  }
}

// Query helper function
async function query(text, params) {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Get single row
async function getOne(text, params) {
  const result = await query(text, params);
  return result.rows[0] || null;
}

// Get multiple rows
async function getMany(text, params) {
  const result = await query(text, params);
  return result.rows;
}

// Insert and return new record
async function insertOne(text, params) {
  const result = await query(text + ' RETURNING *', params);
  return result.rows[0];
}

// Update and return updated record
async function updateOne(text, params) {
  const result = await query(text + ' RETURNING *', params);
  return result.rows[0];
}

module.exports = {
  pool,
  query,
  getOne,
  getMany,
  insertOne,
  updateOne,
  initializeDatabase
};