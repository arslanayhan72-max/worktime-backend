const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL connection using Railway's automatic database URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// Create tables on startup
async function initDatabase() {
  try {
    const client = await pool.connect();
    
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT DEFAULT 'worker',
        department TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await client.query(`
      CREATE TABLE IF NOT EXISTS qr_codes (
        id TEXT PRIMARY KEY,
        code TEXT UNIQUE NOT NULL,
        location_name TEXT NOT NULL,
        description TEXT,
        is_active BOOLEAN DEFAULT true,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await client.query(`
      CREATE TABLE IF NOT EXISTS time_entries (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        qr_code_id TEXT NOT NULL,
        type TEXT CHECK(type IN ('clock_in', 'clock_out')) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        latitude NUMERIC,
        longitude NUMERIC,
        device_info TEXT,
        edited_by TEXT,
        edited_at TIMESTAMP,
        original_timestamp TIMESTAMP
      )
    `);
    
    // Create default admin
    const adminResult = await client.query('SELECT * FROM users WHERE email = $1', ['admin@worktime.com']);
    if (adminResult.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await client.query(
        'INSERT INTO users (id, email, password, name, role) VALUES ($1, $2, $3, $4, $5)',
        [uuidv4(), 'admin@worktime.com', hashedPassword, 'System Admin', 'admin']
      );
      console.log('Default admin created: admin@worktime.com / admin123');
    }
    
    client.release();
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

initDatabase();

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'working', 
    time: new Date().toISOString(),
    database: 'PostgreSQL'
  });
});

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'default-secret', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

function requireManager(req, res, next) {
  if (req.user.role !== 'manager' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Manager access required' });
  }
  next();
}

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, name: user.name },
      process.env.JWT_SECRET || 'default-secret',
      { expiresIn: '8h' }
    );
    
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        department: user.department
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Register employee (manager only)
app.post('/api/auth/register', authenticateToken, requireManager, async (req, res) => {
  const { email, password, name, role, department } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = uuidv4();
    
    await pool.query(
      'INSERT INTO users (id, email, password, name, role, department) VALUES ($1, $2, $3, $4, $5, $6)',
      [id, email, hashedPassword, name, role || 'worker', department]
    );
    
    res.status(201).json({ id, email, name, role: role || 'worker' });
  } catch (err) {
    if (err.message.includes('unique constraint')) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

// Get all users (manager only)
app.get('/api/users', authenticateToken, requireManager, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, role, department FROM users ORDER BY name');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Generate QR code (manager only)
app.post('/api/qr-codes', authenticateToken, requireManager, async (req, res) => {
  const { locationName, description } = req.body;
  const id = uuidv4();
  const code = 'WORK-' + uuidv4().split('-')[0].toUpperCase();
  
  try {
    await pool.query(
      'INSERT INTO qr_codes (id, code, location_name, description, created_by) VALUES ($1, $2, $3, $4, $5)',
      [id, code, locationName, description, req.user.id]
    );
    
    // Generate QR code image URL (using qrserver API)
    const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${code}`;
    
    res.status(201).json({
      id,
      code,
      locationName,
      description,
      qrImage: qrImageUrl
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all QR codes
app.get('/api/qr-codes', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM qr_codes ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Scan QR code (clock in/out)
app.post('/api/scan', authenticateToken, async (req, res) => {
  const { qrCode, latitude, longitude, deviceInfo } = req.body;
  
  try {
    const qrResult = await pool.query('SELECT * FROM qr_codes WHERE code = $1 AND is_active = true', [qrCode]);
    const qrRecord = qrResult.rows[0];
    
    if (!qrRecord) return res.status(404).json({ error: 'Invalid or inactive QR code' });
    
    const lastEntryResult = await pool.query(
      'SELECT * FROM time_entries WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 1',
      [req.user.id]
    );
    const lastEntry = lastEntryResult.rows[0];
    
    const type = (!lastEntry || lastEntry.type === 'clock_out') ? 'clock_in' : 'clock_out';
    const entryId = uuidv4();
    
    await pool.query(
      'INSERT INTO time_entries (id, user_id, qr_code_id, type, latitude, longitude, device_info) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [entryId, req.user.id, qrRecord.id, type, latitude, longitude, JSON.stringify(deviceInfo)]
    );
    
    res.json({
      success: true,
      entryId,
      type,
      timestamp: new Date().toISOString(),
      location: qrRecord.location_name,
      message: type === 'clock_in' ? 'Clock in successful!' : 'Clock out successful!'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get my time entries
app.get('/api/my-entries', authenticateToken, async (req, res) => {
  const { startDate, endDate } = req.query;
  
  try {
    let query = `
      SELECT time_entries.*, qr_codes.location_name 
      FROM time_entries
      JOIN qr_codes ON time_entries.qr_code_id = qr_codes.id
      WHERE time_entries.user_id = $1
    `;
    const params = [req.user.id];
    
    if (startDate && endDate) {
      query += ' AND DATE(time_entries.timestamp) BETWEEN $2 AND $3';
      params.push(startDate, endDate);
    }
    
    query += ' ORDER BY time_entries.timestamp DESC';
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all time entries (manager only)
app.get('/api/time-entries', authenticateToken, requireManager, async (req, res) => {
  const { userId, startDate, endDate } = req.query;
  
  try {
    let query = `
      SELECT time_entries.*, users.name as user_name, users.email, users.department, qr_codes.location_name
      FROM time_entries
      JOIN users ON time_entries.user_id = users.id
      JOIN qr_codes ON time_entries.qr_code_id = qr_codes.id
      WHERE 1=1
    `;
    const params = [];
    let paramCount = 0;
    
    if (userId) {
      paramCount++;
      query += ` AND time_entries.user_id = $${paramCount}`;
      params.push(userId);
    }
    
    if (startDate && endDate) {
      paramCount++;
      query += ` AND DATE(time_entries.timestamp) BETWEEN $${paramCount}`;
      params.push(startDate);
      paramCount++;
      query += ` AND $${paramCount}`;
      params.push(endDate);
    }
    
    query += ' ORDER BY time_entries.timestamp DESC';
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Edit time entry (manager only)
app.put('/api/time-entries/:id', authenticateToken, requireManager, async (req, res) => {
  const entryId = req.params.id;
  const { newTimestamp, reason } = req.body;
  
  try {
    await pool.query(
      'UPDATE time_entries SET timestamp = $1, original_timestamp = COALESCE(original_timestamp, timestamp), edited_by = $2, edited_at = CURRENT_TIMESTAMP WHERE id = $3',
      [newTimestamp, req.user.id, entryId]
    );
    
    res.json({ success: true, message: 'Entry updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete time entry (manager only)
app.delete('/api/time-entries/:id', authenticateToken, requireManager, async (req, res) => {
  const entryId = req.params.id;
  
  try {
    await pool.query('DELETE FROM time_entries WHERE id = $1', [entryId]);
    res.json({ success: true, message: 'Entry deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get dashboard statistics
app.get('/api/dashboard-stats', authenticateToken, requireManager, async (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  
  try {
    const activeResult = await pool.query(
      'SELECT COUNT(DISTINCT user_id) as count FROM time_entries WHERE DATE(timestamp) = $1 AND type = $2',
      [today, 'clock_in']
    );
    
    const editsResult = await pool.query(
      "SELECT COUNT(*) as count FROM time_entries WHERE edited_at > CURRENT_TIMESTAMP - INTERVAL '1 day'"
    );
    
    res.json({
      activeToday: parseInt(activeResult.rows[0].count) || 0,
      recentEdits: parseInt(editsResult.rows[0].count) || 0,
      totalHoursToday: 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log('Server running on port ' + PORT);
});