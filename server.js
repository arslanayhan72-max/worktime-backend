const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();

// Railway uses this port
const PORT = process.env.PORT || 3000;

// Database location - uses Railway storage if available
const dbPath = process.env.RAILWAY_VOLUME_MOUNT_PATH 
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'timetracking.db')
  : './timetracking.db';

const db = new sqlite3.Database(dbPath);

// Allow requests from any website
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// Health check page
app.get('/health', (req, res) => {
  res.json({ 
    status: 'working', 
    time: new Date().toISOString(),
    database: dbPath 
  });
});

// Create database tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'worker',
    department TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS qr_codes (
    id TEXT PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    location_name TEXT NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT 1,
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS time_entries (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    qr_code_id TEXT NOT NULL,
    type TEXT CHECK(type IN ('clock_in', 'clock_out')) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    latitude REAL,
    longitude REAL,
    device_info TEXT,
    edited_by TEXT,
    edited_at DATETIME,
    original_timestamp DATETIME
  )`);

  // Create default admin user
  const adminEmail = 'admin@worktime.com';
  const adminPassword = 'admin123';
  
  db.get('SELECT * FROM users WHERE email = ?', [adminEmail], async (err, user) => {
    if (!user) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      const id = uuidv4();
      db.run(
        'INSERT INTO users (id, email, password, name, role) VALUES (?, ?, ?, ?, ?)',
        [id, adminEmail, hashedPassword, 'System Admin', 'admin']
      );
    }
  });
});

// Check if user is logged in
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

// Check if user is manager
function requireManager(req, res, next) {
  if (req.user.role !== 'manager' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Manager access required' });
  }
  next();
}

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
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
  });
});

// Register new employee (manager only)
app.post('/api/auth/register', authenticateToken, requireManager, async (req, res) => {
  const { email, password, name, role, department } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = uuidv4();
    
    db.run(
      'INSERT INTO users (id, email, password, name, role, department) VALUES (?, ?, ?, ?, ?, ?)',
      [id, email, hashedPassword, name, role || 'worker', department],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Email already exists' });
          }
          throw err;
        }
        res.status(201).json({ id, email, name, role: role || 'worker' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Generate QR code (manager only)
app.post('/api/qr-codes', authenticateToken, requireManager, (req, res) => {
  const { locationName, description } = req.body;
  const id = uuidv4();
  const code = 'WORK-' + uuidv4().split('-')[0].toUpperCase();
  
  db.run(
    'INSERT INTO qr_codes (id, code, location_name, description, created_by) VALUES (?, ?, ?, ?, ?)',
    [id, code, locationName, description, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      
      QRCode.toDataURL(code, { width: 400, margin: 2 }, (err, url) => {
        if (err) return res.status(500).json({ error: 'Failed to generate QR code' });
        
        res.status(201).json({
          id,
          code,
          locationName,
          description,
          qrImage: url
        });
      });
    }
  );
});

// Get all QR codes
app.get('/api/qr-codes', authenticateToken, (req, res) => {
  db.all('SELECT * FROM qr_codes ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Scan QR code (clock in/out)
app.post('/api/scan', authenticateToken, (req, res) => {
  const { qrCode, latitude, longitude, deviceInfo } = req.body;
  
  db.get('SELECT * FROM qr_codes WHERE code = ? AND is_active = 1', [qrCode], (err, qrRecord) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!qrRecord) return res.status(404).json({ error: 'Invalid or inactive QR code' });
    
    db.get(
      'SELECT * FROM time_entries WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1',
      [req.user.id],
      (err, lastEntry) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const type = (!lastEntry || lastEntry.type === 'clock_out') ? 'clock_in' : 'clock_out';
        const entryId = uuidv4();
        
        db.run(
          'INSERT INTO time_entries (id, user_id, qr_code_id, type, latitude, longitude, device_info) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [entryId, req.user.id, qrRecord.id, type, latitude, longitude, JSON.stringify(deviceInfo)],
          function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            res.json({
              success: true,
              entryId,
              type,
              timestamp: new Date().toISOString(),
              location: qrRecord.location_name,
              message: type === 'clock_in' ? 'Clock in successful!' : 'Clock out successful!'
            });
          }
        );
      }
    );
  });
});

// Get my time entries
app.get('/api/my-entries', authenticateToken, (req, res) => {
  const { startDate, endDate } = req.query;
  
  let query = `
    SELECT time_entries.*, qr_codes.location_name 
    FROM time_entries
    JOIN qr_codes ON time_entries.qr_code_id = qr_codes.id
    WHERE time_entries.user_id = ?
  `;
  const params = [req.user.id];
  
  if (startDate && endDate) {
    query += ' AND DATE(time_entries.timestamp) BETWEEN ? AND ?';
    params.push(startDate, endDate);
  }
  
  query += ' ORDER BY time_entries.timestamp DESC';
  
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get all time entries (manager only)
app.get('/api/time-entries', authenticateToken, requireManager, (req, res) => {
  const { userId, startDate, endDate } = req.query;
  
  let query = `
    SELECT time_entries.*, users.name as user_name, users.email, users.department, qr_codes.location_name
    FROM time_entries
    JOIN users ON time_entries.user_id = users.id
    JOIN qr_codes ON time_entries.qr_code_id = qr_codes.id
    WHERE 1=1
  `;
  const params = [];
  
  if (userId) {
    query += ' AND time_entries.user_id = ?';
    params.push(userId);
  }
  
  if (startDate && endDate) {
    query += ' AND DATE(time_entries.timestamp) BETWEEN ? AND ?';
    params.push(startDate, endDate);
  }
  
  query += ' ORDER BY time_entries.timestamp DESC';
  
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get all users (manager only)
app.get('/api/users', authenticateToken, requireManager, (req, res) => {
  db.all('SELECT id, name, email, role, department FROM users ORDER BY name', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Edit time entry (manager only)
app.put('/api/time-entries/:id', authenticateToken, requireManager, (req, res) => {
  const entryId = req.params.id;
  const { newTimestamp, reason } = req.body;
  
  db.get('SELECT * FROM time_entries WHERE id = ?', [entryId], (err, entry) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!entry) return res.status(404).json({ error: 'Entry not found' });
    
    db.run(
      'UPDATE time_entries SET timestamp = ?, original_timestamp = COALESCE(original_timestamp, timestamp), edited_by = ?, edited_at = CURRENT_TIMESTAMP WHERE id = ?',
      [newTimestamp, req.user.id, entryId],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: 'Entry updated successfully' });
      }
    );
  });
});

// Delete time entry (manager only)
app.delete('/api/time-entries/:id', authenticateToken, requireManager, (req, res) => {
  const entryId = req.params.id;
  
  db.run('DELETE FROM time_entries WHERE id = ?', [entryId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true, message: 'Entry deleted successfully' });
  });
});

// Get dashboard statistics
app.get('/api/dashboard-stats', authenticateToken, requireManager, (req, res) => {
  const today = new Date().toISOString().split('T')[0];
  
  db.get(
    'SELECT COUNT(DISTINCT user_id) as count FROM time_entries WHERE DATE(timestamp) = ? AND type = "clock_in"',
    [today],
    (err, activeRow) => {
      db.get(
        'SELECT COUNT(*) as count FROM time_entries WHERE edited_at > datetime("now", "-1 day")',
        [],
        (err, editsRow) => {
          res.json({
            activeToday: activeRow ? activeRow.count : 0,
            recentEdits: editsRow ? editsRow.count : 0,
            totalHoursToday: 0
          });
        }
      );
    }
  );
});

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log('Server running on port ' + PORT);
  console.log('Health check: http://localhost:' + PORT + '/health');
});