const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Auth Middleware to protect routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (token == null) return res.sendStatus(401); // if no token, unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // if token is invalid, forbidden
    req.user = user;
    next();
  });
};

// Register
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const [existingUsers] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUsers.length) return res.status(400).json({ error: 'Email already exists' });

    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
      [name, email, hash]
    );
    const newUser = { id: result.insertId, email };
    const token = jwt.sign(newUser, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'User registered', token, user: newUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(400).json({ error: 'Invalid credentials' });
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    const userPayload = { id: user.id, email: user.email, name: user.name, bio: user.bio, avatar_initials: user.avatar_initials };
    const token = jwt.sign(userPayload, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token, user: userPayload });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get public profile for a user
app.get('/api/users/:id/profile', async (req, res) => {
  try {
    const { id } = req.params;
    // Get user info
    const [userRows] = await pool.query('SELECT id, name, email, bio, avatar_initials FROM users WHERE id = ?', [id]);
    if (!userRows.length) return res.status(404).json({ error: 'User not found' });
    const user = userRows[0];

    // Get user's posts, projects, achievements
    const [posts] = await pool.query('SELECT *, DATE_FORMAT(created_at, "%M %D, %Y") as date FROM posts WHERE user_id = ? ORDER BY created_at DESC', [id]);
    const [projects] = await pool.query('SELECT * FROM projects WHERE user_id = ? AND is_public = TRUE', [id]);
    const [achievements] = await pool.query('SELECT * FROM achievements WHERE user_id = ?', [id]);

    res.json({ user, posts, projects, achievements });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all posts for the logged-in user
app.get('/api/profile/posts', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add a post for the logged-in user
app.post('/api/profile/posts', authenticateToken, async (req, res) => {
  const { title, description, icon } = req.body;
  try {
    await pool.query(
      'INSERT INTO posts (user_id, title, description, icon) VALUES (?, ?, ?, ?)',
      [req.user.id, title, description, icon]
    );
    res.status(201).json({ message: 'Post added' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all projects for the logged-in user
app.get('/api/profile/projects', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM projects WHERE user_id = ?', [req.user.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add a project for the logged-in user
app.post('/api/profile/projects', authenticateToken, async (req, res) => {
  const { title, description, tags, is_public } = req.body;
  try {
    await pool.query(
      'INSERT INTO projects (user_id, title, description, tags, is_public) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, title, description, tags, is_public]
    );
    res.status(201).json({ message: 'Project added' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all achievements for the logged-in user
app.get('/api/profile/achievements', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM achievements WHERE user_id = ?', [req.user.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add an achievement for the logged-in user
app.post('/api/profile/achievements', authenticateToken, async (req, res) => {
  const { title, description, date, type, icon } = req.body;
  try {
    await pool.query(
      'INSERT INTO achievements (user_id, title, description, date, type, icon) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, title, description, date, type, icon]
    );
    res.status(201).json({ message: 'Achievement added' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`)); 