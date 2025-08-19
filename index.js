const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: [
    'https://stock-opname-be.vercel.app',     // Frontend domain
    'https://stock-opname-fe.vercel.app',     // Alternative frontend domain
    'http://localhost:3000',                  // Local development
    'http://localhost:8080'                   // Alternative local
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Handle preflight requests
app.options('*', cors());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  dbName: process.env.DB_NAME
}).then(() => {
  console.log('MongoDB Connected');
}).catch(err => {
  console.error('Database connection error:', err);
});

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    enum: ['admin', 'user'],
    default: 'user'
  }
}, {
  timestamps: true
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Auth Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'Token tidak ditemukan' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ message: 'User tidak ditemukan' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token tidak valid' });
  }
};

// Routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'Stock Opname Backend API',
    version: '1.0.0',
    env_check: {
      mongodb_uri: !!process.env.MONGODB_URI,
      jwt_secret: !!process.env.JWT_SECRET,
      db_name: process.env.DB_NAME
    },
    endpoints: {
      register: 'POST /auth/register',
      login: 'POST /auth/login',
      profile: 'GET /auth/profile'
    }
  });
});

// Register
app.post('/auth/register', async (req, res) => {
  try {
    console.log('Register attempt:', req.body);
    console.log('Environment check:', {
      mongodb_uri: !!process.env.MONGODB_URI,
      jwt_secret: !!process.env.JWT_SECRET,
      db_name: process.env.DB_NAME
    });

    const { username, email, password, role } = req.body;

    if (!username || !email || !password) {
      console.log('Missing fields:', { username: !!username, email: !!email, password: !!password });
      return res.status(400).json({ message: 'Semua field harus diisi' });
    }

    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET not found in environment variables');
      return res.status(500).json({ message: 'Server configuration error' });
    }

    console.log('Checking existing user...');
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      console.log('User already exists:', existingUser.email);
      return res.status(400).json({ message: 'Username atau email sudah terdaftar' });
    }

    console.log('Creating new user...');
    const user = new User({
      username,
      email,
      password,
      role: role || 'user'
    });

    await user.save();
    console.log('User saved successfully');

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '7d' }
    );

    res.status(201).json({
      message: 'Registrasi berhasil',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Register error details:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email dan password harus diisi' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Email atau password salah' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Email atau password salah' });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE || '7d' }
    );

    res.json({
      message: 'Login berhasil',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Profile
app.get('/auth/profile', auth, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Test endpoint
app.get('/test', async (req, res) => {
  try {
    // Test database connection
    const dbState = mongoose.connection.readyState;
    const dbStates = {
      0: 'disconnected',
      1: 'connected',
      2: 'connecting',
      3: 'disconnecting'
    };

    // Test environment variables
    const envCheck = {
      mongodb_uri: !!process.env.MONGODB_URI,
      jwt_secret: !!process.env.JWT_SECRET,
      db_name: process.env.DB_NAME,
      jwt_expire: process.env.JWT_EXPIRE
    };

    // Test user model
    let userTest = null;
    try {
      const userCount = await User.countDocuments();
      userTest = { success: true, count: userCount };
    } catch (err) {
      userTest = { success: false, error: err.message };
    }

    res.json({
      message: 'Backend API is working!',
      timestamp: new Date().toISOString(),
      database: {
        state: dbStates[dbState] || 'unknown',
        stateCode: dbState
      },
      environment: envCheck,
      userModel: userTest
    });
  } catch (error) {
    res.status(500).json({
      message: 'Test endpoint error',
      error: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}`);
});