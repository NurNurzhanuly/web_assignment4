const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB Connection
const username = encodeURIComponent(process.env.DB_USER);
const password = encodeURIComponent(process.env.DB_PASS);
const cluster = process.env.DB_CLUSTER;
const dbName = process.env.DB_NAME;
const mongoUri = `mongodb+srv://${username}:${password}@${cluster}/${dbName}?retryWrites=true&w=majority`;

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(express.json());

// Session setup
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: mongoUri,
    }),
    cookie: {
        maxAge: 60 * 60 * 1000, // 1 hour
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    }
}));

// Authentication middleware
const requireLogin = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    // Добавляем информацию о пользователе в `res.locals`, чтобы она была доступна в шаблонах EJS
    res.locals.user = {
        userId: req.session.userId,
        username: req.session.username,
        role: req.session.role || 'user' // Add default role if not set
    };
    next();
};

// Model import
const User = require('./models/user'); // Assumes you have a User model

// Routes - DEFINED AFTER LAYOUT MIDDLEWARE
app.get('/', (req, res) => {
    res.redirect('/dashboard');
});

// Register
app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Server-side validation
        if (!username || !email || !password) {
            return res.render('register', { error: 'All fields are required' });
        }
        if (password.length < 6) {
            return res.render('register', { error: 'Password must be at least 6 characters' });
        }

        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
          return res.render('register', { error: 'User with this email already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        req.session.userId = user._id;
        req.session.username = username;
        req.session.role = user.role || 'user';  // Role at registration
        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        res.render('register', { error: 'Registration failed' });
    }
});

// Login
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('login', { error: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            req.session.userId = user._id;
            req.session.username = user.username;
            req.session.role = user.role || 'user'; // Role at login
            return res.redirect('/dashboard');
        } else {
            return res.render('login', { error: 'Invalid email or password' });
        }
    } catch (err) {
        console.error(err);
        res.render('login', { error: 'Login failed' });
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
        }
        res.redirect('/login');
    });
});

// Dashboard
app.get('/dashboard', requireLogin, async (req, res) => {
    try {
        // username available in res.locals.user.username
        res.render('dashboard');  // No need to pass data
    } catch (error) {
        console.error(error);
        res.redirect('/login');
    }
});

//Admin test
app.get('/admin', requireLogin, (req, res) => {
    if (req.session.role !== 'admin') {
      return res.status(403).send('Forbidden');
    }
    res.send("Admin Area");
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});