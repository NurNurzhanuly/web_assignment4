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

// EJS setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

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
    next();
};

// Routes

// Home route - ADD THIS
app.get('/', (req, res) => {
    res.send('Welcome to my application!'); // Or any content/HTML you want to display
});

// Register
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Server-side validation
        if (!username || !email || !password) {
            return res.render('register', { error: 'All fields are required' });
        }

        const user = new User({ username, email, password });
        await user.save();
        req.session.userId = user._id;
        req.session.username = username;
        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        res.render('register', { error: 'Registration failed' });
    }
});

// Login
app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('login', { error: 'Invalid email or password' });
        }

        const isMatch = await user.comparePassword(password);

        if (isMatch) {
            req.session.userId = user._id;
            req.session.username = user.username;
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
         // Get username from the session
        const username = req.session.username;

        // Render the dashboard template, passing the username
        res.render('dashboard', { username: username });
    } catch (error) {
        console.error(error);
        res.redirect('/login'); // Redirect to login on error
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});