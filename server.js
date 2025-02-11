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
    // Добавляем информацию о пользователе в `res.locals`, чтобы она была доступна в шаблонах EJS
    res.locals.user = {
        userId: req.session.userId,
        username: req.session.username
        // Здесь можно добавить другие данные пользователя, если они хранятся в сессии
    };
    next();
};

// Routes
// Home route
app.get('/', (req, res) => {
    res.redirect('/dashboard');
});

// Register
app.get('/register', (req, res) => {
    res.render('register', { error: null }); // Передаём `null`, чтобы не было ошибки, если нет сообщения об ошибке
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

        // Проверяем, существует ли пользователь с таким email
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
          return res.render('register', { error: 'User with this email already exists' });
        }

        // Хешируем пароль
        const hashedPassword = await bcrypt.hash(password, 10); // 10 - salt rounds

        const user = new User({ username, email, password: hashedPassword }); // Сохраняем хешированный пароль
        await user.save();
        req.session.userId = user._id;
        req.session.username = username;

        // Добавляем role пользователя в сессию (по умолчанию - 'user')
        req.session.role = user.role || 'user'; // Установка роли, если она определена в модели

        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        res.render('register', { error: 'Registration failed' });
    }
});

// Login
app.get('/login', (req, res) => {
    res.render('login', { error: null }); // То же, что и в GET /register
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('login', { error: 'Invalid email or password' });
        }

        // Сравниваем пароль с хешированным паролем
        const isMatch = await bcrypt.compare(password, user.password); // Используем bcrypt для сравнения

        if (isMatch) {
            req.session.userId = user._id;
            req.session.username = user.username;
            req.session.role = user.role || 'user';  //  Роль в сессию

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
        const username = req.session.username;

        // Передаём username и userId в шаблон
        res.render('dashboard', { username: username, userId: req.session.userId });
    } catch (error) {
        console.error(error);
        res.redirect('/login');
    }
});

//  Пример protected route (для администраторов, например)
app.get('/admin', requireLogin, (req, res) => {
    // Проверка роли пользователя в сессии
    if (req.session.role !== 'admin') {
        return res.status(403).send('Forbidden: You do not have permission to access this page.'); //  Или редирект
    }
    res.send("Welcome to the admin area!"); // Или отрисовка админского интерфейса
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});