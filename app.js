const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const cors = require('cors');
const admin = require('firebase-admin');
const rateLimit = require('express-rate-limit');

// Initialize Firebase
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || require('./serviceAccountKey.json'));
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Serve static files from the public directory
app.use(express.static('public'));

const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key';
const users = [];

// GET /getInfo
// Enhanced logEvent function
async function logEvent(eventType, details, req, res, statusCode) {
    const logEntry = {
        logLevel: statusCode >= 400 ? "error" : "info",
        timestamp: new Date().toISOString(),
        eventType,
        method: req.method,
        url: req.originalUrl,
        path: req.path,
        query: req.query,
        params: req.params,
        body: req.body,
        statusCode: statusCode,
        responseTime: `${Date.now() - req.startTime}ms`,
        ip: req.ip || 'unknown',
        userAgent: req.get('User-Agent') || 'unknown',
        protocol: req.protocol,
        hostname: req.hostname,
        system: {
            nodeVersion: process.version,
            environment: process.env.NODE_ENV || "development",
            pid: process.pid
        },
        userId: details.userId || 'anonymous',
        ...details
    };

    try {
        await db.collection('logs').add(logEntry);
    } catch (error) {
        console.error('Error writing to Firestore:', error);
    }
}

// Add middleware to track request start time
app.use((req, res, next) => {
    req.startTime = Date.now();
    next();
});

// Update routes to use enhanced logging
// Update logEvent calls in routes
app.get('/getInfo', async (req, res) => {
    const info = {
        nodeVersion: process.version,
        student: {
            fullName: 'Luis Antonio Sanchez Garcia',
            group: 'Grupo: IDGS11'
        }
    };
    
    await logEvent('GET_INFO', {
        ip: req.ip,
        userAgent: req.get('User-Agent')
    }, req, res, 200);
    
    res.json(info);
});

app.post('/register', async (req, res) => {
    const { email, username, password } = req.body;
    
    if (!email || !username || !password) {
        await logEvent('REGISTER_ERROR', {
            error: 'All fields are required'
        }, req, res, 400);
        return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (!validateEmail(email)) {
        await logEvent('REGISTER_ERROR', {
            error: 'Invalid email format',
            email
        }, req, res, 400);
        return res.status(400).json({ error: 'Invalid email format' });
    }
    
    const userExists = users.some(u => u.email === email || u.username === username);
    if (userExists) {
        await logEvent('REGISTER_ERROR', {
            error: 'User already exists',
            email,
            username
        }, req, res, 400);
        return res.status(400).json({ error: 'User already exists' });
    }
    
    const user = { email, username, password };
    users.push(user);
    
    await logEvent('USER_REGISTERED', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: username,
        email
    }, req, res, 201);
    
    res.status(201).json({ message: 'User registered successfully' });
});

// POST /login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
        await logEvent('LOGIN_ERROR', {
            error: 'Invalid credentials',
            username
        }, req, res, 401);
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    
    // Generate MFA secret
    const mfaSecret = speakeasy.generateSecret({ length: 20 });
    user.mfaSecret = mfaSecret.base32;
    
    // Generate TOTP code directly
    const totpCode = speakeasy.totp({
        secret: mfaSecret.base32,
        encoding: 'base32'
    });
    
    await logEvent('USER_LOGIN_SUCCESS', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: username,
        success: true
    }, req, res, 200);
    
    res.json({ 
        token,
        mfaSecret: mfaSecret.base32,
        mfaCode: totpCode,
        message: 'Use este código para verificar su identidad'
    });
});

// POST /verify-mfa
app.post('/verify-mfa', async (req, res) => {
    const token = req.headers['x-auth-token'];
    const mfaCode = req.headers['x-mfa-code'];
    
    if (!token || !mfaCode) {
        return res.status(400).json({ error: 'Token and MFA code are required in headers' });
    }
    
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const user = users.find(u => u.username === decoded.username);
        
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }
        
        const verified = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: 'base32',
            token: mfaCode
        });
        
        if (verified) {
            res.json({ message: 'MFA verification successful' });
        } else {
            res.status(401).json({ error: 'Invalid MFA code' });
        }
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// Helper functions
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

// Add rate limiter configuration
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again after 10 minutes',
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    keyGenerator: (req) => {
        // Use IP + user ID if available for more granular rate limiting
        return req.ip + (req.user?.id || '');
    }
});

// Apply to specific routes
app.use('/login', limiter);
app.use('/register', limiter);
app.use('/verify-mfa', limiter);

const PORT = 3002;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Add a new route to fetch logs
app.get('/logs', async (req, res) => {
    try {
        const logsSnapshot = await db.collection('logs')
            .orderBy('timestamp', 'desc')
            .limit(100)
            .get();
        
        const logs = [];
        logsSnapshot.forEach(doc => {
            logs.push(doc.data());
        });
        
        await logEvent('FETCH_LOGS', {
            ip: req.ip,
            userAgent: req.get('User-Agent')
        }, req, res, 200);
        
        res.json(logs);
    } catch (error) {
        console.error('Error fetching logs:', error);
        await logEvent('FETCH_LOGS_ERROR', {
            error: error.message
        }, req, res, 500);
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});
