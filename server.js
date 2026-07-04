/**
 * SOA Secure Online Album System
 * A production-ready video streaming platform with OTP authentication
 * 
 * Features:
 * - Secure video streaming from protected directory
 * - OTP-based user authentication
 * - Time-limited, single-use download tokens
 * - Admin panel for video management
 * - Rate limiting and security headers
 */

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const nodemailer = require('nodemailer');
const Datastore = require('@seald-io/nedb');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// ============================================
// Configuration
// ============================================

const config = {
    port: process.env.PORT || 30000,
    sessionSecret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
    adminPassword: process.env.ADMIN_PASSWORD || 'admin123',
    otpExpiry: parseInt(process.env.OTP_EXPIRY_MINUTES) || 5,
    otpLength: parseInt(process.env.OTP_LENGTH) || 6,
    downloadTokenExpiry: parseInt(process.env.DOWNLOAD_TOKEN_EXPIRY_MINUTES) || 5,
    maxFileSize: (parseInt(process.env.MAX_FILE_SIZE_MB) || 500) * 1024 * 1024,
    allowedMimeTypes: ['video/mp4', 'application/pdf'],
    smtp: {
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true',
        user: process.env.SMTP_USER || '',
        pass: process.env.SMTP_PASS || '',
        from: process.env.EMAIL_FROM || '"SOA Secure Online Album" <noreply@secure-online-album.local>'
    }
};

// ============================================
// Directory Setup
// ============================================

const directories = {
    uploads: path.join(__dirname, 'uploads'),
    data: path.join(__dirname, 'data'),
    views: path.join(__dirname, 'views')
};

const envFilePath = path.join(__dirname, '.env');

const editableEnvKeys = [
    'PORT',
    'NODE_ENV',
    'SESSION_SECRET',
    'ADMIN_PASSWORD',
    'SMTP_HOST',
    'SMTP_PORT',
    'SMTP_SECURE',
    'SMTP_USER',
    'SMTP_PASS',
    'EMAIL_FROM',
    'MAX_FILE_SIZE_MB',
    'OTP_EXPIRY_MINUTES',
    'OTP_LENGTH',
    'DOWNLOAD_TOKEN_EXPIRY_MINUTES'
];

// Create directories if they don't exist
Object.values(directories).forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// ============================================
// Database Setup (NeDB - File-based)
// ============================================

// Albums database - stores album metadata
const albumsDb = new Datastore({
    filename: path.join(directories.data, 'albums.db'),
    autoload: true
});

// OTP database - stores temporary OTP records
const otpDb = new Datastore({
    filename: path.join(directories.data, 'otp.db'),
    autoload: true
});

// Download tokens database
const downloadTokensDb = new Datastore({
    filename: path.join(directories.data, 'download_tokens.db'),
    autoload: true
});

// User info magic-link tokens
const infoTokensDb = new Datastore({
    filename: path.join(directories.data, 'info_tokens.db'),
    autoload: true
});

// Videos database - stores video metadata
const videosDb = new Datastore({
    filename: path.join(directories.data, 'videos.db'),
    autoload: true
});

// Users database - stable identity records for each email
const usersDb = new Datastore({
    filename: path.join(directories.data, 'users.db'),
    autoload: true
});

const favoritesDb = new Datastore({
    filename: path.join(directories.data, 'favorites.db'),
    autoload: true
});

const recentDb = new Datastore({
    filename: path.join(directories.data, 'recent.db'),
    autoload: true
});

const loginHistoryDb = new Datastore({
    filename: path.join(directories.data, 'login_history.db'),
    autoload: true
});

const supportRequestsDb = new Datastore({
    filename: path.join(directories.data, 'support_requests.db'),
    autoload: true
});

const shareTokensDb = new Datastore({
    filename: path.join(directories.data, 'share_tokens.db'),
    autoload: true
});

// Create indexes for better query performance
albumsDb.ensureIndex({ fieldName: 'albumId', unique: true });
albumsDb.ensureIndex({ fieldName: 'userEmail', unique: false });
albumsDb.ensureIndex({ fieldName: 'customerId', unique: false });
albumsDb.ensureIndex({ fieldName: 'userId', unique: false });
otpDb.ensureIndex({ fieldName: 'email', unique: false });
otpDb.ensureIndex({ fieldName: 'albumId', unique: false });
downloadTokensDb.ensureIndex({ fieldName: 'token', unique: true });
downloadTokensDb.ensureIndex({ fieldName: 'used', unique: false });
infoTokensDb.ensureIndex({ fieldName: 'token', unique: true });
infoTokensDb.ensureIndex({ fieldName: 'email', unique: false });
videosDb.ensureIndex({ fieldName: 'albumId', unique: false });
usersDb.ensureIndex({ fieldName: 'email', unique: true });
usersDb.ensureIndex({ fieldName: 'userId', unique: true });
usersDb.ensureIndex({ fieldName: 'customerId', unique: false });
favoritesDb.ensureIndex({ fieldName: 'userEmail', unique: false });
favoritesDb.ensureIndex({ fieldName: 'mediaId', unique: false });
recentDb.ensureIndex({ fieldName: 'userEmail', unique: false });
recentDb.ensureIndex({ fieldName: 'mediaId', unique: false });
loginHistoryDb.ensureIndex({ fieldName: 'userEmail', unique: false });
supportRequestsDb.ensureIndex({ fieldName: 'userEmail', unique: false });
supportRequestsDb.ensureIndex({ fieldName: 'status', unique: false });
supportRequestsDb.ensureIndex({ fieldName: 'requestType', unique: false });
shareTokensDb.ensureIndex({ fieldName: 'token', unique: true });
shareTokensDb.ensureIndex({ fieldName: 'mediaId', unique: false });

// ============================================
// Email Transporter Setup
// ============================================

function createEmailTransporter() {
    return nodemailer.createTransport({
        host: config.smtp.host,
        port: config.smtp.port,
        secure: config.smtp.secure,
        auth: config.smtp.user && config.smtp.pass ? {
            user: config.smtp.user,
            pass: config.smtp.pass
        } : null
    });
}

let transporter = createEmailTransporter();

function verifyEmailTransporter() {
    transporter.verify((error) => {
        if (error) {
            console.log('⚠️  SMTP connection failed. Email features may not work.');
            console.log('   Error:', error.message);
        } else {
            console.log('✅ SMTP server is ready to send emails');
        }
    });
}

verifyEmailTransporter();

// ============================================
// Express App Setup
// ============================================

const app = express();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false, // Disable for simplicity, can be configured
    crossOriginEmbedderPolicy: false
}));

// Trust proxy for rate limiting behind reverse proxy
app.set('trust proxy', 1);

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
    secret: config.sessionSecret,
    resave: true, // Keep session alive on each request
    saveUninitialized: true, // Save sessions even if not modified
    cookie: {
        secure: 'auto',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax' // Allow cookies for same-site requests
    }
}));

// Static files (views)
app.use(express.static(directories.views));

// ============================================
// Rate Limiters
// ============================================

// OTP request rate limiter
const otpRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 requests per window
    message: { error: 'Too many OTP requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

// General API rate limiter
const apiRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // 100 requests per window
    message: { error: 'Too many requests. Please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/', apiRateLimiter);

// ============================================
// File Upload Configuration
// ============================================

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, directories.uploads);
    },
    filename: (req, file, cb) => {
        // Generate unique filename with timestamp and UUID
        const uniqueName = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: config.maxFileSize
    },
    fileFilter: (req, file, cb) => {
        const isPdf = file.mimetype === 'application/pdf' || file.originalname.toLowerCase().endsWith('.pdf');
        if (config.allowedMimeTypes.includes(file.mimetype) || isPdf) {
            cb(null, true);
        } else {
            cb(new Error('Only MP4 video and PDF files are allowed'), false);
        }
    }
});

// ============================================
// Utility Functions
// ============================================

/**
 * Generate a random OTP
 */
function generateOTP() {
    const chars = '0123456789';
    let otp = '';
    for (let i = 0; i < config.otpLength; i++) {
        otp += chars[Math.floor(Math.random() * chars.length)];
    }
    return otp;
}

/**
 * Hash OTP for secure storage
 */
function hashOTP(otp) {
    return bcrypt.hashSync(otp, 10);
}

/**
 * Verify OTP against hash
 */
function verifyOTP(otp, hash) {
    return bcrypt.compareSync(otp, hash);
}

/**
 * Mask email address
 */
function maskEmail(email) {
    if (!email || !email.includes('@')) return '***@***.***';
    const [username, domain] = email.split('@');
    const maskedUsername = username.substring(0, 2) + '****';
    return `${maskedUsername}@${domain}`;
}

function normalizeEmail(email) {
    return (email || '').trim().toLowerCase();
}

function cleanId(value) {
    return (value || '').trim();
}

function generateReadableId(prefix) {
    return `${prefix}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

function readEnvFile() {
    if (!fs.existsSync(envFilePath)) return {};
    const stat = fs.statSync(envFilePath);
    if (!stat.isFile()) {
        throw new Error('.env exists but is not a file. Delete the .env folder and create a .env file.');
    }
    return require('dotenv').parse(fs.readFileSync(envFilePath));
}

function quoteEnvValue(value) {
    const stringValue = String(value ?? '');
    if (stringValue === '') return '';
    if (/[\s#"'<>]/.test(stringValue)) {
        return JSON.stringify(stringValue);
    }
    return stringValue;
}

function maskSecret(value) {
    if (!value) return '';
    if (value.length <= 4) return '****';
    return `${value.slice(0, 2)}****${value.slice(-2)}`;
}

function normalizeEmailFrom(from, smtpUser) {
    let value = String(from || '').trim().replace(/\\"/g, '"');
    if (!smtpUser) return value;

    const addressMatch = value.match(/<([^>]+)>/);
    const fromAddress = addressMatch ? addressMatch[1].trim().toLowerCase() : value.toLowerCase();
    const smtpAddress = smtpUser.trim().toLowerCase();

    if (!value || (smtpAddress.endsWith('@gmail.com') && fromAddress !== smtpAddress)) {
        return `"SOA Secure Online Album" <${smtpUser}>`;
    }

    return value;
}

function writeEnvFile(values) {
    const existing = readEnvFile();
    const next = { ...existing, ...values };
    const now = new Date().toISOString();
    const lines = [
        '# ===========================================',
        '# SOA Secure Online Album System - Configuration',
        `# Updated from admin panel at ${now}`,
        '# ===========================================',
        '',
        '# Server Configuration',
        `PORT=${quoteEnvValue(next.PORT || config.port)}`,
        `NODE_ENV=${quoteEnvValue(next.NODE_ENV || process.env.NODE_ENV || 'production')}`,
        '',
        '# Security',
        `SESSION_SECRET=${quoteEnvValue(next.SESSION_SECRET || config.sessionSecret)}`,
        `ADMIN_PASSWORD=${quoteEnvValue(next.ADMIN_PASSWORD || config.adminPassword)}`,
        '',
        '# SMTP/Email Configuration',
        `SMTP_HOST=${quoteEnvValue(next.SMTP_HOST || config.smtp.host)}`,
        `SMTP_PORT=${quoteEnvValue(next.SMTP_PORT || config.smtp.port)}`,
        `SMTP_SECURE=${quoteEnvValue(String(next.SMTP_SECURE ?? config.smtp.secure))}`,
        `SMTP_USER=${quoteEnvValue(next.SMTP_USER || config.smtp.user)}`,
        `SMTP_PASS=${quoteEnvValue(next.SMTP_PASS || config.smtp.pass)}`,
        `EMAIL_FROM=${quoteEnvValue(next.EMAIL_FROM || config.smtp.from)}`,
        '',
        '# Upload Settings',
        `MAX_FILE_SIZE_MB=${quoteEnvValue(next.MAX_FILE_SIZE_MB || Math.round(config.maxFileSize / (1024 * 1024)))}`,
        '',
        '# OTP Settings',
        `OTP_EXPIRY_MINUTES=${quoteEnvValue(next.OTP_EXPIRY_MINUTES || config.otpExpiry)}`,
        `OTP_LENGTH=${quoteEnvValue(next.OTP_LENGTH || config.otpLength)}`,
        '',
        '# Download Token Settings',
        `DOWNLOAD_TOKEN_EXPIRY_MINUTES=${quoteEnvValue(next.DOWNLOAD_TOKEN_EXPIRY_MINUTES || config.downloadTokenExpiry)}`,
        ''
    ];

    if (fs.existsSync(envFilePath)) {
        const stat = fs.statSync(envFilePath);
        if (!stat.isFile()) {
            throw new Error('.env exists but is not a file. Delete the .env folder and create a .env file.');
        }
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        fs.copyFileSync(envFilePath, path.join(__dirname, `.env.backup-${stamp}`));
    }
    fs.writeFileSync(envFilePath, lines.join('\n'), 'utf8');
    editableEnvKeys.forEach(key => {
        if (next[key] !== undefined) process.env[key] = String(next[key]);
    });
    return next;
}

function refreshRuntimeConfig(envValues = readEnvFile()) {
    config.adminPassword = envValues.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD || config.adminPassword;
    config.otpExpiry = parseInt(envValues.OTP_EXPIRY_MINUTES || process.env.OTP_EXPIRY_MINUTES) || config.otpExpiry;
    config.otpLength = parseInt(envValues.OTP_LENGTH || process.env.OTP_LENGTH) || config.otpLength;
    config.downloadTokenExpiry = parseInt(envValues.DOWNLOAD_TOKEN_EXPIRY_MINUTES || process.env.DOWNLOAD_TOKEN_EXPIRY_MINUTES) || config.downloadTokenExpiry;
    config.smtp.host = envValues.SMTP_HOST || process.env.SMTP_HOST || config.smtp.host;
    config.smtp.port = parseInt(envValues.SMTP_PORT || process.env.SMTP_PORT) || config.smtp.port;
    config.smtp.secure = String(envValues.SMTP_SECURE ?? process.env.SMTP_SECURE) === 'true';
    config.smtp.user = envValues.SMTP_USER || process.env.SMTP_USER || '';
    config.smtp.pass = envValues.SMTP_PASS || process.env.SMTP_PASS || '';
    config.smtp.from = normalizeEmailFrom(envValues.EMAIL_FROM || process.env.EMAIL_FROM || config.smtp.from, config.smtp.user);
    transporter = createEmailTransporter();
}

/**
 * Generate secure download token
 */
function generateDownloadToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * Send email function
 */
async function sendEmail(to, subject, html) {
    if (!config.smtp.user || !config.smtp.pass) {
        console.log('⚠️  Email not configured. Would send to:', to);
        console.log('   Subject:', subject);
        throw new Error('SMTP is not configured');
    }

    try {
        const info = await transporter.sendMail({
            from: normalizeEmailFrom(config.smtp.from, config.smtp.user),
            to: to,
            subject: subject,
            html: html,
            text: html.replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
        });
        console.log('✅ Email accepted by SMTP:', info.messageId, 'to:', to);
        return info;
    } catch (error) {
        console.error('❌ Email send failed:', error.message);
        throw error;
    }
}

/**
 * Format file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function csvEscape(value) {
    const stringValue = String(value ?? '');
    if (/[",\n]/.test(stringValue)) {
        return `"${stringValue.replace(/"/g, '""')}"`;
    }
    return stringValue;
}

function sendCsv(res, filename, rows) {
    const csv = rows.map(row => row.map(csvEscape).join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
}

function getMediaType(file) {
    return file.mimetype === 'application/pdf' || file.originalname.toLowerCase().endsWith('.pdf') ? 'pdf' : 'video';
}

function getDownloadName(media) {
    const fallbackExt = media.type === 'pdf' ? '.pdf' : '.mp4';
    return media.originalName || `${media.title || 'album-file'}${fallbackExt}`;
}

async function createDownloadTokenAndEmail(req, media, userEmail, approvedBy = 'system') {
    const token = generateDownloadToken();
    const expiresAt = new Date(Date.now() + config.downloadTokenExpiry * 60 * 1000);

    await dbInsert(downloadTokensDb, {
        _id: uuidv4(),
        token,
        videoId: media._id,
        videoTitle: media.title,
        userEmail,
        approvedBy,
        expiresAt,
        used: false,
        createdAt: new Date()
    });

    const downloadUrl = `${req.protocol}://${req.get('host')}/api/download/${token}`;
    const emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #333;">Your Album File Download Link is Approved</h2>
            <p>Your download request has been approved. Click the button below to download your file:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="${downloadUrl}" style="background-color: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                    Download File
                </a>
            </div>
            <p><strong>File:</strong> ${media.title}</p>
            <p><strong>Size:</strong> ${formatFileSize(media.size)}</p>
            <p><strong>Important:</strong></p>
            <ul>
                <li>This link expires in <strong>${config.downloadTokenExpiry} minutes</strong></li>
                <li>This link can only be used <strong>once</strong></li>
                <li>Do not share this link with others</li>
            </ul>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">This is an automated message. Please do not reply.</p>
        </div>
    `;

    await sendEmail(userEmail, `Download approved: ${media.title}`, emailHtml);
    return { token, expiresAt };
}

function albumAccessQuery(req) {
    if (req.session.albumIds && Array.isArray(req.session.albumIds)) {
        return { albumId: { $in: req.session.albumIds } };
    }
    return { albumId: req.session.albumId };
}

function getClientIp(req) {
    return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();
}

async function getAccessibleMedia(req, mediaId) {
    if (!mediaId) return null;
    return dbFindOne(videosDb, { _id: mediaId, ...albumAccessQuery(req) });
}

function dbFindOne(db, query) {
    return new Promise((resolve, reject) => {
        db.findOne(query, (err, doc) => err ? reject(err) : resolve(doc));
    });
}

function dbFind(db, query) {
    return new Promise((resolve, reject) => {
        db.find(query, (err, docs) => err ? reject(err) : resolve(docs || []));
    });
}

function dbInsert(db, doc) {
    return new Promise((resolve, reject) => {
        db.insert(doc, (err, inserted) => err ? reject(err) : resolve(inserted));
    });
}

function dbUpdate(db, query, update, options = {}) {
    return new Promise((resolve, reject) => {
        db.update(query, update, options, (err, count) => err ? reject(err) : resolve(count));
    });
}

function dbRemove(db, query, options = {}) {
    return new Promise((resolve, reject) => {
        db.remove(query, options, (err, count) => err ? reject(err) : resolve(count));
    });
}

async function ensureUserForEmail(email, userId = '', customerId = '') {
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail) throw new Error('Email is required');

    let user = await dbFindOne(usersDb, { email: normalizedEmail });
    if (user) {
        const nextUserId = cleanId(user.userId || userId || generateReadableId('USR'));
        const nextCustomerId = cleanId(user.customerId || customerId || generateReadableId('CUST'));
        if (nextUserId !== user.userId || nextCustomerId !== user.customerId) {
            await dbUpdate(usersDb, { _id: user._id }, { $set: { userId: nextUserId, customerId: nextCustomerId, updatedAt: new Date() } });
            user = { ...user, userId: nextUserId, customerId: nextCustomerId };
        }
        return user;
    }

    const newUser = {
        _id: uuidv4(),
        email: normalizedEmail,
        userId: cleanId(userId) || generateReadableId('USR'),
        customerId: cleanId(customerId) || generateReadableId('CUST'),
        notes: '',
        createdAt: new Date(),
        updatedAt: new Date()
    };

    try {
        return await dbInsert(usersDb, newUser);
    } catch (error) {
        if (error.errorType === 'uniqueViolated') {
            return dbFindOne(usersDb, { email: normalizedEmail });
        }
        throw error;
    }
}

async function syncAlbumsToUser(user) {
    await dbUpdate(
        albumsDb,
        { userEmail: user.email },
        { $set: { userId: user.userId, customerId: user.customerId } },
        { multi: true }
    );
}

async function backfillUsersFromAlbums() {
    try {
        const albums = await dbFind(albumsDb, {});
        const seen = new Set();
        for (const album of albums) {
            const email = normalizeEmail(album.userEmail);
            if (!email || seen.has(email)) continue;
            seen.add(email);
            const user = await ensureUserForEmail(email, album.userId, album.customerId);
            await syncAlbumsToUser(user);
        }
    } catch (error) {
        console.error('User backfill failed:', error.message);
    }
}

async function buildUserInfoPayload(email) {
    const normalizedEmail = normalizeEmail(email);
    const user = await dbFindOne(usersDb, { email: normalizedEmail });
    if (!user) return null;

    const albums = await dbFind(albumsDb, { userEmail: normalizedEmail });
    const albumIds = albums.map(album => album.albumId);
    const media = albumIds.length ? await dbFind(videosDb, { albumId: { $in: albumIds } }) : [];

    return {
        user: {
            email: user.email,
            userId: user.userId,
            customerId: user.customerId,
            createdAt: user.createdAt
        },
        summary: {
            albums: albums.length,
            files: media.length,
            videos: media.filter(item => (item.type || 'video') !== 'pdf').length,
            pdfs: media.filter(item => (item.type || 'video') === 'pdf').length
        },
        albums: albums.map(album => ({
            albumId: album.albumId,
            createdAt: album.createdAt,
            fileCount: media.filter(item => item.albumId === album.albumId).length,
            videoCount: media.filter(item => item.albumId === album.albumId && (item.type || 'video') !== 'pdf').length,
            pdfCount: media.filter(item => item.albumId === album.albumId && (item.type || 'video') === 'pdf').length
        })),
        media: media.map(item => ({
            id: item._id,
            albumId: item.albumId,
            title: item.title,
            type: item.type || 'video',
            size: formatFileSize(item.size),
            createdAt: item.createdAt
        }))
    };
}

function requireInfoAuth(req, res, next) {
    if (req.session && req.session.infoEmail) return next();
    res.status(401).json({ error: 'Info verification required' });
}

// ============================================
// Authentication Middleware
// ============================================

/**
 * Check if user is authenticated for album access
 */
function requireAlbumAuth(req, res, next) {
    if (req.session && req.session.authenticated && (req.session.albumId || req.session.albumIds)) {
        return next();
    }
    res.status(401).json({ error: 'Not authenticated', requiresAuth: true });
}

/**
 * Check if admin is authenticated
 */
function requireAdminAuth(req, res, next) {
    if (req.session && req.session.isAdmin) {
        return next();
    }
    res.status(401).json({ error: 'Admin authentication required' });
}

// ============================================
// API Routes
// ============================================

// ---- Health Check ----
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ---- Album Access Flow ----

/**
 * Step 1: Check if album ID exists
 */
app.get('/api/album/:albumId', (req, res) => {
    const { albumId } = req.params;

    albumsDb.findOne({ albumId: albumId.trim() }, (err, album) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!album) {
            return res.status(404).json({ error: 'Album not found' });
        }

        // Return masked email
        res.json({
            found: true,
            maskedEmail: maskEmail(album.userEmail),
            albumId: album.albumId
        });
    });
});

/**
 * Alternate Step 1: Check albums by email + customer ID
 */
app.post('/api/customer/check', (req, res) => {
    const { email, customerId } = req.body;

    if (!email || !customerId) {
        return res.status(400).json({ error: 'Email and Customer ID are required' });
    }

    usersDb.findOne({
        email: normalizeEmail(email),
        customerId: cleanId(customerId)
    }, (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(404).json({ error: 'No albums found for this email and customer ID' });
        }

        albumsDb.find({ userEmail: user.email }, (err, albums) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (!albums || albums.length === 0) {
                return res.status(404).json({ error: 'No albums found for this user' });
            }

            res.json({
                found: true,
                maskedEmail: maskEmail(user.email),
                email: user.email,
                userId: user.userId,
                customerId: user.customerId,
                albumCount: albums.length
            });
        });
    });
});

/**
 * Step 2: Request OTP
 */
app.post('/api/otp/request', otpRateLimiter, async (req, res) => {
    try {
        const { albumId, email, customerId, mode = 'album' } = req.body;

        if (!email || (mode === 'album' && !albumId) || (mode === 'customer' && !customerId)) {
            return res.status(400).json({ error: 'Required login details are missing' });
        }

        const normalizedEmail = email.trim().toLowerCase();
        const normalizedAlbumId = albumId ? albumId.trim() : '';
        const normalizedCustomerId = cleanId(customerId);
        const otpScope = mode === 'customer'
            ? `customer:${normalizedEmail}:${normalizedCustomerId}`
            : normalizedAlbumId;

        const albums = await new Promise((resolve, reject) => {
            const query = mode === 'customer'
                ? { userEmail: normalizedEmail }
                : { albumId: normalizedAlbumId };
            albumsDb.find(query, (err, docs) => {
                if (err) reject(err);
                else resolve(docs || []);
            });
        });

        const user = await ensureUserForEmail(
            normalizedEmail,
            albums[0] ? albums[0].userId : '',
            albums[0] ? albums[0].customerId : normalizedCustomerId
        );
        await syncAlbumsToUser(user);

        if (mode === 'customer' && user.customerId !== normalizedCustomerId) {
            return res.status(403).json({ error: 'Customer ID does not match this email' });
        }

        if (!albums.length) {
            return res.status(404).json({ error: mode === 'customer' ? 'No albums found for this customer' : 'Album not found' });
        }

        // Verify email matches (case-insensitive)
        if (albums.some(album => album.userEmail.toLowerCase() !== normalizedEmail)) {
            return res.status(403).json({ error: 'Email does not match album records' });
        }

        // Generate OTP
        const otp = generateOTP();
        const otpHash = hashOTP(otp);
        const expiresAt = new Date(Date.now() + config.otpExpiry * 60 * 1000);

        // Remove any existing OTPs for this email/album combo
        await new Promise((resolve, reject) => {
            otpDb.remove({ email: normalizedEmail, albumId: otpScope }, { multi: true }, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // Store new OTP
        const otpRecord = {
            _id: uuidv4(),
            email: normalizedEmail,
            albumId: otpScope,
            mode,
            customerId: normalizedCustomerId,
            otpHash: otpHash,
            expiresAt: expiresAt,
            attempts: 0,
            maxAttempts: 5,
            createdAt: new Date()
        };

        await new Promise((resolve, reject) => {
            otpDb.insert(otpRecord, (err, doc) => {
                if (err) reject(err);
                else resolve(doc);
            });
        });

        // Send email
        const emailHtml = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #333;">SOA Secure Online Album Access - OTP Verification</h2>
                <p>Your One-Time Password (OTP) for accessing the secure online album is:</p>
                <div style="background-color: #f4f4f4; padding: 15px; text-align: center; margin: 20px 0;">
                    <span style="font-size: 28px; font-weight: bold; letter-spacing: 5px; color: #2c3e50;">${otp}</span>
                </div>
                <p>This OTP will expire in <strong>${config.otpExpiry} minutes</strong>.</p>
                <p>If you did not request this OTP, please ignore this email.</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="color: #666; font-size: 12px;">This is an automated message. Please do not reply.</p>
            </div>
        `;

        await sendEmail(normalizedEmail, 'Your Album Access OTP', emailHtml);

        res.json({
            success: true,
            message: 'OTP sent successfully',
            expiresAt: expiresAt
        });

    } catch (error) {
        console.error('OTP request error:', error);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});

/**
 * Step 3: Verify OTP
 */
app.post('/api/otp/verify', (req, res) => {
    const { albumId, email, customerId, otp, mode = 'album' } = req.body;

    if (!email || !otp || (mode === 'album' && !albumId) || (mode === 'customer' && !customerId)) {
        return res.status(400).json({ error: 'Required verification details are missing' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedAlbumId = albumId ? albumId.trim() : '';
    const normalizedCustomerId = cleanId(customerId);
    const otpScope = mode === 'customer'
        ? `customer:${normalizedEmail}:${normalizedCustomerId}`
        : normalizedAlbumId;

    // Find OTP record
    otpDb.findOne({ 
        email: normalizedEmail, 
        albumId: otpScope 
    }, (err, otpRecord) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!otpRecord) {
            return res.status(404).json({ error: 'No OTP found. Please request a new one.' });
        }

        // Check if max attempts exceeded
        if (otpRecord.attempts >= otpRecord.maxAttempts) {
            return res.status(429).json({ error: 'Maximum attempts exceeded. Please request a new OTP.' });
        }

        // Check if expired
        if (new Date() > new Date(otpRecord.expiresAt)) {
            return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
        }

        // Verify OTP
        if (!verifyOTP(otp, otpRecord.otpHash)) {
            // Increment attempts
            otpDb.update(
                { _id: otpRecord._id },
                { $inc: { attempts: 1 } },
                {},
                (err) => {
                    if (err) console.error('Failed to update attempts:', err);
                }
            );

            const remaining = otpRecord.maxAttempts - otpRecord.attempts - 1;
            return res.status(400).json({ 
                error: 'Invalid OTP',
                attemptsRemaining: remaining
            });
        }

        const finishLogin = (albumIds) => {
            ensureUserForEmail(normalizedEmail)
                .then(async (user) => {
                    await syncAlbumsToUser(user);
                    req.session.authenticated = true;
                    req.session.albumId = albumIds[0] || normalizedAlbumId;
                    req.session.albumIds = albumIds;
                    req.session.accessMode = mode;
                    req.session.customerId = user.customerId;
                    req.session.userId = user.userId;
                    req.session.userEmail = normalizedEmail;
                    req.session.authenticatedAt = new Date().toISOString();
                    req.session.readOnly = false;

                    await dbInsert(loginHistoryDb, {
                        _id: uuidv4(),
                        userEmail: normalizedEmail,
                        userId: user.userId,
                        customerId: user.customerId,
                        accessMode: mode,
                        albumIds,
                        ip: getClientIp(req),
                        userAgent: req.get('user-agent') || '',
                        createdAt: new Date()
                    });

                    // Delete used OTP
                    otpDb.remove({ _id: otpRecord._id }, {}, () => {});

                    res.json({
                        success: true,
                        message: 'OTP verified successfully',
                        redirect: '/player'
                    });
                })
                .catch((error) => {
                    console.error('User session setup failed:', error);
                    res.status(500).json({ error: 'Failed to prepare user session' });
                });
        };

        const finishCustomerLogin = () => {
            usersDb.findOne({ email: normalizedEmail, customerId: normalizedCustomerId }, (err, user) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                if (!user) return res.status(403).json({ error: 'Customer ID does not match this email' });

                albumsDb.find({ userEmail: normalizedEmail }, (err, albums) => {
                    if (err) return res.status(500).json({ error: 'Database error' });
                    if (!albums || !albums.length) return res.status(404).json({ error: 'No albums found for this customer' });
                    finishLogin(albums.map(album => album.albumId));
                });
            });
        };

        if (mode === 'customer') {
            finishCustomerLogin();
            return;
        }

        finishLogin([normalizedAlbumId]);
    });
});

app.get('/api/session', requireAlbumAuth, (req, res) => {
    const albumIds = req.session.albumIds || [req.session.albumId];
    videosDb.find({ albumId: { $in: albumIds } }, (err, media) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        res.json({
            email: maskEmail(req.session.userEmail),
            fullEmail: req.session.userEmail,
            accessMode: req.session.accessMode || 'album',
            readOnly: !!req.session.readOnly,
            albumCount: albumIds.length,
            customerId: req.session.customerId || '',
            userId: req.session.userId || '',
            videoCount: (media || []).filter(item => (item.type || 'video') !== 'pdf').length,
            pdfCount: (media || []).filter(item => (item.type || 'video') === 'pdf').length,
            albumIds
        });
    });
});

// ---- User Self Info Flow ----

app.post('/api/info/request', otpRateLimiter, async (req, res) => {
    try {
        const email = normalizeEmail(req.body.email);
        if (!email) return res.status(400).json({ error: 'Email is required' });

        await backfillUsersFromAlbums();
        const info = await buildUserInfoPayload(email);
        if (!info) {
            return res.status(404).json({ error: 'No user found for this email' });
        }

        const token = generateDownloadToken();
        const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
        await dbUpdate(infoTokensDb, { email }, { $set: { used: true, replacedAt: new Date() } }, { multi: true });
        await dbInsert(infoTokensDb, {
            _id: uuidv4(),
            token,
            email,
            expiresAt,
            used: false,
            createdAt: new Date()
        });

        const infoUrl = `${req.protocol}://${req.get('host')}/info?token=${token}`;
        const emailHtml = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color:#222;">Your SOA Secure Online Album Info</h2>
                <p>Click the button below to securely view your User ID, Customer ID, albums and files.</p>
                <div style="text-align:center; margin:28px 0;">
                    <a href="${infoUrl}" style="background:#007AFF;color:#fff;padding:14px 24px;border-radius:8px;text-decoration:none;font-weight:bold;">Open My Info</a>
                </div>
                <p>If the button does not work, copy this link:</p>
                <p style="word-break:break-all;color:#007AFF;">${infoUrl}</p>
                <p>This link expires in 15 minutes and can only be used once.</p>
            </div>
        `;

        await sendEmail(email, 'Your SOA Secure Online Album Info Link', emailHtml);
        res.json({ success: true, message: 'Verification email accepted by mail server. Check Inbox, Spam, Promotions, and All Mail.' });
    } catch (error) {
        console.error('Info request error:', error);
        res.status(500).json({ error: 'Failed to send info link' });
    }
});

app.get('/api/info/verify/:token', async (req, res) => {
    try {
        const tokenRecord = await dbFindOne(infoTokensDb, { token: req.params.token });
        if (!tokenRecord || tokenRecord.used) {
            return res.status(404).json({ error: 'Invalid or used info link' });
        }
        if (new Date() > new Date(tokenRecord.expiresAt)) {
            return res.status(410).json({ error: 'Info link has expired' });
        }

        req.session.infoEmail = tokenRecord.email;
        req.session.infoVerifiedAt = new Date().toISOString();
        await dbUpdate(infoTokensDb, { _id: tokenRecord._id }, { $set: { used: true, usedAt: new Date() } });
        res.json({ success: true });
    } catch (error) {
        console.error('Info verify error:', error);
        res.status(500).json({ error: 'Failed to verify info link' });
    }
});

app.get('/api/info/me', requireInfoAuth, async (req, res) => {
    try {
        await backfillUsersFromAlbums();
        const info = await buildUserInfoPayload(req.session.infoEmail);
        if (!info) return res.status(404).json({ error: 'User info not found' });
        res.json(info);
    } catch (error) {
        console.error('Info me error:', error);
        res.status(500).json({ error: 'Failed to load user info' });
    }
});

// ---- Video Streaming ----

/**
 * Secure video stream endpoint
 * Uses range requests for efficient streaming
 */
app.get('/api/video/stream/:videoId', requireAlbumAuth, (req, res) => {
    const { videoId } = req.params;

    // Verify video belongs to authenticated album
    videosDb.findOne({ _id: videoId, type: { $ne: 'pdf' }, ...albumAccessQuery(req) }, async (err, video) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        const filePath = path.join(directories.uploads, video.filename);

        // Check if file exists
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'Video file not found' });
        }

        const stat = fs.statSync(filePath);
        const fileSize = stat.size;
        const range = req.headers.range;

        // Handle range requests for video streaming
        if (range) {
            const parts = range.replace(/bytes=/, '').split('-');
            const start = parseInt(parts[0], 10);
            const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
            const chunksize = (end - start) + 1;
            const file = fs.createReadStream(filePath, { start, end });

            const headers = {
                'Content-Range': `bytes ${start}-${end}/${fileSize}`,
                'Accept-Ranges': 'bytes',
                'Content-Length': chunksize,
                'Content-Type': 'video/mp4',
                'Cache-Control': 'no-cache'
            };

            res.writeHead(206, headers);
            file.pipe(res);
        } else {
            const headers = {
                'Content-Length': fileSize,
                'Content-Type': 'video/mp4',
                'Cache-Control': 'no-cache'
            };

            res.writeHead(200, headers);
            fs.createReadStream(filePath).pipe(res);
        }
    });
});

/**
 * Get video metadata for player
 */
app.get('/api/video/:videoId', requireAlbumAuth, (req, res) => {
    const { videoId } = req.params;

    videosDb.findOne({ _id: videoId, ...albumAccessQuery(req) }, (err, video) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        res.json({
            id: video._id,
            title: video.title,
            type: video.type || 'video',
            duration: video.duration,
            size: formatFileSize(video.size),
            streamUrl: (video.type || 'video') === 'pdf' ? `/api/media/file/${videoId}` : `/api/video/stream/${videoId}`,
            createdAt: video.createdAt
        });
    });
});

app.get('/api/media/file/:mediaId', requireAlbumAuth, (req, res) => {
    const { mediaId } = req.params;

    videosDb.findOne({ _id: mediaId, ...albumAccessQuery(req) }, (err, media) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!media) return res.status(404).json({ error: 'File not found' });

        const filePath = path.join(directories.uploads, media.filename);
        if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });

        const stat = fs.statSync(filePath);
        const type = media.type || 'video';

        res.setHeader('Content-Length', stat.size);
        res.setHeader('Content-Type', type === 'pdf' ? 'application/pdf' : 'video/mp4');
        res.setHeader('Content-Disposition', `inline; filename="${getDownloadName(media).replace(/"/g, '')}"`);
        res.setHeader('Cache-Control', 'private, max-age=300');
        fs.createReadStream(filePath).pipe(res);
    });
});

/**
 * Get all videos for authenticated album
 */
app.get('/api/videos', requireAlbumAuth, (req, res) => {
    videosDb.find(albumAccessQuery(req)).sort({ createdAt: 1 }).exec((err, videos) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        const videoList = videos.map(video => ({
            id: video._id,
            title: video.title,
            type: video.type || 'video',
            albumId: video.albumId,
            size: formatFileSize(video.size),
            duration: video.duration,
            createdAt: video.createdAt
        }));

        res.json({ videos: videoList, media: videoList });
    });
});

app.get('/api/user/activity', requireAlbumAuth, async (req, res) => {
    try {
        const email = req.session.userEmail;
        const [favorites, recent, loginHistory, supportRequests] = await Promise.all([
            dbFind(favoritesDb, { userEmail: email }),
            dbFind(recentDb, { userEmail: email }),
            dbFind(loginHistoryDb, { userEmail: email }),
            dbFind(supportRequestsDb, { userEmail: email })
        ]);

        const mediaIds = [...new Set([
            ...favorites.map(item => item.mediaId),
            ...recent.map(item => item.mediaId)
        ])];
        const media = mediaIds.length ? await dbFind(videosDb, { _id: { $in: mediaIds } }) : [];
        const mediaMap = new Map(media.map(item => [item._id, item]));

        res.json({
            favorites: favorites
                .map(item => ({ ...item, media: mediaMap.get(item.mediaId) }))
                .filter(item => item.media)
                .map(item => ({
                    mediaId: item.mediaId,
                    title: item.media.title,
                    type: item.media.type || 'video',
                    albumId: item.media.albumId,
                    createdAt: item.createdAt
                })),
            recent: recent
                .map(item => ({ ...item, media: mediaMap.get(item.mediaId) }))
                .filter(item => item.media)
                .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
                .slice(0, 12)
                .map(item => ({
                    mediaId: item.mediaId,
                    title: item.media.title,
                    type: item.media.type || 'video',
                    albumId: item.media.albumId,
                    lastTime: item.lastTime || 0,
                    page: item.page || 1,
                    updatedAt: item.updatedAt
                })),
            loginHistory: loginHistory
                .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
                .slice(0, 10)
                .map(item => ({
                    accessMode: item.accessMode,
                    ip: item.ip,
                    createdAt: item.createdAt
                })),
            supportRequests: supportRequests
                .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
                .slice(0, 10)
                .map(item => ({
                    id: item._id,
                    requestType: item.requestType || 'support',
                    mediaId: item.mediaId,
                    mediaTitle: item.mediaTitle,
                    subject: item.subject,
                    message: item.message,
                    status: item.status || 'open',
                    createdAt: item.createdAt
                }))
        });
    } catch (error) {
        console.error('Activity load error:', error);
        res.status(500).json({ error: 'Failed to load activity' });
    }
});

app.post('/api/user/favorites', requireAlbumAuth, async (req, res) => {
    try {
        if (req.session.readOnly) {
            return res.status(403).json({ error: 'Favorites are disabled for temporary view-only links' });
        }
        const media = await getAccessibleMedia(req, req.body.mediaId);
        if (!media) return res.status(404).json({ error: 'File not found' });

        const existing = await dbFindOne(favoritesDb, { userEmail: req.session.userEmail, mediaId: media._id });
        if (existing) {
            await dbRemove(favoritesDb, { _id: existing._id });
            return res.json({ success: true, favorited: false });
        }

        await dbInsert(favoritesDb, {
            _id: uuidv4(),
            userEmail: req.session.userEmail,
            mediaId: media._id,
            albumId: media.albumId,
            createdAt: new Date()
        });
        res.json({ success: true, favorited: true });
    } catch (error) {
        console.error('Favorite toggle error:', error);
        res.status(500).json({ error: 'Failed to update favorite' });
    }
});

app.post('/api/user/recent', requireAlbumAuth, async (req, res) => {
    try {
        if (req.session.readOnly) {
            return res.json({ success: true, readOnly: true });
        }
        const media = await getAccessibleMedia(req, req.body.mediaId);
        if (!media) return res.status(404).json({ error: 'File not found' });

        const payload = {
            userEmail: req.session.userEmail,
            mediaId: media._id,
            albumId: media.albumId,
            lastTime: Math.max(0, Number(req.body.lastTime || 0)),
            page: Math.max(1, Number(req.body.page || 1)),
            updatedAt: new Date()
        };
        const existing = await dbFindOne(recentDb, { userEmail: req.session.userEmail, mediaId: media._id });
        if (existing) {
            await dbUpdate(recentDb, { _id: existing._id }, { $set: payload });
        } else {
            await dbInsert(recentDb, { _id: uuidv4(), ...payload, createdAt: new Date() });
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Recent save error:', error);
        res.status(500).json({ error: 'Failed to save recent activity' });
    }
});

app.post('/api/user/support', requireAlbumAuth, async (req, res) => {
    try {
        if (req.session.readOnly) {
            return res.status(403).json({ error: 'Support requests are disabled for temporary view-only links' });
        }
        const subject = String(req.body.subject || '').trim().slice(0, 120);
        const message = String(req.body.message || '').trim().slice(0, 1200);
        const media = req.body.mediaId ? await getAccessibleMedia(req, req.body.mediaId) : null;
        if (!subject || !message) return res.status(400).json({ error: 'Subject and message are required' });

        await dbInsert(supportRequestsDb, {
            _id: uuidv4(),
            userEmail: req.session.userEmail,
            userId: req.session.userId,
            customerId: req.session.customerId,
            mediaId: media ? media._id : '',
            mediaTitle: media ? media.title : '',
            subject,
            message,
            status: 'open',
            createdAt: new Date()
        });
        res.json({ success: true, message: 'Support request sent' });
    } catch (error) {
        console.error('Support request error:', error);
        res.status(500).json({ error: 'Failed to send support request' });
    }
});

app.post('/api/share/request', requireAlbumAuth, async (req, res) => {
    try {
        if (req.session.readOnly) {
            return res.status(403).json({ error: 'Temporary viewers cannot create share links' });
        }
        const media = await getAccessibleMedia(req, req.body.mediaId);
        if (!media) return res.status(404).json({ error: 'File not found' });

        const token = generateDownloadToken();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await dbInsert(shareTokensDb, {
            _id: uuidv4(),
            token,
            mediaId: media._id,
            albumId: media.albumId,
            ownerEmail: req.session.userEmail,
            usedCount: 0,
            maxUses: 20,
            expiresAt,
            createdAt: new Date()
        });

        const shareUrl = `${req.protocol}://${req.get('host')}/share/${token}`;
        res.json({ success: true, shareUrl, expiresAt });
    } catch (error) {
        console.error('Share link error:', error);
        res.status(500).json({ error: 'Failed to create share link' });
    }
});

// ---- Download System ----

/**
 * Request download link
 */
app.post('/api/download/request', requireAlbumAuth, async (req, res) => {
    try {
        if (req.session.readOnly) {
            return res.status(403).json({ error: 'Downloads are disabled for temporary view-only links' });
        }

        const { videoId, mediaId } = req.body;
        const selectedMediaId = mediaId || videoId;

        if (!selectedMediaId) {
            return res.status(400).json({ error: 'File ID is required' });
        }

        // Verify file belongs to authenticated album
        const media = await new Promise((resolve, reject) => {
            videosDb.findOne({ _id: selectedMediaId, ...albumAccessQuery(req) }, (err, doc) => {
                if (err) reject(err);
                else resolve(doc);
            });
        });

        if (!media) {
            return res.status(404).json({ error: 'File not found' });
        }

        const existingPending = await dbFindOne(supportRequestsDb, {
            requestType: 'download',
            userEmail: req.session.userEmail,
            mediaId: media._id,
            status: { $in: ['pending', 'reviewing'] }
        });

        if (existingPending) {
            return res.json({
                success: true,
                pending: true,
                requestId: existingPending._id,
                message: 'Download request is already waiting for admin approval'
            });
        }

        const request = await dbInsert(supportRequestsDb, {
            _id: uuidv4(),
            requestType: 'download',
            userEmail: req.session.userEmail,
            userId: req.session.userId,
            customerId: req.session.customerId,
            mediaId: media._id,
            mediaTitle: media.title,
            subject: 'Download approval request',
            message: `User requested admin approval to download ${media.title}.`,
            status: 'pending',
            createdAt: new Date()
        });

        res.json({
            success: true,
            pending: true,
            requestId: request._id,
            message: 'Download request sent for admin approval'
        });

    } catch (error) {
        console.error('Download request error:', error);
        res.status(500).json({ error: 'Failed to process download request' });
    }
});

/**
 * Execute download with token
 */
app.get('/api/download/:token', async (req, res) => {
    try {
        const { token } = req.params;

        // Find and validate token
        const tokenRecord = await new Promise((resolve, reject) => {
            downloadTokensDb.findOne({ token: token }, (err, doc) => {
                if (err) reject(err);
                else resolve(doc);
            });
        });

        if (!tokenRecord) {
            return res.status(404).json({ error: 'Invalid or expired download link' });
        }

        // Check if already used
        if (tokenRecord.used) {
            return res.status(410).json({ error: 'This download link has already been used' });
        }

        // Check if expired
        if (new Date() > new Date(tokenRecord.expiresAt)) {
            return res.status(410).json({ error: 'This download link has expired' });
        }

        // Get video details
        const video = await new Promise((resolve, reject) => {
            videosDb.findOne({ _id: tokenRecord.videoId }, (err, doc) => {
                if (err) reject(err);
                else resolve(doc);
            });
        });

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        const filePath = path.join(directories.uploads, video.filename);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'Video file not found' });
        }

        // Mark token as used
        downloadTokensDb.update(
            { _id: tokenRecord._id },
            { $set: { used: true, usedAt: new Date() } },
            {},
            () => {}
        );

        // Send file for download
        const stat = fs.statSync(filePath);
        res.setHeader('Content-Disposition', `attachment; filename="${getDownloadName(video).replace(/"/g, '')}"`);
        res.setHeader('Content-Type', (video.type || 'video') === 'pdf' ? 'application/pdf' : 'video/mp4');
        res.setHeader('Content-Length', stat.size);
        res.setHeader('X-Download-Token', token);

        const file = fs.createReadStream(filePath);
        file.pipe(res);

    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({ error: 'Download failed' });
    }
});

// ---- Admin Routes ----

/**
 * Admin login
 */
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({ error: 'Password is required' });
    }

    if (password === config.adminPassword) {
        req.session.isAdmin = true;
        res.json({ success: true, redirect: '/admin' });
    } else {
        res.status(401).json({ error: 'Invalid password' });
    }
});

/**
 * Admin logout
 */
app.post('/api/admin/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

/**
 * Check admin auth status
 */
app.get('/api/admin/status', (req, res) => {
    res.json({ isAdmin: req.session.isAdmin || false });
});

app.get('/api/admin/settings', requireAdminAuth, async (req, res) => {
    try {
        const env = readEnvFile();
        const [albums, media, users] = await Promise.all([
            dbFind(albumsDb, {}),
            dbFind(videosDb, {}),
            dbFind(usersDb, {})
        ]);
        const uploadBytes = fs.existsSync(directories.uploads)
            ? fs.readdirSync(directories.uploads)
                .filter(name => !name.startsWith('.'))
                .reduce((total, name) => {
                    const filePath = path.join(directories.uploads, name);
                    return fs.statSync(filePath).isFile() ? total + fs.statSync(filePath).size : total;
                }, 0)
            : 0;

        res.json({
            settings: {
                PORT: env.PORT || String(config.port),
                NODE_ENV: env.NODE_ENV || process.env.NODE_ENV || 'production',
                SESSION_SECRET: env.SESSION_SECRET || config.sessionSecret,
                ADMIN_PASSWORD: env.ADMIN_PASSWORD || config.adminPassword,
                SMTP_HOST: env.SMTP_HOST || config.smtp.host,
                SMTP_PORT: env.SMTP_PORT || String(config.smtp.port),
                SMTP_SECURE: String(env.SMTP_SECURE ?? config.smtp.secure),
                SMTP_USER: env.SMTP_USER || config.smtp.user,
                SMTP_PASS_MASKED: maskSecret(env.SMTP_PASS || config.smtp.pass),
                EMAIL_FROM: env.EMAIL_FROM || config.smtp.from,
                MAX_FILE_SIZE_MB: env.MAX_FILE_SIZE_MB || String(Math.round(config.maxFileSize / (1024 * 1024))),
                OTP_EXPIRY_MINUTES: env.OTP_EXPIRY_MINUTES || String(config.otpExpiry),
                OTP_LENGTH: env.OTP_LENGTH || String(config.otpLength),
                DOWNLOAD_TOKEN_EXPIRY_MINUTES: env.DOWNLOAD_TOKEN_EXPIRY_MINUTES || String(config.downloadTokenExpiry)
            },
            system: {
                albums: albums.length,
                files: media.length,
                videos: media.filter(item => (item.type || 'video') !== 'pdf').length,
                pdfs: media.filter(item => (item.type || 'video') === 'pdf').length,
                users: users.length,
                uploadStorage: formatFileSize(uploadBytes),
                nodeEnv: process.env.NODE_ENV || 'development',
                uptimeSeconds: Math.round(process.uptime())
            }
        });
    } catch (error) {
        console.error('Admin settings load error:', error);
        res.status(500).json({ error: 'Failed to load settings' });
    }
});

app.put('/api/admin/settings', requireAdminAuth, (req, res) => {
    try {
        const current = readEnvFile();
        const body = req.body || {};
        const next = {};
        editableEnvKeys.forEach(key => {
            if (body[key] === undefined) return;
            if (key === 'SMTP_PASS' && String(body[key]).trim() === '') {
                next[key] = current.SMTP_PASS || config.smtp.pass || '';
                return;
            }
            next[key] = String(body[key]).trim();
        });

        ['SMTP_PORT', 'MAX_FILE_SIZE_MB', 'OTP_EXPIRY_MINUTES', 'OTP_LENGTH', 'DOWNLOAD_TOKEN_EXPIRY_MINUTES'].forEach(key => {
            if (next[key] && (!Number.isFinite(Number(next[key])) || Number(next[key]) <= 0)) {
                throw new Error(`${key} must be a positive number`);
            }
        });

        if (next.OTP_LENGTH && (Number(next.OTP_LENGTH) < 4 || Number(next.OTP_LENGTH) > 8)) {
            throw new Error('OTP_LENGTH must be between 4 and 8');
        }

        if (next.EMAIL_FROM !== undefined || next.SMTP_USER !== undefined) {
            next.EMAIL_FROM = normalizeEmailFrom(next.EMAIL_FROM || current.EMAIL_FROM || config.smtp.from, next.SMTP_USER || current.SMTP_USER || config.smtp.user);
        }

        const written = writeEnvFile(next);
        refreshRuntimeConfig(written);

        res.json({
            success: true,
            message: 'Settings saved',
            restartRequired: ['PORT', 'SESSION_SECRET', 'NODE_ENV', 'MAX_FILE_SIZE_MB'].some(key => next[key] !== undefined),
            appliedNow: ['ADMIN_PASSWORD', 'SMTP_*', 'EMAIL_FROM', 'OTP_*', 'DOWNLOAD_TOKEN_EXPIRY_MINUTES']
        });
    } catch (error) {
        console.error('Admin settings save error:', error);
        res.status(400).json({ error: error.message || 'Failed to save settings' });
    }
});

app.post('/api/admin/settings/test-email', requireAdminAuth, async (req, res) => {
    try {
        const to = normalizeEmail(req.body.email || config.smtp.user);
        if (!to) return res.status(400).json({ error: 'Test email address is required' });

        await sendEmail(
            to,
            'SOA Secure Online Album SMTP Test',
            '<div style="font-family:Arial,sans-serif"><h2>SMTP test successful</h2><p>Your admin email settings are working.</p></div>'
        );
        res.json({ success: true, message: `Test email sent to ${to}` });
    } catch (error) {
        res.status(500).json({ error: error.message || 'Test email failed' });
    }
});

/**
 * Upload media (Admin only)
 */
app.post('/api/admin/upload', requireAdminAuth, upload.single('media'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const { albumId, userEmail, userId, customerId, title } = req.body;
        const mediaType = getMediaType(req.file);
        const normalizedEmail = normalizeEmail(userEmail);
        const normalizedAlbumId = cleanId(albumId);

        if (!normalizedAlbumId || !normalizedEmail) {
            // Clean up uploaded file
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Album ID and User Email are required' });
        }

        const user = await ensureUserForEmail(normalizedEmail, userId, customerId);

        // Check if album exists
        const existingAlbum = await new Promise((resolve, reject) => {
            albumsDb.findOne({ albumId: normalizedAlbumId }, (err, doc) => {
                if (err) reject(err);
                else resolve(doc);
            });
        });

        let album = existingAlbum;

        if (album && album.userEmail.toLowerCase() !== normalizedEmail) {
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ error: 'Album ID already belongs to another email' });
        }

        if (!album) {
            // Create album record
            album = {
                _id: uuidv4(),
                albumId: normalizedAlbumId,
                userEmail: normalizedEmail,
                userId: user.userId,
                customerId: user.customerId,
                createdAt: new Date()
            };

            await new Promise((resolve, reject) => {
                albumsDb.insert(album, (err, doc) => {
                    if (err) reject(err);
                    else resolve(doc);
                });
            });
        } else if (album.customerId !== user.customerId || album.userId !== user.userId) {
            album.customerId = user.customerId;
            album.userId = user.userId;
            await new Promise((resolve, reject) => {
                albumsDb.update(
                    { _id: album._id },
                    { $set: { customerId: album.customerId, userId: album.userId } },
                    {},
                    (err) => err ? reject(err) : resolve()
                );
            });
        }

        // Create media record
        const video = {
            _id: uuidv4(),
            albumId: normalizedAlbumId,
            filename: req.file.filename,
            originalName: req.file.originalname,
            title: title || req.file.originalname,
            type: mediaType,
            size: req.file.size,
            mimetype: req.file.mimetype,
            duration: mediaType === 'video' ? 0 : null,
            createdAt: new Date()
        };

        await new Promise((resolve, reject) => {
            videosDb.insert(video, (err, doc) => {
                if (err) reject(err);
                else resolve(doc);
            });
        });

        res.json({
            success: true,
            message: `${mediaType === 'pdf' ? 'PDF' : 'Video'} uploaded successfully`,
            album: {
                albumId: album.albumId,
                userEmail: album.userEmail
            },
            user: {
                userId: user.userId,
                customerId: user.customerId
            },
            video: {
                id: video._id,
                title: video.title,
                type: video.type,
                size: formatFileSize(video.size)
            }
        });

    } catch (error) {
        console.error('Upload error:', error);
        // Clean up file on error
        if (req.file && req.file.path && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ error: 'Upload failed' });
    }
});

/**
 * Get all albums (Admin only)
 */
app.get('/api/admin/albums', requireAdminAuth, (req, res) => {
    albumsDb.find({}, (err, albums) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        const albumList = albums.map(album => ({
            id: album._id,
            albumId: album.albumId,
            userEmail: maskEmail(album.userEmail),
            fullEmail: album.userEmail,
            userId: album.userId,
            customerId: album.customerId,
            createdAt: album.createdAt
        }));

        res.json({ albums: albumList });
    });
});

app.put('/api/admin/albums/:id', requireAdminAuth, async (req, res) => {
    try {
        const album = await dbFindOne(albumsDb, { _id: req.params.id });
        if (!album) return res.status(404).json({ error: 'Album not found' });

        const nextAlbumId = cleanId(req.body.albumId || album.albumId);
        const nextEmail = normalizeEmail(req.body.userEmail || album.userEmail);
        const nextUserId = cleanId(req.body.userId || album.userId);
        const nextCustomerId = cleanId(req.body.customerId || album.customerId);

        if (!nextAlbumId || !nextEmail) {
            return res.status(400).json({ error: 'Album ID and email are required' });
        }

        const albumOwner = await dbFindOne(albumsDb, { albumId: nextAlbumId });
        if (albumOwner && albumOwner._id !== album._id) {
            return res.status(400).json({ error: 'Album ID already exists' });
        }

        const user = await ensureUserForEmail(nextEmail, nextUserId, nextCustomerId);
        await dbUpdate(albumsDb, { _id: album._id }, {
            $set: {
                albumId: nextAlbumId,
                userEmail: user.email,
                userId: user.userId,
                customerId: user.customerId,
                updatedAt: new Date()
            }
        });

        if (album.albumId !== nextAlbumId) {
            await dbUpdate(videosDb, { albumId: album.albumId }, { $set: { albumId: nextAlbumId } }, { multi: true });
        }

        res.json({ success: true, message: 'Album updated' });
    } catch (error) {
        console.error('Admin album update error:', error);
        res.status(500).json({ error: 'Failed to update album' });
    }
});

/**
 * Get all videos (Admin only)
 */
app.get('/api/admin/videos', requireAdminAuth, (req, res) => {
    videosDb.find({}).sort({ createdAt: -1 }).exec((err, videos) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        const videoList = videos.map(video => ({
            id: video._id,
            albumId: video.albumId,
            title: video.title,
            type: video.type || 'video',
            size: formatFileSize(video.size),
            filename: video.filename,
            createdAt: video.createdAt
        }));

        res.json({ videos: videoList });
    });
});

app.put('/api/admin/videos/:id', requireAdminAuth, async (req, res) => {
    try {
        const media = await dbFindOne(videosDb, { _id: req.params.id });
        if (!media) return res.status(404).json({ error: 'File not found' });

        const title = cleanId(req.body.title || media.title);
        const albumId = cleanId(req.body.albumId || media.albumId);
        if (!title || !albumId) return res.status(400).json({ error: 'Title and album ID are required' });

        const album = await dbFindOne(albumsDb, { albumId });
        if (!album) return res.status(404).json({ error: 'Target album not found' });

        await dbUpdate(videosDb, { _id: media._id }, {
            $set: {
                title,
                albumId,
                updatedAt: new Date()
            }
        });

        res.json({ success: true, message: 'File updated' });
    } catch (error) {
        console.error('Admin file update error:', error);
        res.status(500).json({ error: 'Failed to update file' });
    }
});

app.get('/api/admin/users', requireAdminAuth, async (req, res) => {
    try {
        await backfillUsersFromAlbums();
        const users = await dbFind(usersDb, {});
        const albums = await dbFind(albumsDb, {});
        const media = await dbFind(videosDb, {});

        const userList = users
            .sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt))
            .map(user => {
                const userAlbums = albums.filter(album => album.userEmail === user.email);
                const albumIds = userAlbums.map(album => album.albumId);
                const userMedia = media.filter(item => albumIds.includes(item.albumId));
                return {
                    id: user._id,
                    email: user.email,
                    maskedEmail: maskEmail(user.email),
                    userId: user.userId,
                    customerId: user.customerId,
                    notes: user.notes || '',
                    albumCount: userAlbums.length,
                    fileCount: userMedia.length,
                    pdfCount: userMedia.filter(item => (item.type || 'video') === 'pdf').length,
                    videoCount: userMedia.filter(item => (item.type || 'video') !== 'pdf').length,
                    createdAt: user.createdAt,
                    updatedAt: user.updatedAt
                };
            });

        res.json({ users: userList });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: 'Failed to load users' });
    }
});

app.get('/api/admin/support', requireAdminAuth, async (req, res) => {
    try {
        const requests = await dbFind(supportRequestsDb, {});
        res.json({
            requests: requests
                .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
                .map(item => ({
                    id: item._id,
                    userEmail: item.userEmail,
                    userId: item.userId,
                    customerId: item.customerId,
                    mediaId: item.mediaId,
                    mediaTitle: item.mediaTitle,
                    subject: item.subject,
                    message: item.message,
                    requestType: item.requestType || 'support',
                    downloadSentAt: item.downloadSentAt,
                    reviewedAt: item.reviewedAt,
                    status: item.status || 'open',
                    createdAt: item.createdAt,
                    updatedAt: item.updatedAt
                }))
        });
    } catch (error) {
        console.error('Admin support error:', error);
        res.status(500).json({ error: 'Failed to load support requests' });
    }
});

app.put('/api/admin/support/:id', requireAdminAuth, async (req, res) => {
    try {
        const status = String(req.body.status || 'open').trim().toLowerCase();
        if (!['open', 'reviewing', 'done', 'pending', 'approved', 'rejected'].includes(status)) {
            return res.status(400).json({ error: 'Invalid support status' });
        }

        const request = await dbFindOne(supportRequestsDb, { _id: req.params.id });
        if (!request) return res.status(404).json({ error: 'Support request not found' });

        const update = { status, updatedAt: new Date() };

        if ((request.requestType || 'support') === 'download' && status === 'approved') {
            if (!request.downloadSentAt) {
                const media = await dbFindOne(videosDb, { _id: request.mediaId });
                if (!media) return res.status(404).json({ error: 'Requested file not found' });
                const tokenInfo = await createDownloadTokenAndEmail(req, media, request.userEmail, 'admin');
                update.downloadSentAt = new Date();
                update.downloadTokenExpiresAt = tokenInfo.expiresAt;
            }
            update.reviewedAt = new Date();
        }

        if ((request.requestType || 'support') === 'download' && status === 'rejected' && request.status !== 'rejected') {
            update.reviewedAt = new Date();
            if (config.smtp.user && config.smtp.pass) {
                await sendEmail(
                    request.userEmail,
                    `Download request update: ${request.mediaTitle || 'Album file'}`,
                    `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
                        <h2>Download Request Update</h2>
                        <p>Your download request for <strong>${request.mediaTitle || 'the selected file'}</strong> was not approved at this time.</p>
                        <p>Please contact support if you need help.</p>
                    </div>`
                );
            }
        }

        const count = await dbUpdate(supportRequestsDb, { _id: req.params.id }, { $set: update });
        if (!count) return res.status(404).json({ error: 'Support request not found' });
        res.json({ success: true, message: status === 'approved' ? 'Download approved and email sent' : 'Support request updated' });
    } catch (error) {
        console.error('Admin support update error:', error);
        res.status(500).json({ error: 'Failed to update support request' });
    }
});

app.get('/api/admin/userinfo/:email', requireAdminAuth, async (req, res) => {
    try {
        await backfillUsersFromAlbums();
        const email = normalizeEmail(req.params.email);
        const user = await dbFindOne(usersDb, { email });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const albums = await dbFind(albumsDb, { userEmail: email });
        const albumIds = albums.map(album => album.albumId);
        const media = await dbFind(videosDb, { albumId: { $in: albumIds } });

        res.json({
            user: {
                id: user._id,
                email: user.email,
                userId: user.userId,
                customerId: user.customerId,
                notes: user.notes || '',
                createdAt: user.createdAt,
                updatedAt: user.updatedAt
            },
            albums: albums.map(album => ({
                id: album._id,
                albumId: album.albumId,
                userId: album.userId,
                customerId: album.customerId,
                createdAt: album.createdAt,
                fileCount: media.filter(item => item.albumId === album.albumId).length,
                pdfCount: media.filter(item => item.albumId === album.albumId && (item.type || 'video') === 'pdf').length,
                videoCount: media.filter(item => item.albumId === album.albumId && (item.type || 'video') !== 'pdf').length
            })),
            media: media.map(item => ({
                id: item._id,
                albumId: item.albumId,
                title: item.title,
                type: item.type || 'video',
                size: formatFileSize(item.size),
                createdAt: item.createdAt
            }))
        });
    } catch (error) {
        console.error('Admin userinfo error:', error);
        res.status(500).json({ error: 'Failed to load user info' });
    }
});

app.put('/api/admin/users/:id', requireAdminAuth, async (req, res) => {
    try {
        const current = await dbFindOne(usersDb, { _id: req.params.id });
        if (!current) return res.status(404).json({ error: 'User not found' });

        const nextEmail = normalizeEmail(req.body.email || current.email);
        const nextUserId = cleanId(req.body.userId || current.userId);
        const nextCustomerId = cleanId(req.body.customerId || current.customerId);
        const notes = (req.body.notes || '').trim();

        if (!nextEmail || !nextUserId || !nextCustomerId) {
            return res.status(400).json({ error: 'Email, User ID and Customer ID are required' });
        }

        const emailOwner = await dbFindOne(usersDb, { email: nextEmail });
        if (emailOwner && emailOwner._id !== current._id) {
            return res.status(400).json({ error: 'Email is already assigned to another user' });
        }

        const userIdOwner = await dbFindOne(usersDb, { userId: nextUserId });
        if (userIdOwner && userIdOwner._id !== current._id) {
            return res.status(400).json({ error: 'User ID is already assigned to another user' });
        }

        await dbUpdate(usersDb, { _id: current._id }, {
            $set: {
                email: nextEmail,
                userId: nextUserId,
                customerId: nextCustomerId,
                notes,
                updatedAt: new Date()
            }
        });

        await dbUpdate(albumsDb, { userEmail: current.email }, {
            $set: {
                userEmail: nextEmail,
                userId: nextUserId,
                customerId: nextCustomerId
            }
        }, { multi: true });

        res.json({
            success: true,
            user: {
                id: current._id,
                email: nextEmail,
                userId: nextUserId,
                customerId: nextCustomerId,
                notes
            }
        });
    } catch (error) {
        console.error('Admin user update error:', error);
        if (error.errorType === 'uniqueViolated') {
            return res.status(400).json({ error: 'User ID or email already exists' });
        }
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.get('/api/admin/export/:type', requireAdminAuth, async (req, res) => {
    try {
        const { type } = req.params;
        if (type === 'albums') {
            const albums = await dbFind(albumsDb, {});
            return sendCsv(res, 'soa-albums.csv', [
                ['Album ID', 'Email', 'User ID', 'Customer ID', 'Created At'],
                ...albums.map(album => [album.albumId, album.userEmail, album.userId, album.customerId, album.createdAt])
            ]);
        }
        if (type === 'files') {
            const files = await dbFind(videosDb, {});
            return sendCsv(res, 'soa-files.csv', [
                ['Title', 'Type', 'Album ID', 'Size Bytes', 'Filename', 'Created At'],
                ...files.map(file => [file.title, file.type || 'video', file.albumId, file.size, file.filename, file.createdAt])
            ]);
        }
        if (type === 'users') {
            await backfillUsersFromAlbums();
            const users = await dbFind(usersDb, {});
            return sendCsv(res, 'soa-users.csv', [
                ['Email', 'User ID', 'Customer ID', 'Notes', 'Created At', 'Updated At'],
                ...users.map(user => [user.email, user.userId, user.customerId, user.notes || '', user.createdAt, user.updatedAt])
            ]);
        }
        if (type === 'support') {
            const requests = await dbFind(supportRequestsDb, {});
            return sendCsv(res, 'soa-support.csv', [
                ['Type', 'Email', 'User ID', 'Customer ID', 'File', 'Subject', 'Message', 'Status', 'Created At', 'Updated At'],
                ...requests.map(item => [item.requestType || 'support', item.userEmail, item.userId, item.customerId, item.mediaTitle, item.subject, item.message, item.status || 'open', item.createdAt, item.updatedAt])
            ]);
        }
        res.status(404).json({ error: 'Unknown export type' });
    } catch (error) {
        console.error('Admin export error:', error);
        res.status(500).json({ error: 'Export failed' });
    }
});

/**
 * Delete album (Admin only)
 */
app.delete('/api/admin/albums/:id', requireAdminAuth, (req, res) => {
    const { id } = req.params;

    // Find album and associated files
    albumsDb.findOne({ _id: id }, (err, album) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!album) {
            return res.status(404).json({ error: 'Album not found' });
        }

        // Find all files for this album
        videosDb.find({ albumId: album.albumId }, (err, videos) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            // Delete media files
            videos.forEach(video => {
                const filePath = path.join(directories.uploads, video.filename);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
            });

            // Delete files from database
            videosDb.remove({ albumId: album.albumId }, { multi: true }, () => {});

            // Delete album
            albumsDb.remove({ _id: id }, {}, (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to delete album' });
                }
                res.json({ success: true, message: 'Album and associated files deleted' });
            });
        });
    });
});

/**
 * Delete file (Admin only)
 */
app.delete('/api/admin/videos/:id', requireAdminAuth, (req, res) => {
    const { id } = req.params;

    videosDb.findOne({ _id: id }, (err, video) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!video) {
            return res.status(404).json({ error: 'Video not found' });
        }

        // Delete file
        const filePath = path.join(directories.uploads, video.filename);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        // Delete from database
        videosDb.remove({ _id: id }, {}, (err) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to delete video' });
            }
            res.json({ success: true, message: 'File deleted' });
        });
    });
});

// ============================================
// Frontend Routes
// ============================================

app.get('/', (req, res) => {
    res.sendFile(path.join(directories.views, 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(directories.views, 'admin.html'));
});

app.get('/userinfo', (req, res) => {
    res.sendFile(path.join(directories.views, 'admin.html'));
});

app.get('/info', (req, res) => {
    res.sendFile(path.join(directories.views, 'info.html'));
});

app.get('/share/:token', async (req, res) => {
    try {
        const record = await dbFindOne(shareTokensDb, { token: req.params.token });
        if (!record) return res.status(404).send('Invalid share link');
        if (new Date() > new Date(record.expiresAt)) return res.status(410).send('This share link has expired');
        if ((record.usedCount || 0) >= (record.maxUses || 20)) return res.status(410).send('This share link has reached its view limit');

        const media = await dbFindOne(videosDb, { _id: record.mediaId });
        if (!media) return res.status(404).send('Shared file not found');
        const owner = await ensureUserForEmail(record.ownerEmail);

        req.session.authenticated = true;
        req.session.albumId = media.albumId;
        req.session.albumIds = [media.albumId];
        req.session.accessMode = 'share';
        req.session.customerId = owner.customerId;
        req.session.userId = owner.userId;
        req.session.userEmail = owner.email;
        req.session.authenticatedAt = new Date().toISOString();
        req.session.readOnly = true;
        req.session.sharedMediaId = media._id;

        await dbUpdate(shareTokensDb, { _id: record._id }, {
            $inc: { usedCount: 1 },
            $set: { lastUsedAt: new Date(), lastIp: getClientIp(req) }
        });

        res.redirect('/player');
    } catch (error) {
        console.error('Share open error:', error);
        res.status(500).send('Failed to open share link');
    }
});

app.get('/player', requireAlbumAuth, (req, res) => {
    res.sendFile(path.join(directories.views, 'player.html'));
});

// ============================================
// Error Handling
// ============================================

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// Server Start
// ============================================

backfillUsersFromAlbums();

app.listen(config.port, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${config.port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received. Shutting down gracefully...');
    process.exit(0);
});

module.exports = app;
