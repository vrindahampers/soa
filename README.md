A production-ready, self-hosted video streaming platform with OTP-based authentication and secure video delivery. Built with Node.js, Express, and Bootstrap.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Node](https://img.shields.io/badge/node-%3E%3D14-brightgreen.svg)

## ✨ Features

### 🔐 Security First
- **OTP Authentication**: 6-digit codes sent via email with 5-minute expiry
- **Secure Video Streaming**: Videos served through authenticated routes only
- **Single-Use Download Tokens**: Time-limited, one-time download links
- **Email Masking**: User emails are masked throughout the system
- **Rate Limiting**: Protection against brute force attacks
- **Session-Based Auth**: Secure cookie-based sessions

### 🎥 Album File Management
- **Protected Uploads**: Videos and PDF albums stored in non-public directory
- **Range Request Support**: Efficient streaming with pause/resume
- **Multiple Videos per Album**: Organize content by album
- **PDF Album Viewer**: Upload PDF albums and let customers view them online
- **Single-Page PDF Controls**: Customers can move page-by-page, zoom, and rotate PDF albums
- **Download System**: Secure, token-based download links

### 👤 User Experience
- **No Account Required**: Access via Album ID + Email OTP
- **Self-Service Info Check**: Users can request a secure email link to view their own User ID, Customer ID, albums and files
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Custom Video Player**: Play, pause, volume, fullscreen, PiP
- **Video Rotation**: Rotate uploaded videos in the player without re-uploading
- **Keyboard Shortcuts**: Space, arrows, F, M for controls

### 🛠️ Admin Panel
- **Password Protection**: Secure admin access
- **Video Upload**: Drag & drop with progress indicator
- **Album Management**: Create, view, delete albums
- **Video Management**: View and delete uploaded videos
- **User Info Page**: View fixed User ID, Customer ID, associated albums, videos and PDFs
- **Settings Panel**: Edit `.env`, SMTP, OTP, upload, security and server settings from admin
- **Full Edit Controls**: Admin can edit users, album ownership/IDs, and file title/album assignment

## 📋 Prerequisites

- **Node.js** 14.x or higher
- **npm** 6.x or higher
- **Linux VPS** (Ubuntu 20.04+ recommended)
- **SMTP Account** (Gmail, SendGrid, etc.)

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Clone or download the project
cd video-locker

# Install Node.js packages
npm install --production
```

### 2. Configure Environment

```bash
# Copy example config
cp .env.example .env

# Edit configuration
nano .env
```

**Essential settings:**
```env
PORT=3000
SESSION_SECRET=your-random-secret-key
ADMIN_PASSWORD=your-secure-password
SMTP_HOST=smtp.gmail.com
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
```

### 3. Create Directories

```bash
mkdir -p uploads data views
chmod 755 uploads data
```

### 4. Start Server

```bash
# Development
npm start

# Development in GitHub Codespaces / forwarded tunnel
npm run dev:tunnel

# Make the Codespaces forwarded port public for sharing, if needed
CODESPACE_PORT_VISIBILITY=public npm run dev:tunnel

# Production (with PM2)
pm2 start server.js --name video-album
pm2 save
pm2 startup
```

### VS Code Dev Tunnels / Port Forwarding

To share the local app with a friend using a VS Code URL like `https://fh0zbknx-3000.inc1.devtunnels.ms`:

1. Start the app with `npm run dev:tunnel` or run the VS Code task **Start Video Locker with VS Code Port Forwarding**.
2. Open VS Code's **Ports** panel.
3. Forward port `3000` if it is not already forwarded.
4. Right-click port `3000` and choose **Port Visibility** → **Public**.
5. Copy the **Forwarded Address** and send that `devtunnels.ms` URL.

VS Code keeps forwarded ports private by default. Private links require your same signed-in account, so use Public when sharing with someone else.

## 📖 Usage Guide

### Admin Panel (`/admin`)

1. Navigate to `http://your-domain.com/admin`
2. Enter admin password
3. **Upload Album File**:
   - Drag & drop MP4 video or PDF album
   - Enter unique Album ID (e.g., `123456`)
   - Enter user email (for OTP verification)
   - Optional: User ID, Customer ID
4. **Manage Content**:
   - View all albums and videos
   - Delete albums (removes associated files)
   - Delete individual videos
5. **Check User Info**:
   - Open `/userinfo` or the **User Info** tab
   - Search by email, User ID or Customer ID
   - Edit fixed User ID / Customer ID and inspect associated albums/files
6. **Manage Settings**:
   - Open the **Settings** tab
   - Edit admin password, SMTP, OTP expiry, upload limit, port and environment values
   - Send a test email after SMTP changes
   - Restart the server when the panel says restart is required
7. **Edit Records**:
   - Use **Edit** in Albums to change Album ID, email, User ID and Customer ID
   - Use **Edit** in Files to rename files or move them to another album
   - Use **User Info** to update fixed user identity records

### User Access Flow

1. **Choose Login Mode** → User can enter SOA Album ID, or Customer Access with email + Customer ID to load every matching album
2. **Verify Email** → Sees masked email, enters full address
3. **Receive OTP** → 6-digit code sent to email (5-min expiry)
4. **Enter OTP** → Validates and creates session
5. **View Album** → Stream videos and open PDF albums online

### User Info Check (`/info`)

1. User opens `/info` or clicks **Check My Info** on the home page
2. User enters email
3. System sends a secure one-use verification link
4. Link opens the site and shows only that email's User ID, Customer ID, associated albums and files
6. **Download** → Request secure download link via email

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `NODE_ENV` | Environment | `production` |
| `SESSION_SECRET` | Session encryption key | *(required)* |
| `ADMIN_PASSWORD` | Admin panel password | `admin123` |
| `SMTP_HOST` | SMTP server | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_SECURE` | Use SSL | `false` |
| `SMTP_USER` | SMTP username | *(required)* |
| `SMTP_PASS` | SMTP password | *(required)* |
| `EMAIL_FROM` | Sender address | `"SOA Secure Online Album" <noreply@...>` |
| `MAX_FILE_SIZE_MB` | Max upload size | `500` |
| `OTP_EXPIRY_MINUTES` | OTP validity | `5` |
| `DOWNLOAD_TOKEN_EXPIRY_MINUTES` | Download link validity | `5` |

### SMTP Setup (Gmail Example)

1. Enable 2-Factor Authentication on Google Account
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Use App Password in `SMTP_PASS` field

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=xxxx-xxxx-xxxx-xxxx  # 16-character app password
EMAIL_FROM="SOA Secure Online Album" <your-email@gmail.com>
```

## 🏗️ Architecture

```
video-locker/
├── server.js           # Main application (Express + routes)
├── package.json        # Dependencies
├── .env.example        # Configuration template
├── .gitignore          # Git ignore rules
├── run.txt             # Detailed setup guide
├── README.md           # This file
├── views/              # Frontend HTML
│   ├── index.html      # User access portal (OTP flow)
│   ├── admin.html      # Admin panel
│   └── player.html     # Video player
├── uploads/            # Protected video storage
└── data/               # NeDB database files
    ├── albums.db
    ├── videos.db
    ├── otp.db
    └── download_tokens.db
```

## 🔒 Security Features

### Video Protection
- ✅ Videos stored outside web root
- ✅ Streamed via authenticated API endpoints
- ✅ Range request support for efficient streaming
- ✅ No direct file access via URL

### Authentication
- ✅ OTP hashed with bcrypt before storage
- ✅ Session-based authentication with secure cookies
- ✅ Rate limiting on OTP requests (5 per 15 minutes)
- ✅ Maximum 5 OTP verification attempts

### Download Security
- ✅ Cryptographically random tokens (256-bit)
- ✅ Single-use enforcement
- ✅ 5-minute expiry
- ✅ Email delivery only

### Input Validation
- ✅ File type validation (MP4 only)
- ✅ File size limits
- ✅ Email format validation
- ✅ Album ID uniqueness enforcement

## 🛡️ Production Deployment

### With Nginx (Recommended)

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### SSL with Let's Encrypt

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### Process Management (PM2)

```bash
# Install PM2
sudo npm install -g pm2

# Start application
pm2 start server.js --name video-album

# Save process list
pm2 save

# Setup startup script
pm2 startup
```

### Firewall (UFW)

```bash
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

## 📊 Monitoring

```bash
# View logs
pm2 logs video-album

# Monitor resources
pm2 monit

# Check status
pm2 list

# Restart if needed
pm2 restart video-album
```

## 🔧 Troubleshooting

### Common Issues

**Port already in use:**
```bash
lsof -i :3000
kill -9 <PID>
```

**Permission denied on uploads:**
```bash
sudo chown -R $USER:$USER uploads/
chmod -R 755 uploads/
```

**Emails not sending:**
- Verify SMTP credentials in `.env`
- Use app-specific password for Gmail
- Check SMTP provider's security settings

**Videos won't play:**
- Ensure videos are MP4 format
- Check file permissions: `ls -la uploads/`
- Verify browser supports HTML5 video

### Database Backup

```bash
# Backup all data
tar -czf backup-$(date +%Y%m%d).tar.gz data/

# Restore
tar -xzf backup-YYYYMMDD.tar.gz
```

## 📱 Keyboard Shortcuts (Video Player)

| Key | Action |
|-----|--------|
| `Space` | Play/Pause |
| `←` | Rewind 5 seconds |
| `→` | Forward 5 seconds |
| `↑` | Increase volume |
| `↓` | Decrease volume |
| `F` | Toggle fullscreen |
| `M` | Toggle mute |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Credits

- **Express.js** - Web framework
- **NeDB** - Embedded database
- **Bootstrap 5** - UI framework
- **Bootstrap Icons** - Icon library
- **Nodemailer** - Email sending
- **Multer** - File upload handling

## 📞 Support

For issues and questions:
1. Check `run.txt` for detailed setup instructions
2. Review `.env.example` for configuration options
3. Check application logs: `pm2 logs video-album`
4. Verify all prerequisites are installed

---

**Built with ❤️ for secure video sharing**
