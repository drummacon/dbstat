# dbstat (macOS 13.0+)

A simple locally hosted dashboard to view real-time information about your Mac.

## Screenshots

### Light Theme
![Light Theme Screenshot](./assets/images/app-screenshot-light.png)

### Dark Theme
![Dark Theme Screenshot](./assets/images/app-screenshot-dark.png)

## Requirements

- Node.js 16+
- macOS 11.0+ (Big Sur or later)
- OpenAI API key (for security commands feature)

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/dbstat
cd dbstat

# Install dependencies
npm install

# Create and configure .env file
cp .env.example .env
```

## Configuration

Create a `.env` that looks like this:

```bash
# Server configuration
PORT=3000
HOST=127.0.0.1
CORS_ORIGIN=http://127.0.0.1:3000

# Security
JWT_SECRET=insert-jwt-token

# Security commands pane (optional)
OPENAI_API_KEY=insert-api-key
```

Generate secure `JWT_secret` in terminal with this command (use output as the `JWT_SECRET` value in your .env file):

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Usage

```bash
# Launch dashboard
npm start
```

Access in browser: `http://localhost:8080`

## Features

- Real-time system metrics monitoring
- Process management- Network connections tracking
- Storage analytics
- Security status monitoring
- Active sessions tracking
- Dark/light theme support
- GitHub integration

## WebSocket Events

| Event | Description |
|-------|-------------|
| `system-update` | System metrics update |
| `process-update` | Process list update |
| `network-update` | Network stats update |
| `storage-update` | Storage info update |

## API Routes

```
GET  /api/get-token         # Get WebSocket auth token
POST /api/security-commands # Get security commands
```

## Dependencies

- express
- socket.io
- systeminformation
- jsonwebtoken
- helmet
- dotenv

## License

MIT