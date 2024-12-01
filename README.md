# dbstat (macOS 13.0+)

A simple locally hosted dashboard to view real-time information about your Mac.

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
# OpenAI API Key for security commands feature
OPENAI_API_KEY=insert-api-key

# Server configuration
PORT=8080
HOST=127.0.0.1
CORS_ORIGIN=http://localhost:8080

# Security
JWT_SECRET=insert-jwt-here
```

`.env` information:

`OPENAI_API_KEY` is used to connect to OpenAI's API for generating security command suggestions. This key is optional - if not provided, the security commands feature will be disabled.

`PORT` defines which port the server will listen on. The default is 8080 but this can be changed if needed.

`HOST` specifies the network interface the server will bind to. Using 127.0.0.1 (localhost) means the server will only accept connections from the local machine.

`CORS_ORIGIN` sets the allowed origin for Cross-Origin Resource Sharing. Since the frontend runs on localhost:8080 by default, this matches that address to allow secure client-server communication.

`JWT_SECRET` is used to sign and verify JSON Web Tokens for authentication. This should be a long, random string to ensure security. You can generate one using the command provided in the README.


Generate secure `JWT_secret` in terminal with this command (use output as the JWT_SECRET value in your .env file):

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