import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import { exec as execCallback } from "child_process";
import { promisify } from "util";
import si from "systeminformation";
import dotenv from "dotenv";
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import { createHash } from 'crypto';
import helmet from "helmet";
import jwt from "jsonwebtoken";

// optional
import getSecurityCommands from "./assets/openai.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const exec = promisify(execCallback);
dotenv.config();

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';
const JWT_SECRET = process.env.JWT_SECRET;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

const app = express();
const httpServer = createServer(app);
const activeConnections = new Map();

app.use(helmet());

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Too many requests from this IP, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', apiLimiter);

app.use((req, res, next) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Content-Security-Policy': "default-src 'self' https://api.github.com; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' https://cdn.socket.io; connect-src 'self' ws://localhost:3000 wss://localhost:3000 https://api.github.com;"
  });
  next();
});

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', CORS_ORIGIN);
  res.header('Access-Control-Allow-Methods', 'GET, POST');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  lastModified: false
}));

app.get('/favicon.ico', (req, res) => res.sendStatus(204));

const UPDATE_INTERVALS = {
  processes: 4000,
  network: 2000,
  system: 5000,
  storage: 30000
};

let lastStates = {
  network: null,
  system: null,
  storage: null
};

const io = new Server(httpServer, {
  cors: {
    origin: CORS_ORIGIN,
    methods: ["GET", "POST"],
    credentials: true
  },
  maxHttpBufferSize: 1e6,
  pingTimeout: 60000,
  pingInterval: 25000,
  connectTimeout: 5000,
  transports: ['websocket'],
  allowUpgrades: false,
  path: '/socket.io/',
  serveClient: false,
});

const connectionLimit = 1;
const connectionCounts = {};

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication token required'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.user = decoded;
    next();
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return next(new Error('Token expired'));
    }
    if (err instanceof jwt.JsonWebTokenError) {
      return next(new Error('Invalid token'));
    }
    return next(new Error('Authentication failed'));
  }
});

io.on("connection", async (socket) => {
  activeConnections.set(socket.id, {
    socketId: socket.id,
    connectTime: Date.now(),
    lastActivity: Date.now(),
    ip: socket.handshake.address,
    userAgent: socket.handshake.headers['user-agent'] || 'Unknown',
    user: socket.user
  });

  try {
    const initialInfo = await getSystemInfo();
    if (initialInfo) {
      socket.emit('system-update', initialInfo);
      socket.emit('network-update', initialInfo.network || {});
      socket.emit('process-update', initialInfo.processes || []);
      socket.emit('storage-update', initialInfo.storage || {});
      lastStates = {
        network: initialInfo.network,
        system: initialInfo,
        storage: initialInfo.storage
      };
    }
  } catch (error) {
    console.error('Error emitting initial data:', error);
  }

  socket.onAny(() => {
    const connection = activeConnections.get(socket.id);
    if (connection) {
      connection.lastActivity = Date.now();
    }
  });

  const intervals = {};

  intervals.processes = setInterval(async () => {
    const processes = await si.processes();
    socket.emit('process-update', processes.list.slice(0, 15));
  }, UPDATE_INTERVALS.processes);

  intervals.network = setInterval(async () => {
    const networkInfo = await getNetworkInfo();
    if (networkInfo && hasStateChanged(networkInfo, lastStates.network, 'network')) {
      socket.emit('network-update', networkInfo);
      lastStates.network = networkInfo;
    }
  }, UPDATE_INTERVALS.network);

  intervals.system = setInterval(async () => {
    const info = await getSystemInfo();
    if (info && hasStateChanged(info, lastStates.system, 'system')) {
      socket.emit('system-update', info);
      lastStates.system = info;
    }
  }, UPDATE_INTERVALS.system);

  intervals.storage = setInterval(async () => {
    const diskSpace = await exec("df -h");
    const disks = await si.diskLayout();
    const storageData = {
      usage: diskSpace.stdout,
      disks: disks
    };
    if (hasStateChanged(storageData, lastStates.storage, 'storage')) {
      socket.emit('storage-update', storageData);
      lastStates.storage = storageData;
    }
  }, UPDATE_INTERVALS.storage);

  socket.on("disconnect", (reason) => {
    Object.values(intervals).forEach(interval => clearInterval(interval));
    activeConnections.delete(socket.id);
  });

  socket.on("error", (error) => {
    console.error(`Socket error for ${socket.id}:`, error);
    Object.values(intervals).forEach(interval => clearInterval(interval));
    activeConnections.delete(socket.id);
    socket.disconnect(true);
  });
});

app.post('/api/security-commands', async (req, res) => {
  try {
    const commands = await getSecurityCommands();
    res.json(commands);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch security commands' });
  }
});

app.get('/api/get-token', (req, res) => {
  const payload = { username: 'localhost' };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

function filterNetworkInterfaces(interfaces) {
  return interfaces.filter(iface => !iface.internal);
}

async function getNetworkInfo() {
  try {
    const [
      dnsSettings,
      hostnameInfo,
      netstatOutput
    ] = await Promise.all([
      exec("scutil --dns"),
      exec("scutil --get HostName || hostname"),
      exec("netstat -anv | grep -E '(ESTABLISHED|LISTEN)'")
    ]);

    const connections = netstatOutput.stdout.split('\n')
      .filter(line => line.trim())
      .map(line => {
        const regex = /^(tcp\d?)\s+\d+\s+\d+\s+([\d\.\:]+)\s+([\d\.\:]+)\s+(\w+)/;
        const match = line.match(regex);

        if (match) {
          const protocol = match[1];
          const localAddressPort = match[2];
          const remoteAddressPort = match[3];
          const state = match[4];

          const lastDotIndexLocal = localAddressPort.lastIndexOf('.');
          const localAddress = localAddressPort.substring(0, lastDotIndexLocal);
          const localPort = localAddressPort.substring(lastDotIndexLocal + 1);

          const lastDotIndexRemote = remoteAddressPort.lastIndexOf('.');
          const remoteAddress = remoteAddressPort.substring(0, lastDotIndexRemote);
          const remotePort = remoteAddressPort.substring(lastDotIndexRemote + 1);

          return {
            protocol: protocol || 'N/A',
            localAddress: localAddress || 'N/A',
            localPort: localPort || 'N/A',
            remoteAddress: remoteAddress || 'N/A',
            remotePort: remotePort || 'N/A',
            state: state || 'N/A',
            ipVersion: protocol.includes('6') ? 'IPv6' : 'IPv4'
          };
        } else {
          return {
            protocol: 'N/A',
            localAddress: 'N/A',
            localPort: 'N/A',
            remoteAddress: 'N/A',
            remotePort: 'N/A',
            state: 'N/A',
            ipVersion: 'N/A'
          };
        }
      });

    const dnsServers = [];
    const dnsLines = dnsSettings.stdout.split('\n');
    let currentResolver = null;

    dnsLines.forEach(line => {
      const resolverMatch = line.match(/^resolver #(\d+)/);
      if (resolverMatch) {
        if (currentResolver && currentResolver.nameservers.length > 0) {
          dnsServers.push(...currentResolver.nameservers);
        }
        currentResolver = { nameservers: [] };
      }
      const nameserverMatch = line.match(/^\s*nameserver\[[\d]+\] : (.+)/);
      if (nameserverMatch && currentResolver) {
        currentResolver.nameservers.push(nameserverMatch[1]);
      }

      if (line.trim() === '' && currentResolver) {
        if (currentResolver.nameservers.length > 0) {
          dnsServers.push(...currentResolver.nameservers);
        }
        currentResolver = null;
      }
    });

    if (currentResolver && currentResolver.nameservers.length > 0) {
      dnsServers.push(...currentResolver.nameservers);
    }

    const uniqueDnsServers = [...new Set(dnsServers)];

    const interfaces = await si.networkInterfaces();
    const filteredInterfaces = filterNetworkInterfaces(interfaces);

    return {
      hostname: hostnameInfo.stdout.trim(),
      interfaces: filteredInterfaces,
      dns: {
        servers: uniqueDnsServers,
        settings: dnsSettings.stdout
      },
      connections: {
        established: connections.filter(conn => conn.state === 'ESTABLISHED'),
        listening: connections.filter(conn => conn.state === 'LISTEN')
      }
    };
  } catch (error) {
    console.error("Error fetching network info:", error);
    return null;
  }
}

async function getSystemInfo() {
  try {
    const [
      cpu,
      mem,
      osInfo,
      diskLayout,
      currentLoad,
      processes,
      battery
    ] = await Promise.all([
      si.cpu(),
      si.mem(),
      si.osInfo(),
      si.diskLayout(),
      si.currentLoad(),
      si.processes(),
      si.battery()
    ]);

    const [
      sipStatus,
      firewallStatus,
      diskSpace,
      activeUsersOutput,
      sshStatusOutput,
      ftpStatusOutput
    ] = await Promise.all([
      exec("csrutil status").catch(() => ({ stdout: '' })),
      exec("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate").catch(() => ({ stdout: '0' })),
      exec("df -h"),
      exec("who"),
      exec("lsof -i :22 | grep LISTEN").catch(() => ({ stdout: '' })),
      exec("lsof -i :21 | grep LISTEN").catch(() => ({ stdout: '' }))
    ]);

    const activeUsers = activeUsersOutput.stdout.trim().split('\n').filter(Boolean).map(line => {
      const parts = line.trim().split(/\s+/);
      let ip = 'N/A';

      if (parts.length >= 6 && parts[5].startsWith('(') && parts[5].endsWith(')')) {
        ip = parts[5].replace(/[()]/g, '');
      }

      let time24 = parts[4] || 'N/A';
      let time12 = time24;
      if (time24 !== 'N/A') {
        const [hourStr, minuteStr] = time24.split(':');
        let hour = parseInt(hourStr, 10);
        const minute = minuteStr;
        const ampm = hour >= 12 ? 'PM' : 'AM';
        hour = hour % 12 || 12;
        time12 = `${hour}:${minute} ${ampm}`;
      }

      return {
        user: parts[0] || 'Unknown',
        tty: parts[1] || 'N/A',
        date: parts[2] && parts[3] ? `${parts[2]} ${parts[3]}` : 'N/A',
        time: time12,
        ip: ip
      };
    });

    const sshStatus = sshStatusOutput.stdout.trim().length > 0;
    const ftpStatus = ftpStatusOutput.stdout.trim().length > 0;

    return {
      system: {
        cpu: cpu,
        memory: mem,
        os: osInfo,
        load: currentLoad
      },
      security: {
        sip: sipStatus.stdout.includes("enabled"),
        firewall: firewallStatus.stdout.includes("enabled") || firewallStatus.stdout.includes("1"),
        activeUsers: activeUsers,
        sshStatus: sshStatus,
        ftpStatus: ftpStatus
      },
      storage: {
        disks: diskLayout,
        usage: diskSpace.stdout
      },
      processes: processes.list.slice(0, 15),
      battery: battery
    };
  } catch (error) {
    console.error("Error fetching system info:", error);
    return null;
  }
}

function hasStateChanged(newState, oldState, section) {
  if (!oldState || !newState) return true;

  const hash = (obj) => createHash('md5').update(JSON.stringify(obj)).digest('hex');

  try {
    switch (section) {
      case 'network':
        return hash(newState.connections) !== hash(oldState.connections);
      case 'system':
        return hash({
          system: newState.system,
          security: newState.security
        }) !== hash({
          system: oldState.system,
          security: oldState.security
        });
      case 'storage':
        return hash(newState.usage) !== hash(oldState.usage);
      default:
        return true;
    }
  } catch (error) {
    console.error(`Error in hasStateChanged for section ${section}:`, error);
    return true;
  }
}

setInterval(() => {
  const now = Date.now();
  activeConnections.forEach((data, socketId) => {
    if (now - data.lastActivity > 300000) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.disconnect(true);
      }
      activeConnections.delete(socketId);
    }
  });
}, 60000);

process.on('SIGINT', () => {
  io.close(() => {
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  io.close(() => {
    process.exit(0);
  });
});

httpServer.listen(PORT, HOST, () => console.log(`Server running on http://${HOST}:${PORT}`));