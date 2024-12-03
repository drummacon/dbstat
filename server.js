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

const SECURITY_PORTS = [
   { port: 20, service: 'FTP Data', description: 'File Transfer Protocol Data Channel' },
   { port: 21, service: 'FTP Control', description: 'File Transfer Protocol Control' },
   { port: 22, service: 'SSH', description: 'Secure Shell Remote Access' },
   { port: 23, service: 'Telnet', description: 'Unencrypted Remote Login' },
   { port: 25, service: 'SMTP', description: 'Simple Mail Transfer Protocol' },
   { port: 53, service: 'DNS', description: 'Domain Name System' },
   { port: 67, service: 'DHCP', description: 'Dynamic Host Configuration' },
   { port: 68, service: 'DHCP', description: 'Dynamic Host Configuration' },
   { port: 80, service: 'HTTP', description: 'Web Traffic' },
   { port: 88, service: 'Kerberos', description: 'Authentication Service' },
   { port: 110, service: 'POP3', description: 'Post Office Protocol' },
   { port: 111, service: 'RPC', description: 'Remote Procedure Call' },
   { port: 123, service: 'NTP', description: 'Network Time Protocol' },
   { port: 135, service: 'RPC Endpoint', description: 'Windows RPC Service' },
   { port: 137, service: 'NetBIOS Name', description: 'Network Name Service' },
   { port: 138, service: 'NetBIOS Datagram', description: 'Network Datagram Distribution' },
   { port: 139, service: 'NetBIOS Session', description: 'Network Session Service' },
   { port: 143, service: 'IMAP', description: 'Internet Message Access Protocol' },
   { port: 161, service: 'SNMP', description: 'Simple Network Management Protocol' },
   { port: 162, service: 'SNMP Trap', description: 'SNMP Notification' },
   { port: 224, service: 'Multicast', description: 'Multicast Base Address' },
   { port: 239, service: 'Multicast', description: 'Multicast Routing' },
   { port: 401, service: 'UNIXWare', description: 'UNIX to UNIX Connection' },
   { port: 402, service: 'UNIXWare', description: 'UNIX to UNIX Connection' },
   { port: 389, service: 'Open Directory', description: 'LDAP Directory Service' },
   { port: 443, service: 'HTTPS', description: 'Secure Web Traffic' },
   { port: 445, service: 'SMB', description: 'Server Message Block/CIFS' },
   { port: 464, service: 'Kerberos Password', description: 'Kerberos Password Change' },
   { port: 500, service: 'ISAKMP', description: 'Internet Security Association and Key Management Protocol' },
   { port: 512, service: 'rexec', description: 'Remote Execution Service' },
   { port: 513, service: 'rlogin', description: 'Remote Login' },
   { port: 514, service: 'rsh', description: 'Remote Shell' },
   { port: 515, service: 'Line Printer', description: 'UNIX Printer Daemon' },
   { port: 520, service: 'RIP', description: 'Routing Information Protocol' },
   { port: 523, service: 'IBM-DB2', description: 'Database Communication' },
   { port: 544, service: 'Kerberos Rsh', description: 'Kerberized Remote Shell' },
   { port: 548, service: 'AFP', description: 'Apple File Protocol' },
   { port: 631, service: 'CUPS', description: 'Common Unix Printing System' },
   { port: 636, service: 'LDAPS', description: 'LDAP over SSL' },
   { port: 749, service: 'Kerberos Admin', description: 'Kerberos Administration' },
   { port: 993, service: 'IMAPS', description: 'IMAP over SSL' },
   { port: 995, service: 'POP3S', description: 'POP3 over SSL' },
   { port: 1025, service: 'Windows RPC', description: 'Microsoft Remote Procedure Call' },
   { port: 1080, service: 'SOCKS Proxy', description: 'Socket Secure Proxy' },
   { port: 1433, service: 'MSSQL', description: 'Microsoft SQL Server' },
   { port: 1521, service: 'Oracle', description: 'Oracle Database' },
   { port: 2049, service: 'NFS', description: 'Network File System' },
   { port: 2222, service: 'SSH Alt', description: 'Alternative SSH Port' },
   { port: 2427, service: 'Net Mount', description: 'Network Mounting Protocol' },
   { port: 2428, service: 'Net Mount', description: 'Alternative Network Mounting' },
   { port: 3306, service: 'MySQL', description: 'MySQL Database' },
   { port: 3389, service: 'RDP', description: 'Remote Desktop Protocol' },
   { port: 3478, service: 'FaceTime', description: 'Apple Video Calling' },
   { port: 4000, service: 'Continuity', description: 'Apple Device Handoff' },
   { port: 4242, service: 'Captive Portal', description: 'Apple Network Capture Detection' },
   { port: 4243, service: 'Captive Portal', description: 'Alternative Network Capture Service' },
   { port: 4444, service: 'Malware C2', description: 'Potential Command & Control' },
   { port: 4897, service: 'FaceTime', description: 'FaceTime Relay' },
   { port: 5000, service: 'Bonjour Sleep Proxy', description: 'Apple Device Sleep Proxy' },
   { port: 5353, service: 'mDNS', description: 'Multicast DNS Service Discovery' },
   { port: 5100, service: 'Handoff', description: 'Apple Device Handoff' },
   { port: 5222, service: 'Jabber', description: 'XMPP Messaging' },
   { port: 5223, service: 'MDM', description: 'Mobile Device Management' },
   { port: 5224, service: 'MDM', description: 'Alternative Mobile Device Management' },
   { port: 5225, service: 'MDM', description: 'Mobile Device Management Service' },
   { port: 5226, service: 'MDM', description: 'Mobile Device Management Notification' },
   { port: 5269, service: 'Jabber Server', description: 'XMPP Server-to-Server' },
   { port: 5280, service: 'XMPP Bosh', description: 'XMPP Web Connection' },
   { port: 5353, service: 'mDNS', description: 'Multicast Domain Name System' },
   { port: 5432, service: 'PostgreSQL', description: 'PostgreSQL Database' },
   { port: 5900, service: 'VNC', description: 'Virtual Network Computing' },
   { port: 5985, service: 'WinRM', description: 'Windows Remote Management' },
   { port: 5986, service: 'WinRM SSL', description: 'Secure Windows Remote Management' },
   { port: 6000, service: 'X11', description: 'X Window System' },
   { port: 6620, service: 'NetAgent', description: 'Network Management' },
   { port: 6667, service: 'IRC', description: 'Potential Botnet Communication' },
   { port: 6771, service: 'Safari Scoped Bookmark', description: 'Web Browser Resource Access' },
   { port: 6772, service: 'Safari Scoped Bookmark Alt', description: 'Alternative Web Resource Access' },
   { port: 6881, service: 'P2P', description: 'Peer-to-Peer Networking' },
   { port: 6881, service: 'Torrent', description: 'BitTorrent Networking' },
   { port: 6882, service: 'P2P Alt', description: 'Alternative Peer-to-Peer Port' },
   { port: 6969, service: 'Tracker', description: 'BitTorrent Tracker' },
   { port: 7000, service: 'Airplay', description: 'Screen Casting' },
   { port: 7070, service: 'Real Time Streaming', description: 'Media Streaming' },
   { port: 7100, service: 'Screen Share', description: 'macOS Screen Sharing' },
   { port: 8000, service: 'P2P', description: 'Peer-to-Peer Streaming' },
   { port: 8265, service: 'AWS', description: 'Amazon Web Services Communication' },
   { port: 9100, service: 'JetDirect', description: 'Printer Network Port' },
   { port: 9418, service: 'Git', description: 'Git Protocol' },
   { port: 11211, service: 'Memcached', description: 'Distributed Memory Caching' },
   { port: 17500, service: 'Dropbox LAN Sync', description: 'Local Network File Synchronization' },
   { port: 27017, service: 'MongoDB', description: 'NoSQL Database' },
   { port: 50000, service: 'VND', description: 'Video Network Discovery' }
];

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
    try {
        const processes = await si.processes();
        const processesWithRam = processes.list.slice(0, 15).map(proc => ({
          pid: proc.pid,
          name: proc.name,
          cpu: proc.cpu,
          mem: proc.mem,
          ram: formatBytes(proc.memRss || 0)
      }));
      socket.emit('process-update', processesWithRam);
    } catch (error) {
        console.error('Error updating processes:', error);
    }
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

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

async function getNetworkInfo() {
  try {
    const [
      dnsSettings,
      hostnameInfo,
      netstatOutput,
      lsofOutput,
      smbStatusOutput
    ] = await Promise.all([
      exec("scutil --dns"),
      exec("scutil --get HostName || hostname"),
      exec("netstat -anv | grep -E '(ESTABLISHED|LISTEN)'"),
      exec("lsof -i -P | grep LISTEN"),
      exec("smbutil status $(scutil --get HostName || hostname)").catch(() => ({ stdout: '' }))
    ]);

    const connections = netstatOutput.stdout.split('\n')
      .filter(line => line.trim())
      .map(line => {
        const regex = /^(tcp\d?|udp\d?)\s+\d+\s+\d+\s+([\d\.\:]+)\s+([\d\.\:]+)\s+(\w+)/;
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

    const listeningPorts = lsofOutput.stdout.split('\n')
      .filter(line => line.trim())
      .map(line => {
        const parts = line.split(/\s+/);
        return {
          process: parts[0],
          protocol: parts[3],
          localAddress: parts[8]?.split(':')[0] || 'N/A',
          localPort: parts[8]?.split(':')[1] || 'N/A',
          state: 'LISTEN'
        };
      });

    const securityPortStatuses = SECURITY_PORTS.map(portInfo => {
      const activeConnections = connections.filter(conn =>
        parseInt(conn.localPort) === portInfo.port || parseInt(conn.remotePort) === portInfo.port
      );

      const listeningTcp = listeningPorts.some(lp =>
        parseInt(lp.localPort) === portInfo.port && lp.protocol.toLowerCase().includes('tcp')
      );
      const listeningUdp = listeningPorts.some(lp =>
        parseInt(lp.localPort) === portInfo.port && lp.protocol.toLowerCase().includes('udp')
      );

      const ipv4Connections = activeConnections.filter(conn => conn.ipVersion === 'IPv4');
      const ipv6Connections = activeConnections.filter(conn => conn.ipVersion === 'IPv6');

      return {
        port: portInfo.port,
        service: portInfo.service,
        description: portInfo.description,
        status: activeConnections.length > 0 ? 'Active' : (listeningTcp || listeningUdp ? 'Listening' : 'Inactive'),
        protocols: {
          tcp: listeningTcp,
          udp: listeningUdp
        },
        ipVersions: {
          ipv4: ipv4Connections.length > 0,
          ipv6: ipv6Connections.length > 0
        },
        activeConnections: activeConnections
      };
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
    const filteredInterfaces = interfaces.filter(iface => !iface.internal);
    const netbiosMatch = smbStatusOutput.stdout.match(/NetBIOS name:\s*(.+)/i);
    const workgroupMatch = smbStatusOutput.stdout.match(/Workgroup:\s*(.+)/i);

    return {
      hostname: hostnameInfo.stdout.trim(),
      netbios: netbiosMatch ? netbiosMatch[1].trim() : 'Unknown',
      workgroup: workgroupMatch ? workgroupMatch[1].trim() : 'Unknown',
      interfaces: filteredInterfaces,
      dns: {
        servers: uniqueDnsServers,
        settings: dnsSettings.stdout
      },
      securityPorts: securityPortStatuses,
      connections: {
        established: connections.filter(conn => conn.state === 'ESTABLISHED'),
        listening: listeningPorts
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