const CONFIG = {
  API: {
    GITHUB: 'https://api.github.com/search',
    BASE_URL: 'http://localhost:3000'
  },
  THEME: {
    LIGHT: 'light',
    DARK: 'dark'
  }
};

const thumbsUp = `<svg class="repo-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="12" height="12"><path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.751.751 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Zm0 2.445L6.615 5.5a.75.75 0 0 1-.564.41l-3.097.45 2.24 2.184a.75.75 0 0 1 .216.664l-.528 3.084 2.769-1.456a.75.75 0 0 1 .698 0l2.77 1.456-.53-3.084a.75.75 0 0 1 .216-.664l2.24-2.183-3.096-.45a.75.75 0 0 1-.564-.41L8 2.694Z"></path></svg>`;
const forksGithub = `<svg class="repo-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="12" height="12"><path d="M5 5.372v.878c0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75v-.878a2.25 2.25 0 1 1 1.5 0v.878a2.25 2.25 0 0 1-2.25 2.25h-1.5v2.128a2.251 2.251 0 1 1-1.5 0V8.5h-1.5A2.25 2.25 0 0 1 3.5 6.25v-.878a2.25 2.25 0 1 1 1.5 0ZM5 3.25a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Zm6.75.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Zm-3 8.75a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Z"></path></svg>`;
const history = `<svg class="history-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="12" height="12"><path d="m.427 1.927 1.215 1.215a8.002 8.002 0 1 1-1.6 5.685.75.75 0 1 1 1.493-.154 6.5 6.5 0 1 0 1.18-4.458l1.358 1.358A.25.25 0 0 1 3.896 6H.25A.25.25 0 0 1 0 5.75V2.104a.25.25 0 0 1 .427-.177ZM7.75 4a.75.75 0 0 1 .75.75v2.992l2.028.812a.75.75 0 0 1-.557 1.392l-2.5-1A.751.751 0 0 1 7 8.25v-3.5A.75.75 0 0 1 7.75 4Z"></path></svg>`
const copyIcon = `<svg class="copy-button" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="12" height="12" fill="currentColor"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>`;

async function fetchToken() {
  const response = await fetch('/api/get-token');
  const data = await response.json();
  return data.token;
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

const getStatusTag = (value, thresholds) => {
  value = parseFloat(value);
  if (isNaN(value)) return `<span class="tag tag-muted mono">N/A</span>`;
  if (value >= thresholds.high) return `<span class="tag tag-danger mono">${value.toFixed(1)}%</span>`;
  if (value >= thresholds.medium) return `<span class="tag tag-warning mono">${value.toFixed(1)}%</span>`;
  return `<span class="tag tag-success mono">${value.toFixed(1)}%</span>`;
};

function formatUptime(seconds) {
  if (!seconds || typeof seconds !== 'number') return 'N/A';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function getPrimaryInterface(interfaces) {
  if (!Array.isArray(interfaces)) return 'None';
  const active = interfaces.find(iface =>
    iface.operstate === 'up' &&
    !iface.internal &&
    (iface.type === 'wireless' || iface.type === 'wired')
  );
  if (!active) return 'None';
  return `${active.type === 'wireless' ? 'WiFi' : 'Ethernet'} (${active.speed || 0}Mbps)`;
}

function initializeTheme() {
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const savedTheme = localStorage.getItem('theme');
  const theme = savedTheme || (prefersDark ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', theme);
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    if (!localStorage.getItem('theme')) {
      document.documentElement.setAttribute('data-theme', e.matches ? 'dark' : 'light');
    }
  });
  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', toggleTheme);
    updateThemeToggleButton(theme);
  }
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme');
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', newTheme);
  localStorage.setItem('theme', newTheme);
  updateThemeToggleButton(newTheme);
}

function updateThemeToggleButton(theme) {
  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.setAttribute('aria-label', `Switch to ${theme === 'light' ? 'dark' : 'light'} theme`);
    themeToggle.setAttribute('title', `Switch to ${theme === 'light' ? 'dark' : 'light'} theme`);
  }
}

function renderNetworkPanel(data) {
  const networkContent = document.getElementById('network-info');
  if (!data || !data.interfaces) {
    networkContent.innerHTML = '<div class="error-message">Network information unavailable</div>';
    return;
  }

  const { dns = { servers: [] }, interfaces = [] } = data;

  const dnsSection = `
    <div class="section-header">DNS Configuration</div>
    <table>
        <thead>
            <tr>
                <th>Server</th>
                <th>Type</th>
            </tr>
        </thead>
        <tbody>
            ${dns.servers.length ? dns.servers.map(server => `
                <tr>
                    <td class="mono">${server}</td>
                    <td class="mono">${server.includes(':') ? 'IPv6' : 'IPv4'}</td>
                </tr>
            `).join('') : '<tr><td colspan="2">No DNS servers configured</td></tr>'}
        </tbody>
    </table>
  `;

  const interfacesSection = `
    <div class="section-header">Network Interfaces</div>
    <table>
        <thead>
            <tr>
                <th>Interface</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>Speed</th>
            </tr>
        </thead>
        <tbody>
            ${interfaces.length ? interfaces.map(iface => `
                <tr>
                    <td class="mono">${iface.iface || 'Unknown'}</td>
                    <td class="mono">${iface.ip4 || iface.ip6 || 'N/A'}</td>
                    <td class="mono">
                        <span class="tag ${iface.operstate === 'up' ? 'tag-success' : 'tag-muted'}">
                            ${(iface.operstate || 'Unknown').charAt(0).toUpperCase() + (iface.operstate || 'Unknown').slice(1)}
                        </span>
                    </td>
                    <td class="mono">${iface.speed > 0 ? iface.speed + 'Mbps' : 'N/A'}</td>
                </tr>
            `).join('') : '<tr><td colspan="4">No network interfaces found</td></tr>'}
        </tbody>
    </table>
  `;

  networkContent.innerHTML = `${dnsSection}${interfacesSection}`;
}

function renderSecurityInfo(securityData) {
  const securityContent = document.getElementById('security-info');
  if (!securityData) {
    securityContent.innerHTML = '<div class="error-message">Security information unavailable</div>';
    return;
  }

  const activeSessions = securityData.activeUsers || [];
  const includeIP = activeSessions.some(session => session.ip && session.ip !== 'N/A');

  const hostnameSection = `
    <div class="headSpcHost">
      <div>
          <span class="hostname-label">Hostname:</span>
          <span class="mono hostname-value">${securityData.hostname || 'Unknown'}</span>
      </div>
      <div>
          <span class="hostname-label">NetBIOS Name:</span>
          <span class="mono">${securityData.netbios || 'Unknown'}</span>
      </div>
      <div>
          <span class="hostname-label">Workgroup:</span>
          <span class="mono">${securityData.workgroup || 'Unknown'}</span>
      </div>
    </div>
  `;

  const sessionsTable = `
    <div class="section-header">Active User Sessions</div>
    <table>
        <thead>
            <tr>
                <th>Username</th>
                <th>TTY</th>
                ${includeIP ? '<th>IP</th>' : ''}
                <th>Login Date</th>
                <th>Login Time</th>
            </tr>
        </thead>
        <tbody>
            ${activeSessions.length ? activeSessions.map(session => `
                <tr>
                    <td class="mono">${session.user || 'Unknown'}</td>
                    <td class="mono">${session.tty || 'N/A'}</td>
                    ${includeIP ? `<td class="mono">${session.ip || 'N/A'}</td>` : ''}
                    <td class="mono">${session.date || 'N/A'}</td>
                    <td class="mono">${session.time || 'N/A'}</td>
                </tr>
            `).join('') : `<tr><td colspan="${includeIP ? 5 : 4}">No active sessions</td></tr>`}
        </tbody>
    </table>
  `;

  securityContent.innerHTML = hostnameSection + sessionsTable;
}

function renderNetworkPanel(data) {
  const networkContent = document.getElementById('network-info');
  if (!data || !data.interfaces) {
    networkContent.innerHTML = '<div class="error-message">Network information unavailable</div>';
    return;
  }

  const { dns = { servers: [] }, interfaces = [] } = data;

  const dnsSection = `
        <div class="section-header">DNS Configuration</div>
        <table>
            <thead>
                <tr>
                    <th>Server</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
                ${dns.servers.length ? dns.servers.map(server => `
                    <tr>
                        <td class="mono">${server}</td>
                        <td class="mono">${server.includes(':') ? 'IPv6' : 'IPv4'}</td>
                    </tr>
                `).join('') : '<tr><td colspan="2">No DNS servers configured</td></tr>'}
            </tbody>
        </table>
    `;

  const interfacesSection = `
        <div class="section-header">Network Interfaces</div>
        <table>
            <thead>
                <tr>
                    <th>Interface</th>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Speed</th>
                </tr>
            </thead>
            <tbody>
                ${interfaces.length ? interfaces.map(iface => `
                    <tr>
                        <td class="mono">${iface.iface || 'Unknown'}</td>
                        <td class="mono">${iface.ip4 || iface.ip6 || 'N/A'}</td>
                        <td class="mono">
                            <span class="tag ${iface.operstate === 'up' ? 'tag-success' : 'tag-muted'}">
                                ${(iface.operstate || 'Unknown').charAt(0).toUpperCase() + (iface.operstate || 'Unknown').slice(1)}
                            </span>
                        </td>
                        <td class="mono">${iface.speed > 0 ? iface.speed + 'Mbps' : 'N/A'}</td>
                    </tr>
                `).join('') : '<tr><td colspan="4">No network interfaces found</td></tr>'}
            </tbody>
        </table>
    `;

  networkContent.innerHTML = `${dnsSection}${interfacesSection}`;
}

function updateProcessPanel(processes) {
    const processContent = document.getElementById('process-info');
    if (!Array.isArray(processes)) {
        processContent.innerHTML = '<div class="error-message">Process information unavailable</div>';
        return;
    }
    processContent.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Name</th>
                    <th>CPU</th>
                    <th>MEM</th>
                    <th>RAM</th>
                </tr>
            </thead>
            <tbody>
                ${processes.map(proc => {
                    const sanitizedCPU = proc.cpu ? proc.cpu.toFixed(1) : 'N/A';
                    const sanitizedMemory = proc.mem ? `${proc.mem}%` : 'N/A';
                    const sanitizedRAM = proc.ram || 'N/A';
                    return `
                        <tr>
                            <td class="mono">${proc.pid || 'N/A'}</td>
                            <td class="mono">${proc.name || 'Unknown'}</td>
                            <td class="mono">${getStatusTag(sanitizedCPU, { medium: 30, high: 60 })}</td>
                            <td class="mono">${sanitizedMemory}</td>
                            <td class="mono">${sanitizedRAM}</td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        </table>
    `;
}

function updateSystemInfo(data) {
  if (!data || !data.system) {
    document.getElementById('system-info').innerHTML = '<div class="error-message">System information unavailable</div>';
    return;
  }
  const { system, battery = {}, security = {} } = data;
  document.getElementById('system-info').innerHTML = `
        <div class="metric-row">
            <span class="metric-label">OS Version</span>
            <span class="mono metric-value">${system.os?.distro || 'Unknown'} ${system.os?.release || ''}</span>
        </div>
        <div class="metric-row">
            <span class="metric-label">CPU Usage</span>
            <span class="metric-value"><span class="mono" id="cpu-usage">${(system.load?.currentLoad || 0).toFixed(1)}</span>%</span>
        </div>
        <div class="metric-row">
            <span class="metric-label">Memory Usage</span>
            <span class="metric-value"><span class="mono" id="memory-usage">
                <span class="mono">${((system.memory?.used / (system.memory?.total || 1)) * 100).toFixed(1)}</span>
            </span>%</span>
        </div>
        <div class="metric-row">
            <span class="metric-label">Total RAM</span>
            <span class="metric-value">
                <span class="mono">${formatBytes(system.memory?.total || `N/A`)}</span>
            </span>
        </div>
        <div class="metric-row">
            <span class="metric-label">Swap Usage</span>
            <span class="metric-value">
                <span class="mono">${((system.memory?.swapused / (system.memory?.swaptotal || 1)) * 100 || 0).toFixed(1)}%</span>
            </span>
        </div>
        <div class="metric-row">
            <span class="metric-label">Power Source</span>
            <span class="mono metric-value">${battery.acConnected ? 'AC Power' : 'Battery'}</span>
        </div>
        <div class="metric-row">
            <span class="metric-label">Battery Remaining</span>
            <span class="metric-value">
                <span id="battery-status">${battery.percent || '--'}</span>% 
                <span class="mono"> ${battery.isCharging ? '⚡' : ''}</span>
            </span>
        </div>
        <div class="metric-row">
            <span class="metric-label">SIP Status</span>
            <span class="mono tag ${security.sip ? 'tag-success' : 'tag-danger'}">
                <span class="mono">${security.sip ? 'True' : 'False'}</span>
            </span>
        </div>
        <div class="metric-row">
            <span class="metric-label">Firewall</span>
            <span class="mono tag ${security.firewall ? 'tag-success' : 'tag-danger'}">
                <span class="mono">${security.firewall ? 'True' : 'False'}</span>
        </div>
    `;
  renderSecurityInfo(security);
}

function updateStoragePanel(data) {
  const storageContent = document.getElementById('storage-info');
  if (!data) {
    storageContent.innerHTML = '<div class="error-message">Storage information unavailable</div>';
    return;
  }
  const { usage = '', disks = [] } = data;
  const usageTable = `
      <table>
          <thead>
              <tr>
                  <th>Device</th>
                  <th>Size</th>
                  <th>Used</th>
                  <th>Available</th>
                  <th>Mount</th>
              </tr>
          </thead>
          <tbody>
     ${usage.split('\n')
    .filter(line => line.trim() && !line.startsWith('Filesystem'))
    .map(line => {
      const parts = line.trim().split(/\s+/);
      return `
        <tr>
            <td class="mono" title="${parts[0]}">${parts[0].split('/').pop()}</td>
            <td class="mono">${parts[1] || 'N/A'}</td>
            <td class="mono">${parts[2] || 'N/A'}</td>
            <td class="mono">${parts[3] || 'N/A'}</td>
            <td title="${parts[8] || ''}">${parts[8] || 'N/A'}</td>
        </tr>
    `;
    }).join('')}
          </tbody>
      </table>
  `;
  const disksTable = `
        <table class="disk-spc">
            <thead>
                <tr>
                    <th>Installed</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Interface</th>
                </tr>
            </thead>
            <tbody>
                ${disks.length ? disks.map(disk => `
                    <tr>
                        <td class="mono">${disk.name || 'Unknown'}</td>
                        <td class="mono">${disk.type || 'N/A'}</td>
                        <td class="mono">${formatBytes(disk.size)}</td>
                        <td class="mono">${disk.interfaceType || 'N/A'}</td>
                    </tr>
                `).join('') : '<tr><td colspan="4">No physical drives detected</td></tr>'}
            </tbody>
        </table>
    `;
  storageContent.innerHTML = disksTable + usageTable;
}

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

function updatePortMonitor(connections = []) {
    const portContent = document.getElementById('port-monitor');
    const allConnections = [
        ...(connections.established || []),
        ...(connections.listening || [])
    ];

    const portStatuses = SECURITY_PORTS.map(portInfo => {
        const activeConnections = allConnections.filter(conn =>
            conn.localPort === portInfo.port.toString() ||
            conn.remotePort === portInfo.port.toString()
        );

        const tcpActive = activeConnections.some(conn => conn.protocol.toLowerCase().includes('tcp'));
        const udpActive = activeConnections.some(conn => conn.protocol.toLowerCase().includes('udp'));
        const ipv4Active = activeConnections.some(conn => conn.ipVersion === 'IPv4');
        const ipv6Active = activeConnections.some(conn => conn.ipVersion === 'IPv6');

        return {
            ...portInfo,
            status: activeConnections.length > 0 ? 'Active' : 'Inactive',
            connections: activeConnections.length,
            details: activeConnections,
            protocols: { tcp: tcpActive, udp: udpActive },
            ipVersions: { ipv4: ipv4Active, ipv6: ipv6Active }
        };
    });

    const connectionsSection = `
        <table>
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Local Address</th>
                    <th>Local Port</th>
                    <th>State</th>
                </tr>
            </thead>
            <tbody>
                ${connections.established.map(conn => `
                    <tr>
                        <td class="mono">${conn.protocol || 'N/A'} ${conn.ipVersion || ''}</td>
                        <td class="mono">${conn.localAddress || 'N/A'}</td>
                        <td class="mono">${conn.localPort || 'N/A'}</td>
                        <td class="mono"><span class="tag tag-success">${conn.state}</span></td>
                    </tr>
                `).join('')}
                ${connections.listening.map(conn => `
                    <tr>
                        <td class="mono">${conn.protocol || 'N/A'} ${conn.ipVersion || ''}</td>
                        <td class="mono">${conn.localAddress || 'N/A'}</td>
                        <td class="mono">${conn.localPort || 'N/A'}</td>
                        <td class="mono"><span class="tag tag-muted">${conn.state}</span></td>
                    </tr>
                `).join('')}
                ${(!connections.established.length && !connections.listening.length) ?
      '<tr><td colspan="4">No active connections</td></tr>' : ''}
            </tbody>
        </table>
    `;

    portContent.innerHTML = `
        <table>
            <thead>
                <tr>
                  <th>Port</th>
                  <th>Proto</th>
                  <th>Name</th>
                  <th>Status</th>
                  <th>Count</th>
                  <th>Layer</th>
                  <th>IP</th>
              </tr>
            </thead>
            <tbody>
                ${portStatuses.map(port => `
                    <tr>
                        <td class="mono">${port.port}</td>
                        <td class="mono">${port.service}</td>
                        <td>${port.description}</td>
                        <td>
                            <span class="tag ${port.status === 'Active' ? 'tag-warning' : 'tag-success'}">
                                ${port.status}
                            </span>
                        </td>
                        <td class="mono">
                            ${port.connections > 0 ? 
                                `<span class="tag tag-warning">${port.connections}</span>` : 
                                '<span class="tag tag-success">0</span>'}
                        </td>
                        <td class="mono">
                            ${port.protocols.tcp ? '<span class="tag tag-success">TCP</span>' : '<span class="tag tag-muted">TCP</span>'}
                            ${port.protocols.udp ? '<span class="tag tag-success">UDP</span>' : '<span class="tag tag-muted">UDP</span>'}
                        </td>
                        <td class="mono">
                            ${port.ipVersions.ipv4 ? '<span class="tag tag-success">IPv4</span>' : '<span class="tag tag-muted">IPv4</span>'}
                            ${port.ipVersions.ipv6 ? '<span class="tag tag-success">IPv6</span>' : '<span class="tag tag-muted">IPv6</span>'}
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
        <div id="hdrNetConn" class="section-header">Active Connections</div>
        ${connectionsSection}
    `;
}

function updateCommandsPanel(commands) {
    console.log("Starting to update commands panel");
    if (!Array.isArray(commands) || commands.length === 0) {
        console.log("No commands to display");
        document.getElementById('tab-content').innerHTML = `
            <div class="error-message">No commands available</div>
        `;
        return;
    }
    
    const tableHTML = `
        <table class="command-table">
            <thead>
                <tr>
                    <th>Command</th>
                    <th>Description</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                ${commands.map(cmd => `
                    <tr>
                        <td class="mono">
                            <div class="command-name">${cmd.name || 'No name available'}</div>
                        </td>
                        <td>
                            ${cmd.description || 'No description available'}
                        </td>
                        <td class="mono">
                            <div class="command-cell">
                                <code class="command-text">${cmd.command || 'N/A'}</code>
                                <span class="copy-icon" data-command="${cmd.command}">${copyIcon}</span>
                            </div>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    const tabContent = document.getElementById('tab-content');
    if (tabContent) {
        tabContent.innerHTML = tableHTML;
        
        document.querySelectorAll('.copy-icon').forEach(icon => {
            icon.addEventListener('click', (e) => {
                const command = e.currentTarget.dataset.command;
                const svg = e.currentTarget.querySelector('svg');
                
                navigator.clipboard.writeText(command)
                    .then(() => {
                        svg.style.fill = '#4CAF50';
                        setTimeout(() => {
                            svg.style.fill = 'currentColor';
                        }, 3000);
                    })
                    .catch(err => console.error('Failed to copy:', err));
            });
        });
    }
}

function renderGists() {
  document.getElementById('tab-content').innerHTML = `
        <div class="coming-soon">Coming soon!</div>
    `;
}

function renderCommunityScripts() {
  document.getElementById('tab-content').innerHTML = `
        <div class="coming-soon">Coming soon!</div>
    `;
}

let currentTab = 'repos';

async function fetchSecurityRepos() {
  try {
    const query = encodeURIComponent(
      'security in:name,description,topics macos in:name,description,topics stars:>50'
    );
    
    const response = await fetch(`https://api.github.com/search/repositories?q=${query}&sort=stars&order=desc&per_page=50`, {
      headers: {
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    const rateLimit = {
      remaining: response.headers.get('X-RateLimit-Remaining'),
      reset: response.headers.get('X-RateLimit-Reset')
    };

    if (response.status === 403 && rateLimit.remaining === '0') {
      const resetTime = new Date(rateLimit.reset * 1000).toLocaleString();
      throw new Error(`GitHub API rate limit exceeded. Resets at ${resetTime}`);
    }

    if (!response.ok) {
      throw new Error(`GitHub API error: ${response.status}`);
    }

    const data = await response.json();
    return data;

  } catch (error) {
    console.error('Error fetching repos:', error);
    return { items: [] };
  }
}

function renderRepos(data) {
  if (!data || !Array.isArray(data.items)) {
    document.getElementById('tab-content').innerHTML = '<div class="error-message">No repositories available</div>';
    return;
  }

  const content = `
    <table class="repo-table">
      <tbody>
        ${data.items.map(repo => `
          <tr>
            <td class="repo-name">
              <a href="${repo.html_url}" target="_blank" rel="noopener noreferrer">${repo.name}</a>
            </td>
            <td>
              <span title="${repo.language || 'N/A'}" class="rp-lang">${repo.language}</span>
            </td>
            <td class="repo-description">
              <div class="description-content">
                ${repo.description || 'No description'}
              </div>
            </td>
            <td class="repo-tags">
              ${repo.topics && repo.topics.length > 0 ? `
                <span class="script-tags">
                  ${repo.topics.slice(0, 2).map(topic =>
                    `<span class="script-tag">${topic}</span>`
                  ).join('')}
                </span>
              ` : ''}
            </td>
            <td class="repo-date">
              ${history}
              Updated: 
              ${new Date(repo.updated_at).toLocaleDateString()}
            </td>
            <td class="repo-stats">
              <span class="script-stat">${thumbsUp} ${repo.stargazers_count?.toLocaleString() || '0'}</span>
              <span class="script-stat">${forksGithub} ${repo.forks_count?.toLocaleString() || '0'}</span>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  document.getElementById('tab-content').innerHTML = content;

  document.getElementById('repo-sort').addEventListener('change', (e) => {
    const sortBy = e.target.value;
    const sortedItems = [...data.items].sort((a, b) => {
      switch(sortBy) {
        case 'stars':
          return b.stargazers_count - a.stargazers_count;
        case 'forks':
          return b.forks_count - a.forks_count;
        case 'updated':
          return new Date(b.updated_at) - new Date(a.updated_at);
        case 'created':
          return new Date(b.created_at) - new Date(a.created_at);
        default:
          return 0;
      }
    });
    
    renderRepos({ ...data, items: sortedItems });
  });
};

async function initializeSocket() {
  const SOCKET_IO_TOKEN = await fetchToken();
  const socket = io(CONFIG.API.BASE_URL, {
    transports: ['websocket'],
    auth: {
      token: SOCKET_IO_TOKEN
    }
  });
  socket.on('connect', () => {
    console.log('Connected to Socket.IO server');
  });
  socket.on('system-update', (data) => updateSystemInfo(data));
  socket.on('network-update', (data) => {
      renderNetworkPanel(data);
      if (data.connections) {
          updatePortMonitor(data.connections);
      }
  });
  socket.on('process-update', (data) => updateProcessPanel(data));
  socket.on('storage-update', (data) => updateStoragePanel(data));
  socket.on('connect_error', (error) => {
    console.error('Connection Error:', error.message);
  });
  const refreshBtn = document.getElementById('refresh-btn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', refreshCommands);
  }
  const tabButtons = document.querySelectorAll('.tab-btn');
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.getAttribute('data-tab');
      switchTab(tab);
    });
  });
  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', toggleTheme);
  }
}

const tabState = {
    repos: null,
    commands: null,
    scripts: null
};

const loadingTemplate = `
    <div class="loading-container">
        <div class="loading-dot"></div>
    </div>
`;

async function switchTab(tabName) {
    if (!['repos', 'commands', 'scripts'].includes(tabName)) {
        console.error('Invalid tab name:', tabName);
        return;
    }
    
    currentTab = tabName;
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => btn.classList.remove('active'));
    const activeTab = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
    if (activeTab) activeTab.classList.add('active');
    
    const contentDiv = document.getElementById('tab-content');
    const refreshBtn = document.getElementById('refresh-btn');
    const sortSelect = document.getElementById('repo-sort');
    
    refreshBtn.style.display = tabName === 'commands' ? 'block' : 'none';
    sortSelect.style.display = tabName === 'repos' ? 'block' : 'none';

    if (tabState[tabName]) {
        contentDiv.innerHTML = tabState[tabName];
        return;
    }

    contentDiv.innerHTML = loadingTemplate;

    try {
        switch (tabName) {
            case 'repos':
                const repos = await fetchSecurityRepos();
                renderRepos(repos);
                tabState.repos = contentDiv.innerHTML;
                break;
            case 'commands':
                await refreshCommands();
                break;
            case 'scripts':
                renderGists();
                tabState.scripts = contentDiv.innerHTML;
                break;
        }
    } catch (error) {
        console.error(`Error switching to tab ${tabName}:`, error);
        contentDiv.innerHTML = '<div class="error-message">Failed to load content</div>';
    }
}

async function refreshCommands() {
    const refreshBtn = document.getElementById('refresh-btn');
    const contentDiv = document.getElementById('tab-content');
    
    if (refreshBtn) {
        refreshBtn.classList.add('loading');
        refreshBtn.disabled = true;
    }

    if (!tabState.commands) {
        contentDiv.innerHTML = loadingTemplate;
    }
    
    try {
        const response = await fetch(`${CONFIG.API.BASE_URL}/api/security-commands`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const commands = await response.json();
        
        updateCommandsPanel(commands);
        tabState.commands = contentDiv.innerHTML;
    } catch (error) {
        console.error('Error refreshing commands:', error);
        contentDiv.innerHTML = `
            <div class="error-message">Failed to fetch security commands</div>
        `;
        tabState.commands = contentDiv.innerHTML;
    } finally {
        if (refreshBtn) {
            setTimeout(() => {
                refreshBtn.classList.remove('loading');
                refreshBtn.disabled = false;
            }, 1000);
        }
    }
}

const commandsTab = document.querySelector('.tab-btn[data-tab="commands"]');
if (commandsTab) {
    commandsTab.addEventListener('click', async () => {
        if (!tabState.commands) {
            await refreshCommands();
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    initializeTheme();
    initializeSocket();
    switchTab('repos');
    
    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshCommands);
        refreshBtn.style.display = 'none';
    }
});