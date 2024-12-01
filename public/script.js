const CONFIG = {
  API: {
    GITHUB: 'https://api.github.com',
    BASE_URL: 'http://localhost:3000'
  },
  THEME: {
    LIGHT: 'light',
    DARK: 'dark'
  }
};

async function fetchToken() {
  const response = await fetch('/api/get-token');
  const data = await response.json();
  return data.token;
}

const formatBytes = bytes => {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
};

const getStatusTag = (value, thresholds) => {
  value = parseFloat(value);
  if (isNaN(value)) return `<span class="tag tag-muted">N/A</span>`;
  if (value >= thresholds.high) return `<span class="tag tag-danger">${value.toFixed(1)}%</span>`;
  if (value >= thresholds.medium) return `<span class="tag tag-warning">${value.toFixed(1)}%</span>`;
  return `<span class="tag tag-success">${value.toFixed(1)}%</span>`;
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
  if (!data || !data.hostname || !data.interfaces) {
    networkContent.innerHTML = '<div class="error-message">Network information unavailable</div>';
    return;
  }

  const { dns = { servers: [] }, connections = { established: [], listening: [] }, interfaces = [] } = data;

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

  const connectionsSection = `
        <div class="section-header">Active Connections</div>
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
                                ${(iface.operstate || 'unknown').toUpperCase()}
                            </span>
                        </td>
                        <td class="mono">${iface.speed > 0 ? iface.speed + 'Mbps' : 'N/A'}</td>
                    </tr>
                `).join('') : '<tr><td colspan="4">No network interfaces found</td></tr>'}
            </tbody>
        </table>
    `;

  networkContent.innerHTML = `
        <div class="network-hostname">
            <span class="hostname-label">Hostname:</span>
            <span class="mono hostname-value">${data.hostname || 'Unknown'}</span>
        </div>
        ${dnsSection}
        ${connectionsSection}
        ${interfacesSection}
    `;
}

function renderSecurityInfo(securityData) {
  const securityContent = document.getElementById('security-info');
  if (!securityData) {
    securityContent.innerHTML = '<div class="error-message">Security information unavailable</div>';
    return;
  }

  const activeSessions = securityData.activeUsers || [];

  const includeIP = activeSessions.some(session => session.ip && session.ip !== 'N/A');

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
                        ${includeIP ? `<td class="mono">${session.ip || '192.168.1.1'}</td>` : ''}
                        <td class="mono">${session.date || 'N/A'}</td>
                        <td class="mono">${session.time || 'N/A'}</td>
                    </tr>
                `).join('') : `<tr><td colspan="${includeIP ? 5 : 4}">No active sessions</td></tr>`}
            </tbody>
        </table>
    `;

  const servicesStatus = `
        <div class="section-header">Service Status</div>
        <table>
            <tbody>
                <tr>
                    <td>SSH Service</td>
                    <td>
                        <span class="mono tag ${securityData.sshStatus ? 'tag-success' : 'tag-error'}">
                            ${securityData.sshStatus ? 'Running' : 'Stopped'}
                        </span>
                    </td>
                </tr>
                <tr>
                    <td>FTP Service</td>
                    <td>
                        <span class="mono tag ${securityData.ftpStatus ? 'tag-success' : 'tag-error'}">
                            ${securityData.ftpStatus ? 'Running' : 'Stopped'}
                        </span>
                    </td>
                </tr>
            </tbody>
        </table>
    `;

  const securitySection = `
        ${sessionsTable}
        ${servicesStatus}
    `;

  securityContent.innerHTML = securitySection;
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
                    <th>Memory</th>
                    <th>Command</th>
                </tr>
            </thead>
            <tbody>
                ${processes.map(proc => `
                    <tr>
                        <td class="mono">${proc.pid || 'N/A'}</td>
                        <td class="mono">${proc.name || 'Unknown'}</td>
                        <td class="mono">${getStatusTag(proc.cpu, { medium: 30, high: 60 })}</td>
                        <td class="mono">${getStatusTag(proc.mem, { medium: 30, high: 60 })}</td>
                        <td class="mono command-cell" title="${proc.command || ''}">${proc.command || 'N/A'}</td>
                    </tr>
                `).join('')}
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
            <span class="metric-label">Swap Usage</span>
            <span class="metric-value">
                <span class="mono">${((system.memory?.swapused / (system.memory?.swaptotal || 1)) * 100 || 0).toFixed(1)}%</span>
            </span>
        </div>
        <div class="metric-row">
            <span class="metric-label">Battery Status</span>
            <span class="metric-value">
                <span id="battery-status">${battery.percent || '--'}</span>% 
                <span class="mono"> ${battery.isCharging ? '⚡' : ''}</span>
            </span>
        </div>
        <div class="metric-row">
            <span class="metric-label">Power Source</span>
            <span class="mono metric-value">${battery.acConnected ? 'AC Power' : 'Battery'}</span>
        </div>
        <div class="metric-row">
            <span class="metric-label">Uptime</span>
            <span class="mono metric-value">${formatUptime(system.os?.uptime)}</span>
        </div>
        <div class="metric-row">
            <span class="metric-label">Active Network</span>
            <span class="mono metric-value">${getPrimaryInterface(system.network?.interfaces || [])}</span>
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
        <div class="metric-row">
            <span class="metric-label">OS Version</span>
            <span class="mono metric-value">${system.os?.distro || 'Unknown'} ${system.os?.release || ''}</span>
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
                                <td title="${parts[0]}">${parts[0].split('/').pop()}</td>
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
                    <th>Name</th>
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

async function refreshCommands() {
  const refreshBtn = document.getElementById('refresh-btn');
  if (refreshBtn) {
    refreshBtn.classList.add('loading');
    refreshBtn.disabled = true;
  }
  try {
    console.log("Fetching security commands...");
    const response = await fetch(`${CONFIG.API.BASE_URL}/api/security-commands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    console.log("API Response status:", response.status);
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
    const commands = await response.json();
    console.log("Received commands:", commands);
    updateCommandsPanel(commands);
  } catch (error) {
    console.error('Error refreshing commands:', error);
    document.getElementById("command-info").innerHTML = `
            <div class="error-message">Failed to fetch security commands</div>
        `;
  } finally {
    if (refreshBtn) {
      setTimeout(() => {
        refreshBtn.classList.remove('loading');
        refreshBtn.disabled = false;
      }, 1000);
    }
  }
}

function updateCommandsPanel(commands) {
  console.log("Starting to update commands panel");
  if (!Array.isArray(commands) || commands.length === 0) {
    console.log("No commands to display");
    document.getElementById("command-info").innerHTML = `
            <div class="error-message">No commands available</div>
        `;
    return;
  }
  
  const copyIcon = `<svg class="copy-button" width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>`;
  
  const tableHTML = `
        <table class="command-table">
            <thead>
                <tr>
                    <th>Description</th>
                    <th>Command</th> 
                </tr>
            </thead>
            <tbody>
                ${commands.map(cmd => `
                    <tr>
                        <td>${cmd.description || 'No description available'}</td>
                        <td class="mono">
                            <div class="command-cell">
                                <code class="command-text">${cmd.command || 'N/A'}</code>
                                <span class="copy-icon" data-command="${cmd.command}">${copyIcon}</span>
                            </div>
                        </td>
                    </tr>
                `).join("")}
            </tbody>
        </table>
    `;
  console.log("Generated table HTML:", tableHTML.slice(0, 100) + "...");
  const commandInfoElement = document.getElementById("command-info");
  if (commandInfoElement) {
    commandInfoElement.innerHTML = tableHTML;
    console.log("Table updated successfully");
    
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
  } else {
    console.error("Could not find command-info element");
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

async function switchTab(tabName) {
  if (!['repos', 'gists', 'scripts'].includes(tabName)) {
    console.error('Invalid tab name:', tabName);
    return;
  }
  currentTab = tabName;
  const tabButtons = document.querySelectorAll('.tab-btn');
  tabButtons.forEach(btn => btn.classList.remove('active'));
  const activeTab = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
  if (activeTab) activeTab.classList.add('active');
  const contentDiv = document.getElementById('tab-content');
  contentDiv.innerHTML = '';

  try {
    switch (tabName) {
      case 'repos':
        const repos = await fetchSecurityRepos();
        renderRepos(repos);
        break;
      case 'gists':
        renderGists();
        break;
      case 'scripts':
        renderCommunityScripts();
        break;
    }
  } catch (error) {
    console.error(`Error switching to tab ${tabName}:`, error);
    contentDiv.innerHTML = '<div class="error-message">Failed to load content</div>';
  }
}

async function fetchSecurityRepos() {
  try {
    const queries = [
      'macos security',
      'apple security',
      'macos firewall',
      'macos malware',
      'vulnerability macos'
    ];

    const allResults = [];

    for (const query of queries) {
      let page = 1;
      let hasMoreResults = true;

      while (hasMoreResults) {
        const response = await fetch(`${CONFIG.API.GITHUB}/search/repositories?q=${encodeURIComponent(query)}&sort=stars&order=desc&per_page=10&page=${page}`);
        if (!response.ok) throw new Error(`GitHub API error: ${response.status}`);
        
        const data = await response.json();

        if (data.items && data.items.length > 0) {
          allResults.push(...data.items);
          page++;
        } else {
          hasMoreResults = false;
        }
      }
    }

    const uniqueResults = Array.from(new Map(allResults.map(repo => [repo.id, repo])).values());

    const sortedResults = uniqueResults.sort((a, b) => b.stargazers_count - a.stargazers_count);

    return { items: sortedResults.slice(0, 50) }; // Return the top 50 results
  } catch (error) {
    console.error('Error fetching repos:', error);
    return { items: [] };
  }
}

const thumbsUp = `<svg class="repo-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="12" height="12"><path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.751.751 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Zm0 2.445L6.615 5.5a.75.75 0 0 1-.564.41l-3.097.45 2.24 2.184a.75.75 0 0 1 .216.664l-.528 3.084 2.769-1.456a.75.75 0 0 1 .698 0l2.77 1.456-.53-3.084a.75.75 0 0 1 .216-.664l2.24-2.183-3.096-.45a.75.75 0 0 1-.564-.41L8 2.694Z"></path></svg>`;
const forksGithub = `<svg class="repo-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="12" height="12"><path d="M5 5.372v.878c0 .414.336.75.75.75h4.5a.75.75 0 0 0 .75-.75v-.878a2.25 2.25 0 1 1 1.5 0v.878a2.25 2.25 0 0 1-2.25 2.25h-1.5v2.128a2.251 2.251 0 1 1-1.5 0V8.5h-1.5A2.25 2.25 0 0 1 3.5 6.25v-.878a2.25 2.25 0 1 1 1.5 0ZM5 3.25a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Zm6.75.75a.75.75 0 1 0 0-1.5.75.75 0 0 0 0 1.5Zm-3 8.75a.75.75 0 1 0-1.5 0 .75.75 0 0 0 1.5 0Z"></path></svg>`;


function renderRepos(data) {
  if (!data || !Array.isArray(data.items)) {
    document.getElementById('tab-content').innerHTML = '<div class="error-message">No repositories available</div>';
    return;
  }
  const content = data.items.map(repo => `
        <div class="script-post">
            <div class="script-header">
                <span class="script-title">
                    <a href="${repo.html_url}" target="_blank" rel="noopener noreferrer">${repo.name}</a>
                    ${repo.language ? `<span class="script-description">${repo.language}</span>` : ''}
                    <span class="script-description">•</span>
                    <span class="script-description">Updated ${new Date(repo.updated_at).toLocaleDateString()}</span>
                    <span class="script-description">${repo.description || ''}</span>
                </span>
                ${repo.topics && repo.topics.length > 0 ? `
                    <span class="script-tags">
                        ${repo.topics.slice(0, 2).map(topic =>
      `<span class="script-tag">${topic}</span>`
    ).join('')}
                    </span>
                ` : ''}
                <span class="script-stats">
                    <span class="script-stat">${thumbsUp} ${repo.stargazers_count?.toLocaleString() || '0'}</span>
                    <span class="script-stat">${forksGithub} ${repo.forks_count?.toLocaleString() || '0'}</span>
                </span>
            </div>
        </div>
    `).join('');
  document.getElementById('tab-content').innerHTML = content || '<div class="error-message">No repositories found</div>';
}

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
  socket.on('network-update', (data) => renderNetworkPanel(data));
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

document.addEventListener('DOMContentLoaded', () => {
  initializeTheme();
  initializeSocket();
  switchTab('repos');
  refreshCommands();
});