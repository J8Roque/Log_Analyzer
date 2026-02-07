// Log Analyzer - Core Engine
class LogAnalyzer {
    constructor() {
        this.logs = [];
        this.threats = [];
        this.analysisResults = {};
        this.charts = {};
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadSampleLogs();
        this.initCharts();
    }
    
    setupEventListeners() {
        // File upload
        const dropArea = document.getElementById('drop-area');
        const fileInput = document.getElementById('file-input');
        
        dropArea.addEventListener('click', () => fileInput.click());
        dropArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropArea.style.borderColor = '#60a5fa';
            dropArea.style.background = 'rgba(96, 165, 250, 0.1)';
        });
        
        dropArea.addEventListener('dragleave', () => {
            dropArea.style.borderColor = '#475569';
            dropArea.style.background = 'rgba(30, 41, 59, 0.5)';
        });
        
        dropArea.addEventListener('drop', (e) => {
            e.preventDefault();
            dropArea.style.borderColor = '#475569';
            dropArea.style.background = 'rgba(30, 41, 59, 0.5)';
            
            const files = e.dataTransfer.files;
            this.processFiles(files);
        });
        
        fileInput.addEventListener('change', (e) => {
            this.processFiles(e.target.files);
        });
        
        // Sample log buttons
        document.querySelectorAll('.sample-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const logType = btn.dataset.log;
                this.loadSampleLog(logType);
            });
        });
        
        // Analyze button
        document.getElementById('analyze-btn').addEventListener('click', () => {
            this.analyzeLogs();
        });
        
        // Export button
        document.getElementById('export-btn').addEventListener('click', () => {
            this.exportReport();
        });
        
        // Clear button
        document.getElementById('clear-btn').addEventListener('click', () => {
            this.clearLogs();
        });
        
        // Search
        document.getElementById('log-search').addEventListener('input', (e) => {
            this.filterLogs(e.target.value);
        });
        
        // View controls
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.filterByView(btn.dataset.view);
            });
        });
    }
    
    async processFiles(files) {
        if (!files.length) return;
        
        this.showLoading(true);
        
        for (let file of files) {
            if (file.type === 'text/plain' || file.name.endsWith('.log')) {
                const content = await file.text();
                this.parseLogFile(content, file.name);
            }
        }
        
        this.showLoading(false);
        this.updateStats();
        this.showToast(`Processed ${files.length} file(s)`, 'success');
    }
    
    parseLogFile(content, filename) {
        const lines = content.split('\n');
        let logType = this.detectLogType(filename, content);
        
        lines.forEach((line, index) => {
            if (line.trim()) {
                const logEntry = this.parseLogLine(line, logType, filename, index + 1);
                if (logEntry) {
                    this.logs.push(logEntry);
                }
            }
        });
        
        this.updateLogViewer();
    }
    
    detectLogType(filename, content) {
        // Detect log type based on filename and content
        if (filename.includes('auth') || content.includes('Failed password') || content.includes('Accepted password')) {
            return 'auth';
        } else if (filename.includes('apache') || filename.includes('access') || content.includes('HTTP/')) {
            return 'apache';
        } else if (filename.includes('firewall') || content.includes('DROP') || content.includes('ACCEPT')) {
            return 'firewall';
        } else if (filename.includes('syslog') || content.includes('kernel:')) {
            return 'system';
        }
        return 'generic';
    }
    
    parseLogLine(line, type, filename, lineNumber) {
        const timestamp = this.extractTimestamp(line);
        const ip = this.extractIP(line);
        
        let severity = 'info';
        let category = 'generic';
        
        // Determine severity based on content
        if (line.includes('error') || line.includes('Error') || line.includes('ERROR')) {
            severity = 'error';
        } else if (line.includes('warning') || line.includes('Warning') || line.includes('WARN')) {
            severity = 'warning';
        } else if (line.includes('fail') || line.includes('Fail') || line.includes('FAIL')) {
            severity = 'error';
        }
        
        // Parse based on log type
        switch(type) {
            case 'auth':
                category = 'authentication';
                if (line.includes('Failed password')) {
                    severity = 'warning';
                }
                if (line.includes('Invalid user') || line.includes('authentication failure')) {
                    severity = 'error';
                }
                break;
                
            case 'apache':
                category = 'web';
                if (line.includes(' 404 ') || line.includes(' 403 ') || line.includes(' 500 ')) {
                    severity = 'warning';
                }
                if (line.includes(' 404 ')) severity = 'low';
                if (line.includes(' 403 ')) severity = 'medium';
                if (line.includes(' 500 ')) severity = 'high';
                break;
                
            case 'firewall':
                category = 'firewall';
                if (line.includes('DROP')) {
                    severity = 'warning';
                }
                if (line.includes('IN=') && line.includes('OUT=')) {
                    // iptables log
                }
                break;
                
            case 'system':
                category = 'system';
                if (line.includes('kernel:') && line.includes('error')) {
                    severity = 'error';
                }
                break;
        }
        
        return {
            id: Date.now() + Math.random(),
            raw: line,
            timestamp: timestamp || new Date().toISOString(),
            ip: ip,
            severity: severity,
            category: category,
            source: filename,
            line: lineNumber,
            analyzed: false
        };
    }
    
    extractTimestamp(line) {
        // Try to extract timestamp from common formats
        const timestampPatterns = [
            /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/, // ISO
            /(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2})/, // Apache
            /(\w{3} \d{2} \d{2}:\d{2}:\d{2})/, // Syslog
            /(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})/, // Combined log
        ];
        
        for (let pattern of timestampPatterns) {
            const match = line.match(pattern);
            if (match) return match[1];
        }
        
        return null;
    }
    
    extractIP(line) {
        // Extract IP addresses from log line
        const ipPattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
        const match = line.match(ipPattern);
        return match ? match[1] : null;
    }
    
    loadSampleLogs() {
        // Predefined sample logs for demonstration
        this.sampleLogs = {
            apache: `192.168.1.105 - - [15/Feb/2024:14:30:22 +0000] "GET /admin HTTP/1.1" 403 512
192.168.1.105 - - [15/Feb/2024:14:30:23 +0000] "POST /login HTTP/1.1" 200 1234
192.168.1.106 - - [15/Feb/2024:14:30:24 +0000] "GET /wp-admin HTTP/1.1" 404 291
203.0.113.45 - - [15/Feb/2024:14:30:25 +0000] "GET /api/users HTTP/1.1" 200 2345
192.168.1.105 - - [15/Feb/2024:14:30:26 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 512
198.51.100.23 - - [15/Feb/2024:14:30:27 +0000] "POST /login HTTP/1.1" 200 1234
192.168.1.105 - - [15/Feb/2024:14:30:28 +0000] "GET /?param=<script>alert(1)</script> HTTP/1.1" 403 512`,

            auth: `Feb 15 14:30:22 server sshd[1234]: Failed password for invalid user admin from 192.168.1.105 port 22
Feb 15 14:30:23 server sshd[1234]: Failed password for invalid user admin from 192.168.1.105 port 22
Feb 15 14:30:24 server sshd[1234]: Failed password for invalid user admin from 192.168.1.105 port 22
Feb 15 14:30:25 server sshd[1234]: Accepted password for user1 from 10.0.0.5 port 22
Feb 15 14:30:26 server sshd[1234]: Invalid user test from 203.0.113.45
Feb 15 14:30:27 server sshd[1234]: Failed password for root from 192.168.1.106 port 22
Feb 15 14:30:28 server sshd[1234]: Accepted publickey for admin from 192.168.1.100 port 22`,

            firewall: `Feb 15 14:30:22 firewall kernel: DROP IN=eth0 OUT= MAC= SRC=203.0.113.45 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0
Feb 15 14:30:23 firewall kernel: ACCEPT IN=eth0 OUT= MAC= SRC=10.0.0.5 DST=192.168.1.100 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=12345 DPT=443 WINDOW=29200 RES=0x00 SYN URGP=0
Feb 15 14:30:24 firewall kernel: DROP IN=eth0 OUT= MAC= SRC=198.51.100.23 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=12345 DPT=3389 WINDOW=29200 RES=0x00 SYN URGP=0
Feb 15 14:30:25 firewall kernel: DROP IN=eth0 OUT= MAC= SRC=192.168.1.105 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=54321 DPT=445 WINDOW=29200 RES=0x00 SYN URGP=0`,

            system: `Feb 15 14:30:22 server kernel: CPU0: Temperature above threshold
Feb 15 14:30:23 server systemd[1]: Started Daily apt upgrade and clean activities.
Feb 15 14:30:24 server kernel: usb 1-1: new high-speed USB device number 2 using xhci_hcd
Feb 15 14:30:25 server systemd[1]: Starting Docker Application Container Engine...
Feb 15 14:30:26 server kernel: ata1: SATA link up 6.0 Gbps (SStatus 133 SControl 300)
Feb 15 14:30:27 server systemd[1]: Started Docker Application Container Engine.
Feb 15 14:30:28 server kernel: IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready`
        };
    }
    
    loadSampleLog(logType) {
        if (!this.sampleLogs[logType]) return;
        
        this.parseLogFile(this.sampleLogs[logType], `${logType}.log`);
        this.showToast(`Loaded sample ${logType} logs`, 'info');
    }
    
    analyzeLogs() {
        if (this.logs.length === 0) {
            this.showToast('No logs to analyze', 'warning');
            return;
        }
        
        this.showLoading(true);
        
        // Reset threats
        this.threats = [];
        
        // Analyze each log for threats
        this.logs.forEach(log => {
            const threats = this.detectThreats(log);
            threats.forEach(threat => this.threats.push(threat));
            log.analyzed = true;
        });
        
        // Perform correlation analysis
        this.correlateThreats();
        
        // Update UI
        this.updateStats();
        this.updateThreatsList();
        this.updateCharts();
        this.updateLogViewer();
        
        this.showLoading(false);
        
        const threatCount = this.threats.length;
        if (threatCount > 0) {
            this.showToast(`Analysis complete: Found ${threatCount} potential threats`, 
                          threatCount > 5 ? 'error' : 'warning');
        } else {
            this.showToast('Analysis complete: No threats found', 'success');
        }
    }
    
    detectThreats(log) {
        const threats = [];
        
        // Brute force detection
        if (log.category === 'authentication' && log.raw.includes('Failed password')) {
            // Count failed attempts from same IP
            const failedAttempts = this.logs.filter(l => 
                l.ip === log.ip && 
                l.category === 'authentication' && 
                l.raw.includes('Failed password')
            ).length;
            
            if (failedAttempts > 3) {
                threats.push({
                    id: `brute-${log.ip}-${Date.now()}`,
                    type: 'brute_force',
                    severity: failedAttempts > 10 ? 'critical' : 'high',
                    title: 'Potential Brute Force Attack',
                    description: `${failedAttempts} failed login attempts from ${log.ip}`,
                    ip: log.ip,
                    count: failedAttempts,
                    timestamp: log.timestamp,
                    logEntry: log
                });
            }
        }
        
        // Directory traversal detection
        if (log.category === 'web' && log.raw.includes('/../')) {
            threats.push({
                id: `traversal-${Date.now()}`,
                type: 'directory_traversal',
                severity: 'high',
                title: 'Directory Traversal Attempt',
                description: `Path traversal attempt detected from ${log.ip || 'unknown IP'}`,
                ip: log.ip,
                timestamp: log.timestamp,
                logEntry: log
            });
        }
        
        // XSS detection
        if (log.category === 'web' && (
            log.raw.includes('<script>') || 
            log.raw.includes('alert(') ||
            log.raw.includes('onerror=') ||
            log.raw.includes('javascript:')
        )) {
            threats.push({
                id: `xss-${Date.now()}`,
                type: 'xss',
                severity: 'high',
                title: 'Cross-Site Scripting Attempt',
                description: `XSS attempt detected in request from ${log.ip || 'unknown IP'}`,
                ip: log.ip,
                timestamp: log.timestamp,
                logEntry: log
            });
        }
        
        // Port scanning detection (firewall logs)
        if (log.category === 'firewall' && log.raw.includes('DROP')) {
            const droppedFromIP = this.extractIP(log.raw);
            if (droppedFromIP) {
                const dropCount = this.logs.filter(l => 
                    l.ip === droppedFromIP && 
                    l.category === 'firewall' && 
                    l.raw.includes('DROP')
                ).length;
                
                if (dropCount > 5) {
                    threats.push({
                        id: `portscan-${droppedFromIP}-${Date.now()}`,
                        type: 'port_scan',
                        severity: dropCount > 20 ? 'critical' : 'medium',
                        title: 'Port Scanning Activity',
                        description: `${dropCount} blocked connection attempts from ${droppedFromIP}`,
                        ip: droppedFromIP,
                        count: dropCount,
                        timestamp: log.timestamp,
                        logEntry: log
                    });
                }
            }
        }
        
        // SQL injection detection (simplified)
        if (log.category === 'web' && (
            log.raw.toLowerCase().includes('union select') ||
            log.raw.includes('drop table') ||
            log.raw.includes('or 1=1') ||
            log.raw.includes('sleep(')
        )) {
            threats.push({
                id: `sqli-${Date.now()}`,
                type: 'sql_injection',
                severity: 'critical',
                title: 'SQL Injection Attempt',
                description: `SQL injection pattern detected from ${log.ip || 'unknown IP'}`,
                ip: log.ip,
                timestamp: log.timestamp,
                logEntry: log
            });
        }
        
        // Unauthorized access attempts
        if (log.category === 'web' && log.raw.includes(' 403 ')) {
            threats.push({
                id: `unauth-${Date.now()}`,
                type: 'unauthorized_access',
                severity: 'medium',
                title: 'Unauthorized Access Attempt',
                description: `403 Forbidden response for ${log.ip || 'unknown IP'}`,
                ip: log.ip,
                timestamp: log.timestamp,
                logEntry: log
            });
        }
        
        return threats;
    }
    
    correlateThreats() {
        // Group threats by IP
        const threatsByIP = {};
        this.threats.forEach(threat => {
            if (threat.ip) {
                if (!threatsByIP[threat.ip]) {
                    threatsByIP[threat.ip] = [];
                }
                threatsByIP[threat.ip].push(threat);
            }
        });
        
        // Find IPs with multiple threat types (more suspicious)
        Object.entries(threatsByIP).forEach(([ip, threats]) => {
            const uniqueTypes = [...new Set(threats.map(t => t.type))];
            
            if (uniqueTypes.length > 1) {
                // Add a correlation threat
                this.threats.push({
                    id: `correlated-${ip}-${Date.now()}`,
                    type: 'correlated_attack',
                    severity: 'critical',
                    title: 'Correlated Attack Pattern',
                    description: `${ip} involved in ${uniqueTypes.length} different attack types: ${uniqueTypes.join(', ')}`,
                    ip: ip,
                    threatTypes: uniqueTypes,
                    timestamp: new Date().toISOString(),
                    isCorrelated: true
                });
            }
        });
        
        // Remove duplicates (keep highest severity)
        const uniqueThreats = [];
        const threatKeys = new Set();
        
        this.threats.forEach(threat => {
            const key = `${threat.type}-${threat.ip}`;
            if (!threatKeys.has(key)) {
                threatKeys.add(key);
                uniqueThreats.push(threat);
            }
        });
        
        this.threats = uniqueThreats;
    }
    
    updateStats() {
        // Update statistics
        document.getElementById('total-logs').textContent = this.logs.length;
        document.getElementById('threat-count').textContent = this.threats.length;
        
        // Count errors
        const errorCount = this.logs.filter(log => log.severity === 'error').length;
        document.getElementById('error-count').textContent = errorCount;
        
        // Count unique IPs
        const uniqueIPs = new Set(this.logs.map(log => log.ip).filter(ip => ip));
        document.getElementById('unique-ips').textContent = uniqueIPs.size;
    }
    
    updateThreatsList() {
        const container = document.getElementById('threats-list');
        if (!container) return;
        
        container.innerHTML = '';
        
        // Sort threats by severity (critical first)
        const sortedThreats = [...this.threats].sort((a, b) => {
            const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
            return severityOrder[a.severity] - severityOrder[b.severity];
        });
        
        sortedThreats.forEach(threat => {
            const item = document.createElement('div');
            item.className = `threat-item ${threat.severity}`;
            
            let details = threat.description;
            if (threat.count) {
                details += ` (${threat.count} attempts)`;
            }
            
            item.innerHTML = `
                <div class="threat-header">
                    <div class="threat-title">
                        <i class="fas fa-${this.getThreatIcon(threat.type)}"></i>
                        ${threat.title}
                    </div>
                    <span class="threat-severity">${threat.severity.toUpperCase()}</span>
                </div>
                <div class="threat-details">${details}</div>
                <div class="threat-meta">
                    ${threat.ip ? `<span><i class="fas fa-network-wired"></i> ${threat.ip}</span>` : ''}
                    <span><i class="fas fa-clock"></i> ${this.formatTime(threat.timestamp)}</span>
                    <span><i class="fas fa-bug"></i> ${threat.type.replace('_', ' ')}</span>
                </div>
            `;
            
            container.appendChild(item);
        });
        
        if (sortedThreats.length === 0) {
            container.innerHTML = `
                <div class="no-threats">
                    <i class="fas fa-shield-check"></i>
                    <h3>No Threats Detected</h3>
                    <p>All logs appear to be normal</p>
                </div>
            `;
        }
    }
    
    updateLogViewer() {
        const container = document.getElementById('log-viewer');
        if (!container) return;
        
        container.innerHTML = '';
        
        this.logs.forEach(log => {
            const entry = document.createElement('div');
            entry.className = `log-entry ${log.severity}`;
            
            const time = this.formatTime(log.timestamp);
            const source = log.source ? `<span class="log-source">${log.source}</span>` : '';
            const ip = log.ip ? `<span class="log-ip">${log.ip}</span>` : '';
            
            entry.innerHTML = `
                <div class="log-line">
                    <span class="log-timestamp">[${time}]</span>
                    ${source}
                    ${ip}
                    <span class="log-content">${this.escapeHTML(log.raw)}</span>
                </div>
            `;
            
            container.appendChild(entry);
        });
        
        if (this.logs.length === 0) {
            container.innerHTML = `
                <div class="no-logs">
                    <i class="fas fa-file-import"></i>
                    <h3>No Logs Loaded</h3>
                    <p>Upload log files or load sample logs to begin analysis</p>
                </div>
            `;
        }
    }
    
    filterLogs(searchTerm) {
        if (!searchTerm) {
            this.updateLogViewer();
            return;
        }
        
        const container = document.getElementById('log-viewer');
        if (!container) return;
        
        container.innerHTML = '';
        
        const filtered = this.logs.filter(log => 
            log.raw.toLowerCase().includes(searchTerm.toLowerCase()) ||
            (log.ip && log.ip.includes(searchTerm)) ||
            log.severity.toLowerCase().includes(searchTerm.toLowerCase())
        );
        
        filtered.forEach(log => {
            const entry = document.createElement('div');
            entry.className = `log-entry ${log.severity}`;
            
            const time = this.formatTime(log.timestamp);
            const ip = log.ip ? `<span class="log-ip">${log.ip}</span>` : '';
            
            // Highlight search term
            let highlighted = this.escapeHTML(log.raw);
            const regex = new RegExp(`(${searchTerm})`, 'gi');
            highlighted = highlighted.replace(regex, '<mark>$1</mark>');
            
            entry.innerHTML = `
                <div class="log-line">
                    <span class="log-timestamp">[${time}]</span>
                    ${ip}
                    <span class="log-content">${highlighted}</span>
                </div>
            `;
            
            container.appendChild(entry);
        });
        
        if (filtered.length === 0) {
            container.innerHTML = `
                <div class="no-results">
                    <i class="fas fa-search"></i>
                    <h3>No Results Found</h3>
                    <p>No logs match "${searchTerm}"</p>
                </div>
            `;
        }
    }
    
    filterByView(view) {
        const container = document.getElementById('log-viewer');
        if (!container) return;
        
        container.innerHTML = '';
        
        let filteredLogs = [];
        
        switch(view) {
            case 'errors':
                filteredLogs = this.logs.filter(log => log.severity === 'error');
                break;
            case 'threats':
                // Show logs that generated threats
                const threatLogIds = new Set(this.threats.map(t => t.logEntry?.id));
                filteredLogs = this.logs.filter(log => threatLogIds.has(log.id));
                break;
            default:
                filteredLogs = this.logs;
        }
        
        filteredLogs.forEach(log => {
            const entry = document.createElement('div');
            entry.className = `log-entry ${log.severity}`;
            
            const time = this.formatTime(log.timestamp);
            const ip = log.ip ? `<span class="log-ip">${log.ip}</span>` : '';
            
            entry.innerHTML = `
                <div class="log-line">
                    <span class="log-timestamp">[${time}]</span>
                    ${ip}
                    <span class="log-content">${this.escapeHTML(log.raw)}</span>
                </div>
            `;
            
            container.appendChild(entry);
        });
        
        if (filteredLogs.length === 0) {
            container.innerHTML = `
                <div class="no-logs">
                    <i class="fas fa-filter"></i>
                    <h3>No Logs Match Filter</h3>
                    <p>Try changing filter settings</p>
                </div>
            `;
        }
    }
    
    initCharts() {
        // Initialize Chart.js instances
        const severityCtx = document.getElementById('severity-chart').getContext('2d');
        const ipCtx = document.getElementById('ip-chart').getContext('2d');
        const timelineCtx = document.getElementById('timeline-chart').getContext('2d');
        const attackCtx = document.getElementById('attack-chart').getContext('2d');
        
        this.charts = {
            severity: new Chart(severityCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: [
                            '#ef4444',
                            '#f97316',
                            '#eab308',
                            '#22c55e',
                            '#60a5fa'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#cbd5e1' }
                        }
                    }
                }
            }),
            
            ip: new Chart(ipCtx, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Log Count',
                        data: [],
                        backgroundColor: '#3b82f6'
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { display: false },
                        title: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#94a3b8' },
                            grid: { color: '#334155' }
                        },
                        x: {
                            ticks: { color: '#94a3b8' },
                            grid: { color: '#334155' }
                        }
                    }
                }
            }),
            
            timeline: new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Log Activity',
                        data: [],
                        borderColor: '#60a5fa',
                        backgroundColor: 'rgba(96, 165, 250, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { labels: { color: '#cbd5e1' } }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#94a3b8' },
                            grid: { color: '#334155' }
                        },
                        x: {
                            ticks: { color: '#94a3b8' },
                            grid: { color: '#334155' }
                        }
                    }
                }
            }),
            
            attack: new Chart(attackCtx, {
                type: 'polarArea',
                data: {
                    labels: ['Brute Force', 'XSS', 'SQLi', 'Port Scan', 'Traversal'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: [
                            '#ef4444',
                            '#f97316',
                            '#eab308',
                            '#22c55e',
                            '#8b5cf6'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#cbd5e1' }
                        }
                    }
                }
            })
        };
    }
    
    updateCharts() {
        if (!this.charts.severity) return;
        
        // Severity chart
        const severityCounts = {
            critical: this.threats.filter(t => t.severity === 'critical').length,
            high: this.threats.filter(t => t.severity === 'high').length,
            medium: this.threats.filter(t => t.severity === 'medium').length,
            low: this.threats.filter(t => t.severity === 'low').length,
            info: this.logs.filter(l => l.severity === 'info').length
        };
        
        this.charts.severity.data.datasets[0].data = [
            severityCounts.critical,
            severityCounts.high,
            severityCounts.medium,
            severityCounts.low,
            severityCounts.info
        ];
        this.charts.severity.update();
        
        // Top IPs chart
        const ipCounts = {};
        this.logs.forEach(log => {
            if (log.ip) {
                ipCounts[log.ip] = (ipCounts[log.ip] || 0) + 1;
            }
        });
        
        const topIPs = Object.entries(ipCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        
        this.charts.ip.data.labels = topIPs.map(([ip]) => ip);
        this.charts.ip.data.datasets[0].data = topIPs.map(([, count]) => count);
        this.charts.ip.update();
        
        // Timeline chart (simplified)
        const hourCounts = new Array(24).fill(0);
        this.logs.forEach(log => {
            if (log.timestamp) {
                const hour = new Date(log.timestamp).getHours();
                hourCounts[hour]++;
            }
        });
        
        this.charts.timeline.data.labels = Array.from({length: 24}, (_, i) => `${i}:00`);
        this.charts.timeline.data.datasets[0].data = hourCounts;
        this.charts.timeline.update();
        
        // Attack types chart
        const attackCounts = {
            brute_force: this.threats.filter(t => t.type === 'brute_force').length,
            xss: this.threats.filter(t => t.type === 'xss').length,
            sql_injection: this.threats.filter(t => t.type === 'sql_injection').length,
            port_scan: this.threats.filter(t => t.type === 'port_scan').length,
            directory_traversal: this.threats.filter(t => t.type === 'directory_traversal').length
        };
        
        this.charts.attack.data.datasets[0].data = [
            attackCounts.brute_force,
            attackCounts.xss,
            attackCounts.sql_injection,
            attackCounts.port_scan,
            attackCounts.directory_traversal
        ];
        this.charts.attack.update();
    }
    
    exportReport() {
        if (this.logs.length === 0) {
            this.showToast('No logs to export', 'warning');
            return;
        }
        
        const report = {
            generated: new Date().toISOString(),
            summary: {
                totalLogs: this.logs.length,
                threatsFound: this.threats.length,
                uniqueIPs: new Set(this.logs.map(log => log.ip).filter(ip => ip)).size,
                timeRange: {
                    start: this.logs.reduce((min, log) => log.timestamp < min ? log.timestamp : min, this.logs[0]?.timestamp),
                    end: this.logs.reduce((max, log) => log.timestamp > max ? log.timestamp : max, this.logs[0]?.timestamp)
                }
            },
            threats: this.threats.map(t => ({
                type: t.type,
                severity: t.severity,
                description: t.description,
                ip: t.ip,
                timestamp: t.timestamp
            })),
            analysis: {
                severityBreakdown: {
                    critical: this.threats.filter(t => t.severity === 'critical').length,
                    high: this.threats.filter(t => t.severity === 'high').length,
                    medium: this.threats.filter(t => t.severity === 'medium').length,
                    low: this.threats.filter(t => t.severity === 'low').length
                },
                topOffendingIPs: Object.entries(
                    this.logs.reduce((acc, log) => {
                        if (log.ip) acc[log.ip] = (acc[log.ip] || 0) + 1;
                        return acc;
                    }, {})
                ).sort((a, b) => b[1] - a[1]).slice(0, 5),
                recommendations: this.generateRecommendations()
            }
        };
        
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-report-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.showToast('Report exported successfully', 'success');
    }
    
    generateRecommendations() {
        const recommendations = [];
        
        if (this.threats.some(t => t.type === 'brute_force')) {
            recommendations.push({
                priority: 'high',
                action: 'Implement rate limiting on authentication endpoints',
                reason: 'Multiple failed login attempts detected'
            });
        }
        
        if (this.threats.some(t => t.type === 'sql_injection' || t.type === 'xss')) {
            recommendations.push({
                priority: 'critical',
                action: 'Review and sanitize all user input handling',
                reason: 'Injection attacks detected'
            });
        }
        
        if (this.threats.some(t => t.type === 'port_scan')) {
            recommendations.push({
                priority: 'medium',
                action: 'Consider implementing intrusion detection system (IDS)',
                reason: 'Port scanning activity detected'
            });
        }
        
        const errorCount = this.logs.filter(l => l.severity === 'error').length;
        if (errorCount > 10) {
            recommendations.push({
                priority: 'medium',
                action: 'Investigate recurring system errors',
                reason: `High error count detected (${errorCount} errors)`
            });
        }
        
        if (recommendations.length === 0) {
            recommendations.push({
                priority: 'low',
                action: 'Continue regular security monitoring',
                reason: 'No critical issues detected'
            });
        }
        
        return recommendations;
    }
    
    clearLogs() {
        if (this.logs.length === 0) return;
        
        if (confirm('Are you sure you want to clear all logs?')) {
            this.logs = [];
            this.threats = [];
            this.updateStats();
            this.updateThreatsList();
            this.updateLogViewer();
            this.updateCharts();
            this.showToast('All logs cleared', 'info');
        }
    }
    
    // Utility methods
    getThreatIcon(type) {
        const icons = {
            brute_force: 'key',
            xss: 'code',
            sql_injection: 'database',
            port_scan: 'search',
            directory_traversal: 'folder-open',
            unauthorized_access: 'lock',
            correlated_attack: 'link'
        };
        return icons[type] || 'exclamation-triangle';
    }
    
    formatTime(timestamp) {
        if (!timestamp) return 'Unknown';
        
        try {
            const date = new Date(timestamp);
            if (isNaN(date.getTime())) {
                // Try parsing other formats
                return timestamp.length > 20 ? timestamp.substring(0, 20) + '...' : timestamp;
            }
            return date.toLocaleTimeString();
        } catch {
            return timestamp;
        }
    }
    
    escapeHTML(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    showToast(message, type = 'info') {
        // Remove existing toasts
        const existing = document.querySelectorAll('.toast');
        existing.forEach(toast => toast.remove());
        
        // Create toast
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = message;
        
        const colors = {
            success: '#22c55e',
            error: '#ef4444',
            warning: '#f97316',
            info: '#3b82f6'
        };
        
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${colors[type] || colors.info};
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            z-index: 9999;
            font-weight: 500;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            animation: slideIn 0.3s ease;
        `;
        
        // Add animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes slideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(style);
        
        document.body.appendChild(toast);
        
        // Remove after 3 seconds
        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
    
    showLoading(show) {
        let loader = document.getElementById('analyzer-loader');
        
        if (show && !loader) {
            loader = document.createElement('div');
            loader.id = 'analyzer-loader';
            loader.innerHTML = `
                <div class="loader-content">
                    <div class="loader-spinner"></div>
                    <p>Analyzing logs...</p>
                </div>
            `;
            loader.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(15, 23, 42, 0.95);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 9998;
            `;
            
            const style = document.createElement('style');
            style.textContent = `
                .loader-spinner {
                    width: 60px;
                    height: 60px;
                    border: 4px solid rgba(96, 165, 250, 0.3);
                    border-top: 4px solid #60a5fa;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                    margin-bottom: 20px;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            `;
            document.head.appendChild(style);
            
            document.body.appendChild(loader);
        } else if (!show && loader) {
            loader.remove();
        }
    }
}

// Initialize the analyzer when page loads
document.addEventListener('DOMContentLoaded', () => {
    window.logAnalyzer = new LogAnalyzer();
});
