// Log Analyzer - Enhanced Core Engine
class LogAnalyzer {
    constructor() {
        this.logs = [];
        this.threats = [];
        this.analysisResults = {};
        this.charts = {};
        this.isAnalyzing = false;
        
        // Default sample data
        this.sampleData = {
            apache: {
                name: "Apache Access Logs",
                content: `192.168.1.105 - - [15/Feb/2024:14:30:22 +0000] "GET /admin HTTP/1.1" 403 512
192.168.1.105 - - [15/Feb/2024:14:30:23 +0000] "POST /login HTTP/1.1" 200 1234
192.168.1.106 - - [15/Feb/2024:14:30:24 +0000] "GET /wp-admin HTTP/1.1" 404 291
203.0.113.45 - - [15/Feb/2024:14:30:25 +0000] "GET /api/users HTTP/1.1" 200 2345
192.168.1.105 - - [15/Feb/2024:14:30:26 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 512
198.51.100.23 - - [15/Feb/2024:14:30:27 +0000] "POST /login HTTP/1.1" 200 1234
192.168.1.105 - - [15/Feb/2024:14:30:28 +0000] "GET /?param=<script>alert(1)</script> HTTP/1.1" 403 512
10.0.0.5 - - [15/Feb/2024:14:30:29 +0000] "GET /index.html HTTP/1.1" 200 1423`
            },
            auth: {
                name: "SSH Authentication Logs",
                content: `Feb 15 14:30:22 server sshd[1234]: Failed password for invalid user admin from 192.168.1.105 port 22
Feb 15 14:30:23 server sshd[1234]: Failed password for invalid user admin from 192.168.1.105 port 22
Feb 15 14:30:24 server sshd[1234]: Failed password for invalid user admin from 192.168.1.105 port 22
Feb 15 14:30:25 server sshd[1234]: Accepted password for user1 from 10.0.0.5 port 22
Feb 15 14:30:26 server sshd[1234]: Invalid user test from 203.0.113.45
Feb 15 14:30:27 server sshd[1234]: Failed password for root from 192.168.1.106 port 22
Feb 15 14:30:28 server sshd[1234]: Accepted publickey for admin from 192.168.1.100 port 22`
            },
            firewall: {
                name: "Firewall Logs",
                content: `Feb 15 14:30:22 firewall kernel: DROP IN=eth0 OUT= MAC= SRC=203.0.113.45 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0
Feb 15 14:30:23 firewall kernel: ACCEPT IN=eth0 OUT= MAC= SRC=10.0.0.5 DST=192.168.1.100 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=12345 DPT=443 WINDOW=29200 RES=0x00 SYN URGP=0
Feb 15 14:30:24 firewall kernel: DROP IN=eth0 OUT= MAC= SRC=198.51.100.23 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=12345 DPT=3389 WINDOW=29200 RES=0x00 SYN URGP=0
Feb 15 14:30:25 firewall kernel: DROP IN=eth0 OUT= MAC= SRC=192.168.1.105 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=54321 DPT=445 WINDOW=29200 RES=0x00 SYN URGP=0
Feb 15 14:30:26 firewall kernel: DROP IN=eth0 OUT= MAC= SRC=203.0.113.45 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=0 DF PROTO=TCP SPT=12345 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0`
            }
        };
        
        this.threatPatterns = {
            bruteForce: /Failed password|Invalid user|authentication failure/gi,
            xss: /<script>|alert\(|onerror=|javascript:|eval\(/gi,
            sqlInjection: /union select|drop table|or 1=1|sleep\(|benchmark\(|information_schema/gi,
            directoryTraversal: /\.\.\/|\.\.\\/gi,
            portScan: /DROP.*DPT=(\d+)/gi,
            commandInjection: /; ls|; cat|; rm|\|\s*\w+|\$\s*\(/gi
        };
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.initCharts();
        this.updateDashboardStats();
    }
    
    setupEventListeners() {
        // File upload handlers
        const dropArea = document.getElementById('drop-area');
        const fileInput = document.getElementById('file-input');
        
        if (dropArea && fileInput) {
            dropArea.addEventListener('click', () => fileInput.click());
            
            ['dragover', 'dragenter'].forEach(event => {
                dropArea.addEventListener(event, (e) => {
                    e.preventDefault();
                    dropArea.style.borderColor = '#60a5fa';
                    dropArea.style.background = 'rgba(96, 165, 250, 0.1)';
                });
            });
            
            ['dragleave', 'dragend'].forEach(event => {
                dropArea.addEventListener(event, () => {
                    dropArea.style.borderColor = '#475569';
                    dropArea.style.background = 'rgba(30, 41, 59, 0.5)';
                });
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
        }
        
        // Sample log buttons
        document.querySelectorAll('.sample-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const logType = btn.dataset.log;
                this.loadSampleLog(logType);
            });
        });
        
        // Action buttons
        const analyzeBtn = document.getElementById('analyze-btn');
        const exportBtn = document.getElementById('export-btn');
        const clearBtn = document.getElementById('clear-btn');
        
        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', () => this.analyzeLogs());
        }
        
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportReport());
        }
        
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearLogs());
        }
        
        // Search functionality
        const searchInput = document.getElementById('log-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.filterLogs(e.target.value);
            });
        }
        
        // View controls
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.filterByView(btn.dataset.view);
            });
        });
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'a') {
                e.preventDefault();
                this.analyzeLogs();
            }
            if (e.ctrlKey && e.key === 'e') {
                e.preventDefault();
                this.exportReport();
            }
            if (e.key === 'Escape') {
                this.clearSearch();
            }
        });
    }
    
    async processFiles(files) {
        if (!files || files.length === 0) return;
        
        this.showLoading(true);
        
        const processPromises = Array.from(files).map(async (file) => {
            if (file.type === 'text/plain' || file.name.match(/\.(log|txt)$/i)) {
                try {
                    const content = await this.readFile(file);
                    return this.parseLogFile(content, file.name);
                } catch (error) {
                    console.error(`Error processing ${file.name}:`, error);
                    this.showToast(`Error processing ${file.name}`, 'error');
                    return null;
                }
            } else {
                this.showToast(`Skipped ${file.name}: Unsupported file type`, 'warning');
                return null;
            }
        });
        
        const results = await Promise.all(processPromises);
        const successful = results.filter(r => r !== null).length;
        
        this.showLoading(false);
        
        if (successful > 0) {
            this.updateDashboardStats();
            this.showToast(`Successfully processed ${successful} file(s)`, 'success');
        }
    }
    
    readFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
    }
    
    parseLogFile(content, filename) {
        const lines = content.split('\n');
        const logType = this.detectLogType(filename, content);
        let parsedCount = 0;
        
        lines.forEach((line, index) => {
            if (line.trim()) {
                const logEntry = this.parseLogLine(line, logType, filename, index + 1);
                if (logEntry) {
                    this.logs.push(logEntry);
                    parsedCount++;
                }
            }
        });
        
        this.updateLogViewer();
        return parsedCount;
    }
    
    detectLogType(filename, content) {
        const checks = [
            { type: 'auth', patterns: [/auth|sshd|login|password/i, /Failed password|Accepted password|Invalid user/] },
            { type: 'apache', patterns: [/apache|access|nginx/i, /HTTP\/|"GET|"POST|"PUT|"DELETE/] },
            { type: 'firewall', patterns: [/firewall|iptables|ufw/i, /DROP|ACCEPT|REJECT|IN=|OUT=/] },
            { type: 'system', patterns: [/syslog|kernel|systemd/i, /kernel:|systemd\[|Started|Starting/] }
        ];
        
        for (const check of checks) {
            if (check.patterns.some(pattern => 
                pattern.test(filename) || pattern.test(content.substring(0, 500))
            )) {
                return check.type;
            }
        }
        
        return 'generic';
    }
    
    parseLogLine(line, type, source, lineNumber) {
        const timestamp = this.extractTimestamp(line);
        const ip = this.extractIP(line);
        const severity = this.determineSeverity(line, type);
        const category = this.determineCategory(type);
        
        return {
            id: `${source}-${lineNumber}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            raw: line,
            timestamp: timestamp || new Date().toISOString(),
            ip: ip,
            severity: severity,
            category: category,
            source: source,
            line: lineNumber,
            analyzed: false,
            tags: this.extractTags(line, type)
        };
    }
    
    extractTimestamp(line) {
        const patterns = [
            /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/,
            /\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}/,
            /\w{3} \d{2} \d{2}:\d{2}:\d{2}/,
            /\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}/
        ];
        
        for (const pattern of patterns) {
            const match = line.match(pattern);
            if (match) {
                try {
                    return new Date(match[0]).toISOString();
                } catch {
                    return match[0];
                }
            }
        }
        
        return null;
    }
    
    extractIP(line) {
        const ipv4Pattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
        const match = line.match(ipv4Pattern);
        return match ? match[0] : null;
    }
    
    determineSeverity(line, type) {
        const lowerLine = line.toLowerCase();
        
        // Check for critical patterns
        if (/(critical|emerg|fatal|panic)/i.test(line) || 
            /sql.*injection|command.*injection|shell.*exec/i.test(line)) {
            return 'critical';
        }
        
        // Check for error patterns
        if (/(error|err|fail|denied|reject|invalid|unauthorized)/i.test(line)) {
            return 'error';
        }
        
        // Check for warning patterns
        if (/(warn|alert|notice|suspicious|unusual)/i.test(line) || 
            /404|403|500/.test(line) ||
            /failed.*password|invalid.*user/.test(line)) {
            return 'warning';
        }
        
        // Type-specific severity
        if (type === 'auth' && /accepted.*password|successful.*login/.test(lowerLine)) {
            return 'info';
        }
        
        if (type === 'firewall' && /ACCEPT/.test(line)) {
            return 'info';
        }
        
        return 'info';
    }
    
    determineCategory(type) {
        const categories = {
            auth: 'authentication',
            apache: 'web',
            firewall: 'network',
            system: 'system',
            generic: 'general'
        };
        return categories[type] || 'general';
    }
    
    extractTags(line, type) {
        const tags = [];
        
        // Add log type tag
        tags.push(type);
        
        // Add protocol tags
        if (line.includes('HTTP/')) tags.push('http');
        if (line.includes('HTTPS')) tags.push('https');
        if (line.includes('SSH')) tags.push('ssh');
        if (line.includes('FTP')) tags.push('ftp');
        if (line.includes('DNS')) tags.push('dns');
        
        // Add method tags for web logs
        if (line.includes('"GET')) tags.push('get');
        if (line.includes('"POST')) tags.push('post');
        if (line.includes('"PUT')) tags.push('put');
        if (line.includes('"DELETE')) tags.push('delete');
        
        return tags;
    }
    
    loadSampleLog(logType) {
        if (!this.sampleData[logType]) {
            this.showToast(`No sample data for ${logType}`, 'warning');
            return;
        }
        
        this.showLoading(true);
        
        setTimeout(() => {
            this.parseLogFile(this.sampleData[logType].content, `${this.sampleData[logType].name}.log`);
            this.updateDashboardStats();
            this.showLoading(false);
            this.showToast(`Loaded ${this.sampleData[logType].name}`, 'success');
        }, 500);
    }
    
    analyzeLogs() {
        if (this.logs.length === 0) {
            this.showToast('No logs to analyze', 'warning');
            return;
        }
        
        if (this.isAnalyzing) {
            this.showToast('Analysis already in progress', 'warning');
            return;
        }
        
        this.isAnalyzing = true;
        this.showLoading(true);
        this.threats = [];
        
        // Use requestAnimationFrame for smoother UI updates
        const analyzeBatch = () => {
            const batchSize = 100;
            const totalBatches = Math.ceil(this.logs.length / batchSize);
            let currentBatch = 0;
            
            const processBatch = () => {
                const start = currentBatch * batchSize;
                const end = Math.min(start + batchSize, this.logs.length);
                const batch = this.logs.slice(start, end);
                
                batch.forEach(log => {
                    if (!log.analyzed) {
                        const threats = this.detectThreats(log);
                        threats.forEach(threat => this.threats.push(threat));
                        log.analyzed = true;
                    }
                });
                
                currentBatch++;
                
                // Update progress
                const progress = Math.round((currentBatch / totalBatches) * 100);
                this.updateProgress(progress);
                
                if (currentBatch < totalBatches) {
                    requestAnimationFrame(processBatch);
                } else {
                    // Analysis complete
                    this.correlateThreats();
                    this.updateDashboardStats();
                    this.updateThreatsList();
                    this.updateCharts();
                    this.updateLogViewer();
                    
                    this.isAnalyzing = false;
                    this.showLoading(false);
                    
                    const threatCount = this.threats.length;
                    if (threatCount > 0) {
                        this.showToast(`Analysis complete: Found ${threatCount} potential threats`, 
                                      threatCount > 10 ? 'error' : 'warning');
                    } else {
                        this.showToast('Analysis complete: No threats found', 'success');
                    }
                }
            };
            
            requestAnimationFrame(processBatch);
        };
        
        setTimeout(analyzeBatch, 100);
    }
    
    detectThreats(log) {
        const threats = [];
        
        // Brute Force Detection
        if (log.category === 'authentication') {
            const failedAttempts = this.logs.filter(l => 
                l.ip === log.ip && 
                l.category === 'authentication' &&
                l.severity === 'warning' &&
                l.raw.includes('Failed')
            ).length;
            
            if (failedAttempts >= 3) {
                threats.push({
                    id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                    type: 'brute_force',
                    severity: failedAttempts > 10 ? 'critical' : (failedAttempts > 5 ? 'high' : 'medium'),
                    title: 'Brute Force Attack',
                    description: `${failedAttempts} failed authentication attempts from ${log.ip}`,
                    ip: log.ip,
                    count: failedAttempts,
                    timestamp: log.timestamp,
                    logEntry: log,
                    confidence: Math.min(95, 70 + (failedAttempts * 2))
                });
            }
        }
        
        // XSS Detection
        if (log.category === 'web' && this.threatPatterns.xss.test(log.raw)) {
            threats.push({
                id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                type: 'xss',
                severity: 'high',
                title: 'Cross-Site Scripting (XSS) Attempt',
                description: `XSS attempt detected from ${log.ip || 'unknown IP'}`,
                ip: log.ip,
                timestamp: log.timestamp,
                logEntry: log,
                confidence: 85
            });
        }
        
        // SQL Injection Detection
        if (log.category === 'web' && this.threatPatterns.sqlInjection.test(log.raw)) {
            threats.push({
                id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                type: 'sql_injection',
                severity: 'critical',
                title: 'SQL Injection Attempt',
                description: `SQL injection pattern detected from ${log.ip || 'unknown IP'}`,
                ip: log.ip,
                timestamp: log.timestamp,
                logEntry: log,
                confidence: 90
            });
        }
        
        // Directory Traversal
        if (log.category === 'web' && this.threatPatterns.directoryTraversal.test(log.raw)) {
            threats.push({
                id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                type: 'directory_traversal',
                severity: 'high',
                title: 'Directory Traversal Attempt',
                description: `Path traversal attempt from ${log.ip || 'unknown IP'}`,
                ip: log.ip,
                timestamp: log.timestamp,
                logEntry: log,
                confidence: 80
            });
        }
        
        // Port Scanning Detection
        if (log.category === 'network' && log.raw.includes('DROP')) {
            const dropCount = this.logs.filter(l => 
                l.ip === log.ip && 
                l.category === 'network' && 
                l.raw.includes('DROP')
            ).length;
            
            if (dropCount > 5) {
                const portMatch = log.raw.match(/DPT=(\d+)/);
                const port = portMatch ? portMatch[1] : 'unknown';
                
                threats.push({
                    id: `threat-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                    type: 'port_scan',
                    severity: dropCount > 20 ? 'critical' : (dropCount > 10 ? 'high' : 'medium'),
                    title: 'Port Scanning Activity',
                    description: `${dropCount} blocked connection attempts from ${log.ip} (Port: ${port})`,
                    ip: log.ip,
                    count: dropCount,
                    timestamp: log.timestamp,
                    logEntry: log,
                    confidence: Math.min(95, 60 + (dropCount * 1.5))
                });
            }
        }
        
        return threats;
    }
    
    correlateThreats() {
        // Group threats by IP for correlation
        const threatsByIP = {};
        this.threats.forEach(threat => {
            if (threat.ip) {
                if (!threatsByIP[threat.ip]) {
                    threatsByIP[threat.ip] = [];
                }
                threatsByIP[threat.ip].push(threat);
            }
        });
        
        // Identify correlated attacks
        Object.entries(threatsByIP).forEach(([ip, ipThreats]) => {
            if (ipThreats.length > 1) {
                const uniqueTypes = [...new Set(ipThreats.map(t => t.type))];
                
                if (uniqueTypes.length > 1) {
                    this.threats.push({
                        id: `corr-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                        type: 'correlated_attack',
                        severity: 'critical',
                        title: 'Correlated Attack Campaign',
                        description: `${ip} involved in ${uniqueTypes.length} attack types: ${uniqueTypes.join(', ')}`,
                        ip: ip,
                        threatTypes: uniqueTypes,
                        count: ipThreats.length,
                        timestamp: new Date().toISOString(),
                        isCorrelated: true,
                        confidence: 95
                    });
                }
            }
        });
        
        // Remove duplicate threats (keep highest severity)
        const uniqueThreats = [];
        const seenKeys = new Set();
        
        this.threats.forEach(threat => {
            const key = `${threat.type}-${threat.ip}`;
            if (!seenKeys.has(key) || threat.severity === 'critical') {
                seenKeys.add(key);
                uniqueThreats.push(threat);
            }
        });
        
        this.threats = uniqueThreats.sort((a, b) => {
            const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
            return severityOrder[a.severity] - severityOrder[b.severity];
        });
    }
    
    updateDashboardStats() {
        // Update main statistics
        const totalLogs = document.getElementById('total-logs');
        const threatCount = document.getElementById('threat-count');
        const errorCount = document.getElementById('error-count');
        const uniqueIPs = document.getElementById('unique-ips');
        
        if (totalLogs) totalLogs.textContent = this.logs.length.toLocaleString();
        if (threatCount) threatCount.textContent = this.threats.length.toLocaleString();
        
        if (errorCount) {
            const errors = this.logs.filter(log => 
                ['error', 'critical', 'high'].includes(log.severity)
            ).length;
            errorCount.textContent = errors.toLocaleString();
        }
        
        if (uniqueIPs) {
            const ips = new Set(this.logs.map(log => log.ip).filter(ip => ip));
            uniqueIPs.textContent = ips.size.toLocaleString();
        }
        
        // Update severity breakdown
        this.updateSeverityBreakdown();
        
        // Update top IPs list
        this.updateTopIPsList();
        
        // Update attack type breakdown
        this.updateAttackTypeBreakdown();
    }
    
    updateSeverityBreakdown() {
        const severityContainer = document.querySelector('.severity-list');
        if (!severityContainer) return;
        
        const severityCounts = {
            critical: this.threats.filter(t => t.severity === 'critical').length,
            high: this.threats.filter(t => t.severity === 'high').length +
                 this.logs.filter(l => l.severity === 'error').length,
            medium: this.threats.filter(t => t.severity === 'medium').length +
                   this.logs.filter(l => l.severity === 'warning').length,
            low: this.threats.filter(t => t.severity === 'low').length,
            info: this.logs.filter(l => l.severity === 'info').length
        };
        
        const total = Object.values(severityCounts).reduce((a, b) => a + b, 0);
        
        severityContainer.innerHTML = '';
        
        Object.entries(severityCounts).forEach(([severity, count]) => {
            if (count > 0) {
                const percentage = total > 0 ? Math.round((count / total) * 100) : 0;
                const item = document.createElement('div');
                item.className = `severity-item severity-${severity}`;
                item.innerHTML = `
                    <div class="severity-label">
                        <span class="severity-dot"></span>
                        <span>${severity.charAt(0).toUpperCase() + severity.slice(1)}</span>
                    </div>
                    <div class="severity-stats">
                        <span class="severity-count">${count}</span>
                        <span class="severity-percent">${percentage}%</span>
                    </div>
                `;
                severityContainer.appendChild(item);
            }
        });
    }
    
    updateTopIPsList() {
        const ipContainer = document.querySelector('.ip-grid');
        if (!ipContainer) return;
        
        // Count occurrences by IP
        const ipCounts = {};
        this.logs.forEach(log => {
            if (log.ip) {
                ipCounts[log.ip] = (ipCounts[log.ip] || 0) + 1;
            }
        });
        
        // Get top 5 IPs
        const topIPs = Object.entries(ipCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        
        ipContainer.innerHTML = '';
        
        topIPs.forEach(([ip, count]) => {
            // Determine threat level for this IP
            const ipThreats = this.threats.filter(t => t.ip === ip);
            let threatLevel = 'low';
            if (ipThreats.some(t => t.severity === 'critical')) threatLevel = 'critical';
            else if (ipThreats.some(t => t.severity === 'high')) threatLevel = 'high';
            else if (ipThreats.some(t => t.severity === 'medium')) threatLevel = 'medium';
            
            const item = document.createElement('div');
            item.className = `ip-item ip-threat-${threatLevel}`;
            item.innerHTML = `
                <div class="ip-address">${ip}</div>
                <div class="ip-info">
                    <span class="ip-threat">${threatLevel} Threat</span>
                    <span class="ip-count">${count} events</span>
                </div>
                ${threatLevel !== 'low' ? '<i class="fas fa-exclamation-triangle ip-icon"></i>' : '<i class="fas fa-desktop ip-icon"></i>'}
            `;
            
            // Add click handler for IP details
            item.addEventListener('click', () => this.showIPDetails(ip));
            ipContainer.appendChild(item);
        });
    }
    
    updateAttackTypeBreakdown() {
        const attackContainer = document.querySelector('.attack-list');
        if (!attackContainer) return;
        
        const attackCounts = {
            brute_force: this.threats.filter(t => t.type === 'brute_force').length,
            xss: this.threats.filter(t => t.type === 'xss').length,
            sql_injection: this.threats.filter(t => t.type === 'sql_injection').length,
            port_scan: this.threats.filter(t => t.type === 'port_scan').length,
            directory_traversal: this.threats.filter(t => t.type === 'directory_traversal').length
        };
        
        const totalAttacks = Object.values(attackCounts).reduce((a, b) => a + b, 0);
        
        attackContainer.innerHTML = '';
        
        const attackTypes = [
            { key: 'brute_force', name: 'Bruteforce' },
            { key: 'port_scan', name: 'Port Scan' },
            { key: 'xss', name: 'XSS' },
            { key: 'sql_injection', name: 'SQLi' },
            { key: 'directory_traversal', name: 'Traversal' }
        ];
        
        attackTypes.forEach(({ key, name }) => {
            const count = attackCounts[key] || 0;
            const percentage = totalAttacks > 0 ? Math.round((count / totalAttacks) * 100) : 0;
            
            const item = document.createElement('div');
            item.className = `attack-item attack-${key}`;
            item.innerHTML = `
                <div class="attack-label">
                    <span class="attack-name">${name}</span>
                    <span class="attack-bar-container">
                        <span class="attack-bar" style="width: ${percentage}%"></span>
                    </span>
                </div>
                <span class="attack-percent">${percentage}%</span>
            `;
            attackContainer.appendChild(item);
        });
    }
    
    updateProgress(percentage) {
        let progressBar = document.getElementById('progress-bar');
        if (!progressBar) {
            progressBar = document.createElement('div');
            progressBar.id = 'progress-bar';
            progressBar.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 3px;
                background: #334155;
                z-index: 9999;
            `;
            const progressFill = document.createElement('div');
            progressFill.id = 'progress-fill';
            progressFill.style.cssText = `
                height: 100%;
                background: linear-gradient(90deg, #60a5fa, #8b5cf6);
                width: 0%;
                transition: width 0.3s ease;
            `;
            progressBar.appendChild(progressFill);
            document.body.appendChild(progressBar);
        }
        
        const progressFill = document.getElementById('progress-fill');
        if (progressFill) {
            progressFill.style.width = `${percentage}%`;
        }
        
        if (percentage >= 100) {
            setTimeout(() => {
                if (progressBar.parentNode) {
                    progressBar.parentNode.removeChild(progressBar);
                }
            }, 500);
        }
    }
    
    // ... (rest of the methods remain similar but updated with improvements)

    // Add new method for IP details
    showIPDetails(ip) {
        const ipLogs = this.logs.filter(log => log.ip === ip);
        const ipThreats = this.threats.filter(threat => threat.ip === ip);
        
        const details = `
            <div class="ip-details">
                <h3>IP: ${ip}</h3>
                <div class="details-grid">
                    <div class="detail-item">
                        <span class="detail-label">Total Logs</span>
                        <span class="detail-value">${ipLogs.length}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Threats</span>
                        <span class="detail-value">${ipThreats.length}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">First Seen</span>
                        <span class="detail-value">${this.formatTime(ipLogs[0]?.timestamp || 'Unknown')}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Last Seen</span>
                        <span class="detail-value">${this.formatTime(ipLogs[ipLogs.length - 1]?.timestamp || 'Unknown')}</span>
                    </div>
                </div>
                ${ipThreats.length > 0 ? `
                <div class="threat-list">
                    <h4>Detected Threats:</h4>
                    ${ipThreats.map(threat => `
                        <div class="threat-item">
                            <strong>${threat.title}</strong> - ${threat.description}
                        </div>
                    `).join('')}
                </div>
                ` : ''}
            </div>
        `;
        
        this.showModal('IP Details', details);
    }
    
    showModal(title, content) {
        // Remove existing modal
        const existingModal = document.querySelector('.modal-overlay');
        if (existingModal) existingModal.remove();
        
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal">
                <div class="modal-header">
                    <h3>${title}</h3>
                    <button class="modal-close">&times;</button>
                </div>
                <div class="modal-content">
                    ${content}
                </div>
            </div>
        `;
        
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10000;
        `;
        
        const modalContent = modal.querySelector('.modal');
        modalContent.style.cssText = `
            background: white;
            border-radius: 12px;
            width: 90%;
            max-width: 600px;
            max-height: 80vh;
            overflow-y: auto;
        `;
        
        const closeBtn = modal.querySelector('.modal-close');
        closeBtn.addEventListener('click', () => modal.remove());
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.remove();
        });
        
        document.body.appendChild(modal);
    }
    
    // Utility methods
    formatTime(timestamp) {
        if (!timestamp) return 'Unknown';
        try {
            const date = new Date(timestamp);
            if (isNaN(date.getTime())) return timestamp;
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } catch {
            return timestamp;
        }
    }
    
    showToast(message, type = 'info') {
        // Implementation remains similar
    }
    
    showLoading(show) {
        // Implementation remains similar
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.logAnalyzer = new LogAnalyzer();
    });
} else {
    window.logAnalyzer = new LogAnalyzer();
}
