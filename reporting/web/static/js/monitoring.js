// shikra/reporting/web/static/js/monitoring.js
// Real-time monitoring interface for Shikra Analysis Framework

(function() {
    'use strict';

    // ===== MONITORING INTERFACE =====
    window.MonitoringInterface = {
        config: {
            maxActivityItems: 100,
            maxProcessNodes: 50,
            maxConnections: 50,
            updateInterval: 1000,
            chartUpdateInterval: 5000,
            autoScroll: true,
            severityColors: {
                'critical': '#e74c3c',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#20c997',
                'info': '#17a2b8'
            }
        },
        
        state: {
            isMonitoring: false,
            isPaused: false,
            filters: {
                severity: 'all',
                category: 'all',
                process: 'all'
            },
            activityItems: [],
            processes: new Map(),
            connections: new Map(),
            metrics: {
                totalEvents: 0,
                eventsPerSecond: 0,
                suspiciousEvents: 0,
                processes: 0,
                connections: 0
            },
            charts: {},
            lastUpdate: Date.now()
        },

        /**
         * Initialize monitoring interface
         */
        init: function() {
            this.initializeControls();
            this.initializeFilters();
            this.initializeCharts();
            this.bindEvents();
            this.startMetricsUpdate();
            
            console.log('Monitoring interface initialized');
        },

        /**
         * Initialize control buttons
         */
        initializeControls: function() {
            const startBtn = document.getElementById('start-monitoring');
            const stopBtn = document.getElementById('stop-monitoring');
            const pauseBtn = document.getElementById('pause-monitoring');
            const resetBtn = document.getElementById('reset-monitoring');
            const exportBtn = document.getElementById('export-data');

            if (startBtn) {
                startBtn.addEventListener('click', () => this.startMonitoring());
            }
            
            if (stopBtn) {
                stopBtn.addEventListener('click', () => this.stopMonitoring());
            }
            
            if (pauseBtn) {
                pauseBtn.addEventListener('click', () => this.togglePause());
            }
            
            if (resetBtn) {
                resetBtn.addEventListener('click', () => this.resetMonitoring());
            }
            
            if (exportBtn) {
                exportBtn.addEventListener('click', () => this.exportData());
            }
        },

        /**
         * Initialize filter controls
         */
        initializeFilters: function() {
            const severityFilter = document.getElementById('severity-filter');
            const categoryFilter = document.getElementById('category-filter');
            const processFilter = document.getElementById('process-filter');
            const autoScrollToggle = document.getElementById('auto-scroll-toggle');

            if (severityFilter) {
                severityFilter.addEventListener('change', (e) => {
                    this.state.filters.severity = e.target.value;
                    this.applyFilters();
                });
            }

            if (categoryFilter) {
                categoryFilter.addEventListener('change', (e) => {
                    this.state.filters.category = e.target.value;
                    this.applyFilters();
                });
            }

            if (processFilter) {
                processFilter.addEventListener('change', (e) => {
                    this.state.filters.process = e.target.value;
                    this.applyFilters();
                });
            }

            if (autoScrollToggle) {
                autoScrollToggle.addEventListener('change', (e) => {
                    this.config.autoScroll = e.target.checked;
                });
            }
        },

        /**
         * Initialize charts
         */
        initializeCharts: function() {
            // Activity timeline chart
            const timelineCanvas = document.getElementById('activity-timeline-chart');
            if (timelineCanvas && window.Chart) {
                this.state.charts.timeline = new Chart(timelineCanvas, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Events per Second',
                            data: [],
                            borderColor: '#3498db',
                            backgroundColor: 'rgba(52, 152, 219, 0.1)',
                            tension: 0.4,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            x: {
                                type: 'time',
                                time: {
                                    unit: 'second',
                                    displayFormats: {
                                        second: 'HH:mm:ss'
                                    }
                                }
                            },
                            y: {
                                beginAtZero: true
                            }
                        },
                        plugins: {
                            legend: {
                                display: false
                            }
                        }
                    }
                });
            }

            // Severity distribution chart
            const severityCanvas = document.getElementById('severity-distribution-chart');
            if (severityCanvas && window.Chart) {
                this.state.charts.severity = new Chart(severityCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{
                            data: [0, 0, 0, 0, 0],
                            backgroundColor: [
                                this.config.severityColors.critical,
                                this.config.severityColors.high,
                                this.config.severityColors.medium,
                                this.config.severityColors.low,
                                this.config.severityColors.info
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            }
        },

        /**
         * Bind event listeners
         */
        bindEvents: function() {
            // Handle activity item clicks
            document.addEventListener('click', (e) => {
                if (e.target.closest('.activity-item')) {
                    const item = e.target.closest('.activity-item');
                    this.showActivityDetails(item);
                }
            });

            // Handle process node clicks
            document.addEventListener('click', (e) => {
                if (e.target.closest('.process-node')) {
                    const node = e.target.closest('.process-node');
                    this.showProcessDetails(node);
                }
            });

            // Handle connection item clicks
            document.addEventListener('click', (e) => {
                if (e.target.closest('.connection-item')) {
                    const item = e.target.closest('.connection-item');
                    this.showConnectionDetails(item);
                }
            });

            // Handle clear buttons
            document.addEventListener('click', (e) => {
                if (e.target.matches('[data-clear-target]')) {
                    const target = e.target.getAttribute('data-clear-target');
                    this.clearPanel(target);
                }
            });
        },

        /**
         * Start monitoring
         */
        startMonitoring: function() {
            if (this.state.isMonitoring) return;

            this.state.isMonitoring = true;
            this.state.isPaused = false;
            
            // Update UI
            this.updateControlStates();
            this.showAlert('Monitoring started', 'success');

            // Send start command via WebSocket or API
            if (window.Shikra && window.Shikra.websocket) {
                window.Shikra.websocket.send({
                    type: 'start_monitoring',
                    timestamp: Date.now()
                });
            }

            console.log('Monitoring started');
        },

        /**
         * Stop monitoring
         */
        stopMonitoring: function() {
            if (!this.state.isMonitoring) return;

            this.state.isMonitoring = false;
            this.state.isPaused = false;
            
            // Update UI
            this.updateControlStates();
            this.showAlert('Monitoring stopped', 'info');

            // Send stop command
            if (window.Shikra && window.Shikra.websocket) {
                window.Shikra.websocket.send({
                    type: 'stop_monitoring',
                    timestamp: Date.now()
                });
            }

            console.log('Monitoring stopped');
        },

        /**
         * Toggle pause monitoring
         */
        togglePause: function() {
            if (!this.state.isMonitoring) return;

            this.state.isPaused = !this.state.isPaused;
            
            // Update UI
            this.updateControlStates();
            this.showAlert(this.state.isPaused ? 'Monitoring paused' : 'Monitoring resumed', 'info');

            // Send pause/resume command
            if (window.Shikra && window.Shikra.websocket) {
                window.Shikra.websocket.send({
                    type: this.state.isPaused ? 'pause_monitoring' : 'resume_monitoring',
                    timestamp: Date.now()
                });
            }

            console.log('Monitoring', this.state.isPaused ? 'paused' : 'resumed');
        },

        /**
         * Reset monitoring data
         */
        resetMonitoring: function() {
            if (confirm('Are you sure you want to reset all monitoring data?')) {
                this.state.activityItems = [];
                this.state.processes.clear();
                this.state.connections.clear();
                this.state.metrics = {
                    totalEvents: 0,
                    eventsPerSecond: 0,
                    suspiciousEvents: 0,
                    processes: 0,
                    connections: 0
                };

                // Clear UI
                this.clearAllPanels();
                this.resetCharts();
                this.updateMetricsDisplay();

                this.showAlert('Monitoring data reset', 'info');
                console.log('Monitoring data reset');
            }
        },

        /**
         * Update control button states
         */
        updateControlStates: function() {
            const startBtn = document.getElementById('start-monitoring');
            const stopBtn = document.getElementById('stop-monitoring');
            const pauseBtn = document.getElementById('pause-monitoring');

            if (startBtn) {
                startBtn.disabled = this.state.isMonitoring;
                startBtn.textContent = this.state.isMonitoring ? 'Running...' : 'Start';
            }

            if (stopBtn) {
                stopBtn.disabled = !this.state.isMonitoring;
            }

            if (pauseBtn) {
                pauseBtn.disabled = !this.state.isMonitoring;
                pauseBtn.textContent = this.state.isPaused ? 'Resume' : 'Pause';
                pauseBtn.classList.toggle('pause', !this.state.isPaused);
                pauseBtn.classList.toggle('start', this.state.isPaused);
            }

            // Update status indicator
            const statusIndicator = document.querySelector('.monitoring-status .status-indicator');
            if (statusIndicator) {
                statusIndicator.className = 'status-indicator';
                if (this.state.isMonitoring) {
                    statusIndicator.classList.add(this.state.isPaused ? 'status-pending' : 'status-running');
                } else {
                    statusIndicator.classList.add('status-completed');
                }
            }

            const statusText = document.querySelector('.monitoring-status .status-text');
            if (statusText) {
                if (this.state.isMonitoring) {
                    statusText.textContent = this.state.isPaused ? 'Paused' : 'Running';
                } else {
                    statusText.textContent = 'Stopped';
                }
            }
        },

        /**
         * Handle incoming monitoring update
         */
        handleUpdate: function(data) {
            if (!this.state.isMonitoring || this.state.isPaused) {
                return;
            }

            switch (data.event_type) {
                case 'activity':
                    this.addActivityItem(data);
                    break;
                case 'process':
                    this.updateProcessTree(data);
                    break;
                case 'network':
                    this.updateNetworkConnections(data);
                    break;
                case 'metrics':
                    this.updateMetrics(data);
                    break;
                default:
                    console.log('Unknown monitoring update type:', data.event_type);
            }

            this.state.lastUpdate = Date.now();
        },

        /**
         * Add new activity item
         */
        addActivityItem: function(data) {
            const activityItem = {
                id: data.id || this.generateId(),
                timestamp: data.timestamp || Date.now(),
                category: data.category || 'unknown',
                subcategory: data.subcategory || '',
                severity: data.severity || 'info',
                title: data.title || 'Unknown Activity',
                description: data.description || '',
                process: data.process || 'Unknown',
                pid: data.pid || '',
                details: data.details || {}
            };

            // Add to state
            this.state.activityItems.unshift(activityItem);

            // Limit array size
            if (this.state.activityItems.length > this.config.maxActivityItems) {
                this.state.activityItems = this.state.activityItems.slice(0, this.config.maxActivityItems);
            }

            // Update metrics
            this.state.metrics.totalEvents += 1;
            if (['critical', 'high'].includes(activityItem.severity)) {
                this.state.metrics.suspiciousEvents += 1;
            }

            // Render if passes filters
            if (this.passesFilters(activityItem)) {
                this.renderActivityItem(activityItem);
            }

            // Update charts
            this.updateActivityChart();
        },

        /**
         * Render activity item in the feed
         */
        renderActivityItem: function(activityItem) {
            const activityFeed = document.querySelector('.activity-feed');
            if (!activityFeed) return;

            const itemElement = document.createElement('div');
            itemElement.className = `activity-item new ${activityItem.severity}-severity`;
            itemElement.setAttribute('data-activity-id', activityItem.id);
            itemElement.setAttribute('data-category', activityItem.category);
            itemElement.setAttribute('data-severity', activityItem.severity);

            const iconClass = this.getActivityIcon(activityItem.category);
            const timeString = new Date(activityItem.timestamp).toLocaleTimeString();

            itemElement.innerHTML = `
                <div class="activity-icon ${activityItem.category}">
                    <i class="${iconClass}"></i>
                </div>
                <div class="activity-content">
                    <div class="activity-title">${this.escapeHtml(activityItem.title)}</div>
                    <div class="activity-description">${this.escapeHtml(activityItem.description)}</div>
                    <div class="activity-meta">
                        <span class="activity-time">
                            <i class="fas fa-clock"></i> ${timeString}
                        </span>
                        <span class="activity-process">
                            <i class="fas fa-cog"></i> ${this.escapeHtml(activityItem.process)} (${activityItem.pid})
                        </span>
                    </div>
                </div>
            `;

            // Insert at top
            activityFeed.insertBefore(itemElement, activityFeed.firstChild);

            // Remove animation class after animation completes
            setTimeout(() => {
                itemElement.classList.remove('new');
            }, 500);

            // Auto-scroll if enabled
            if (this.config.autoScroll) {
                activityFeed.scrollTop = 0;
            }

            // Limit DOM elements
            const items = activityFeed.querySelectorAll('.activity-item');
            if (items.length > this.config.maxActivityItems) {
                for (let i = this.config.maxActivityItems; i < items.length; i++) {
                    items[i].remove();
                }
            }
        },

        /**
         * Update process tree
         */
        updateProcessTree: function(data) {
            const processInfo = {
                pid: data.pid,
                ppid: data.ppid || '',
                name: data.name || 'Unknown',
                command: data.command || '',
                timestamp: data.timestamp || Date.now(),
                suspicious: data.suspicious || false
            };

            this.state.processes.set(data.pid, processInfo);
            this.state.metrics.processes = this.state.processes.size;

            this.renderProcessTree();
        },

        /**
         * Render process tree
         */
        renderProcessTree: function() {
            const processTree = document.querySelector('.process-tree');
            if (!processTree) return;

            // Clear existing content
            processTree.innerHTML = '';

            // Build tree structure
            const rootProcesses = [];
            const childProcesses = new Map();

            for (const [pid, process] of this.state.processes) {
                if (!process.ppid || !this.state.processes.has(process.ppid)) {
                    rootProcesses.push(process);
                } else {
                    if (!childProcesses.has(process.ppid)) {
                        childProcesses.set(process.ppid, []);
                    }
                    childProcesses.get(process.ppid).push(process);
                }
            }

            // Render tree
            rootProcesses.forEach(process => {
                this.renderProcessNode(processTree, process, childProcesses, 0);
            });
        },

        /**
         * Render process node
         */
        renderProcessNode: function(container, process, childProcesses, depth) {
            const nodeElement = document.createElement('div');
            nodeElement.className = `process-node ${process.suspicious ? 'suspicious' : ''}`;
            nodeElement.setAttribute('data-pid', process.pid);

            const indent = '  '.repeat(depth);
            const timeString = new Date(process.timestamp).toLocaleTimeString();

            nodeElement.innerHTML = `
                <span class="process-indent">${indent}├─</span>
                <span class="process-name">${this.escapeHtml(process.name)}</span>
                <span class="process-pid">[${process.pid}]</span>
                <span class="process-args">${this.escapeHtml(process.command)}</span>
                <small class="text-muted ms-2">${timeString}</small>
            `;

            container.appendChild(nodeElement);

            // Add children
            const children = childProcesses.get(process.pid) || [];
            children.forEach(child => {
                this.renderProcessNode(container, child, childProcesses, depth + 1);
            });
        },

        /**
         * Update network connections
         */
        updateNetworkConnections: function(data) {
            const connectionInfo = {
                id: data.id || `${data.dest_ip}:${data.dest_port}`,
                dest_ip: data.dest_ip || 'Unknown',
                dest_port: data.dest_port || '',
                protocol: data.protocol || 'TCP',
                process: data.process || 'Unknown',
                pid: data.pid || '',
                timestamp: data.timestamp || Date.now(),
                suspicious: data.suspicious || false
            };

            this.state.connections.set(connectionInfo.id, connectionInfo);
            this.state.metrics.connections = this.state.connections.size;

            this.renderNetworkConnections();
        },

        /**
         * Render network connections
         */
        renderNetworkConnections: function() {
            const connectionList = document.querySelector('.connection-list');
            if (!connectionList) return;

            // Clear existing content
            connectionList.innerHTML = '';

            // Sort by timestamp (newest first)
            const connections = Array.from(this.state.connections.values())
                .sort((a, b) => b.timestamp - a.timestamp)
                .slice(0, this.config.maxConnections);

            connections.forEach(connection => {
                const itemElement = document.createElement('div');
                itemElement.className = `connection-item ${connection.suspicious ? 'suspicious' : ''}`;
                itemElement.setAttribute('data-connection-id', connection.id);

                const timeString = new Date(connection.timestamp).toLocaleTimeString();

                itemElement.innerHTML = `
                    <div class="connection-icon ${connection.protocol.toLowerCase()}">
                        ${this.getProtocolIcon(connection.protocol)}
                    </div>
                    <div class="connection-details">
                        <div class="connection-destination">
                            ${this.escapeHtml(connection.dest_ip)}:${connection.dest_port}
                        </div>
                        <div class="connection-info">
                            <span class="connection-protocol">${connection.protocol}</span>
                            <span class="connection-process">${this.escapeHtml(connection.process)} (${connection.pid})</span>
                            <span class="connection-time">${timeString}</span>
                        </div>
                    </div>
                `;

                connectionList.appendChild(itemElement);
            });
        },

        /**
         * Update metrics
         */
        updateMetrics: function(data) {
            Object.assign(this.state.metrics, data);
            this.updateMetricsDisplay();
        },

        /**
         * Update metrics display
         */
        updateMetricsDisplay: function() {
            // Update stat widgets
            const totalEventsElement = document.querySelector('[data-metric="total-events"] .stat-value');
            if (totalEventsElement) {
                totalEventsElement.textContent = this.state.metrics.totalEvents.toLocaleString();
            }

            const eventsPerSecElement = document.querySelector('[data-metric="events-per-sec"] .stat-value');
            if (eventsPerSecElement) {
                eventsPerSecElement.textContent = this.state.metrics.eventsPerSecond.toFixed(1);
            }

            const suspiciousEventsElement = document.querySelector('[data-metric="suspicious-events"] .stat-value');
            if (suspiciousEventsElement) {
                suspiciousEventsElement.textContent = this.state.metrics.suspiciousEvents.toLocaleString();
            }

            const processesElement = document.querySelector('[data-metric="processes"] .stat-value');
            if (processesElement) {
                processesElement.textContent = this.state.metrics.processes.toLocaleString();
            }

            const connectionsElement = document.querySelector('[data-metric="connections"] .stat-value');
            if (connectionsElement) {
                connectionsElement.textContent = this.state.metrics.connections.toLocaleString();
            }
        },

        /**
         * Start metrics update interval
         */
        startMetricsUpdate: function() {
            setInterval(() => {
                if (this.state.isMonitoring && !this.state.isPaused) {
                    this.calculateEventsPerSecond();
                    this.updateCharts();
                }
            }, this.config.chartUpdateInterval);
        },

        /**
         * Calculate events per second
         */
        calculateEventsPerSecond: function() {
            const now = Date.now();
            const oneSecondAgo = now - 1000;
            
            const recentEvents = this.state.activityItems.filter(
                item => item.timestamp > oneSecondAgo
            );
            
            this.state.metrics.eventsPerSecond = recentEvents.length;
            this.updateMetricsDisplay();
        },

        /**
         * Update activity chart
         */
        updateActivityChart: function() {
            const chart = this.state.charts.timeline;
            if (!chart) return;

            const now = new Date();
            const labels = chart.data.labels;
            const data = chart.data.datasets[0].data;

            // Add current data point
            labels.push(now);
            data.push(this.state.metrics.eventsPerSecond);

            // Keep only last 60 data points (1 minute)
            if (labels.length > 60) {
                labels.shift();
                data.shift();
            }

            chart.update('none'); // No animation for real-time updates
        },

        /**
         * Update charts
         */
        updateCharts: function() {
            this.updateActivityChart();
            this.updateSeverityChart();
        },

        /**
         * Update severity distribution chart
         */
        updateSeverityChart: function() {
            const chart = this.state.charts.severity;
            if (!chart) return;

            const severityCounts = {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0
            };

            this.state.activityItems.forEach(item => {
                if (severityCounts.hasOwnProperty(item.severity)) {
                    severityCounts[item.severity]++;
                }
            });

            chart.data.datasets[0].data = [
                severityCounts.critical,
                severityCounts.high,
                severityCounts.medium,
                severityCounts.low,
                severityCounts.info
            ];

            chart.update('none');
        },

        /**
         * Apply filters to activity feed
         */
        applyFilters: function() {
            const activityItems = document.querySelectorAll('.activity-item');
            
            activityItems.forEach(item => {
                const category = item.getAttribute('data-category');
                const severity = item.getAttribute('data-severity');
                
                const visible = this.passesFilters({
                    category: category,
                    severity: severity
                });
                
                item.style.display = visible ? '' : 'none';
            });
        },

        /**
         * Check if item passes current filters
         */
        passesFilters: function(item) {
            if (this.state.filters.severity !== 'all' && item.severity !== this.state.filters.severity) {
                return false;
            }
            
            if (this.state.filters.category !== 'all' && item.category !== this.state.filters.category) {
                return false;
            }
            
            return true;
        },

        /**
         * Show activity details modal
         */
        showActivityDetails: function(itemElement) {
            const activityId = itemElement.getAttribute('data-activity-id');
            const activity = this.state.activityItems.find(item => item.id === activityId);
            
            if (!activity) return;

            // Create modal content
            const modalContent = `
                <div class="modal-header">
                    <h5 class="modal-title">Activity Details</h5>
                    <button type="button" class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <table class="table table-sm">
                        <tr><th>Timestamp</th><td>${new Date(activity.timestamp).toLocaleString()}</td></tr>
                        <tr><th>Category</th><td>${activity.category}</td></tr>
                        <tr><th>Severity</th><td><span class="severity-indicator severity-${activity.severity}">${activity.severity}</span></td></tr>
                        <tr><th>Process</th><td>${activity.process} (PID: ${activity.pid})</td></tr>
                        <tr><th>Title</th><td>${activity.title}</td></tr>
                        <tr><th>Description</th><td>${activity.description}</td></tr>
                    </table>
                    ${Object.keys(activity.details).length > 0 ? `
                        <h6>Additional Details</h6>
                        <pre class="bg-light p-2"><code>${JSON.stringify(activity.details, null, 2)}</code></pre>
                    ` : ''}
                </div>
            `;

            this.showModal('Activity Details', modalContent);
        },

        /**
         * Show process details modal
         */
        showProcessDetails: function(nodeElement) {
            const pid = nodeElement.getAttribute('data-pid');
            const process = this.state.processes.get(pid);
            
            if (!process) return;

            const modalContent = `
                <div class="modal-header">
                    <h5 class="modal-title">Process Details</h5>
                    <button type="button" class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <table class="table table-sm">
                        <tr><th>PID</th><td>${process.pid}</td></tr>
                        <tr><th>Parent PID</th><td>${process.ppid || 'N/A'}</td></tr>
                        <tr><th>Name</th><td>${process.name}</td></tr>
                        <tr><th>Command</th><td><code>${process.command || 'N/A'}</code></td></tr>
                        <tr><th>Started</th><td>${new Date(process.timestamp).toLocaleString()}</td></tr>
                        <tr><th>Suspicious</th><td>${process.suspicious ? 'Yes' : 'No'}</td></tr>
                    </table>
                </div>
            `;

            this.showModal('Process Details', modalContent);
        },

        /**
         * Show connection details modal
         */
        showConnectionDetails: function(itemElement) {
            const connectionId = itemElement.getAttribute('data-connection-id');
            const connection = this.state.connections.get(connectionId);
            
            if (!connection) return;

            const modalContent = `
                <div class="modal-header">
                    <h5 class="modal-title">Connection Details</h5>
                    <button type="button" class="modal-close">&times;</button>
                </div>
                <div class="modal-body">
                    <table class="table table-sm">
                        <tr><th>Destination</th><td>${connection.dest_ip}:${connection.dest_port}</td></tr>
                        <tr><th>Protocol</th><td>${connection.protocol}</td></tr>
                        <tr><th>Process</th><td>${connection.process} (PID: ${connection.pid})</td></tr>
                        <tr><th>Established</th><td>${new Date(connection.timestamp).toLocaleString()}</td></tr>
                        <tr><th>Suspicious</th><td>${connection.suspicious ? 'Yes' : 'No'}</td></tr>
                    </table>
                </div>
            `;

            this.showModal('Connection Details', modalContent);
        },

        /**
         * Show modal
         */
        showModal: function(title, content) {
            let modal = document.getElementById('monitoring-modal');
            if (!modal) {
                modal = document.createElement('div');
                modal.id = 'monitoring-modal';
                modal.className = 'modal-overlay';
                modal.innerHTML = '<div class="modal"></div>';
                document.body.appendChild(modal);
            }

            const modalBody = modal.querySelector('.modal');
            modalBody.innerHTML = content;

            modal.classList.add('show');

            // Bind close events
            modal.querySelector('.modal-close').addEventListener('click', () => {
                modal.classList.remove('show');
            });

            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('show');
                }
            });
        },

        /**
         * Clear specific panel
         */
        clearPanel: function(panelName) {
            switch (panelName) {
                case 'activity':
                    document.querySelector('.activity-feed').innerHTML = '';
                    this.state.activityItems = [];
                    break;
                case 'processes':
                    document.querySelector('.process-tree').innerHTML = '';
                    this.state.processes.clear();
                    break;
                case 'connections':
                    document.querySelector('.connection-list').innerHTML = '';
                    this.state.connections.clear();
                    break;
            }
            
            this.updateMetricsDisplay();
        },

        /**
         * Clear all panels
         */
        clearAllPanels: function() {
            this.clearPanel('activity');
            this.clearPanel('processes');
            this.clearPanel('connections');
        },

        /**
         * Reset charts
         */
        resetCharts: function() {
            Object.values(this.state.charts).forEach(chart => {
                if (chart.data) {
                    chart.data.labels = [];
                    chart.data.datasets.forEach(dataset => {
                        dataset.data = [];
                    });
                    chart.update();
                }
            });
        },

        /**
         * Export monitoring data
         */
        exportData: function() {
            const data = {
                timestamp: new Date().toISOString(),
                metrics: this.state.metrics,
                activityItems: this.state.activityItems,
                processes: Array.from(this.state.processes.values()),
                connections: Array.from(this.state.connections.values())
            };

            const blob = new Blob([JSON.stringify(data, null, 2)], {
                type: 'application/json'
            });

            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `shikra_monitoring_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
            a.click();
            
            URL.revokeObjectURL(url);
            this.showAlert('Monitoring data exported', 'success');
        },

        /**
         * Show alert notification
         */
        showAlert: function(message, type) {
            if (window.Shikra && window.Shikra.notifications) {
                window.Shikra.notifications.show(message, type);
            } else {
                console.log(`[${type.toUpperCase()}] ${message}`);
            }
        },

        /**
         * Get activity icon class
         */
        getActivityIcon: function(category) {
            const icons = {
                'process': 'fas fa-cogs',
                'file': 'fas fa-file',
                'registry': 'fas fa-database',
                'network': 'fas fa-network-wired'
            };
            return icons[category] || 'fas fa-info-circle';
        },

        /**
         * Get protocol icon
         */
        getProtocolIcon: function(protocol) {
            const icons = {
                'TCP': '<i class="fas fa-arrow-right"></i>',
                'UDP': '<i class="fas fa-exchange-alt"></i>',
                'HTTP': '<i class="fas fa-globe"></i>',
                'HTTPS': '<i class="fas fa-lock"></i>',
                'DNS': '<i class="fas fa-search"></i>'
            };
            return icons[protocol] || '<i class="fas fa-question"></i>';
        },

        /**
         * Generate unique ID
         */
        generateId: function() {
            return 'mon_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
        },

        /**
         * Escape HTML
         */
        escapeHtml: function(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    };

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        if (document.querySelector('.monitoring-dashboard')) {
            MonitoringInterface.init();
        }
    });

})();