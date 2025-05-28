// shikra/reporting/web/static/js/shikra.js
// Main JavaScript functionality for Shikra Analysis Framework
// Aligned with actual project structure and capabilities

(function() {
    'use strict';

    // ===== GLOBAL VARIABLES =====
    window.Shikra = {
        config: {
            apiBaseUrl: '/api/v1',
            wsBaseUrl: location.protocol === 'https:' ? 'wss:' : 'ws:' + '//' + location.host,
            refreshInterval: 5000,
            maxLogLines: 1000,
            chartOptions: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        },
        state: {
            currentAnalysis: null,
            notifications: [],
            websocket: null,
            charts: {},
            intervals: {},
            monitoringActive: false
        },
        utils: {},
        ui: {},
        api: {},
        charts: {},
        notifications: {},
        monitoring: {},
        analysis: {}
    };

    // ===== UTILITY FUNCTIONS =====
    Shikra.utils = {
        /**
         * Format timestamp to readable string
         */
        formatTimestamp: function(timestamp) {
            if (!timestamp) return 'N/A';
            
            let date;
            if (typeof timestamp === 'number') {
                date = new Date(timestamp * 1000);
            } else {
                date = new Date(timestamp);
            }
            
            return date.toLocaleString();
        },

        /**
         * Format file size in bytes to human readable
         */
        formatFileSize: function(bytes) {
            if (bytes === 0) return '0 Bytes';
            
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },

        /**
         * Escape HTML to prevent XSS
         */
        escapeHtml: function(text) {
            if (!text) return '';
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.toString().replace(/[&<>"']/g, function(m) { return map[m]; });
        },

        /**
         * Debounce function calls
         */
        debounce: function(func, wait, immediate) {
            let timeout;
            return function() {
                const context = this, args = arguments;
                const later = function() {
                    timeout = null;
                    if (!immediate) func.apply(context, args);
                };
                const callNow = immediate && !timeout;
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
                if (callNow) func.apply(context, args);
            };
        },

        /**
         * Generate unique ID
         */
        generateId: function() {
            return 'shikra_' + Math.random().toString(36).substr(2, 9);
        },

        /**
         * Get severity color based on analysis results
         */
        getSeverityColor: function(severity) {
            const colors = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745',
                'info': '#17a2b8',
                'malicious': '#dc3545',
                'suspicious': '#fd7e14',
                'benign': '#28a745',
                'undetermined': '#6c757d'
            };
            return colors[severity?.toLowerCase()] || '#6c757d';
        },

        /**
         * Get severity icon
         */
        getSeverityIcon: function(severity) {
            const icons = {
                'critical': 'fas fa-exclamation-triangle',
                'high': 'fas fa-exclamation-circle',
                'medium': 'fas fa-info-circle',
                'low': 'fas fa-check-circle',
                'info': 'fas fa-info',
                'malicious': 'fas fa-virus',
                'suspicious': 'fas fa-question-circle',
                'benign': 'fas fa-shield-alt',
                'undetermined': 'fas fa-question'
            };
            return icons[severity?.toLowerCase()] || 'fas fa-question-circle';
        },

        /**
         * Copy text to clipboard
         */
        copyToClipboard: function(text) {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(text).then(() => {
                    Shikra.notifications.show('Copied to clipboard', 'success', 2000);
                });
            } else {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                Shikra.notifications.show('Copied to clipboard', 'success', 2000);
            }
        },

        /**
         * Format analysis classification for display
         */
        formatClassification: function(classification) {
            if (!classification) return 'Unknown';
            
            // Handle different classification formats from analysis modules
            const normalizedClassification = classification.toLowerCase();
            
            if (normalizedClassification.includes('malicious') || normalizedClassification.includes('ransomware')) {
                return 'Malicious';
            } else if (normalizedClassification.includes('suspicious')) {
                return 'Suspicious';
            } else if (normalizedClassification.includes('benign') || normalizedClassification.includes('low concern')) {
                return 'Benign';
            } else {
                return 'Undetermined';
            }
        }
    };

    // ===== API FUNCTIONS (Aligned with actual endpoints) =====
    Shikra.api = {
        /**
         * Generic API request handler
         */
        request: function(endpoint, options = {}) {
            const defaultOptions = {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            };

            const config = Object.assign(defaultOptions, options);
            const url = Shikra.config.apiBaseUrl + endpoint;

            return fetch(url, config)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    return response.json();
                })
                .catch(error => {
                    console.error('API request failed:', error);
                    Shikra.notifications.show(`API Error: ${error.message}`, 'danger');
                    throw error;
                });
        },

        /**
         * Get analysis list
         */
        getAnalyses: function(params = {}) {
            const queryString = new URLSearchParams(params).toString();
            const endpoint = '/analyses' + (queryString ? '?' + queryString : '');
            return this.request(endpoint);
        },

        /**
         * Get specific analysis details
         */
        getAnalysis: function(analysisId) {
            return this.request(`/analyses/${analysisId}`);
        },

        /**
         * Submit new analysis
         */
        submitAnalysis: function(formData) {
            return this.request('/analyses', {
                method: 'POST',
                body: formData,
                headers: {} // Let browser set Content-Type for FormData
            });
        },

        /**
         * Get analysis status
         */
        getAnalysisStatus: function(analysisId) {
            return this.request(`/analyses/${analysisId}/status`);
        },

        /**
         * Get real-time monitoring status
         */
        getMonitoringStatus: function(analysisId) {
            return this.request(`/monitoring/${analysisId}/status`);
        },

        /**
         * Get ProcMon events for analysis
         */
        getProcMonEvents: function(analysisId, params = {}) {
            const queryString = new URLSearchParams(params).toString();
            const endpoint = `/monitoring/${analysisId}/events` + (queryString ? '?' + queryString : '');
            return this.request(endpoint);
        },

        /**
         * Cancel analysis
         */
        cancelAnalysis: function(analysisId) {
            return this.request(`/analyses/${analysisId}/cancel`, {
                method: 'POST'
            });
        },

        /**
         * Download analysis report
         */
        downloadReport: function(analysisId, format = 'json') {
            const url = `${Shikra.config.apiBaseUrl}/analyses/${analysisId}/report?format=${format}`;
            window.open(url, '_blank');
        },

        /**
         * Get system status
         */
        getSystemStatus: function() {
            return this.request('/system/status');
        },

        /**
         * Get VM status
         */
        getVMStatus: function() {
            return this.request('/vm/status');
        },

        /**
         * Get available VM profiles
         */
        getVMProfiles: function() {
            return this.request('/vm/profiles');
        }
    };

    // ===== MONITORING FUNCTIONS (Aligned with actual monitoring modules) =====
    Shikra.monitoring = {
        /**
         * Initialize real-time monitoring display
         */
        init: function(analysisId) {
            this.analysisId = analysisId;
            this.eventCount = 0;
            this.startTime = Date.now();
            
            // Initialize monitoring UI components
            this.initEventStream();
            this.initFilters();
            this.startStatusPolling();
        },

        /**
         * Initialize event stream display
         */
        initEventStream: function() {
            const eventContainer = document.getElementById('monitoring-events');
            if (!eventContainer) return;

            // Create event stream header
            const header = document.createElement('div');
            header.className = 'event-stream-header d-flex justify-content-between align-items-center mb-3';
            header.innerHTML = `
                <div>
                    <h5>Real-time Events</h5>
                    <small class="text-muted">Events: <span id="event-count">0</span> | 
                           Duration: <span id="monitoring-duration">00:00</span></small>
                </div>
                <div class="btn-group btn-group-sm">
                    <button type="button" class="btn btn-outline-primary" id="pause-monitoring">
                        <i class="fas fa-pause"></i> Pause
                    </button>
                    <button type="button" class="btn btn-outline-secondary" id="clear-events">
                        <i class="fas fa-eraser"></i> Clear
                    </button>
                </div>
            `;
            eventContainer.appendChild(header);

            // Create event list container
            const eventList = document.createElement('div');
            eventList.id = 'event-list';
            eventList.className = 'event-list';
            eventContainer.appendChild(eventList);

            // Bind events
            document.getElementById('pause-monitoring')?.addEventListener('click', () => {
                this.toggleMonitoring();
            });

            document.getElementById('clear-events')?.addEventListener('click', () => {
                this.clearEvents();
            });
        },

        /**
         * Initialize event filters
         */
        initFilters: function() {
            const filterContainer = document.getElementById('monitoring-filters');
            if (!filterContainer) return;

            filterContainer.innerHTML = `
                <div class="row g-3">
                    <div class="col-md-3">
                        <label class="form-label">Process</label>
                        <input type="text" class="form-control form-control-sm" id="filter-process" 
                               placeholder="Filter by process name">
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Operation</label>
                        <select class="form-select form-select-sm" id="filter-operation">
                            <option value="">All Operations</option>
                            <option value="CreateFile">File Create</option>
                            <option value="WriteFile">File Write</option>
                            <option value="RegSetValue">Registry Set</option>
                            <option value="Process">Process Activity</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <label class="form-label">Severity</label>
                        <select class="form-select form-select-sm" id="filter-severity">
                            <option value="">All Severities</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <div class="col-md-3 d-flex align-items-end">
                        <button type="button" class="btn btn-primary btn-sm" id="apply-filters">
                            <i class="fas fa-filter"></i> Apply
                        </button>
                    </div>
                </div>
            `;

            // Bind filter events
            document.getElementById('apply-filters')?.addEventListener('click', () => {
                this.applyFilters();
            });
        },

        /**
         * Start monitoring status polling
         */
        startStatusPolling: function() {
            if (!this.analysisId) return;

            this.statusInterval = setInterval(() => {
                if (!Shikra.state.monitoringActive) return;

                Shikra.api.getProcMonEvents(this.analysisId, {
                    since: this.lastEventTime || 0,
                    limit: 50
                })
                .then(response => {
                    if (response.events && response.events.length > 0) {
                        this.processEvents(response.events);
                        this.lastEventTime = response.events[response.events.length - 1].timestamp;
                    }
                })
                .catch(error => {
                    console.error('Error polling events:', error);
                });

                // Update duration
                this.updateDuration();
            }, 2000);
        },

        /**
         * Process incoming events
         */
        processEvents: function(events) {
            const eventList = document.getElementById('event-list');
            if (!eventList) return;

            events.forEach(event => {
                this.eventCount++;
                const eventElement = this.createEventElement(event);
                eventList.appendChild(eventElement);

                // Limit number of displayed events
                if (eventList.children.length > Shikra.config.maxLogLines) {
                    eventList.removeChild(eventList.firstChild);
                }
            });

            // Update event count
            const countElement = document.getElementById('event-count');
            if (countElement) {
                countElement.textContent = this.eventCount;
            }

            // Auto-scroll to bottom
            eventList.scrollTop = eventList.scrollHeight;
        },

        /**
         * Create event display element
         */
        createEventElement: function(event) {
            const element = document.createElement('div');
            element.className = `event-item event-${event.severity || 'info'}`;
            
            const timestamp = Shikra.utils.formatTimestamp(event.timestamp);
            const severity = event.severity || 'info';
            const severityColor = Shikra.utils.getSeverityColor(severity);
            const severityIcon = Shikra.utils.getSeverityIcon(severity);

            element.innerHTML = `
                <div class="event-header d-flex justify-content-between align-items-center">
                    <div class="event-meta">
                        <span class="event-time text-muted">${timestamp}</span>
                        <span class="event-severity ms-2" style="color: ${severityColor}">
                            <i class="${severityIcon}"></i> ${severity?.toUpperCase()}
                        </span>
                    </div>
                    <div class="event-process">
                        <small class="text-muted">${Shikra.utils.escapeHtml(event.process || 'Unknown')}</small>
                    </div>
                </div>
                <div class="event-content">
                    <div class="event-operation">
                        <strong>${Shikra.utils.escapeHtml(event.operation || 'Unknown Operation')}</strong>
                    </div>
                    <div class="event-details text-muted">
                        ${Shikra.utils.escapeHtml(event.details || event.path || 'No details available')}
                    </div>
                </div>
            `;

            return element;
        },

        /**
         * Toggle monitoring pause/resume
         */
        toggleMonitoring: function() {
            Shikra.state.monitoringActive = !Shikra.state.monitoringActive;
            const button = document.getElementById('pause-monitoring');
            
            if (Shikra.state.monitoringActive) {
                button.innerHTML = '<i class="fas fa-pause"></i> Pause';
                button.className = 'btn btn-outline-primary';
            } else {
                button.innerHTML = '<i class="fas fa-play"></i> Resume';
                button.className = 'btn btn-outline-success';
            }
        },

        /**
         * Clear events display
         */
        clearEvents: function() {
            const eventList = document.getElementById('event-list');
            if (eventList) {
                eventList.innerHTML = '';
                this.eventCount = 0;
                document.getElementById('event-count').textContent = '0';
            }
        },

        /**
         * Apply event filters
         */
        applyFilters: function() {
            const processFilter = document.getElementById('filter-process')?.value?.toLowerCase() || '';
            const operationFilter = document.getElementById('filter-operation')?.value || '';
            const severityFilter = document.getElementById('filter-severity')?.value || '';

            const events = document.querySelectorAll('.event-item');
            
            events.forEach(event => {
                const processText = event.querySelector('.event-process')?.textContent?.toLowerCase() || '';
                const operationText = event.querySelector('.event-operation')?.textContent || '';
                const severityClass = Array.from(event.classList).find(cls => cls.startsWith('event-'));
                const eventSeverity = severityClass ? severityClass.replace('event-', '') : '';

                let visible = true;

                if (processFilter && !processText.includes(processFilter)) {
                    visible = false;
                }
                if (operationFilter && !operationText.includes(operationFilter)) {
                    visible = false;
                }
                if (severityFilter && eventSeverity !== severityFilter) {
                    visible = false;
                }

                event.style.display = visible ? '' : 'none';
            });
        },

        /**
         * Update monitoring duration display
         */
        updateDuration: function() {
            const durationElement = document.getElementById('monitoring-duration');
            if (!durationElement) return;

            const elapsed = Math.floor((Date.now() - this.startTime) / 1000);
            const minutes = Math.floor(elapsed / 60);
            const seconds = elapsed % 60;
            
            durationElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        },

        /**
         * Stop monitoring
         */
        stop: function() {
            if (this.statusInterval) {
                clearInterval(this.statusInterval);
                this.statusInterval = null;
            }
            Shikra.state.monitoringActive = false;
        }
    };

    // ===== ANALYSIS FUNCTIONS =====
    Shikra.analysis = {
        /**
         * Initialize analysis view
         */
        init: function(analysisId) {
            this.analysisId = analysisId;
            this.loadAnalysisData();
            this.initCharts();
            this.startStatusPolling();
        },

        /**
         * Load analysis data
         */
        loadAnalysisData: function() {
            if (!this.analysisId) return;

            Shikra.api.getAnalysis(this.analysisId)
                .then(data => {
                    this.updateAnalysisDisplay(data);
                })
                .catch(error => {
                    console.error('Failed to load analysis data:', error);
                });
        },

        /**
         * Update analysis display
         */
        updateAnalysisDisplay: function(data) {
            // Update basic info
            this.updateAnalysisInfo(data);
            
            // Update status
            this.updateAnalysisStatus(data.status);
            
            // Update results if available
            if (data.results) {
                this.updateAnalysisResults(data.results);
            }
        },

        /**
         * Update analysis info section
         */
        updateAnalysisInfo: function(data) {
            const elements = {
                'analysis-filename': data.filename,
                'analysis-submitted': Shikra.utils.formatTimestamp(data.submitted_at),
                'analysis-filesize': Shikra.utils.formatFileSize(data.filesize),
                'analysis-filetype': data.file_type,
                'analysis-md5': data.md5,
                'analysis-sha256': data.sha256
            };

            Object.entries(elements).forEach(([id, value]) => {
                const element = document.getElementById(id);
                if (element && value) {
                    element.textContent = value;
                }
            });
        },

        /**
         * Update analysis status
         */
        updateAnalysisStatus: function(status) {
            const statusElement = document.querySelector('.analysis-status');
            if (!statusElement) return;

            const indicator = statusElement.querySelector('.status-indicator');
            const text = statusElement.querySelector('.status-text');

            if (indicator) {
                indicator.className = `status-indicator status-${status.toLowerCase()}`;
            }

            if (text) {
                text.textContent = status;
            }

            // Update progress bar if exists
            const progressBar = document.querySelector('.analysis-progress');
            if (progressBar) {
                const progress = this.getStatusProgress(status);
                progressBar.style.width = `${progress}%`;
                progressBar.setAttribute('aria-valuenow', progress);
            }
        },

        /**
         * Get progress percentage for status
         */
        getStatusProgress: function(status) {
            const progressMap = {
                'submitted': 10,
                'queued': 20,
                'running': 50,
                'analyzing': 75,
                'completed': 100,
                'failed': 100,
                'cancelled': 100
            };
            return progressMap[status.toLowerCase()] || 0;
        },

        /**
         * Update analysis results
         */
        updateAnalysisResults: function(results) {
            // Update overall verdict
            this.updateVerdict(results);
            
            // Update module results
            if (results.behavioral) {
                this.updateModuleResults('behavioral', results.behavioral);
            }
            if (results.network) {
                this.updateModuleResults('network', results.network);
            }
            if (results.memory) {
                this.updateModuleResults('memory', results.memory);
            }

            // Update charts with new data
            this.updateCharts(results);
        },

        /**
         * Update overall verdict
         */
        updateVerdict: function(results) {
            const verdictElement = document.getElementById('analysis-verdict');
            const scoreElement = document.getElementById('analysis-score');

            if (verdictElement && results.verdict) {
                const classification = Shikra.utils.formatClassification(results.verdict);
                const color = Shikra.utils.getSeverityColor(classification);
                const icon = Shikra.utils.getSeverityIcon(classification);

                verdictElement.innerHTML = `
                    <i class="${icon}" style="color: ${color}"></i>
                    <span style="color: ${color}">${classification}</span>
                `;
            }

            if (scoreElement && typeof results.score === 'number') {
                scoreElement.textContent = `${results.score}/100`;
                
                // Update score bar if exists
                const scoreBar = document.querySelector('.score-bar');
                if (scoreBar) {
                    scoreBar.style.width = `${results.score}%`;
                    scoreBar.className = `score-bar score-${this.getScoreCategory(results.score)}`;
                }
            }
        },

        /**
         * Get score category for styling
         */
        getScoreCategory: function(score) {
            if (score >= 80) return 'high';
            if (score >= 60) return 'medium';
            if (score >= 40) return 'low';
            return 'minimal';
        },

        /**
         * Update module results
         */
        updateModuleResults: function(module, results) {
            const moduleElement = document.getElementById(`${module}-results`);
            if (!moduleElement) return;

            // Update module status
            const statusElement = moduleElement.querySelector('.module-status');
            if (statusElement) {
                const classification = Shikra.utils.formatClassification(results.classification);
                const color = Shikra.utils.getSeverityColor(classification);
                statusElement.innerHTML = `<span style="color: ${color}">${classification}</span>`;
            }

            // Update module score
            const scoreElement = moduleElement.querySelector('.module-score');
            if (scoreElement && typeof results.score === 'number') {
                scoreElement.textContent = `${results.score}/100`;
            }

            // Update signatures count
            const signaturesElement = moduleElement.querySelector('.module-signatures');
            if (signaturesElement && results.signatures) {
                signaturesElement.textContent = results.signatures.length;
            }
        },

        /**
         * Initialize charts
         */
        initCharts: function() {
            // Initialize severity distribution chart
            const severityCanvas = document.getElementById('severity-chart');
            if (severityCanvas && typeof Chart !== 'undefined') {
                Shikra.state.charts.severity = new Chart(severityCanvas, {
                    type: 'doughnut',
                    data: {
                        labels: [],
                        datasets: [{
                            data: [],
                            backgroundColor: [],
                            borderWidth: 2
                        }]
                    },
                    options: Shikra.config.chartOptions
                });
            }
        },

        /**
         * Update charts with analysis data
         */
        updateCharts: function(results) {
            this.updateSeverityChart(results);
        },

        /**
         * Update severity distribution chart
         */
        updateSeverityChart: function(results) {
            const chart = Shikra.state.charts.severity;
            if (!chart) return;

            // Collect severity data from all modules
            const severityData = {};
            
            ['behavioral', 'network', 'memory'].forEach(module => {
                if (results[module] && results[module].signatures) {
                    results[module].signatures.forEach(sig => {
                        const severity = sig.severity || 'unknown';
                        severityData[severity] = (severityData[severity] || 0) + 1;
                    });
                }
            });

            // Update chart
            chart.data.labels = Object.keys(severityData);
            chart.data.datasets[0].data = Object.values(severityData);
            chart.data.datasets[0].backgroundColor = Object.keys(severityData).map(s => 
                Shikra.utils.getSeverityColor(s)
            );
            chart.update();
        },

        /**
         * Start status polling for running analysis
         */
        startStatusPolling: function() {
            if (!this.analysisId) return;

            this.statusInterval = setInterval(() => {
                Shikra.api.getAnalysisStatus(this.analysisId)
                    .then(response => {
                        this.updateAnalysisStatus(response.status);
                        
                        // Stop polling if analysis is complete
                        if (['completed', 'failed', 'cancelled'].includes(response.status)) {
                            clearInterval(this.statusInterval);
                            this.loadAnalysisData(); // Reload full data
                        }
                    })
                    .catch(error => {
                        console.error('Status polling error:', error);
                    });
            }, Shikra.config.refreshInterval);
        },

        /**
         * Stop status polling
         */
        stopStatusPolling: function() {
            if (this.statusInterval) {
                clearInterval(this.statusInterval);
                this.statusInterval = null;
            }
        }
    };

    // ===== UI FUNCTIONS =====
    Shikra.ui = {
        /**
         * Initialize UI components
         */
        init: function() {
            this.initModals();
            this.initDropdowns();
            this.initTabs();
            this.initFileUpload();
            this.initSearch();
            this.initTooltips();
            this.bindGlobalEvents();
        },

        /**
         * Initialize modals
         */
        initModals: function() {
            document.addEventListener('click', function(e) {
                if (e.target.matches('[data-modal-target]')) {
                    const modalId = e.target.getAttribute('data-modal-target');
                    Shikra.ui.showModal(modalId);
                }
                
                if (e.target.matches('.modal-close, .modal-overlay')) {
                    Shikra.ui.hideModal();
                }
            });

            // Close modal on Escape key
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') {
                    Shikra.ui.hideModal();
                }
            });
        },

        /**
         * Show modal
         */
        showModal: function(modalId) {
            const modal = document.getElementById(modalId);
            if (modal) {
                modal.classList.add('show');
                document.body.style.overflow = 'hidden';
            }
        },

        /**
         * Hide modal
         */
        hideModal: function() {
            const modals = document.querySelectorAll('.modal-overlay.show');
            modals.forEach(modal => {
                modal.classList.remove('show');
            });
            document.body.style.overflow = '';
        },

        /**
         * Initialize dropdowns
         */
        initDropdowns: function() {
            document.addEventListener('click', function(e) {
                if (e.target.matches('.dropdown-toggle')) {
                    e.preventDefault();
                    const dropdown = e.target.closest('.dropdown');
                    const menu = dropdown.querySelector('.dropdown-menu');
                    
                    // Close other dropdowns
                    document.querySelectorAll('.dropdown-menu.show').forEach(m => {
                        if (m !== menu) m.classList.remove('show');
                    });
                    
                    menu.classList.toggle('show');
                }
                
                // Close dropdowns when clicking outside
                if (!e.target.closest('.dropdown')) {
                    document.querySelectorAll('.dropdown-menu.show').forEach(m => {
                        m.classList.remove('show');
                    });
                }
            });
        },

        /**
         * Initialize tabs
         */
        initTabs: function() {
            document.addEventListener('click', function(e) {
                if (e.target.matches('.nav-tab')) {
                    e.preventDefault();
                    
                    const tabContainer = e.target.closest('.nav-tabs').parentNode;
                    const targetId = e.target.getAttribute('data-tab-target');
                    
                    // Remove active class from all tabs and content
                    tabContainer.querySelectorAll('.nav-tab.active').forEach(tab => {
                        tab.classList.remove('active');
                    });
                    tabContainer.querySelectorAll('.tab-content.active').forEach(content => {
                        content.classList.remove('active');
                    });
                    
                    // Add active class to clicked tab and target content
                    e.target.classList.add('active');
                    const targetContent = document.getElementById(targetId);
                    if (targetContent) {
                        targetContent.classList.add('active');
                    }
                }
            });
        },

        /**
         * Initialize file upload
         */
        initFileUpload: function() {
            const fileUploadAreas = document.querySelectorAll('.file-upload-area');
            
            fileUploadAreas.forEach(area => {
                const input = area.querySelector('.file-upload-input');
                if (!input) return;
                
                area.addEventListener('click', () => input.click());
                
                area.addEventListener('dragover', (e) => {
                    e.preventDefault();
                    area.classList.add('dragover');
                });
                
                area.addEventListener('dragleave', () => {
                    area.classList.remove('dragover');
                });
                
                area.addEventListener('drop', (e) => {
                    e.preventDefault();
                    area.classList.remove('dragover');
                    
                    const files = e.dataTransfer.files;
                    if (files.length > 0) {
                        input.files = files;
                        Shikra.ui.handleFileSelect(input);
                    }
                });
                
                input.addEventListener('change', () => {
                    Shikra.ui.handleFileSelect(input);
                });
            });
        },

        /**
         * Handle file selection
         */
        handleFileSelect: function(input) {
            const files = Array.from(input.files);
            const fileList = input.closest('.file-upload-area').querySelector('.file-list') || 
                           input.closest('.file-upload-area').appendChild(document.createElement('div'));
            
            fileList.className = 'file-list mt-3';
            fileList.innerHTML = '';
            
            files.forEach(file => {
                const fileItem = document.createElement('div');
                fileItem.className = 'file-item d-flex align-items-center justify-content-between p-2 border rounded mb-2';
                fileItem.innerHTML = `
                    <div>
                        <i class="fas fa-file me-2"></i>
                        <span class="file-name">${Shikra.utils.escapeHtml(file.name)}</span>
                        <small class="text-muted ms-2">(${Shikra.utils.formatFileSize(file.size)})</small>
                    </div>
                    <button type="button" class="btn btn-sm btn-outline-danger remove-file">
                        <i class="fas fa-times"></i>
                    </button>
                `;
                
                fileItem.querySelector('.remove-file').addEventListener('click', () => {
                    fileItem.remove();
                });
                
                fileList.appendChild(fileItem);
            });
        },

        /**
         * Initialize search functionality
         */
        initSearch: function() {
            const searchInputs = document.querySelectorAll('.search-input');
            
            searchInputs.forEach(input => {
                const searchHandler = Shikra.utils.debounce(function() {
                    const query = input.value.trim();
                    const searchableElements = document.querySelectorAll('[data-searchable]');
                    
                    searchableElements.forEach(element => {
                        const searchText = element.getAttribute('data-searchable').toLowerCase();
                        const visible = !query || searchText.includes(query.toLowerCase());
                        element.style.display = visible ? '' : 'none';
                    });
                }, 300);
                
                input.addEventListener('input', searchHandler);
            });
        },

        /**
         * Initialize tooltips
         */
        initTooltips: function() {
            document.addEventListener('mouseenter', function(e) {
                if (e.target.hasAttribute('title') && !e.target.hasAttribute('data-tooltip-shown')) {
                    const title = e.target.getAttribute('title');
                    e.target.setAttribute('data-original-title', title);
                    e.target.removeAttribute('title');
                    e.target.setAttribute('data-tooltip-shown', 'true');
                    
                    // Create tooltip element
                    const tooltip = document.createElement('div');
                    tooltip.className = 'tooltip-custom';
                    tooltip.textContent = title;
                    tooltip.style.cssText = `
                        position: absolute;
                        background: rgba(0, 0, 0, 0.8);
                        color: white;
                        padding: 0.5rem;
                        border-radius: 0.25rem;
                        font-size: 0.8rem;
                        z-index: 1070;
                        pointer-events: none;
                        white-space: nowrap;
                        opacity: 0;
                        transition: opacity 0.2s;
                    `;
                    
                    document.body.appendChild(tooltip);
                    
                    // Position tooltip
                    const rect = e.target.getBoundingClientRect();
                    tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
                    tooltip.style.top = rect.top - tooltip.offsetHeight - 8 + 'px';
                    
                    // Show tooltip
                    setTimeout(() => tooltip.style.opacity = '1', 10);
                    
                    e.target._tooltip = tooltip;
                }
            }, true);
            
            document.addEventListener('mouseleave', function(e) {
                if (e.target._tooltip) {
                    e.target._tooltip.remove();
                    delete e.target._tooltip;
                    e.target.removeAttribute('data-tooltip-shown');
                    if (e.target.hasAttribute('data-original-title')) {
                        e.target.setAttribute('title', e.target.getAttribute('data-original-title'));
                        e.target.removeAttribute('data-original-title');
                    }
                }
            }, true);
        },

        /**
         * Bind global events
         */
        bindGlobalEvents: function() {
            // Handle copy buttons
            document.addEventListener('click', function(e) {
                if (e.target.matches('[data-copy]') || e.target.closest('[data-copy]')) {
                    const copyButton = e.target.matches('[data-copy]') ? e.target : e.target.closest('[data-copy]');
                    const text = copyButton.getAttribute('data-copy');
                    Shikra.utils.copyToClipboard(text);
                }
            });

            // Handle refresh buttons
            document.addEventListener('click', function(e) {
                if (e.target.matches('[data-refresh]') || e.target.closest('[data-refresh]')) {
                    const refreshButton = e.target.matches('[data-refresh]') ? e.target : e.target.closest('[data-refresh]');
                    const target = refreshButton.getAttribute('data-refresh');
                    Shikra.ui.refreshComponent(target);
                }
            });

            // Handle analysis submission
            document.addEventListener('submit', function(e) {
                if (e.target.matches('#analysis-form')) {
                    e.preventDefault();
                    Shikra.ui.handleAnalysisSubmission(e.target);
                }
            });

            // Handle analysis cancellation
            document.addEventListener('click', function(e) {
                if (e.target.matches('[data-cancel-analysis]') || e.target.closest('[data-cancel-analysis]')) {
                    const cancelButton = e.target.matches('[data-cancel-analysis]') ? e.target : e.target.closest('[data-cancel-analysis]');
                    const analysisId = cancelButton.getAttribute('data-cancel-analysis');
                    if (confirm('Are you sure you want to cancel this analysis?')) {
                        Shikra.ui.cancelAnalysis(analysisId);
                    }
                }
            });
        },

        /**
         * Handle analysis form submission
         */
        handleAnalysisSubmission: function(form) {
            const formData = new FormData(form);
            const submitBtn = form.querySelector('[type="submit"]');
            const originalText = submitBtn.textContent;

            // Show loading state
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Submitting...';

            Shikra.api.submitAnalysis(formData)
                .then(response => {
                    if (response.success) {
                        Shikra.notifications.show('Analysis submitted successfully', 'success');
                        if (response.analysis_id) {
                            // Redirect to analysis page
                            window.location.href = `/analyses/${response.analysis_id}`;
                        }
                    } else {
                        Shikra.notifications.show(response.message || 'Submission failed', 'danger');
                    }
                })
                .catch(error => {
                    console.error('Analysis submission error:', error);
                    Shikra.notifications.show('Failed to submit analysis', 'danger');
                })
                .finally(() => {
                    // Restore button state
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalText;
                });
        },

        /**
         * Cancel analysis
         */
        cancelAnalysis: function(analysisId) {
            Shikra.api.cancelAnalysis(analysisId)
                .then(response => {
                    if (response.success) {
                        Shikra.notifications.show('Analysis cancelled', 'info');
                        // Refresh the page or update status
                        location.reload();
                    } else {
                        Shikra.notifications.show(response.message || 'Failed to cancel analysis', 'danger');
                    }
                })
                .catch(error => {
                    console.error('Analysis cancellation error:', error);
                    Shikra.notifications.show('Failed to cancel analysis', 'danger');
                });
        },

        /**
         * Refresh component data
         */
        refreshComponent: function(componentId) {
            const component = document.getElementById(componentId);
            if (!component) return;

            const refreshUrl = component.getAttribute('data-refresh-url');
            if (!refreshUrl) return;

            // Add loading indicator
            component.classList.add('loading');

            fetch(refreshUrl, {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.text())
            .then(html => {
                component.innerHTML = html;
                component.classList.remove('loading');
            })
            .catch(error => {
                console.error('Component refresh error:', error);
                component.classList.remove('loading');
                Shikra.notifications.show('Failed to refresh component', 'warning');
            });
        },

        /**
         * Show loading spinner
         */
        showLoading: function(element) {
            if (typeof element === 'string') {
                element = document.getElementById(element);
            }
            
            if (element) {
                element.classList.add('loading');
            }
        },

        /**
         * Hide loading spinner
         */
        hideLoading: function(element) {
            if (typeof element === 'string') {
                element = document.getElementById(element);
            }
            
            if (element) {
                element.classList.remove('loading');
            }
        }
    };

    // ===== NOTIFICATION SYSTEM =====
    Shikra.notifications = {
        /**
         * Show notification
         */
        show: function(message, type = 'info', duration = 5000) {
            const notification = {
                id: Shikra.utils.generateId(),
                message: message,
                type: type,
                timestamp: new Date()
            };

            Shikra.state.notifications.push(notification);
            this.render(notification);

            if (duration > 0) {
                setTimeout(() => {
                    this.hide(notification.id);
                }, duration);
            }

            return notification.id;
        },

        /**
         * Render notification
         */
        render: function(notification) {
            let container = document.getElementById('notifications-container');
            if (!container) {
                container = document.createElement('div');
                container.id = 'notifications-container';
                container.className = 'notifications-container';
                container.style.cssText = `
                    position: fixed;
                    top: 1rem;
                    right: 1rem;
                    z-index: 1060;
                    max-width: 400px;
                `;
                document.body.appendChild(container);
            }

            const element = document.createElement('div');
            element.id = notification.id;
            element.className = `alert alert-${this.getBootstrapType(notification.type)} alert-dismissible`;
            element.style.cssText = `
                margin-bottom: 0.5rem;
                animation: slideInRight 0.3s ease;
            `;
            
            element.innerHTML = `
                <div class="d-flex align-items-start">
                    <i class="${Shikra.utils.getSeverityIcon(notification.type)} me-2"></i>
                    <div class="flex-grow-1">
                        ${Shikra.utils.escapeHtml(notification.message)}
                    </div>
                    <button type="button" class="btn-close ms-2" data-notification-id="${notification.id}">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
            `;

            element.querySelector('.btn-close').addEventListener('click', () => {
                this.hide(notification.id);
            });

            container.appendChild(element);
        },

        /**
         * Convert notification type to Bootstrap alert type
         */
        getBootstrapType: function(type) {
            const typeMap = {
                'success': 'success',
                'danger': 'danger',
                'warning': 'warning',
                'info': 'info',
                'error': 'danger'
            };
            return typeMap[type] || 'info';
        },

        /**
         * Hide notification
         */
        hide: function(notificationId) {
            const element = document.getElementById(notificationId);
            if (element) {
                element.style.animation = 'slideOutRight 0.3s ease';
                setTimeout(() => {
                    element.remove();
                }, 300);
            }

            // Remove from state
            Shikra.state.notifications = Shikra.state.notifications.filter(
                n => n.id !== notificationId
            );
        },

        /**
         * Clear all notifications
         */
        clear: function() {
            const container = document.getElementById('notifications-container');
            if (container) {
                container.innerHTML = '';
            }
            Shikra.state.notifications = [];
        }
    };

    // ===== WEBSOCKET CONNECTION =====
    Shikra.websocket = {
        /**
         * Connect to WebSocket
         */
        connect: function() {
            if (Shikra.state.websocket) {
                return;
            }

            const wsUrl = `${Shikra.config.wsBaseUrl}/ws/updates`;
            
            try {
                Shikra.state.websocket = new WebSocket(wsUrl);

                Shikra.state.websocket.onopen = function() {
                    console.log('WebSocket connected');
                    Shikra.notifications.show('Connected to real-time updates', 'success', 3000);
                };

                Shikra.state.websocket.onmessage = function(event) {
                    try {
                        const data = JSON.parse(event.data);
                        Shikra.websocket.handleMessage(data);
                    } catch (error) {
                        console.error('WebSocket message parse error:', error);
                    }
                };

                Shikra.state.websocket.onclose = function() {
                    console.log('WebSocket disconnected');
                    Shikra.state.websocket = null;
                    
                    // Try to reconnect after 5 seconds
                    setTimeout(() => {
                        Shikra.websocket.connect();
                    }, 5000);
                };

                Shikra.state.websocket.onerror = function(error) {
                    console.error('WebSocket error:', error);
                };

            } catch (error) {
                console.error('WebSocket connection failed:', error);
            }
        },

        /**
         * Handle WebSocket message
         */
        handleMessage: function(data) {
            switch (data.type) {
                case 'analysis_status':
                    if (Shikra.analysis.analysisId === data.analysis_id) {
                        Shikra.analysis.updateAnalysisStatus(data.status);
                    }
                    
                    if (data.status === 'completed') {
                        Shikra.notifications.show(`Analysis completed`, 'success');
                        if (Shikra.analysis.analysisId === data.analysis_id) {
                            Shikra.analysis.loadAnalysisData();
                        }
                    } else if (data.status === 'failed') {
                        Shikra.notifications.show(`Analysis failed: ${data.error || 'Unknown error'}`, 'danger');
                    }
                    break;

                case 'monitoring_event':
                    if (Shikra.state.monitoringActive && Shikra.monitoring.analysisId === data.analysis_id) {
                        Shikra.monitoring.processEvents([data.event]);
                    }
                    break;

                case 'system_alert':
                    Shikra.notifications.show(data.message, data.severity || 'warning');
                    break;

                case 'vm_status':
                    // Update VM status display if present
                    const vmStatusElement = document.getElementById('vm-status');
                    if (vmStatusElement) {
                        vmStatusElement.textContent = data.status;
                        vmStatusElement.className = `vm-status status-${data.status.toLowerCase()}`;
                    }
                    break;

                default:
                    console.log('Unknown WebSocket message type:', data.type);
            }
        },

        /**
         * Send message
         */
        send: function(data) {
            if (Shikra.state.websocket && Shikra.state.websocket.readyState === WebSocket.OPEN) {
                Shikra.state.websocket.send(JSON.stringify(data));
            }
        },

        /**
         * Disconnect
         */
        disconnect: function() {
            if (Shikra.state.websocket) {
                Shikra.state.websocket.close();
                Shikra.state.websocket = null;
            }
        }
    };

    // ===== INITIALIZATION =====
    document.addEventListener('DOMContentLoaded', function() {
        // Initialize UI components
        Shikra.ui.init();

        // Connect WebSocket if supported
        if (window.WebSocket) {
            Shikra.websocket.connect();
        }

        // Initialize specific page functionality based on page type
        const pageType = document.body.getAttribute('data-page-type');
        const analysisId = document.body.getAttribute('data-analysis-id');

        switch (pageType) {
            case 'analysis-detail':
                if (analysisId) {
                    Shikra.analysis.init(analysisId);
                }
                break;
                
            case 'analysis-monitoring':
                if (analysisId) {
                    Shikra.monitoring.init(analysisId);
                    Shikra.state.monitoringActive = true;
                }
                break;
                
            case 'dashboard':
                // Initialize dashboard-specific functionality
                Shikra.ui.initDashboard();
                break;
        }

        // Add CSS animations if not already present
        if (!document.querySelector('#shikra-animations')) {
            const style = document.createElement('style');
            style.id = 'shikra-animations';
            style.textContent = `
                @keyframes slideInRight {
                    from { opacity: 0; transform: translateX(100%); }
                    to { opacity: 1; transform: translateX(0); }
                }
                @keyframes slideOutRight {
                    from { opacity: 1; transform: translateX(0); }
                    to { opacity: 0; transform: translateX(100%); }
                }
                .loading {
                    position: relative;
                    pointer-events: none;
                    opacity: 0.6;
                }
                .loading::after {
                    content: '';
                    position: absolute;
                    top: 50%;
                    left: 50%;
                    width: 20px;
                    height: 20px;
                    margin: -10px 0 0 -10px;
                    border: 2px solid #f3f3f3;
                    border-top: 2px solid #007bff;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                    z-index: 10;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                .tooltip-custom {
                    position: absolute;
                    background: rgba(0, 0, 0, 0.8);
                    color: white;
                    padding: 0.5rem;
                    border-radius: 0.25rem;
                    font-size: 0.8rem;
                    z-index: 1070;
                    pointer-events: none;
                    white-space: nowrap;
                    transition: opacity 0.2s;
                }
                .event-item {
                    border-left: 4px solid #dee2e6;
                    padding: 0.75rem;
                    margin-bottom: 0.5rem;
                    background: #f8f9fa;
                    border-radius: 0.25rem;
                }
                .event-item.event-high {
                    border-left-color: #fd7e14;
                }
                .event-item.event-medium {
                    border-left-color: #ffc107;
                }
                .event-item.event-low {
                    border-left-color: #28a745;
                }
                .event-list {
                    max-height: 500px;
                    overflow-y: auto;
                    border: 1px solid #dee2e6;
                    border-radius: 0.25rem;
                    padding: 0.5rem;
                }
                .status-indicator {
                    display: inline-block;
                    width: 8px;
                    height: 8px;
                    border-radius: 50%;
                    margin-right: 0.5rem;
                }
                .status-indicator.status-running {
                    background-color: #007bff;
                    animation: pulse 1.5s infinite;
                }
                .status-indicator.status-completed {
                    background-color: #28a745;
                }
                .status-indicator.status-failed {
                    background-color: #dc3545;
                }
                .status-indicator.status-cancelled {
                    background-color: #6c757d;
                }
                @keyframes pulse {
                    0% { box-shadow: 0 0 0 0 rgba(0, 123, 255, 0.7); }
                    70% { box-shadow: 0 0 0 10px rgba(0, 123, 255, 0); }
                    100% { box-shadow: 0 0 0 0 rgba(0, 123, 255, 0); }
                }
                .score-bar {
                    height: 20px;
                    border-radius: 10px;
                    transition: width 0.3s ease;
                }
                .score-bar.score-high { background-color: #dc3545; }
                .score-bar.score-medium { background-color: #fd7e14; }
                .score-bar.score-low { background-color: #ffc107; }
                .score-bar.score-minimal { background-color: #28a745; }
            `;
            document.head.appendChild(style);
        }

        console.log('Shikra Framework initialized');
    });

    // ===== GLOBAL ERROR HANDLING =====
    window.addEventListener('error', function(event) {
        console.error('Global error:', event.error);
        Shikra.notifications.show('An unexpected error occurred', 'danger');
    });

    window.addEventListener('unhandledrejection', function(event) {
        console.error('Unhandled promise rejection:', event.reason);
        Shikra.notifications.show('An unexpected error occurred', 'danger');
        event.preventDefault();
    });

    // ===== CLEANUP ON PAGE UNLOAD =====
    window.addEventListener('beforeunload', function() {
        // Close WebSocket connection
        Shikra.websocket.disconnect();
        
        // Clear intervals
        if (Shikra.analysis.statusInterval) {
            clearInterval(Shikra.analysis.statusInterval);
        }
        if (Shikra.monitoring.statusInterval) {
            clearInterval(Shikra.monitoring.statusInterval);
        }
        
        // Destroy charts
        Object.values(Shikra.state.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
        
        // Stop monitoring
        if (Shikra.monitoring.stop) {
            Shikra.monitoring.stop();
        }
    });

})();