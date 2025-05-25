// static/js/shikra.js - Custom JavaScript for Shikra Web Interface

/**
 * Shikra Web Interface JavaScript
 * Provides interactive functionality for the malware analysis platform
 */

// Global Shikra namespace
window.Shikra = window.Shikra || {};

// Configuration and constants
Shikra.config = {
    refreshInterval: 30000, // 30 seconds
    maxRetries: 3,
    apiTimeout: 10000,
    webSocketUrl: window.location.protocol === 'https:' ? 'wss://' : 'ws://' + window.location.host
};

// WebSocket connection management
Shikra.WebSocket = {
    socket: null,
    connected: false,
    reconnectAttempts: 0,
    maxReconnectAttempts: 5,
    
    connect: function() {
        if (typeof io !== 'undefined') {
            this.socket = io(Shikra.config.webSocketUrl);
            this.setupEventHandlers();
        }
    },
    
    setupEventHandlers: function() {
        if (!this.socket) return;
        
        this.socket.on('connect', () => {
            console.log('Connected to Shikra WebSocket');
            this.connected = true;
            this.reconnectAttempts = 0;
            this.showConnectionStatus('Connected', 'success');
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from Shikra WebSocket');
            this.connected = false;
            this.showConnectionStatus('Disconnected', 'warning');
            this.attemptReconnect();
        });
        
        this.socket.on('analysis_progress', (data) => {
            this.handleProgressUpdate(data);
        });
        
        this.socket.on('analysis_complete', (data) => {
            this.handleAnalysisComplete(data);
        });
        
        this.socket.on('system_alert', (data) => {
            this.showAlert(data.message, data.type || 'info');
        });
    },
    
    attemptReconnect: function() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            setTimeout(() => {
                this.reconnectAttempts++;
                console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
                this.connect();
            }, 5000 * this.reconnectAttempts);
        }
    },
    
    joinAnalysis: function(analysisId) {
        if (this.socket && this.connected) {
            this.socket.emit('join_analysis', { analysis_id: analysisId });
        }
    },
    
    leaveAnalysis: function(analysisId) {
        if (this.socket && this.connected) {
            this.socket.emit('leave_analysis', { analysis_id: analysisId });
        }
    },
    
    handleProgressUpdate: function(data) {
        const progressBar = document.getElementById('progressBar');
        const currentPhase = document.getElementById('currentPhase');
        
        if (progressBar) {
            progressBar.style.width = data.progress + '%';
            progressBar.textContent = data.progress + '%';
            progressBar.setAttribute('aria-valuenow', data.progress);
        }
        
        if (currentPhase && data.phase) {
            currentPhase.textContent = data.phase;
        }
        
        // Update any dashboard elements
        this.updateDashboardProgress(data);
    },
    
    handleAnalysisComplete: function(data) {
        this.showAlert(`Analysis ${data.analysis_id} completed successfully!`, 'success');
        
        // Redirect to results page if we're on progress page
        if (window.location.pathname.includes('/analysis/') && window.location.pathname.includes(data.analysis_id)) {
            setTimeout(() => {
                window.location.href = `/analysis/${data.analysis_id}`;
            }, 2000);
        }
        
        // Refresh dashboard if we're on dashboard
        if (window.location.pathname === '/' || window.location.pathname === '/dashboard') {
            setTimeout(() => {
                window.location.reload();
            }, 3000);
        }
    },
    
    updateDashboardProgress: function(data) {
        const activeAnalysisCard = document.querySelector(`[data-analysis-id="${data.analysis_id}"]`);
        if (activeAnalysisCard) {
            const progressBar = activeAnalysisCard.querySelector('.progress-bar');
            const phaseText = activeAnalysisCard.querySelector('.analysis-phase');
            
            if (progressBar) {
                progressBar.style.width = data.progress + '%';
            }
            
            if (phaseText) {
                phaseText.textContent = data.phase;
            }
        }
    },
    
    showConnectionStatus: function(message, type) {
        // Only show if there's a status indicator element
        const statusIndicator = document.getElementById('connectionStatus');
        if (statusIndicator) {
            statusIndicator.textContent = message;
            statusIndicator.className = `badge bg-${type}`;
        }
    }
};

// API utilities
Shikra.API = {
    baseUrl: '/api',
    
    request: function(endpoint, options = {}) {
        const url = this.baseUrl + endpoint;
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            timeout: Shikra.config.apiTimeout
        };
        
        const config = { ...defaultOptions, ...options };
        
        return fetch(url, config)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            })
            .catch(error => {
                console.error('API request failed:', error);
                throw error;
            });
    },
    
    getAnalysisList: function(page = 1, perPage = 20) {
        return this.request(`/analyses?page=${page}&per_page=${perPage}`);
    },
    
    getAnalysisDetail: function(analysisId) {
        return this.request(`/analysis/${analysisId}`);
    },
    
    getAnalysisStatus: function(analysisId) {
        return this.request(`/status/${analysisId}`);
    },
    
    searchIOCs: function(query, type = 'all', limit = 100) {
        return this.request(`/search/ioc?q=${encodeURIComponent(query)}&type=${type}&limit=${limit}`);
    }
};

// UI utilities
Shikra.UI = {
    showAlert: function(message, type = 'info', duration = 5000) {
        const alertContainer = document.getElementById('alertContainer') || document.body;
        const alertId = 'alert-' + Date.now();
        
        const alertHTML = `
            <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        
        // Create temporary container if none exists
        let container = document.getElementById('alertContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'alertContainer';
            container.style.position = 'fixed';
            container.style.top = '20px';
            container.style.right = '20px';
            container.style.zIndex = '9999';
            container.style.maxWidth = '400px';
            document.body.appendChild(container);
        }
        
        container.insertAdjacentHTML('beforeend', alertHTML);
        
        // Auto-dismiss after duration
        if (duration > 0) {
            setTimeout(() => {
                const alertElement = document.getElementById(alertId);
                if (alertElement) {
                    const bsAlert = new bootstrap.Alert(alertElement);
                    bsAlert.close();
                }
            }, duration);
        }
    },
    
    showModal: function(title, content, options = {}) {
        const modalId = 'modal-' + Date.now();
        const modalHTML = `
            <div class="modal fade" id="${modalId}" tabindex="-1">
                <div class="modal-dialog ${options.size || ''}">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">${title}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            ${content}
                        </div>
                        ${options.footer ? `<div class="modal-footer">${options.footer}</div>` : ''}
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', modalHTML);
        const modal = new bootstrap.Modal(document.getElementById(modalId));
        modal.show();
        
        // Clean up after modal is hidden
        document.getElementById(modalId).addEventListener('hidden.bs.modal', function() {
            this.remove();
        });
        
        return modal;
    },
    
    copyToClipboard: function(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                this.showAlert('Copied to clipboard!', 'success', 2000);
            }).catch(() => {
                this.fallbackCopyToClipboard(text);
            });
        } else {
            this.fallbackCopyToClipboard(text);
        }
    },
    
    fallbackCopyToClipboard: function(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            this.showAlert('Copied to clipboard!', 'success', 2000);
        } catch (err) {
            this.showAlert('Failed to copy to clipboard', 'danger', 3000);
        }
        
        document.body.removeChild(textArea);
    },
    
    formatFileSize: function(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    
    formatDateTime: function(timestamp) {
        if (!timestamp) return 'N/A';
        
        try {
            const date = new Date(timestamp);
            return date.toLocaleString();
        } catch (error) {
            return timestamp;
        }
    },
    
    truncateText: function(text, maxLength = 50) {
        if (!text || text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }
};

// Analysis-specific utilities
Shikra.Analysis = {
    refreshStatus: function(analysisId, callback) {
        Shikra.API.getAnalysisStatus(analysisId)
            .then(data => {
                if (callback) callback(null, data);
                
                // Update UI elements
                this.updateStatusUI(data);
            })
            .catch(error => {
                console.error('Failed to refresh analysis status:', error);
                if (callback) callback(error, null);
            });
    },
    
    updateStatusUI: function(statusData) {
        // Update progress bars
        const progressBars = document.querySelectorAll('[data-analysis-progress]');
        progressBars.forEach(bar => {
            if (bar.dataset.analysisId === statusData.analysis_id) {
                bar.style.width = statusData.progress + '%';
                bar.textContent = statusData.progress + '%';
            }
        });
        
        // Update status badges
        const statusBadges = document.querySelectorAll('[data-analysis-status]');
        statusBadges.forEach(badge => {
            if (badge.dataset.analysisId === statusData.analysis_id) {
                badge.textContent = statusData.status;
                badge.className = `badge bg-${this.getStatusColor(statusData.status)}`;
            }
        });
    },
    
    getStatusColor: function(status) {
        const colorMap = {
            'completed': 'success',
            'running': 'primary',
            'queued': 'warning',
            'failed': 'danger',
            'cancelled': 'secondary'
        };
        return colorMap[status] || 'secondary';
    },
    
    exportAnalysis: function(analysisId, format) {
        const exportUrl = `/export/${analysisId}/${format}`;
        
        // Create temporary link for download
        const link = document.createElement('a');
        link.href = exportUrl;
        link.download = `analysis_${analysisId}.${format}`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        Shikra.UI.showAlert(`Exporting analysis as ${format.toUpperCase()}...`, 'info', 3000);
    }
};

// Search functionality
Shikra.Search = {
    performSearch: function(query, type = 'all') {
        const searchForm = document.getElementById('searchForm');
        const resultsContainer = document.getElementById('searchResults');
        const loadingSpinner = document.getElementById('searchLoading');
        
        if (loadingSpinner) {
            loadingSpinner.style.display = 'block';
        }
        
        if (resultsContainer) {
            resultsContainer.innerHTML = '';
        }
        
        // Determine search endpoint based on type
        let searchPromise;
        if (type === 'ioc') {
            searchPromise = Shikra.API.searchIOCs(query, 'all', 50);
        } else {
            // For general search, we'd need to implement a general search endpoint
            searchPromise = Promise.resolve({ results: [], total_results: 0 });
        }
        
        searchPromise
            .then(data => {
                this.displaySearchResults(data, resultsContainer);
            })
            .catch(error => {
                console.error('Search failed:', error);
                Shikra.UI.showAlert('Search failed. Please try again.', 'danger');
            })
            .finally(() => {
                if (loadingSpinner) {
                    loadingSpinner.style.display = 'none';
                }
            });
    },
    
    displaySearchResults: function(data, container) {
        if (!container) return;
        
        if (!data.results || data.results.length === 0) {
            container.innerHTML = `
                <div class="text-center py-5">
                    <i class="fas fa-search fa-3x text-muted mb-3"></i>
                    <h4>No results found</h4>
                    <p class="text-muted">Try adjusting your search terms.</p>
                </div>
            `;
            return;
        }
        
        const resultsHTML = data.results.map(result => `
            <div class="search-result">
                <div class="row">
                    <div class="col-md-8">
                        <h6>
                            <a href="${result.analysis_url || '#'}">
                                <i class="fas fa-file"></i> ${result.indicator || result.filename || 'Unknown'}
                            </a>
                        </h6>
                        <p class="text-muted mb-2">
                            Type: ${result.type || 'Unknown'} | 
                            Analysis: ${result.analysis_id || 'Unknown'}
                        </p>
                        ${result.context ? `<small class="text-muted">${result.context}</small>` : ''}
                    </div>
                    <div class="col-md-4 text-end">
                        <a href="${result.analysis_url || '#'}" class="btn btn-sm btn-outline-primary">
                            <i class="fas fa-eye"></i> View Analysis
                        </a>
                    </div>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = `
            <div class="mb-3">
                <h5>Search Results (${data.total_results || data.results.length} found)</h5>
            </div>
            ${resultsHTML}
        `;
    }
};

// File upload enhancements
Shikra.FileUpload = {
    setupDragDrop: function(elementId) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        element.addEventListener('dragover', (e) => {
            e.preventDefault();
            element.classList.add('dragover');
        });
        
        element.addEventListener('dragleave', (e) => {
            e.preventDefault();
            element.classList.remove('dragover');
        });
        
        element.addEventListener('drop', (e) => {
            e.preventDefault();
            element.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.handleFileSelection(files[0], elementId);
            }
        });
    },
    
    handleFileSelection: function(file, elementId) {
        const fileInput = document.querySelector(`#${elementId} input[type="file"]`);
        const preview = document.getElementById(`${elementId}Preview`);
        
        if (fileInput) {
            // Create a new FileList with the dropped file
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(file);
            fileInput.files = dataTransfer.files;
        }
        
        if (preview) {
            this.showFilePreview(file, preview);
        }
        
        // Validate file
        this.validateFile(file);
    },
    
    showFilePreview: function(file, previewElement) {
        const fileInfo = `
            <div class="file-preview">
                <div class="d-flex align-items-center">
                    <i class="fas fa-file fa-2x text-primary me-3"></i>
                    <div>
                        <strong>${file.name}</strong><br>
                        <small class="text-muted">
                            ${Shikra.UI.formatFileSize(file.size)} | ${file.type || 'Unknown type'}
                        </small>
                    </div>
                </div>
            </div>
        `;
        previewElement.innerHTML = fileInfo;
    },
    
    validateFile: function(file) {
        const maxSize = 100 * 1024 * 1024; // 100MB
        const allowedTypes = [
            'application/x-msdownload', // .exe
            'application/x-dosexec',    // .exe
            'application/octet-stream', // generic binary
            'application/zip',          // .zip
            'application/x-rar-compressed', // .rar
            'application/x-7z-compressed',  // .7z
            'application/pdf',          // .pdf
            'application/msword',       // .doc
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document' // .docx
        ];
        
        if (file.size > maxSize) {
            Shikra.UI.showAlert('File too large. Maximum size is 100MB.', 'danger');
            return false;
        }
        
        // Note: MIME type detection isn't reliable for all file types
        // Server-side validation is essential
        
        return true;
    }
};

// Dashboard utilities
Shikra.Dashboard = {
    refreshStats: function() {
        // Refresh dashboard statistics
        fetch('/api/dashboard/stats')
            .then(response => response.json())
            .then(data => {
                this.updateStatCards(data);
            })
            .catch(error => {
                console.error('Failed to refresh dashboard stats:', error);
            });
    },
    
    updateStatCards: function(stats) {
        const statElements = {
            'totalAnalyses': stats.total_analyses,
            'activeAnalyses': stats.active_analyses,
            'queuedAnalyses': stats.queued_analyses,
            'completedToday': stats.completed_today
        };
        
        Object.entries(statElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value || 0;
            }
        });
    },
    
    initCharts: function() {
        // Initialize Chart.js charts if Chart is available
        if (typeof Chart !== 'undefined') {
            this.initThreatDistributionChart();
            this.initActivityChart();
        }
    },
    
    initThreatDistributionChart: function() {
        const ctx = document.getElementById('threatChart');
        if (!ctx) return;
        
        // Get data from page context or make API call
        const threatData = window.threatDistribution || {};
        
        if (Object.keys(threatData).length === 0) return;
        
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(threatData),
                datasets: [{
                    data: Object.values(threatData),
                    backgroundColor: [
                        '#dc3545', // Critical - red
                        '#fd7e14', // High - orange
                        '#ffc107', // Medium - yellow
                        '#28a745', // Low - green
                        '#6c757d'  // Minimal - gray
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((context.raw / total) * 100).toFixed(1);
                                return `${context.label}: ${context.raw} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    },
    
    initActivityChart: function() {
        const ctx = document.getElementById('activityChart');
        if (!ctx) return;
        
        // Sample data - replace with actual API data
        const activityData = {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [{
                label: 'Analyses Completed',
                data: [12, 19, 3, 5, 2, 3, 9],
                borderColor: '#007bff',
                backgroundColor: 'rgba(0, 123, 255, 0.1)',
                fill: true,
                tension: 0.4
            }]
        };
        
        new Chart(ctx, {
            type: 'line',
            data: activityData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
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
};

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize WebSocket connection
    Shikra.WebSocket.connect();
    
    // Initialize dashboard charts if on dashboard page
    if (document.getElementById('threatChart') || document.getElementById('activityChart')) {
        Shikra.Dashboard.initCharts();
    }
    
    // Set up file upload drag & drop
    const fileUploadArea = document.querySelector('.file-upload-area');
    if (fileUploadArea) {
        Shikra.FileUpload.setupDragDrop(fileUploadArea.id || 'fileUploadArea');
    }
    
    // Initialize tooltips
    if (typeof bootstrap !== 'undefined') {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function(tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
    
    // Set up auto-refresh for progress pages
    if (window.location.pathname.includes('/analysis/') && document.getElementById('progressBar')) {
        const analysisId = window.location.pathname.split('/').pop();
        if (analysisId) {
            Shikra.WebSocket.joinAnalysis(analysisId);
            
            // Fallback refresh every 10 seconds
            setInterval(() => {
                Shikra.Analysis.refreshStatus(analysisId);
            }, 10000);
        }
    }
    
    // Set up click handlers for copy buttons
    document.addEventListener('click', function(e) {
        if (e.target.matches('.copy-btn') || e.target.closest('.copy-btn')) {
            const button = e.target.matches('.copy-btn') ? e.target : e.target.closest('.copy-btn');
            const textToCopy = button.dataset.copy || button.textContent;
            Shikra.UI.copyToClipboard(textToCopy);
        }
    });
    
    // Set up export buttons
    document.addEventListener('click', function(e) {
        if (e.target.matches('.export-btn') || e.target.closest('.export-btn')) {
            const button = e.target.matches('.export-btn') ? e.target : e.target.closest('.export-btn');
            const analysisId = button.dataset.analysisId;
            const format = button.dataset.format;
            
            if (analysisId && format) {
                Shikra.Analysis.exportAnalysis(analysisId, format);
            }
        }
    });
    
    // Set up search form if present
    const searchForm = document.getElementById('searchForm');
    if (searchForm) {
        searchForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(searchForm);
            const query = formData.get('query');
            const type = formData.get('search_type');
            
            if (query) {
                Shikra.Search.performSearch(query, type);
            }
        });
    }
    
    // Set up periodic dashboard refresh
    if (window.location.pathname === '/' || window.location.pathname === '/dashboard') {
        setInterval(() => {
            Shikra.Dashboard.refreshStats();
        }, Shikra.config.refreshInterval);
    }
    
    // Global error handler
    window.addEventListener('error', function(e) {
        console.error('Global error:', e.error);
        // Don't show alerts for every error, but log them
    });
    
    // Handle browser back/forward navigation
    window.addEventListener('popstate', function(e) {
        // Clean up any WebSocket room subscriptions
        if (Shikra.WebSocket.socket && e.state && e.state.analysisId) {
            Shikra.WebSocket.leaveAnalysis(e.state.analysisId);
        }
    });
});

// Utility functions available globally
window.copyToClipboard = Shikra.UI.copyToClipboard.bind(Shikra.UI);
window.showAlert = Shikra.UI.showAlert.bind(Shikra.UI);
window.formatFileSize = Shikra.UI.formatFileSize.bind(Shikra.UI);
window.formatDateTime = Shikra.UI.formatDateTime.bind(Shikra.UI);

// Export analysis function for global use
window.exportAnalysis = Shikra.Analysis.exportAnalysis.bind(Shikra.Analysis);

// Console info for developers
console.log('%c🛡️ Shikra Malware Analysis Platform', 'color: #007bff; font-size: 16px; font-weight: bold;');
console.log('%cWebSocket Status:', 'color: #28a745; font-weight: bold;', Shikra.WebSocket.connected ? 'Connected' : 'Disconnected');
console.log('%cAvailable APIs:', 'color: #17a2b8; font-weight: bold;', Object.keys(Shikra.API));

// Development helpers (only in debug mode)
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    window.Shikra = Shikra; // Expose for debugging
    
    // Add debug panel
    const debugPanel = document.createElement('div');
    debugPanel.innerHTML = `
        <div id="debugPanel" style="position: fixed; bottom: 10px; right: 10px; background: rgba(0,0,0,0.8); color: white; padding: 10px; border-radius: 5px; font-size: 12px; z-index: 10000; max-width: 300px;">
            <strong>Debug Panel</strong><br>
            WebSocket: <span id="wsStatus">${Shikra.WebSocket.connected ? 'Connected' : 'Disconnected'}</span><br>
            <button onclick="Shikra.WebSocket.connect()" style="background: #007bff; color: white; border: none; padding: 2px 8px; border-radius: 3px; margin-top: 5px;">Reconnect WS</button>
            <button onclick="document.getElementById('debugPanel').remove()" style="background: #dc3545; color: white; border: none; padding: 2px 8px; border-radius: 3px; margin-top: 5px; float: right;">×</button>
        </div>
    `;
    document.body.appendChild(debugPanel);
    
    // Update debug panel WebSocket status
    setInterval(() => {
        const wsStatus = document.getElementById('wsStatus');
        if (wsStatus) {
            wsStatus.textContent = Shikra.WebSocket.connected ? 'Connected' : 'Disconnected';
            wsStatus.style.color = Shikra.WebSocket.connected ? '#28a745' : '#dc3545';
        }
    }, 1000);
}