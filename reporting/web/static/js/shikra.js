/*
Shikra Web Interface JavaScript (shikra.js)

Purpose:
This JavaScript file provides interactive functionality for the Shikra malware
analysis web interface. It handles dynamic content updates, user interactions,
API communications, and real-time status updates.

Context in Shikra:
- Client-side functionality for reporting/web/app.py Flask application
- Interactive features for analysis result browsing
- Real-time updates and WebSocket communications
- API integration for dynamic content loading

Key Features:
- AJAX requests for dynamic content loading
- Real-time analysis status updates via WebSocket
- Interactive charts and visualization controls
- Search and filtering functionality
- File upload handling with progress indicators
- Responsive user interface interactions
*/

// Global Shikra application object
const Shikra = {
    // Configuration and settings
    config: {
        apiBaseUrl: '/api', // Relative URL for API requests
        // Ensure wsUrl is correctly configured for your deployment environment
        // For local development, it might be 'ws://localhost:5000/ws' or 'ws://127.0.0.1:5000/ws'
        // For production, it should use wss:// and your domain.
        wsUrl: (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws',
        refreshInterval: 10000, // Default refresh interval for polling (e.g., for active analyses)
        defaultChartColors: ['#0d6efd', '#6c757d', '#198754', '#ffc107', '#dc3545', '#0dcaf0']
    },
    
    socket: null, // WebSocket connection object
    activeTimers: {}, // To store any active timers (e.g., for polling)

    // Initialize application
    init: function() {
        this.setupEventListeners();
        this.initializeComponents();
        // WebSocket connection is often initiated by specific pages (e.g., progress page)
        // rather than globally, but a general connect method is good to have.
        // this.connectWebSocket(); // Potentially connect if on a relevant page or if global updates are needed
        console.log('Shikra web interface initialized. API URL:', this.config.apiBaseUrl, 'WS URL:', this.config.wsUrl);
    },
    
    // Set up event listeners for user interactions
    setupEventListeners: function() {
        // Example: Listener for a hypothetical dashboard refresh button
        const refreshDashboardButton = document.getElementById('refreshDashboard');
        if (refreshDashboardButton) {
            refreshDashboardButton.addEventListener('click', () => {
                console.log('Dashboard refresh triggered.');
                // this.loadDashboardData(); // Assuming such a function exists
            });
        }

        // Example: Sample submission form (if one exists with this ID)
        const sampleForm = document.getElementById('sampleSubmissionForm');
        if (sampleForm) {
            sampleForm.addEventListener('submit', (event) => {
                event.preventDefault();
                const formData = new FormData(sampleForm);
                this.handleFileUpload(formData);
            });
        }
        // Add more specific event listeners for forms, buttons, etc. as needed
        // e.g., search form submission, filter changes on analysis list
    },
    
    // Initialize UI components and widgets
    initializeComponents: function() {
        // Example: Initialize Bootstrap tooltips if used
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });

        // Example: Initialize charts on pages that have them (e.g., dashboard)
        if (document.getElementById('threatChart')) {
            // Data would typically be fetched or passed via template
            // const threatData = { labels: [], datasets: [{ data: [] }] }; 
            // this.renderVisualization('threatChart', threatData, 'pie');
            console.log('Threat chart element found, ready for rendering.');
        }
        // Initialize other components like modals, progress bars based on page content
    },
    
    // WebSocket connection for real-time updates
    connectWebSocket: function(analysisId = null) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            console.log('WebSocket already connected.');
            if (analysisId) this.joinAnalysisRoom(analysisId); // If re-connecting or joining a specific room
            return;
        }

        this.socket = new WebSocket(this.config.wsUrl);

        this.socket.onopen = () => {
            console.log('WebSocket connection established.');
            if (analysisId) {
                this.joinAnalysisRoom(analysisId);
            }
            // Example: Send a generic join message or authentication token if needed
            // this.socket.send(JSON.stringify({ type: 'join', client_type: 'web_ui' }));
        };

        this.socket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                console.log('WebSocket message received:', message);
                if (message.type === 'analysis_progress' && message.analysis_id) {
                    this.updateAnalysisStatus(message.analysis_id, message);
                } else if (message.type === 'analysis_complete' && message.analysis_id) {
                    this.handleAnalysisCompletion(message.analysis_id, message.report_url);
                }
                // Handle other message types (e.g., system notifications)
            } catch (e) {
                console.error('Error processing WebSocket message:', e);
            }
        };

        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
            // Optionally, implement retry logic here or notify the user
        };

        this.socket.onclose = (event) => {
            console.log('WebSocket connection closed:', event.reason, 'Code:', event.code);
            this.socket = null;
            // Optionally, attempt to reconnect after a delay
            // setTimeout(() => this.connectWebSocket(analysisId), 5000);
        };
    },

    joinAnalysisRoom: function(analysisId) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify({ type: 'join_analysis_room', analysis_id: analysisId }));
            console.log(`Sent join request for analysis room: ${analysisId}`);
        } else {
            console.warn('WebSocket not connected. Cannot join analysis room.');
            // Optionally, queue the join request or attempt to connect first
        }
    },
    
    // API communication functions
    apiRequest: async function(endpoint, method = 'GET', data = null, headers = {}) {
        const url = `${this.config.apiBaseUrl}${endpoint}`;
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                // Add CSRF token if your Flask app uses Flask-WTF or similar
                // 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content'),
                ...headers
            },
        };

        if (data) {
            if (data instanceof FormData) {
                delete options.headers['Content-Type']; // Browser sets it for FormData
                options.body = data;
            } else {
                options.body = JSON.stringify(data);
            }
        }

        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: response.statusText }));
                console.error(`API Error ${response.status}: ${errorData.message || 'Unknown error'}`, errorData);
                this.showNotification(`API Error: ${errorData.message || response.statusText}`, 'danger');
                return null; // Or throw an error
            }
            // Handle cases where response might not have a body (e.g., 204 No Content)
            if (response.status === 204) return true; 
            return await response.json();
        } catch (error) {
            console.error('Network or API request error:', error);
            this.showNotification('Network error. Please try again.', 'danger');
            return null; // Or throw error
        }
    },
    
    // Analysis management functions
    loadAnalysisList: async function(page = 1, filters = {}) {
        const queryParams = new URLSearchParams({ page, ...filters }).toString();
        const data = await this.apiRequest(`/analyses?${queryParams}`);
        if (data && data.analyses) {
            // Code to update the analysis list table in the UI
            // This would involve selecting the table body and populating rows
            console.log('Analyses loaded:', data.analyses, 'Pagination:', data.pagination);
            // Example: updateTableWithAnalyses(data.analyses);
            // Example: updatePaginationControls(data.pagination);
        }
    },
    
    // Real-time status update handling (called by WebSocket or polling)
    updateAnalysisStatus: function(analysisId, statusData) {
        console.log(`Updating status for analysis ${analysisId}:`, statusData);
        const progressBar = document.getElementById(`progressBar-${analysisId}`) || document.getElementById('progressBar'); // General or specific
        const phaseElement = document.getElementById(`currentPhase-${analysisId}`) || document.getElementById('currentPhase');

        if (progressBar) {
            progressBar.style.width = statusData.progress + '%';
            progressBar.textContent = statusData.progress + '%';
        }
        if (phaseElement) {
            phaseElement.textContent = statusData.current_phase || statusData.phase;
        }
        // Further UI updates based on status (e.g., in a list view)
    },

    handleAnalysisCompletion: function(analysisId, reportUrl) {
        console.log(`Analysis ${analysisId} completed. Redirecting to ${reportUrl}`);
        this.showNotification(`Analysis ${analysisId} is complete!`, 'success');
        // If on the progress page for this analysis, redirect
        if (window.location.pathname.includes(`/analysis/${analysisId}/progress`)) {
            window.location.href = reportUrl;
        } else {
            // Optionally, refresh parts of the UI or the analysis list
            // this.loadAnalysisList(); 
        }
    },
    
    // File upload functionality
    handleFileUpload: async function(formData) {
        // Assuming the form has an input with name="sample_file"
        const fileInput = formData.get('sample_file');
        if (!fileInput || fileInput.size === 0) {
            this.showNotification('Please select a file to upload.', 'warning');
            return;
        }

        // Show progress indicator (more advanced would use XMLHttpRequest for progress events)
        this.showNotification('Uploading sample...', 'info');
        
        const response = await this.apiRequest('/submit', 'POST', formData);
        if (response && response.analysis_id) {
            this.showNotification(`Sample submitted. Analysis ID: ${response.analysis_id}`, 'success');
            // Redirect to progress page or update UI
            window.location.href = `/analysis/${response.analysis_id}/progress`;
        } else {
            this.showNotification(response?.error || 'Submission failed. Please try again.', 'danger');
        }
    },
    
    // Search and filtering functionality (example placeholder)
    performSearch: async function(query, searchType = 'all') {
        console.log(`Performing search for: "${query}", type: "${searchType}"`);
        const response = await this.apiRequest('/search', 'POST', { query, search_type: searchType });
        if (response && response.results) {
            // Update UI with search results
            console.log('Search results:', response.results);
            // Example: displaySearchResults(response.results);
            this.showNotification(`${response.results.length} results found.`, 'info');
        } else if (response) {
             this.showNotification('No results found for your search.', 'info');
        }
    },
    
    // Visualization and chart management
    renderVisualization: function(containerId, chartData, chartType) {
        const ctx = document.getElementById(containerId);
        if (!ctx) {
            console.error(`Chart container with ID '${containerId}' not found.`);
            return null;
        }
        try {
            return new Chart(ctx.getContext('2d'), {
                type: chartType, // 'pie', 'bar', 'line', etc.
                data: chartData, // { labels: [...], datasets: [{ label: '', data: [], ...}] }
                options: {
                    responsive: true,
                    maintainAspectRatio: false, // Adjust as needed
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        title: {
                            display: true,
                            text: chartData.datasets[0]?.label || 'Chart' // Use dataset label as title if available
                        }
                    }
                    // Add more Chart.js options as needed
                }
            });
        } catch (e) {
            console.error('Error rendering chart:', e);
            this.showNotification('Could not render visualization.', 'danger');
            return null;
        }
    },
    
    // Notification and alert system (simple example using Bootstrap alerts)
    showNotification: function(message, type = 'info') {
        // Assumes a container for alerts exists in base.html, e.g., <div id="alertContainer" class="container mt-3"></div>
        const alertContainer = document.getElementById('alertContainer') || document.querySelector('main.container');
        if (!alertContainer) {
            console.warn('Alert container not found. Cannot display notification:', message);
            alert(`${type.toUpperCase()}: ${message}`); // Fallback to browser alert
            return;
        }

        const alertType = (type === 'error' ? 'danger' : type); // Map 'error' to 'danger' for Bootstrap
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${alertType} alert-dismissible fade show`;
        alertDiv.setAttribute('role', 'alert');
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        // Prepend to show newest alerts at the top
        if (alertContainer.firstChild) {
            alertContainer.insertBefore(alertDiv, alertContainer.firstChild);
        } else {
            alertContainer.appendChild(alertDiv);
        }

        // Auto-dismiss after some time (e.g., 5 seconds)
        setTimeout(() => {
            // Use Bootstrap's API to dismiss if available, otherwise just remove
            const bsAlert = bootstrap.Alert.getInstance(alertDiv);
            if (bsAlert) {
                bsAlert.close();
            } else {
                alertDiv.remove();
            }
        }, 7000);
    },
    
    // Utility functions
    utils: {
        formatTimestamp: function(isoTimestamp) {
            if (!isoTimestamp) return 'N/A';
            try {
                const date = new Date(isoTimestamp);
                return date.toLocaleString(); // Adjust formatting as needed
            } catch (e) {
                return isoTimestamp; // Return original if parsing fails
            }
        },
        
        formatFileSize: function(bytes) {
            if (bytes === 0) return '0 Bytes';
            if (!bytes || isNaN(parseFloat(bytes)) || !isFinite(bytes)) return 'N/A';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },
        
        // Example: get a color based on score for UI elements
        getScoreColor: function(score) {
            if (score >= 75) return 'danger'; // Bootstrap class suffix
            if (score >= 50) return 'warning';
            if (score >= 25) return 'info';
            return 'success'; // Or 'secondary' for low/benign
        },

        // Example: get a color for threat classification
        getThreatColor: function(classification) {
            const cls = String(classification).toLowerCase();
            if (cls === 'critical' || cls === 'malicious') return 'danger';
            if (cls === 'high' || cls === 'suspicious') return 'warning'; // fd7e14 (orange) might need custom class
            if (cls === 'medium') return 'info'; // ffc107 (yellow) might need custom class
            if (cls === 'low') return 'primary'; // 0dcaf0 (Bootstrap info)
            if (cls === 'benign' || cls === 'clean' || cls === 'safe') return 'success';
            return 'secondary'; // For unknown or informational
        },
        
        // Simple unique ID generator
        generateId: function(prefix = 'shikra-id-') {
            return prefix + Math.random().toString(36).substr(2, 9);
        }
    }
};

// Initialize application when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    Shikra.init();

    // Example: If there's an analysis ID on the page (e.g., progress page), connect WebSocket
    const analysisProgressElement = document.querySelector('[data-analysis-id]');
    if (analysisProgressElement) {
        const analysisId = analysisProgressElement.dataset.analysisId;
        if (analysisId) {
            Shikra.connectWebSocket(analysisId);
        }
    }
});

// Export for module systems (optional, if you plan to use it with bundlers like Webpack/Rollup)
// if (typeof module !== 'undefined' && module.exports) {
//     module.exports = Shikra;
// }
