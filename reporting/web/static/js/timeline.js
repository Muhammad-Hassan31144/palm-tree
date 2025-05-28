// shikra/reporting/web/static/js/timeline.js
// Interactive timeline visualization for Shikra Analysis Framework

(function() {
    'use strict';

    // ===== TIMELINE INTERFACE =====
    window.TimelineInterface = {
        config: {
            containerSelector: '.timeline-container',
            height: 600,
            margin: { top: 20, right: 50, bottom: 50, left: 100 },
            colors: {
                'critical': '#e74c3c',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#20c997',
                'info': '#17a2b8',
                'process': '#3498db',
                'file': '#27ae60',
                'registry': '#9b59b6',
                'network': '#e67e22'
            },
            zoom: {
                enabled: true,
                minScale: 0.1,
                maxScale: 10
            }
        },

        state: {
            data: [],
            filteredData: [],
            svg: null,
            xScale: null,
            yScale: null,
            zoom: null,
            selectedEvent: null,
            filters: {
                categories: [],
                severities: [],
                timeRange: { start: null, end: null },
                searchTerm: ''
            }
        },

        /**
         * Initialize timeline
         */
        init: function(data) {
            if (!data || !Array.isArray(data)) {
                console.warn('Timeline: No valid data provided');
                return;
            }

            this.state.data = this.processData(data);
            this.state.filteredData = [...this.state.data];
            
            this.createContainer();
            this.setupScales();
            this.setupZoom();
            this.bindEvents();
            this.render();
            this.createControls();

            console.log('Timeline initialized with', this.state.data.length, 'events');
        },

        /**
         * Process raw data into timeline format
         */
        processData: function(rawData) {
            return rawData.map((item, index) => ({
                id: item.id || `event_${index}`,
                timestamp: new Date(item.timestamp),
                category: item.category || 'unknown',
                subcategory: item.subcategory || '',
                severity: item.severity || 'info',
                title: item.title || item.description || 'Unknown Event',
                description: item.description || '',
                phase: item.phase || 'unknown',
                details: item.details || {},
                process: item.details?.process || 'Unknown',
                pid: item.details?.pid || '',
                y: Math.random() * 0.8 + 0.1 // Random vertical position for better visualization
            })).sort((a, b) => a.timestamp - b.timestamp);
        },

        /**
         * Create SVG container
         */
        createContainer: function() {
            const container = document.querySelector(this.config.containerSelector);
            if (!container) {
                console.error('Timeline container not found');
                return;
            }

            // Clear existing content
            container.innerHTML = '';

            // Create SVG
            const width = container.clientWidth;
            const height = this.config.height;

            this.state.svg = d3.select(container)
                .append('svg')
                .attr('width', width)
                .attr('height', height)
                .style('background', '#f8f9fa')
                .style('border-radius', '8px');

            // Create main group for zooming/panning
            this.state.mainGroup = this.state.svg
                .append('g')
                .attr('transform', `translate(${this.config.margin.left}, ${this.config.margin.top})`);

            // Create axis groups
            this.state.xAxisGroup = this.state.svg
                .append('g')
                .attr('class', 'x-axis')
                .attr('transform', `translate(${this.config.margin.left}, ${height - this.config.margin.bottom})`);

            this.state.yAxisGroup = this.state.svg
                .append('g')
                .attr('class', 'y-axis')
                .attr('transform', `translate(${this.config.margin.left}, ${this.config.margin.top})`);

            // Add timeline title
            this.state.svg
                .append('text')
                .attr('class', 'timeline-title')
                .attr('x', width / 2)
                .attr('y', 20)
                .attr('text-anchor', 'middle')
                .style('font-size', '16px')
                .style('font-weight', 'bold')
                .style('fill', '#2c3e50')
                .text('Analysis Timeline');
        },

        /**
         * Setup scales
         */
        setupScales: function() {
            if (!this.state.data.length) return;

            const width = this.state.svg.node().clientWidth - this.config.margin.left - this.config.margin.right;
            const height = this.config.height - this.config.margin.top - this.config.margin.bottom;

            // Time scale for X axis
            const timeExtent = d3.extent(this.state.data, d => d.timestamp);
            this.state.xScale = d3.scaleTime()
                .domain(timeExtent)
                .range([0, width]);

            // Linear scale for Y axis (for event distribution)
            this.state.yScale = d3.scaleLinear()
                .domain([0, 1])
                .range([height, 0]);

            // Color scale for categories
            this.state.colorScale = d3.scaleOrdinal()
                .domain(Object.keys(this.config.colors))
                .range(Object.values(this.config.colors));
        },

        /**
         * Setup zoom and pan functionality
         */
        setupZoom: function() {
            if (!this.config.zoom.enabled) return;

            this.state.zoom = d3.zoom()
                .scaleExtent([this.config.zoom.minScale, this.config.zoom.maxScale])
                .on('zoom', (event) => {
                    const transform = event.transform;
                    
                    // Update scales
                    const newXScale = transform.rescaleX(this.state.xScale);
                    
                    // Update main group transform
                    this.state.mainGroup.attr('transform', 
                        `translate(${this.config.margin.left + transform.x}, ${this.config.margin.top}) scale(${transform.k})`
                    );
                    
                    // Update axis
                    this.state.xAxisGroup.call(d3.axisBottom(newXScale));
                    
                    // Update events
                    this.updateEventPositions(newXScale);
                });

            this.state.svg.call(this.state.zoom);
        },

        /**
         * Bind event handlers
         */
        bindEvents: function() {
            // Filter controls
            document.addEventListener('change', (e) => {
                if (e.target.matches('.timeline-filter')) {
                    this.applyFilters();
                }
            });

            // Search input
            const searchInput = document.querySelector('.timeline-search');
            if (searchInput) {
                searchInput.addEventListener('input', this.debounce(() => {
                    this.applyFilters();
                }, 300));
            }

            // Reset zoom button
            const resetZoomBtn = document.querySelector('.timeline-reset-zoom');
            if (resetZoomBtn) {
                resetZoomBtn.addEventListener('click', () => {
                    this.resetZoom();
                });
            }

            // Export button
            const exportBtn = document.querySelector('.timeline-export');
            if (exportBtn) {
                exportBtn.addEventListener('click', () => {
                    this.exportTimeline();
                });
            }

            // Window resize
            window.addEventListener('resize', this.debounce(() => {
                this.resize();
            }, 250));
        },

        /**
         * Render timeline
         */
        render: function() {
            this.renderAxes();
            this.renderEvents();
            this.renderLegend();
            this.renderPhaseLabels();
        },

        /**
         * Render axes
         */
        renderAxes: function() {
            // X axis (time)
            const xAxis = d3.axisBottom(this.state.xScale)
                .tickFormat(d3.timeFormat('%H:%M:%S'))
                .ticks(10);

            this.state.xAxisGroup
                .call(xAxis)
                .selectAll('text')
                .style('font-size', '12px')
                .style('fill', '#495057');

            // Y axis label
            this.state.svg
                .append('text')
                .attr('class', 'y-axis-label')
                .attr('transform', 'rotate(-90)')
                .attr('x', -(this.config.height / 2))
                .attr('y', 20)
                .attr('text-anchor', 'middle')
                .style('font-size', '12px')
                .style('fill', '#6c757d')
                .text('Event Distribution');

            // X axis label
            this.state.svg
                .append('text')
                .attr('class', 'x-axis-label')
                .attr('x', (this.state.svg.node().clientWidth) / 2)
                .attr('y', this.config.height - 10)
                .attr('text-anchor', 'middle')
                .style('font-size', '12px')
                .style('fill', '#6c757d')
                .text('Time');
        },

        /**
         * Render events as circles
         */
        renderEvents: function() {
            const events = this.state.mainGroup
                .selectAll('.timeline-event')
                .data(this.state.filteredData, d => d.id);

            // Remove old events
            events.exit().remove();

            // Add new events
            const newEvents = events.enter()
                .append('g')
                .attr('class', 'timeline-event')
                .attr('transform', d => `translate(${this.state.xScale(d.timestamp)}, ${this.state.yScale(d.y)})`);

            // Add circles
            newEvents.append('circle')
                .attr('r', 0)
                .attr('fill', d => this.getEventColor(d))
                .attr('stroke', '#fff')
                .attr('stroke-width', 2)
                .style('cursor', 'pointer')
                .transition()
                .duration(500)
                .attr('r', d => this.getEventRadius(d));

            // Add hover effects and click handlers
            newEvents
                .on('mouseover', (event, d) => {
                    this.showTooltip(event, d);
                    d3.select(event.currentTarget).select('circle')
                        .transition()
                        .duration(200)
                        .attr('r', this.getEventRadius(d) * 1.5)
                        .attr('stroke-width', 3);
                })
                .on('mouseout', (event, d) => {
                    this.hideTooltip();
                    d3.select(event.currentTarget).select('circle')
                        .transition()
                        .duration(200)
                        .attr('r', this.getEventRadius(d))
                        .attr('stroke-width', 2);
                })
                .on('click', (event, d) => {
                    this.selectEvent(d);
                });

            // Update existing events
            events.merge(newEvents)
                .transition()
                .duration(300)
                .attr('transform', d => `translate(${this.state.xScale(d.timestamp)}, ${this.state.yScale(d.y)})`);
        },

        /**
         * Render legend
         */
        renderLegend: function() {
            const legendData = [
                { category: 'process', label: 'Process' },
                { category: 'file', label: 'File' },
                { category: 'registry', label: 'Registry' },
                { category: 'network', label: 'Network' }
            ];

            const legend = this.state.svg
                .append('g')
                .attr('class', 'legend')
                .attr('transform', `translate(${this.state.svg.node().clientWidth - 150}, 50)`);

            const legendItems = legend.selectAll('.legend-item')
                .data(legendData)
                .enter()
                .append('g')
                .attr('class', 'legend-item')
                .attr('transform', (d, i) => `translate(0, ${i * 25})`);

            legendItems.append('circle')
                .attr('r', 8)
                .attr('fill', d => this.config.colors[d.category])
                .attr('stroke', '#fff')
                .attr('stroke-width', 1);

            legendItems.append('text')
                .attr('x', 15)
                .attr('y', 5)
                .style('font-size', '12px')
                .style('fill', '#495057')
                .text(d => d.label);
        },

        /**
         * Render phase labels
         */
        renderPhaseLabels: function() {
            const phases = this.getPhaseRanges();
            
            const phaseGroups = this.state.mainGroup
                .selectAll('.phase-label')
                .data(phases)
                .enter()
                .append('g')
                .attr('class', 'phase-label');

            // Add phase background rectangles
            phaseGroups.append('rect')
                .attr('x', d => this.state.xScale(d.start))
                .attr('y', -10)
                .attr('width', d => this.state.xScale(d.end) - this.state.xScale(d.start))
                .attr('height', this.state.yScale(0) + 10)
                .attr('fill', (d, i) => d3.schemeCategory10[i % 10])
                .attr('opacity', 0.1);

            // Add phase labels
            phaseGroups.append('text')
                .attr('x', d => (this.state.xScale(d.start) + this.state.xScale(d.end)) / 2)
                .attr('y', -15)
                .attr('text-anchor', 'middle')
                .style('font-size', '10px')
                .style('font-weight', 'bold')
                .style('fill', '#343a40')
                .text(d => d.phase);
        },

        /**
         * Get phase time ranges
         */
        getPhaseRanges: function() {
            const phases = {};
            
            this.state.filteredData.forEach(d => {
                if (!phases[d.phase]) {
                    phases[d.phase] = {
                        phase: d.phase,
                        start: d.timestamp,
                        end: d.timestamp,
                        events: []
                    };
                } else {
                    phases[d.phase].start = d3.min([phases[d.phase].start, d.timestamp]);
                    phases[d.phase].end = d3.max([phases[d.phase].end, d.timestamp]);
                }
                phases[d.phase].events.push(d);
            });

            return Object.values(phases).filter(p => p.phase !== 'unknown');
        },

        /**
         * Create filter controls
         */
        createControls: function() {
            const container = document.querySelector(this.config.containerSelector);
            if (!container) return;

            const controlsHTML = `
                <div class="timeline-controls mb-3">
                    <div class="row">
                        <div class="col-md-3">
                            <label class="form-label">Category Filter</label>
                            <select class="form-control timeline-filter" id="category-filter">
                                <option value="">All Categories</option>
                                <option value="process">Process</option>
                                <option value="file">File</option>
                                <option value="registry">Registry</option>
                                <option value="network">Network</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">Severity Filter</label>
                            <select class="form-control timeline-filter" id="severity-filter">
                                <option value="">All Severities</option>
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                                <option value="info">Info</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label class="form-label">Search Events</label>
                            <input type="text" class="form-control timeline-search" placeholder="Search descriptions...">
                        </div>
                        <div class="col-md-2">
                            <label class="form-label">&nbsp;</label>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-outline-primary timeline-reset-zoom" title="Reset Zoom">
                                    <i class="fas fa-search-minus"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-success timeline-export" title="Export Timeline">
                                    <i class="fas fa-download"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            container.insertAdjacentHTML('beforebegin', controlsHTML);
        },

        /**
         * Apply filters to timeline data
         */
        applyFilters: function() {
            const categoryFilter = document.getElementById('category-filter')?.value || '';
            const severityFilter = document.getElementById('severity-filter')?.value || '';
            const searchTerm = document.querySelector('.timeline-search')?.value.toLowerCase() || '';

            this.state.filteredData = this.state.data.filter(d => {
                if (categoryFilter && d.category !== categoryFilter) return false;
                if (severityFilter && d.severity !== severityFilter) return false;
                if (searchTerm && !d.title.toLowerCase().includes(searchTerm) && 
                    !d.description.toLowerCase().includes(searchTerm)) return false;
                return true;
            });

            // Re-render events
            this.renderEvents();
            this.renderPhaseLabels();

            // Update stats
            this.updateStats();
        },

        /**
         * Update event positions during zoom
         */
        updateEventPositions: function(newXScale) {
            this.state.mainGroup
                .selectAll('.timeline-event')
                .attr('transform', d => `translate(${newXScale(d.timestamp)}, ${this.state.yScale(d.y)})`);
        },

        /**
         * Reset zoom to original view
         */
        resetZoom: function() {
            this.state.svg
                .transition()
                .duration(750)
                .call(this.state.zoom.transform, d3.zoomIdentity);
        },

        /**
         * Show tooltip on hover
         */
        showTooltip: function(event, data) {
            let tooltip = document.getElementById('timeline-tooltip');
            if (!tooltip) {
                tooltip = document.createElement('div');
                tooltip.id = 'timeline-tooltip';
                tooltip.className = 'tooltip-custom';
                tooltip.style.cssText = `
                    position: absolute;
                    background: rgba(0, 0, 0, 0.9);
                    color: white;
                    padding: 10px;
                    border-radius: 5px;
                    font-size: 12px;
                    pointer-events: none;
                    z-index: 1000;
                    max-width: 300px;
                    opacity: 0;
                    transition: opacity 0.2s;
                `;
                document.body.appendChild(tooltip);
            }

            const timeString = data.timestamp.toLocaleString();
            tooltip.innerHTML = `
                <div><strong>${this.escapeHtml(data.title)}</strong></div>
                <div class="mt-1">
                    <small>Time: ${timeString}</small><br>
                    <small>Category: ${data.category}</small><br>
                    <small>Severity: ${data.severity}</small><br>
                    <small>Process: ${this.escapeHtml(data.process)} (${data.pid})</small>
                </div>
                ${data.description ? `<div class="mt-1"><small>${this.escapeHtml(data.description)}</small></div>` : ''}
            `;

            tooltip.style.left = event.pageX + 10 + 'px';
            tooltip.style.top = event.pageY - 10 + 'px';
            tooltip.style.opacity = '1';
        },

        /**
         * Hide tooltip
         */
        hideTooltip: function() {
            const tooltip = document.getElementById('timeline-tooltip');
            if (tooltip) {
                tooltip.style.opacity = '0';
            }
        },

        /**
         * Select event and show details
         */
        selectEvent: function(event) {
            this.state.selectedEvent = event;
            
            // Highlight selected event
            this.state.mainGroup
                .selectAll('.timeline-event circle')
                .attr('stroke', '#fff')
                .attr('stroke-width', 2);

            this.state.mainGroup
                .selectAll('.timeline-event')
                .filter(d => d.id === event.id)
                .select('circle')
                .attr('stroke', '#000')
                .attr('stroke-width', 3);

            // Show event details panel
            this.showEventDetails(event);
        },

        /**
         * Show event details in sidebar
         */
        showEventDetails: function(event) {
            let detailsPanel = document.querySelector('.timeline-details');
            if (!detailsPanel) {
                detailsPanel = document.createElement('div');
                detailsPanel.className = 'timeline-details card mt-3';
                detailsPanel.innerHTML = `
                    <div class="card-header">
                        <h6 class="mb-0">Event Details</h6>
                    </div>
                    <div class="card-body">
                        <div class="timeline-details-content"></div>
                    </div>
                `;
                
                const container = document.querySelector(this.config.containerSelector);
                container.parentNode.appendChild(detailsPanel);
            }

            const content = detailsPanel.querySelector('.timeline-details-content');
            content.innerHTML = `
                <table class="table table-sm">
                    <tr><th>Title</th><td>${this.escapeHtml(event.title)}</td></tr>
                    <tr><th>Timestamp</th><td>${event.timestamp.toLocaleString()}</td></tr>
                    <tr><th>Category</th><td><span class="badge" style="background-color: ${this.getEventColor(event)}">${event.category}</span></td></tr>
                    <tr><th>Severity</th><td><span class="severity-indicator severity-${event.severity}">${event.severity}</span></td></tr>
                    <tr><th>Phase</th><td>${event.phase}</td></tr>
                    <tr><th>Process</th><td>${this.escapeHtml(event.process)} (PID: ${event.pid})</td></tr>
                    ${event.description ? `<tr><th>Description</th><td>${this.escapeHtml(event.description)}</td></tr>` : ''}
                </table>
                ${Object.keys(event.details).length > 0 ? `
                    <h6>Additional Details</h6>
                    <pre class="bg-light p-2" style="font-size: 11px; max-height: 200px; overflow-y: auto;"><code>${JSON.stringify(event.details, null, 2)}</code></pre>
                ` : ''}
            `;
        },

        /**
         * Update statistics display
         */
        updateStats: function() {
            const stats = this.calculateStats();
            
            let statsPanel = document.querySelector('.timeline-stats');
            if (!statsPanel) {
                statsPanel = document.createElement('div');
                statsPanel.className = 'timeline-stats alert alert-info mt-3';
                
                const container = document.querySelector(this.config.containerSelector);
                container.parentNode.appendChild(statsPanel);
            }

            statsPanel.innerHTML = `
                <div class="row text-center">
                    <div class="col-3">
                        <div class="h5 mb-0">${stats.total}</div>
                        <small>Total Events</small>
                    </div>
                    <div class="col-3">
                        <div class="h5 mb-0">${stats.critical + stats.high}</div>
                        <small>High Risk</small>
                    </div>
                    <div class="col-3">
                        <div class="h5 mb-0">${stats.duration}</div>
                        <small>Duration</small>
                    </div>
                    <div class="col-3">
                        <div class="h5 mb-0">${stats.avgPerMinute}</div>
                        <small>Avg/Min</small>
                    </div>
                </div>
            `;
        },

        /**
         * Calculate timeline statistics
         */
        calculateStats: function() {
            const data = this.state.filteredData;
            
            if (!data.length) {
                return { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, duration: '0s', avgPerMinute: '0' };
            }

            const severityCounts = data.reduce((acc, d) => {
                acc[d.severity] = (acc[d.severity] || 0) + 1;
                return acc;
            }, {});

            const timeExtent = d3.extent(data, d => d.timestamp);
            const durationMs = timeExtent[1] - timeExtent[0];
            const durationMinutes = durationMs / (1000 * 60);
            
            return {
                total: data.length,
                critical: severityCounts.critical || 0,
                high: severityCounts.high || 0,
                medium: severityCounts.medium || 0,
                low: severityCounts.low || 0,
                info: severityCounts.info || 0,
                duration: this.formatDuration(durationMs),
                avgPerMinute: durationMinutes > 0 ? (data.length / durationMinutes).toFixed(1) : '0'
            };
        },

        /**
         * Format duration in milliseconds to human readable
         */
        formatDuration: function(ms) {
            const seconds = Math.floor(ms / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);
            
            if (hours > 0) {
                return `${hours}h ${minutes % 60}m`;
            } else if (minutes > 0) {
                return `${minutes}m ${seconds % 60}s`;
            } else {
                return `${seconds}s`;
            }
        },

        /**
         * Get event color based on category and severity
         */
        getEventColor: function(event) {
            // Priority: severity colors for high-severity events, otherwise category colors
            if (['critical', 'high'].includes(event.severity)) {
                return this.config.colors[event.severity];
            }
            return this.config.colors[event.category] || this.config.colors.info;
        },

        /**
         * Get event radius based on severity
         */
        getEventRadius: function(event) {
            const sizeMap = {
                'critical': 12,
                'high': 10,
                'medium': 8,
                'low': 6,
                'info': 5
            };
            return sizeMap[event.severity] || 5;
        },

        /**
         * Export timeline as SVG
         */
        exportTimeline: function() {
            try {
                const svgElement = this.state.svg.node();
                const serializer = new XMLSerializer();
                const svgString = serializer.serializeToString(svgElement);
                
                const blob = new Blob([svgString], { type: 'image/svg+xml' });
                const url = URL.createObjectURL(blob);
                
                const a = document.createElement('a');
                a.href = url;
                a.download = `timeline_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.svg`;
                a.click();
                
                URL.revokeObjectURL(url);
                
                if (window.Shikra && window.Shikra.notifications) {
                    window.Shikra.notifications.show('Timeline exported successfully', 'success');
                }
            } catch (error) {
                console.error('Export failed:', error);
                if (window.Shikra && window.Shikra.notifications) {
                    window.Shikra.notifications.show('Export failed', 'danger');
                }
            }
        },

        /**
         * Resize timeline
         */
        resize: function() {
            const container = document.querySelector(this.config.containerSelector);
            if (!container || !this.state.svg) return;

            const newWidth = container.clientWidth;
            this.state.svg.attr('width', newWidth);
            
            // Update scales and re-render
            this.setupScales();
            this.render();
        },

        /**
         * Debounce utility function
         */
        debounce: function(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        },

        /**
         * Escape HTML utility
         */
        escapeHtml: function(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        },

        /**
         * Update timeline with new data
         */
        update: function(newData) {
            this.state.data = this.processData(newData);
            this.state.filteredData = [...this.state.data];
            this.setupScales();
            this.render();
            this.updateStats();
        },

        /**
         * Destroy timeline and cleanup
         */
        destroy: function() {
            if (this.state.svg) {
                this.state.svg.remove();
            }
            
            // Remove created elements
            const elementsToRemove = [
                '.timeline-controls',
                '.timeline-details',
                '.timeline-stats',
                '#timeline-tooltip'
            ];
            
            elementsToRemove.forEach(selector => {
                const element = document.querySelector(selector);
                if (element) {
                    element.remove();
                }
            });
        }
    };

    // Auto-initialize if D3 is available and timeline data exists
    document.addEventListener('DOMContentLoaded', function() {
        if (typeof d3 !== 'undefined' && window.timelineData) {
            TimelineInterface.init(window.timelineData);
        }
    });

})();