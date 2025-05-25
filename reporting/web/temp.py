import os
from pathlib import Path

# Define the template files and their content
# Each item in the list is a dictionary with 'path' and 'content'
templates_data = [
    {
        "path": "templates/base.html",
        "content": """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Shikra Malware Analysis Platform">
    <title>{% block title %}Shikra - Malware Analysis Platform{% endblock %}</title>
    
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/shikra.css') }}">
    {% block additional_css %}{% endblock %}
    
    <link rel="icon" type="image/x-icon" href="{{ url_for('static', filename='images/favicon.ico') }}">
    
    {% block head_extras %}{% endblock %}
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand d-flex align-items-center" href="{{ url_for('dashboard') }}">
                <i class="fas fa-shield-virus me-2"></i>
                <strong>Shikra</strong>
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('dashboard') }}">
                            <i class="fas fa-tachometer-alt"></i> Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('analysis_list') }}">
                            <i class="fas fa-list"></i> Analyses
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('sample_submission') }}">
                            <i class="fas fa-upload"></i> Submit Sample
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('search') }}">
                            <i class="fas fa-search"></i> Search
                        </a>
                    </li>
                    {% if current_user.is_authenticated and current_user.is_admin() %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('admin') }}">
                            <i class="fas fa-cog"></i> Admin
                        </a>
                    </li>
                    {% endif %}
                </ul>
                
                <ul class="navbar-nav">
                    {% if current_user.is_authenticated %}
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user"></i> {{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}">
                                <i class="fas fa-sign-out-alt"></i> Logout
                            </a></li>
                        </ul>
                    </li>
                    {% else %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('login') }}">
                            <i class="fas fa-sign-in-alt"></i> Login
                        </a>
                    </li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>
    
    <div class="container mt-3">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
    </div>
    
    <main class="container mt-4">
        {% block content %}
        {% endblock %}
    </main>
    
    <footer class="bg-light mt-5 py-4">
        <div class="container text-center">
            <p class="mb-0">&copy; 2024 Shikra Malware Analysis Platform - 
                <small class="text-muted">Version 1.0.0</small>
            </p>
        </div>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.socket.io/4.7.0/socket.io.min.js"></script>
    <script src="{{ url_for('static', filename='js/shikra.js') }}"></script>
    {% block additional_js %}{% endblock %}
</body>
</html>
"""
    },
    {
        "path": "templates/dashboard.html",
        "content": """{% extends "base.html" %}

{% block title %}Dashboard - Shikra{% endblock %}

{% block content %}
<div class="row">
    <div class="col-12">
        <h1 class="mb-4">
            <i class="fas fa-tachometer-alt text-primary"></i>
            Analysis Dashboard
        </h1>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.total_analyses or 0 }}</h4>
                        <p class="mb-0">Total Analyses</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-chart-bar fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.active_analyses or 0 }}</h4>
                        <p class="mb-0">Active Analyses</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-spinner fa-2x fa-spin"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.queued_analyses or 0 }}</h4>
                        <p class="mb-0">Queued</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-clock fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.completed_today or 0 }}</h4>
                        <p class="mb-0">Today</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-check fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-pie-chart"></i> Threat Distribution</h5>
            </div>
            <div class="card-body">
                <canvas id="threatChart" width="400" height="200"></canvas>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-activity"></i> System Health</h5>
            </div>
            <div class="card-body">
                <div class="d-flex justify-content-between mb-2">
                    <span>Analysis Engine:</span>
                    <span class="badge bg-success">{{ system_health.analysis_engine or 'Running' }}</span>
                </div>
                <div class="d-flex justify-content-between mb-2">
                    <span>CPU Usage:</span>
                    <span class="badge bg-info">{{ system_health.cpu_usage or 'Normal' }}</span>
                </div>
                <div class="d-flex justify-content-between mb-2">
                    <span>Memory:</span>
                    <span class="badge bg-info">{{ system_health.memory_usage or 'Normal' }}</span>
                </div>
                <div class="d-flex justify-content-between">
                    <span>Disk Space:</span>
                    <span class="badge bg-success">{{ system_health.disk_space or 'Normal' }}</span>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-history"></i> Recent Analyses</h5>
            </div>
            <div class="card-body">
                {% if recent_analyses %}
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Sample</th>
                                <th>Score</th>
                                <th>Classification</th>
                                <th>Time</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for analysis in recent_analyses %}
                            <tr>
                                <td>
                                    <i class="fas fa-file"></i>
                                    {{ analysis.filename[:30] }}{% if analysis.filename|length > 30 %}...{% endif %}
                                </td>
                                <td>
                                    <span class="badge bg-{{ get_score_color(analysis.score) }}">
                                        {{ analysis.score }}/100
                                    </span>
                                </td>
                                <td>
                                    <span class="badge bg-{{ get_threat_color(analysis.classification) }}">
                                        {{ analysis.classification }}
                                    </span>
                                </td>
                                <td>
                                    <small class="text-muted">{{ analysis.timestamp|datetime }}</small>
                                </td>
                                <td>
                                    <a href="{{ url_for('analysis_detail', analysis_id=analysis.id) }}" 
                                       class="btn btn-sm btn-outline-primary">
                                        <i class="fas fa-eye"></i> View
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <p class="text-muted text-center py-4">No recent analyses available.</p>
                {% endif %}
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-spinner fa-spin"></i> Active Analyses</h5>
            </div>
            <div class="card-body">
                {% if active_analyses %}
                    {% for analysis in active_analyses %}
                    <div class="mb-3 p-2 border rounded">
                        <div class="d-flex justify-content-between mb-1">
                            <small class="fw-bold">{{ analysis.filename[:25] }}...</small>
                            <small class="text-muted">{{ analysis.progress }}%</small>
                        </div>
                        <div class="progress mb-1" style="height: 5px;">
                            <div class="progress-bar" role="progressbar" 
                                 style="width: {{ analysis.progress }}%"></div>
                        </div>
                        <small class="text-muted">{{ analysis.current_phase }}</small>
                    </div>
                    {% endfor %}
                {% else %}
                <p class="text-muted text-center py-4">No active analyses.</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block additional_js %}
<script>
// Threat Distribution Chart
const threatData = {{ threat_distribution|tojson }};
if (Object.keys(threatData).length > 0) {
    const ctx = document.getElementById('threatChart').getContext('2d');
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: Object.keys(threatData),
            datasets: [{
                data: Object.values(threatData),
                backgroundColor: [
                    '#dc3545', '#fd7e14', '#ffc107', '#28a745', '#6c757d'
                ]
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}
</script>
{% endblock %}
"""
    },
    {
        "path": "templates/auth/login.html",
        "content": """{% extends "base.html" %}

{% block title %}Login - Shikra{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
        <div class="card shadow">
            <div class="card-body">
                <div class="text-center mb-4">
                    <i class="fas fa-shield-virus fa-3x text-primary mb-3"></i>
                    <h3>Shikra Login</h3>
                    <p class="text-muted">Malware Analysis Platform</p>
                </div>
                
                <form method="POST">
                    {{ form.hidden_tag() }}
                    
                    <div class="mb-3">
                        {{ form.username.label(class="form-label") }}
                        {{ form.username(class="form-control" + (" is-invalid" if form.username.errors else "")) }}
                        {% if form.username.errors %}
                            <div class="invalid-feedback">
                                {% for error in form.username.errors %}{{ error }}{% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="mb-3">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-control", type="password") }}
                        {% if form.password.errors %}
                            <div class="invalid-feedback">
                                {% for error in form.password.errors %}{{ error }}{% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-sign-in-alt"></i> Login
                        </button>
                    </div>
                </form>
                
                <div class="text-center mt-3">
                    <small class="text-muted">
                        Demo credentials: admin/admin123 or analyst/analyst123
                    </small>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
"""
    },
    {
        "path": "templates/analyses/list.html",
        "content": """{% extends "base.html" %}

{% block title %}Analyses - Shikra{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1><i class="fas fa-list"></i> Analysis Results</h1>
    <a href="{{ url_for('sample_submission') }}" class="btn btn-primary">
        <i class="fas fa-plus"></i> New Analysis
    </a>
</div>

<div class="card mb-4">
    <div class="card-body">
        <form method="GET" class="row g-3">
            <div class="col-md-3">
                <label class="form-label">Classification</label>
                <select name="classification" class="form-select">
                    <option value="">All Classifications</option>
                    <option value="CRITICAL" {% if filters.classification == 'CRITICAL' %}selected{% endif %}>Critical</option>
                    <option value="HIGH" {% if filters.classification == 'HIGH' %}selected{% endif %}>High</option>
                    <option value="MEDIUM" {% if filters.classification == 'MEDIUM' %}selected{% endif %}>Medium</option>
                    <option value="LOW" {% if filters.classification == 'LOW' %}selected{% endif %}>Low</option>
                </select>
            </div>
            
            <div class="col-md-2">
                <label class="form-label">Min Score</label>
                <input type="number" name="score_min" class="form-control" 
                       value="{{ filters.score_min or '' }}" min="0" max="100">
            </div>
            
            <div class="col-md-2">
                <label class="form-label">Max Score</label>
                <input type="number" name="score_max" class="form-control" 
                       value="{{ filters.score_max or '' }}" min="0" max="100">
            </div>
            
            <div class="col-md-3">
                <label class="form-label">Sort By</label>
                <select name="sort" class="form-select">
                    <option value="timestamp" {% if filters.sort == 'timestamp' %}selected{% endif %}>Date</option>
                    <option value="score" {% if filters.sort == 'score' %}selected{% endif %}>Score</option>
                    <option value="filename" {% if filters.sort == 'filename' %}selected{% endif %}>Filename</option>
                </select>
            </div>
            
            <div class="col-md-2">
                <label class="form-label">&nbsp;</label>
                <div class="d-grid">
                    <button type="submit" class="btn btn-outline-primary">
                        <i class="fas fa-filter"></i> Filter
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<div class="card">
    <div class="card-body">
        {% if analyses %}
        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>Sample</th>
                        <th>Size</th>
                        <th>Hash</th>
                        <th>Score</th>
                        <th>Classification</th>
                        <th>Date</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for analysis in analyses %}
                    <tr>
                        <td>
                            <i class="fas fa-file text-muted"></i>
                            <strong>{{ analysis.filename }}</strong>
                        </td>
                        <td>{{ analysis.size|filesize }}</td>
                        <td>
                            <code class="small">{{ analysis.hash|truncate_hash }}</code>
                        </td>
                        <td>
                            <span class="badge bg-{{ get_score_color(analysis.score) }}">
                                {{ analysis.score }}/100
                            </span>
                        </td>
                        <td>
                            <span class="badge bg-{{ get_threat_color(analysis.classification) }}">
                                {{ analysis.classification }}
                            </span>
                        </td>
                        <td>
                            <small>{{ analysis.timestamp|datetime }}</small>
                        </td>
                        <td>
                            <div class="btn-group btn-group-sm">
                                <a href="{{ url_for('analysis_detail', analysis_id=analysis.id) }}" 
                                   class="btn btn-outline-primary" title="View Details">
                                    <i class="fas fa-eye"></i>
                                </a>
                                <a href="{{ url_for('export_analysis', analysis_id=analysis.id, export_format='json') }}" 
                                   class="btn btn-outline-secondary" title="Export JSON">
                                    <i class="fas fa-download"></i>
                                </a>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        {% if pagination.pages > 1 %}
        <nav aria-label="Analysis pagination">
            <ul class="pagination justify-content-center">
                {% if pagination.has_prev %}
                    <li class="page-item">
                        <a class="page-link" href="?page={{ pagination.page - 1 }}">Previous</a>
                    </li>
                {% endif %}
                
                {% for page_num in range(1, pagination.pages + 1) %}
                    {% if page_num == pagination.page %}
                        <li class="page-item active">
                            <span class="page-link">{{ page_num }}</span>
                        </li>
                    {% else %}
                        <li class="page-item">
                            <a class="page-link" href="?page={{ page_num }}">{{ page_num }}</a>
                        </li>
                    {% endif %}
                {% endfor %}
                
                {% if pagination.has_next %}
                    <li class="page-item">
                        <a class="page-link" href="?page={{ pagination.page + 1 }}">Next</a>
                    </li>
                {% endif %}
            </ul>
        </nav>
        {% endif %}
        
        {% else %}
        <div class="text-center py-5">
            <i class="fas fa-search fa-3x text-muted mb-3"></i>
            <h4>No analyses found</h4>
            <p class="text-muted">Try adjusting your search criteria or submit a new sample for analysis.</p>
            <a href="{{ url_for('sample_submission') }}" class="btn btn-primary">
                <i class="fas fa-upload"></i> Submit Sample
            </a>
        </div>
        {% endif %}
    </div>
</div>
{% endblock %}
"""
    },
    {
        "path": "templates/analyses/detail.html",
        "content": """{% extends "base.html" %}

{% block title %}Analysis {{ analysis_id }} - Shikra{% endblock %}

{% block additional_css %}
<style>
.threat-score {
    font-size: 2rem;
    font-weight: bold;
}
.ioc-item {
    font-family: monospace;
    font-size: 0.9em;
    background-color: #f8f9fa;
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    margin: 0.25rem 0;
}
</style>
{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col-md-8">
        <h1>
            <i class="fas fa-file-alt"></i>
            {{ sample_info.filename or 'Unknown Sample' }}
        </h1>
        <p class="text-muted mb-0">Analysis ID: {{ analysis_id }}</p>
        <p class="text-muted">
            <i class="fas fa-clock"></i> 
            {{ metadata.generated_at|datetime if metadata.generated_at else 'Unknown time' }}
        </p>
    </div>
    <div class="col-md-4 text-end">
        <div class="btn-group">
            <a href="{{ url_for('export_analysis', analysis_id=analysis_id, export_format='json') }}" 
               class="btn btn-outline-primary">
                <i class="fas fa-download"></i> JSON
            </a>
            <a href="{{ url_for('export_analysis', analysis_id=analysis_id, export_format='pdf') }}" 
               class="btn btn-outline-secondary">
                <i class="fas fa-file-pdf"></i> PDF
            </a>
            <a href="{{ url_for('export_analysis', analysis_id=analysis_id, export_format='csv') }}" 
               class="btn btn-outline-success">
                <i class="fas fa-table"></i> CSV
            </a>
        </div>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-exclamation-triangle"></i> Executive Summary</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h3>Threat Level</h3>
                        <span class="badge bg-{{ get_threat_color(executive_summary.threat_level) }} fs-6">
                            {{ executive_summary.threat_level or 'Unknown' }}
                        </span>
                        <p class="mt-2">{{ executive_summary.risk_description or 'No description available.' }}</p>
                    </div>
                    <div class="col-md-6 text-center">
                        <h3>Threat Score</h3>
                        <div class="threat-score text-{{ get_score_color(executive_summary.overall_score) }}">
                            {{ executive_summary.overall_score or 0 }}/100
                        </div>
                    </div>
                </div>
                
                {% if executive_summary.key_capabilities %}
                <h5 class="mt-4">Key Capabilities</h5>
                <div class="d-flex flex-wrap gap-2">
                    {% for capability in executive_summary.key_capabilities %}
                    <span class="badge bg-warning text-dark">{{ capability }}</span>
                    {% endfor %}
                </div>
                {% endif %}
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-info-circle"></i> Sample Information</h5>
            </div>
            <div class="card-body">
                <table class="table table-sm">
                    <tr>
                        <td><strong>Filename:</strong></td>
                        <td>{{ sample_info.filename or 'Unknown' }}</td>
                    </tr>
                    <tr>
                        <td><strong>Size:</strong></td>
                        <td>{{ sample_info.size_bytes|filesize if sample_info.size_bytes else 'Unknown' }}</td>
                    </tr>
                    <tr>
                        <td><strong>SHA256:</strong></td>
                        <td><code class="small">{{ sample_info.sha256[:16] + '...' if sample_info.sha256 else 'Unknown' }}</code></td>
                    </tr>
                </table>
            </div>
        </div>
    </div>
</div>

<div class="row mb-4">
    {% if behavioral_analysis %}
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-running"></i> Behavioral Analysis</h5>
            </div>
            <div class="card-body">
                <div class="text-center mb-3">
                    <div class="fs-4 fw-bold text-{{ get_score_color(behavioral_analysis.score) }}">
                        {{ behavioral_analysis.score or 0 }}/100
                    </div>
                    <div class="badge bg-{{ get_threat_color(behavioral_analysis.classification) }}">
                        {{ behavioral_analysis.classification or 'Unknown' }}
                    </div>
                </div>
                <small class="text-muted">
                    Signatures: {{ behavioral_analysis.signatures|length if behavioral_analysis.signatures else 0 }}
                </small>
            </div>
        </div>
    </div>
    {% endif %}
    
    {% if network_analysis %}
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-network-wired"></i> Network Analysis</h5>
            </div>
            <div class="card-body">
                <div class="text-center mb-3">
                    <div class="fs-4 fw-bold text-{{ get_score_color(network_analysis.score) }}">
                        {{ network_analysis.score or 0 }}/100
                    </div>
                    <div class="badge bg-{{ get_threat_color(network_analysis.classification) }}">
                        {{ network_analysis.classification or 'Unknown' }}
                    </div>
                </div>
                <small class="text-muted">
                    DNS Queries: {{ network_analysis.dns_queries|length if network_analysis.dns_queries else 0 }}
                </small>
            </div>
        </div>
    </div>
    {% endif %}
    
    {% if memory_analysis %}
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-memory"></i> Memory Analysis</h5>
            </div>
            <div class="card-body">
                <div class="text-center mb-3">
                    <div class="fs-4 fw-bold text-{{ get_score_color(memory_analysis.score) }}">
                        {{ memory_analysis.score or 0 }}/100
                    </div>
                    <div class="badge bg-{{ get_threat_color(memory_analysis.classification) }}">
                        {{ memory_analysis.classification or 'Unknown' }}
                    </div>
                </div>
                <small class="text-muted">
                    Processes: {{ memory_analysis.suspicious_processes|length if memory_analysis.suspicious_processes else 0 }}
                </small>
            </div>
        </div>
    </div>
    {% endif %}
</div>

{% if iocs %}
<div class="card mb-4">
    <div class="card-header">
        <h5><i class="fas fa-crosshairs"></i> Indicators of Compromise</h5>
    </div>
    <div class="card-body">
        <div class="row">
            {% for category, ioc_list in iocs.items() %}
                {% if ioc_list %}
                <div class="col-md-6 mb-3">
                    <h6>{{ category.replace('_', ' ').title() }} ({{ ioc_list|length }})</h6>
                    <div style="max-height: 200px; overflow-y: auto;">
                        {% for ioc in ioc_list[:10] %}
                        <div class="ioc-item">
                            {% if ioc is mapping %}
                                {{ ioc.indicator or ioc }}
                            {% else %}
                                {{ ioc }}
                            {% endif %}
                        </div>
                        {% endfor %}
                        {% if ioc_list|length > 10 %}
                        <small class="text-muted">... and {{ ioc_list|length - 10 }} more</small>
                        {% endif %}
                    </div>
                </div>
                {% endif %}
            {% endfor %}
        </div>
    </div>
</div>
{% endif %}

{% if mitre_attack %}
<div class="card mb-4">
    <div class="card-header">
        <h5><i class="fas fa-shield-alt"></i> MITRE ATT&CK Techniques</h5>
    </div>
    <div class="card-body">
        <div class="row">
            {% for technique in mitre_attack %}
            <div class="col-md-6 mb-3">
                <div class="border rounded p-3">
                    <h6>{{ technique.technique_id }}: {{ technique.technique_name }}</h6>
                    <div class="mb-2">
                        <span class="badge bg-primary">{{ technique.tactic }}</span>
                        <span class="badge bg-secondary">{{ technique.confidence }}</span>
                    </div>
                    <small class="text-muted">{{ technique.evidence }}</small>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
</div>
{% endif %}

{% if visualizations %}
<div class="card mb-4">
    <div class="card-header">
        <h5><i class="fas fa-chart-line"></i> Visualizations</h5>
    </div>
    <div class="card-body">
        <div class="row">
            {% for viz in visualizations %}
            <div class="col-md-6 mb-3">
                <div class="card">
                    <div class="card-header">
                        <h6>{{ viz.name.replace('_', ' ').title() }}</h6>
                    </div>
                    <div class="card-body text-center p-2">
                        {% if viz.type == 'image' %}
                        <img src="{{ viz.path }}" class="img-fluid" alt="{{ viz.name }}" 
                             style="max-height: 300px; cursor: pointer;" 
                             data-bs-toggle="modal" data-bs-target="#vizModal{{ loop.index }}">
                        {% else %}
                        <iframe src="{{ viz.path }}" width="100%" height="300px" frameborder="0"></iframe>
                        {% endif %}
                    </div>
                </div>
                
                {% if viz.type == 'image' %}
                <div class="modal fade" id="vizModal{{ loop.index }}" tabindex="-1">
                    <div class="modal-dialog modal-xl">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">{{ viz.name.replace('_', ' ').title() }}</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body text-center">
                                <img src="{{ viz.path }}" class="img-fluid" alt="{{ viz.name }}">
                            </div>
                        </div>
                    </div>
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
    </div>
</div>
{% endif %}

{% if timeline %}
<div class="card">
    <div class="card-header">
        <h5><i class="fas fa-timeline"></i> Execution Timeline</h5>
    </div>
    <div class="card-body">
        <div class="timeline" style="max-height: 400px; overflow-y: auto;">
            {% for event in timeline %}
            <div class="d-flex mb-3">
                <div class="flex-shrink-0">
                    <span class="badge bg-{{ get_threat_color(event.severity) }}">
                        {{ event.severity.upper() }}
                    </span>
                </div>
                <div class="flex-grow-1 ms-3">
                    <h6>{{ event.event_type }}</h6>
                    <p class="mb-1">{{ event.description }}</p>
                    <small class="text-muted">{{ event.timestamp }}</small>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
</div>
{% endif %}
{% endblock %}
"""
    },
    {
        "path": "templates/submit.html",
        "content": """{% extends "base.html" %}

{% block title %}Submit Sample - Shikra{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h3><i class="fas fa-upload"></i> Submit Malware Sample</h3>
            </div>
            <div class="card-body">
                <form method="POST" enctype="multipart/form-data">
                    {{ form.hidden_tag() }}
                    
                    <div class="mb-4">
                        {{ form.sample_file.label(class="form-label") }}
                        {{ form.sample_file(class="form-control" + (" is-invalid" if form.sample_file.errors else "")) }}
                        {% if form.sample_file.errors %}
                            <div class="invalid-feedback">
                                {% for error in form.sample_file.errors %}{{ error }}{% endfor %}
                            </div>
                        {% endif %}
                        <div class="form-text">
                            Supported formats: EXE, DLL, ZIP, RAR, 7Z, PDF, DOC, DOCX, XLS, XLSX (Max: 100MB)
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                {{ form.vm_profile.label(class="form-label") }}
                                {{ form.vm_profile(class="form-select") }}
                            </div>
                        </div>
                        
                        <div class="col-md-6">
                            <div class="mb-3">
                                {{ form.analysis_timeout.label(class="form-label") }}
                                {{ form.analysis_timeout(class="form-control", min="5", max="60") }}
                                <div class="form-text">Recommended: 10-15 minutes</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label class="form-label">Analysis Options</label>
                        <div class="form-check">
                            {{ form.network_simulation(class="form-check-input") }}
                            {{ form.network_simulation.label(class="form-check-label") }}
                            <div class="form-text">Enable internet simulation for network behavior analysis</div>
                        </div>
                        <div class="form-check">
                            {{ form.detailed_logging(class="form-check-input") }}
                            {{ form.detailed_logging.label(class="form-check-label") }}
                            <div class="form-text">Capture detailed system logs (may increase analysis time)</div>
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        {{ form.description.label(class="form-label") }}
                        {{ form.description(class="form-control", rows="3", placeholder="Optional: Describe the sample source, behavior, or analysis goals...") }}
                        {% if form.description.errors %}
                            <div class="invalid-feedback">
                                {% for error in form.description.errors %}{{ error }}{% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                        <a href="{{ url_for('analysis_list') }}" class="btn btn-secondary">
                            <i class="fas fa-arrow-left"></i> Cancel
                        </a>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-upload"></i> Submit for Analysis
                        </button>
                    </div>
                </form>
            </div>
        </div>
        
        <div class="alert alert-warning mt-4">
            <h5><i class="fas fa-exclamation-triangle"></i> Security Notice</h5>
            <p class="mb-0">
                Only submit files you suspect are malware and have proper authorization to analyze. 
                Files are processed in isolated virtual machines, but exercise caution with sensitive data.
            </p>
        </div>
    </div>
</div>
{% endblock %}
"""
    },
    {
        "path": "templates/search.html",
        "content": """{% extends "base.html" %}

{% block title %}Search - Shikra{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-8 offset-md-2">
        <h1 class="text-center mb-4">
            <i class="fas fa-search"></i> Search Analysis Results
        </h1>
        
        <div class="card mb-4">
            <div class="card-body">
                <form method="POST">
                    {{ form.hidden_tag() }}
                    <div class="row">
                        <div class="col-md-8">
                            {{ form.query(class="form-control form-control-lg", placeholder="Search for files, hashes, IOCs, signatures...") }}
                        </div>
                        <div class="col-md-4">
                            <div class="input-group">
                                {{ form.search_type(class="form-select") }}
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search"></i> Search
                                </button>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
        </div>
        
        <div class="card mb-4">
            <div class="card-header">
                <h5><i class="fas fa-lightbulb"></i> Search Tips</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h6>Search Types:</h6>
                        <ul class="list-unstyled">
                            <li><strong>All Fields:</strong> Search across all analysis data</li>
                            <li><strong>Filename:</strong> Search by sample filename</li>
                            <li><strong>Hash:</strong> Search by MD5, SHA1, or SHA256</li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <h6>Examples:</h6>
                        <ul class="list-unstyled">
                            <li><code>malware.exe</code> - Find specific filename</li>
                            <li><code>192.168.1.1</code> - Find IP address in IOCs</li>
                            <li><code>persistence</code> - Find persistence techniques</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

{% if search_performed %}
<div class="row">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-search-plus"></i> Search Results ({{ results|length }} found)</h5>
            </div>
            <div class="card-body">
                {% if results %}
                    {% for result in results %}
                    <div class="border-bottom pb-3 mb-3">
                        <div class="row">
                            <div class="col-md-8">
                                <h6>
                                    <a href="{{ url_for('analysis_detail', analysis_id=result.analysis_id) }}">
                                        <i class="fas fa-file"></i> {{ result.filename }}
                                    </a>
                                </h6>
                                <p class="text-muted mb-2">
                                    Analysis ID: {{ result.analysis_id }} | 
                                    {{ result.timestamp|datetime }}
                                </p>
                                
                                {% if result.match_details %}
                                <div class="small">
                                    <strong>Matches found in:</strong>
                                    {% for detail in result.match_details %}
                                    <span class="badge bg-light text-dark me-1">{{ detail }}</span>
                                    {% endfor %}
                                </div>
                                {% endif %}
                            </div>
                            <div class="col-md-4 text-end">
                                <div class="mb-2">
                                    <span class="badge bg-{{ get_score_color(result.score) }}">
                                        {{ result.score }}/100
                                    </span>
                                    <span class="badge bg-{{ get_threat_color(result.classification) }}">
                                        {{ result.classification }}
                                    </span>
                                </div>
                                <a href="{{ url_for('analysis_detail', analysis_id=result.analysis_id) }}" 
                                   class="btn btn-sm btn-outline-primary">
                                    <i class="fas fa-eye"></i> View Details
                                </a>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                {% else %}
                <div class="text-center py-5">
                    <i class="fas fa-search fa-3x text-muted mb-3"></i>
                    <h4>No results found</h4>
                    <p class="text-muted">Try adjusting your search terms or search type.</p>
                </div>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endif %}
{% endblock %}
"""
    },
    {
        "path": "templates/analyses/progress.html",
        "content": """{% extends "base.html" %}

{% block title %}Analysis Progress - Shikra{% endblock %}

{% block additional_css %}
<style>
.progress-large {
    height: 2rem;
}
</style>
{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h3><i class="fas fa-spinner fa-spin"></i> Analysis in Progress</h3>
            </div>
            <div class="card-body text-center">
                <h4>{{ status.filename }}</h4>
                <p class="text-muted">Analysis ID: {{ analysis_id }}</p>
                
                <div class="mb-4">
                    <div class="progress progress-large">
                        <div class="progress-bar progress-bar-striped progress-bar-animated" 
                             role="progressbar" 
                             style="width: {{ status.progress }}%"
                             id="progressBar">
                            {{ status.progress }}%
                        </div>
                    </div>
                </div>
                
                <h5 id="currentPhase">{{ status.current_phase }}</h5>
                <p class="text-muted">Started: {{ status.started|datetime }}</p>
                
                <div class="mt-4">
                    <button class="btn btn-outline-primary" onclick="location.reload()">
                        <i class="fas fa-sync-alt"></i> Refresh Status
                    </button>
                    <a href="{{ url_for('analysis_list') }}" class="btn btn-secondary">
                        <i class="fas fa-list"></i> Back to List
                    </a>
                </div>
            </div>
        </div>
        
        <div class="alert alert-info mt-4">
            <i class="fas fa-info-circle"></i>
            <strong>Real-time Updates:</strong> This page will automatically update when the analysis completes.
            You can safely navigate away and return later.
        </div>
    </div>
</div>
{% endblock %}

{% block additional_js %}
<script>
// WebSocket connection for real-time updates
if (typeof io !== 'undefined') {
    const socket = io();
    
    socket.emit('join_analysis', { analysis_id: '{{ analysis_id }}' });
    
    socket.on('analysis_progress', function(data) {
        if (data.analysis_id === '{{ analysis_id }}') {
            document.getElementById('progressBar').style.width = data.progress + '%';
            document.getElementById('progressBar').textContent = data.progress + '%';
            document.getElementById('currentPhase').textContent = data.phase;
        }
    });
    
    socket.on('analysis_complete', function(data) {
        if (data.analysis_id === '{{ analysis_id }}') {
            window.location.href = "{{ url_for('analysis_detail', analysis_id=analysis_id) }}";
        }
    });
}

// Fallback: Auto-refresh every 10 seconds
setInterval(function() {
    fetch('{{ url_for("api_status", analysis_id=analysis_id) }}')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'completed') {
                window.location.href = "{{ url_for('analysis_detail', analysis_id=analysis_id) }}";
            } else if (data.status === 'running') {
                document.getElementById('progressBar').style.width = data.progress + '%';
                document.getElementById('progressBar').textContent = data.progress + '%';
                document.getElementById('currentPhase').textContent = data.current_phase;
            }
        })
        .catch(error => console.error('Status update error:', error));
}, 10000);
</script>
{% endblock %}
"""
    },
    {
        "path": "templates/admin/dashboard.html",
        "content": """{% extends "base.html" %}

{% block title %}Administration - Shikra{% endblock %}

{% block content %}
<h1><i class="fas fa-cog"></i> System Administration</h1>

<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body">
                <h4>{{ system_stats.total_analyses or 0 }}</h4>
                <p>Total Analyses</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body">
                <h4>{{ system_stats.active_analyses or 0 }}</h4>
                <p>Active Analyses</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body">
                <h4>{{ system_stats.queued_analyses or 0 }}</h4>
                <p>Queued Analyses</p>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body">
                <h4>{{ system_stats.disk_usage.percent|round(1) if system_stats.disk_usage else 0 }}%</h4>
                <p>Disk Usage</p>
            </div>
        </div>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-heartbeat"></i> System Health</h5>
            </div>
            <div class="card-body">
                <table class="table table-sm">
                    {% for key, value in system_health.items() %}
                    <tr>
                        <td><strong>{{ key.replace('_', ' ').title() }}:</strong></td>
                        <td>
                            <span class="badge bg-{{ 'success' if value in ['healthy', 'Running', 'Normal'] else 'warning' }}">
                                {{ value }}
                            </span>
                        </td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-users"></i> Active Users</h5>
            </div>
            <div class="card-body">
                {% if active_users %}
                <table class="table table-sm">
                    {% for user in active_users %}
                    <tr>
                        <td><i class="fas fa-user"></i> {{ user.username }}</td>
                        <td><small class="text-muted">{{ user.last_seen }}</small></td>
                    </tr>
                    {% endfor %}
                </table>
                {% else %}
                <p class="text-muted">No active users</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>

{% if analysis_queue %}
<div class="card mb-4">
    <div class="card-header">
        <h5><i class="fas fa-clock"></i> Analysis Queue</h5>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table">
                <thead>
                    <tr>
                        <th>Position</th>
                        <th>Filename</th>
                        <th>Submitted By</th>
                        <th>Submitted At</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in analysis_queue %}
                    <tr>
                        <td>{{ loop.index }}</td>
                        <td>{{ item.filename }}</td>
                        <td>{{ item.submitted_by }}</td>
                        <td>{{ item.submitted_at|datetime }}</td>
                        <td>
                            <button class="btn btn-sm btn-outline-danger" 
                                    onclick="removeFromQueue('{{ item.analysis_id }}')">
                                <i class="fas fa-times"></i> Remove
                            </button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endif %}

<div class="card">
    <div class="card-header">
        <h5><i class="fas fa-history"></i> Recent Activities</h5>
    </div>
    <div class="card-body">
        {% if recent_activities %}
        <div class="timeline">
            {% for activity in recent_activities %}
            <div class="d-flex mb-3">
                <div class="flex-shrink-0">
                    <i class="fas fa-check-circle text-success"></i>
                </div>
                <div class="flex-grow-1 ms-3">
                    <strong>{{ activity.type.replace('_', ' ').title() }}</strong>
                    <p class="mb-1">{{ activity.filename }} ({{ activity.analysis_id }})</p>
                    <small class="text-muted">by {{ activity.user }} at {{ activity.timestamp|datetime }}</small>
                </div>
            </div>
            {% endfor %}
        </div>
        {% else %}
        <p class="text-muted">No recent activities</p>
        {% endif %}
    </div>
</div>
{% endblock %}

{% block additional_js %}
<script>
function removeFromQueue(analysisId) {
    if (confirm('Are you sure you want to remove this analysis from the queue?')) {
        // Implementation for queue management
        fetch('/admin/queue/remove/' + analysisId, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': '{{ csrf_token() }}'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Error removing from queue: ' + data.error);
            }
        });
    }
}
</script>
{% endblock %}
"""
    },
    {
        "path": "templates/errors/404.html",
        "content": """{% extends "base.html" %}

{% block title %}Page Not Found - Shikra{% endblock %}

{% block content %}
<div class="text-center py-5">
    <i class="fas fa-exclamation-triangle fa-5x text-warning mb-4"></i>
    <h1>404 - Page Not Found</h1>
    <p class="lead">The page you're looking for doesn't exist.</p>
    <a href="{{ url_for('dashboard') }}" class="btn btn-primary">
        <i class="fas fa-home"></i> Return to Dashboard
    </a>
</div>
{% endblock %}
"""
    },
    {
        "path": "templates/errors/500.html",
        "content": """{% extends "base.html" %}

{% block title %}Server Error - Shikra{% endblock %}

{% block content %}
<div class="text-center py-5">
    <i class="fas fa-server fa-5x text-danger mb-4"></i>
    <h1>500 - Internal Server Error</h1>
    <p class="lead">Something went wrong on our end. Please try again later.</p>
    <a href="{{ url_for('dashboard') }}" class="btn btn-primary">
        <i class="fas fa-home"></i> Return to Dashboard
    </a>
</div>
{% endblock %}
"""
    }
]

def create_template_files():
    """
    Creates the directory structure and HTML files based on templates_data.
    """
    base_dir = Path(".") # Creates files in the current working directory

    for template_info in templates_data:
        file_path_str = template_info["path"]
        content = template_info["content"]
        
        # Create a Path object
        file_path = base_dir / file_path_str
        
        # Create parent directories if they don't exist
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            print(f"Ensured directory exists: {file_path.parent}")
        except Exception as e:
            print(f"Error creating directory {file_path.parent}: {e}")
            continue # Skip this file if directory creation fails
            
        # Write the file content
        try:
            file_path.write_text(content, encoding='utf-8')
            print(f"Successfully created file: {file_path}")
        except IOError as e:
            print(f"Error writing file {file_path}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred for {file_path}: {e}")

if __name__ == "__main__":
    print("Starting template file creation...")
    create_template_files()
    print("Template file creation process finished.")
